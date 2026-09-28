package sync

import (
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// ChangeKind classifies an invalidation. A subscriber uses it to decide whether
// a refetch is a content change or an authorization change, which is why the
// four values are named rather than folded into "changed".
type ChangeKind string

const (
	// ChangeCreated is a page that was not in the index before.
	ChangeCreated ChangeKind = "created"
	// ChangeUpdated is a page whose bytes differ from the indexed ones.
	ChangeUpdated ChangeKind = "updated"
	// ChangeDeleted is a page whose file is gone.
	ChangeDeleted ChangeKind = "deleted"
	// ChangeRenamed is a page that kept its content and changed its path. It is
	// distinct from updated because a subscriber holding the old path has to
	// discard its entry rather than refetch it.
	ChangeRenamed ChangeKind = "renamed"
)

// PageInvalidated is the announcement that a page's index state moved.
//
// It carries no content and no authorization decision. A subscriber receives it
// and then fetches the page with its own captured principal, so the bytes it
// ends up holding are produced by the ordinary handler under the subscriber's
// own authorization and never by the bus.
type PageInvalidated struct {
	// PageID is the page row's id, or 0 for a page that was never indexed.
	PageID int64
	// Path is the vault-relative path, slash-separated.
	Path string
	// Hash is the sha256 of the indexed file, or nil for a deletion.
	Hash []byte
	// Kind is what happened to the page.
	Kind ChangeKind
}

// DefaultQueueDepth is how many distinct pages one subscriber may have pending
// before the oldest is dropped.
//
// The bound is on *distinct* pages, not on events, because the queue coalesces:
// a DM saving one page in an editor produces a write, a rename and a save
// within a second and the subscriber only ever needs to hear about the last
// one. A vault with ten thousand pages all changing at once is a paste, and the
// right answer for a paste is "here is the state, re-read what you show".
const DefaultQueueDepth = 4096

// eventKey identifies the page an invalidation is about.
//
// It is the path and not the id, because a rename keeps the id and changes the
// path: coalescing on the id alone would collapse a rename into the update that
// preceded it and the subscriber would keep serving a URL that no longer
// resolves. Coalescing on the path alone would leave a deleted page's id
// unanswerable, so both are in the key.
type eventKey struct {
	pageID int64
	path   string
}

func keyOf(ev PageInvalidated) eventKey {
	return eventKey{pageID: ev.PageID, path: ev.Path}
}

// Bus fans invalidations out to subscribers.
//
// It exists because the indexer and the things that care about the index are on
// opposite sides of a process: an SSE connection, a DataStar fetch, a panel. The
// indexer must never block on any of them, so Publish does no work beyond
// taking a lock and touching a map.
//
// Coalescing is per subscriber, not global. Two subscribers at different speeds
// are two queues, so one slow consumer cannot make the other miss anything, and
// a subscriber that is behind gets the latest state per page rather than a
// backlog of states it has already passed.
type Bus struct {
	log *obs.Logger
	// max is the per-subscriber pending bound. It is set at construction and
	// never written again, so a subscription may read it without a lock.
	max int

	mu   sync.Mutex
	subs map[uint64]*subscription
	next uint64

	dropped atomic.Int64
	// published counts announcements, for the boot report and for a test that
	// asserts nothing was published rather than asserting it was.
	published atomic.Int64
}

// NewBus returns a bus. A nil log discards.
func NewBus(log *obs.Logger) *Bus {
	return &Bus{
		log:  loggerOf(log),
		max:  DefaultQueueDepth,
		subs: map[uint64]*subscription{},
	}
}

// Subscribe registers fn to receive invalidations and returns the function that
// cancels the subscription.
//
// fn is called from a goroutine of its own, one call at a time, and never
// concurrently with itself: a subscriber that needs to serialise its own state
// does not also need a lock. The unsubscribe function is safe to call from
// inside fn, and safe to call twice.
func (b *Bus) Subscribe(fn func(PageInvalidated)) func() {
	if fn == nil {
		return func() {}
	}
	s := &subscription{
		fn:      fn,
		bus:     b,
		id:      b.nextID(),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		pending: map[eventKey]PageInvalidated{},
	}
	b.mu.Lock()
	b.subs[s.id] = s
	b.mu.Unlock()

	go s.run()
	return func() { b.remove(s) }
}

func (b *Bus) nextID() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	return b.next
}

func (b *Bus) remove(s *subscription) { s.detach(b) }

// Publish announces one invalidation to every subscriber.
//
// It never blocks. A subscriber whose queue is at its bound loses its oldest
// pending entry, which is counted and logged rather than silently dropped: the
// reconciliation scan makes a missed invalidation a latency problem, not a
// correctness one, but "silently" is the word that turns a latency problem into
// a mystery.
func (b *Bus) Publish(ev PageInvalidated) {
	b.published.Add(1)
	b.mu.Lock()
	subs := make([]*subscription, 0, len(b.subs))
	for _, s := range b.subs {
		subs = append(subs, s)
	}
	b.mu.Unlock()

	for _, s := range subs {
		if s.enqueue(ev, b.max) {
			b.dropped.Add(1)
			b.log.Warn("invalidation queue full, dropped the oldest pending page",
				"action", "bus.drop", "path", ev.Path, "limit", b.max)
		}
	}
}

// Subscribers reports how many subscriptions are live.
func (b *Bus) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// Dropped reports how many pending entries have been evicted. It is a
// monotonically increasing counter for the life of the bus, and it is the only
// honest way to answer "did anything get away from us".
func (b *Bus) Dropped() int64 { return b.dropped.Load() }

// Published reports how many announcements have been made.
func (b *Bus) Published() int64 { return b.published.Load() }

func loggerOf(l *obs.Logger) *obs.Logger {
	if l != nil {
		return l
	}
	return obs.Discard()
}

// subscription is one subscriber's queue and its worker.
type subscription struct {
	fn   func(PageInvalidated)
	bus  *Bus
	id   uint64
	wake chan struct{}
	done chan struct{}

	mu      sync.Mutex
	pending map[eventKey]PageInvalidated
	// order is the arrival order of the keys in pending, so eviction can drop
	// the oldest without sorting on every insert.
	order   []eventKey
	stopped bool
}

// enqueue records ev, coalescing onto an event for the same page already
// waiting. It reports whether an eviction happened.
func (s *subscription) enqueue(ev PageInvalidated, max int) (evicted bool) {
	key := keyOf(ev)

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return false
	}
	if _, seen := s.pending[key]; seen {
		// Coalesce: the later state replaces the earlier one, and the arrival
		// order is left alone so that eviction still drops the page that has
		// been waiting longest.
		s.pending[key] = ev
		s.mu.Unlock()
		s.wakeOnce()
		return false
	}
	if len(s.pending) >= max {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.pending, oldest)
		evicted = true
	}
	s.pending[key] = ev
	s.order = append(s.order, key)
	s.mu.Unlock()

	s.wakeOnce()
	return evicted
}

// wakeOnce rings the worker without blocking. The channel has one slot, so a
// burst of ten announcements costs one wake-up and the worker drains the whole
// coalesced set when it gets there.
func (s *subscription) wakeOnce() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run delivers batches until the subscription is cancelled.
func (s *subscription) run() {
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		}
		for _, ev := range s.take() {
			s.deliver(ev)
		}
	}
}

// take swaps out the pending set.
func (s *subscription) take() []PageInvalidated {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return nil
	}
	out := make([]PageInvalidated, 0, len(s.pending))
	for _, key := range s.order {
		out = append(out, s.pending[key])
	}
	s.pending = make(map[eventKey]PageInvalidated, len(s.pending))
	s.order = s.order[:0]
	return out
}

// deliver calls fn, and contains a panic.
//
// A subscriber is a socket writer, and a socket writer can panic on a closed
// connection in a way the indexer cannot anticipate. Letting that kill the
// worker would silently stop every future invalidation for that subscriber,
// which reads as "the live updates stopped working" weeks later with nothing in
// the log.
func (s *subscription) deliver(ev PageInvalidated) {
	defer func() {
		if r := recover(); r != nil {
			s.bus.log.Error("a bus subscriber panicked and was detached",
				"action", "bus.panic", "path", ev.Path, "panic", r, "stack", string(debug.Stack()))
			s.detach(s.bus)
		}
	}()
	s.fn(ev)
}

// detach removes the subscription from its bus and stops its worker. It is
// idempotent, because the unsubscribe closure a caller holds is the same one a
// panic handler reaches, and a caller may hold it while the handler runs.
func (s *subscription) detach(b *Bus) {
	s.mu.Lock()
	already := s.stopped
	s.stopped = true
	s.mu.Unlock()

	b.mu.Lock()
	delete(b.subs, s.id)
	b.mu.Unlock()

	if already {
		return
	}
	close(s.done)
}
