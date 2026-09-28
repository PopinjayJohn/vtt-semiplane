package sync

import (
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// waitFor polls until cond holds or the deadline passes. A bus delivery is
// asynchronous by construction, so every assertion about one is a wait.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type recorder struct {
	mu     sync.Mutex
	events []PageInvalidated
	// seen counts every delivery, so a coalesced event can be told from a
	// dropped one.
	seen int
}

func (r *recorder) add(ev PageInvalidated) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen++
	r.events = append(r.events, ev)
}

func (r *recorder) snapshot() []PageInvalidated {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]PageInvalidated(nil), r.events...)
}

func (r *recorder) deliveries() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

// TestBusCoalescesToTheLatestStatePerPage asserts that a subscriber which is
// behind gets the latest state for a page, not a backlog of states it has already
// passed.
//
// An editor that saves produces a write, a rename and a save in under a second.
// A subscriber that has to be told about all three is a subscriber three renders
// behind; one that is told about the last is a subscriber that is current.
func TestBusCoalescesToTheLatestStatePerPage(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	rec := &recorder{}
	stop := bus.Subscribe(rec.add)
	defer stop()

	first := PageInvalidated{PageID: 7, Path: "A.md", Hash: []byte("one"), Kind: ChangeUpdated}
	for _, hash := range []string{"two", "three", "four"} {
		bus.Publish(PageInvalidated{PageID: 7, Path: "A.md", Hash: []byte(hash), Kind: ChangeUpdated})
	}
	waitFor(t, "the coalesced event", func() bool { return rec.deliveries() > 0 })
	if got := rec.deliveries(); got != 1 {
		t.Fatalf("the subscriber saw %d events for one page, want 1", got)
	}
	if got := string(rec.snapshot()[0].Hash); got != "four" {
		t.Fatalf("the delivered hash is %q, want the latest one", got)
	}
	_ = first

	// Distinct pages are distinct events.
	for i, path := range []string{"B.md", "C.md", "D.md"} {
		bus.Publish(PageInvalidated{PageID: int64(100 + i), Path: path, Kind: ChangeCreated})
	}
	waitFor(t, "one event per page", func() bool { return rec.deliveries() == 4 })
}

// TestBusDistinguishesAPageFromItsOwnRename asserts the coalescing key: a rename
// keeps the id and changes the path, so the two states are not the same event and
// one may not swallow the other.
func TestBusDistinguishesAPageFromItsOwnRename(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	rec := &recorder{}
	stop := bus.Subscribe(rec.add)
	defer stop()

	bus.Publish(PageInvalidated{PageID: 9, Path: "Old.md", Kind: ChangeUpdated})
	bus.Publish(PageInvalidated{PageID: 9, Path: "New.md", Kind: ChangeRenamed})
	waitFor(t, "both states", func() bool { return rec.deliveries() == 2 })
	var kinds []ChangeKind
	for _, ev := range rec.snapshot() {
		kinds = append(kinds, ev.Kind)
	}
	if kinds[0] != ChangeUpdated || kinds[1] != ChangeRenamed {
		t.Fatalf("delivered %v, want [updated renamed]", kinds)
	}
}

// TestPublishNeverBlocks asserts the property the indexer depends on: a
// subscriber that has stopped reading cannot stall an index pass.
//
// A subscriber here is a socket writer. If Publish waited for it, one wedged
// connection would stop the indexer, and the indexer stopping is how a DM's save
// stops appearing.
func TestPublishNeverBlocks(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	defer bus.Subscribe(func(PageInvalidated) {})()
	wedge := make(chan struct{})
	defer close(wedge)
	stop := bus.Subscribe(func(PageInvalidated) { <-wedge })
	defer stop()

	done := make(chan struct{})
	go func() {
		for i := range 20000 {
			bus.Publish(PageInvalidated{PageID: int64(i), Path: "Slow.md", Kind: ChangeUpdated})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Publish blocked on a subscriber that was not reading")
	}
}

// TestTheQueueIsBounded asserts that a subscriber which is behind for ever has a
// bounded cost, and that the eviction is reported rather than silent.
func TestTheQueueIsBounded(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	bus.max = 4
	rec := &recorder{}
	// The callback wedges on its first delivery and is released at the end of the
	// test, so the worker is stuck inside deliver and nothing drains behind it.
	wedge := make(chan struct{})
	entered := make(chan struct{}, 1)
	stop := bus.Subscribe(func(ev PageInvalidated) {
		select {
		case entered <- struct{}{}:
			<-wedge
		default:
		}
		rec.add(ev)
	})
	defer stop()

	bus.Publish(PageInvalidated{PageID: 1, Path: "First.md", Kind: ChangeCreated})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the wedged subscriber was never called")
	}
	for i := range 50 {
		bus.Publish(PageInvalidated{PageID: int64(100 + i), Path: "P.md", Kind: ChangeUpdated})
	}
	if bus.Dropped() == 0 {
		t.Fatal("a queue of four was filled with fifty pages and nothing was dropped")
	}
	if got := bus.Dropped(); got != 46 {
		t.Fatalf("%d drops for 50 publishes into a queue of four, want 46", got)
	}
	if got := rec.deliveries(); got != 0 {
		t.Fatalf("a wedged subscriber completed %d callbacks, want 0 in flight", got)
	}
	close(wedge)
	// Once released it is told about the four pages that survived, not the fifty.
	waitFor(t, "the survivors to be delivered", func() bool { return rec.deliveries() == 5 })
}

// TestUnsubscribeStopsDelivery asserts that the returned function really
// detaches, including when it is called twice and when it is called from inside a
// callback.
func TestUnsubscribeStopsDelivery(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	rec := &recorder{}
	stop := bus.Subscribe(rec.add)
	bus.Publish(PageInvalidated{PageID: 1, Path: "A.md", Kind: ChangeCreated})
	waitFor(t, "the first delivery", func() bool { return rec.deliveries() == 1 })

	stop()
	stop()
	waitFor(t, "the subscription to be gone", func() bool { return bus.Subscribers() == 0 })
	bus.Publish(PageInvalidated{PageID: 2, Path: "B.md", Kind: ChangeCreated})
	time.Sleep(100 * time.Millisecond)
	if got := rec.deliveries(); got != 1 {
		t.Fatalf("an unsubscribed callback was called %d times", got)
	}

	// Unsubscribing from inside a callback is the SSE-teardown path, and a
	// double close of the done channel there would panic in a request goroutine.
	var once sync.Once
	self := &recorder{}
	var inner func()
	inner = bus.Subscribe(func(ev PageInvalidated) {
		self.add(ev)
		inner()
	})
	bus.Publish(PageInvalidated{PageID: 3, Path: "C.md", Kind: ChangeCreated})
	waitFor(t, "the self-unsubscribing delivery", func() bool { return self.deliveries() == 1 })
	bus.Publish(PageInvalidated{PageID: 4, Path: "D.md", Kind: ChangeCreated})
	time.Sleep(100 * time.Millisecond)
	if got := self.deliveries(); got != 1 {
		t.Fatalf("a callback that unsubscribed itself kept being called (%d)", got)
	}
	once.Do(func() {})
}

// TestAPanickingSubscriberIsDetachedAndTheOthersSurvive asserts that one bad
// callback cannot stop the bus.
//
// A subscriber is a socket writer and a socket writer panics on a closed
// connection. Letting that kill the worker would stop every future
// invalidation for that subscriber, which reads as "live updates stopped working"
// weeks later with nothing in the log.
func TestAPanickingSubscriberIsDetachedAndTheOthersSurvive(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	rec := &recorder{}
	stop := bus.Subscribe(rec.add)
	defer stop()
	stopPanic := bus.Subscribe(func(PageInvalidated) { panic("the socket was closed") })
	defer stopPanic()

	bus.Publish(PageInvalidated{PageID: 1, Path: "A.md", Kind: ChangeCreated})
	waitFor(t, "the healthy delivery", func() bool { return rec.deliveries() == 1 })
	waitFor(t, "the panicking subscriber to be detached", func() bool { return bus.Subscribers() == 1 })

	bus.Publish(PageInvalidated{PageID: 2, Path: "B.md", Kind: ChangeCreated})
	waitFor(t, "the healthy subscriber to keep working", func() bool { return rec.deliveries() == 2 })
}

// TestBusCountersAreHonest asserts the two numbers a boot report would print.
func TestBusCountersAreHonest(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	stop := bus.Subscribe(func(PageInvalidated) {})
	defer stop()
	if bus.Published() != 0 || bus.Dropped() != 0 {
		t.Fatal("a fresh bus has non-zero counters")
	}
	bus.Publish(PageInvalidated{PageID: 1, Path: "A.md", Kind: ChangeCreated})
	bus.Publish(PageInvalidated{PageID: 2, Path: "B.md", Kind: ChangeCreated})
	if bus.Published() != 2 {
		t.Fatalf("published = %d, want 2", bus.Published())
	}
	if bus.Dropped() != 0 {
		t.Fatalf("dropped = %d on an empty queue", bus.Dropped())
	}
}

// TestSubscribeIgnoresANilCallback asserts the degenerate case does not panic.
func TestSubscribeIgnoresANilCallback(t *testing.T) {
	t.Parallel()
	bus := NewBus(discard())
	stop := bus.Subscribe(nil)
	bus.Publish(PageInvalidated{PageID: 1, Path: "A.md"})
	stop()
	stop()
	if bus.Subscribers() != 0 {
		t.Fatal("a nil callback was registered")
	}
}

// TestPublishWithNoSubscribersIsANoOp asserts that an indexer with no bus still
// works, which is the state before the HTTP layer exists.
func TestPublishWithNoSubscribersIsANoOp(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"A.md": "# A\n"})
	h.bus.mu.Lock()
	for id := range h.bus.subs {
		delete(h.bus.subs, id)
	}
	h.bus.mu.Unlock()
	res := h.indexAll()
	if !res.Changed() {
		t.Fatal("indexing did nothing with no subscribers")
	}
	if h.bus.Published() != 1 {
		t.Fatalf("published = %d, want 1", h.bus.Published())
	}
}

func discard() *obs.Logger { return obs.Discard() }
