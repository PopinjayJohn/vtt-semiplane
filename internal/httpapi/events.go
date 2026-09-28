package httpapi

// Live page updates: the per-subscriber fragment push.
//
// The whole design of this file is one rule, and it is the rule the plan states
// for §4.5: **the push path and the fetch path are the same code.** A delivery is
// produced by calling s.page — the very handler the router dispatches to — with a
// synthetic request that carries the subscriber's own captured principal, and
// writing the bytes it returns. There is no second renderer here, no second
// redaction call and no second set of SQL predicates, so a bug fixed in the fetch
// path is fixed in the push path because it is the same function. Everything below
// — the coalescing window, the queue bound, the caps, the generation watcher —
// exists to keep that one call safe, bounded and reachable.
//
// Two consequences are worth stating before the code:
//
//   - The stream carries a *trigger* and never content. The trigger is a small
//     JSON object naming what changed, and it says nothing a reader was not
//     already looking at. The rendered bytes that follow it are produced by the
//     ordinary handler under the subscriber's own principal, which is what makes
//     the trigger-only rule sufficient rather than a constraint we hope holds.
//   - A stream terminates on any change to its subscriber's authorization. The
//     five triggers the plan names — role change, disable, page-owner change,
//     logout, generation bump — are all bumps of meta['authz_generation'], so one
//     watched counter closes all five. Five checks would be five places to forget
//     one; one counter is a property of the store that every mutation path
//     already maintains.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	// The internal sync package is aliased because this file also needs the
	// standard library's, and an unaliased one of them would be unreadable.
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/go-chi/chi/v5"
)

// The stream's bounds. They are constants rather than configuration because each
// one is a memory argument: a stream costs a goroutine pair, a queue and a socket
// buffer, and the only question any of them answers is how much of that a
// client may have.
const (
	// MaxEventStreams is how many live-update streams one server holds at once,
	// across every account. The app is a LAN wiki for one small group, so this is
	// roughly "everybody is reading at once, twice over"; past it a stream is
	// refused rather than queued, because a refused stream costs the client one
	// ordinary page load and a queued one costs the server a socket forever.
	MaxEventStreams = 64
	// MaxEventStreamsPerUser is how many streams one account may hold. The client
	// contract is one EventSource per tab, so this is four tabs' worth: enough
	// that nobody is refused for the app behaving as specified, low enough that
	// one client in a reconnect loop cannot take the budget for the group.
	MaxEventStreamsPerUser = 4
	// MaxStreamQueueBytes and MaxStreamQueueEvents bound one connection's outbound
	// buffer, and whichever binds first wins. A subscriber that cannot keep up
	// loses its connection rather than the server its memory: the client refetches
	// on reconnect, so a dropped stream costs a latency and nothing else.
	MaxStreamQueueBytes  = 32 << 10
	MaxStreamQueueEvents = 32
	// EventRetryAfterSeconds is the Retry-After sent with a 429. The value is a
	// hint to a client that wants one, not a promise: an EventSource that is
	// refused will reconnect on its own schedule, and the page it is showing
	// keeps working because every surface in the app also renders without push.
	EventRetryAfterSeconds = 5
	// DefaultRenderWindow is the coalescing window. One render per window per
	// page, so a bulk paste that touches forty files costs each reader one
	// re-render and not forty. The window is not extended by later changes: a
	// continuous stream of edits would otherwise postpone the first push for ever.
	DefaultRenderWindow = 300 * time.Millisecond
	// DefaultAuthzPoll is how often the authorization generation is read. It is a
	// poll and not a notification because the counter is a row in a table that
	// five different packages bump, and adding a notifier to each of those five
	// call sites is five chances to forget one — the failure this whole mechanism
	// exists to prevent. A quarter of a second of extra latency on a stream that
	// is about to be closed anyway costs a reader nothing.
	DefaultAuthzPoll = 250 * time.Millisecond
	// streamCloseGrace is how long a terminating stream waits for its last event
	// to reach the socket before the handler returns. It is a wall-clock bound and
	// not s.clock: a stopped test clock would turn a teardown path into a hang,
	// and the thing it is waiting for is a socket write, not a logical deadline.
	streamCloseGrace = 2 * time.Second
)

// The event names and reasons on the wire. A closed set of three names and two
// reasons, so a client can switch on them exhaustively and a future event is a
// compile error on the client rather than a silently ignored frame.
const (
	// EventChanged says the page this client is displaying changed.
	EventChanged = "changed"
	// EventReload says stop trusting what you have and refetch.
	EventReload = "reload"
	// EventFragment carries the ordinary handler's bytes for the page.
	EventFragment = "fragment"
	// ReasonAuthz is a reload because the subscriber's authorization moved.
	ReasonAuthz = "authz"
	// ReasonRevoked is a reload because a secret on this page changed visibility.
	ReasonRevoked = "revoked"
)

// StreamWriter wraps the ResponseWriter a live-update stream writes through.
//
// It exists so that the leak tripwire can watch a stream with the same machinery
// that watches an ordinary response. The tripwire is a test, and a test cannot
// inspect a writer the production code offers no seam for, so this is the seam:
// an identity function in production, a scanner in TestTripwireAlsoCoversPushWrites.
// A wrapper must implement http.Flusher, because the stream is useless without
// it, and must forward Unwrap so http.ResponseController can still reach the
// socket underneath it.
type StreamWriter func(http.ResponseWriter) http.ResponseWriter

// trigger is the JSON object every trigger event carries.
//
// Two optional fields rather than a map, so that the shape is closed and a
// caller cannot invent a third field that some client starts reading. Path names
// the page and never a fragment of it, and Reason says why a reload happened and
// never what changed: both are facts about the subscriber's own current page and
// its own session, not about anything in the vault.
type trigger struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// The refusals attach can return. They are sentinels rather than status codes
// because the caller has to distinguish "over the cap" (429, retry later) from
// "this server is shutting down" (503, come back after the restart), and a bare
// int would collapse the two.
var (
	errStreamAtCap      = errors.New("the live-update stream limit is reached")
	errStreamAtUserCap  = errors.New("the live-update stream limit for this account is reached")
	errStreamShutdown   = errors.New("the live-update registry is shut down")
	errStreamBadRequest = errors.New("the live-update request could not be read")
)

// Events is the live-update registry: the open streams, their coalescing windows
// and the one background watcher that terminates a stream whose captured
// principal has gone stale.
//
// It is the boot report's and a test's window onto the push path — Subscribers
// answers "how many streams are open" and Shutdown ends them — and it owns the
// bus subscription, so a Server with no bus has a registry that never fires.
// That is the honest behaviour: a server built without an indexer has nothing
// that could announce a change, and a stream that can never push is a client
// falling back to ordinary fetching, which is what the app does without push at
// all.
type Events struct {
	srv *Server
	log *obs.Logger
	// unsub cancels the bus subscription, and is nil when there is no bus.
	unsub func()

	// capGlobal and capUser are the two caps as atomics because a test may
	// change them and a connection is reading them from another goroutine.
	capGlobal atomic.Int64
	capUser   atomic.Int64
	// windowNanos and pollNanos are the two intervals, held the same way.
	windowNanos atomic.Int64
	pollNanos   atomic.Int64
	// queueBytes and queueEvents bound one connection's outbound buffer.
	queueBytes  atomic.Int64
	queueEvents atomic.Int64

	// wrap is the tripwire seam and onRender the render counter. Both are nil in
	// production and both are read from the delivery goroutine, so they are
	// written under mu like everything else in the registry.
	mu       sync.Mutex
	wrap     StreamWriter
	onRender func(path string)
	subs     map[uint64]*subscriber
	next     uint64
	closed   bool
	// watchCtx, watchStop and watchDone are the running generation watcher's
	// context, cancel and completion, or nil for watchStop when no stream is
	// open. A context rather than a bare cancel function because the watcher
	// selects on it, and selecting on a CancelFunc is how a watcher cancels
	// itself by accident.
	watchCtx  context.Context
	watchStop context.CancelFunc
	watchDone chan struct{}

	renders atomic.Int64
	dropped atomic.Int64
	// live counts this registry's own goroutines: one per open stream's render
	// loop and writer, plus the generation watcher. It is the only honest way for
	// a test or a boot report to ask "did the push path leave anything running",
	// because a process-wide goroutine count cannot tell whose they are.
	live atomic.Int64
}

// Events returns this server's live-update registry.
//
// app and the tests reach the registry through this rather than through the
// handler, which is what lets a boot report count open streams and a test
// install the tripwire's writer before it opens any. New builds it, so this
// never returns nil and never allocates.
func (s *Server) Events() *Events { return s.streams }

// newEvents builds a registry and subscribes it to the invalidation bus.
func newEvents(s *Server) *Events {
	e := &Events{
		srv:         s,
		log:         s.log,
		subs:        map[uint64]*subscriber{},
		capGlobal:   atomic.Int64{},
		capUser:     atomic.Int64{},
		windowNanos: atomic.Int64{},
		pollNanos:   atomic.Int64{},
		queueBytes:  atomic.Int64{},
		queueEvents: atomic.Int64{},
	}
	e.capGlobal.Store(MaxEventStreams)
	e.capUser.Store(MaxEventStreamsPerUser)
	e.windowNanos.Store(int64(DefaultRenderWindow))
	e.pollNanos.Store(int64(DefaultAuthzPoll))
	e.queueBytes.Store(MaxStreamQueueBytes)
	e.queueEvents.Store(MaxStreamQueueEvents)
	if s.bus != nil {
		// The bus owns the goroutine this callback runs on, so the callback does
		// the least possible work: copy the subscriber list and hand each one its
		// own flag. It must never block, because a slow push would then be a slow
		// index pass for every other consumer of the bus.
		e.unsub = s.bus.Subscribe(e.invalidate)
	}
	return e
}

// SetCaps changes the two stream caps. It exists for the test that asserts the
// global cap, which would otherwise have to create sixteen accounts — one
// argon2id derivation each — to fill sixty-four streams.
func (e *Events) SetCaps(global, perUser int) {
	e.capGlobal.Store(int64(global))
	e.capUser.Store(int64(perUser))
}

// SetTimings changes the render window and the generation poll interval.
//
// The window is the interval a test must not sleep for: asserting that forty
// changes produce one render by waiting 300 ms and hoping is a test that passes
// on a fast machine and fails on a loaded one. With the window set to 20 ms the
// assertion is about the code rather than about the scheduler.
func (e *Events) SetTimings(window, poll time.Duration) {
	e.windowNanos.Store(int64(window))
	e.pollNanos.Store(int64(poll))
}

// SetQueueBound changes the per-connection outbound bound, in bytes and in
// events.
//
// Two knobs because the byte bound masks the event bound in production: the
// smallest real fragment is a few kilobytes, so thirty-two of them overflow
// thirty-two kilobytes several times over and the event bound is unreachable. A
// test that only exercised the byte bound would not know the other one worked.
func (e *Events) SetQueueBound(bytesLimit, eventLimit int) {
	e.queueBytes.Store(int64(bytesLimit))
	e.queueEvents.Store(int64(eventLimit))
}

// SetStreamWrapper installs the writer wrapper every stream writes through.
// The identity wrapper is the default, so production pays one function call per
// write and no tripwire.
func (e *Events) SetStreamWrapper(fn StreamWriter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wrap = fn
}

// SetRenderHook installs a function called once per fragment a stream
// re-renders, with the path it re-rendered. It is how a test counts renders
// without counting what reached the client, so that "one render" and "one event
// delivered" are two independent observations rather than one.
func (e *Events) SetRenderHook(fn func(path string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onRender = fn
}

// Subscribers reports how many streams are open. The boot report reads it to
// say whether live push is in use, and a test reads it to say whether a
// connection was really released.
func (e *Events) Subscribers() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.subs)
}

// Renders reports how many fragments have been re-rendered since boot.
func (e *Events) Renders() int64 { return e.renders.Load() }

// Dropped reports how many connections have been dropped for a full queue.
func (e *Events) Dropped() int64 { return e.dropped.Load() }

// Goroutines reports how many goroutines this registry is holding.
func (e *Events) Goroutines() int { return int(e.live.Load()) }

// Shutdown ends every stream and stops the generation watcher.
//
// It is the call app needs and the one a test needs in its cleanup. It does not
// wait for a connection that is mid-write: that write is unblocked by returning
// from the handler, which the stream's own teardown asks for, and waiting for
// it here would make a shutdown depend on a player's wifi. What it does wait for
// is the watcher, because that goroutine touches the database and the database
// is closed after this.
func (e *Events) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	subs := make([]*subscriber, 0, len(e.subs))
	for _, sub := range e.subs {
		subs = append(subs, sub)
	}
	stop, done := e.watchStop, e.watchDone
	unsub := e.unsub
	e.watchCtx, e.watchStop, e.watchDone = nil, nil, nil
	e.unsub = nil
	e.mu.Unlock()

	if stop != nil {
		stop()
	}
	if unsub != nil {
		unsub()
	}
	for _, sub := range subs {
		sub.teardown()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("httpapi: the authorization watcher did not stop: %w", ctx.Err())
	}
}

// events is the live-update stream.
//
// It is a plain SSE endpoint and not a DataStar action endpoint, because the
// events it sends are server-initiated and @get cannot express them. It holds
// the connection open and writes nothing but triggers until a page the client is
// displaying changes, its authorization moves, or it goes away.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	who := PrincipalFrom(r.Context())
	// The route is PermSession, so the gate has already refused an anonymous
	// principal. It is checked again because this is the one handler in the
	// package whose authority does not end with the response: a hundredth request
	// down the same socket must not be admitted by a gate that only ever saw the
	// first one.
	if !who.Authenticated() {
		s.writeError(w, r, http.StatusForbidden)
		return
	}

	ctx := r.Context()
	hub := s.Events()

	// The page the client says it is displaying. It is validated with the same
	// containment check the page handler's read uses, and it is never reflected
	// back: the only bytes that carry the path are the trigger's own field, and
	// it is the path the client sent.
	//
	// There is no POST to tell the server what changed page, deliberately: a
	// mutating route for a stream would need the CSRF token an EventSource cannot
	// hold, and a stream that has to be re-established per page is a stream that
	// is not open for the page you are reading.
	raw := r.URL.Query().Get("page")
	path := ""
	if raw != "" {
		var err error
		if path, err = s.streamPage(ctx, raw); err != nil {
			// A path that does not resolve names no file inside the vault, so it
			// is not a page and the stream becomes one that pushes nothing. That
			// is the same answer a client gets for a page that does not exist, and
			// a stream endpoint has no error page to give: an EventSource that was
			// answered with a body would reconnect in a loop.
			s.log.WarnContext(ctx, "a live-update stream named a page that does not resolve",
				"action", "http.events", "request_id", obs.RequestID(ctx), "path", raw)
			path = ""
		}
	}

	gen, err := store.AuthzGeneration(ctx, s.db.Reader())
	if err != nil {
		s.fail(w, r, "read the authorization generation", err)
		return
	}

	sub, err := hub.attach(streamParams{
		principal:  who,
		session:    SessionFrom(ctx),
		path:       path,
		secrets:    s.secretFingerprint(ctx, path),
		generation: gen,
	})
	switch {
	case errors.Is(err, errStreamShutdown):
		// The status line and a Retry-After, with no body. writeError cannot be
		// used for it: the error model has no copy for 503, so it would answer
		// 500 and be wrong in the direction that looks like a bug rather than a
		// shutdown. An EventSource only needs to be told that this was not a
		// stream.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", strconv.Itoa(EventRetryAfterSeconds))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	case errors.Is(err, errStreamAtCap), errors.Is(err, errStreamAtUserCap):
		// 429 with a Retry-After rather than a 503: a client over the cap is a
		// client that is better off fetching normally than retrying, and the
		// answer says so. The client refetches on reconnect regardless, so the
		// page it is showing never goes stale because of this.
		s.log.WarnContext(ctx, "a live-update stream was refused over the cap",
			"action", "http.events.cap", "request_id", obs.RequestID(ctx), "reason", err.Error())
		w.Header().Set("Retry-After", strconv.Itoa(EventRetryAfterSeconds))
		s.writeError(w, r, http.StatusTooManyRequests)
		return
	case err != nil:
		// Unreachable today: attach answers with one of the three sentinels
		// above. It is the package's idiom anyway, because a sentinel somebody
		// adds later should render an error page and not a bare status line.
		s.fail(w, r, "open a live-update stream", err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	// A proxy that buffers an event stream turns every push into a push that
	// arrives when the buffer fills, which is indistinguishable from push being
	// broken. The app is not behind a proxy and the header is a hint to one that
	// appears later.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// The preamble is a comment, so it is ignored by an EventSource and still
	// forces the response headers out. Without the flush the browser does not
	// consider the connection open, and a client that waits for `open` before
	// fetching would wait for the first change.
	if _, err := w.Write([]byte(": semiplane live updates\n\n")); err != nil {
		sub.teardown()
		return
	}
	flush(w)

	sub.serve(r, w)
}

// streamParams is one connection's captured state.
//
// It is a struct rather than six parameters because the six are the whole
// security argument of this file: a subscriber is exactly the identity captured
// at connect, the page it is allowed to be pushed, the generation that identity
// was minted against, and the secret fingerprint that page had at the time.
type streamParams struct {
	principal  authz.Principal
	session    string
	path       string
	secrets    string
	generation int64
}

// streamPage resolves the page a client says it is displaying.
//
// It accepts the URL the app emits (/p/Tavern) and the vault path
// (Tavern.md), and answers the index's own canonical path, so that a stream is
// keyed on the same string an invalidation carries whether the client spoke the
// first form or the second. A path that is inside the vault but not in the index
// answers its own cleaned path: a page that does not exist yet is still a page a
// client may be on, and the invalidation announcing its creation is the one that
// should push.
func (s *Server) streamPage(ctx context.Context, raw string) (string, error) {
	// Both forms: the app's own URLs carry the /p/ prefix and the bare path is
	// what an EventSource URL is easiest to build from.
	candidate := strings.TrimPrefix(raw, "/p/")
	candidate = strings.TrimPrefix(candidate, "/")
	if candidate == "" {
		return "", errStreamBadRequest
	}
	// Containment first: this is the check that refuses ../.., and it is the same
	// one the page handler applies to the file it is about to read.
	resolved, err := vault.Resolve(s.root, candidate)
	if err != nil {
		return "", err
	}
	path := resolved.Rel()
	if row, err := s.lookupPage(ctx, path); err == nil {
		return row.Path, nil
	}
	return path, nil
}

// secretFingerprint summarises a page's fences as ids and visibilities.
//
// It is the observable that tells a reveal or a revoke apart from a role change,
// and it holds nothing a client can be shown: the ids are opaque handles and the
// visibilities are three words the store already answers to anyone with a
// database. It is never logged and never rendered — it stays on the server and is
// compared, nothing more.
//
// It is read from the file and not from the index, which is the only choice that
// is correct at the moment it is needed. A reveal writes the file, commits the
// audit row and the generation bump, and only then reindexes; a reader that
// consulted the index at the instant the generation moved would see the old
// visibility and report a revoke as a role change. The file is canonical, it is
// written before the bump, and it is the answer the index is about to be
// derived from.
func (s *Server) secretFingerprint(ctx context.Context, path string) string {
	if path == "" {
		return ""
	}
	// The same containment check the page handler applies, on the same string: a
	// path that no longer resolves is a page that has been renamed or removed, and
	// both of those change the page rather than its secrets.
	resolved, err := vault.Resolve(s.root, path)
	if err != nil {
		return ""
	}
	onDisk, err := vault.Read(ctx, resolved)
	if err != nil {
		return ""
	}
	fences, _ := secrets.Parse(md.Parse(path, onDisk))
	var b strings.Builder
	for _, fence := range fences {
		b.WriteString(fence.ID)
		b.WriteByte(':')
		b.WriteString(string(fence.Visibility))
		b.WriteByte(';')
	}
	return b.String()
}

// attach registers a stream, or refuses it.
func (e *Events) attach(p streamParams) (*subscriber, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errStreamShutdown
	}
	if len(e.subs) >= int(e.capGlobal.Load()) {
		e.mu.Unlock()
		return nil, errStreamAtCap
	}
	if e.streamsOf(p.principal.UserID) >= int(e.capUser.Load()) {
		e.mu.Unlock()
		return nil, errStreamAtUserCap
	}
	// The stream's own context, built here rather than in a constructor because
	// it is the one thing about a subscriber that is not captured state.
	subctx, cancel := context.WithCancel(context.WithoutCancel(context.Background()))
	sub := &subscriber{
		ev:    e,
		id:    e.nextID(),
		who:   p.principal,
		token: p.session,
		path:  p.path,
		gen:   p.generation,
		secr:  p.secrets,
		// WithoutCancel is the whole point of the line: a context derived from
		// the request dies when the *request* is done, and the request is done
		// the moment this handler returns, which would kill every stream the
		// instant it opened. What replaces it is a context with no values of its
		// own and a cancel this stream owns, so a stream still ends when its
		// teardown runs and the principal and session put on the deliveries are
		// the only things a query under it can see.
		ctx:        subctx,
		cancel:     cancel,
		wake:       make(chan struct{}, 1),
		queuedWake: make(chan struct{}, 1),
		done:       make(chan struct{}),
		aborted:    make(chan struct{}),
		wrote:      make(chan struct{}),
	}
	e.subs[sub.id] = sub
	start := e.watchStop == nil
	var wctx context.Context
	var wdone chan struct{}
	var cancelWatch context.CancelFunc
	if start {
		// Plain assignment, not := : a short declaration inside this block would
		// declare a second wctx that the goroutine below does not capture, and the
		// watcher would then run against a nil context.
		wctx, cancelWatch = context.WithCancel(context.Background())
		wdone = make(chan struct{})
		e.watchCtx, e.watchStop, e.watchDone = wctx, cancelWatch, wdone
	}
	e.mu.Unlock()

	if start {
		e.live.Add(1)
		go func() {
			defer e.live.Add(-1)
			e.watchGeneration(wctx, wdone)
		}()
	}
	return sub, nil
}

// streamsOf counts one account's open streams, and the caller holds the lock.
func (e *Events) streamsOf(userID int64) int {
	if userID == 0 {
		return 0
	}
	n := 0
	for _, sub := range e.subs {
		if sub.who.UserID == userID {
			n++
		}
	}
	return n
}

// nextID is the stream's correlation id, and the caller holds the lock.
func (e *Events) nextID() uint64 {
	e.next++
	return e.next
}

// detach removes a stream from the registry. It is idempotent, because a client
// that goes away, a queue that overflows and a shutdown all reach it and only
// the first of them should matter.
func (e *Events) detach(sub *subscriber) {
	e.mu.Lock()
	delete(e.subs, sub.id)
	stop, done := e.watchStop, e.watchDone
	empty := len(e.subs) == 0
	if empty {
		e.watchStop, e.watchDone = nil, nil
	}
	e.mu.Unlock()

	if empty && stop != nil {
		stop()
		<-done
	}
}

// invalidate is the bus callback: one index announcement, fanned out.
//
// The fan-out is a copy of the subscriber list under the lock and a flag set on
// each outside it, because the registry lock must not be held while a subscriber
// takes its own.
func (e *Events) invalidate(ev isync.PageInvalidated) {
	e.mu.Lock()
	subs := make([]*subscriber, 0, len(e.subs))
	for _, sub := range e.subs {
		subs = append(subs, sub)
	}
	e.mu.Unlock()
	for _, sub := range subs {
		sub.invalidated(ev)
	}
}

// watchGeneration is the one background goroutine, and the reason a stream ends.
//
// It reads meta['authz_generation'] and closes every stream whose captured value
// no longer matches. That is the whole of §4.5's "any change to a user's
// authorization terminates their streams", and it covers all five named triggers
// — a role change, a disable, a page-owner change, a logout and a global bump —
// because every one of them bumps this counter as part of its transaction. The
// alternative, five checks, would be five places where a new kind of
// authorization change is silently not covered.
func (e *Events) watchGeneration(ctx context.Context, done chan struct{}) {
	defer close(done)
	poll := time.Duration(e.pollNanos.Load())
	if poll <= 0 {
		poll = DefaultAuthzPoll
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
		read, cancel := context.WithTimeout(ctx, 5*time.Second)
		gen, err := store.AuthzGeneration(read, e.srv.db.Reader())
		cancel()
		if err != nil {
			// A generation that cannot be read is not a reason to close every
			// stream: the next tick reads it again, and a player whose role
			// changed in the meantime gets a push they were already not entitled
			// to, which the next read then ends. Preferring the false negative
			// here is the direction that does not help an attacker.
			e.log.Warn("the authorization generation could not be read",
				"action", "http.events.authz", "err", err.Error())
			continue
		}
		e.terminateStale(ctx, gen)
	}
}

// terminateStale closes every stream whose captured generation has moved.
//
// The reason distinguishes the two classes a client must treat differently, and
// the test for it is the page's own secret visibility set, read from the file at
// the moment the generation moved: a reveal and a revoke both bump the generation
// and both make the bytes on the page wrong, while a role change or a logout
// bumps it and makes the *client's* identity wrong. Sending `revoked` for a page
// whose fences moved and `authz` for everything else is the honest report, and it
// is reported from the file rather than from the bus because the bus does not
// distinguish a revoke from any other content change — that is the design
// decision this file made, stated here so the next reader does not go looking for
// a bus event that cannot exist.
func (e *Events) terminateStale(ctx context.Context, gen int64) {
	e.mu.Lock()
	stale := make([]*subscriber, 0, 4)
	for _, sub := range e.subs {
		if sub.gen != gen {
			stale = append(stale, sub)
		}
	}
	e.mu.Unlock()

	for _, sub := range stale {
		reason := ReasonAuthz
		if e.srv.secretFingerprint(ctx, sub.path) != sub.secr {
			reason = ReasonRevoked
		}
		sub.terminate(reason)
	}
}

// subscriber is one open stream.
//
// The captured identity — who, token, gen — is written once at attach and never
// written again. That is the rule the whole file is safe by: a stream never
// re-derives its principal, so a stream cannot outlive the authority it was
// opened under, and the only way to renew one is to close it and let the client
// reconnect with a fresh handshake.
type subscriber struct {
	ev    *Events
	id    uint64
	who   authz.Principal
	token string
	path  string
	gen   int64
	secr  string

	// ctx is this stream's own lifetime context, and it is the one place in the
	// package where a context lives in a struct. It is not a request context: it
	// is built with WithoutCancel so that returning from the HTTP handler does
	// not kill it, and with a cancel the teardown calls so that it cannot outlive
	// the connection. The values a query needs — the principal and the session —
	// are put on a derived context per delivery rather than stored here, so that
	// the only thing this one carries is the right to exist.
	ctx    context.Context
	cancel context.CancelFunc

	wake       chan struct{} // cap 1: a change is pending a window
	queuedWake chan struct{} // cap 1: the queue is non-empty
	done       chan struct{} // the render loop has finished
	aborted    chan struct{} // tear down at once
	wrote      chan struct{} // the writer has finished

	mu      sync.Mutex
	pending bool   // a change is waiting for the window to open
	reason  string // non-empty means: send a reload and stop
	queue   [][]byte
	queued  int
	stopped bool
	once    sync.Once
}

// serve runs the stream until it ends.
//
// It owns the connection for its whole life: the handler must not return while
// the socket is still being written to, and it must not return early either,
// because returning is what closes the stream for good.
func (sub *subscriber) serve(r *http.Request, w http.ResponseWriter) {
	defer sub.teardown()

	out := w
	if wrap := sub.ev.wrapper(); wrap != nil {
		// The tripwire seam, applied to the SSE writer and not only to ordinary
		// responses: a push is a second way for bytes to reach a player, and a
		// leak detector that only watched the first one would be watching half
		// the surface.
		out = wrap(w)
	}
	ev := sub.ev
	ev.live.Add(2)
	go func() {
		defer ev.live.Add(-1)
		sub.write(out)
	}()
	go func() {
		defer ev.live.Add(-1)
		sub.run()
	}()

	// The client's own context is the lifetime signal. It is the request context
	// of the HTTP request, so it ends when the connection does — which is the
	// only place the truth about "has the client gone" can be read from.
	clientGone := r.Context().Done()
	select {
	case <-clientGone:
		sub.abort()
	case <-sub.done:
	}

	// A terminating stream still owes its client the reload it was told to
	// expect, so the handler waits a bounded moment for the writer to put it on
	// the wire. A client that is not reading gets the grace and then the
	// connection closes; the refetch-on-reconnect contract covers it.
	select {
	case <-sub.wrote:
	case <-sub.aborted:
	case <-time.After(streamCloseGrace):
	}
}

// wrapper reads the tripwire seam under the lock.
func (e *Events) wrapper() StreamWriter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.wrap
}

// run is the coalescing and delivery loop: one goroutine per stream.
//
// A change sets a flag and rings a one-slot channel, so a burst of forty costs
// one wake-up however many arrive, and the window is opened by the first of them
// and not extended by the rest. That combination is what makes "one render per
// window per page" hold: a paste that touches forty files leaves one flag set
// and one timer running.
func (sub *subscriber) run() {
	defer close(sub.done)
	var timer *time.Timer
	var tick <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		pending, reason := sub.take()
		if reason != "" {
			sub.end(reason)
			return
		}
		if pending && tick == nil {
			timer = time.NewTimer(sub.ev.renderWindow())
			tick = timer.C
		}
		select {
		case <-sub.aborted:
			return
		case <-sub.wake:
		case <-tick:
			tick, timer = nil, nil
			sub.deliver()
		}
	}
}

// take reads and clears the flags, in one lock, so that a wake-up with nothing
// to report is harmless and a change with no wake-up left to spend is not lost.
func (sub *subscriber) take() (pending bool, reason string) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	pending, reason = sub.pending, sub.reason
	sub.pending, sub.reason = false, ""
	return pending, reason
}

// write is the socket half: it drains the queue and never renders.
//
// Rendering and writing are separate goroutines so that a subscriber who cannot
// keep up blocks here and nowhere else. That is the whole of the backpressure
// design — the queue in front of this loop is bounded, so a slow reader fills it
// and is dropped, and a fast reader never waits for a render.
func (sub *subscriber) write(w http.ResponseWriter) {
	defer close(sub.wrote)
	for {
		if block, ok := sub.pop(); ok {
			if _, err := w.Write(block); err != nil {
				sub.abort()
				return
			}
			flush(w)
			continue
		}
		select {
		case <-sub.aborted:
			return
		case <-sub.queuedWake:
		case <-sub.done:
			// The render loop has finished, and it enqueued whatever it was
			// going to before it did, so the queue is drained exactly when this
			// finds it empty. Popping once more is what makes the reload of a
			// terminating stream reliably reach the socket.
			if _, ok := sub.pop(); !ok {
				return
			}
		}
	}
}

// invalidated records a bus announcement for this subscriber.
//
// A page the client is not displaying is not a page it gets pushed: a stream is
// per-tab and the tab is showing one page, so matching on the path is what keeps
// a bulk paste from re-rendering forty pages for a reader looking at one of them.
func (sub *subscriber) invalidated(ev isync.PageInvalidated) {
	if sub.path == "" || ev.Path != sub.path {
		return
	}
	sub.mu.Lock()
	if sub.stopped {
		sub.mu.Unlock()
		return
	}
	sub.pending = true
	sub.mu.Unlock()
	sub.ring(sub.wake)
}

// terminate asks a stream to send a reload and close.
func (sub *subscriber) terminate(reason string) {
	sub.mu.Lock()
	if sub.stopped {
		sub.mu.Unlock()
		return
	}
	sub.reason = reason
	sub.mu.Unlock()
	sub.ring(sub.wake)
}

// end sends the final reload and queues the stop.
//
// The order is the contract: the reload goes into the queue before done is
// closed, so a writer waiting on an empty queue is woken with something to
// write rather than with a close.
func (sub *subscriber) end(reason string) {
	if sub.enqueue(frameJSON(EventReload, trigger{Type: EventReload, Reason: reason})) {
		return
	}
	// The queue was already full, so the reload cannot be sent. Refusing to
	// pretend otherwise is the point: the client will reconnect, refetch
	// unconditionally and be correct, which is the same recovery a dropped
	// connection gets.
	sub.abort()
}

// deliver re-renders the page and queues it.
//
// This is the single line that the whole file is safe by. The bytes are produced
// by s.page, with the subscriber's own captured principal on the request, so
// every predicate, every redaction call and every permission check in the fetch
// path has already run by the time anything is queued. There is no redaction
// here to get wrong because there is no redaction here.
func (sub *subscriber) deliver() {
	ev := sub.ev
	if sub.path == "" {
		return
	}
	ev.mu.Lock()
	hook := ev.onRender
	ev.mu.Unlock()
	if hook != nil {
		hook(sub.path)
	}

	var buf renderBuffer
	ev.srv.page(&buf, sub.syntheticRequest())
	ev.renders.Add(1)

	block := frameJSON(EventChanged, trigger{Type: EventChanged, Path: sub.path})
	if buf.Len() > 0 {
		block = append(block, frameBytes(EventFragment, buf.Bytes())...)
	}
	if !sub.enqueue(block) {
		return
	}
	// The log line names the path, the actor and the size. A path is public
	// content by the same measure as a page title, and the size is here because a
	// push nobody can account for is a push nobody can debug — but it is a length
	// and never the bytes, which on this page would be a secret body.
	ev.log.InfoContext(sub.ctx, "a live-update stream re-rendered a page",
		"action", "http.events.push", "request_id", sub.requestID(),
		"path", sub.path, "actor", sub.who.String(), "bytes", len(block))
}

// syntheticRequest builds the request the ordinary handler is called with.
//
// The chi route context is the part that is not optional: s.page reads its path
// from the matched "*" parameter, and a request the router never routed has no
// such parameter, so without it every push would render the 404 page — correctly
// authorized, and useless.
func (sub *subscriber) syntheticRequest() *http.Request {
	u := url.URL{Scheme: "http", Host: "push.invalid", Path: pagePath(sub.path)}
	req, err := http.NewRequestWithContext(sub.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		// u.String() on a scheme, a host and a path cannot fail to parse, so this
		// is unreachable rather than expected; a request with no URL still renders
		// the page, which is a better answer than dropping the push.
		req, _ = http.NewRequestWithContext(sub.ctx, http.MethodGet, "http://push.invalid/p/", nil)
	}
	// The negotiation header is what makes Render choose the fragment, and the
	// comparison it is compared against is the same one a DataStar fetch is
	// compared against, which is what makes the two byte-identical.
	req.Header.Set(DataStarRequestHeader, "true")

	route := chi.NewRouteContext()
	route.URLParams.Add("*", sub.path)

	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
	ctx = withValue(ctx, principalKey, sub.who)
	ctx = withValue(ctx, sessionKey, sub.token)
	ctx = withValue(ctx, csrfKey, sub.csrf())
	ctx = withValue(ctx, routeKey, "/p/*")
	return req.WithContext(ctx)
}

// csrf is the token a fetch of this page would have carried, computed the way the
// session middleware computes it.
//
// It is here for one reason: if a fragment ever grows a form, the fragment a push
// delivers and the fragment a fetch returns have to carry the same token or the
// pushed one would be a form the client cannot submit.
func (sub *subscriber) csrf() string {
	if sub.token == "" || !sub.who.Authenticated() {
		return ""
	}
	token, err := sub.ev.srv.auth.CSRFToken(sub.token)
	if err != nil {
		return ""
	}
	return token
}

// requestID is the correlation id a push's log lines carry. It is derived from
// the stream's own id rather than generated, so a log line names the connection
// and a test can find it without the server minting a token per stream.
func (sub *subscriber) requestID() string { return "push-" + strconv.FormatUint(sub.id, 10) }

// enqueue puts one already-framed block on the outbound queue, or drops the
// connection.
//
// The bound is on bytes and on events, and exceeding either drops. A blocked
// write would be the alternative, and it is the wrong one: it holds the socket,
// the goroutine and the render that produced the block for as long as the
// client's TCP window stays shut, and one player on bad wifi would then be
// costing every other reader a goroutine. A dropped connection costs that client
// a refetch, which its reconnect contract already performs.
func (sub *subscriber) enqueue(block []byte) bool {
	limit := int(sub.ev.queueBytes.Load())
	maxEvents := int(sub.ev.queueEvents.Load())

	sub.mu.Lock()
	if sub.stopped {
		sub.mu.Unlock()
		return false
	}
	if len(sub.queue) >= maxEvents || sub.queued+len(block) > limit {
		// Read for the log line while the lock is still held: the writer goroutine
		// pops from this queue concurrently, and a diagnostic that races with the
		// thing it is diagnosing is a race detector failure in the failure path.
		queued := sub.queued
		sub.mu.Unlock()
		sub.ev.dropped.Add(1)
		sub.ev.log.Warn("a live-update connection was dropped with a full queue",
			"action", "http.events.overflow", "path", sub.path,
			"actor", sub.who.String(), "queued_bytes", queued, "limit", limit)
		sub.abort()
		return false
	}
	sub.queue = append(sub.queue, block)
	sub.queued += len(block)
	sub.mu.Unlock()

	sub.ring(sub.queuedWake)
	return true
}

// pop takes the oldest queued block.
func (sub *subscriber) pop() ([]byte, bool) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if len(sub.queue) == 0 {
		return nil, false
	}
	block := sub.queue[0]
	sub.queue[0] = nil
	sub.queue = sub.queue[1:]
	sub.queued -= len(block)
	return block, true
}

// ring wakes a loop without blocking. The channel has one slot, so a burst costs
// one wake-up and the flags in front of it carry the rest.
func (sub *subscriber) ring(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// abort tears the stream down at once, without a final event.
//
// It is the path for a full queue and for a socket that has failed, and both
// want the same thing: stop. The reason a full queue cannot also send a reload
// is that the queue is what is full.
func (sub *subscriber) abort() {
	sub.once.Do(func() {
		sub.mu.Lock()
		sub.stopped = true
		sub.pending, sub.reason = false, ""
		sub.queue, sub.queued = nil, 0
		sub.mu.Unlock()
		close(sub.aborted)
		sub.cancel()
	})
}

// teardown ends the stream, removes it from the registry, and releases the
// goroutines.
//
// The ordering matters and is the reason this is one function rather than three
// calls at the call sites: the connection stops writing, then it leaves the
// registry, then the registry may stop its watcher because this was the last
// stream. The queue is dropped rather than flushed, because whatever is in it
// was computed for a connection that is no longer entitled to it.
func (sub *subscriber) teardown() {
	sub.abort()
	sub.ev.detach(sub)
}

// renderWindow is the coalescing window, read once per change rather than
// captured, so that a test may shorten it after the streams are open.
func (e *Events) renderWindow() time.Duration {
	if d := time.Duration(e.windowNanos.Load()); d > 0 {
		return d
	}
	return DefaultRenderWindow
}

// pagePath is the URL the app emits for a vault path.
func pagePath(path string) string { return "/p/" + path }

// frameJSON frames a trigger as one SSE event.
//
// The payload is marshalled with HTML escaping on, which is not a decoration:
// goldmark output is the other thing on this connection, and a path or a reason
// that could contain "<" is escaped by construction rather than by the reader's
// care.
func frameJSON(name string, t trigger) []byte {
	payload, err := json.Marshal(t)
	if err != nil {
		// A struct of three strings cannot fail to marshal. If it ever does, the
		// stream carries an empty event rather than a panic in a goroutine.
		payload = []byte(`{"type":"` + name + `"}`)
	}
	return frame(name, payload)
}

// frameBytes frames a rendered fragment as one SSE event.
//
// Every line of the payload is prefixed, which is what the SSE format requires
// and what makes a payload unable to look like a field: a fragment of HTML
// cannot inject an `event:` line into the stream no matter what the vault holds.
func frameBytes(name string, payload []byte) []byte {
	buf := make([]byte, 0, len(payload)+len(name)*2+64)
	buf = append(buf, "event: "...)
	buf = append(buf, name...)
	buf = append(buf, '\n')
	for line := range bytes.Lines(payload) {
		buf = append(buf, "data: "...)
		buf = append(buf, line...)
	}
	buf = append(buf, '\n', '\n')
	return buf
}

// frame frames a payload that is already one line.
func frame(name string, payload []byte) []byte {
	buf := make([]byte, 0, len(payload)+len(name)*2+64)
	buf = append(buf, "event: "...)
	buf = append(buf, name...)
	buf = append(buf, "\ndata: "...)
	buf = append(buf, payload...)
	buf = append(buf, '\n', '\n')
	return buf
}

// renderBuffer collects what the ordinary handler wrote, so that a render cannot
// hold the socket for as long as goldmark takes.
//
// It implements the whole of http.ResponseWriter. The header map is never
// inspected: a push has already committed its response with text/event-stream,
// and re-negotiating content type per event is how a fragment ends up delivered
// as a document inside a stream.
type renderBuffer struct {
	header http.Header
	buf    bytes.Buffer
}

// Header returns the headers the handler wrote. Nothing reads them, and a nil map
// is created on demand because the handlers do write to them.
func (b *renderBuffer) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

// Write collects the bytes.
func (b *renderBuffer) Write(p []byte) (int, error) { return b.buf.Write(p) }

// WriteHeader is recorded and ignored: the status is the stream's, already sent.
func (b *renderBuffer) WriteHeader(int) {}

// Len is how many bytes the handler produced, which is how a push decides
// whether there is a fragment to frame at all.
func (b *renderBuffer) Len() int { return b.buf.Len() }

// Bytes is the collected body.
func (b *renderBuffer) Bytes() []byte { return b.buf.Bytes() }

// flush pushes what has been written to the socket.
//
// A stream whose writer cannot flush is not an error: the bytes are buffered
// until the connection ends, which for a stream means a push that arrives when
// the client next reads. The wrapper has to be transparent about this, which is
// why the tripwire's writer in the test has to implement http.Flusher too.
func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
