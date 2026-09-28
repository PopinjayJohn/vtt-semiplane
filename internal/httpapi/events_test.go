package httpapi_test

// The live-push tests.
//
// Everything here drives the real stack over a real httptest server, because the
// property under test is a property of the wire: what bytes reach a player's open
// connection, and whether they are the bytes the ordinary handler would have
// written for that same principal. A stubbed stream would assert that the stub
// agrees with itself.
//
// Two rules shape the whole file:
//
//   - A test must not sleep for the thing it is testing. The render window and
//     the generation poll are named constants, and every fixture here shortens
//     them (hub.SetTimings) so that the assertions are about the code rather than
//     about the scheduler.
//   - Every negative assertion carries a positive control. A stream that leaked
//     nothing because nothing was ever pushed is the failure mode this suite
//     exists to prevent, so each test proves it received a real render first.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The stream's test timings. Short enough to be fast, long enough that a burst
// lands inside one window, and far below the shipped values so that a test
// failing here is never a test that failed because the machine was busy.
const (
	testWindow = 25 * time.Millisecond
	testPoll   = 15 * time.Millisecond
	// testTimeout bounds every wait. It is generous on purpose: the assertions
	// are about whether something eventually happened, and a tight deadline turns
	// a loaded machine into a red build.
	testTimeout = 15 * time.Second
)

// The fixture tokens, named. Each is the body of exactly one fence in
// campaignFiles, so a finding names the secret that leaked and not just the page
// it leaked on. tableToken is the harness's own: it is the one body a player may
// read, and this file must not have a second name for it.
const (
	privateToken = "PRIVATE-BODY-TOKEN-9f3a2c" // private, authored by the DM, on the Tavern
	dmToken      = "DM-BODY-TOKEN-7b1e4d"      // dm, on the Tavern
	ownerToken   = "OWNER-BODY-TOKEN-2a6e10"   // private, authored by Thia, on the Tavern
	ruinToken    = "RUIN-BODY-TOKEN-2c8f61"    // dm, on the Ruin
)

// eventFixture is the harness fixture with an invalidation bus wired into both
// the indexer and the server.
//
// It is a separate builder rather than an option on newFixtureWith because the
// harness deliberately builds a server with no bus — a test that never subscribes
// wants that — and a push test cannot reach the push path without one. Everything
// else is the harness's own, so the accounts, the seeding and the index pass are
// identical to every other test in the package.
type eventFixture struct {
	*fixture
	bus *isync.Bus
	hub *httpapi.Events
}

func newEventFixture(t *testing.T, files map[string]string, mutate ...func(*config.Config)) *eventFixture {
	t.Helper()
	dir := t.TempDir()
	writeVault(t, dir, files)

	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = 0
	cfg.Vault = dir
	cfg.NoOpen = true
	for _, m := range mutate {
		m(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the fixture's configuration is not valid: %v", err)
	}

	log := obs.NewLogger(io.Discard, obs.Options{Level: slog.LevelError})
	clock := &testClock{now: startTime}
	clockFn := clock.obs()

	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := store.Migrate(context.Background(), db.Writer(), func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("migrate the index: %v", err)
	}
	if err := store.MetaSet(context.Background(), db.Writer(), store.KeyBootState, store.BootStateReady); err != nil {
		t.Fatalf("record the boot state: %v", err)
	}

	// The bus is the only difference from the harness, and it is wired into both
	// the indexer that announces and the server that listens, because a bus only
	// one of them knows about is a stream that never fires.
	bus := isync.NewBus(log)
	indexer, err := isync.New(isync.Options{DB: db, Root: dir, Bus: bus, Log: log, Clock: clockFn})
	if err != nil {
		t.Fatalf("build the indexer: %v", err)
	}
	res, err := indexer.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk the vault: %v", err)
	}
	if _, err := indexer.IndexBatch(context.Background(), res.Files); err != nil {
		t.Fatalf("index the vault: %v", err)
	}

	writer := vault.NewWriter(dir, log)
	writer.Clock = clockFn
	policy := authz.NewPolicy(cfg.AllowAnonymousRead)
	accounts, err := auth.New(auth.Options{DB: db, Policy: policy, Log: log, Clock: clockFn})
	if err != nil {
		t.Fatalf("build the account service: %v", err)
	}
	secretSvc, err := secrets.NewService(secrets.Options{
		DB: db, Writer: writer, Policy: policy, Reindexer: indexer, Log: log, Clock: clockFn,
	})
	if err != nil {
		t.Fatalf("build the secrets service: %v", err)
	}

	srv, err := httpapi.New(httpapi.Options{
		Config: cfg, DB: db, Writer: writer, Reindexer: indexer, AuthorRetryer: indexer,
		Bus: bus, Log: log, Clock: clockFn, Build: app.Info(),
		Assets: web.Assets(), Renderer: web.NewRenderer(),
	})
	if err != nil {
		t.Fatalf("build the server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	fx := &fixture{
		t: t, dir: dir, cfg: cfg,
		DB: db, Auth: accounts, Vault: writer, Root: dir,
		Log: log, Clock: clock, Indexer: indexer, Secrets: secretSvc,
		Server: srv, HTTP: ts,
	}
	hub := srv.Events()
	hub.SetTimings(testWindow, testPoll)
	// The registry has to be stopped before the database closes, and the cleanup
	// order here is last-in-first-out, so this one is registered after the two
	// above and therefore runs first.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := hub.Shutdown(ctx); err != nil {
			t.Errorf("shutting the live-update registry down: %v", err)
		}
	})
	return &eventFixture{fixture: fx, bus: bus, hub: hub}
}

// seeded is the standard campaign with the four accounts and Thia's ownership of
// the Tavern, which is the state every push assertion is written against.
func seeded(t *testing.T) *eventFixture {
	t.Helper()
	fx := newEventFixture(t, campaignFiles)
	fx.accountsFor()
	return fx
}

// save appends one line to a page through the writer and reindexes it, which is
// exactly the sequence a DM's edit produces: the bytes land atomically, then the
// index is brought up to date, and only then is the change announced.
//
// The line is public text and no fence is touched, so the reindex does not bump
// the authorization generation: a test about a content push must not be a test
// about a reload.
func (fx *eventFixture) save(t *testing.T, path, line string) {
	t.Helper()
	ctx := context.Background()
	current, err := os.ReadFile(filepath.Join(fx.Root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	next := append(append([]byte{}, current...), []byte("\n"+line+"\n")...)
	err = fx.Vault.Save(ctx, vault.SaveRequest{
		Path:            path,
		NewContent:      next,
		BaseContentHash: vault.Hash(current),
		ActorID:         fx.userID(dmName),
		ExpectPerm:      authz.PermWritePage,
	})
	if err != nil {
		t.Fatalf("save %s: %v", path, err)
	}
	if err := fx.Indexer.Reindex(ctx, path); err != nil {
		t.Fatalf("reindex %s: %v", path, err)
	}
}

// announce publishes one invalidation for a page, the way the indexer does when a
// file changes underneath it.
func (fx *eventFixture) announce(path string, kind isync.ChangeKind) {
	fx.bus.Publish(isync.PageInvalidated{Path: path, Kind: kind})
}

// principalFor builds a Principal for an account, the way a service call from a
// handler would receive one.
func (fx *eventFixture) principalFor(t *testing.T, username string, role authz.Role) authz.Principal {
	t.Helper()
	u, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), username)
	if err != nil {
		t.Fatalf("look up %s: %v", username, err)
	}
	return authz.ForUser(u.ID, u.Username, role, fx.cfg.AllowAnonymousRead)
}

// streamRequest builds the request that opens a stream.
//
// It does not go through session.send, and that is deliberate: send reads every
// GET response to EOF so it can pick up a CSRF token, and an event stream does
// not end. A test that used it would hang instead of failing, which is a trap
// worth naming because the authorization matrix hit it too: driving a streaming
// route through a helper that reads to EOF needs a deadline, not a body.
func (fx *eventFixture) streamRequest(t *testing.T, s *session, page string) *http.Request {
	t.Helper()
	target := fx.HTTP.URL + "/_/events"
	if page != "" {
		target += "?page=" + url.QueryEscape(page)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build the stream request: %v", err)
	}
	return req
}

// openStream opens a stream and asserts that it opened.
func (fx *eventFixture) openStream(t *testing.T, s *session, page string) *eventStream {
	t.Helper()
	resp, err := s.http.Do(fx.streamRequest(t, s, page))
	if err != nil {
		t.Fatalf("open a stream on %s: %v", page, err)
	}
	if resp.StatusCode != http.StatusOK {
		body := readAndClose(resp)
		t.Fatalf("open a stream on %s: status %d, want 200\n%s", page, resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		drain(resp)
		t.Fatalf("open a stream on %s: content type %q, want text/event-stream", page, got)
	}
	es := &eventStream{resp: resp}
	go es.read()
	t.Cleanup(es.stop)
	return es
}

// eventStream is one open connection, read continuously.
//
// It reads in a goroutine because the server holds the connection open and every
// assertion about a stream is therefore an assertion about a moment in time: the
// bytes so far, and whether they have stopped arriving.
type eventStream struct {
	resp *http.Response
	once sync.Once

	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (es *eventStream) read() {
	chunk := make([]byte, 8<<10)
	for {
		n, err := es.resp.Body.Read(chunk)
		if n > 0 {
			es.mu.Lock()
			es.buf.Write(chunk[:n])
			es.mu.Unlock()
		}
		if err != nil {
			es.mu.Lock()
			es.closed = true
			es.mu.Unlock()
			return
		}
	}
}

// stop closes the connection, which is what a tab does when it goes away.
func (es *eventStream) stop() {
	es.once.Do(func() { _ = es.resp.Body.Close() })
}

// text is every byte the server has written so far.
func (es *eventStream) text() string {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.buf.String()
}

// isClosed reports whether the server has stopped writing.
func (es *eventStream) isClosed() bool {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.closed
}

// waitFor waits until the stream satisfies want, or the connection ends, and
// fails the test with what arrived if neither happens.
func (es *eventStream) waitFor(t *testing.T, why string, want func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		text := es.text()
		if want(text) {
			return text
		}
		if es.isClosed() {
			t.Fatalf("the stream closed before %s\n%s", why, clip(text))
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s\n%s", testTimeout, why, clip(text))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitClosed waits for the server to end the connection.
func (es *eventStream) waitClosed(t *testing.T, why string) string {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !es.isClosed() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for the stream to close (%s)\n%s", testTimeout, why, clip(es.text()))
		}
		time.Sleep(2 * time.Millisecond)
	}
	return es.text()
}

// sseEvent is one parsed event.
type sseEvent struct {
	name string
	data string
}

// parseSSE splits a stream into the events it carries.
//
// It is written rather than imported because the framing is four lines of code
// and because a parser shared with the server would be a parser that cannot catch
// the server getting its own framing wrong.
func parseSSE(raw string) []sseEvent {
	var out []sseEvent
	for _, block := range strings.Split(raw, "\n\n") {
		if block == "" || strings.HasPrefix(block, ":") {
			continue
		}
		var ev sseEvent
		var data []string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = append(data, strings.TrimPrefix(line, "data: "))
			}
		}
		if ev.name == "" {
			continue
		}
		ev.data = strings.Join(data, "\n")
		out = append(out, ev)
	}
	return out
}

// count returns how many delivered events have the given name.
func countEvents(evs []sseEvent, name string) int {
	n := 0
	for _, ev := range evs {
		if ev.name == name {
			n++
		}
	}
	return n
}

// first returns the first event with the given name.
func firstEvent(evs []sseEvent, name string) (sseEvent, bool) {
	for _, ev := range evs {
		if ev.name == name {
			return ev, true
		}
	}
	return sseEvent{}, false
}

// clip shortens a body for a failure message. A page fragment is a few kilobytes
// and a failure that printed all of them would bury the assertion.
func clip(s string) string {
	const max = 1200
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n… (" + strconv.Itoa(len(s)) + " bytes in total)"
}

// waitUntil waits for a condition about the server, or fails the test.
//
// Every assertion about the push path is an assertion about something that
// happens on another goroutine — a render, a registration, a teardown — so every
// one of them is a wait. The deadline is generous and the failure message carries
// the state that was reached, because "timed out" on its own says nothing about
// which half of the machinery stalled.
func waitUntil(t *testing.T, why string, want func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !want() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", testTimeout, why)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// mayRead is the visibility rule, written out for this file.
//
// It is deliberately a second statement of the same rule rather than a call into
// authz or a reuse of the tripwire's table: a leak test that asks the code it is
// testing whether a leak is a leak has stopped being a leak test. A disagreement
// between this function and tripwire_test.go's is a finding about one of the two,
// which is the reason to have both.
func mayRead(role, token string) bool {
	switch role {
	case "dm", "admin":
		return true
	case "page owner":
		// A page owner reads the private fences on her own page, whoever wrote
		// them, and nothing else on it. The dm fences are the negative case that
		// an OR-chain gets wrong.
		switch token {
		case privateToken, ownerToken, tableToken:
			return true
		}
		return false
	case "player":
		// A player owns nothing and authored nothing here, so the only fence she
		// may read is the one revealed to the table.
		return token == tableToken
	case "anonymous":
		return false
	}
	return false
}

// pushRole is one role as these tests model it: who signs in, which page they are
// looking at, and which fences on it they may read.
type pushRole struct {
	role  string
	user  string
	pass  string
	page  string
	reads string // the token this role must see in a delivered fragment
}

var pushRoles = []pushRole{
	{role: "player", user: otherName, pass: otherPass, page: "Tavern.md", reads: tableToken},
	{role: "other player", user: playerName, pass: playerPass, page: "Ruin.md", reads: ""},
	{role: "page owner", user: playerName, pass: playerPass, page: "Tavern.md", reads: ownerToken},
	{role: "dm", user: dmName, pass: dmPass, page: "Tavern.md", reads: dmToken},
	{role: "admin", user: adminName, pass: adminPass, page: "Tavern.md", reads: dmToken},
}

// assertNoLeak is the assertion, over every byte the connection received.
func assertNoLeak(t *testing.T, role, text string) {
	t.Helper()
	for _, token := range bodyTokens {
		if mayRead(role, token) {
			continue
		}
		if strings.Contains(text, token) {
			t.Errorf("the stream for %s carries a secret it may not read: %q", role, token)
		}
	}
}

// TestPushNeverLeaksSecret is the leak test for the push path.
//
// A DM edits a page that carries all four visibilities while a player has it open,
// and every byte the connection receives is checked. It runs for every role, and
// then again with all of them connected at once, because the failure this path
// is most likely to have is not "the wrong principal's bytes" but "somebody
// else's principal's bytes": a render computed under a different context and
// queued to the wrong subscriber would pass every single-role row and fail only
// when they are all open.
func TestPushNeverLeaksSecret(t *testing.T) {
	t.Parallel()

	t.Run("one stream at a time", func(t *testing.T) {
		t.Parallel()
		for _, r := range pushRoles {
			t.Run(r.role, func(t *testing.T) {
				t.Parallel()
				fx := seeded(t)
				s := fx.asUser(r.user, r.pass)
				es := fx.openStream(t, s, r.page)
				waitUntil(t, "the stream to be registered", func() bool {
					return fx.hub.Subscribers() == 1
				})

				fx.save(t, r.page, "A line written while a reader had the page open.")
				text := es.waitFor(t, "the pushed fragment", func(s string) bool {
					return strings.Contains(s, "A line written while a reader had the page open.")
				})
				assertNoLeak(t, r.role, text)
				// The positive control: the reader really did receive a rendered
				// page under their own authorization, so the assertion above is
				// about what was filtered rather than about nothing arriving.
				if r.reads == "" {
					if len(parseSSE(text)) == 0 {
						t.Errorf("no event at all reached %s, so the leak assertions are vacuous", r.role)
					}
				} else if !strings.Contains(text, r.reads) {
					t.Errorf("the stream for %s does not carry %q, which it is entitled to read; the push delivered nothing to assert about",
						r.role, r.reads)
				}
			})
		}
	})

	t.Run("anonymous with anonymous read on", func(t *testing.T) {
		t.Parallel()
		fx := newEventFixture(t, campaignFiles, func(c *config.Config) { c.AllowAnonymousRead = true })
		fx.accounts()
		s := fx.newSession()
		resp, err := s.http.Do(fx.streamRequest(t, s, "Tavern.md"))
		if err != nil {
			t.Fatalf("ask for a stream without a session: %v", err)
		}
		defer drain(resp)
		// The route is PermSession, so the gate refuses before the handler runs
		// and the client is sent to the login form. The assertion is that no
		// stream exists for an anonymous reader at all — a subtest that opened one
		// and found it clean would be asserting nothing.
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("an anonymous stream: status %d, want 303", resp.StatusCode)
		}
		if got := fx.hub.Subscribers(); got != 0 {
			t.Errorf("an anonymous request registered %d streams, want 0", got)
		}
	})

	t.Run("every role connected at once", func(t *testing.T) {
		t.Parallel()
		fx := seeded(t)
		type live struct {
			role pushRole
			es   *eventStream
		}
		var open []live
		for _, r := range pushRoles {
			s := fx.asUser(r.user, r.pass)
			es := fx.openStream(t, s, r.page)
			open = append(open, live{role: r, es: es})
		}
		// Two principals appear twice — Thia is both "other player" and "page
		// owner" — so this is four accounts and five streams, which is the point:
		// the same identity on two pages must not share a render.
		waitUntil(t, "every stream to be registered", func() bool {
			return fx.hub.Subscribers() == len(open)
		})

		// One write per page, because a subscriber is only ever pushed for the page
		// it is displaying. The Ruin reader must get nothing from a change to the
		// Tavern, and that is asserted by the wait below rather than assumed.
		line := map[string]string{
			"Tavern.md": "Five readers, two pages, one write each.",
			"Ruin.md":   "Five readers, two pages, one write each.",
		}
		for _, page := range []string{"Tavern.md", "Ruin.md"} {
			fx.save(t, page, line[page])
		}
		for _, l := range open {
			want := line[l.role.page]
			text := l.es.waitFor(t, "the pushed fragment", func(s string) bool {
				return strings.Contains(s, want)
			})
			assertNoLeak(t, l.role.role, text)
		}
		// The Ruin carries a dm secret and no reader here may see it, which is
		// the one page whose fragment was pushed from a different account's
		// request than any of the Tavern's.
		for _, l := range open {
			if l.role.page == "Ruin.md" {
				continue
			}
			if strings.Contains(l.es.text(), ruinToken) {
				t.Errorf("the stream for %s carries the Ruin's secret, which is on a different page", l.role.role)
			}
		}
	})
}

// TestPushAndFetchProduceIdenticalFragments is the single-renderer test.
//
// It is the assertion the whole design rests on: what a push writes and what an
// ordinary DataStar fetch of the same page returns, under the same principal, are
// the same bytes. If they ever differ then one of the two is not the ordinary
// handler, and every argument about the push path being safe is void.
func TestPushAndFetchProduceIdenticalFragments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		role  string
		user  string
		pass  string
		reads string
	}{
		{role: "player", user: otherName, pass: otherPass, reads: tableToken},
		{role: "dm", user: dmName, pass: dmPass, reads: dmToken},
	} {
		t.Run(tc.role, func(t *testing.T) {
			t.Parallel()
			fx := seeded(t)
			s := fx.asUser(tc.user, tc.pass)
			es := fx.openStream(t, s, "Tavern.md")
			waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

			fx.save(t, "Tavern.md", "Identical on both paths.")
			text := es.waitFor(t, "the pushed fragment", func(s string) bool {
				return strings.Contains(s, "Identical on both paths.")
			})
			pushed, ok := firstEvent(parseSSE(text), httpapi.EventFragment)
			if !ok {
				t.Fatalf("no %s event arrived\n%s", httpapi.EventFragment, clip(text))
			}
			if !strings.Contains(pushed.data, tc.reads) {
				t.Errorf("the pushed fragment does not carry %q, which this principal may read; the identity below would be an identity between two empty things",
					tc.reads)
			}

			// The same URL the subscriber declared, so the two sides cannot differ
			// by an argument the client happened to spell differently.
			fetched := s.text(s.fragment("/p/Tavern.md"))
			if pushed.data != fetched {
				t.Errorf("the pushed fragment and the fetched one differ (%d vs %d bytes)\npushed: %s\nfetched: %s",
					len(pushed.data), len(fetched), clip(pushed.data), clip(fetched))
			}
		})
	}
}

// TestPushTerminatesOnRoleChange is the staleness test.
//
// A stream holds a principal captured at connect. When that principal is no longer
// the one the server would mint, the stream has to end: a reconnected client
// re-handshakes and captures a fresh principal, and a stream that survived would
// keep rendering under an identity the store has withdrawn.
func TestPushTerminatesOnRoleChange(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	s := fx.asUser(otherName, otherPass)
	es := fx.openStream(t, s, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

	// The role change through the account service, which is the path a real
	// administrative change takes: it revokes the sessions and bumps the
	// authorization generation in the same transaction. The test does not bump the
	// counter by hand, because a hand-made bump would pass even if the service
	// stopped doing it — which is the property that actually matters here.
	if err := fx.Auth.SetRole(context.Background(), fx.adminPrincipal(), fx.userID(otherName), authz.RoleDM); err != nil {
		t.Fatalf("change the role: %v", err)
	}

	text := es.waitFor(t, "the stream to end", func(string) bool { return es.isClosed() })
	reload, ok := firstEvent(parseSSE(text), httpapi.EventReload)
	if !ok {
		t.Fatalf("the stream ended without a reload event\n%s", clip(text))
	}
	var got struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(reload.data), &got); err != nil {
		t.Fatalf("the reload payload is not JSON: %v (%q)", err, reload.data)
	}
	if got.Type != httpapi.EventReload || got.Reason != httpapi.ReasonAuthz {
		t.Errorf("the reload says %+v, want type %q and reason %q", got, httpapi.EventReload, httpapi.ReasonAuthz)
	}
	// Nothing may follow the reload, and nothing may be rendered under the new
	// role: the stream is over.
	if countEvents(parseSSE(text), httpapi.EventFragment) != 0 {
		t.Errorf("a fragment was delivered after the authorization changed\n%s", clip(text))
	}
	waitUntil(t, "the registry to release the stream", func() bool { return fx.hub.Subscribers() == 0 })
}

// TestPushDropsSlowConsumer is the memory property.
//
// A subscriber that cannot keep up is dropped, not waited for. Blocking would hold
// the socket, the render goroutine and everything the render allocated for as
// long as the client's TCP window stayed shut, and one player on bad wifi would
// then be costing every other reader a goroutine; a dropped connection costs that
// client one refetch, which its reconnect contract already performs.
func TestPushDropsSlowConsumer(t *testing.T) {
	t.Parallel()

	t.Run("the byte bound", func(t *testing.T) {
		t.Parallel()
		// A page whose fragment is larger than the whole outbound bound, so a
		// single delivery cannot fit and the connection is dropped on the first
		// one. The writer never gets to run, which is the point: nothing is
		// queued, so nothing is waiting to be flushed into a socket that is not
		// draining.
		files := map[string]string{}
		for name, body := range campaignFiles {
			files[name] = body
		}
		files["Long.md"] = "---\ntitle: Long\n---\n\n# Long\n\n" + strings.Repeat("A sentence of ordinary prose. ", 6000)
		fx := newEventFixture(t, files)
		fx.accounts()
		release := newStalledWriter()
		fx.hub.SetStreamWrapper(release.wrap)
		defer release.open()

		s := fx.asUser(otherName, otherPass)
		es := fx.openStream(t, s, "Long.md")
		waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

		fx.announce("Long.md", isync.ChangeUpdated)
		waitUntil(t, "the connection to be dropped", func() bool { return fx.hub.Subscribers() == 0 })
		es.waitClosed(t, "the dropped connection to end")
		if got := fx.hub.Dropped(); got < 1 {
			t.Errorf("the connection was dropped without being counted: Dropped() is %d", got)
		}
		// The queue is released rather than left holding the bytes it was told to
		// hold, which is what "no unbounded growth" means concretely: the
		// subscriber is out of the registry and its buffer is empty.
		waitUntil(t, "the push path to release its goroutines", func() bool { return fx.hub.Goroutines() == 0 })
	})

	t.Run("the event bound", func(t *testing.T) {
		t.Parallel()
		// The byte bound masks the event bound for every real fragment — the
		// smallest is a few kilobytes, so thirty-two of them overflow thirty-two
		// kilobytes several times over — so the bound has to be moved for the
		// other one to be reachable at all.
		fx := seeded(t)
		fx.hub.SetQueueBound(1<<20, 3)
		// A window far shorter than the spacing, so an announcement is a delivery
		// of its own rather than something the window absorbs. The spacing is
		// longer than the window for the same reason.
		fx.hub.SetTimings(2*time.Millisecond, testPoll)
		release := newStalledWriter()
		fx.hub.SetStreamWrapper(release.wrap)
		defer release.open()

		s := fx.asUser(otherName, otherPass)
		es := fx.openStream(t, s, "Tavern.md")
		waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

		// Announced until the connection is dropped, rather than a fixed number of
		// times. The queue needs four deliveries to overflow, and how many
		// announcements that takes depends on how long a render takes — which is
		// exactly the kind of number a test should not hard-code.
		deadline := time.Now().Add(testTimeout)
		for fx.hub.Subscribers() > 0 && time.Now().Before(deadline) {
			fx.announce("Tavern.md", isync.ChangeUpdated)
			time.Sleep(5 * time.Millisecond)
		}
		if got := fx.hub.Subscribers(); got != 0 {
			t.Fatalf("the event bound was not reached: %d subscribers are still open", got)
		}
		es.waitClosed(t, "the dropped connection to end")
		// The writer is inside a write that will not return until the stall is
		// released, and it is the only thing left holding a goroutine.
		release.open()
		waitUntil(t, "the push path to release its goroutines", func() bool { return fx.hub.Goroutines() == 0 })
	})
}

// stalledWriter is a response writer that stops draining.
//
// It is how a slow consumer is made deterministic. Filling a real socket's
// buffers is a function of the kernel's window sizes, so a test that did it would
// be measuring the machine; a writer that blocks on a channel the test controls
// is the same condition — a subscriber that has stopped reading — arrived at
// exactly, and it is the condition the bound exists for.
type stalledWriter struct {
	release chan struct{}
	once    sync.Once
	writes  atomic.Int64
	bytes   atomic.Int64
}

// newStalledWriter returns a wrapper whose first write blocks.
func newStalledWriter() *stalledWriter {
	return &stalledWriter{release: make(chan struct{})}
}

// wrap is the StreamWriter the registry installs.
func (sw *stalledWriter) wrap(w http.ResponseWriter) http.ResponseWriter {
	return stalledResponseWriter{sw: sw, w: w}
}

// open releases every blocked write and makes later ones fail, which is what a
// client that has gone away looks like to a socket.
func (sw *stalledWriter) open() {
	sw.once.Do(func() { close(sw.release) })
}

// stalledResponseWriter forwards everything except Write, which waits.
type stalledResponseWriter struct {
	sw *stalledWriter
	w  http.ResponseWriter
}

func (s stalledResponseWriter) Header() http.Header { return s.w.Header() }

func (s stalledResponseWriter) WriteHeader(code int) { s.w.WriteHeader(code) }

func (s stalledResponseWriter) Write(p []byte) (int, error) {
	<-s.sw.release
	s.sw.writes.Add(1)
	s.sw.bytes.Add(int64(len(p)))
	return 0, errors.New("the test released a stalled connection")
}

func (s stalledResponseWriter) Flush() {
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap keeps http.ResponseController able to reach the socket.
func (s stalledResponseWriter) Unwrap() http.ResponseWriter { return s.w }

// TestPushCoalescesBurst is the coalescing test.
//
// A bulk paste that touches forty files must cost each reader one re-render and
// not forty. Two shapes of burst are asserted, because they exercise different
// halves of the mechanism: forty announcements inside one instant, which the
// invalidation bus collapses before the registry ever sees them, and forty spread
// across a window, which only the render window can collapse.
func TestPushCoalescesBurst(t *testing.T) {
	t.Parallel()

	t.Run("forty at once", func(t *testing.T) {
		t.Parallel()
		fx := seeded(t)
		var renders atomic.Int64
		fx.hub.SetRenderHook(func(string) { renders.Add(1) })
		s := fx.asUser(otherName, otherPass)
		es := fx.openStream(t, s, "Tavern.md")
		waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

		for i := 0; i < 40; i++ {
			fx.announce("Tavern.md", isync.ChangeUpdated)
		}
		text := es.waitFor(t, "the coalesced render", func(string) bool {
			return countEvents(parseSSE(es.text()), httpapi.EventFragment) >= 1
		})
		// Long enough that a second render would have happened, had the window not
		// collapsed the burst.
		time.Sleep(4 * testWindow)
		text = es.text()

		if got := countEvents(parseSSE(text), httpapi.EventFragment); got != 1 {
			t.Errorf("a burst of forty changes produced %d fragments, want 1", got)
		}
		if got := countEvents(parseSSE(text), httpapi.EventChanged); got != 1 {
			t.Errorf("a burst of forty changes produced %d triggers, want 1", got)
		}
		if got := renders.Load(); got != 1 {
			t.Errorf("a burst of forty changes reached the renderer %d times, want 1", got)
		}
		if got := fx.hub.Renders(); got != 1 {
			t.Errorf("the registry counted %d renders, want 1", got)
		}
	})

	t.Run("forty inside one window", func(t *testing.T) {
		t.Parallel()
		fx := seeded(t)
		// A window several times the spacing, so the forty announcements are
		// spread over most of it and the bus delivers them as forty separate
		// notifications. This is the case the bus cannot collapse and the render
		// window exists for.
		fx.hub.SetTimings(20*testWindow, testPoll)
		var renders atomic.Int64
		fx.hub.SetRenderHook(func(string) { renders.Add(1) })
		s := fx.asUser(otherName, otherPass)
		es := fx.openStream(t, s, "Tavern.md")
		waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

		deadline := time.Now().Add(10 * testWindow)
		for i := 0; i < 40 && time.Now().Before(deadline); i++ {
			fx.announce("Tavern.md", isync.ChangeUpdated)
			time.Sleep(testWindow / 2)
		}
		es.waitFor(t, "the coalesced render", func(string) bool {
			return countEvents(parseSSE(es.text()), httpapi.EventFragment) >= 1
		})
		time.Sleep(2 * testWindow)
		text := es.text()

		if got := countEvents(parseSSE(text), httpapi.EventFragment); got != 1 {
			t.Errorf("forty changes inside one window produced %d fragments, want 1", got)
		}
		if got := renders.Load(); got != 1 {
			t.Errorf("forty changes inside one window reached the renderer %d times, want 1", got)
		}
	})
}

// TestPushRevokeSendsReloadEvent is the revoke test.
//
// A revoke is a file mutation, a generation bump and a reindex, and the bus cannot
// tell it apart from any other content change. The server therefore decides from
// the page's own secret visibility set, read at the moment the generation moved:
// if the fences moved, the client's copy of this page is wrong and it is told to
// reload; if they did not, the client's identity is what changed.
//
// The test also carries the positive control the plan asks for: a revealed secret
// *is* pushed to the players who may read it, so a player who was online sees it
// appear. What no system can do is take it back, and the test says so.
func TestPushRevokeSendsReloadEvent(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	dm := fx.principalFor(t, dmName, authz.RoleDM)

	player := fx.asUser(otherName, otherPass)
	es := fx.openStream(t, player, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

	// Reveal, then revoke. The reveal is the interesting half: it is the one that
	// hands a new body to a player, and a client that must be told to refetch is
	// the client that gets it.
	if err := fx.Secrets.Reveal(context.Background(), dm, "a1a1a1a1a1a1"); err != nil {
		t.Fatalf("reveal the Tavern's private secret: %v", err)
	}
	text := es.waitFor(t, "the stream to end on the reveal", func(string) bool { return es.isClosed() })
	assertReloadReason(t, text, httpapi.ReasonRevoked)
	// While the secret was still private, nothing about it reached this stream.
	assertNoLeak(t, "player", text)

	// The positive control: while the secret is revealed, a player's push carries
	// it. Without this, every assertion below would also pass for a push that
	// delivered nothing at all — and the revealed one is the whole reason a
	// reveal has to end a stream rather than quietly re-render it.
	second := fx.openStream(t, player, "Tavern.md")
	waitUntil(t, "the second stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })
	fx.save(t, "Tavern.md", "Written while the secret was revealed.")
	pushed := second.waitFor(t, "the revealed secret to be pushed", func(s string) bool {
		return strings.Contains(s, "Written while the secret was revealed.")
	})
	if !strings.Contains(pushed, privateToken) {
		t.Errorf("a revealed secret was not pushed to a player who may read it, so the reload assertions prove nothing")
	}
	// The fences that did not move are still hidden, which is the assertion the
	// static model cannot make on its own any more.
	for _, token := range []string{dmToken, ownerToken, ruinToken} {
		if strings.Contains(pushed, token) {
			t.Errorf("a revealed secret was pushed alongside %q, which is still hidden", token)
		}
	}

	if err := fx.Secrets.Revoke(context.Background(), dm, "a1a1a1a1a1a1"); err != nil {
		t.Fatalf("revoke the Tavern's private secret: %v", err)
	}
	after := second.waitFor(t, "the stream to end on the revoke", func(string) bool { return second.isClosed() })
	assertReloadReason(t, after, httpapi.ReasonRevoked)
	// Nothing may follow the reload. The stream is over by then, so this asserts
	// that the revoke did not also queue a render — which is the shape of the bug
	// a "just re-render it" fix would introduce, and the one place a revoked body
	// could still be delivered.
	if after := fragmentsAfter(parseSSE(after), httpapi.EventReload); len(after) != 0 {
		t.Errorf("%d fragments were delivered after the reload that ended the stream", len(after))
	}

	// And the durable half: a stream opened after the revoke does not carry the
	// revoked body, which is the property a reader actually depends on. The
	// table-visible secret is the control that the push delivered a real render.
	third := fx.openStream(t, player, "Tavern.md")
	waitUntil(t, "the third stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })
	fx.save(t, "Tavern.md", "Written after the revoke.")
	revoked := third.waitFor(t, "the fragment after the revoke", func(s string) bool {
		return strings.Contains(s, "Written after the revoke.")
	})
	if strings.Contains(revoked, privateToken) {
		t.Error("the revoked body is still in a fragment pushed to a player")
	}
	if !strings.Contains(revoked, tableToken) {
		t.Errorf("the fragment after the revoke carries no %q either, so the assertion above cannot tell a revoked body from no render at all", tableToken)
	}
}

// fragmentsAfter counts the fragments that follow an event of the given name.
func fragmentsAfter(evs []sseEvent, after string) []sseEvent {
	var out []sseEvent
	seen := false
	for _, ev := range evs {
		if ev.name == after {
			seen = true
		}
		if seen && ev.name == httpapi.EventFragment {
			out = append(out, ev)
		}
	}
	return out
}

// assertReloadReason is the shape assertion on a reload event.
func assertReloadReason(t *testing.T, text, want string) {
	t.Helper()
	reload, ok := firstEvent(parseSSE(text), httpapi.EventReload)
	if !ok {
		t.Fatalf("no %s event arrived\n%s", httpapi.EventReload, clip(text))
	}
	var got struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(reload.data), &got); err != nil {
		t.Fatalf("the reload payload is not JSON: %v (%q)", err, reload.data)
	}
	if got.Type != httpapi.EventReload || got.Reason != want {
		t.Errorf("the reload says %+v, want type %q and reason %q", got, httpapi.EventReload, want)
	}
}

// TestPushIsCappedGloballyAndPerUser is the bound on concurrent streams.
//
// A stream is a goroutine pair, a queue and a socket, so the number of them is a
// memory argument rather than a tuning question. Over the cap the answer is a 429
// with a Retry-After, so a client that gets it falls back to ordinary fetching
// rather than reconnecting in a loop; the page it is showing keeps working
// because every surface in the app also renders without push.
func TestPushIsCappedGloballyAndPerUser(t *testing.T) {
	t.Parallel()

	t.Run("the shipped caps are the plan's", func(t *testing.T) {
		t.Parallel()
		if httpapi.MaxEventStreams != 64 || httpapi.MaxEventStreamsPerUser != 4 {
			t.Errorf("the caps are %d globally and %d per account; the plan says 64 and 4",
				httpapi.MaxEventStreams, httpapi.MaxEventStreamsPerUser)
		}
	})

	t.Run("per account", func(t *testing.T) {
		t.Parallel()
		fx := seeded(t)
		s := fx.asUser(otherName, otherPass)
		var open []*eventStream
		defer func() {
			for _, es := range open {
				es.stop()
			}
		}()
		for i := 0; i < httpapi.MaxEventStreamsPerUser; i++ {
			open = append(open, fx.openStream(t, s, "Tavern.md"))
		}
		waitUntil(t, "every stream to be registered", func() bool {
			return fx.hub.Subscribers() == httpapi.MaxEventStreamsPerUser
		})

		resp, err := s.http.Do(fx.streamRequest(t, s, "Tavern.md"))
		if err != nil {
			t.Fatalf("ask for a fifth stream: %v", err)
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("the fifth stream for one account: status %d, want 429", resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got == "" {
			t.Error("the 429 carries no Retry-After, so a client has nothing to back off on")
		}
		if got := fx.hub.Subscribers(); got != httpapi.MaxEventStreamsPerUser {
			t.Errorf("a refused stream still registered: %d subscribers, want %d", got, httpapi.MaxEventStreamsPerUser)
		}
	})

	t.Run("globally", func(t *testing.T) {
		t.Parallel()
		// Sixteen accounts at the shipped cap would be sixteen argon2id
		// derivations to test one branch, so the cap is moved and the branch is
		// what is under test. The shipped number is asserted above.
		fx := seeded(t)
		fx.hub.SetCaps(2, httpapi.MaxEventStreamsPerUser)
		first := fx.asUser(otherName, otherPass)
		second := fx.asUser(playerName, playerPass)
		open := []*eventStream{fx.openStream(t, first, "Tavern.md"), fx.openStream(t, second, "Tavern.md")}
		defer func() {
			for _, es := range open {
				es.stop()
			}
		}()
		waitUntil(t, "both streams to be registered", func() bool { return fx.hub.Subscribers() == 2 })

		// A third account, so the refusal is about the global cap and not about
		// the per-account one the previous two streams are within.
		admin := fx.asUser(adminName, adminPass)
		resp, err := admin.http.Do(fx.streamRequest(t, admin, "Tavern.md"))
		if err != nil {
			t.Fatalf("ask for a third stream: %v", err)
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("a stream over the global cap: status %d, want 429", resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got == "" {
			t.Error("the 429 carries no Retry-After")
		}
	})
}

// TestPushSendsOnlyTriggers is the erosion test.
//
// The rule is that the channel carries a trigger and never content: a trigger is
// a small JSON object naming what changed, and every assertion here is about
// keeping it that way as the code around it changes. A trigger that grew a field
// carrying a title, a length or an excerpt would be the first step towards a push
// that answers a question about the vault, and nothing else in the suite would
// notice.
//
// The fragment events are the other half of the same argument, and they are
// asserted from the other direction: their bytes must be exactly what the ordinary
// handler produced for that principal, so the content on the wire is provably the
// fetch path's and not something the push path assembled.
func TestPushSendsOnlyTriggers(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	// A DM, because the DM's fragment carries the most a fragment can carry: every
	// secret body on the page. If a trigger leaked anything, this is the stream
	// that would show it.
	s := fx.asUser(dmName, dmPass)
	es := fx.openStream(t, s, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

	fx.save(t, "Tavern.md", "Trigger-only assertions.")
	text := es.waitFor(t, "the pushed fragment", func(s string) bool {
		return strings.Contains(s, "Trigger-only assertions.")
	})
	// A reload too, so both trigger shapes are on the wire at once.
	if _, err := store.BumpAuthzGeneration(context.Background(), fx.DB.Writer()); err != nil {
		t.Fatalf("bump the authorization generation: %v", err)
	}
	text = es.waitClosed(t, "the stream to end on the generation bump")

	evs := parseSSE(text)
	if len(evs) == 0 {
		t.Fatalf("the stream carried no events at all\n%s", clip(text))
	}
	triggers, fragments := 0, 0
	for _, ev := range evs {
		switch ev.name {
		case httpapi.EventChanged, httpapi.EventReload:
			triggers++
			assertTriggerOnly(t, ev)
		case httpapi.EventFragment:
			fragments++
		default:
			t.Errorf("the stream carried an event named %q, which no client is written for", ev.name)
		}
	}
	if triggers == 0 {
		t.Errorf("no trigger was delivered, so the assertions above are vacuous\n%s", clip(text))
	}
	if fragments == 0 {
		t.Errorf("no fragment was delivered, so the stream proved nothing about a push\n%s", clip(text))
	}
	// And the fragment is the ordinary handler's output, byte for byte.
	fetched := s.text(s.fragment("/p/Tavern.md"))
	pushed, _ := firstEvent(evs, httpapi.EventFragment)
	if pushed.data != fetched {
		t.Errorf("the delivered fragment is not what the ordinary handler writes for this principal")
	}
}

// assertTriggerOnly is the rule itself.
func assertTriggerOnly(t *testing.T, ev sseEvent) {
	t.Helper()
	if len(ev.data) >= 512 {
		t.Errorf("the %s trigger is %d bytes, which is not a trigger any more", ev.name, len(ev.data))
	}
	if strings.ContainsAny(ev.data, "<") {
		t.Errorf("the %s trigger contains a %q, so it carries markup", ev.name, "<")
	}
	if strings.Contains(ev.data, "secret") {
		t.Errorf("the %s trigger mentions a secret: %q", ev.name, ev.data)
	}
	var got struct {
		Type   string `json:"type"`
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(ev.data), &got); err != nil {
		t.Errorf("the %s trigger is not a JSON object: %v (%q)", ev.name, err, ev.data)
		return
	}
	if got.Type != ev.name {
		t.Errorf("the %s trigger's own type field says %q", ev.name, got.Type)
	}
	if got.Type == httpapi.EventReload && got.Reason == "" {
		t.Errorf("a reload trigger carries no reason: %q", ev.data)
	}
	if got.Type == httpapi.EventChanged && got.Path == "" {
		t.Errorf("a changed trigger names no page: %q", ev.data)
	}
}

// TestEventsAreCancelledWhenTheClientGoesAway is the lifecycle test.
//
// A client that closes its tab must leave nothing behind: no registry entry, which
// is the connection's place in the caps, and no goroutine, which is the render
// loop, the writer and the generation watcher. The count the assertion uses is
// this registry's own counter rather than the process's, because a process-wide
// count cannot tell whose goroutines they are and a test that measured the wrong
// one would be a test that measures nothing.
func TestEventsAreCancelledWhenTheClientGoesAway(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	s := fx.asUser(otherName, otherPass)
	es := fx.openStream(t, s, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })
	// One render and one write, so that both loops have been entered and the
	// teardown has something to tear down.
	fx.save(t, "Tavern.md", "Written before the client left.")
	es.waitFor(t, "the pushed fragment", func(s string) bool {
		return strings.Contains(s, "Written before the client left.")
	})

	es.stop()
	es.waitClosed(t, "the server to notice the client is gone")
	waitUntil(t, "the registry to release the stream", func() bool { return fx.hub.Subscribers() == 0 })
	waitUntil(t, "every push goroutine to exit", func() bool { return fx.hub.Goroutines() == 0 })
	if got := fx.hub.Renders(); got < 1 {
		t.Errorf("no render was counted, so the teardown had nothing to release (%d)", got)
	}

	// And the cap is genuinely available again, which is the registry entry's only
	// purpose: a connection that stayed would have consumed one of the four.
	// Opened through the stream helper so that the cleanup closes it, because a
	// body that is read to EOF on an event stream never ends.
	fx.openStream(t, s, "Tavern.md")
	waitUntil(t, "the reopened stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })
}

// TestTripwireAlsoCoversPushWrites is the tripwire's second half.
//
// The leak tripwire watches responses. A push is a second way for bytes to reach
// a player, through a writer the ordinary response path never sees, so the scanner
// has to be installed on the stream's writer too — and proving that requires both
// halves: that the scanner saw the stream's bytes, and that the scanner would
// have caught a leak if there had been one.
func TestTripwireAlsoCoversPushWrites(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	// Armed with what this principal may *not* read, which is how the ordinary
	// tripwire is armed too: a scanner holding every token would fire on the one
	// body a player is entitled to and report a leak where there is none.
	scanner := &leakScanner{armed: forbiddenFor("player")}
	fx.hub.SetStreamWrapper(scanner.wrap)

	s := fx.asUser(otherName, otherPass)
	es := fx.openStream(t, s, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })
	fx.save(t, "Tavern.md", "Watched by the tripwire.")
	text := es.waitFor(t, "the pushed fragment", func(s string) bool {
		return strings.Contains(s, "Watched by the tripwire.")
	})

	if scanner.written.Load() == 0 {
		t.Fatal("the tripwire's writer was installed but saw no bytes at all, so it is not watching this stream")
	}
	assertNoLeak(t, "player", text)
	if got := scanner.found(); len(got) != 0 {
		t.Errorf("the tripwire's writer found %v in a player's stream", got)
	}

	// The positive control: the same scanner over the same page as a principal who
	// may read all of it. A scanner that reports nothing because it is broken is
	// the failure a negative assertion like this one cannot see.
	dm := fx.asUser(dmName, dmPass)
	dmFragment := dm.text(dm.fragment("/p/Tavern.md"))
	control := &leakScanner{armed: forbiddenFor("player")}
	control.inspect([]byte(dmFragment))
	if got := control.found(); len(got) == 0 {
		t.Errorf("the scanner found nothing in the DM's own fragment, so its silence above is not evidence\n%s", clip(dmFragment))
	}
}

// forbiddenFor is the set a scanner is armed with for a role: the tokens that
// role may not read.
func forbiddenFor(role string) []string {
	var out []string
	for _, token := range bodyTokens {
		if !mayRead(role, token) {
			out = append(out, token)
		}
	}
	return out
}

// leakScanner is the tripwire over a response writer.
//
// It is the same assertion the tripwire makes over an ordinary response — no
// fixture token this principal may not read, anywhere in the bytes — applied to
// the writer a stream is served through. It counts what it saw as well as what it
// found, because "found nothing" and "was not watching" are otherwise
// indistinguishable.
type leakScanner struct {
	armed   []string
	written atomic.Int64
	mu      sync.Mutex
	leaks   []string
}

// wrap is the StreamWriter the registry installs.
func (ls *leakScanner) wrap(w http.ResponseWriter) http.ResponseWriter {
	return scannedWriter{scanner: ls, w: w}
}

// inspect looks at a block of bytes.
func (ls *leakScanner) inspect(b []byte) {
	ls.written.Add(int64(len(b)))
	for _, token := range ls.armed {
		if bytes.Contains(b, []byte(token)) {
			ls.mu.Lock()
			ls.leaks = append(ls.leaks, token)
			ls.mu.Unlock()
		}
	}
}

// found is what the scanner has seen, deduplicated for a readable failure.
func (ls *leakScanner) found() []string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, token := range ls.leaks {
		if !seen[token] {
			seen[token] = true
			out = append(out, token)
		}
	}
	return out
}

// scannedWriter forwards everything and looks at the bytes.
type scannedWriter struct {
	scanner *leakScanner
	w       http.ResponseWriter
}

func (s scannedWriter) Header() http.Header { return s.w.Header() }

func (s scannedWriter) WriteHeader(code int) { s.w.WriteHeader(code) }

func (s scannedWriter) Write(p []byte) (int, error) {
	s.scanner.inspect(p)
	return s.w.Write(p)
}

func (s scannedWriter) Flush() {
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap keeps http.ResponseController able to reach the socket.
func (s scannedWriter) Unwrap() http.ResponseWriter { return s.w }

// readAndClose reads a body for a failure message and closes it.
func readAndClose(resp *http.Response) string {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "could not read the body: " + err.Error()
	}
	return string(body)
}
