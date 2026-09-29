package httpapi_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// TestCSRFRequiredOnAllMutations is derived from the route table, not from a
// hand-written list.
//
// The set of routes that need a token is read out of Routes() at test time: every
// row whose method is not GET or HEAD. A route added to the table tomorrow is
// covered tomorrow with no edit here, and a route whose method changes from POST
// to GET stops being checked with no edit either. A test that restated the list
// would be a test of the list.
//
// It runs the whole table twice, once against a vault with accounts and once
// against a vault with none, because one route exists in exactly one of those
// states: /setup is a 404 once the first administrator is claimed, and a 404 that
// looks like a refusal is not the CSRF gate answering. Between the two runs every
// mutating row is exercised in a state where it exists, which is asserted rather
// than assumed.
//
// Each row is performed five ways, because a gate that refuses only one of them is
// not a gate:
//
//   - no token at all;
//   - a well-formed token belonging to a *different* session, which is what a
//     cross-origin attacker who has read any page could construct;
//   - a well-formed token belonging to nobody;
//   - a value that is not token-shaped at all;
//   - and, as the control, the row's own token, which must be accepted.
func TestCSRFRequiredOnAllMutations(t *testing.T) {
	t.Parallel()
	// One map for both states, because coverage is a property of the test rather
	// than of a run: a route that exists in exactly one of the two states is
	// covered by the pair. The two runs are therefore sequential — the cost is a
	// few seconds of argon2id, and the alternative is a mutex around a map that
	// exists only to let two goroutines disagree about it.
	checked := map[string]bool{}

	for _, state := range []struct {
		name    string
		prepare func(*fixture)
		signed  bool
	}{
		{name: "with accounts", prepare: func(fx *fixture) { fx.onePlayer() }, signed: true},
		{name: "with no accounts", prepare: func(*fixture) {}, signed: false},
	} {
		t.Run(state.name, func(t *testing.T) {
			// The table is read from one fixture and each row is then exercised on
			// a fixture of its own. A fixture per row is not tidiness: the rate
			// limiter is per server and per address, and a whole table driven from
			// one fixture spends the login budget on its own refusals and then
			// measures the limiter instead of the gate. Four argon2id derivations
			// and four index passes buy a table whose failures all mean something.
			template := newFixture(t)
			state.prepare(template)
			mutations := mutationsOf(template)
			if len(mutations) == 0 {
				t.Fatal("the route table has no mutating routes, so this test would pass vacuously")
			}
			if got, want := len(mutations), mutatingRouteCount(template); got != want {
				t.Fatalf("found %d mutating routes, want %d", got, want)
			}

			for _, rt := range mutations {
				t.Run(rt.Name(), func(t *testing.T) {
					fx := newFixture(t)
					state.prepare(fx)
					victim := fx.newSession()
					if state.signed {
						victim = fx.asUser(otherName, otherPass)
						// A page-scoped write needs a principal the route's
						// coarse gate admits, and that is a DM or an admin:
						// permit asks the policy with a zero Resource, so the
						// player this test signs in as is refused before the
						// handler runs. A control run refused by the gate
						// measures the gate, not the token — and there is no
						// state in which a player can be the control for
						// these rows, so the row would otherwise be skipped
						// in both states and the coverage assertion at the
						// bottom would fail.
						if admin, ok := fx.tryAdminSession(); ok && needsAWriter(rt) {
							victim = admin
						}
					} else {
						victim.prime()
					}
					allowed := statusOfRoute(fx, victim, rt, rt.Method, true)
					if !isAccepted(allowed) {
						// The route does not exist for this principal in this state;
						// the other run covers it. Recorded rather than skipped
						// silently, so the coverage assertion below can fail.
						t.Skipf("the route does not exist for this principal in this state: %d", allowed)
					}
					checked[rt.Name()] = true
					assertRefused(t, fx, victim, rt, "no token", false)
					assertRefused(t, fx, victim, rt, "a token from another session", true)
					assertRefused(t, fx, victim, rt, "an invented token", false)
					assertRefused(t, fx, victim, rt, "a value that is not a token", false)
				})
			}
		})
	}

	// Every mutating route must have been exercised somewhere. A route that was
	// skipped in both states is a hole, and the hole is the reason this test is
	// derived from the table rather than from a list.
	probe := newFixture(t)
	for _, rt := range mutationsOf(probe) {
		if !checked[rt.Name()] {
			t.Errorf("%s was never exercised in a state where it exists", rt.Name())
		}
	}
}

// isAccepted reports whether a status means the request went through.
func isAccepted(status int) bool {
	switch status {
	case http.StatusOK, http.StatusSeeOther, http.StatusCreated, http.StatusNoContent:
		return true
	default:
		return false
	}
}

// assertRefused performs one mutating request with a broken token and asserts the
// gate refused it.
//
// A CSRF refusal is a 403 and nothing else. A redirect would mean the request was
// handled, and a 404 would mean the test was measuring the router rather than the
// gate — which is why the control run established the row's own answer first.
func assertRefused(t *testing.T, fx *fixture, s *session, rt httpapi.Route, what string, foreign bool) {
	t.Helper()
	c := &call{method: rt.Method, path: concretePath(fx, rt)}
	c.form = routeFormFor(fx, rt)
	switch {
	case foreign:
		// A token minted for a different session: a reader of any page could
		// build this, so it is the case that matters most.
		other := fx.newSession()
		other.prime()
		c.csrf = other.csrf
	case what == "an invented token":
		c.badCSRF = true
	case what == "a value that is not a token":
		c.noCSRF = true
		c.body = withCSRFField(routeFormFor(fx, rt), "x")
	default:
		c.noCSRF = true
	}
	resp := s.do(c)
	got := resp.StatusCode
	drain(resp)
	if got != http.StatusForbidden {
		t.Errorf("%s: status %d, want 403", what, got)
	}
}

// withCSRFField returns a copy of a form with the token field replaced, for the
// case where the token is submitted in the body rather than in a header.
func withCSRFField(form url.Values, token string) string {
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	out.Set("csrf", token)
	return out.Encode()
}

// mutationsOf is the mutating half of the route table: every row whose method is
// not GET or HEAD. It is read from the table at test time rather than restated, so
// the list of gated routes is the list of routes.
func mutationsOf(fx *fixture) []httpapi.Route {
	var out []httpapi.Route
	for _, rt := range fx.Server.Routes() {
		if rt.Mutating() {
			out = append(out, rt)
		}
	}
	return out
}

// mutatingRouteCount counts the mutating rows a second way, so the assertion that
// mutationsOf found them all cannot be satisfied by mutationsOf returning whatever
// it happened to return.
func mutatingRouteCount(fx *fixture) int {
	n := 0
	for _, rt := range fx.Server.Routes() {
		switch rt.Method {
		case http.MethodGet, http.MethodHead:
		default:
			n++
		}
	}
	return n
}

// concretePath fills a route's pattern in with a path the fixture has.
func concretePath(fx *fixture, rt httpapi.Route) string {
	switch rt.Pattern {
	case "/invite/{token}":
		return "/invite/" + fixtureInviteToken(fx)
	case "/p/*/raw":
		return "/p/Index.md/raw"
	case "/p/*/edit":
		return "/p/Index.md/edit"
	case "/p/*/history":
		return "/p/Index.md/history"
	case "/p/*/revisions/{revID}":
		return "/p/Index.md/revisions/1"
	case "/p/*/revert/{revID}":
		// A real revert needs a real revision, and a vault has none until
		// something writes one. So the control run for this route makes one
		// through the ordinary save path first — which is the only way a
		// revision can come into existence — and then names the newest. A
		// non-existent id would answer 404, and a control run that is refused
		// measures the revision lookup rather than the token.
		return "/p/Index.md/revert/" + fixtureNewestRevisionID(fx)
	case "/p/*/attachment/{name...}":
		return "/p/Index.md/attachment/tavern-map.png"
	case "/api/pages/{id}/rename":
		// Page 3 is Tavern.md, which the fixture makes thia a page owner of, so
		// the control run is a rename by someone entitled to make it. needsAWriter
		// below is what makes that sign-in happen; a path alone does not.
		return "/api/pages/3/rename"
	case "/api/pages/{id}/update-links":
		return "/api/pages/3/update-links"
	default:
		return rt.Pattern
	}
}

// fixtureNewestRevisionID produces one revision of the fixture's index page by
// saving it unchanged, and returns its id.
//
// Saving the page's own bytes with its own hash is a real write that is also a
// no-op as far as the campaign is concerned, which is what makes it usable as a
// control: the refusal cases that follow must still find the page as it was, and
// they do, because a save of identical bytes writes identical bytes.
func fixtureNewestRevisionID(fx *fixture) string {
	fx.t.Helper()
	fx.revisionOnce.Do(func() {
		fx.newestRevision = "1"
		path := filepath.Join(fx.Root, "Index.md")
		src, err := os.ReadFile(path)
		if err != nil {
			return
		}
		p, err := vault.Resolve(fx.Root, "Index.md")
		if err != nil {
			return
		}
		// The fixture's own writer, so the revision is recorded by the same
		// mechanism the route uses and not by a test-only insert.
		if err := fx.Vault.Save(context.Background(), vault.SaveRequest{
			Path:            p.Rel(),
			NewContent:      src,
			BaseContentHash: vault.Hash(src),
			ActorID:         fx.tryAdminPrincipal().UserID,
			ExpectPerm:      authz.PermWritePage,
		}); err != nil {
			return
		}
		fx.reindexAll()
		page, ok := fx.pageIDByPath("Index.md")
		if !ok {
			return
		}
		rows, err := store.ListRevisionMetaByPage(context.Background(), fx.DB.Reader(), page, 10)
		if err != nil || len(rows) == 0 {
			return
		}
		fx.newestRevision = strconv.FormatInt(rows[0].ID, 10)
	})
	return fx.newestRevision
}

// routeFormFor is a body that satisfies a mutating route's handler, so that a
// refusal is about the token and not about a field the handler never read.
//
// It is a per-route switch rather than one blanket form because a blanket form
// would let a handler that returned early on a missing field pass a test that is
// meant to be about the gate.
func routeFormFor(fx *fixture, rt httpapi.Route) url.Values {
	switch rt.Pattern {
	case "/login":
		return url.Values{"username": {otherName}, "passphrase": {otherPass}}
	case "/setup":
		// A username the validator refuses, deliberately. The control run has to
		// exercise the route without changing the world: a form that claimed the
		// first administrator would close /setup for the three refusal cases that
		// follow it, and they would then be measuring the route's absence rather
		// than the gate. The handler answers a refused field by re-rendering the
		// form, which is an accepted response and claims nothing.
		return url.Values{"username": {"x"}, "display_name": {"New Name"}, "passphrase": {"a passphrase long enough"}}
	case "/invite/{token}":
		return url.Values{"username": {"newname"}, "passphrase": {"a passphrase long enough"}}
	case "/p/*/edit":
		// A real save, not a refused one. The editor is the one mutating route
		// whose refusal answers 400 and its success answers 200, and the control
		// run has to be the success — the whole point of the row is that a bad
		// token is refused on a route that does work with a good one. The base
		// hash is the page's own, read from the fixture's file, and the content
		// is the page's own bytes, so the write is a no-op as far as the campaign
		// is concerned and the three refusals after it still find the page intact.
		src, err := os.ReadFile(filepath.Join(fx.Root, "Index.md"))
		if err != nil {
			return url.Values{"content": {"# Index\n"}, "base_hash": {""}}
		}
		return url.Values{"content": {string(src)}, "base_hash": {vault.HashHex(src)}}
	case "/p/*/revert/{revID}":
		// A revert takes no fields: the revision is in the path and the token
		// travels in the header, the way a script would send it. An empty form is
		// the honest one rather than a placeholder a handler might read.
		return url.Values{}
	case "/api/pages/{id}/rename":
		// A real rename, not a refused one: the control run has to be the
		// success, and Tavern.md's name is free to be taken.
		return url.Values{"new": {"The Drowned Lantern Inn"}}
	case "/api/pages/{id}/update-links":
		// confirmed is not a formality. Without it the route answers 400 and
		// touches nothing, which is not an accepted response and would make the
		// row skip in both states.
		return url.Values{"new": {"The Inn"}, "confirmed": {"true"}}
	default:
		return url.Values{}
	}
}

// fixtureInviteToken mints an invite so the invite route has a real token to
// carry. It is a read of the fixture's own state, not a second way to create an
// account.
//
// On a vault with no administrator there is nobody to mint one, and the route
// still has to be reachable for the CSRF table to be complete. A well-formed token
// that was never issued is exactly what a stranger would present, and the
// redemption path answers it with the form and a problem, which is an accepted
// response.
func fixtureInviteToken(fx *fixture) string {
	fx.t.Helper()
	fx.inviteOnce.Do(func() {
		token, err := fx.Auth.CreateInvite(context.Background(), fx.tryAdminPrincipal(), "player", time.Hour)
		if err != nil {
			fx.invite = "0123456789abcdef01234567"
			return
		}
		fx.invite = token
	})
	return fx.invite
}

// TestTheMiddlewareChainIsInOrder walks the chain the router was built with.
//
// The order is a comment, and a comment is not a property. This asserts it
// behaviourally: the request logger's record must carry the request id, which is
// only true if RequestID is outside it, and a response must carry the security
// headers even when the handler never ran, which is only true if SecureHeaders is
// outside everything that can fail.
func TestTheMiddlewareChainIsInOrder(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)

	t.Run("the request id reaches the response", func(t *testing.T) {
		t.Parallel()
		resp := s.do(s.get("/p/Index.md"))
		defer drain(resp)
		if resp.Header.Get("X-Request-Id") == "" {
			t.Error("no X-Request-Id header: the id middleware is inside something it should be outside")
		}
	})

	t.Run("the security headers are on a refused response too", func(t *testing.T) {
		t.Parallel()
		// A 404 from the router's NotFound handler is written without touching a
		// session, so a missing header here means the header middleware is inside
		// the router rather than outside it.
		anon := fx.newSession()
		resp := anon.do(anon.get("/no-such-route"))
		defer drain(resp)
		// HSTS is deliberately absent here: this fixture is bound to a loopback
		// address, and the sibling subtest below is where a routable bind is
		// checked. Sending it on loopback would pin http://127.0.0.1 to https.
		for header, want := range map[string]string{
			"Content-Security-Policy": "default-src 'self'",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "same-origin",
			"X-Frame-Options":         "DENY",
			"Permissions-Policy":      "camera=()",
		} {
			got := resp.Header.Get(header)
			if !strings.HasPrefix(got, want) {
				t.Errorf("%s is %q, want a value starting %q", header, got, want)
			}
		}
	})

	t.Run("no remote origin and no unsafe-eval in the policy", func(t *testing.T) {
		t.Parallel()
		anon := fx.newSession()
		resp := anon.do(anon.get("/"))
		defer drain(resp)
		csp := resp.Header.Get("Content-Security-Policy")
		for _, forbidden := range []string{"unsafe-eval", "unsafe-inline", "http://", "https://", "//cdn", "data: script"} {
			if strings.Contains(csp, forbidden) {
				t.Errorf("the content security policy contains %q: %s", forbidden, csp)
			}
		}
	})

	t.Run("hsts is sent for a non-loopback bind", func(t *testing.T) {
		t.Parallel()
		lan := newFixture(t, func(c *config.Config) { c.Host = "192.168.1.10" })
		anon := lan.newSession()
		resp := anon.do(anon.get("/login"))
		defer drain(resp)
		if resp.Header.Get("Strict-Transport-Security") == "" {
			t.Error("no HSTS on a server bound to a routable address")
		}
		loop := newFixture(t)
		anon2 := loop.newSession()
		resp2 := anon2.do(anon2.get("/login"))
		defer drain(resp2)
		if got := resp2.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS is %q on a loopback bind, where it would pin http://127.0.0.1 to https", got)
		}
	})
}

// TestLoginRotatesTheSession asserts that a login presented with a token
// replaces that token rather than adding a second one.
//
// Rotation is the property that matters and it is scoped correctly here: the
// session service revokes the token the *client presented* and issues a new one,
// so a token captured before a re-login on the same client stops working. Two
// clients that never met are two sessions, and that is not a rotation — it is two
// people on two devices, and the test below says so rather than leaving the
// question open.
func TestLoginRotatesTheSession(t *testing.T) {
	t.Parallel()

	t.Run("a re-login on the same client replaces the token", func(t *testing.T) {
		t.Parallel()
		// Its own fixture: the assertion is a count over one account's live
		// sessions, and the sibling subtest signs the same account in twice. Two
		// subtests counting each other's logins is a test that measures the test.
		fx := newFixture(t)
		fx.accountsFor()
		s := fx.newSession()
		resp := s.login(otherName, otherPass)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("the first login answered %d, want 303", resp.StatusCode)
		}
		drain(resp)
		first := fx.cookieValue(s, httpapi.SessionCookie)
		if first == "" {
			t.Fatal("the first login set no session cookie")
		}

		// The second login presents the first token, exactly as a browser does
		// with its cookie jar.
		again := fx.newSession().withJar(s.jar)
		resp = again.login(otherName, otherPass)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("the second login answered %d, want 303", resp.StatusCode)
		}
		drain(resp)
		second := fx.cookieValue(again, httpapi.SessionCookie)
		if second == "" {
			t.Fatal("the second login set no session cookie")
		}
		if first == second {
			t.Error("the second login issued the same token as the first; a re-login must rotate")
		}
		if who, err := fx.Auth.Session(context.Background(), first); err != nil || who.Authenticated() {
			t.Errorf("the superseded token still resolves: principal %+v, err %v", who, err)
		}
		if who, err := fx.Auth.Session(context.Background(), second); err != nil || !who.Authenticated() {
			t.Errorf("the new token does not resolve: principal %+v, err %v", who, err)
		}
		if got := fx.liveSessionCount(fx.userID(otherName)); got != 1 {
			t.Errorf("the account has %d live sessions after a rotation, want 1: %s", got, fx.sessionRows(fx.userID(otherName)))
		}
		// And the client that rotated can still read the campaign, which is the
		// other half: a rotation that logs everybody out is not a rotation.
		again.getOK("/p/Index.md")
	})

	t.Run("two clients that never met are two sessions", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t)
		fx.accountsFor()
		phone := fx.newSession()
		drain(phone.login(otherName, otherPass))
		laptop := fx.newSession()
		drain(laptop.login(otherName, otherPass))
		if got := fx.liveSessionCount(fx.userID(otherName)); got < 2 {
			t.Errorf("two independent logins produced %d live sessions; a second device is not a rotation and must not be revoked", got)
		}
		if first, second := fx.cookieValue(phone, httpapi.SessionCookie), fx.cookieValue(laptop, httpapi.SessionCookie); first == second {
			t.Error("two independent logins issued the same token, so a rotation would revoke both")
		}
	})
}

// TestLogoutInvalidatesTheSession asserts that a sign-out is a server-side fact
// and not a cookie the client forgot to send.
func TestLogoutInvalidatesTheSession(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)
	token := fx.cookieValue(s, httpapi.SessionCookie)
	if token == "" {
		t.Fatal("the sign-in set no session cookie")
	}
	// The page is readable now.
	s.getOK("/p/Index.md")

	resp := s.do(&call{method: http.MethodPost, path: "/logout", form: url.Values{"csrf": {"x"}}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the sign-out answered %d, want 303", resp.StatusCode)
	}
	drain(resp)

	if who, err := fx.Auth.Session(context.Background(), token); err != nil || who.Authenticated() {
		t.Errorf("the session still resolves after a sign-out: principal %+v, err %v", who, err)
	}
	if got := fx.liveSessionCount(fx.userID(otherName)); got != 0 {
		t.Errorf("the account has %d live sessions after signing out, want 0", got)
	}
	// And a client that replays the old cookie gets the anonymous answer, not the
	// page it was reading a moment ago.
	replay := s.do(s.get("/p/Index.md"))
	defer drain(replay)
	if replay.StatusCode != http.StatusSeeOther {
		t.Errorf("a replayed session cookie after a sign-out: status %d, want 303 to the login form", replay.StatusCode)
	}
}

// TestRateLimitRefusesTheEleventhLoginInAMinute is the reason the login limit
// exists at all: an Argon2id verification costs about 130 ms of memory-hard
// work, so an unthrottled login form is a denial-of-service amplifier aimed at a
// single-connection write pool.
func TestRateLimitRefusesTheEleventhLoginInAMinute(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	for i := 1; i <= 10; i++ {
		s := fx.newSession()
		s.prime()
		resp := s.do(&call{
			method: http.MethodPost, path: "/login",
			form: url.Values{"username": {otherName}, "passphrase": {otherPass}}, csrf: s.token(),
		})
		got := resp.StatusCode
		drain(resp)
		if got == http.StatusTooManyRequests {
			t.Fatalf("login attempt %d was refused; the budget is 10 a minute", i)
		}
	}
	s := fx.newSession()
	s.prime()
	resp := s.do(&call{
		method: http.MethodPost, path: "/login",
		form: url.Values{"username": {otherName}, "passphrase": {otherPass}}, csrf: s.token(),
	})
	defer drain(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the eleventh login in a minute: status %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a 429 with no Retry-After: the client is not told how long to wait")
	}

	// Moving the clock on refills the bucket, which is what makes the limit a rate
	// rather than a total.
	fx.Clock.advance(90 * time.Second)
	s2 := fx.newSession()
	s2.prime()
	resp2 := s2.do(&call{
		method: http.MethodPost, path: "/login",
		form: url.Values{"username": {otherName}, "passphrase": {otherPass}}, csrf: s2.csrf,
	})
	got := resp2.StatusCode
	drain(resp2)
	if got == http.StatusTooManyRequests {
		t.Error("a login a minute and a half later was still refused; the limiter is not refilling")
	}
}

// TestTheSearchBudgetIsLowerThanTheGeneralOne pins the second of the three
// budgets, because a search is the one query a client can make arbitrarily
// expensive and a page view is not.
func TestTheSearchBudgetIsLowerThanTheGeneralOne(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)

	// A page view is cheap enough that 40 of them are fine.
	for i := 0; i < 40; i++ {
		resp := s.do(s.get("/p/Index.md"))
		got := resp.StatusCode
		drain(resp)
		if got == http.StatusTooManyRequests {
			t.Fatalf("page view %d was refused; the general budget is 300 a minute", i+1)
		}
	}
	// Thirty searches is the whole search budget; the thirty-first is refused.
	for i := 0; i < 30; i++ {
		resp := s.do(s.get("/search?q=lantern"))
		got := resp.StatusCode
		drain(resp)
		if got == http.StatusTooManyRequests {
			t.Fatalf("search %d was refused; the search budget is 30 a minute", i+1)
		}
	}
	resp := s.do(s.get("/search?q=lantern"))
	defer drain(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the thirty-first search in a minute: status %d, want 429", resp.StatusCode)
	}
}

// TestNoRenderedPageCache is the test for §2.8.
//
// There is deliberately no rendered-page cache in stage 1, and this is what fails
// if one appears. It asks the same server, with the same warm caches, for the same
// page as two principals who may see different amounts of it, and asserts that
// each got what *they* may see. A cache keyed by page id alone passes the
// functional tests everywhere else in the project and fails exactly here.
func TestNoRenderedPageCache(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	player := fx.asUser(otherName, otherPass)
	dm := fx.asUser(dmName, dmPass)

	// Interleave the two so a cache that fills on the first read and serves on the
	// next cannot pass by luck.
	for i := 0; i < 3; i++ {
		playerBody := player.getOK("/p/Tavern.md")
		dmBody := dm.getOK("/p/Tavern.md")

		assertNoToken(t, playerBody, "DM-BODY-TOKEN-7b1e4d", "the dm secret, read by a player")
		assertNoToken(t, playerBody, "PRIVATE-BODY-TOKEN-9f3a2c", "a private secret, read by a non-owner")
		assertHasToken(t, dmBody, "DM-BODY-TOKEN-7b1e4d", "the dm secret, read by a dm")
		assertHasToken(t, dmBody, "PRIVATE-BODY-TOKEN-9f3a2c", "a private secret, read by a dm")

		if playerBody == dmBody {
			t.Fatalf("round %d: a player and a dm received byte-identical bodies for the same page, so the response is being cached", i)
		}
	}
	// And the reverse order, because a cache that only keeps the first answer for
	// a second would pass the loop above and fail here.
	dmFirst := dm.getOK("/p/Tavern.md")
	playerSecond := player.getOK("/p/Tavern.md")
	assertHasToken(t, dmFirst, "DM-BODY-TOKEN-7b1e4d", "the dm secret, read first")
	assertNoToken(t, playerSecond, "DM-BODY-TOKEN-7b1e4d", "the dm secret, read second by a player")
}

// TestConcurrentRequestsForOnePageAreIndependent says the same thing across
// goroutines, which is where a shared cache would actually be shared.
func TestConcurrentRequestsForOnePageAreIndependent(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	player := fx.asUser(otherName, otherPass)
	dm := fx.asUser(dmName, dmPass)

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			body := player.getOK("/p/Tavern.md")
			if strings.Contains(body, "DM-BODY-TOKEN-7b1e4d") {
				errs <- "a concurrent player's read carried a dm secret"
			}
		}()
		go func() {
			defer wg.Done()
			body := dm.getOK("/p/Tavern.md")
			if !strings.Contains(body, "DM-BODY-TOKEN-7b1e4d") {
				errs <- "a concurrent dm's read lost the dm secret"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// needsAWriter reports whether a route's gate admits only a DM or an admin.
//
// The answer is a property of the table's permission, not of this test, and it is
// read from the table rather than kept as a list here: a route that gains or
// loses a coarse gate would be picked up with no edit to this file, which is the
// property the rest of this test is built on. Only a write permission can be
// satisfied without a resource, so only a write can be closed to a player while
// the table still says the route exists.
func needsAWriter(rt httpapi.Route) bool {
	switch rt.Perm {
	case authz.PermWritePage, authz.PermWriteSecret, authz.PermDM, authz.PermAdmin:
		return true
	}
	// The page-scoped writes are PermSession in the table — see routes.go for
	// why — so the column says nothing about whether the route writes, and the
	// control run has to sign in as the page owner rather than as whoever
	// `otherName` is. Naming the patterns rather than the permission keeps every
	// other row on the session it already used.
	switch rt.Pattern {
	case "/p/*/edit", "/p/*/revert/{revID}",
		"/api/pages/{id}/rename", "/api/pages/{id}/update-links":
		return true
	}
	return false
}
