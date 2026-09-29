package httpapi_test

import (
	"net/http"
	"slices"

	"strings"
	"testing"
)

// TestTripwireFiresOnLeak is the proof that the leak scanner has teeth, and it is
// a test rather than a claim because "the tripwire would catch it" is the one
// sentence in this package nobody can check by reading the code.
//
// **The scanner is a test instrument. The server does not have one.** The plan's
// §18 also describes a *runtime* response scanner and
// `docs/spec.md`'s divergence 11 records that it does not exist; nothing here
// changes that, and nothing here may be read as evidence that a leak in
// production would be caught at runtime. What this test proves is narrower and is
// the only thing that can be proved from the test side: the scanner, installed
// over the ordinary response path, **sees every byte the client receives and
// reports a fixture body when it is armed to** — over a real handler, over a
// real session, and over a stub for the case no route in this build produces.
//
// Three arms, and the order matters because each is the control for the one
// before it:
//
//  1. **It reports.** The same handler and the same reader, with the scanner armed
//     as though the reader were entitled to nothing. A DM's page view really does
//     contain the dm secret's body, so an over-armed scanner must find it. This
//     is a real response from the real router carrying a real secret — the only
//     forced thing about it is the arming, which is exactly the shape of the bug
//     the scanner exists to find: a wire that disagrees with the authorization.
//  2. **It reports nothing, and it was watching.** The same handler and the same
//     reader, armed correctly. Reports nothing, and `written` is greater than
//     zero. A scanner that is silent because it saw nothing and a scanner that is
//     silent because it was not in the path are the same observation, and this is
//     what tells them apart.
//  3. **It reports a body no route in this build can produce.** A stub that writes
//     a fixture body, wrapped in the same scanner. The honest floor: the teeth do
//     not depend on there being a leak to find today.
//
// And a fourth assertion that is not about the scanner at all: the bytes it
// counted are the bytes the client received, which is what makes "it saw the
// whole response" a statement about the response rather than about the wrapper.
func TestTripwireFiresOnLeak(t *testing.T) {
	t.Parallel()

	t.Run("it reports a real secret body served through the ordinary path", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t)
		fx.accountsFor()
		armed := &leakScanner{armed: []string{dmBodyToken}}
		served := viewOver(t, fx, scanningHandler{scanner: armed, next: fx.Server.Handler()})
		s := served.asUser(dmName, dmPass)

		body := s.getOK("/p/Tavern.md")
		if got := armed.found(); len(got) != 1 || got[0] != dmBodyToken {
			t.Errorf("the scanner over the ordinary response path reported %v, want exactly the %s token: a scanner that does not fire on a real secret body in a real response cannot be trusted to fire on one", got, dmBodyToken)
		}
		// And the body is real, not a scanner reading its own arming: the token
		// is in what the client got, and the client is the same one.
		if !strings.Contains(body, dmBodyToken) {
			t.Error("the page the scanner was pointed at does not carry the token the scanner reported, so the scanner and the client were not looking at the same response")
		}
		if armed.written.Load() == 0 {
			t.Error("the scanner counted no bytes, so it reported something it never read")
		}
	})

	t.Run("it reports nothing on a clean response and was watching while it did", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t)
		fx.accountsFor()
		// Armed with the forbidden set: everything the player may not read. That
		// is what a scanner is armed with everywhere in this package, and the
		// arming is the whole point of the instrument — a scanner armed with what
		// a principal *may* read fires on every correct page and means nothing.
		armed := &leakScanner{}
		for _, token := range bodyTokens {
			if !bodyTokenReaders[token][rolePlayer] {
				armed.armed = append(armed.armed, token)
			}
		}
		if len(armed.armed) == 0 {
			t.Fatal("a player is entitled to every token, so the scanner is armed with nothing and the subtest below would pass for that reason rather than for a real one")
		}
		served := viewOver(t, fx, scanningHandler{scanner: armed, next: fx.Server.Handler()})
		s := served.asUser(otherName, otherPass)

		for _, path := range []string{"/p/Tavern.md", "/p/Ruin.md", "/p/characters/Thia.md"} {
			before := armed.written.Load()
			s.getOK(path)
			if armed.written.Load() == before {
				t.Errorf("%s: the scanner counted no bytes, so it reported nothing because it was not in the path rather than because the response was clean", path)
			}
		}
		if got := armed.found(); len(got) != 0 {
			t.Errorf("the scanner reported %v on a player's reads of three pages, which carry a secret the player may not read", got)
		}
	})

	t.Run("it reports a body served through a header", func(t *testing.T) {
		t.Parallel()
		// A body that is clean and a Location that carries the text is still a
		// leak, and the stream's scanner has no reason to look at a final header
		// set — a stream's headers are written once, before anything is streamed.
		// So the response-side twin is where that check belongs, and it is here
		// rather than asserted of a capability that does not exist.
		fx := newFixture(t)
		fx.accountsFor()
		armed := &leakScanner{armed: bodyTokens}
		served := viewOver(t, fx, scanningHandler{scanner: armed, next: replacingHandler{
			fx:       fx,
			replaced: "/p/Tavern.md",
			serve: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", `</p/Ruin.md>; rel="alternate"; note="`+ruinBodyToken+`"`)
				_, _ = w.Write([]byte("<p>an entirely clean page</p>"))
			},
		}})
		s := served.asUser(otherName, otherPass)

		body := s.getOK("/p/Tavern.md")
		if strings.Contains(body, ruinBodyToken) {
			t.Fatal("the replacement put the token in the body, so the header check below is not testing the header")
		}
		if got := armed.found(); !slices.Contains(got, ruinBodyToken) {
			t.Errorf("the scanner reported %v for a body carrying a secret in a response header; a body-only scanner misses a leak that is in the same response", got)
		}
	})

	t.Run("it reports a body no route in this build produces", func(t *testing.T) {
		t.Parallel()
		// The honest floor, and the reason the scanner can be trusted at all: the
		// teeth are a property of the scanner, not of whether the campaign
		// currently has a hole in it. Nothing in this build serves
		// privateBodyToken to a player, so the replacement is the only way to
		// drive the exact failure the tripwire exists to catch.
		fx := newFixture(t)
		fx.accountsFor()
		armed := &leakScanner{armed: bodyTokens}
		served := viewOver(t, fx, scanningHandler{scanner: armed, next: replacingHandler{
			fx:       fx,
			replaced: "/p/Tavern.md",
			serve: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("<p>" + privateBodyToken + "</p>"))
			},
		}})
		s := served.asUser(otherName, otherPass)

		body := s.getOK("/p/Tavern.md")
		if !strings.Contains(body, privateBodyToken) {
			t.Fatal("the replacement did not serve the body it was written to serve")
		}
		found := armed.found()
		if !slices.Contains(found, privateBodyToken) {
			t.Errorf("the scanner reported %v for a response carrying a private secret a player may not read, want that finding", found)
		}
	})

	t.Run("the bytes it counted are the bytes the client received", func(t *testing.T) {
		t.Parallel()
		// A scanner that wraps the writer has to be transparent, or it is a
		// different response: a header it dropped, a status it lost, a body it
		// truncated. Counting the bytes is only a statement about the response
		// if the client got all of them, so this compares the two directly rather
		// than trusting the wrapper. The count is a difference, not a total: the
		// client signs in and primes a CSRF token on the way, and those are
		// responses too.
		fx := newFixture(t)
		fx.accountsFor()
		armed := &leakScanner{armed: bodyTokens}
		served := viewOver(t, fx, scanningHandler{scanner: armed, next: fx.Server.Handler()})
		s := served.asUser(dmName, dmPass)
		s.getOK("/p/Tavern.md") // sign in and let the token settle

		before := armed.written.Load()
		body := s.getOK("/p/Tavern.md")
		if got := armed.written.Load() - before; got != int64(len(body)) {
			t.Errorf("the scanner counted %d bytes and the client received %d, so the wrapper is not transparent and the count is not a statement about the response", got, len(body))
		}
	})
}

// replacingHandler answers one path itself and delegates every other request to
// the real router.
//
// It is a handler rather than a bare http.HandlerFunc because a bare one would
// also swallow the login, and then there would be no session, and then the test
// would be asserting about an unauthenticated client's view of a stub. Only the
// one route is replaced; the session middleware, the CSRF gate and the session
// cookie are the production ones.
type replacingHandler struct {
	fx       *fixture
	replaced string
	serve    http.HandlerFunc
}

// ServeHTTP implements http.Handler.
func (h replacingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == h.replaced {
		h.serve(w, r)
		return
	}
	h.fx.Server.Handler().ServeHTTP(w, r)
}

// scanningHandler is the response-side twin of the tripwire events_test.go
// installs on a stream's writer.
//
// It wraps the whole ordinary handler rather than a registry's writer, which is
// the same instrument pointed at a different place: a reader's response is a
// body plus a header set, and a leak in either is a leak. The header pass is the
// only part of it that has no counterpart on the stream side, because a stream's
// headers are written once before anything is streamed and so are already final.
type scanningHandler struct {
	scanner *leakScanner
	next    http.Handler
}

// ServeHTTP runs the wrapped handler with a scanned writer, then scans the
// header set the handler left behind.
//
// The header pass is after the handler rather than before, because a header value
// a handler writes in its own deferral would otherwise be missed, and a scanner
// that can be defeated by writing the header last is not a scanner.
func (h scanningHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scanned := h.scanner.wrap(w)
	h.next.ServeHTTP(scanned, r)
	h.scanner.inspectHeader(scanned.Header())
}

// inspectHeader is the header half of the scan.
//
// It lives here rather than in events_test.go for one reason: that scanner is
// armed on a stream's writer, where a header pass would be dead code, and a
// method that is only ever called by this file's twin belongs with the file that
// calls it.
func (ls *leakScanner) inspectHeader(h http.Header) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, values := range h {
		for _, v := range values {
			for _, token := range ls.armed {
				if strings.Contains(v, token) {
					ls.leaks = append(ls.leaks, token)
				}
			}
		}
	}
}
