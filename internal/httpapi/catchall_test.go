package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The routing question the whole editor surface rests on, measured rather than
// believed.
//
// The plan's §9.2 page-scoped URLs — /p/*/raw, /p/*/edit, /p/*/revisions/{id} —
// cannot be written as chi patterns, and the way they cannot be is worth
// pinning down precisely, because each of the three obvious alternatives fails
// differently and two of them fail *quietly*. A reviewer who has not measured
// them would reasonably conclude one of them works.
//
// The measurements, on chi v5.3.2:
//
//  1. "/p/*/raw" — a wildcard in the middle — **panics at registration**:
//     "chi: wildcard '*' must be the last value in a route". Not a pattern that
//     never matches; a pattern the trie refuses to hold.
//  2. "/p/{path...}" — the v4 named catch-all — matches only a single-segment
//     path, and hands back an **empty** value when it does. It looks like it
//     works, and every page in a nested folder would 404.
//  3. "/p/{raw}" and "/p/{raw...}" are param nodes, and a param node cannot span
//     a "/". "/p/Guild/Cellar/Wine.md/raw" matches neither, so a flat param
//     serves only root-level pages — and it *shadows* the page named raw.md at
//     the root, because chi prefers the param node for a one-segment path
//     whichever order the two rows were registered in.
//
// The resolution is in internal/httpapi/pagedispatch.go: every page-scoped row
// mounts on the one catch-all and is told apart by the trailing segments of the
// value. The subtests below assert the three measurements, so that a chi upgrade
// re-measures them, and then assert the shape of the shipped table, so that a
// row added tomorrow with a pattern the dispatcher cannot express is a failing
// test rather than a route that answers 404 to everything.
func TestTheCatchAllAndItsSuffixesAreUnambiguous(t *testing.T) {
	t.Parallel()

	t.Run("a wildcard in the middle of a pattern panics at registration", func(t *testing.T) {
		t.Parallel()
		defer func() {
			rec := recover()
			if rec == nil {
				t.Fatalf("chi accepted /p/*/raw: if it now supports a mid-pattern wildcard, the dispatcher in pagedispatch.go can be replaced by one chi pattern per surface and this file is wrong")
			}
		}()
		chi.NewRouter().Get("/p/*/raw", func(http.ResponseWriter, *http.Request) {})
	})

	t.Run("the v4 named catch-all matches one segment and binds nothing", func(t *testing.T) {
		t.Parallel()
		r := chi.NewRouter()
		r.Get("/p/{path...}", func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("|" + chi.URLParam(req, "path") + "|"))
		})
		for _, tc := range []struct{ path, want string }{
			{"/p/Tavern.md", "||"},
			{"/p/Guild/Cellar/Wine.md", ""},
			{"/p/Tavern.md/raw", ""},
		} {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))
			got := w.Body.String()
			if tc.want == "" {
				if w.Code != http.StatusNotFound {
					t.Errorf("GET %s: status %d, want 404", tc.path, w.Code)
				}
				continue
			}
			if got != tc.want {
				t.Errorf("GET %s bound %q, want %q", tc.path, got, tc.want)
			}
		}
	})

	t.Run("a flat param cannot span a slash, and shadows a page named for it", func(t *testing.T) {
		t.Parallel()
		r := chi.NewRouter()
		r.Get("/p/*", func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("page:" + chi.URLParam(req, "*")))
		})
		r.Get("/p/{raw}", func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("raw:" + chi.URLParam(req, "raw")))
		})
		for _, tc := range []struct{ path, want string }{
			{"/p/Guild/Cellar/Wine.md/raw", "page:Guild/Cellar/Wine.md/raw"},
			// The shadow: a page at the vault's root called raw.md is
			// unopenable, whichever order the two were registered in.
			{"/p/raw", "raw:raw"},
		} {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))
			if got := w.Body.String(); got != tc.want {
				t.Errorf("GET %s reached %q, want %q", tc.path, got, tc.want)
			}
		}
	})

	t.Run("every page-scoped pattern in the table has a distinct selector", func(t *testing.T) {
		t.Parallel()
		// Not a duplicate-pattern check: two rows may legitimately share a
		// mounted chi pattern, because that is the design. What must be distinct
		// is what the dispatcher keys on — the template that picks the row out of
		// the value — because two rows with the same template are two rows where
		// the second is unreachable and nothing says so.
		seen := map[string]string{}
		for _, rt := range newFixture(t).Server.Routes() {
			mount, sel := splitPattern(rt.Pattern)
			if sel == "" {
				continue
			}
			if mount != "/p/*" {
				t.Errorf("%s mounts on %q, not on the page catch-all: the dispatcher only resolves selectors under /p/*", rt.Name(), mount)
			}
			key := rt.Method + " " + sel
			if prev, ok := seen[key]; ok {
				t.Errorf("%q and %q share the selector %q under the same method, so one of them is unreachable", prev, rt.Name(), sel)
			}
			seen[key] = rt.Name()
		}
		if len(seen) < 6 {
			t.Errorf("only %d page-scoped selectors are in the table, want at least the six of §9.2–§9.4; a gate that checks nothing is not a gate", len(seen))
		}
	})
}

// splitPattern is the test's own copy of the two derivations in pagedispatch.go
// — the mounted chi pattern and the trailing selector — so that the assertion
// above reads against the public table rather than against package internals.
// It is a restatement, and it is a restatement on purpose: the alternative is a
// test that can only reach the values through the very code it is checking.
func splitPattern(pattern string) (mount, sel string) {
	const wildcard = "/*"
	for i := 0; i+len(wildcard) <= len(pattern); i++ {
		if pattern[i:i+len(wildcard)] != wildcard {
			continue
		}
		return pattern[:i+len(wildcard)], trimSlashes(pattern[i+len(wildcard):])
	}
	return pattern, ""
}

func trimSlashes(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
