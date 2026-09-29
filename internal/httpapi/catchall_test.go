package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
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

// What the greedy segment is, measured end to end, and what the loosening that
// made it work did not undo.
//
// TestTheCatchAllAndItsSuffixesAreUnambiguous above measures the three routing
// spellings. It cannot see the bug this file is about, because the bug is not in
// the spelling: the route matched, and what the value inside it did was not
// measured. pagedispatch.go's own comment says the greedy {name...} exists
// because "an attachment's recorded path is vault-relative and may live in a
// subdirectory, so {name} would silently refuse to serve every attachment under
// assets/", and bind required the tail to be exactly as long as the template — so
// it did refuse every attachment under assets/, for every principal including an
// administrator, while the same filename at the vault's root was served. The code
// disagreed with the comment that explains it, and a test that reads only the
// routing agreed with both.
//
// So the tests below drive names through the real router and pin two things at
// once: the name that must now be served, and every name that must still be
// refused. The second half is the half a careless fix skips, and it is where the
// method matters, so it is worth saying up front what is measurable and what is
// not:
//
//   - Which of the two rows answered a 404 is not observable from this package.
//     The page row and the attachment row both refuse by calling writeError, so
//     the two refusals are the same status over the same bytes, and the request
//     logger records RouteFrom(r.Context()) from the *outer* request — the
//     stamped context never reaches it, so its route attribute is always empty.
//     The rows are therefore told apart where they can be, by the 200 they
//     disagree on, and everything else is pinned by what the log does and does not
//     contain (below).
//   - Which *layer inside* the attachment row refused is observable, because
//     pageattachment.go writes one line and only one when vault.Resolve refuses a
//     recorded path. That line is an instrument rather than an inference because
//     the first case of the last test makes it fire: after that, its absence from
//     a request's own log window means the request never got that far.
//
// The vault the cases share is built for two A/B comparisons that a status alone
// settles: the same basename at the root and in a subdirectory, and a page
// addressed with and without a name after the attachment segment. A test that
// passes a bound name and refuses the same name unbound is the measurement; one
// that refuses both is not.

// The served files' contents, and the one heading a response for the chart page
// carries and a response for any other page in the vault does not.
//
// The basenames are deliberately the same at the vault root and one directory
// down, and the markers share no substring, because that is what makes the
// served-bytes assertion sharp rather than merely present: a bind that kept only
// the last segment would answer the nested URL with the root file's bytes, and a
// bind that refused the name answers 404. Only the join the fix makes — the whole
// tail, separators and all — produces the nested file's own bytes for the nested
// name.
const (
	rootBytes   = "ROOT-ATTACHMENT-BYTES-4f2b19"
	nestedBytes = "NESTED-ATTACHMENT-BYTES-c07e53"
	quayBytes   = "QUAY-ATTACHMENT-BYTES-1a6d40"
	// outsideBytes is what a file the vault links to but does not contain holds.
	// It is not vault content and must never reach a response; the assertions on
	// it are written as absences for that reason.
	outsideBytes = "OUTSIDE-THE-VAULT-BYTES-5ad9c0"
	chartHeading = "The harbour chart"
)

// attachmentDispatchVault is the vault the four tests share.
//
// Four of its files are load-bearing in a way the map does not show:
//
//   - map.png and assets/map.png share a basename, for the reason rootBytes
//     documents;
//   - notes/attachment/Chart.md puts a segment named attachment in the middle of a
//     page's own path, which is the only shape on which the attachment template's
//     literal block and a page collide: a page whose *last* segment is attachment
//     cannot collide at all, because match's bound on the literal's position is
//     len(segs)-lits-1, which for a two-segment value is 0 and below its floor of
//     1, so the template is never tried;
//   - dockside.md and dockside/attachment.md are both pages, so the value
//     "dockside/attachment" names one, and a name after it would be an
//     attachment of dockside. That is the A/B for the selector refusing a tail
//     that is shorter than the template, and it is settled by the status alone;
//   - .semiplane/semiplane.lock is present on disk, so the refusal of it is a
//     refusal of a file that really is there and really is inside the vault. The
//     walk skips .semiplane, which is the whole of why that refusal is a fact
//     about the index rather than about containment, and the last test asserts
//     both halves.
func attachmentDispatchVault() map[string]string {
	return map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\ntype: note\n---\n\n" +
			"# The Drowned Lantern\n\nTwo charts hang by the door.\n\n" +
			"![the coast](map.png)\n\n" +
			"![the harbour](assets/map.png)\n\n",
		"map.png":        "\x89PNG\r\n\x1a\n" + rootBytes,
		"assets/map.png": "\x89PNG\r\n\x1a\n" + nestedBytes,
		"dockside.md": "---\ntitle: The dockside\ntype: note\n---\n\n" +
			"# The dockside\n\n![the quay](quay.png)\n\n",
		"quay.png": "\x89PNG\r\n\x1a\n" + quayBytes,
		"dockside/attachment.md": "---\ntitle: The berth ledger\ntype: note\n---\n\n" +
			"# The berth ledger\n\nEvery hull that paid the harbourmaster.\n",
		"notes/attachment/Chart.md": "---\ntitle: " + chartHeading + "\ntype: note\n---\n\n" +
			"# " + chartHeading + "\n\nSoundings in fathoms.\n",
		".semiplane/semiplane.lock": "the single-instance lock, which this test does not take\n",
	}
}

// TestANestedAttachmentNameIsServedAsTheWholeJoinedPath is the case the routing
// measurement could not reach: a name with a directory in it, through the real
// router, against a real index and a real principal.
//
// The precondition is asserted rather than assumed. A recorded attachments row is
// only ever written for a name that resolved to itself inside the vault and named
// a regular file, so the two names below really are on disk at the two paths the
// requests will name. A test that passed because the index had recorded nothing
// would be the §5 shape: a fixture that did not set up what it asserts.
func TestANestedAttachmentNameIsServedAsTheWholeJoinedPath(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentDispatchVault())
	fx.accountsFor()

	recorded := recordedAttachments(t, fx, "Tavern.md")
	if want := []string{"assets/map.png", "map.png"}; !slices.Equal(recorded, want) {
		t.Fatalf("the index holds %v for Tavern.md, want %v: both names below would be refused by an empty table, which says nothing about the router", recorded, want)
	}

	dm := fx.asUser(dmName, dmPass)
	for _, tc := range []struct {
		name  string
		url   string
		bytes string
		want  int
	}{
		{"a name at the vault root", "/p/Tavern.md/attachment/map.png", rootBytes, http.StatusOK},
		{"a name in a subdirectory", "/p/Tavern.md/attachment/assets/map.png", nestedBytes, http.StatusOK},
		{
			// The other side of the same join, and the half that catches a bind
			// which kept the tail but lost its first segment. The last segment here
			// is a file that really exists and really is served under its own name,
			// so a handler that received "map.png" would have answered this URL with
			// the root file's bytes; what answers it is that the store was asked
			// about "maps/map.png" and holds no such name.
			name:  "a name in a directory that holds nothing",
			url:   "/p/Tavern.md/attachment/maps/map.png",
			bytes: rootBytes,
			want:  http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := dm.do(dm.get(tc.url))
			body := dm.read(resp)
			if resp.StatusCode != tc.want {
				t.Fatalf("GET %s: status %d, want %d", tc.url, resp.StatusCode, tc.want)
			}
			// The bytes, not the status: a join that dropped a segment is a 200
			// carrying the wrong file, which is the shape a half-fix takes, and the
			// field names the bytes this URL must produce — so for a refusal it
			// names the ones a join that dropped a directory would have produced.
			if got := strings.Contains(body, tc.bytes); got != (tc.want == http.StatusOK) {
				t.Errorf("GET %s: the file's bytes are present=%v, want %v, so the greedy segment did not bind the whole joined path", tc.url, got, tc.want == http.StatusOK)
			}
			if tc.want == http.StatusOK {
				if csp := resp.Header.Get("Content-Security-Policy"); csp != attachmentCSP {
					t.Errorf("GET %s: Content-Security-Policy is %q, want %q", tc.url, csp, attachmentCSP)
				}
				return
			}
			if strings.Contains(body, nestedBytes) {
				t.Errorf("GET %s was refused, and served a file's bytes on the way", tc.url)
			}
		})
	}
}

// TestAPageWithAnAttachmentSegmentInItsPathIsStillAPage is the other half of the
// greedy form: match takes the literal block at its LAST occurrence, and the
// dispatcher asks the index whether the value is a page before letting a template
// win. So a page that happens to sit under a directory called attachment stays
// openable.
//
// The status is the measurement, and it is a measurement of both halves. Had the
// attachment row answered this value it would have looked for an attachment called
// "Chart.md" on a page called "notes" — a page this vault does not have — and
// answered 404. So 200 is the page row's answer, and the only way to get it is for
// isPagePath to have been asked and to have found the page.
func TestAPageWithAnAttachmentSegmentInItsPathIsStillAPage(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentDispatchVault())
	fx.accountsFor()

	if _, ok := fx.pageIDByPath("notes"); ok {
		t.Fatal("the vault has a page called notes, so the attachment row's answer for this value would be a 200 and the case would distinguish nothing")
	}
	if _, ok := fx.pageIDByPath("notes/attachment/Chart.md"); !ok {
		t.Fatal("the index has no row for notes/attachment/Chart.md, so this test would be measuring a 404 that says nothing about the selector")
	}

	const url = "/p/notes/attachment/Chart.md"
	dm := fx.asUser(dmName, dmPass)
	resp := dm.do(dm.get(url))
	body := dm.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	if !strings.Contains(body, chartHeading) {
		t.Errorf("GET %s answered 200 without the page's own heading, so the value resolved to something other than the page it names", url)
	}
}

// TestAValueWithNoNameIsThePageItNamesAndNotAnAttachmentRequest is the
// unit-level half, reached over HTTP, and it is an A/B.
//
// bind's guard is len(tail) < len(sel.segments), and it is worth saying plainly
// that no value the shipped table can produce reaches it: match bounds where the
// literal may sit at len(segs)-lits-1 and refuses below its floor of 1, and with
// one literal and one greedy name that is already out of range for a value of two
// segments. So match answers first and bind's guard is defence in depth for a
// template with more literals than the table has today. What this test pins is the
// observable that guard protects, which is a statement about the selector rather
// than about one function: a value with nothing after the attachment segment is
// not an attachment request, so no name was produced for it.
//
// The A/B is the same page and the same literal with a name after it, which binds
// and is served, so the difference between the two answers is the name and nothing
// else. And the 200 is the refusal read from the other side: had the selector
// produced a name for the shorter value — an empty one, which match's bound and
// bind's empty-value check both refuse — the row would have been asked for an
// attachment called "" on a page called dockside, and answered 404. It answered
// the page instead.
//
// There is no unexported selector to assert ok == false against from this package,
// and exporting one to make a test possible would be a larger change than the one
// under test. This is the same two-valued answer, measured one layer out: the
// selector bound the value, or the value was answered as a page.
func TestAValueWithNoNameIsThePageItNamesAndNotAnAttachmentRequest(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentDispatchVault())
	fx.accountsFor()

	if _, ok := fx.pageIDByPath("dockside/attachment.md"); !ok {
		t.Fatal("the index has no row for dockside/attachment.md, so the value below is not a page and this test is measuring nothing")
	}
	if recorded := recordedAttachments(t, fx, "dockside.md"); !slices.Equal(recorded, []string{"quay.png"}) {
		t.Fatalf("the index holds %v for dockside.md, want [quay.png]: the attached case needs a real recorded row, or a 404 would prove nothing about the selector", recorded)
	}

	dm := fx.asUser(dmName, dmPass)
	for _, tc := range []struct {
		name  string
		url   string
		bytes string
	}{
		{"the same page and literal with a name after them", "/p/dockside/attachment/quay.png", quayBytes},
		{"the same page and literal with no name after them", "/p/dockside/attachment", "Every hull that paid the harbourmaster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := dm.do(dm.get(tc.url))
			body := dm.read(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200", tc.url, resp.StatusCode)
			}
			if !strings.Contains(body, tc.bytes) {
				t.Errorf("GET %s answered 200 with neither the attachment nor the page, so the value resolved to something no row in the table owns", tc.url)
			}
		})
	}
}

// TestTheLoosenedBindRefusesEveryNameItMust is the half a careless fix skips.
//
// A greedy span that now crosses segments is a span that hands a longer string to
// whatever consumes it, so each row here is a shape that became reachable *because*
// of the fix: the multi-segment traversal and the empty segment only exist because
// the tail may be longer than the template, and bind could not have bound them
// before. The one-segment traversal and the app's own state are the older shapes,
// carried over from the table in pageroutes_test.go that drives them against a
// root-level attachment; what is added here is the segment count and the layer.
//
// Every refusal is the same document as a page that does not exist, because a 404
// that can be told apart from another 404 is a probe.
func TestTheLoosenedBindRefusesEveryNameItMust(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentDispatchVault())
	fx.accountsFor()
	dm := fx.asUser(dmName, dmPass)

	refused := refusedDocument(t, dm)

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"one parent directory", "/p/Tavern.md/attachment/../Index.md"},
		{"a parent directory inside the greedy span", "/p/Tavern.md/attachment/assets/../../Index.md"},
		{"a dot segment inside the greedy span", "/p/Tavern.md/attachment/assets/./map.png"},
		{"the app's own state", "/p/Tavern.md/attachment/.semiplane/semiplane.lock"},
		{"an empty segment inside the greedy span", "/p/Tavern.md/attachment/assets//map.png"},
		{"a trailing separator inside the greedy span", "/p/Tavern.md/attachment/assets/map.png/"},
		{"a parent directory after a name that exists", "/p/dockside/attachment/quay.png/.."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := dm.do(dm.get(tc.url))
			body := dm.read(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s: status %d, want 404", tc.url, resp.StatusCode)
			}
			if body != refused {
				t.Errorf("GET %s answered a document of its own (%d bytes, want the %d bytes every refusal shares)", tc.url, len(body), len(refused))
			}
		})
	}
}

// TestWhichLayerRefusedEachNameIsMeasuredRatherThanAssumed names the layer for
// the refusals above, because a 404 does not and a comment should not be taken on
// trust — that is how the bug this file pins survived in the first place.
//
// The instrument is the one line pageattachment.go writes when vault.Resolve
// refuses a recorded path, and it is an instrument rather than an inference
// because the first case makes it fire. After that, its absence from a request's
// own log window means the request never got that far, which is a statement about
// a layer rather than about a status.
//
// The rows in this table are ones the indexer cannot write: it resolves a name
// before it records it, so a traversal-shaped name, a doubled separator and a path
// that leaves the vault never reach the index through a boot. That is the correct
// behaviour, and it is also what makes these cases unreachable through an honest
// fixture — so the index is wrong on purpose, and the assertion is that the route
// does not depend on the index being right.
//
// Two of the four name a layer, one names the index, and the fourth names a pair:
// an empty segment in a greedy span is refused by the selector and would be refused
// by the route's own name check as well, and which of the two runs is not
// observable from here. That case says so rather than claiming a layer it cannot
// establish, and it is worth having anyway: the store is a string comparison that
// has been handed a name with a doubled separator in it, and the armed row is what
// makes "the store would have said yes" a measured fact rather than a guess.
func TestWhichLayerRefusedEachNameIsMeasuredRatherThanAssumed(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, attachmentDispatchVault())
	fx.accountsFor()
	dm := fx.asUser(dmName, dmPass)
	// The window each case reads is what the main log grew by across its own
	// request, and it is measured rather than arranged. Two traps, both of which
	// make an absence pass for the wrong reason: fx.discardLogs is the obvious way
	// to get a clean log and it is a trap, because it stops the buffer collecting
	// rather than emptying it, so every case would read an always-empty window;
	// and fx.logs() is the main log *concatenated with* the audit log, so a length
	// taken from it is a boundary in the middle of neither and the window that
	// comes back is the new main records followed by the whole audit buffer. The
	// subtests are sequential and the main log only grows, so a length taken from
	// it before a request is a boundary no earlier record can cross.
	refused := refusedDocument(t, dm)

	t.Run("vault.Resolve refuses a recorded path that leaves the vault", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.png")
		if err := os.WriteFile(outside, []byte(outsideBytes), 0o600); err != nil {
			t.Fatalf("write the file outside the vault: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(fx.Root, "escape.png")); err != nil {
			t.Fatalf("link the vault's escape.png to a file outside it: %v", err)
		}
		armAttachment(t, fx, "Tavern.md", "escape.png")

		const url = "/p/Tavern.md/attachment/escape.png"
		before := len(fx.mainLog.String())
		resp := dm.do(dm.get(url))
		body := dm.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", url, resp.StatusCode)
		}
		if strings.Contains(body, outsideBytes) {
			t.Error("GET " + url + ": the file outside the vault was served")
		}
		if !strings.Contains(fx.mainLog.String()[before:], resolveWarning) {
			t.Fatalf("GET %s answered 404 without %q, so the containment layer was never reached and this case measures no layer at all", url, resolveWarning)
		}
	})

	t.Run("a traversal the index holds anyway is refused before the index is asked", func(t *testing.T) {
		armAttachment(t, fx, "Tavern.md", "../escape.png")

		const url = "/p/Tavern.md/attachment/../escape.png"
		before := len(fx.mainLog.String())
		resp := dm.do(dm.get(url))
		body := dm.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", url, resp.StatusCode)
		}
		if body != refused {
			t.Errorf("GET %s answered a document of its own rather than the one every refusal shares", url)
		}
		// The measurement. The index holds this name — armAttachment wrote the
		// rows — so a request that reached store.AttachmentVisibleTo would be told
		// yes and would go on to Resolve, which refuses it and warns. No warning
		// therefore means the request was turned away before the index was asked,
		// which is attachmentName: the fixed-size check the route's own comment
		// says exists so that a store which later loosened its match would not
		// loosen this one with it.
		if strings.Contains(fx.mainLog.String()[before:], resolveWarning) {
			t.Errorf("GET %s reached vault.Resolve, so the refusal came from the containment layer and the route's own name check did not run", url)
		}
	})

	t.Run("the app's own state is refused because the index never held it", func(t *testing.T) {
		const name = ".semiplane/semiplane.lock"
		if _, err := os.Stat(filepath.Join(fx.Root, filepath.FromSlash(name))); err != nil {
			t.Fatalf("the vault has no %s: refusing a name for a file that is not there is a refusal of nothing", name)
		}
		if recorded := recordedAttachments(t, fx, "Tavern.md"); slices.Contains(recorded, name) {
			t.Fatalf("the index holds %q for Tavern.md, so this case would be measuring a served file rather than the refusal of the app's own state", name)
		}

		const url = "/p/Tavern.md/attachment/" + name
		before := len(fx.mainLog.String())
		resp := dm.do(dm.get(url))
		body := dm.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", url, resp.StatusCode)
		}
		if strings.Contains(body, "single-instance lock") {
			t.Error("GET " + url + ": the lock file was served")
		}
		// The name is well formed — no dot segment, not absolute, no empty
		// segment — so the route's own check let it through and the index is what
		// stopped it. That is a stronger statement than containment would have
		// been: the file is inside the vault and unnameable, because the walk never
		// descends into .semiplane, rather than named and then resolved.
		if strings.Contains(fx.mainLog.String()[before:], resolveWarning) {
			t.Errorf("GET %s reached vault.Resolve, so the refusal came from the containment layer rather than from the index never having held the name", url)
		}
	})

	t.Run("a name with an empty segment is refused before the index is asked", func(t *testing.T) {
		// A pair, not a layer. The selector refuses a span with an empty segment in
		// it and so would attachmentName, and this test cannot tell which of the two
		// ran — both were measured to be enough on their own, by removing each in
		// turn and watching the other hold. What it can say is the thing worth
		// saying: the store would have answered yes. The row is a name the index
		// does not hold — the real path with a doubled separator in it — and
		// AttachmentVisibleTo matches strings, so the name had to be refused before
		// the store was asked or the file behind it would have been served under a
		// name nothing recorded.
		armAttachment(t, fx, "Tavern.md", "assets//map.png")

		const url = "/p/Tavern.md/attachment/assets//map.png"
		before := len(fx.mainLog.String())
		resp := dm.do(dm.get(url))
		body := dm.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", url, resp.StatusCode)
		}
		if strings.Contains(body, nestedBytes) {
			t.Errorf("GET %s served the file under a name the index does not hold, so a greedy span with an empty segment in it was bound", url)
		}
		if strings.Contains(fx.mainLog.String()[before:], resolveWarning) {
			t.Errorf("GET %s reached vault.Resolve, so the span with an empty segment in it was bound and cleaned rather than refused", url)
		}
	})
}

// resolveWarning is the one line pageattachment.go writes when vault.Resolve
// refuses a recorded path, restated here rather than reached for.
//
// It is restated for the reason attachmentCSP is (pageroutes_test.go): the
// assertion reads against the string the log will carry, not against an import of
// the package under test — and this file is in the external test package, where
// the function that writes it is unexported anyway.
const resolveWarning = "a recorded attachment did not resolve inside the vault"

// refusedDocument is the 404 every refusal shares, asked for once from a page
// that does not exist.
func refusedDocument(t *testing.T, s *session) string {
	t.Helper()
	resp := s.do(s.get("/p/Nowhere at all.md"))
	body := s.read(resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a page that does not exist: status %d, want 404", resp.StatusCode)
	}
	return body
}

// recordedAttachments is the names the index holds for one page, sorted.
func recordedAttachments(t *testing.T, fx *fixture, page string) []string {
	t.Helper()
	id, ok := fx.pageIDByPath(page)
	if !ok {
		t.Fatalf("look up %s: the vault has no such page", page)
	}
	rows, err := store.ListAttachmentsByPage(context.Background(), fx.DB.Reader(), id)
	if err != nil {
		t.Fatalf("list the attachments of %s: %v", page, err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Path)
	}
	slices.Sort(out)
	return out
}

// armAttachment writes, by hand, the rows the indexer writes for a page that
// references a file under a name the indexer would refuse to record.
func armAttachment(t *testing.T, fx *fixture, page, name string) {
	t.Helper()
	id, ok := fx.pageIDByPath(page)
	if !ok {
		t.Fatalf("look up %s: the vault has no such page", page)
	}
	ctx := context.Background()
	if _, err := store.InsertAttachment(ctx, fx.DB.Writer(), store.Attachment{
		PageID: &id, Path: name, Mime: "image/png", SizeBytes: 1,
	}); err != nil {
		t.Fatalf("record the attachment %s: %v", name, err)
	}
	if _, err := store.InsertLink(ctx, fx.DB.Writer(), store.Link{
		SourcePageID: id, TargetRaw: name, Kind: store.LinkAttachment,
		ByteStart: store.LinkByteStartUnset,
	}); err != nil {
		t.Fatalf("record the reference to %s: %v", name, err)
	}
}
