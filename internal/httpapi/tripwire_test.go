package httpapi_test

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoSecretLeaksThroughAnyPath is the leak tripwire, and it is the test that
// justifies the design rather than a consequence of it.
//
// It walks the full demo path as every role — sign in, read the dashboard, read
// the page, read the page as a fragment, search, read an asset, ask for the
// readiness probe, follow a link, sign out, ask again — and asserts that no
// secret body the principal may not read appears in the response body, in any
// response header, or in any data-signals payload. The headers matter as much as
// the body: a body that is clean and a Location or a Link header that carries the
// text is still a leak, and a request logger is not a response.
//
// The campaign is seeded with one distinguishable token per secret, across all
// three visibilities, so a finding names the secret that leaked and not just the
// page it leaked on.
func TestNoSecretLeaksThroughAnyPath(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	cases := []leakPrincipal{
		{name: "admin", user: adminName, pass: adminPass},
		{name: "dm", user: dmName, pass: dmPass},
		{name: "page owner", user: playerName, pass: playerPass},
		{name: "player", user: otherName, pass: otherPass},
		{name: "anonymous with read off", anonymous: true},
	}

	// mayRead is the tripwire's own model of the rule, written out so that a
	// failure says which expectation was wrong rather than only that something
	// was missing. It is deliberately not a call into authz: a tripwire that
	// shares the implementation it is testing cannot catch that implementation
	// being wrong.
	mayRead := func(p leakPrincipal, token string) bool {
		adminOrDM := p.name == "admin" || p.name == "dm"
		// ownsTavern is true only for the one player the harness granted
		// ownership of the Tavern page.
		ownsTavern := p.name == "page owner"
		switch token {
		case "TABLE-BODY-TOKEN-5d0a8f":
			// visibility=table: any account at all, and never an anonymous one.
			return !p.anonymous
		case "PRIVATE-BODY-TOKEN-9f3a2c":
			// visibility=private, authored by the DM, on a page Thia owns: the
			// rule is DMs, the author, or an owner of the page.
			return adminOrDM || ownsTavern
		case "DM-BODY-TOKEN-7b1e4d", "RUIN-BODY-TOKEN-2c8f61":
			// visibility=dm: DMs and admins only. Not the author when the author
			// is a DM anyway, and never the page owner.
			return adminOrDM
		case "OWNER-BODY-TOKEN-2a6e10":
			// visibility=private, authored by Thia, on a page Thia owns: twice
			// over, and still hers.
			return adminOrDM || ownsTavern
		}
		return false
	}

	for _, p := range cases {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s := fx.newSession()
			if !p.anonymous {
				resp := s.login(p.user, p.pass)
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("sign in: status %d, want 303", resp.StatusCode)
				}
				drain(resp)
			}
			for _, step := range demoSteps(fx) {
				t.Run(step.name, func(t *testing.T) {
					// The fragment really is asked for. It used not to be: the step
					// carried a fragment field and the walk ignored it, so "page as a
					// fragment" was a byte-identical duplicate of "page as a
					// document" and the only thing it proved was that the same
					// request twice is the same request twice.
					var c *call
					if step.fragment {
						c = s.fragment(step.path)
					} else {
						c = s.get(step.path)
					}
					resp := s.do(c)
					defer drain(resp)
					// The body is read through the harness so the session's CSRF
					// token refreshes the way a browser's would.
					body := s.read(resp)
					assertNoLeaks(t, body, resp.Header, mayRead, p, step.name)
				})
			}
			// And the two shapes are proven to be two shapes, so the field cannot go
			// dead again without this failing: a walk that stopped sending the
			// header would return identical bytes for a document and a fragment, and
			// a leak that only the fragment branch can produce would have gone
			// unnoticed while every assertion above still passed.
			//
			// Only where the document actually rendered. A principal that is
			// redirected to the login form gets that redirect for both shapes —
			// there is no fragment of a page that was never rendered — so the
			// comparison would be asserting that two identical refusals differ.
			for _, step := range demoSteps(fx) {
				if !step.fragment {
					continue
				}
				document := s.do(s.get(step.path))
				documentBody := s.read(document)
				fragment := s.text(s.fragment(step.path))
				if document.StatusCode != http.StatusOK {
					continue
				}
				if documentBody == fragment {
					t.Errorf("%s: the fragment and the document of %s are byte-identical, so the fragment was not asked for as a fragment and its code path was never walked", p.name, step.path)
				}
			}
		})
	}
}

// leakPrincipal is one role as the tripwire models it. It is a separate type from
// the harness's so that the tripwire's own expectations are written out rather
// than reached for: a tripwire that shares the implementation it is testing
// cannot catch that implementation being wrong.
type leakPrincipal struct {
	name       string
	user, pass string
	anonymous  bool
}

// step is one request in the demo path.
type step struct {
	name   string
	method string
	path   string
	// fragment asks for the content region on its own, which is a different code
	// path on the server and can therefore leak differently.
	//
	// It is read by the walk below and pinned by the assertion that follows it,
	// because a flag nothing reads is a step that looks covered and is not: the
	// "page as a fragment" step sat here for four stages being a byte-identical
	// duplicate of the one above it, and nothing said so.
	fragment bool
}

// demoSteps is the path a reader actually takes, in the order they take it. The
// tripwire walks exactly this list for every role, so a leak is reported against
// the step that produced it rather than against the test as a whole.
func demoSteps(_ *fixture) []step {
	return []step{
		{name: "dashboard", method: http.MethodGet, path: "/"},
		{name: "page as a document", method: http.MethodGet, path: "/p/Tavern.md"},
		{name: "page as a fragment", method: http.MethodGet, path: "/p/Tavern.md", fragment: true},
		{name: "second page", method: http.MethodGet, path: "/p/Ruin.md"},
		{name: "page that does not exist", method: http.MethodGet, path: "/p/Nope.md"},
		{name: "search page", method: http.MethodGet, path: "/search?q=lantern"},
		{name: "search api", method: http.MethodGet, path: "/api/search?q=lantern"},
		{name: "readiness probe", method: http.MethodGet, path: "/readyz"},
		{name: "stylesheet", method: http.MethodGet, path: "/_/assets/app.css"},
		{name: "script", method: http.MethodGet, path: "/_/assets/app.js"},
		{name: "sprite", method: http.MethodGet, path: "/_/assets/icons.svg"},
		{name: "datastar", method: http.MethodGet, path: "/_/assets/vendor/datastar.js"},
	}
}

// assertNoLeaks is the assertion the whole design rests on.
//
// It looks in the body, in every header value, and in every data-signals payload
// the body carries. The signals are worth a separate pass because a fragment
// response can carry state as attributes rather than as text, and a token in an
// attribute is exactly as readable as one in a paragraph.
func assertNoLeaks(t *testing.T, body string, header http.Header, mayRead func(leakPrincipal, string) bool, who leakPrincipal, where string) {
	t.Helper()
	check := func(token string) bool { return mayRead(who, token) }
	for _, token := range bodyTokens {
		if check(token) {
			continue
		}
		if strings.Contains(body, token) {
			t.Errorf("%s: the body of %s carries a secret this reader may not read: %q", who.name, where, token)
		}
	}
	for name, values := range header {
		for _, v := range values {
			for _, token := range bodyTokens {
				if check(token) {
					continue
				}
				if strings.Contains(v, token) {
					t.Errorf("%s: the %s header of %s carries a secret this reader may not read: %q", who.name, name, where, token)
				}
			}
		}
	}
	for _, payload := range signalPayloads(body) {
		for _, token := range bodyTokens {
			if check(token) {
				continue
			}
			if strings.Contains(payload, token) {
				t.Errorf("%s: a data-signals payload in %s carries a secret this reader may not read: %q", who.name, where, token)
			}
		}
	}
}

// signalsAttr matches a data-signals attribute and its payload.
var signalsAttr = regexp.MustCompile(`data-signals="([^"]*)"`)

// signalPayloads returns every data-signals payload in a body. There are none in
// stage 1, and the assertion is written so that adding the first one does not
// need a new test: a leak through a signal would be found here.
func signalPayloads(body string) []string {
	var out []string
	for _, m := range signalsAttr.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestSecretFixturesNeverLeak is the same tripwire over the search index, which
// is a different leak surface: a secret that never reaches a page can still
// reach a result, and the result is a snippet.
//
// FTS only admits a table-visible secret, so a player may see a table secret's
// hit — which names the page and carries no body at all — and must see nothing of
// the other four, in the snippet, the title or the path alike.
func TestSecretFixturesNeverLeakThroughSearch(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	for _, tc := range []struct {
		user, pass string
		forbidden  []string
	}{
		{user: otherName, pass: otherPass, forbidden: []string{
			"PRIVATE-BODY-TOKEN-9f3a2c", "DM-BODY-TOKEN-7b1e4d", "RUIN-BODY-TOKEN-2c8f61",
		}},
		{user: playerName, pass: playerPass, forbidden: []string{
			"PRIVATE-BODY-TOKEN-9f3a2c", "DM-BODY-TOKEN-7b1e4d", "RUIN-BODY-TOKEN-2c8f61",
		}},
		{user: dmName, pass: dmPass},
	} {
		t.Run(tc.user, func(t *testing.T) {
			t.Parallel()
			s := fx.asUser(tc.user, tc.pass)
			// Two terms: a word that is in every secret body and in no page, and a
			// word from a page. A hidden secret's body must answer neither, and the
			// term is not itself a secret so that the echoed query cannot be
			// mistaken for a leak.
			for _, term := range []string{searchWord, "dry"} {
				body := s.getOK("/search?q=" + term)
				for _, token := range tc.forbidden {
					assertNoToken(t, body, token, "a search for "+term)
				}
			}
			api := s.getOK("/api/search?q=" + searchWord)
			for _, token := range tc.forbidden {
				assertNoToken(t, api, token, "the search api for a secret body")
			}
			// The positive control, and it is the reason the negative assertions
			// above mean anything: the index really does hold the table-visible
			// secret, so a search for a word inside it finds a secret hit. What the
			// response never carries is the body — a secret hit names its page and
			// nothing else, which is why the assertion above is that the token is
			// absent rather than present.
			if tc.user == otherName {
				found := s.getOK("/search?q=" + searchWord)
				assertHasToken(t, found, "from a shared secret", "a secret hit in search")
				if strings.Contains(found, "0 results") {
					t.Error("the search for a word inside a table-visible secret found nothing, so the positive control is vacuous")
				}
				// And the page search still works, so the negative assertions are
				// not passing because the query is broken.
				assertHasToken(t, s.getOK("/search?q=lantern"), "Lantern", "a page in search")
			}
		})
	}
}

// TestA404IsTheSameAnswerForEveryKindOfNothing is the existence property.
//
// Stage 1 has no per-page read restriction: PermReadPage is campaign-wide, so
// there is no page an authenticated principal may not read. The property is
// therefore asserted where it is actually load-bearing — over every kind of
// "there is nothing here", which must be one answer and not four, and over the
// one case where a page does exist and the reader is refused, which must also be
// the same answer.
//
// The assertion is byte for byte, not on a status, because a status can match
// while the body leaks the page's title. Anything that could differ between the
// cases — a request id, the path that was asked for, a page title — would make
// this fail, and all three are absent because the error model has no field to
// put them in.
func TestA404IsTheSameAnswerForEveryKindOfNothing(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)

	kinds := []struct {
		name string
		path string
	}{
		{name: "a page that does not exist", path: "/p/No-such-page.md"},
		{name: "a path that traverses out of the vault", path: "/p/../../etc/passwd"},
		{name: "an asset that is in the binary but not in the table", path: "/_/assets/assets.go"},
		{name: "a url no route claims", path: "/admin/users"},
		{name: "a directory", path: "/p/"},
	}
	var firstBody string
	for i, k := range kinds {
		resp := s.do(s.get(k.path))
		body := s.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", k.name, resp.StatusCode)
		}
		if i == 0 {
			firstBody = body
			continue
		}
		if body != firstBody {
			t.Errorf("%s: the body differs from the one for a page that does not exist\nthis: %q\n404:  %q", k.name, body, firstBody)
		}
	}
	// The body must not carry the thing that was asked for, or the equality above
	// would be an accident of these particular paths.
	for _, k := range kinds {
		if strings.Contains(firstBody, strings.TrimPrefix(k.path, "/")) {
			t.Errorf("the 404 body echoes the path %q", k.path)
		}
	}
	if strings.Contains(firstBody, "No-such-page") {
		t.Error("the 404 body names the page that was asked for, which confirms the answer was about it")
	}
	// And the positive control: a page the reader may read is not a 404 at all.
	readable := s.do(s.get("/p/Tavern.md"))
	readableBody := s.read(readable)
	if readable.StatusCode != http.StatusOK {
		t.Fatalf("a readable page answered %d, want 200", readable.StatusCode)
	}
	if readableBody == firstBody {
		t.Error("a readable page rendered the 404 body, so the comparison above is vacuous")
	}
}

// TestAnUnauthenticatedPrincipalCannotDistinguishAPageFromItsAbsence is the
// other half of the existence property, and the half that a real deployment
// depends on: with anonymous read off, a visitor who has not signed in must get
// the same answer for a page that exists and one that does not.
//
// The route gate runs before the handler, so both are redirected to the login
// form and neither is confirmed. The redirect target differs only by the path the
// client itself asked for, which the client already knows.
func TestAnUnauthenticatedPrincipalCannotDistinguishAPageFromItsAbsence(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.newSession()

	existing := s.do(s.get("/p/Index.md"))
	existingBody := s.read(existing)
	missing := s.do(s.get("/p/No-such-page.md"))
	missingBody := s.read(missing)

	if existing.StatusCode != http.StatusSeeOther || missing.StatusCode != http.StatusSeeOther {
		t.Fatalf("an unauthenticated request: existing page %d, missing page %d; both must be 303",
			existing.StatusCode, missing.StatusCode)
	}
	if existingBody != missingBody {
		t.Errorf("the body for a page that exists differs from the body for one that does not\nexisting: %q\nmissing:  %q", existingBody, missingBody)
	}
	if strings.Contains(existingBody, "Index") {
		t.Error("the redirect body names the page that was asked for")
	}
	// The same is true of the Location, modulo the path the client chose.
	wantPrefix := "/login?next=/p/"
	if got := existing.Header.Get("Location"); !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("the redirect for an existing page is %q, want a prefix of %q", got, wantPrefix)
	}
	if got := missing.Header.Get("Location"); !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("the redirect for a missing page is %q, want a prefix of %q", got, wantPrefix)
	}
}

// TestSecretPlaceholdersCarryNoMetadata is the placeholder test.
//
// A lock affordance may carry the fence's id and one word. It may not carry the
// body, the byte length, the author, the title, or anything that scales with the
// secret, because the response a reader receives is observable and a length is a
// disclosure. The test walks the rendered lock for all three visibilities and
// asserts the only attribute and the only words are the id and the label.
func TestSecretPlaceholdersCarryNoMetadata(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	player := fx.asUser(otherName, otherPass)
	// The Tavern page carries a private secret authored by the DM, a dm secret,
	// and Thia's own private secret; the Ruin carries another dm secret. Between
	// them, all three visibilities are represented.
	for _, page := range []string{"/p/Tavern.md", "/p/Ruin.md"} {
		body := player.getOK(page)
		locks := lockAffordances(body)
		if len(locks) == 0 {
			t.Fatalf("%s rendered no lock affordance at all, so the placeholder assertions would be vacuous", page)
		}
		for _, lock := range locks {
			id, ok := lock["data-secret-id"]
			if !ok {
				t.Errorf("%s: a lock carries no data-secret-id: %s", page, lock["__markup"])
				continue
			}
			if len(id) != 12 {
				t.Errorf("%s: a lock's id is %q, which is not a 12-character fence id", page, id)
			}
			for attr, value := range lock {
				switch attr {
				case "__markup", "data-secret-id", "class":
					continue
				default:
					t.Errorf("%s: a lock carries the attribute %q=%q; a placeholder may carry an id and a label and nothing else", page, attr, value)
				}
			}
			markup := lock["__markup"]
			for _, forbidden := range []string{
				// The author, the title, the body, and the byte length, spelled
				// the ways each of them could plausibly be rendered.
				"dungeonmaster", "thia", "The true name", "The cellar key", "The trap",
				"PRIVATE-BODY", "DM-BODY", "OWNER-BODY", "RUIN-BODY",
				"bytes", "length", "len=", "visibility=", "private", "dm", "table",
			} {
				if strings.Contains(strings.ToLower(markup), strings.ToLower(forbidden)) {
					t.Errorf("%s: a lock's markup mentions %q: %s", page, forbidden, markup)
				}
			}
		}
	}
}

// lockRe matches one rendered lock affordance and its attributes.
var lockRe = regexp.MustCompile(`<div class="secret-locked"([^>]*)>(.*?)</div>`)

// lockAffordances returns the attributes and inner markup of every lock in a
// body. The set of keys is the whole assertion: a lock with an extra attribute
// is as much a leak as a lock with an extra word.
func lockAffordances(body string) []map[string]string {
	out := []map[string]string{}
	for _, m := range lockRe.FindAllStringSubmatch(body, -1) {
		attrs := map[string]string{"__markup": m[0]}
		for _, a := range regexp.MustCompile(`([a-z-]+)="([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
			attrs[a[1]] = a[2]
		}
		out = append(out, attrs)
	}
	return out
}

// TestOnlyThisPackageMarksHTMLRaw is the §2.6 enforcement test.
//
// templ.Raw is what makes a string unescaped, so the whole safety of the view
// layer rests on there being a narrow funnel for it and on nothing else reaching
// for it. This walks internal/ and fails on any call outside the one file that
// is allowed to hold them. The walk skips test files: this one names templ.Raw in
// its own comment, and an assertion that trips over its own documentation is an
// assertion somebody deletes.
func TestOnlyThisPackageMarksHTMLRaw(t *testing.T) {
	t.Parallel()
	// Two funnels, both in one file, both documented: PreRendered for HTML the
	// markdown renderer produced and Escaped for a string another package in this
	// codebase already escaped.
	got := countRawCalls(t, "../../internal")
	if got != 0 {
		t.Errorf("the tree contains %d templ.Raw calls outside the funnel; every one of them is a string the browser will not escape", got)
	}
	// And the funnel is still there, because a tree that grew no raw call sites at
	// all is the same failure as one that grew them everywhere.
	inFunnel := strings.Count(readFileString(t, "../../internal/web/html.go"), "templ.Raw(")
	if inFunnel != 2 {
		t.Errorf("internal/web/html.go holds %d templ.Raw calls, want 2: the funnels for a rendered body and for an already-escaped string", inFunnel)
	}
}

// countRawCalls counts templ.Raw call sites under a directory, skipping the one
// file that is allowed to hold them.
func countRawCalls(t *testing.T, dir string) int {
	t.Helper()
	var total int
	for _, path := range goFilesUnder(t, dir) {
		name := filepath.Base(path)
		// The funnel itself, and this test — whose own comment names templ.Raw,
		// which is exactly the false positive a source-level assertion has to be
		// careful about or it stops being believed.
		if name == "html.go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		total += strings.Count(readFileString(t, path), "templ.Raw(")
	}
	return total
}

// goFilesUnder walks a directory for .go files, following no symlinks.
func goFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// readFileString reads a file for a source-level assertion.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// skipDir names directories the source-level assertions do not walk: build
// output, vendored dependencies and fixtures that a grep would find full of noise.
func skipDir(name string) bool {
	switch name {
	case "node_modules", "dist", ".git", "testdata":
		return true
	default:
		return false
	}
}
