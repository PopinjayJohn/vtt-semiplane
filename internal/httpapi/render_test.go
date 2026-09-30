package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// TestNoRemoteAssetReference is the §2.5 test, and it is a grep of our own output
// rather than a scan of the source.
//
// A rule that says "no remote origin" and is enforced only by a reviewer's eyes is
// a rule that fails the day somebody adds a CDN link. This walks every page the
// server can render, the committed stylesheet and the shell script, and fails on
// any absolute http or https URL, any protocol-relative //host reference, and any
// of the shapes a remote origin takes in CSS and in JavaScript.
func TestNoRemoteAssetReference(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)

	pages := []string{"/", "/search?q=lantern", "/p/Index.md", "/p/Tavern.md", "/p/Ruin.md", "/healthz", "/readyz"}
	for _, path := range pages {
		assertNoRemoteReference(t, "the body of "+path, s.getOK(path))
	}
	// The two pre-session forms and the invite page, reached as a visitor. A
	// signed-in client is redirected away from /login, which is the right answer
	// and would make this a test of the redirect instead of of the shell.
	anon := fx.newSession()
	anon.prime()
	for _, path := range []string{"/login", "/invite/whatever"} {
		assertNoRemoteReference(t, "the body of "+path, anon.getOK(path))
	}
	// A fragment is the same content with the shell left off, and a shell that
	// introduced a remote origin would put it in the shell.
	assertNoRemoteReference(t, "the fragment of /p/Tavern.md", s.text(s.fragment("/p/Tavern.md")))

	// The assets are checked with a targeted pattern rather than the loose one
	// above, because a stylesheet's licence comment and an SVG's namespace
	// declaration both contain an absolute URL and neither is a fetch. What must
	// not appear is a remote origin in a position a browser resolves.
	for _, asset := range []string{"app.css", "app.js", "icons.svg", "vendor/datastar.js"} {
		assertNoRemoteFetch(t, asset, s.getOK("/_/assets/"+asset))
	}

	// The header is checked separately, with the policy's own allowance removed.
	resp := s.do(s.get("/"))
	defer drain(resp)
	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "://") || strings.Contains(csp, "unsafe-") {
		t.Errorf("the content security policy names a remote origin or an unsafe keyword: %s", csp)
	}
	for _, want := range []string{
		"default-src 'self'", "script-src 'self'", "style-src 'self'",
		"object-src 'none'", "frame-ancestors 'none'", "form-action 'self'", "base-uri 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("the content security policy is missing %q: %s", want, csp)
		}
	}
}

// remoteReference matches the shapes a remote origin takes in a document: an
// absolute URL, a protocol-relative reference, and a bare //host that a CSS url()
// or a script src would resolve against the document's own scheme.
//
// The scheme list is explicit rather than a general "://" match so that an
// xml-namespaced URL or a doc-comment example cannot trip it by accident: a grep
// that cries wolf is a grep that gets disabled.
var remoteReference = regexp.MustCompile(
	`(?i)\b(?:https?:|ftp:|ws{1,2}:)//|\b(?://[a-z0-9-]+\.[a-z]{2,})|\burl\(\s*['"]?\s*/[a-z0-9-]+\.[a-z]{2,}`)

// assertNoRemoteReference fails on any remote reference in a body.
func assertNoRemoteReference(t *testing.T, what, body string) {
	t.Helper()
	if m := remoteReference.FindString(body); m != "" {
		t.Errorf("%s refers to a remote origin: %q", what, m)
	}
}

// remoteFetch matches a remote origin in a position a browser acts on: a CSS
// url() or @import, an attribute a document fetches from, and a fetch or XHR
// target in a script.
var remoteFetch = regexp.MustCompile(
	`(?i)url\(\s*['"]?\s*(?:https?:)?//|@import\s+(?:url\()?\s*['"]\s*(?:https?:)?//|` +
		`(?:src|href|action|poster|data)\s*=\s*["'](?:https?:)?//|` +
		"(?:fetch|open|send)\\s*\\(\\s*[\"'](?:https?:)?//")

// assertNoRemoteFetch fails when an asset references a remote origin in a way a
// browser would act on.
func assertNoRemoteFetch(t *testing.T, what, body string) {
	t.Helper()
	if m := remoteFetch.FindString(body); m != "" {
		t.Errorf("%s fetches from a remote origin: %q", what, m)
	}
}

// TestAssetsAreServedFromTheBinary asserts that every asset in the table resolves
// with the right content type and with bytes identical to the embedded file.
//
// Byte-identical is the point: an asset handler that transforms on the way out —
// re-minifying, rewriting a url, appending a cache-busting query — is an asset
// handler that can be made to serve something the binary never contained.
func TestAssetsAreServedFromTheBinary(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := fx.newSession()

	cases := []struct{ name, ctype string }{
		{name: "app.css", ctype: "text/css; charset=utf-8"},
		{name: "app.js", ctype: "text/javascript; charset=utf-8"},
		{name: "icons.svg", ctype: "image/svg+xml"},
		{name: "vendor/datastar.js", ctype: "text/javascript; charset=utf-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := s.do(s.get("/_/assets/" + tc.name))
			got := resp.StatusCode
			body := s.read(resp)
			if got != http.StatusOK {
				t.Fatalf("status %d, want 200", got)
			}
			if ct := resp.Header.Get("Content-Type"); ct != tc.ctype {
				t.Errorf("content type is %q, want %q", ct, tc.ctype)
			}
			if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Error("no nosniff on an asset")
			}
			if resp.Header.Get("Cache-Control") == "" {
				t.Error("no cache control on an asset")
			}
			// The bytes must be the embedded bytes, and the asset FS is the one the
			// production wiring passes.
			embedded, err := web.Assets().Open(tc.name)
			if err != nil {
				t.Fatalf("the asset is not in the embedded filesystem: %v", err)
			}
			defer func() { _ = embedded.Close() }()
			buf := make([]byte, 1<<22)
			n, _ := embedded.Read(buf)
			if body != string(buf[:n]) {
				t.Errorf("the served bytes differ from the embedded file: %d served, %d embedded", len(body), n)
			}
			if n == 0 {
				t.Error("the embedded file is empty, so the byte comparison above is vacuous")
			}
		})
	}

	t.Run("a file that is not in the table is unreachable", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"../assets.go", "app.css.map", "vendor/../../go.mod", "secret.txt", ""} {
			resp := s.do(s.get("/_/assets/" + name))
			got := resp.StatusCode
			drain(resp)
			if got != http.StatusNotFound {
				t.Errorf("/_/assets/%s: status %d, want 404", name, got)
			}
		}
	})
}

func TestPageViewIsNegotiated(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	raw := fx.cookieValue(fx.asUser(otherName, otherPass), httpapi.SessionCookie)

	cases := []struct{ name, path string }{
		{name: "page", path: "/p/Tavern.md"},
		{name: "dashboard", path: "/"},
		{name: "search", path: "/search?q=lantern"},
		{name: "error", path: "/p/No-such-page.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A client per subtest. A shared one would have two goroutines writing
			// the same CSRF token from responses at once, which the race detector
			// is right to call a race and which would make this test's failures
			// about the harness rather than about the router.
			s := fx.sessionFor(raw)
			document := s.text(s.get(tc.path))
			fragment := s.text(s.fragment(tc.path))

			if !hasDoctype(document) {
				t.Errorf("the document for %s is not a whole HTML document:\n%s", tc.path, snippet(document))
			}
			// "<head>" and not "<head": the page template has a <header>, and a
			// test that cannot tell a shell from a header is a test that will be
			// "fixed" by deleting the assertion.
			if hasDoctype(fragment) || strings.Contains(fragment, "<head>") || strings.Contains(fragment, "<head ") {
				t.Errorf("the fragment for %s carries a document shell", tc.path)
			}
			if !strings.Contains(fragment, `id="page-region"`) {
				t.Errorf("the fragment for %s has no page-region to swap into", tc.path)
			}
			if len(fragment) >= len(document) {
				t.Errorf("the fragment for %s is %d bytes and the document is %d; the fragment must be strictly smaller",
					tc.path, len(fragment), len(document))
			}
			for _, line := range strings.Split(fragment, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if !strings.Contains(document, line) {
					t.Errorf("the fragment for %s contains a line the document does not:\n%s", tc.path, line)
				}
			}
			// And both carry the same content, which is the security half: a
			// fragment that showed a different amount of the page would be a
			// second authorization decision made by a different code path.
			assertNoToken(t, fragment, "DM-BODY-TOKEN-7b1e4d", "the dm secret in a fragment")
		})
	}

	t.Run("an unrecognised shape header is a document", func(t *testing.T) {
		t.Parallel()
		// Not " true": leading whitespace in a header value is stripped by the
		// parser, so that value arrives as "true" and the server is right to treat
		// it as a fragment. A test asserting otherwise would be asserting that the
		// HTTP parser is broken.
		s := fx.sessionFor(raw)
		for _, header := range []string{"", "1", "yes", "TRUE", "false", "True"} {
			c := s.get("/p/Index.md")
			if header != "" {
				c.headers = map[string]string{httpapi.DataStarRequestHeader: header}
			}
			if body := s.text(c); !hasDoctype(body) {
				t.Errorf("with %s=%q the response is not a whole document", httpapi.DataStarRequestHeader, header)
			}
		}
	})

	t.Run("the 404 region is the 404 document's region", func(t *testing.T) {
		t.Parallel()
		// Byte-identity has to hold across the negotiation too: a fragment 404 that
		// was a different shape would be a second existence signal.
		s := fx.sessionFor(raw)
		document := s.text(s.get("/p/No-such-page.md"))
		fragment := s.text(s.fragment("/p/No-such-page.md"))
		if !strings.Contains(fragment, strings.TrimSpace(regionOf(document))) {
			t.Error("the 404 fragment is not the region of the 404 document")
		}
	})
}

// hasDoctype reports whether a body is a whole HTML document. The comparison is
// case-insensitive because the doctype is not case-sensitive, and a test that
// pinned its spelling would fail on a template change that changed nothing.
func hasDoctype(body string) bool {
	trimmed := strings.TrimSpace(body)
	return len(trimmed) >= 9 && strings.EqualFold(trimmed[:9], "<!doctype")
}

// regionOf is the content region of a document, without the region element.
func regionOf(document string) string {
	const open = `<div id="page-region" tabindex="-1">`
	i := strings.Index(document, open)
	if i < 0 {
		return document
	}
	rest := document[i+len(open):]
	if j := strings.Index(rest, "</main>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestXSSFixturesAreEscaped runs the hostile inputs §2.6 is about.
//
// Each fixture is a thing a player can save into a note, so each is a stored-XSS
// attempt rather than a hypothetical: a script element, an attribute break with an
// event handler, a javascript: URL in a markdown link, an obsidian embed of a
// filename crafted to escape its own attribute, and the same tricks with the case
// and the syntax varied.
func TestXSSFixturesAreEscaped(t *testing.T) {
	t.Parallel()

	fixtures := map[string]string{
		"Script.md": "---\ntitle: Script\n---\n\n# Script\n\n<script>alert(1)</script>\n\n" +
			"<img src=x onerror=alert(1)>\n\n" +
			"```\n<script>alert('in a code block')</script>\n```\n",
		"Attribute.md": "---\ntitle: Attribute\n---\n\n# Attribute\n\n" +
			"\"><img src=x onerror=alert(1)>\n\n" +
			"a [link](https://example.invalid/\"><script>alert(2)</script>)\n",
		"Scheme.md": "---\ntitle: Scheme\n---\n\n# Scheme\n\n" +
			"[click me](javascript:alert(1))\n\n" +
			"[data](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)\n\n" +
			"<a href=\"javascript:alert(3)\">raw</a>\n",
		"Embed.md": "---\ntitle: Embed\n---\n\n# Embed\n\n" +
			"![[image\"><script>alert(1)</script>.png]]\n\n" +
			"![[../../../../etc/passwd]]\n",
		"Obfuscated.md": "---\ntitle: Obfuscated\n---\n\n# Obfuscated\n\n" +
			"<ScRiPt>alert(1)</ScRiPt>\n\n" +
			"<svg/onload=alert(1)>\n\n" +
			"<iframe src=\"javascript:alert(1)\"></iframe>\n",
	}

	for name := range fixtures {
		t.Run(strings.TrimSuffix(name, ".md"), func(t *testing.T) {
			t.Parallel()
			fx := newFixtureWith(t, fixtures)
			fx.accounts()
			s := fx.asUser(dmName, dmPass)
			assertNoXSS(t, name, pageRegion(t, s.getOK("/p/"+name)))
			// And the same page as a fragment, because a fragment is rendered by a
			// different call in the renderer and a difference between the two shapes
			// would be a hole in one of them.
			assertNoXSS(t, name+" as a fragment", pageRegion(t, s.text(s.fragment("/p/"+name))))
		})
	}
}

// pageRegion is the part of a document the server produced from a vault file: the
// content region and nothing else.
//
// The XSS assertion runs over this rather than over the whole document, because
// the shell legitimately contains a script tag — the vendored DataStar bundle this
// application serves — and a test that cannot tell the application's own script
// from a vault's is a test that would be "fixed" by deleting the fixture.
func pageRegion(t *testing.T, document string) string {
	t.Helper()
	const open = `<div id="page-region" tabindex="-1">`
	i := strings.Index(document, open)
	if i < 0 {
		t.Fatalf("the document has no content region, so the assertion would be vacuous:\n%s", snippet(document))
	}
	rest := document[i+len(open):]
	if j := strings.Index(rest, "</main>"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// executable matches the shapes of markup a browser will run: a script element, an
// inline event handler, and a javascript: or data: URL.
var executable = regexp.MustCompile(`(?i)<script|onerror\s*=|onload\s*=|javascript:|data:text/html`)

// assertNoXSS fails when a rendered page contains anything a browser will execute.
//
// The check is positional rather than a plain substring search, because a
// passthrough box legitimately shows the *source* of a hostile construct as
// escaped text — that is the feature, not a leak. What must never appear is the
// construct in a position the parser will act on.
func assertNoXSS(t *testing.T, what, rendered string) {
	t.Helper()
	lower := strings.ToLower(rendered)
	for _, m := range executable.FindAllString(lower, -1) {
		i := strings.Index(lower, m)
		ctx := rendered[max(0, i-70):min(len(rendered), i+70)]
		switch {
		case m == "javascript:" || m == "data:text/html":
			// A javascript: URL is a leak only inside an attribute a browser
			// navigates from. Elsewhere it is escaped text.
			if strings.Contains(ctx, `href="`) || strings.Contains(ctx, `src="`) {
				t.Errorf("%s produced an executable URL: %s", what, ctx)
			}
		case strings.HasPrefix(m, "onerror"), strings.HasPrefix(m, "onload"):
			// An event handler is a leak only as an attribute of a real element.
			if strings.Contains(ctx, "<") && !strings.Contains(ctx, "&lt;") {
				t.Errorf("%s produced an inline event handler: %s", what, ctx)
			}
		default:
			if !strings.Contains(ctx, "&lt;script") {
				t.Errorf("%s produced a script element: %s", what, ctx)
			}
		}
	}
	// The blunt version, as a backstop for a shape the positional check above
	// did not think of: a live script element that this application did not put
	// in its own layout.
	if strings.Contains(rendered, "<script>alert") {
		t.Errorf("%s emitted a live script element", what)
	}
}

// raceEnabled reports whether this binary was built with the race detector.
//
// It is a build tag rather than a runtime probe, and the branch it guards is not
// compiled out in either build: a test that quietly asserts less under -race is a
// test that nobody is told about, so both builds carry the code and only one of
// them takes the deadline.
func raceEnabled() bool { return raceBuild }

// proseLine is an ordinary line of campaign prose, newline included, so that a
// fixture built from it is made of real lines.
const proseLine = "The lantern gutters and the tide comes in, and nobody in the tavern says a word.\n"

// TestTheRenderPathIsBounded is the goldmark hazard, and it is a test with a
// deadline rather than a test with a timeout.
//
// goldmark's inline loop rescans the rest of a line at every character that could
// open an inline construct, so the cost of one line is quadratic in its length:
// 64 KiB of `[` is about 140 ms, and 1 MiB extrapolates to about twelve seconds. A
// player who can save a note could therefore pin a request, so the page-render
// path caps the two things that make the parser quadratic — the total body and the
// longest run of bytes on one line — and this asserts the cap holds by measuring
// the time rather than by reading the constant.
func TestTheRenderPathIsBounded(t *testing.T) {
	t.Parallel()

	// The sizes are chosen against the *index* budget rather than the render
	// budget. The request under test is bounded by the caps, but the fixture's
	// index pass parses the whole file through the same uncapped goldmark loop, and
	// that pass is quadratic in a single line. 128 KiB on one line is eight times
	// the line cap — enough to prove the clip — and costs a second or two to index
	// rather than half a minute.
	cases := []struct {
		name string
		body string
		// wantUnclipped says the page is within every budget and must therefore not
		// claim to be clipped. Without it a cap that clipped *everything* would pass
		// these assertions, which is the failure a budget test has to rule out as
		// carefully as the one it is looking for.
		wantUnclipped bool
	}{
		{
			name: "128 KiB of inline openers on one line",
			body: strings.Repeat("[", 128<<10),
		},
		{
			// A different inline construct, because the quadratic walk looks for
			// emphasis as well as for brackets.
			name: "64 KiB of emphasis markers on one line",
			body: strings.Repeat("**a", (64<<10)/3),
		},
		{
			// Over the total budget with every line a normal length, so the *other*
			// cap is the one that fires. Prose is linear to index, so this is cheap
			// in the fixture and cheap in the request.
			// Newlines, because a "prose" fixture without them is a single long
			// line and the *line* cap is what would clip it — which would make the
			// unclipped control below a claim about the wrong cap.
			name: "three megabytes of prose",
			body: strings.Repeat(proseLine, (3<<20)/len(proseLine)),
		},
		{
			// The control: an ordinary long page, under both caps, which must render
			// in full and must not claim otherwise.
			name:          "a megabyte and a half of prose",
			body:          strings.Repeat(proseLine, (3<<19)/len(proseLine)),
			wantUnclipped: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A page over the file cap is refused by the walker, so every fixture
			// here is written under it: eight megabytes is the largest file the
			// indexer will accept, and that is the largest body that can reach a
			// render at all.
			if int64(len(tc.body)) > vault.MaxFileBytes {
				t.Fatalf("the fixture is %d bytes, over the %d the indexer accepts", len(tc.body), vault.MaxFileBytes)
			}
			fx := newFixtureWith(t, map[string]string{"Hostile.md": "---\ntitle: Hostile\n---\n\n" + tc.body})
			fx.accounts()
			s := fx.asUser(dmName, dmPass)

			start := time.Now()
			resp := s.do(s.get("/p/Hostile.md"))
			body := s.read(resp)
			elapsed := time.Since(start)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}
			// The deadline is not asserted under the race detector. A race build
			// instruments every memory access and runs three to ten times slower, so
			// the number it produces says something about the instrumentation and
			// nothing about the render path — and a budget that only holds in the
			// uninstrumented build is a budget that gets raised the first time
			// somebody runs the race suite. The *shape* assertions below are asserted
			// in both modes, because what the caps do is not a timing question.
			if !raceEnabled() {
				const budget = 3 * time.Second
				if elapsed > budget {
					t.Errorf("rendering %d bytes took %s, over the %s budget", len(tc.body), elapsed, budget)
				}
			}
			// And the response is bounded, not merely fast: a render that took no
			// time because it produced nothing would pass the deadline.
			if len(body) < 512 {
				t.Errorf("the response is %d bytes, which is too small to be a rendered page", len(body))
			}
			clipped := strings.Contains(body, "longer than one view")
			switch {
			case tc.wantUnclipped && clipped:
				t.Errorf("a body of %d bytes of ordinary prose was reported as clipped; the budget is meant to bite only on pathological input", len(tc.body))
			case !tc.wantUnclipped && !clipped:
				t.Errorf("a body of %d bytes was not reported as clipped", len(tc.body))
			}
		})
	}
}

// TestTheRenderCapClipsRatherThanBreaksAFile is the byte-preservation half.
//
// The cap is on the *view*, never on the file: the page's bytes on disk are exactly
// what was written, and the index row's content hash still matches. A cap that
// wrote back a clipped body would be the worst possible bug in this codebase, so
// it is asserted directly rather than inferred from the page looking right.
func TestTheRenderCapClipsRatherThanBreaksAFile(t *testing.T) {
	t.Parallel()
	source := "---\ntitle: Long\n---\n\n" + strings.Repeat("[", 128<<10)
	fx := newFixtureWith(t, map[string]string{"Long.md": source})
	fx.accounts()
	s := fx.asUser(dmName, dmPass)
	if body := s.getOK("/p/Long.md"); !strings.Contains(body, "longer than one view") {
		t.Fatal("the page did not report being clipped, so the assertions below are not about a clipped render")
	}

	onDisk, err := os.ReadFile(filepath.Join(fx.dir, "Long.md"))
	if err != nil {
		t.Fatalf("read the file back: %v", err)
	}
	if string(onDisk) != source {
		t.Error("the render cap rewrote the file; the view was to be clipped, not the vault")
	}
	row, err := store.GetPageByPath(t.Context(), fx.DB.Reader(), "Long.md")
	if err != nil {
		t.Fatalf("read the page row: %v", err)
	}
	// ContentHash is the raw sha256 of the file, not a hash of a hash.
	want := sha256.Sum256([]byte(source))
	if row.ContentHash == nil || !bytes.Equal(row.ContentHash, want[:]) {
		t.Error("the indexed content hash no longer matches the file; something rewrote the bytes")
	}
	if int64(len(onDisk)) != row.SizeBytes {
		t.Errorf("the index records %d bytes and the file has %d", row.SizeBytes, len(onDisk))
	}
}
