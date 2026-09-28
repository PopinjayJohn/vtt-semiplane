package httpapi_test

import (
	"io"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The command palette's fragment response.
//
// Everything here exists because the palette is the one surface whose transport
// is not obvious. It is not an event stream, and it is not JSON, and the reasons
// are in internal/httpapi/datastar.go. What is left is a fragment of HTML
// rendered by the same component the full page uses, fetched by app.js, and
// these are the tests that hold all three claims at once.

// The palette row markup, as CommandRow renders it. A test reading this is
// reading a shape this file defines, which is deliberate: the alternative is a
// test that passes against any markup at all and therefore proves nothing.
var (
	paletteRowRe   = regexp.MustCompile(`<li><a href="([^"]+)"[^>]*>(.*?)</a></li>`)
	paletteIconRe  = regexp.MustCompile(`icons\.svg#(i-[a-z-]+)`)
	paletteHintRe  = regexp.MustCompile(`<kbd[^>]*>([^<]*)</kbd>`)
	paletteLabelRe = regexp.MustCompile(`<span class="font-medium">([^<]*)</span>`)
)

// commandsFrom turns a fragment into the rows it contains.
func commandsFrom(t *testing.T, elements string) jsonCommandsBody {
	t.Helper()
	if strings.TrimSpace(elements) == "" {
		t.Fatalf("the fragment carried no markup at all")
	}
	// The fragment is parsed with DOMParser in the client, so it must be a
	// fragment and not a document. A whole document in here would be parsed and
	// its <html> discarded, leaving the rows to render inside the region by
	// accident — which is the kind of accident that works until it does not.
	if strings.Contains(elements, "<!doctype") || strings.Contains(elements, "<html") {
		t.Fatalf("the fragment is a whole document, not a region: %s", snippet(elements))
	}
	var out jsonCommandsBody
	for _, m := range paletteRowRe.FindAllStringSubmatch(elements, -1) {
		row := jsonCommandBody{Href: m[1]}
		if icon := paletteIconRe.FindStringSubmatch(m[2]); icon != nil {
			switch icon[1] {
			case "i-command":
				row.Kind = httpapi.CommandAction
			case "i-book":
				row.Kind = httpapi.CommandPage
			case "i-tag":
				row.Kind = httpapi.CommandTag
			}
		}
		if label := paletteLabelRe.FindStringSubmatch(m[2]); label != nil {
			row.Label = label[1]
		}
		if hint := paletteHintRe.FindStringSubmatch(m[2]); hint != nil {
			row.Hint = hint[1]
		}
		out.Commands = append(out.Commands, row)
	}
	return out
}

// commandsFor fetches the palette the way the enhancement does: a fragment
// request, answered with the region as HTML.
func commandsFor(t *testing.T, s *session, q string) jsonCommandsBody {
	t.Helper()
	return commandsFrom(t, s.getOK("/_/commands?into=palette&fragment=1"+"&q="+url.QueryEscape(q)))
}

// commandsDocument fetches the palette as a browser does, with no fragment
// parameter, and asserts it is a document.
//
// Every row in the palette is a real href, so the URL has to be a page a browser
// can be sent to. A reader with the enhancement blocked is not a degraded
// reader, and a JSON answer would make "the palette works without JavaScript" a
// claim about a URL that is not a page.
func commandsDocument(t *testing.T, s *session, q string) string {
	t.Helper()
	path := "/_/commands"
	if q != "" {
		path += "?q=" + url.QueryEscape(q)
	}
	return s.getOK(path)
}

// TestThePaletteFragmentIsHTMLAndNotAWholeDocument is the transport, stated as
// a test.
//
// The two shapes this could have been are both silently wrong in a browser: an
// application/json response is a *signals* patch, so the rows would be merged
// into the reactive store and never rendered, and a whole document would be
// parsed with its <html> discarded. Neither throws. The palette would just be
// empty, with nothing in the console.
func TestThePaletteFragmentIsHTMLAndNotAWholeDocument(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	resp := s.do(s.get("/_/commands?into=palette&fragment=1&q=Tav"))
	body := s.read(resp)
	if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
		t.Errorf("the palette answered %q, want %q", got, want)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("the palette's fragment is cacheable as %q: it carries page titles", got)
	}
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Cookie") {
		t.Errorf("the palette's fragment does not vary on Cookie, so a shared cache could serve one principal's titles to another")
	}
	rows := commandsFrom(t, body)
	if len(rows.Commands) == 0 {
		t.Fatal("the fragment carried no rows for a term that matches a page")
	}
	if !strings.Contains(body, `href="/p/Tavern.md"`) {
		t.Errorf("the fragment did not carry the page the term names: %s", snippet(body))
	}
}

// TestThePaletteRegionNameIsChosenByTheServerNotTheClient is the property that
// makes the `into` parameter safe to accept from a request.
//
// A client that chose its own target could name any element on the page, and the
// server would write a fragment rendered for one purpose into it. So the name is
// a closed set, the element it maps to is the server's, and a name the server
// has never heard of is a 400 rather than a quiet fallback.
func TestThePaletteRegionNameIsChosenByTheServerNotTheClient(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	for _, into := range []string{"body", "main", "palette-results", "anything-else", "../etc"} {
		if got := s.status(s.get("/_/commands?into=" + url.QueryEscape(into) + "&fragment=1")); got != 400 {
			t.Errorf("into=%q was answered %d, want 400: a client must not be able to name the element the server writes into", into, got)
		}
	}
	for _, into := range []string{"palette", "page"} {
		if got := s.status(s.get("/_/commands?into=" + into + "&fragment=1")); got != 200 {
			t.Errorf("into=%q was answered %d, want 200", into, got)
		}
	}
	// An absent name falls back rather than failing, because the dialog's fetch
	// is the one that can arrive without one.
	if got := s.status(s.get("/_/commands?fragment=1")); got != 200 {
		t.Errorf("a fragment request with no region was answered %d, want 200", got)
	}
}

// TestEveryRegionNameIsAddressedByTheMarkup holds the two tables together.
//
// regionTargets says what the server can render; regionSelectors says where the
// markup says to put it. They are two tables because the client must not be told
// a selector over the wire, and a region the server can render but no element can
// show is a feature that does nothing — which is how the palette's first version
// worked for two days.
func TestEveryRegionNameIsAddressedByTheMarkup(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	for name, selector := range map[string]string{
		"palette": "#palette-results",
		"page":    "#command-results",
	} {
		if got := s.getOK("/_/commands?into=" + name + "&fragment=1"); got == "" {
			t.Errorf("the %q region rendered nothing", name)
		}
		// The document for that surface must name its own region, or the client
		// has nowhere to put the rows.
		body := s.getOK(map[string]string{
			"palette": "/",
			"page":    "/_/commands",
		}[name])
		if !strings.Contains(body, `data-region-target="`+selector+`"`) {
			t.Errorf("the %q surface does not declare data-region-target=%q, so the client has nowhere to put the rows", name, selector)
		}
	}
}

// TestThePaletteIsARealPageWithoutJavaScript is the promise §4.1 makes.
func TestThePaletteIsARealPageWithoutJavaScript(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	body := commandsDocument(t, s, "Tav")
	if !strings.HasPrefix(strings.ToLower(body), "<!doctype html>") {
		t.Errorf("/_/commands is not a document: %s", snippet(body))
	}
	for _, want := range []string{`id="commands-q"`, `id="command-results"`, `href="/p/Tavern.md"`, `role="search"`, `name="q"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the palette page is missing %s", want)
		}
	}
}

// TestThePaletteFragmentAndThePageAgree is the "one implementation" cross-check.
//
// The fragment and the document are the same component called twice, and the
// only way that stops being true is a handler that grows a second version. So
// this compares the two byte for byte on the region each of them renders.
func TestThePaletteFragmentAndThePageAgree(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	page := s.getOK("/_/commands?into=page&fragment=1&q=Tav")
	document := s.getOK("/_/commands?q=Tav")
	if !strings.Contains(document, page) {
		t.Errorf("the region the fragment returns is not the region the page renders.\nfragment: %s", snippet(page))
	}
}

// TestTheVendoredDataStarStillRoutesJSONToSignals is the test that makes the
// claim "we pinned DataStar" mean something.
//
// The reason the palette is a plain fetch and not a `@get` is a branch in a
// minified file that a dependency bump could remove silently. If the branch
// goes, this fails and somebody has to decide again whether the bundle's own
// actions are usable here — rather than discovering it when a reader reports an
// empty palette.
func TestTheVendoredDataStarStillRoutesJSONToSignals(t *testing.T) {
	t.Parallel()
	bundle := readVendoredDataStar(t)
	for _, want := range []string{
		"datastar-patch-signals", // the branch an application/json response takes
		"application/json",
		"datastar-patch-elements", // the action this codebase decided not to use
	} {
		if !strings.Contains(bundle, want) {
			t.Errorf("the vendored DataStar no longer contains %q: the transport this codebase works around is being read by a version that is not the one pinned here", want)
		}
	}
}

// readVendoredDataStar returns the pinned bundle's bytes, out of the binary's
// own embedded filesystem rather than out of a path on disk.
//
// The test is about what will be served, and the served bytes come from the
// embed. Reading the file from the working tree instead would pass even if the
// embed had been narrowed, which is the failure that would matter.
func readVendoredDataStar(t *testing.T) string {
	t.Helper()
	f, err := web.Assets().Open("vendor/datastar.js")
	if err != nil {
		t.Fatalf("the vendored DataStar is not in the embedded assets: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read the vendored DataStar: %v", err)
	}
	return string(b)
}
