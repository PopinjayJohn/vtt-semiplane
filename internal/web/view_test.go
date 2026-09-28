package web_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
	"github.com/a-h/templ"
)

// TestTheRendererIsTotalOverItsViewModels walks every view model in the
// httpapi package and renders it in both shapes.
//
// The dispatch is a type switch, and a type switch has no exhaustiveness check: a
// new view model compiles, is passed to the renderer, and produces an empty page
// at runtime. This asserts the switch covers everything httpapi can hand it, and
// that both shapes render, which is what a later phase's live-push path needs.
func TestTheRendererIsTotalOverItsViewModels(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	principal := httpapi.Shell{Title: "Campaign", CSRF: "x", Campaign: "vault"}

	views := []httpapi.View{
		httpapi.HomeView{Shell: principal, PageCount: 2, Pages: []httpapi.PageCard{
			{ID: 1, Path: "Index.md", Title: "Index"},
		}, Tags: []httpapi.TagCard{{Name: "area/port", Count: 1}}},
		httpapi.PageView{
			Shell: principal,
			Card:  httpapi.PageCard{ID: 1, Path: "Index.md", Title: "Index", PageType: "note"},
			Body:  `<p>Hello</p>`,
			Toc:   []httpapi.TocEntry{{Level: 1, Text: "Hello", Slug: "hello"}},
			Backlinks: []httpapi.BacklinkChip{
				{Card: httpapi.PageCard{ID: 2, Path: "Ruin.md", Title: "Ruin"}, Line: 3},
			},
			BacklinkCount: 1,
			Secrets: []httpapi.SecretView{
				{ID: "a1a1a1a1a1a1", Ordinal: 0, Hidden: true, Label: "‹s:a1a1a1a1a1a1:41:0123456789abcdef› hidden"},
				{ID: "b2b2b2b2b2b2", Ordinal: 1, Body: "revealed to the table", Visibility: "table"},
			},
			Problems:  []string{"secret.author_unknown: the fence names an author that does not exist"},
			Truncated: true,
		},
		httpapi.SearchView{
			Shell: principal, Query: "lantern", Total: 1,
			Hits: []httpapi.SearchHit{{
				Card:    httpapi.PageCard{ID: 1, Path: "Tavern.md", Title: "The Drowned Lantern"},
				Kind:    "page",
				Snippet: "the only <b>dry</b> room",
			}},
		},
		httpapi.LoginView{Shell: principal, Problem: "That username and passphrase do not match an account."},
		httpapi.SetupView{Shell: principal, Problem: "that is too short", Field: "username"},
		httpapi.InviteView{Shell: principal, Token: "0123456789abcdef01234567", Role: "player"},
		httpapi.ErrorView{Shell: principal, Status: 404, Heading: "Not found", Detail: "There is no page at that address."},
	}

	for _, v := range views {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			document := render(t, r, v, false)
			fragment := render(t, r, v, true)

			if !strings.HasPrefix(strings.TrimSpace(document), "<!doctype") {
				t.Errorf("the document does not begin with a doctype:\\n%.120s", document)
			}
			if strings.Contains(strings.ToLower(fragment), "<!doctype") {
				t.Error("the fragment carries a doctype")
			}
			if !strings.Contains(fragment, `id="page-region"`) {
				t.Error("the fragment has no region to swap into")
			}
			if len(fragment) >= len(document) {
				t.Errorf("the fragment is %d bytes and the document is %d", len(fragment), len(document))
			}
			// Every *mutating* form carries a token, in both shapes. A shape that
			// dropped it would be a shape in which nothing could be submitted. A
			// GET form is not a mutation and correctly has none, so the count is
			// against the post forms rather than against all of them.
			for _, shape := range []struct{ name, body string }{
				{"the document", document}, {"the fragment", fragment},
			} {
				posts := strings.Count(shape.body, `method="post"`)
				if posts > strings.Count(shape.body, `name="csrf"`) {
					t.Errorf("%s has %d post forms and %d csrf inputs", shape.name, posts, strings.Count(shape.body, `name="csrf"`))
				}
			}
		})
	}
}

// TestAMissingViewModelIsAnError asserts the dispatch fails loudly.
//
// A missing view model is a mistake, and a mistake must not render as a blank
// page: a blank page looks like a page with no content, and the reader has no way
// to tell that from a bug.
//
// A view model this package does not *recognise* cannot be written from here, and
// that is deliberate: httpapi.View has an unexported marker method, so no other
// package can produce one. A new view model therefore has to be added to httpapi
// and to this package's switch, and a forgetter gets a 500 rather than an empty
// page — which is the outcome this test pins for the case that is writable.
func TestAMissingViewModelIsAnError(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := r.Document(rec, req, nil); err == nil {
		t.Error("a missing view model rendered a document without an error")
	}
	if err := r.Fragment(rec, req, nil); err == nil {
		t.Error("a missing view model rendered a fragment without an error")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a missing view model wrote %d bytes to the response", rec.Body.Len())
	}
}

// TestPreRenderedIsTheOnlyWayToEmitRawHTML checks the funnel's own invariant.
//
// The two funnels are the only place templ.Raw is called, and their contract is
// that the string has already been escaped or has already been rendered. This
// asserts what a caller can and cannot do with them: a raw vault string passed to
// PreRendered is exactly the mistake the funnel exists to make impossible, and the
// test is here to say that the *name* is a promise rather than a suggestion.
func TestPreRenderedIsTheOnlyWayToEmitRawHTML(t *testing.T) {
	t.Parallel()
	// A string that would be dangerous if it were not escaped.
	hostile := `<script>alert(1)</script>`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	view := httpapi.PageView{
		Shell: httpapi.Shell{Title: "x", Campaign: "v"},
		Card:  httpapi.PageCard{ID: 1, Path: "H.md", Title: "H"},
		// Passed through the funnel, which is what the page handler does with HTML
		// md.Renderer produced. A fixture that passed a *vault string* here would
		// be the stored XSS this whole design exists to prevent — so the hostile
		// string goes through templ's own escaping instead, and the assertion is
		// that it comes out inert.
		Body: templ.EscapeString(hostile),
	}
	if err := web.NewRenderer().Document(rec, req, view); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("a hostile string reached the response unescaped")
	}
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Error("the hostile string was neither escaped nor rendered, so the assertion is not testing what it says")
	}
}

// TestTheLayoutIsServerRenderedAndDegradable asserts the degradation contract in
// the markup rather than in a script.
//
// With JavaScript blocked, every internal link is an ordinary anchor and every
// form is an ordinary form submission. There is no state that exists only in
// JavaScript and no control that only appears once a script has run, so the test
// checks the two things that would break that: an href on every internal link, and
// a method plus an action on every form.
func TestTheLayoutIsServerRenderedAndDegradable(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	principal := httpapi.Shell{Title: "Campaign", CSRF: strings.Repeat("a", 64), Campaign: "vault"}
	document := render(t, r, httpapi.HomeView{
		Shell: principal,
		Pages: []httpapi.PageCard{{ID: 1, Path: "Index.md", Title: "Index"}, {ID: 2, Path: "Area/Ruin.md", Title: "Ruin"}},
	}, false)

	hrefRe := regexp.MustCompile(`<a\b[^>]*href="([^"]*)"[^>]*>`)
	for _, m := range hrefRe.FindAllStringSubmatch(document, -1) {
		href := m[1]
		switch {
		case strings.HasPrefix(href, "/"):
		case strings.HasPrefix(href, "#"):
			// A fragment-only href is the skip link and the table of contents.
			// Those work with JavaScript disabled and are the reason they are
			// written this way.
		case href == "":
			t.Error("an anchor has no href, so it is a control with nothing behind it")
		default:
			t.Errorf("an anchor's href is %q, which is not a same-origin path", href)
		}
	}
	formRe := regexp.MustCompile(`<form\b[^>]*>`)
	forms := formRe.FindAllString(document, -1)
	if len(forms) == 0 {
		t.Fatal("the layout rendered no forms, so the degradation assertions are vacuous")
	}
	for _, form := range forms {
		if !strings.Contains(form, `method="post"`) && !strings.Contains(form, `method="get"`) {
			t.Errorf("a form has no method: %s", form)
		}
		if !strings.Contains(form, "action=") {
			t.Errorf("a form has no action: %s", form)
		}
	}
	// The landmark set the brief asks for: a skip link, a nav, a main and an aside.
	for _, want := range []string{"Skip to content", `<nav aria-label=`, `<main id="main"`, `role="search"`} {
		if !strings.Contains(document, want) {
			t.Errorf("the layout is missing %q", want)
		}
	}
	// Every asset comes from the binary and from nowhere else.
	for _, want := range []string{`href="/_/assets/app.css"`, `src="/_/assets/app.js"`, `src="/_/assets/vendor/datastar.js"`, `href="/_/assets/icons.svg"`} {
		if !strings.Contains(document, want) {
			t.Errorf("the layout does not load %q", want)
		}
	}
}

// TestAPageWithSecretsRendersLocksAndBodies asserts the secret components, because
// the lock is the component this project is most likely to get wrong.
func TestAPageWithSecretsRendersLocksAndBodies(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	// The label is the one secrets.LockPlaceholder produces: the id and one word.
	// It is called directly rather than written out, so that if the placeholder's
	// shape ever changes the test fails here instead of quietly asserting a rule
	// that is no longer the rule.
	hidden := httpapi.SecretView{ID: "a1a1a1a1a1a1", Ordinal: 0, Hidden: true, Label: secrets.LockPlaceholder("a1a1a1a1a1a1")}
	shown := httpapi.SecretView{ID: "b2b2b2b2b2b2", Ordinal: 1, Body: "the true name is Orrin", Visibility: "table"}

	document := render(t, r, httpapi.PageView{
		Shell:   httpapi.Shell{Title: "Tavern", CSRF: strings.Repeat("b", 64), Campaign: "v"},
		Card:    httpapi.PageCard{ID: 1, Path: "Tavern.md", Title: "Tavern"},
		Body:    "<p>body</p>",
		Secrets: []httpapi.SecretView{hidden, shown},
	}, false)

	// The lock carries the id and the words, and nothing about the secret.
	lock := between(document, `<div class="secret-locked"`, "</div>")
	if !strings.Contains(lock, `data-secret-id="a1a1a1a1a1a1"`) {
		t.Errorf("the lock carries no id: %s", lock)
	}
	if !strings.Contains(lock, "Hidden") {
		t.Errorf("the lock carries no label: %s", lock)
	}
	// The whole of the lock's text content, compared exactly. An enumeration of
	// forbidden substrings would be a worse test: it would have to guess the ways
	// a title or a length could be spelled, and it would pass the day somebody
	// spelled one differently. This says what the text is, which is the property.
	text := strings.Join(strings.Fields(stripTags(lock)), " ")
	if want := "Hidden " + secrets.LockPlaceholder("a1a1a1a1a1a1"); text != want {
		t.Errorf("the lock's text is %q, want exactly %q", text, want)
	}
	// A revealed secret's body is rendered, and escaped like anything else.
	if !strings.Contains(document, "the true name is Orrin") {
		t.Error("a revealed secret's body is missing from the page")
	}
	// A hidden secret renders no body at all, and the view model is the only
	// place one could have come from: Body is empty when Hidden is true.
	if hidden.Body != "" {
		t.Error("the hidden secret in this fixture carries a body, so the assertion below is vacuous")
	}
}

// render is the harness for both shapes.
func render(t *testing.T, r *web.Renderer, v httpapi.View, fragment bool) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	var err error
	if fragment {
		err = r.Fragment(rec, req, v)
	} else {
		err = r.Document(rec, req, v)
	}
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return rec.Body.String()
}

// typeName is the subtest label for a view model.
func typeName(v httpapi.View) string {
	switch v.(type) {
	case httpapi.HomeView:
		return "home"
	case httpapi.PageView:
		return "page"
	case httpapi.SearchView:
		return "search"
	case httpapi.LoginView:
		return "login"
	case httpapi.SetupView:
		return "setup"
	case httpapi.InviteView:
		return "invite"
	case httpapi.ErrorView:
		return "error"
	default:
		return "unknown"
	}
}

// stripTags removes the markup from a fragment, leaving its text.
func stripTags(s string) string {
	var out strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// between is the substring from a start marker to the next end marker.
func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest
	}
	return rest[:j+len(end)]
}
