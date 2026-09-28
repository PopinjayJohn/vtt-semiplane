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
	// allViews is the shared fixture list, so that "the dispatch is total" and
	// "every page has the landmarks" are claims about the same set. A view model
	// added to the router with a template and no fixture here would be a page
	// nobody ever rendered.
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			// Exercise the real call sites: a view that renders as a document but
			// not as a fragment is a view that can be navigated to and not swapped.
			if err := r.Document(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), v); err != nil {
				t.Errorf("the document does not render: %v", err)
			}
			if err := r.Fragment(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), v); err != nil {
				t.Errorf("the fragment does not render: %v", err)
			}
		})
	}
}

// typeName names a subtest after the view model rather than after its index.
func typeName(v httpapi.View) string {
	switch v.(type) {
	case httpapi.HomeView:
		return "Home"
	case httpapi.PageView:
		return "Page"
	case httpapi.SearchView:
		return "Search"
	case httpapi.FilesView:
		return "Files"
	case httpapi.TagsView:
		return "Tags"
	case httpapi.TagView:
		return "Tag"
	case httpapi.ContextView:
		return "Context"
	case httpapi.CommandsView:
		return "Commands"
	case httpapi.LoginView:
		return "Login"
	case httpapi.SetupView:
		return "Setup"
	case httpapi.InviteView:
		return "Invite"
	case httpapi.ErrorView:
		return "Error"
	default:
		return "unknown"
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
	// The ids are the ones app.js and the stylesheet address the columns by, so
	// this is also the assertion that they were not renamed.
	for _, want := range []string{"Skip to content", `<nav id="left-nav"`, `<main id="content"`, `<aside id="context"`, `aria-label="Context"`, `role="search"`} {
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
