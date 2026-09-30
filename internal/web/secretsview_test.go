package web_test

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The two shapes a readable secret can have, asserted on the bytes a browser
// gets.
//
// The split from internal/httpapi/pagesecrets_test.go is deliberate and it is
// the same one internal/web/surfaces_test.go draws. That file asks whether the
// *server* shows the right body to the right principal, over the whole route and
// every principal; this one asks whether the *template* says something true about
// the secret it is putting on the page. A page that shows a DM their own private
// note under the caption "Shared with the table" leaks nothing and is still
// wrong, and only a test that reads the caption can notice.

// revealed renders the shared-with-the-table shape.
func revealed() httpapi.SecretView {
	return httpapi.SecretView{
		ID: "11a1a1a1a1a1", Ordinal: 0, Body: "A note for the table.",
		Visibility: "table", Revealed: true,
	}
}

// readable renders the shape for a secret this viewer may read and the table may
// not — a `dm` fence on a DM's page, a `private` fence on one a player owns.
func readable() httpapi.SecretView {
	return httpapi.SecretView{
		ID: "22b2b2b2b2b2", Ordinal: 1, Body: "The DM's own note.",
		Visibility: "dm", Revealed: false,
	}
}

// renderComponent renders one component on its own, rather than a whole view
// through the Renderer. The claim in this file is about one component's markup, so
// rendering only that component is what keeps a failure readable and what stops a
// change elsewhere in the shell from being blamed for it.
func renderComponent(t *testing.T, c templ.Component) string {
	t.Helper()
	var b strings.Builder
	if err := c.Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

// TestASecretIsToldApartFromAPublishedOne is the caption and the tint, and the
// two must agree with each other as well as with the view model.
//
// It used to fail, and it is the second half of the reported symptom: a secret
// rendered correctly is one that is not described wrongly. A DM's `private` note
// came out in a green "Shared with the table" box with a "Reveal to the table"
// button directly beneath it — a page telling its most trusted reader that their
// own private note was published.
func TestASecretIsToldApartFromAPublishedOne(t *testing.T) {
	t.Parallel()
	shared, mine := renderComponent(t, web.SecretRevealed(revealed())), renderComponent(t, web.SecretRevealed(readable()))

	for _, c := range []struct {
		what, body, wantClass, wantCaption, forbiddenClass, forbiddenCaption string
	}{
		{
			what: "shared with the table", body: shared,
			wantClass: `class="secret-revealed"`, wantCaption: "Shared with the table",
			forbiddenClass: "secret-readable", forbiddenCaption: "",
		},
		{
			what: "readable but not shared", body: mine,
			wantClass: `class="secret-readable"`, wantCaption: "A secret you can read",
			forbiddenClass: "secret-revealed", forbiddenCaption: "Shared with the table",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(c.body, c.wantClass) {
				t.Errorf("the box is not %s", c.wantClass)
			}
			if strings.Contains(c.body, c.forbiddenClass) {
				t.Errorf("the box is also %s, so the tint and the caption disagree about whether this secret is published", c.forbiddenClass)
			}
			if !strings.Contains(c.body, c.wantCaption) {
				t.Errorf("the box does not say %q", c.wantCaption)
			}
			if c.forbiddenCaption != "" && strings.Contains(c.body, c.forbiddenCaption) {
				t.Errorf("the box says %q, which is a claim about who else can read it", c.forbiddenCaption)
			}
		})
	}
}

// TestASecretWithNoBodyIsNotAnEmptyBox is the empty state.
//
// An empty ```secret block is a real state — it is what a DM writes before they
// have written anything, and the indexer holds a row for it — and an empty <pre>
// under a caption reads as a rendering failure rather than as "nothing here yet".
// A body of one space is in the same position: md keeps the fence, and the box
// would render a blank line.
func TestASecretWithNoBodyIsNotAnEmptyBox(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", " ", "\n"} {
		v := readable()
		v.Body = body
		out := renderComponent(t, web.SecretRevealed(v))
		if !strings.Contains(out, "This secret has no text yet") {
			t.Errorf("a secret whose body is %q renders no sentence saying so:\n%s", body, out)
		}
		if strings.Contains(out, "<pre") {
			t.Errorf("a secret whose body is %q renders an empty preformatted block", body)
		}
	}
}

// TestASecretBodyIsShownAsSourceAndNeverAsHTML pins the rendering rule the
// caption change did not touch, and the one AGENTS.md §2.6 is about.
//
// The body is text, in a `<pre>`, escaped by templ. If it were ever handed to
// PreRendered — the one funnel in this codebase that calls templ.Raw — a
// ```secret body containing a `<script>` would be a stored XSS vector in a page
// that is otherwise the most careful renderer in the project. The body in this
// test is deliberately hostile Markdown, and the assertion is that none of it
// survives as markup.
func TestASecretBodyIsShownAsSourceAndNeverAsHTML(t *testing.T) {
	t.Parallel()
	const hostile = "<script>alert(1)</script> and **bold** and [a link](x.md)"
	v := revealed()
	v.Body = hostile
	out := renderComponent(t, web.SecretRevealed(v))

	if strings.Contains(out, "<script>") {
		t.Error("the body reached the page as markup rather than as text")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("the body was not escaped at all:\n%s", out)
	}
	if !strings.Contains(out, "**bold**") {
		t.Errorf("the body is not shown as source, so a secret written in Markdown is reflowed into the page's own Markdown:\n%s", out)
	}
	if strings.Contains(out, "<a href=") {
		t.Errorf("a link inside the body became a live link on the page:\n%s", out)
	}
}

// TestAHiddenSecretStillRendersTheLockAndNothingElse is the negative half of the
// same component, kept beside the positive one so a template that dropped the
// hidden shape would be noticed here rather than in the httpapi walk.
func TestAHiddenSecretStillRendersTheLockAndNothingElse(t *testing.T) {
	t.Parallel()
	v := httpapi.SecretView{
		ID: "33c3c3c3c3c3", Ordinal: 2, Hidden: true,
		Label: secrets.LockPlaceholder("33c3c3c3c3c3"),
	}
	out := renderComponent(t, web.SecretLock(v))
	if !strings.Contains(out, secrets.LockPlaceholder("33c3c3c3c3c3")) {
		t.Errorf("the lock does not carry the placeholder:\n%s", out)
	}
	for _, unwanted := range []string{"secret-revealed", "secret-readable", "<pre"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the lock renders %q", unwanted)
		}
	}
}
