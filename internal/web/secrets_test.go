package web_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// secretFormRe matches a rendered reveal or revoke form and its action.
//
// Written out rather than reused from the handler, for the reason the edit-link
// test in the httpapi package writes its own attribute regex: the assertion is
// that the control and the route agree on a string, and a regex derived from the
// same expression the server uses cannot catch a disagreement.
var secretFormRe = regexp.MustCompile(`<form method="post" action="([^"]*?)"[^>]*>`)

// TestTheRevealControlsFollowTheGateTheRouteAsks is the server's half of §8.3's
// control.
//
// The page view is given three secrets: one the viewer may neither read nor
// broadcast, one shared with the table and one not. The first must render nothing
// at all — not a disabled button, not a greyed row — because a control whose
// activation answers 403 is a broken control, and AGENTS.md §7 calls that a bug.
// The other two must each render exactly one form, pointed at the matching
// direction, carrying a CSRF token, because §8.3's answer is a 303 back to the
// page and a form without a token is a form that submits nothing.
func TestTheRevealControlsFollowTheGateTheRouteAsks(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	shell := httpapi.Shell{Title: "The Drowned Lantern", CSRF: testCSRF, Campaign: "drowned-lantern"}
	document := render(t, r, httpapi.PageView{
		Shell: shell,
		Card:  httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Body:  "<p>body</p>",
		Secrets: []httpapi.SecretView{
			{
				// The shape a principal the gate refuses gets: no actions at all.
				ID: "a1a1a1a1a1a1", Ordinal: 0, Hidden: true,
				Label: secrets.LockPlaceholder("a1a1a1a1a1a1"),
			},
			{
				ID: "b2b2b2b2b2b2", Ordinal: 1, Body: fixtureSecret, Visibility: "dm",
				RevealAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/reveal",
				RevokeAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/revoke",
			},
			{
				ID: "c3c3c3c3c3c3", Ordinal: 2, Body: "already shared", Visibility: "table", Revealed: true,
				RevealAction: "/p/Tavern.md/secrets/c3c3c3c3c3c3/reveal",
				RevokeAction: "/p/Tavern.md/secrets/c3c3c3c3c3c3/revoke",
			},
		},
	}, false)

	forms := secretFormRe.FindAllStringSubmatch(document, -1)
	if len(forms) != 2 {
		t.Fatalf("the page rendered %d secret forms, want 2: one per secret this viewer may broadcast\n%s", len(forms), document)
	}
	// The hidden secret contributed nothing. Without this the two forms above
	// would pass for a template that offered the control to everybody and was
	// only saved from a broken page by luck.
	for _, form := range forms {
		if strings.Contains(form[0], "a1a1a1a1a1a1") {
			t.Errorf("a form was offered for a secret this viewer may not broadcast: %s", form[0])
		}
	}
	// A fence already shared gets the revoke and not the reveal: the reveal would
	// write a file that already says what it says, so offering it would be a
	// control that does nothing when pressed.
	want := []string{
		"/p/Tavern.md/secrets/b2b2b2b2b2b2/reveal",
		"/p/Tavern.md/secrets/c3c3c3c3c3c3/revoke",
	}
	got := make([]string, 0, len(forms))
	for _, f := range forms {
		got = append(got, f[1])
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("no form posts to %s; the page offered %v", w, got)
		}
	}
	// And the CSRF token travels with each of them. A form whose token is empty
	// submits and is refused, which reads to a reader as a broken button.
	for _, form := range elementsOf(document, "input") {
		if !strings.Contains(form, `name="csrf"`) {
			continue
		}
		if !strings.Contains(form, testCSRF) {
			t.Errorf("a secret form's CSRF input carries no token: %s", form)
		}
	}
}

// TestTheControlsDegradeToNothingRatherThanToABrokenButton is the other half of
// the same property, asserted on its own so that a failure names the absence
// rather than a count.
//
// One page, two renders: the same secret with the actions and without. The one
// without must contain no form and no button at all — not a disabled one. A
// disabled button still says "there is a control here" and AGENTS.md §7 is
// explicit that a hover affordance with nothing behind it is a bug.
func TestTheControlsDegradeToNothingRatherThanToABrokenButton(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	shell := httpapi.Shell{Title: "The Drowned Lantern", CSRF: testCSRF, Campaign: "drowned-lantern"}
	card := httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"}

	offered := render(t, r, httpapi.PageView{
		Shell: shell, Card: card, Body: "<p>body</p>",
		Secrets: []httpapi.SecretView{{
			ID: "b2b2b2b2b2b2", Body: fixtureSecret, Visibility: "dm",
			RevealAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/reveal",
			RevokeAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/revoke",
		}},
	}, false)
	withheld := render(t, r, httpapi.PageView{
		Shell: shell, Card: card, Body: "<p>body</p>",
		Secrets: []httpapi.SecretView{{
			ID: "b2b2b2b2b2b2", Body: fixtureSecret, Visibility: "dm",
		}},
	}, false)

	if n := len(secretFormRe.FindAllString(withheld, -1)); n != 0 {
		t.Errorf("a principal that may not broadcast was offered %d secret forms", n)
	}
	// The label this template owns, and nothing else. Asserting on it rather than
	// on <button> because the layout has buttons of its own — a count over the
	// whole document would be measuring the shell — and because it is what a
	// reader would read and click. Only the reveal label is at issue here: this
	// fence is not shared, so the revoke label belongs to the other test's
	// fixture and its absence here would say nothing.
	if strings.Contains(withheld, "Reveal to the table") {
		t.Error("the page offers the reveal control to a principal that may not broadcast")
	}
	if !strings.Contains(offered, "Reveal to the table") {
		t.Error("the page does not offer the reveal control to a principal that may")
	}
	// The positive control, so the first assertion is not "this template renders
	// nothing anywhere" — which would pass with a component that never worked.
	if n := len(secretFormRe.FindAllString(offered, -1)); n != 1 {
		t.Errorf("the offered render has %d secret forms, want 1, so the withheld one proves nothing", n)
	}
}

// TestTheAuditTrailRendersOnlyMetadata is §8.6's page, asserted as a property.
//
// The row model carries five fields and the fixture below carries a title, an
// author and a body beside them, so a template that reached for any of them would
// render something. It does not, because the model cannot: a view model with no
// field is not a thing a template can print.
func TestTheAuditTrailRendersOnlyMetadata(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.AdminSecretsView{
		Shell:      httpapi.Shell{Title: "Secret audit", CSRF: testCSRF, Campaign: "drowned-lantern"},
		ShownLimit: 200,
		Events: []httpapi.SecretEventRow{
			{Action: "reveal", Actor: "The Dungeon Master", SecretID: "a1a1a1a1a1a1",
				FromVis: "private", ToVis: "table", At: aDay},
			// A create has no visibility on one side of it, and an account that
			// no longer exists is a fact the trail records rather than a blank
			// cell — so both shapes are here, because both are the branches a
			// template quietly stops rendering.
			{Action: "create", Actor: "Thia", SecretID: "b2b2b2b2b2b2",
				ToVis: "dm", At: aDay.Add(-time.Hour)},
			{Action: "revoke", Actor: "an account that no longer exists", SecretID: "c3c3c3c3c3c3",
				FromVis: "table", At: aDay.Add(-2 * time.Hour)},
		},
	}, false)

	// The five fields of every row.
	for _, want := range []string{
		"reveal", "create", "revoke",
		"The Dungeon Master", "Thia", "an account that no longer exists",
		"a1a1a1a1a1a1", "b2b2b2b2b2b2", "c3c3c3c3c3c3",
		"private", "table", "dm",
		aDay.Format("2006-01-02 15:04"),
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the audit trail does not render %q", want)
		}
	}
	// The scope, in the page's own words rather than in a comment: a reader told
	// "who has touched the campaign's secrets" and handed their own history draws
	// the wrong conclusion from a page answering correctly.
	if !strings.Contains(stripTags(document), "from this account") {
		t.Error("the audit page does not say whose trail it is")
	}
	// Nothing that could be a body, a title or an author. These are the three
	// things a fence has that a trail must not carry, and they are here only to
	// be absent.
	for _, forbidden := range []string{
		fixtureSecret,
		"The cellar key", "The true name", "Orrin's other name",
		"obsidianquill",
		"By:", "Bytes", "Title:", "Excerpt",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("the audit trail renders %q, which is a property of a secret rather than of an event", forbidden)
		}
	}
	// One row per event, and no more. The count is of the row's own marker
	// rather than of <tr>, because the layout carries tables of its own and a
	// count taken over the whole document would be measuring the shell.
	if got := strings.Count(document, `data-audit-action="`); got != 3 {
		t.Errorf("the audit trail rendered %d rows, want 3", got)
	}
}

// TestTheAuditPageSaysSoWhenThereIsNothing is the empty branch.
//
// It is here because an empty list is a branch a template quietly stops
// rendering, and a page that says "0 results" over a header and no table reads as
// a working page rather than as a missing one.
func TestTheAuditPageSaysSoWhenThereIsNothing(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.AdminSecretsView{
		Shell:      httpapi.Shell{Title: "Secret audit", CSRF: testCSRF, Campaign: "drowned-lantern"},
		ShownLimit: 200,
	}, false)
	text := strings.Join(strings.Fields(stripTags(document)), " ")
	for _, want := range []string{
		"Nothing has been recorded yet",
		"written by the app",
		"not here",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("an empty audit trail does not say %q; it says: %s", want, text)
		}
	}
	if n := strings.Count(document, `data-audit-action="`); n != 0 {
		t.Errorf("an empty audit trail rendered %d rows", n)
	}
	if strings.Contains(document, "Newest first, at most") {
		t.Error("an empty audit trail renders the cap line, which is a sentence about rows it does not have")
	}
}

// TestEveryFormCarriesAToken is this package's version of the CSRF gate, applied
// to the controls it renders.
//
// It is a whole-document assertion rather than a per-fixture one because the
// failure it exists for is a form added to any of these pages without one, and
// enumerating pages is how one gets missed.
func TestEverySecretFormCarriesAToken(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.PageView{
		Shell: httpapi.Shell{Title: "The Drowned Lantern", CSRF: testCSRF, Campaign: "drowned-lantern"},
		Card:  httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Secrets: []httpapi.SecretView{
			{ID: "b2b2b2b2b2b2", Body: fixtureSecret, Visibility: "dm", Revealed: false,
				RevealAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/reveal",
				RevokeAction: "/p/Tavern.md/secrets/b2b2b2b2b2b2/revoke"},
		},
	}, false)
	forms := secretFormRe.FindAllString(document, -1)
	if len(forms) == 0 {
		t.Fatal("the page rendered no secret form, so the token assertion below would pass vacuously")
	}
	if n := strings.Count(document, `name="csrf"`); n < len(forms) {
		t.Errorf("the page has %d forms and %d CSRF inputs", len(forms), n)
	}
	// And the method is post, which is what makes the gate apply to it at all.
	for _, form := range forms {
		if !strings.Contains(form, `method="post"`) {
			t.Errorf("a secret form is not a POST: %s", form)
		}
	}
}

// contains reports whether got holds want.
func contains(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}
