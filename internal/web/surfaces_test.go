package web_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The six write-and-history surfaces, asserted on the bytes a reader's browser
// gets rather than on the components that produced them.
//
// The split is deliberate: the editor and the conflict page carry user
// Markdown and the question is whether it arrives escaped; the history and the
// revision carry a re-authorization decision and the question is whether the
// template makes it again; the broken-links panel carries two numbers and the
// question is whether they can disagree. Each is a different failure and none
// of them is visible in the source.

// pageCard is the page every surface below is about.
func pageCard() httpapi.PageCard {
	return httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern", PageType: "location", UpdatedAt: aDay}
}

// editorShell is a shell for a surface that posts, so every form on the page
// has a token to carry and a test that finds a form without one is looking at a
// real gap.
func editorShell() httpapi.Shell {
	return httpapi.Shell{
		Title: "Editing The Drowned Lantern", CSRF: testCSRF, Campaign: "drowned-lantern",
		CurrentPageID: 12, CurrentPageURL: "/p/Tavern.md",
	}
}

// editView builds the editor for one mode, with the mode's consequences already
// applied by whoever filled the model — a redacted buffer holding a marker in
// place of the body, and the mode string saying so.
func editView(mode, content string) httpapi.EditView {
	v := httpapi.EditView{
		Shell:       editorShell(),
		Card:        pageCard(),
		Action:      "/p/Tavern.md/edit",
		PageHref:    "/p/Tavern.md",
		RawHref:     "/p/Tavern.md/raw",
		HistoryHref: "/p/Tavern.md/history",
		Content:     content,
		BaseHash:    strings.Repeat("b", 64),
		Mode:        mode,
		MayWrite:    true,
	}
	if mode == httpapi.EditModeRedacted {
		v.HiddenIDs = []string{"a1a1a1a1a1a1"}
		v.HiddenCount = 1
	}
	return v
}

// TestTheEditorSaysWhichBufferItIsShowing asserts the one fact a writer cannot
// infer from the page: whether the bytes in the textarea are the file.
//
// The two modes are the whole design of this surface — a DM's editor is the
// file and a player's is the file with markers in it — and a template that got
// the branches the wrong way round would be the difference between a save that
// works and one that overwrites a secret with a marker, with no error either
// time.
func TestTheEditorSaysWhichBufferItIsShowing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mode    string
		content string
		want    []string
		refuse  []string
	}{
		{
			name:    "the whole file",
			mode:    httpapi.EditModeFull,
			content: "# The Drowned Lantern\n\n" + fixtureSecret + "\n",
			want: []string{
				"This editor is the whole file",
				"the secrets in it included",
			},
			refuse: []string{"hidden from you", "marker standing in for"},
		},
		{
			name:    "the redacted buffer",
			mode:    httpapi.EditModeRedacted,
			content: "# The Drowned Lantern\n\n" + editSentinel + "\n",
			want: []string{
				"This editor is redacted",
				"1 secret on this page is hidden from you",
				// The three things a writer who will be refused must be told
				// before they type, not after.
				"Leave every marker exactly as it is",
				"refused",
				"cannot be edited here",
			},
			refuse: []string{"password", "passphrase", "type the", "enter the"},
		},
	}
	r := web.NewRenderer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			document := render(t, r, editView(tc.mode, tc.content), false)
			for _, want := range tc.want {
				if !strings.Contains(document, want) {
					t.Errorf("the editor does not say %q", want)
				}
			}
			for _, refuse := range tc.refuse {
				if strings.Contains(document, refuse) {
					t.Errorf("the editor says %q, and a marker is not a credential to be filled in", refuse)
				}
			}
		})
	}
}

// TestTheEditorBufferIsEscapedNotInterpolated is the security assertion for the
// editor, and it is over the buffer's one rendering path: the textarea's text
// content.
//
// A buffer is the file, and a file is whatever its author put in it — including
// a line that looks like a tag. A textarea is also the one control whose
// contents a stray "</textarea>" can end early, so the assertion is that the
// hostile text appears nowhere in the document in its original form and
// appears once escaped.
func TestTheEditorBufferIsEscapedNotInterpolated(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	hostile := "# Tavern <script>alert(1)</script>\n\nA line with <b>markup</b> & an ampersand, </textarea> and a close.\n"
	document := render(t, r, editView(httpapi.EditModeFull, hostile), false)

	if strings.Contains(document, hostile) {
		t.Error("the buffer reached the document verbatim, so its own markup would be the document's markup")
	}
	for _, escaped := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;b&gt;markup&lt;/b&gt;",
		"&amp;",
		// The one that would end the control early, and the reason a textarea
		// is worth its own assertion rather than being assumed.
		"&lt;/textarea&gt;",
	} {
		if !strings.Contains(document, escaped) {
			t.Errorf("the buffer's %q is not present escaped, so the assertion above is vacuous", escaped)
		}
	}
	// And the marker is data: shown, once, and never wrapped in anything.
	marker := render(t, r, editView(httpapi.EditModeRedacted, "a\n"+editSentinel+"\nb\n"), false)
	if !strings.Contains(marker, editSentinel) {
		t.Errorf("the restore marker is not in the buffer: %q", editSentinel)
	}
	if strings.Contains(marker, editSentinel+"<") {
		t.Error("the restore marker is being interpolated into the markup rather than escaped as text")
	}
}

// TestAnUnwritablePageOffersNoSubmitControl is AGENTS.md §7's rule, on the one
// surface where getting it wrong costs a reader their edits.
//
// MayWrite is false when the route's coarse gate let the request through and
// the page-scoped write refused it. The handler answers 403 on that path today,
// so the branch is defence in depth — and defence in depth that renders a form
// is not defence in depth, it is a button that takes a page of typing and then
// loses it.
func TestAnUnwritablePageOffersNoSubmitControl(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := editView(httpapi.EditModeRedacted, "a\n"+editSentinel+"\n")
	view.MayWrite = false
	// The fragment, not the document: the shell carries a search form of its
	// own, and what is being asserted is about this view's own markup.
	region := render(t, r, view, true)

	for _, forbidden := range []string{
		"<form",
		`type="submit"`,
		"action=",
		`name="base_hash"`,
		`name="content"`,
	} {
		if strings.Contains(region, forbidden) {
			t.Errorf("an editor the server would refuse renders %q", forbidden)
		}
	}
	// The buffer is still there: "the same text, and you may not type in it" is
	// a smaller difference than two pages to compare.
	if !strings.Contains(region, "readonly") {
		t.Error("the read-only buffer is not marked readonly, so it looks writable")
	}
	if !strings.Contains(region, editSentinel) {
		t.Error("the read-only buffer does not show the buffer, so the page says nothing about the file")
	}
	if !strings.Contains(region, "may read this page and you may not write it") {
		t.Error("the page does not say why there is nothing to save")
	}
	// And the fixture has to be unwritable at all, or the branch is dead code
	// and the assertions above are about a form that is never rendered.
	if writable := render(t, r, editView(httpapi.EditModeFull, "a\n"), true); !strings.Contains(writable, `type="submit"`) {
		t.Fatal("a writable editor renders no submit control, so the assertion above is vacuous")
	}
}

// TestTheEditorCarriesTheOneFieldASaveIsCheckedAgainst is the editor's contract
// with the server: the buffer, the token, and the hash of the bytes the buffer
// was built from.
//
// The base hash is the interesting one. A save is refused unless it is composed
// against the bytes that are on disk, and a form that computed the hash at
// submit time would be checking a write against itself — so the hash has to
// travel with the buffer as it was rendered.
func TestTheEditorCarriesTheOneFieldASaveIsCheckedAgainst(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := editView(httpapi.EditModeFull, "buffer\n")
	document := render(t, r, view, false)

	for _, want := range []string{
		`action="/p/Tavern.md/edit"`,
		`method="post"`,
		`name="base_hash" value="` + strings.Repeat("b", 64) + `"`,
		`name="content"`,
		`name="csrf" value="` + testCSRF + `"`,
		// The Ctrl+S hook, named here so that a rename fails this test rather
		// than quietly unbinding the shortcut.
		"data-editor-form",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the editor form is missing %q", want)
		}
	}
	// The buffer is the textarea's own value and not an attribute, which is
	// what keeps a 400 KiB page out of the document's attribute budget.
	if !strings.Contains(document, ">buffer\n</textarea>") {
		t.Error("the buffer is not the textarea's text content")
	}
}

// TestTheSavedAnswerIsAnnounced asserts the one thing on the page a reader who
// pressed the button is waiting for is a live region, so a screen reader says so
// without the reader going looking for it.
func TestTheSavedAnswerIsAnnounced(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := editView(httpapi.EditModeFull, "saved\n")
	view.Saved = true
	document := render(t, r, view, false)
	if !strings.Contains(document, `role="status"`) {
		t.Error("the confirmation is not a live region")
	}
	if !strings.Contains(document, "Saved.") {
		t.Error("the confirmation does not say the save landed")
	}
	if fresh := render(t, r, editView(httpapi.EditModeFull, "fresh\n"), false); strings.Contains(fresh, "Saved.") {
		t.Error("an editor that was not answered by a save says it was saved")
	}
}

// TestTheProblemsAreCodesAndSaySo asserts the editor's error list does not read
// like a quotation of the file. md.Problem carries a code and a short message
// and never a line of content, so a reader who is told that can tell a problem
// from a leak.
func TestTheProblemsAreCodesAndSaySo(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := editView(httpapi.EditModeFull, "a\n")
	view.Problems = []string{"secret_fence_unreadable", "wikilink_flood"}
	document := render(t, r, view, false)
	for _, want := range []string{"secret_fence_unreadable", "wikilink_flood", "not quotations"} {
		if !strings.Contains(document, want) {
			t.Errorf("the problem list is missing %q", want)
		}
	}
	if clean := render(t, r, editView(httpapi.EditModeFull, "a\n"), false); strings.Contains(clean, "The parser reported a problem") {
		t.Error("a file with no problems renders a problem notice")
	}
}

// conflictView is a lost save with one replacement and one pure insertion, so
// the diff has a row with a line on both sides and a row with one on neither.
func conflictView() httpapi.ConflictView {
	return httpapi.ConflictView{
		Shell: editorShell(),
		Card:  pageCard(),
		Conflict: httpapi.Conflict{
			Theirs:   "# The Drowned Lantern\n\nThe room was dry.\nA closing line.\n",
			Mine:     "# The Drowned Lantern\n\nThe cellar is wet.\nA closing line.\nAn added line.\n",
			BaseHash: strings.Repeat("c", 64),
			Reason:   "save",
			Hunks: []httpapi.DiffHunk{
				{FromA: 3, CountA: 1, FromB: 3, CountB: 1, Lines: []httpapi.DiffLine{
					{Op: " ", No: 1, Text: "# The Drowned Lantern"},
					{Op: "-", No: 3, Text: "The room was dry."},
					{Op: "+", No: 3, Text: "The cellar is wet."},
					{Op: " ", No: 4, Text: "A closing line."},
				}},
				{FromA: 5, CountA: 0, FromB: 5, CountB: 1, Lines: []httpapi.DiffLine{
					{Op: "+", No: 5, Text: "An added line."},
				}},
			},
		},
	}
}

// TestTheConflictPageShowsBothSides is the assertion §8.9 exists for: a save
// that refuses must not throw the work away, so the buffer that lost is on the
// page.
//
// The second half is the security half, and it is the one that is easy to get
// wrong by accident: the page carries a body in it, so it has to be shown not to
// carry a body the reader may not read. The fixture is a DM's page and the token
// is a DM's body, so "the page renders Mine" and "the page renders no body the
// reader was refused" are asserted against the same document.
func TestTheConflictPageShowsBothSides(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := conflictView()
	// The DM's own secret, on the page, in the on-disk side as the DM reads it.
	view.Conflict.Theirs += "\n```secret id=aa11bb22cc33 visibility=private\n" + fixtureSecret + "\n```\n"
	document := render(t, r, view, false)

	for _, want := range []string{
		"This page changed while you were editing it",
		// Both sides, by content, which is the only way to tell them apart.
		"The room was dry.",
		"The cellar is wet.",
		"An added line.",
		// And the form that can resolve it.
		`action="/p/Tavern.md/edit"`,
		`method="post"`,
		`name="base_hash" value="` + strings.Repeat("c", 64) + `"`,
		`name="csrf"`,
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the conflict page is missing %q", want)
		}
	}
	// The DM's own body is in the on-disk side and is rendered, because the DM
	// may read it. The other direction — a body this reader was refused, which
	// arrives as the lock label — is the next test.
	if !strings.Contains(document, fixtureSecret) {
		t.Error("the conflict page dropped a body this principal is entitled to read")
	}
	if got := render(t, r, revertConflict(), false); !strings.Contains(got, "changed while you were reverting it") {
		t.Error("a revert conflict is not named as one, so the heading says the reader was editing when they were not")
	}
	if got := render(t, r, revertConflict(), false); !strings.Contains(got, "The revision") {
		t.Error("a revert conflict calls the revision being put back \"Your version\", so the reader is shown a document they never typed")
	}
}

// TestTheConflictPageCarriesNoBodyTheReaderWasRefused is the tripwire for the
// conflict page, over a redacted on-disk side.
//
// The handler redacts the on-disk side through the same path the raw view uses,
// so the page should be showing a lock label where a body was and nothing else.
// What is asserted here is that the label is what arrives: a page that rendered
// the body as well would be the failure this whole surface is designed against.
func TestTheConflictPageCarriesNoBodyTheReaderWasRefused(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := conflictView()
	// What a player is shown: the file with a body they may not read replaced
	// by the fixed lock label, and nothing of the body in either side.
	view.Conflict.Theirs = strings.ReplaceAll(view.Conflict.Theirs, "The room was dry.", "⟨secret:aa11bb22cc33 hidden⟩")
	document := render(t, r, view, false)

	if strings.Contains(document, fixtureSecret) {
		t.Error("the conflict page carries a body the reader was refused")
	}
	if !strings.Contains(document, "⟨secret:aa11bb22cc33 hidden⟩") {
		t.Error("the redacted on-disk side is not the lock label, so the redaction did not survive the render")
	}
}

// TestTheConflictFormCarriesOneAnswerPerHunk is the submission contract, pinned
// on the markup so that it cannot drift without this failing.
//
// Each hunk contributes exactly one control, its value names the hunk by index
// and the side to keep, and the buffer that lost travels with the form. That is
// what makes the answer order-independent: a client that serialised two
// selects the other way round still answers the right hunk, and a submission
// that is missing one is missing rather than silently shifted onto its
// neighbour's answer.
func TestTheConflictFormCarriesOneAnswerPerHunk(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := conflictView()
	document := render(t, r, view, false)

	selects := elementsOf(document, "select")
	if len(selects) != len(view.Conflict.Hunks) {
		t.Fatalf("%d selects for %d hunks, want one per hunk", len(selects), len(view.Conflict.Hunks))
	}
	for i, control := range selects {
		if !strings.Contains(control, `name="resolve"`) {
			t.Errorf("hunk %d's control is not named resolve", i)
		}
		for _, side := range []string{itoaTest(i) + ":mine", itoaTest(i) + ":theirs"} {
			if !strings.Contains(control, `value="`+side+`"`) {
				t.Errorf("hunk %d offers no %q option", i, side)
			}
		}
		// Yours is the default, so a save nobody thought about does not
		// discard the work the reader just did.
		if !strings.Contains(control, "<option value=\""+itoaTest(i)+":mine\" selected>") {
			t.Errorf("hunk %d does not preselect the reader's own version", i)
		}
		// Every control is named, which is what a screen reader reads and what
		// AGENTS.md §3.5 requires of every control.
		if !strings.Contains(document, `for="resolve-`+itoaTest(i)+`"`) {
			t.Errorf("hunk %d's control has no label", i)
		}
	}
	// The losing buffer travels with the form, because a resolution is a merge
	// against it and the server has no other copy of what the reader typed.
	if !strings.Contains(document, `name="content"`) {
		t.Error("the conflict form does not carry the buffer that lost")
	}
	// One hunk, one fieldset, so a reader can see how many choices they are
	// being asked for.
	if got := strings.Count(document, "data-hunk="); got != len(view.Conflict.Hunks) {
		t.Errorf("%d hunk fieldsets for %d hunks", got, len(view.Conflict.Hunks))
	}
}

// resolutionForm is the conflict page's own form, found by its action rather
// than counted: the shell carries a search form and, for a signed-in principal,
// a sign-out form, and neither of them is the one being asserted on.
func resolutionForm(document string) string {
	for _, form := range elementsOf(document, "form") {
		if strings.Contains(form, pageEditHrefForTest(pageCard())) {
			return form
		}
	}
	return ""
}

// pageEditHrefForTest re-derives the URL the conflict form posts to rather than
// asking the template for it, so the assertion pins the address instead of
// agreeing with whatever the template happens to build.
func pageEditHrefForTest(card httpapi.PageCard) string { return card.Href() + "/edit" }

// TestTheDiffShowsBothColumnsAndIsNavigable asserts the diff's two jobs: that
// each row says which side each line is on, and that a screen reader can walk
// it as a table rather than as a wall of preformatted text.
func TestTheDiffShowsBothColumnsAndIsNavigable(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, conflictView(), false)

	for _, want := range []string{
		`<table class="diff"`,
		`<th scope="col">`,
		`<caption class="sr-only">`,
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the diff is missing %q", want)
		}
	}
	// The four row classes, all four present in this fixture: context, changed
	// and added. Removed needs a hunk of its own, and is asserted below.
	for _, op := range []string{`data-diff-op="context"`, `data-diff-op="changed"`, `data-diff-op="added"`} {
		if !strings.Contains(document, op) {
			t.Errorf("the diff has no %s row", op)
		}
	}
	// The header text names both sides, and the sr-only span names the side for
	// the number column, which is otherwise a column of bare digits.
	for _, want := range []string{">On disk<", ">Your version<", "Line in On disk", "Line in Your version"} {
		if !strings.Contains(document, want) {
			t.Errorf("the diff headers are missing %q", want)
		}
	}
	// The marker glyph, so the row is readable without the colour. One per
	// text cell of a changed or added row, none on a context row.
	if !strings.Contains(document, `<span aria-hidden="true" class="diff-mark">`) {
		t.Error("the diff's rows carry no non-colour marker")
	}
}

// TestTheDiffEscapesEveryLineItPrints is the security assertion for the diff,
// and it is the one place on these surfaces where a line of vault Markdown is
// printed many times over: a diff that renders a line as markup turns a page of
// text into a script on a 409.
func TestTheDiffEscapesEveryLineItPrints(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := conflictView()
	hostile := "<img src=x onerror=alert(1)> & \"quoted\""
	view.Conflict.Hunks[0].Lines[1] = httpapi.DiffLine{Op: "-", No: 3, Text: hostile}
	view.Conflict.Hunks[0].Lines[2] = httpapi.DiffLine{Op: "+", No: 3, Text: hostile}
	document := render(t, r, view, false)

	if strings.Contains(document, "<img src=x") {
		t.Fatal("a diff line reached the document unescaped")
	}
	if !strings.Contains(document, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("the diff line is not present escaped, so the assertion above is vacuous")
	}
}

// TestTheHistoryListsEveryRowAndSaysHowManyAreMissing is the history panel's
// two counts, which come from the handler and cannot be re-derived here — so the
// template's job is to print both and to refuse to hide a row.
func TestTheHistoryListsEveryRowAndSaysHowManyAreMissing(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := historyView()
	document := render(t, r, view, false)

	if got := strings.Count(document, "data-revision="); got != len(view.Revisions) {
		t.Errorf("%d rows rendered for %d revisions", got, len(view.Revisions))
	}
	if !strings.Contains(document, "14 revisions") {
		t.Error("the panel does not carry the total from the count query")
	}
	if !strings.Contains(document, "the 2 most recent of 14") {
		t.Error("a truncated panel does not say how many rows it is not showing")
	}
	// Both row links, so a listed revision can be opened and put back.
	for _, want := range []string{"/p/Tavern.md/revisions/9", "/p/Tavern.md/revert/9", "/p/Tavern.md/revisions/8", "/p/Tavern.md/revert/8"} {
		if !strings.Contains(document, want) {
			t.Errorf("the panel is missing %q", want)
		}
	}
	// A revert is a write, so it is a form with a token and not a link.
	if !strings.Contains(document, `method="post" action="/p/Tavern.md/revert/9"`) {
		t.Error("the revert is not an ordinary form posting to its own URL")
	}
	if got := strings.Count(document, `name="csrf"`); got != len(view.Revisions) {
		t.Errorf("%d revert forms for %d rows, so one has no token", got, len(view.Revisions))
	}
}

// TestTheHistoryNamesAnExternalChangeAndDoesNotGuessAtReadability is the row
// that is easy to get wrong in two directions at once.
//
// An external row's author is empty because nobody is responsible, so it says
// "changed outside the app" rather than rendering a blank cell or the word
// "nobody". And a row whose Visible flag is false is still listed with its link,
// because the flag is documented as an approximation in both directions and the
// single-revision read re-decides from the revision's own bytes: a page that
// dropped the link would be deciding, wrongly, that the revision does not exist.
func TestTheHistoryNamesAnExternalChangeAndDoesNotGuessAtReadability(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := historyView()
	document := render(t, r, view, false)

	if !strings.Contains(document, "changed outside the app") {
		t.Error("an external change is not named as one")
	}
	if strings.Contains(document, "nobody") {
		t.Error("an external change is attributed to nobody rather than to the app's absence")
	}
	if !strings.Contains(document, "changed by thia") {
		t.Error("a change with an account responsible does not name it")
	}
	// The unreadable row: listed, linked, and with nothing on the page claiming
	// to be its content.
	unreadable := between(document, `data-revision="8"`, "</tr>")
	if unreadable == "" {
		t.Fatal("the row whose Visible flag is false is not on the page at all")
	}
	if !strings.Contains(unreadable, `href="/p/Tavern.md/revisions/8"`) {
		t.Error("the unreadable row has no link, so the page has decided the revision does not exist")
	}
	if strings.Contains(unreadable, fixtureSecret) {
		t.Error("a history row carries a body")
	}
}

// TestTheRevisionRendersItsTextAndWithholdsOnlyTheComparison is the read-time
// re-authorization of §8.10, split the way the view model splits it.
//
// The revision's own bytes are authorized by the handler, which answers 404 for
// a revision holding a body this principal may not read, so the text is
// rendered. The comparison is a different question: its left column is the page
// as it is now, and the only way to make that safe is a redaction marker that
// carries a hidden body's length. So a principal who may not read everything
// the page holds now loses the comparison and keeps the revision.
func TestTheRevisionRendersItsTextAndWithholdsOnlyTheComparison(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := revisionView()
	view.Hunks = []httpapi.DiffHunk{{FromA: 3, CountA: 1, FromB: 3, CountB: 1, Lines: []httpapi.DiffLine{
		{Op: "-", No: 3, Text: "The room was dry."},
		{Op: "+", No: 3, Text: "The cellar is wet."},
	}}}
	document := render(t, r, view, false)

	if !strings.Contains(document, "The room was dry. And a bottle. And a lantern.") {
		t.Error("the revision's own content is not on the page, so a reader has been refused something they were entitled to")
	}
	if !strings.Contains(document, `class="diff"`) {
		t.Error("the comparison is not rendered for a comparable revision")
	}

	// The other half: not comparable, so the reason and no diff.
	opaque := revisionView()
	opaque.Comparable = false
	opaque.DiffOpaque = httpapi.DiffOpaqueUnreadable
	denied := render(t, r, opaque, false)
	if !strings.Contains(denied, httpapi.DiffOpaqueUnreadable) {
		t.Error("an incomparable revision does not carry the reason it is not compared")
	}
	if strings.Contains(denied, `class="diff"`) {
		t.Error("an incomparable revision renders a diff of the current file")
	}
	// And the fallback: no comparison and no reason must not fall through to
	// the diff either, because the reason is the only thing standing between a
	// view model and a reader.
	silent := revisionView()
	silent.Comparable = false
	blank := render(t, r, silent, false)
	if strings.Contains(blank, `class="diff"`) {
		t.Error("a revision with no comparison and no reason renders a diff anyway")
	}
	if !strings.Contains(blank, "not compared with the page") {
		t.Error("a revision with no reason does not say why")
	}
}

// TestTheBrokenLinksPanelRendersBothNumbers is the badge-and-list rule, which is
// the only shape a leak can take on a panel that lists rows a reader may not
// all see.
//
// The count and the cap are the handler's, from the same statement. The
// template's job is to print both and to print the cap, because a reader shown
// 200 of 431 and told nothing is being told, wrongly, that the campaign has 200
// mistakes in it.
func TestTheBrokenLinksPanelRendersBothNumbers(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := brokenLinksView()
	document := render(t, r, view, false)

	if !strings.Contains(document, "431") {
		t.Error("the panel does not carry the total")
	}
	if !strings.Contains(document, "the first 2 of 431") {
		t.Error("a truncated panel does not say how many rows it is not showing")
	}
	if !strings.Contains(document, "200") {
		t.Error("the panel does not say what the cap is")
	}
	if got := strings.Count(brokenRowsOf(document), "<tr>"); got != len(view.Rows) {
		t.Errorf("%d rows for %d references", got, len(view.Rows))
	}
	// The reference as the author wrote it, not a reconstructed URL: the whole
	// point of the panel is what is dangling, which is the author's spelling.
	if !strings.Contains(document, "The Salt Keep") {
		t.Error("the panel does not show the reference as it was written")
	}
	if !strings.Contains(document, "Wiki link") {
		t.Error("the panel does not name the kind of reference")
	}
	// A referring page the index does not have is rendered as words, because a
	// link to a path the panel does not know is a control that answers 404.
	if !strings.Contains(document, "A page the index does not have") {
		t.Error("a row with no referring page is not named")
	}
}

// TestTheBrokenLinksPanelSaysSoWhenNothingDangles keeps the empty state a
// sentence: a panel that is empty because nothing dangles and a panel that is
// empty because the query found nothing are the same document otherwise, and
// the reader deserves to know which one they are looking at.
func TestTheBrokenLinksPanelSaysSoWhenNothingDangles(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := brokenLinksView()
	view.Rows = nil
	view.Total = 0
	view.Truncated = false
	document := render(t, r, view, false)
	if !strings.Contains(document, "Nothing dangles") {
		t.Error("an empty panel does not say it is empty")
	}
	if strings.Contains(document, "the first") {
		t.Error("an untruncated panel claims to be truncated")
	}
}

// brokenRowsOf is the panel's own table body, found by the one caption that
// names it and cut below its header row. The shell's keyboard table has rows of
// its own, and a count taken over the whole document would be a count of the
// wrong thing.
func brokenRowsOf(document string) string {
	start := strings.Index(document, "Every reference in the campaign that does not resolve to a page")
	if start < 0 {
		return ""
	}
	rest := document[start:]
	head := strings.Index(rest, "</thead>")
	if head < 0 {
		return ""
	}
	rest = rest[head+len("</thead>"):]
	if end := strings.Index(rest, "</table>"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// historyView is a page with two revisions of every kind the panel has to tell
// apart: one with an account responsible and readable, one external and not
// readable by this viewer, a total larger than the list, and a truncated flag.
func historyView() httpapi.HistoryView {
	return httpapi.HistoryView{
		Shell: editorShell(),
		Card:  pageCard(),
		Revisions: []httpapi.RevisionRow{
			{ID: 9, At: aDay, Source: "app", Author: "thia", Visible: true, Href: "/p/Tavern.md/revisions/9", RevertHref: "/p/Tavern.md/revert/9"},
			{ID: 8, At: aDay.Add(-26 * time.Hour), Source: "external", External: true, Visible: false, Href: "/p/Tavern.md/revisions/8", RevertHref: "/p/Tavern.md/revert/8"},
		},
		Total:     14,
		Truncated: true,
		PageHref:  "/p/Tavern.md",
	}
}

// revisionView is a revision this principal may read, and so may compare.
func revisionView() httpapi.RevisionView {
	return httpapi.RevisionView{
		Shell:       editorShell(),
		Card:        pageCard(),
		ID:          9,
		At:          aDay,
		Source:      "app",
		Author:      "thia",
		Content:     "# The Drowned Lantern\n\nThe room was dry. And a bottle. And a lantern.\n",
		Comparable:  true,
		PageHref:    "/p/Tavern.md",
		HistoryHref: "/p/Tavern.md/history",
	}
}

// brokenLinksView is a panel with two rows, a count far above the cap, and one
// referring page the index does not have.
func brokenLinksView() httpapi.BrokenLinksView {
	return httpapi.BrokenLinksView{
		Shell:      httpapi.Shell{Title: "Broken links", CSRF: testCSRF, Campaign: "drowned-lantern"},
		Total:      431,
		ShownLimit: httpapi.ShownLimit,
		Truncated:  true,
		Rows: []httpapi.BrokenLinkRow{
			{Card: pageCard(), Target: "The Salt Keep", Line: 12, Kind: "wikilink"},
			{Target: "old-name", Line: 4, Kind: "markdown"},
		},
	}
}

// revertConflict is the same lost write, reached by a revert rather than by a
// save, so the heading is the other one.
func revertConflict() httpapi.ConflictView {
	view := conflictView()
	view.Conflict.Reason = "revert"
	return view
}

// itoaTest is strconv.Itoa for a test that builds an expected attribute value.
func itoaTest(n int) string { return strconv.Itoa(n) }

// TestTheSixSurfacesSwapAsRegions asserts the content-negotiation contract over
// the new views specifically, because a form carrying a base hash is the one
// thing here a morph would have to reproduce exactly: a swapped region with a
// different hash is an editor that saves against the wrong bytes.
func TestTheSixSurfacesSwapAsRegions(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	views := map[string]httpapi.View{
		"Edit":        editView(httpapi.EditModeRedacted, "a\n"+editSentinel+"\n"),
		"Conflict":    conflictView(),
		"History":     historyView(),
		"Revision":    revisionView(),
		"BrokenLinks": brokenLinksView(),
	}
	for name, view := range views {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := render(t, r, view, false)
			fragment := render(t, r, view, true)
			if !strings.Contains(document, fragment) {
				t.Errorf("%s: the fragment is not a substring of the document, so a morph would write bytes this page never produced", name)
			}
			if !strings.HasPrefix(fragment, `<div id="page-region"`) {
				t.Errorf("%s: the fragment does not carry the region's own id", name)
			}
			// The fragment is a form submission target as well, so its forms
			// have to be the document's forms, token and all.
			for _, field := range []string{`name="csrf"`, `name="base_hash"`} {
				if strings.Contains(document, field) && !strings.Contains(fragment, field) {
					t.Errorf("%s: the document has %s and the fragment does not", name, field)
				}
			}
		})
	}
}

// TestTheConflictPageIsReachableWithoutAnyScript is the degradation contract
// for the resolution form: it is a POST with a select per hunk and a button, so
// it works with this file blocked. What is asserted is the shape that makes that
// true — a real form, a real submit, a real method — rather than the absence of
// a script.
func TestTheConflictPageIsReachableWithoutAnyScript(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, conflictView(), false)
	form := resolutionForm(document)
	if form == "" {
		t.Fatal("the conflict page renders no form posting to the page's own editor, so the resolution needs a script to happen at all")
	}
	if !strings.Contains(form, `method="post"`) {
		t.Error("the resolution form is not an ordinary submission")
	}
	if !strings.Contains(form, "Write the resolved file") {
		t.Error("the resolution form has no submit control, or one that does not say what it does")
	}
	// And the choices are selects inside that form, not divs with handlers.
	if !strings.Contains(form, "<select") {
		t.Error("the resolution form has no select, so the per-hunk choice is not a control")
	}
}
