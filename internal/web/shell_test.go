package web_test

import (
	"encoding/json"
	"html"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
	"github.com/a-h/templ"
)

// fixtureSecret is a body that only a reader allowed to see it will ever be
// shown. It is the thing the signal and asset tests assert the absence of: a
// claim that a payload carries no content is only worth anything against a
// content that could have been in it.
const fixtureSecret = "DM-BODY-TOKEN-7b1e4d"

var (
	// aDay is a fixed instant, so that a fixture's rendered timestamps do not
	// depend on the day the test runs.
	aDay = time.Date(2026, 3, 14, 19, 0, 0, 0, time.UTC)
	// testCSRF is a token-shaped string. Its shape is not checked here; what is
	// checked is that every post form carries one.
	testCSRF = strings.Repeat("a", 64)
)

// allViews is every view model this package can render, with fixtures realistic
// enough that a template which quietly stopped rendering something still renders
// something.
//
// It is one list because "the dispatch is total" and "the landmarks hold on every
// page" are the same claim made about the same set. Two lists would let a view
// model be added to the router, be a compile error in neither test, and ship with
// no page of its own.
func allViews() []httpapi.View {
	player := authz.ForUser(7, "thia", authz.RolePlayer, false)
	shell := httpapi.Shell{
		Title:          "The Drowned Lantern",
		Principal:      player,
		CSRF:           testCSRF,
		Campaign:       "drowned-lantern",
		CurrentPageID:  12,
		CurrentPageURL: "/p/Tavern.md",
		PushEnabled:    true,
	}
	card := httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern", PageType: "location", UpdatedAt: aDay}
	return []httpapi.View{
		httpapi.HomeView{
			Shell:     shell,
			PageCount: 41,
			Pages: []httpapi.PageCard{
				{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern", UpdatedAt: aDay},
				{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin", UpdatedAt: aDay.Add(-24 * time.Hour)},
			},
			Tags:   []httpapi.TagCard{{Name: "area/wild", Count: 2}, {Name: "npc", Count: 5}},
			Status: campaignStatus(),
		},
		httpapi.PageView{
			Shell:     shell,
			Card:      card,
			Body:      "<p>The lantern gutters and the tide comes in.</p>",
			Toc:       []httpapi.TocEntry{{Level: 2, Text: "The room", Slug: "the-room"}},
			Backlinks: []httpapi.BacklinkChip{{Card: httpapi.PageCard{ID: 3, Path: "Index.md", Title: "Index"}, Line: 4}},
			// The count is larger than the list on purpose: the list is a window
			// and the count is the total, and a template that read one for the
			// other would be wrong here rather than invisible.
			BacklinkCount: 3,
			Secrets: []httpapi.SecretView{
				{ID: "a1a1a1a1a1a1", Ordinal: 0, Hidden: true, Label: "hidden"},
				{ID: "b2b2b2b2b2b2", Ordinal: 1, Body: fixtureSecret, Visibility: "table"},
			},
			Related: []httpapi.PageCard{{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}},
			Status:  campaignStatus(),
		},
		httpapi.SearchView{
			Shell: shell,
			Query: "lantern",
			Total: 2,
			Hits: []httpapi.SearchHit{
				{Card: card, Kind: "page", Snippet: "the only <b>dry</b> room"},
				{Card: httpapi.PageCard{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}, Kind: "secret"},
			},
		},
		httpapi.FilesView{Shell: shell, PageCount: 3, Tree: fileTree()},
		httpapi.TagsView{Shell: shell, Tags: []httpapi.TagCard{{Name: "area/wild", Count: 2}, {Name: "npc", Count: 5}}},
		httpapi.TagView{
			Shell: shell,
			Tag:   httpapi.TagCard{Name: "area/wild", Count: 2},
			Pages: []httpapi.PageCard{{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}},
			All:   []httpapi.TagCard{{Name: "area/wild", Count: 2}, {Name: "npc", Count: 5}},
		},
		httpapi.ContextView{
			Shell:         shell,
			Card:          card,
			Toc:           []httpapi.TocEntry{{Level: 2, Text: "The room", Slug: "the-room"}},
			Backlinks:     []httpapi.BacklinkChip{{Card: httpapi.PageCard{ID: 3, Path: "Index.md", Title: "Index"}, Line: 4}},
			BacklinkCount: 3,
			Related:       []httpapi.PageCard{{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}},
			Status:        campaignStatus(),
		},
		httpapi.CommandsView{
			Shell: shell,
			Query: "salt",
			Commands: []httpapi.Command{
				{Label: "Campaign home", Href: "/", Kind: httpapi.CommandAction, Hint: "g h"},
				{Label: "The Salt Ruin", Href: "/p/Area/Salt_Ruin.md", Kind: httpapi.CommandPage, Hint: "↵"},
				{Label: "#area/wild", Href: "/tag/area%2Fwild", Kind: httpapi.CommandTag},
			},
		},
		// The boot report, with one row of every kind. A skipped row with a
		// reason and a warning are both here on purpose: those are the two
		// branches a template quietly stops rendering, and a fixture with only
		// healthy rows would pass either omission.
		httpapi.AdminPluginsView{
			Shell:      shell,
			HostLevel:  1,
			APIWindow:  2,
			Registered: 1,
			Compat:     1,
			Skipped:    1,
			Lines: []httpapi.PluginReportLine{
				{
					ID: "dnd5e", Name: "D&D 5e", Kind: "system", Version: "0.4.0", Status: "ok",
					APILevel: 1, HostLevel: 1,
					Capabilities: []string{"character_sheet", "ui_panels", "sidebar_nav"},
					Counts:       []string{"3 page types", "2 panels", "1 nav item"},
				},
				{
					ID: "houserules", Name: "House rules", Kind: "feature", Version: "0.1.0", Status: "compat",
					APILevel: 0, HostLevel: 1,
					Capabilities: []string{"none granted"},
					Counts:       []string{"no contributions"},
				},
				{
					ID: "maptool", Name: "Map tool", Kind: "system", Version: "0.2.0", Status: "skipped",
					Reason:   "it claimed the reserved page type map without holding the maps capability",
					APILevel: 1, HostLevel: 1,
					Capabilities: []string{"none granted"},
					Counts:       []string{"no contributions"},
				},
			},
			Warnings: []string{"maptool contributed a panel for the slot right-far-side, which core does not render"},
		},
		httpapi.LoginView{Shell: shell, Problem: "That username and passphrase do not match an account."},
		httpapi.SetupView{Shell: shell, Problem: "that is too short", Field: "username"},
		httpapi.InviteView{Shell: shell, Token: "0123456789abcdef01234567", Role: "player"},
		httpapi.ErrorView{Shell: shell, Status: 404, Heading: "Not found", Detail: "There is no page at that address."},
	}
}

// campaignStatus is a panel with every field filled, so that a template which
// stopped rendering one of them shows up as a missing row rather than as a test
// that never asked.
//
// The thread count is seven against a one-entry list, and one party member has a
// note while the other does not. Both are the mismatches §3.3 and §3.4 are about,
// and a fixture that agrees with itself would pass either way.
func campaignStatus() httpapi.CampaignStatus {
	return httpapi.CampaignStatus{
		Session:     &httpapi.SessionRef{Card: httpapi.PageCard{ID: 14, Path: "Sessions/12.md", Title: "Session 12"}, Number: 12, Date: "2026-03-14"},
		Threads:     []httpapi.PageCard{{ID: 21, Path: "Threads/The_tide.md", Title: "The tide will turn"}},
		ThreadCount: 7,
		LastActivity: []httpapi.PageCard{
			{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"},
		},
		Party: []httpapi.PartyMember{
			{Card: httpapi.PageCard{ID: 31, Path: "Party/Thia.md", Title: "Thia Vane"}, Owner: "Thia", Note: "climbing 3"},
			{Card: httpapi.PageCard{ID: 32, Path: "Party/Orrin.md", Title: "Orrin Vale"}},
		},
		SystemNote: "D&D 5e: the party is on the road between the ruin and the sea.",
	}
}

// fileTree is a nested tree: a directory holding a page, a directory holding a
// page of its own, and a page at the root.
func fileTree() httpapi.FileNode {
	return httpapi.FileNode{
		Name: "",
		Dir:  true,
		Pages: []httpapi.PageCard{
			{ID: 3, Path: "Index.md", Title: "Index"},
		},
		Children: []httpapi.FileNode{
			{
				Name: "Area",
				Path: "Area",
				Dir:  true,
				Children: []httpapi.FileNode{
					{
						Name:  "Salt_Ruin",
						Path:  "Area/Salt_Ruin",
						Dir:   true,
						Pages: []httpapi.PageCard{{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}},
					},
				},
			},
			{
				Name:  "Sessions",
				Path:  "Sessions",
				Dir:   true,
				Pages: []httpapi.PageCard{{ID: 14, Path: "Sessions/12.md", Title: "Session 12"}},
			},
		},
	}
}

// TestEveryPageHasOneH1AndLandmarks walks every view model and asserts the two
// properties §3.5 puts on the shell itself rather than on any one surface: one
// first-level heading, and the five landmarks.
//
// The heading count is the interesting one. A page's own heading belongs to the
// content, so the columns, the chrome and the dialogs must not introduce a
// second one — a document with two h1s gives a screen reader two document
// titles, and the one it announces second is a fragment of chrome.
func TestEveryPageHasOneH1AndLandmarks(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			document := render(t, r, v, false)
			if n := countH1(document); n != 1 {
				t.Errorf("%d h1 elements, want exactly 1", n)
			}
			for _, want := range []string{
				"<header",
				`<nav id="left-nav" aria-label="Campaign"`,
				`<main id="content" tabindex="-1"`,
				`<aside id="context" aria-label="Context"`,
				"<footer",
			} {
				if !strings.Contains(document, want) {
					t.Errorf("the landmark %s is missing", want)
				}
			}
			// And only one of each. Two asides named Context is two answers to
			// "what is around this page", and they would not agree.
			if n := strings.Count(document, `aria-label="Context"`); n != 1 {
				t.Errorf("%d asides named Context, want 1", n)
			}
		})
	}
}

// TestAPagesBodyCannotAddASecondH1 is the same property from the other side.
//
// A rendered Markdown body may contain an h1 of its own, because goldmark
// renders a level-one heading as one. That is a fact about the markdown
// pipeline and not about the view layer, so what this asserts is the half the
// view layer owns: whatever the body holds, the template and the chrome
// contribute exactly one h1 between them.
func TestAPagesBodyCannotAddASecondH1(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	body := "<h1>A heading the author wrote</h1><p>and a paragraph</p>"
	view := httpapi.PageView{
		Shell: httpapi.Shell{Title: "A page", CSRF: testCSRF, Campaign: "v"},
		Card:  httpapi.PageCard{ID: 1, Path: "A.md", Title: "A page"},
		Body:  body,
	}
	document := render(t, r, view, false)
	if !strings.Contains(document, body) {
		t.Fatalf("the body was not rendered into the document, so the count below is not about it")
	}
	if n := countH1(strings.ReplaceAll(document, body, "")); n != 1 {
		t.Errorf("the shell and the template contribute %d h1 elements around the body, want 1", n)
	}
}

// TestSkipLinkIsTheFirstFocusableElement asserts the first thing a keyboard
// reader reaches.
//
// Tab order is document order, so this is a property of position and not of
// markup: a skip link that is correct but third is a skip link that costs three
// tabs.
func TestSkipLinkIsTheFirstFocusableElement(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			document := render(t, r, v, false)
			first := firstFocusable(t, document)
			if first == "" {
				t.Fatal("the document has no focusable element, so the assertion below is vacuous")
			}
			if !strings.HasPrefix(first, `<a href="#content"`) {
				t.Errorf("the first focusable element is %s, want the skip link to #content", first)
			}
		})
	}
}

// TestFragmentIsAStrictSubsetOfDocument is the content negotiation contract,
// over every view model rather than the four stage 1 had.
//
// The bytes a fragment writes have to appear in the bytes a document writes for
// the same view, because the fragment is what a morph writes into a page the
// document produced. A difference is not a cosmetic one: a fragment that
// rendered a different amount of a page than a document would be a second
// authorization decision made by a second code path.
func TestFragmentIsAStrictSubsetOfDocument(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			document := render(t, r, v, false)
			fragment := render(t, r, v, true)
			if !strings.Contains(document, fragment) {
				t.Errorf("the fragment is not a substring of the document:\nfragment:\n%.400s", fragment)
			}
			if len(fragment) >= len(document) {
				t.Errorf("the fragment is %d bytes and the document is %d; the fragment carries no shell to be a subset of", len(fragment), len(document))
			}
		})
	}
}

// TestSignalsCarryNoContent is the tripwire for the data-signals attribute.
//
// The seed is read by every script on the page and is written into the response
// twice over, so "the three keys are the page's URL and two booleans" is a claim
// worth a test rather than a comment. The fixture carries a secret body on the
// same page, so the assertion has something that could have leaked to not leak.
//
// `previews` is the third key and it is the one that had to earn its place: it
// says whether a plugin registered a summary provider, which is a fact about the
// build rather than about the page. Nothing here asserts that it is harmless —
// the exact-key-set assertion below is what does that. Adding a fourth key would
// have to change `want` and this test would then be a list rather than a
// boundary, which is the failure mode §2's "the set of keys is a security
// boundary" is about.
func TestSignalsCarryNoContent(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.PageView{
		Shell: httpapi.Shell{
			Title: "The Drowned Lantern", CSRF: testCSRF, Campaign: "v",
			CurrentPageID: 12, CurrentPageURL: "/p/Tavern.md", PushEnabled: true,
			PreviewsEnabled: true,
		},
		Card: httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Body: "<p>body</p>",
		Secrets: []httpapi.SecretView{
			{ID: "b2b2b2b2b2b2", Body: fixtureSecret, Visibility: "table"},
			{ID: "a1a1a1a1a1a1", Hidden: true, Label: "hidden"},
		},
	}, false)

	// There is exactly one payload and it is on the shell, which is the element
	// that outlives every swap of the content.
	payloads := signalPayloads(document)
	if len(payloads) != 1 {
		t.Fatalf("the document carries %d data-signals payloads, want 1", len(payloads))
	}
	if !strings.Contains(document, `id="shell"`) || !strings.Contains(document, `data-signals=`) {
		t.Fatal("the shell does not carry the seed, so the payload is somewhere else")
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(payloads[0]), &got); err != nil {
		t.Fatalf("the seed is not JSON once unescaped: %v\n%.200s", err, payloads[0])
	}
	want := map[string]any{"currentPageUrl": "/p/Tavern.md", "push": true, "previews": true}
	if len(got) != len(want) {
		t.Errorf("the seed has %d keys (%v), want exactly %v", len(got), keysOf(got), keysOf(want))
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("the seed's %q is %v, want %v", key, got[key], value)
		}
	}
	// And the values are not, or do not contain, anything from the vault.
	if strings.Contains(payloads[0], fixtureSecret) {
		t.Error("the seed carries a secret body")
	}
	if !strings.Contains(document, fixtureSecret) {
		t.Error("the fixture secret is not on the page, so the assertion above is vacuous")
	}
}

// TestNoExternalAssetReferences is §3.6's rule over the rendered output rather
// than over the source: a page that names a remote origin is a page that phones
// home, and the only place that can happen is the markup.
func TestNoExternalAssetReferences(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			for _, shape := range []struct{ name, body string }{
				{"the document", render(t, r, v, false)},
				{"the fragment", render(t, r, v, true)},
			} {
				for _, scheme := range []string{"http://", "https://"} {
					if strings.Contains(shape.body, scheme) {
						t.Errorf("%s contains %s", shape.name, scheme)
					}
				}
			}
		})
	}
}

// TestEveryIconOnlyButtonHasAName asserts the §3.5 rule over every control this
// package renders.
//
// It is checked on the rendered markup rather than on a list of call sites,
// because the call site knows what the author meant and the markup is what the
// reader's browser sees.
func TestEveryIconOnlyButtonHasAName(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	seen := 0
	for _, v := range allViews() {
		for _, document := range []string{render(t, r, v, false), render(t, r, v, true)} {
			for _, element := range elementsOf(document, "button", "a") {
				seen++
				if strings.TrimSpace(stripTags(element)) != "" {
					continue
				}
				if !strings.Contains(element, "aria-label=") && !strings.Contains(element, `class="sr-only"`) {
					t.Errorf("a control with no text is unnamed: %.160s", element)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no controls were found, so the assertion above is vacuous")
	}
}

// TestTabsBindSelectionToOneSignal is the WAI-ARIA tab contract, on the one
// component that has tabs.
//
// The rule being asserted is §3.5's fourth: aria-selected is driven by the same
// signal as the visual state. A tab list that sets aria-selected in one place and
// the class in another is a tab list that lies to half its readers.
func TestTabsBindSelectionToOneSignal(t *testing.T) {
	t.Parallel()
	tabs := []web.Tab{
		{ID: "pages", Label: "Pages", Href: "/p/Tavern.md"},
		{ID: "tags", Label: "Tags", Href: "/tags"},
	}
	// The attribute values hold single quotes, and templ escapes those on the
	// way out; the browser decodes them again, so the comparison is made against
	// what the browser will see.
	rendered := html.UnescapeString(component(t, web.Tabs(tabs, "tags", "$section")))
	if !strings.Contains(rendered, `role="tablist"`) {
		t.Error("the tab list has no role=tablist")
	}
	if n := strings.Count(rendered, `role="tab"`); n != len(tabs) {
		t.Errorf("%d elements have role=tab, want %d", n, len(tabs))
	}
	if !strings.Contains(rendered, `aria-selected="true"`) || strings.Count(rendered, `aria-selected="true"`) != 1 {
		t.Errorf("exactly one tab must be selected and it must say so: %s", rendered)
	}
	// The bound expression and the click handler name the same signal, so the
	// selection a reader makes and the selection a reader is told about are one
	// value.
	for _, want := range []string{
		`data-attr:aria-selected="$section === 'pages' ? 'true' : 'false'"`,
		`data-attr:aria-selected="$section === 'tags' ? 'true' : 'false'"`,
		`data-on:click="$section = 'tags'"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the tab list is missing %q:\n%s", want, rendered)
		}
	}
}

// TestTheCommandPaletteIsARealPage is the palette's degradation contract.
//
// Every command is a link, and the list of them is a page at /_/commands, so a
// reader with the script blocked reaches the same rows by following a link. The
// dialog in the shell is the enhancement; this is the thing it enhances.
func TestTheCommandPaletteIsARealPage(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.CommandsView{
		Shell: httpapi.Shell{Title: "Commands", CSRF: testCSRF, Campaign: "v", CurrentPageURL: "/p/Tavern.md"},
		Commands: []httpapi.Command{
			{Label: "Campaign home", Href: "/", Kind: httpapi.CommandAction, Hint: "g h"},
			{Label: "The Drowned Lantern", Href: "/p/Tavern.md", Kind: httpapi.CommandPage},
		},
	}, false)
	if !strings.Contains(document, `action="/_/commands"`) || !strings.Contains(document, `method="get"`) {
		t.Error("the commands page has no ordinary form, so the rows are unreachable without a script")
	}
	for _, want := range []string{`href="/"`, `href="/p/Tavern.md"`, "Actions", "Pages"} {
		if !strings.Contains(document, want) {
			t.Errorf("the commands page is missing %q", want)
		}
	}
	// The row for the page being read says so, and only that row does.
	if n := strings.Count(document, `aria-current="true"`); n != 1 {
		t.Errorf("%d rows are marked as the current page, want 1", n)
	}
	// The hint is the keyboard tail, and it is text rather than a drawn key.
	if !strings.Contains(document, "<kbd") || !strings.Contains(document, "g h") {
		t.Error("a command's keyboard hint is not rendered")
	}
}

// TestTheContextToggleExistsOnlyWhereTheColumnHasSomething is the "never a
// broken control" rule, asserted on the shell.
//
// A search page's view model carries no page and no campaign state, so the
// context column has nothing to show. A toggle that opens an empty panel is a
// control with nothing behind it, and the fix is not a disabled button: it is
// not rendering the control at all. The column itself stays in the markup,
// because a grid that reflows when a control appears is its own kind of wrong.
func TestTheContextToggleExistsOnlyWhereTheColumnHasSomething(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()

	// A page view carries a card and a campaign: the toggle is there.
	page := render(t, r, httpapi.PageView{
		Shell:  httpapi.Shell{Title: "A page", CSRF: testCSRF, Campaign: "v"},
		Card:   httpapi.PageCard{ID: 1, Path: "A.md", Title: "A page"},
		Toc:    []httpapi.TocEntry{{Level: 2, Text: "One", Slug: "one"}},
		Status: httpapi.CampaignStatus{SystemNote: "D&D 5e"},
	}, false)
	if !strings.Contains(page, `aria-controls="context"`) {
		t.Error("a page view renders no control for the context column, so the column cannot be reached on a narrow screen")
	}
	if !strings.Contains(page, `id="context"`) {
		t.Error("a page view has no context column")
	}

	// A command list carries neither, so the control is not rendered.
	commands := render(t, r, httpapi.CommandsView{
		Shell: httpapi.Shell{Title: "Commands", CSRF: testCSRF, Campaign: "v"},
		Commands: []httpapi.Command{
			{Label: "Campaign home", Href: "/", Kind: httpapi.CommandAction},
		},
	}, false)
	if strings.Contains(commands, `aria-controls="context"`) {
		t.Error("a view with nothing in the context column renders a control that opens it")
	}
	// The column is still there, because the grid must not reflow per page.
	if !strings.Contains(commands, `id="context"`) {
		t.Error("the context column is missing from the layout, so the grid changes shape per page")
	}
}

// countH1 counts the first-level headings in a document.
//
// The match requires a delimiter after the name so that a future element called
// h10 would not be counted as ten h1s.
var h1Tag = regexp.MustCompile(`<h1[\s>/]`)

func countH1(document string) int { return len(h1Tag.FindAllString(document, -1)) }

// focusable is the set of elements a keyboard can reach without help.
var focusableTag = regexp.MustCompile(`<(a|button|input|select|textarea)\b`)

// firstFocusable returns the opening tag of the first focusable element after
// the body.
func firstFocusable(t *testing.T, document string) string {
	t.Helper()
	body := document
	if i := strings.Index(body, "<body"); i >= 0 {
		body = body[i:]
	}
	loc := focusableTag.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	// The opening tag, not the element: enough to name it and to check its href.
	rest := body[loc[0]:]
	if end := strings.Index(rest, ">"); end >= 0 {
		return rest[:end+1]
	}
	return rest
}

// signalPayloads returns every data-signals payload in a body, unescaped.
//
// The unescape matters: the payload is JSON written into an attribute, so its
// quotes arrive as entities, and a test that parsed the raw attribute value
// would be testing the escaper rather than the seed.
var signalsAttr = regexp.MustCompile(`data-signals="([^"]*)"`)

func signalPayloads(document string) []string {
	matches := signalsAttr.FindAllStringSubmatch(document, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// elementsOf returns every whole element of the named tags, in document order.
//
// The scan is a small one rather than an HTML parse because the package may not
// take a dependency to test itself, and because the property being asserted is
// about what a browser sees in the bytes: an element that a parser would repair
// is exactly the element a reader's browser does not see as written.
func elementsOf(document string, tags ...string) []string {
	var out []string
	i := 0
	for i < len(document) {
		j := strings.IndexByte(document[i:], '<')
		if j < 0 {
			break
		}
		i += j
		name := elementName(document[i:])
		if name == "" {
			i++
			continue
		}
		found := false
		for _, tag := range tags {
			if name == tag {
				found = true
			}
		}
		if !found {
			i++
			continue
		}
		// elementEnd counts from the start of the slice it is given, so the
		// offset it returns is relative and has to be rebased before it indexes
		// the document.
		end := i + elementEnd(document[i:], name)
		out = append(out, document[i:end])
		i = end
	}
	return out
}

// elementName is the tag name at an opening bracket, or "" if it is not one.
func elementName(at string) string {
	if !strings.HasPrefix(at, "<") || strings.HasPrefix(at, "</") || strings.HasPrefix(at, "<!") {
		return ""
	}
	name := strings.Builder{}
	for _, r := range at[1:] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			name.WriteRune(r)
		default:
			if name.Len() == 0 {
				return ""
			}
			return name.String()
		}
	}
	return ""
}

// elementEnd is the offset just past the matching close tag of the element that
// starts at the beginning of s.
func elementEnd(s, name string) int {
	open := regexp.MustCompile(`<` + name + `\b[^>]*>`)
	shut := regexp.MustCompile(`</` + name + `\s*>`)
	depth, i := 0, 0
	for i < len(s) {
		o := open.FindStringIndex(s[i:])
		c := shut.FindStringIndex(s[i:])
		switch {
		case c == nil:
			return len(s)
		case o != nil && o[0] < c[0]:
			depth++
			i += o[1]
		default:
			depth--
			i += c[1]
			if depth == 0 {
				return i
			}
		}
	}
	return len(s)
}

// component renders a single component outside the shell.
func component(t *testing.T, c templ.Component) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := c.Render(t.Context(), rec); err != nil {
		t.Fatalf("render: %v", err)
	}
	return rec.Body.String()
}

// keysOf is a sorted key list, so a failure prints the keys in a stable order.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
