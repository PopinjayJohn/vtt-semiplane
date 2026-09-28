package web_test

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// TestCampaignStatusOmitsUnauthorizedFieldsEntirely is the field-level rule of
// §3.3, asserted as an absence.
//
// A panel this small is the whole context column, so the temptation is to render
// every field and blank the ones a reader may not see. That is the wrong shape: a
// row that is present and empty says there is something in it, and its height
// says how much. A player gets a smaller panel instead, and a smaller panel is
// indistinguishable from a campaign that has no session and no threads.
func TestCampaignStatusOmitsUnauthorizedFieldsEntirely(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.CampaignStatusPanel(httpapi.CampaignStatus{
		// A reader who may see the party and the system, and nothing else.
		Party: []httpapi.PartyMember{
			{Card: httpapi.PageCard{ID: 31, Path: "Party/Thia.md", Title: "Thia Vane"}, Owner: "Thia"},
		},
	}))

	for _, field := range []string{"session", "threads", "last-activity"} {
		if strings.Contains(rendered, `data-status-field="`+field+`"`) {
			t.Errorf("the panel rendered a %s row this reader may not see", field)
		}
	}
	// The positive control: the party row is there, so the panel is not simply
	// empty and the assertions above are about the right thing.
	if !strings.Contains(rendered, `data-status-field="party"`) {
		t.Error("the party row is missing, so the omissions above prove nothing")
	}
	// The system layer is never nothing. §3.3 requires a missing plugin to look
	// like a missing plugin rather than like a panel that failed to render.
	if !strings.Contains(rendered, `data-status-field="system"`) {
		t.Error("the system layer is missing")
	}
	if !strings.Contains(rendered, "No game system is registered") {
		t.Errorf("the system layer did not name the absence of a system:\n%s", rendered)
	}

	// And the whole panel, with every field filled, has all five rows. A test
	// that only ever renders the empty case cannot tell an omission from a field
	// that was never wired up.
	full := component(t, web.CampaignStatusPanel(campaignStatus()))
	for _, field := range []string{"session", "threads", "last-activity", "party", "system"} {
		if !strings.Contains(full, `data-status-field="`+field+`"`) {
			t.Errorf("the panel is missing the %s row", field)
		}
	}
}

// TestThreadBadgeIsTheCountNotTheListLength is §3.3's one number with two
// sources.
//
// The panel shows a count and a list, and the two come from different fields on
// purpose: the list is a window on the closure queue and the count is the whole
// of it. A badge computed from the list would tell a reader that the five rows
// on screen are all of the campaign's open threads, which is the existence leak
// AGENTS.md §2.4 is about wearing a badge.
func TestThreadBadgeIsTheCountNotTheListLength(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.CampaignStatusPanel(httpapi.CampaignStatus{
		Threads: []httpapi.PageCard{
			{ID: 21, Path: "Threads/One.md", Title: "One"},
			{ID: 22, Path: "Threads/Two.md", Title: "Two"},
			{ID: 23, Path: "Threads/Three.md", Title: "Three"},
			{ID: 24, Path: "Threads/Four.md", Title: "Four"},
			{ID: 25, Path: "Threads/Five.md", Title: "Five"},
		},
		ThreadCount: 7,
	}))

	if !strings.Contains(rendered, `data-count-for="threads">7</span>`) {
		t.Errorf("the badge is not the count:\n%s", rendered)
	}
	if strings.Contains(rendered, `data-count-for="threads">5</span>`) {
		t.Error("the badge is the length of the list, which is the leak §2.4 is about")
	}
	// The window still renders: a count with nothing under it would be a count
	// the reader cannot do anything with.
	if n := strings.Count(rendered, `href="/p/Threads/`); n != 5 {
		t.Errorf("%d thread rows rendered, want 5", n)
	}
}

// TestAPanelWithACountAndNoRowsSaysSo covers the other direction: a reader who
// may see that threads exist and none of them.
//
// The list is empty and the count is not, which a template that assumed the two
// agree would render as a heading with nothing under it.
func TestAPanelWithACountAndNoRowsSaysSo(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.CampaignStatusPanel(httpapi.CampaignStatus{ThreadCount: 3}))
	if !strings.Contains(rendered, `data-count-for="threads">3</span>`) {
		t.Errorf("the count is missing:\n%s", rendered)
	}
	if !strings.Contains(rendered, "None of the open threads are pages you may read") {
		t.Errorf("an empty list is not explained:\n%s", rendered)
	}
}

// TestPartyNoteIsOmittedWhenEmpty is the system plugin's one field.
//
// A character sheet with no note from the system must not render a note element
// at all. A blank line under a name is a thing a reader will ask about and there
// is nobody to answer.
func TestPartyNoteIsOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.CampaignStatusPanel(httpapi.CampaignStatus{
		Party: []httpapi.PartyMember{
			{Card: httpapi.PageCard{ID: 31, Path: "Party/Thia.md", Title: "Thia Vane"}, Owner: "Thia", Note: "climbing 3"},
			{Card: httpapi.PageCard{ID: 32, Path: "Party/Orrin.md", Title: "Orrin Vale"}},
		},
	}))

	if n := strings.Count(rendered, "data-party-note"); n != 1 {
		t.Errorf("%d party notes rendered, want 1: the member with no note must render none", n)
	}
	if !strings.Contains(rendered, ">climbing 3</p>") {
		t.Errorf("the note that exists is not rendered:\n%s", rendered)
	}
	// The owner is a separate field and it renders on its own, so the assertion
	// about notes is not an assertion about the whole row.
	if !strings.Contains(rendered, "Thia") || !strings.Contains(rendered, "Orrin Vale") {
		t.Errorf("a party member is missing:\n%s", rendered)
	}
}

// hiddenAttr matches the HTML hidden attribute and nothing else.
var hiddenAttr = regexp.MustCompile(`\shidden(\s|=|>|/)`)

// TestFileTreeRendersEveryPageExactlyOnce is the tree's whole contract.
//
// Every page appears once, as an ordinary link, and no directory carries a
// number. FileNode has no field for a count or a timestamp, and that is not an
// oversight to be patched in the view layer: a count in a sidebar is a number
// whose derivation a reader cannot check, and one that disagrees with a list
// somewhere else is an existence leak wearing a number.
func TestFileTreeRendersEveryPageExactlyOnce(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.Files(httpapi.FilesView{
		Shell:     httpapi.Shell{Title: "Files", CSRF: testCSRF, Campaign: "v"},
		PageCount: 4,
		Tree:      fileTree(),
	}))

	for _, path := range []string{"Index.md", "Area/Salt_Ruin.md", "Sessions/12.md"} {
		if n := strings.Count(rendered, `data-page="`+path+`"`); n != 1 {
			t.Errorf("the page %q rendered %d rows, want exactly 1", path, n)
		}
	}
	if n := strings.Count(rendered, `class="file-page"`); n != 3 {
		t.Errorf("%d page rows rendered, want 3:\n%s", n, rendered)
	}
	// Every page row is a link, so the tree works with the script blocked. This
	// is the assertion that a future rewrite of the tree as buttons would fail.
	if n := strings.Count(rendered, `href="/p/`); n != 3 {
		t.Errorf("%d page links rendered, want 3", n)
	}
	// The three directories render their names and carry nothing countable.
	for _, name := range []string{"Area", "Salt_Ruin", "Sessions"} {
		if !strings.Contains(rendered, `class="file-dir-name">`+name+`<`) {
			t.Errorf("the directory %q is not rendered", name)
		}
	}
	for _, forbidden := range []string{"data-count", "badge", "data-updated-at", "badge-"} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the tree carries %q, and a directory has no count and no timestamp to carry", forbidden)
		}
	}
	// A directory's expanded state is bound to one signal, and that signal is the
	// one that hides its children — so the accessibility state and the visual
	// state cannot disagree.
	if !strings.Contains(rendered, `aria-expanded="false"`) {
		t.Error("a directory's row has no static expanded state to start from")
	}
	row := between(rendered, `<button`, `</button>`)
	if !strings.Contains(row, `data-attr:aria-expanded="$_open_`) {
		t.Errorf("a directory's aria-expanded is not bound to a signal:\n%s", row)
	}
	if !strings.Contains(row, `data-on:click="$_open_`) {
		t.Errorf("a directory's toggle does not write to the same signal:\n%s", row)
	}
}

// TestTagsLinkToTagPages is the escaping, and it is load-bearing rather than
// cosmetic.
//
// A tag is hierarchical: "area/wild" is one tag and its name contains the
// router's own separator. Escaping the name as a query value leaves the slash
// alone, so the href becomes /tag/area/wild, which matches no route, and every
// nested tag in the campaign is a dead link. The href has to be built by
// escaping the name as one path segment.
func TestTagsLinkToTagPages(t *testing.T) {
	t.Parallel()
	nested := "area/wild"
	rendered := component(t, web.Tag(httpapi.TagView{
		Shell: httpapi.Shell{Title: "Tag", CSRF: testCSRF, Campaign: "v"},
		Tag:   httpapi.TagCard{Name: nested, Count: 2},
		Pages: []httpapi.PageCard{{ID: 13, Path: "Area/Salt_Ruin.md", Title: "The Salt Ruin"}},
		All:   []httpapi.TagCard{{Name: nested, Count: 2}, {Name: "npc village", Count: 5}},
	}))

	want := "/tag/" + url.PathEscape(nested)
	if !strings.Contains(rendered, `href="`+want+`"`) {
		t.Errorf("a nested tag does not link to %q:\n%s", want, rendered)
	}
	// A space is a space, and a tag with one must not break out of the href.
	if !strings.Contains(rendered, `href="/tag/npc%20village"`) {
		t.Errorf("a tag containing a space is not escaped:\n%s", rendered)
	}
	// Neither is the query-escaping the old href used, and the old surface is
	// gone: a search for a bare tag name matches page text as well as the tag.
	if strings.Contains(rendered, "/search?q=") {
		t.Error("a tag links to a search rather than to its own page")
	}
	// The tag being looked at is marked, once, and only once.
	if n := strings.Count(rendered, `aria-current="true"`); n != 1 {
		t.Errorf("%d tags are marked as the current page, want 1:\n%s", n, rendered)
	}
	// The count is the badge, and it renders after the name.
	if !strings.Contains(rendered, "#"+nested+`</span>`) {
		t.Errorf("the tag's name is not rendered:\n%s", rendered)
	}
	if !strings.Contains(rendered, `<span class="text-xs text-neutral-500 dark:text-neutral-400">2</span>`) {
		t.Errorf("the tag's count is not rendered next to it:\n%s", rendered)
	}
}

// TestTheCloudOnTheTagsPageIsTheSameComponent keeps the two tag surfaces from
// drifting.
//
// /tags and the cloud on /tag/{name} are the same list, so they are the same
// component; this asserts it by checking that the heading differs and the
// entries do not.
func TestTheCloudOnTheTagsPageIsTheSameComponent(t *testing.T) {
	t.Parallel()
	tags := []httpapi.TagCard{{Name: "area/wild", Count: 2}, {Name: "npc", Count: 5}}
	cloud := component(t, web.TagCloud(tags))
	page := component(t, web.Tags(httpapi.TagsView{
		Shell: httpapi.Shell{Title: "Tags", CSRF: testCSRF, Campaign: "v"},
		Tags:  tags,
	}))

	for _, tag := range tags {
		want := `href="/tag/` + url.PathEscape(tag.Name) + `"`
		if !strings.Contains(cloud, want) {
			t.Errorf("the dashboard cloud does not link %q", want)
		}
		if !strings.Contains(page, want) {
			t.Errorf("the /tags page does not link %q", want)
		}
	}
	// On the dashboard the cloud is a panel under an h2; on /tags it is the
	// page's own content and the h2 is a caption for it. Different words, same
	// component, so neither surface owns the list.
	if !strings.Contains(cloud, "Tags") || !strings.Contains(page, "Every tag") {
		t.Error("the two clouds are not distinguishable")
	}
}

// TestTheFileTreeWorksWithoutJavaScript is the degradation claim, asserted on
// the markup rather than on the script that is not there.
//
// With DataStar blocked, data-show does nothing and every directory is open, and
// every page is an ordinary anchor. There is no content that only appears once a
// script has run, which is the property that makes the whole shell safe to
// enhance.
func TestTheFileTreeWorksWithoutJavaScript(t *testing.T) {
	t.Parallel()
	rendered := component(t, web.Files(httpapi.FilesView{
		Shell: httpapi.Shell{Title: "Files", CSRF: testCSRF, Campaign: "v"},
		Tree:  fileTree(),
	}))
	// The children list is a plain element with a client-side visibility
	// attribute, not a hidden one: no inline display:none and no hidden
	// attribute, so the browser's own rendering shows it. The hidden *attribute*
	// and not the substring, because aria-hidden is on every icon in the tree.
	children := between(rendered, `<ul class="file-children"`, `</ul>`)
	if strings.Contains(children, `style="display:none"`) {
		t.Errorf("a directory's children are hidden in the markup itself:\n%s", children)
	}
	if hiddenAttr.MatchString(children) {
		t.Errorf("a directory's children carry the hidden attribute:\n%s", children)
	}
	// The one thing that is not a link is the directory toggle, and a button that
	// does nothing without a script is acceptable: it collapses a panel, and the
	// panel's contents are links that are all still reachable.
	if !strings.Contains(rendered, "<button") {
		t.Error("no directory toggle is rendered")
	}
}
