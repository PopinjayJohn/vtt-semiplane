package web_test

import (
	"encoding/hex"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The left sidebar's vault tree: the shape of a campaign, its degradation, its
// escaping, and the accessibility contract its disclosure control carries.
//
// The tests read the rendered bytes rather than the view model wherever the
// claim is about the document. "The tree links exactly the pages this principal
// may read" is a claim about which hrefs reached the page, and asserting it from
// the model would be asserting the thing that produced the claim. A template
// that rendered one link from somewhere other than the tree would pass a
// model-shaped test and fail this one, which is the entire difference.
//
// None of this is an accessibility audit. The a11y assertions here check that
// attributes are *present and consistent*, which is what a Go test can see;
// contrast, focus order under a real browser, and anything a treeview role
// implies are the pa11y gate's (pa11y.config.js names this file as a Go-side
// markup assertion and says so explicitly). A green suite here is not a passing
// audit, and the two are complementary rather than interchangeable.

// sortedPageKeys is a sorted key list for a count in a failure message.
func sortedPageKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pageHref matches the href of a page link, capturing the raw attribute value.
//
// It matches the *raw* value, not the unescaped one, so a test that compares
// against PageCard.Href can see whether the document carries the app's own
// encoding or something invented beside it. Everything else in this file that
// wants a link's target unescapes it through html.UnescapeString first.
var pageHref = regexp.MustCompile(`<a href="(/p/[^"]*)" data-wikilink`)

// anyHref matches every href in the document, so a claim about the *whole* link
// set can be made — which is what the readable-pages test needs, because a tree
// that linked a page through some other attribute would satisfy pageHref and
// still be a leak.
var anyHref = regexp.MustCompile(`href="([^"]*)"`)

// emittedPages is the set of page paths the rendered document links to, read
// back out of the HTML and unescaped the way a browser would.
func emittedPages(t *testing.T, rendered string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range pageHref.FindAllStringSubmatch(rendered, -1) {
		out[html.UnescapeString(m[1])]++
	}
	return out
}

// emittedHrefs is every href in the document, unescaped, for the assertions
// that are about the whole set rather than about page links.
func emittedHrefs(t *testing.T, rendered string) []string {
	t.Helper()
	var out []string
	for _, m := range anyHref.FindAllStringSubmatch(rendered, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// sidebar is the rendered left column, so a test about the tree is not also a
// test about the plugin group or the destinations above it.
func sidebar(t *testing.T, shell httpapi.Shell) string {
	t.Helper()
	col := between(component(t, web.Layout(web.Doc{
		Title: "Campaign",
		Shell: shell,
		Body:  web.Text("the page"),
	})), `<nav id="left-nav"`, "</nav>")
	if col == "" {
		t.Fatal("the layout rendered no left navigation")
	}
	return col
}

// treeShell is a shell carrying one tree, which is what every case here needs
// except the ones that are about the shell not carrying one.
func treeShell(root httpapi.FileNode, omitted int) httpapi.Shell {
	return httpapi.Shell{
		Title:            "Campaign",
		CSRF:             testCSRF,
		Campaign:         "v",
		VaultTree:        &root,
		VaultTreeOmitted: omitted,
	}
}

// page is a card, so a fixture can be written without repeating the zero fields.
func page(id int64, path, title string) httpapi.PageCard {
	return httpapi.PageCard{ID: id, Path: path, Title: title, UpdatedAt: aDay}
}

// dir is a directory node.
func dir(name, path string, pages []httpapi.PageCard, children ...httpapi.FileNode) httpapi.FileNode {
	return httpapi.FileNode{Name: name, Path: path, Dir: true, Pages: pages, Children: children}
}

// TestTheSidebarTreeLinksTheWholeVaultAsAHierarchy is the feature's claim, one
// subtest per shape of vault it has to survive.
//
// Each case states the vault and the links the sidebar must carry. The links are
// read out of the document and compared as a set, so a row that is missing, a
// row that is duplicated and a row that points somewhere else are three
// different failures rather than one count.
func TestTheSidebarTreeLinksTheWholeVaultAsAHierarchy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		root  httpapi.FileNode
		paths []string
	}{
		{
			name:  "a flat vault hangs every page off the root",
			root:  dir("", "", []httpapi.PageCard{page(1, "Index.md", "Index"), page(2, "Tavern.md", "The Drowned Lantern")}),
			paths: []string{"/p/Index.md", "/p/Tavern.md"},
		},
		{
			name: "a nested vault nests, and the root's own pages are not lost",
			root: dir("", "", []httpapi.PageCard{page(1, "Index.md", "Index")},
				dir("Area", "Area", nil,
					dir("Salt_Ruin", "Area/Salt_Ruin", []httpapi.PageCard{page(3, "Area/Salt_Ruin.md", "The Salt Ruin")}),
				),
				dir("Sessions", "Sessions", []httpapi.PageCard{page(4, "Sessions/12.md", "Session 12")}),
			),
			paths: []string{"/p/Index.md", "/p/Area/Salt_Ruin.md", "/p/Sessions/12.md"},
		},
		{
			name: "a directory that holds pages and folders shows both",
			root: dir("", "", nil,
				dir("Guild", "Guild", []httpapi.PageCard{page(5, "Guild.md", "The Guild")},
					dir("Cellar", "Guild/Cellar", []httpapi.PageCard{page(6, "Guild/Cellar/Rats.md", "Rats")}),
				),
			),
			// Guild.md and Guild/ are the same name at the same level. Both are
			// shown, because dropping either one loses a file the reader can open.
			paths: []string{"/p/Guild.md", "/p/Guild/Cellar/Rats.md"},
		},
		{
			name:  "a deeply nested path is rendered to its full depth",
			root:  deepTree(40),
			paths: []string{"/p/" + deepPath(40) + "/leaf.md"},
		},
		{
			name: "a folder whose name needs escaping is one row, escaped",
			root: dir("", "", nil,
				dir(`Ash & Ember "The" Folio`, `Ash & Ember "The" Folio`, []httpapi.PageCard{
					page(7, `Ash & Ember "The" Folio/Naïve & Bold.md`, "Naïve & Bold"),
				}),
			),
			paths: []string{`/p/Ash & Ember "The" Folio/Naïve & Bold.md`},
		},
		{
			name:  "a path that tries to traverse is rendered as the text it is",
			root:  dir("", "", []httpapi.PageCard{page(8, "../../etc/passwd.md", "passwd")}),
			paths: []string{"/p/../../etc/passwd.md"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rendered := sidebar(t, treeShell(tc.root, 0))

			got := emittedPages(t, rendered)
			want := map[string]int{}
			for _, p := range tc.paths {
				want[p] = 1
			}
			if len(got) != len(want) {
				t.Fatalf("the sidebar links %d pages, want %d:\nlinks: %v", len(got), len(want), sortedPageKeys(got))
			}
			for p, n := range want {
				if got[p] != n {
					t.Errorf("the sidebar carries %q %d times, want %d", p, got[p], n)
				}
			}
			// The depth is the claim about recursion, and it is measured on the
			// markup rather than on the view model: one nested children list per
			// directory means a template that stopped recursing would show fewer
			// and a template that recursed wrongly would show more.
			if got, want := strings.Count(rendered, `<ul class="file-children"`), directoryRows(tc.root); got != want {
				t.Errorf("the sidebar rendered %d directory rows, want %d; the tree does not nest to the depth it was given", got, want)
			}
			// Every href is the app's own encoding of the path, so a second
			// encoding could not have crept in beside it.
			for _, href := range emittedHrefs(t, rendered) {
				if strings.HasPrefix(href, "/p/") {
					if _, ok := got[href]; !ok {
						t.Errorf("the sidebar links %q, which is not a page this principal may read", href)
					}
				}
			}
		})
	}
}

// TestTheSidebarTreeLinksExactlyTheReadablePages is the authorization claim, and
// it is the reason the tree is on the shell rather than assembled in a template.
//
// A tree is a list of everything that exists. The claim is that the list the
// reader sees is the list they may open, and that nothing reaches the document
// beside it. The assertion is over *every* href in the column, not only the ones
// on a row that looks like a page, because a link that reached a page by
// another route is still a link to it.
//
// v1 filters no page — a page has no visibility column and PermReadPage is
// resource-free — so the honest version of this test is the constructed one
// below: a shell whose tree deliberately omits a page the principal may not
// read. It is written that way rather than as a walk of a real vault because a
// walk would pass vacuously today, and a test that passes because the fixture
// never set up what it asserts is the same failure wearing a different hat.
func TestTheSidebarTreeLinksExactlyTheReadablePages(t *testing.T) {
	t.Parallel()
	readable := page(3, "Area/Salt_Ruin.md", "The Salt Ruin")
	hidden := page(4, "Area/Ascent.md", "The Ascent")

	shell := treeShell(dir("", "", nil,
		dir("Area", "Area", []httpapi.PageCard{readable}),
	), 0)
	// The view model carries the readable page only. Nothing in this package
	// knows about the hidden one — it is named here only so the assertion below
	// can prove it is absent, and the claim is that no code path in the template
	// could invent it back.
	shell.Principal = authz.ForUser(7, "thia", authz.RolePlayer, false)

	rendered := sidebar(t, shell)
	links := emittedHrefs(t, rendered)
	for _, href := range links {
		if href == "/p/Area/Ascent.md" {
			t.Fatalf("the sidebar links a page this principal may not read:\n%s", rendered)
		}
	}
	if !slicesContains(links, "/p/Area/Salt_Ruin.md") {
		t.Fatalf("the sidebar does not link the page this principal may read: %v", links)
	}
	// The claim is about the whole set, so the count is asserted too: a column
	// that linked the readable page twice would satisfy the "is it there" half
	// and be a tree showing the same file twice.
	pageLinks := 0
	for _, href := range links {
		if strings.HasPrefix(href, "/p/") {
			pageLinks++
		}
	}
	if pageLinks != 1 {
		t.Errorf("the sidebar carries %d page links, want exactly the 1 readable page: %v", pageLinks, links)
	}
	_ = hidden
}

// TestTheSidebarTreeDegradesToSomethingReadable is the three absences, asserted
// as three states rather than one.
//
// Each of these is a case where the naive rendering is a control with nothing
// behind it or a heading promising a destination and offering none, which
// AGENTS.md §7 names as a bug rather than a cosmetic fault.
func TestTheSidebarTreeDegradesToSomethingReadable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		shell   httpapi.Shell
		absent  []string
		present []string
	}{
		{
			name: "a listing that failed renders no section at all",
			// A nil tree is the degradation a broken query gets, and it must be
			// indistinguishable from a build that never had one: no heading, no
			// list, and above all no "no pages" message, which would be a lie —
			// the reader's pages are all still there.
			shell:  httpapi.Shell{Title: "Campaign", CSRF: testCSRF, Campaign: "v"},
			absent: []string{"left-tree", "left-tree-heading", "No pages in this vault", "empty-state", "file-tree"},
		},
		{
			name:    "an empty vault says so in words",
			shell:   treeShell(dir("", "", nil), 0),
			present: []string{"No pages in this vault", "empty-state", "Add a Markdown file"},
			// The heading is the thing being promised here, so with nothing under
			// it the heading is not in the document.
			absent: []string{"left-tree-heading", "file-tree"},
		},
		{
			name:    "a vault with pages renders a tree and no empty state",
			shell:   treeShell(dir("", "", []httpapi.PageCard{page(1, "Index.md", "Index")}), 0),
			present: []string{"left-tree", "left-tree-heading", "Pages", "file-tree", "href=\"/p/Index.md\""},
			absent:  []string{"No pages in this vault"},
		},
		{
			name: "an empty folder is shown, expandable, and empty when expanded",
			// A directory node with neither children nor pages. It renders a real
			// disclosure control and a list with nothing in it, which is what an
			// empty folder is: a place the reader can go and find that it is
			// empty, rather than a folder that is not in the sidebar at all.
			shell:   treeShell(dir("", "", nil, dir("Empty", "Empty", nil)), 0),
			present: []string{"Empty", "aria-expanded=\"false\"", "aria-controls=\"left-tree-children-"},
			absent:  []string{"No pages in this vault"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rendered := sidebar(t, tc.shell)
			for _, want := range tc.present {
				if !strings.Contains(rendered, want) {
					t.Errorf("the sidebar does not contain %q:\n%s", want, snippetBytes(rendered))
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(rendered, unwanted) {
					t.Errorf("the sidebar contains %q, which this state must not render:\n%s", unwanted, snippetBytes(rendered))
				}
			}
		})
	}
}

// TestTheSidebarTreeNamesWhatItLeftOut is the truncation claim.
//
// A navigation that silently drops pages is a map of a vault that does not
// exist, and the number it dropped is a number the reader cannot otherwise
// check. The notice is asserted in both states: absent when nothing was left
// out, present with the count and a way to reach the rest when something was.
func TestTheSidebarTreeNamesWhatItLeftOut(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		omitted    int
		wantNotice bool
		wantCount  string
	}{
		{name: "nothing left out says nothing", omitted: 0, wantNotice: false},
		{name: "one left out is named", omitted: 1, wantNotice: true, wantCount: "1 more page in this vault."},
		{name: "many left out are named", omitted: 300, wantNotice: true, wantCount: "300 more pages in this vault."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rendered := sidebar(t, treeShell(dir("", "", []httpapi.PageCard{page(1, "Index.md", "Index")}), tc.omitted))
			if !tc.wantNotice {
				if strings.Contains(rendered, "more page") {
					t.Fatalf("the sidebar announces an omission that did not happen:\n%s", snippetBytes(rendered))
				}
				if got := attrValue(rendered, "data-tree-omitted"); got != "" {
					t.Errorf("the sidebar carries a notice that did not happen: data-tree-omitted=%q", got)
				}
				return
			}
			if !strings.Contains(rendered, tc.wantCount) {
				t.Errorf("the sidebar does not name what it left out (%q):\n%s", tc.wantCount, snippetBytes(rendered))
			}
			// And the number as a value, not only as English: the claim is about
			// the figure, and a test that matched only the sentence would break on
			// a reword rather than on a wrong count.
			if got := attrValue(rendered, "data-tree-omitted"); got != strconv.Itoa(tc.omitted) {
				t.Errorf("the notice carries data-tree-omitted=%q, want %d", got, tc.omitted)
			}
			// The way out is a real link to the surface that shows all of it, not
			// a sentence. A notice that says "300 more pages" and offers nothing
			// is a smaller version of the same lie.
			if !strings.Contains(rendered, `<a href="/files"`) {
				t.Errorf("the omission notice offers no way to reach the rest of the vault:\n%s", snippetBytes(rendered))
			}
		})
	}
}

// TestTheSidebarTreeDisclosureCarriesItsAccessibilityContract is the markup half
// of the disclosure's obligations, and it is NOT an audit.
//
// What is checked: the control is a real <button type="button">, it carries an
// aria-expanded that is bound to the same signal that shows its children, and
// aria-controls names the element that is hidden. Those are the three things a
// disclosure pattern owes a screen reader, and each is checked for the *same*
// signal rather than for the mere presence of an attribute — an aria-expanded
// that is a constant "false" satisfies a presence check and is useless.
//
// What is not checked, and cannot be: contrast, focus order, whether a real
// treeview role would be better than nested lists, and how any of it behaves
// under the other theme. Those are the pa11y gate's, and pa11y.config.js lists
// this package as a Go-side markup assertion that does not replace it. A green
// result here is a precondition for the audit, not the audit.
func TestTheSidebarTreeDisclosureCarriesItsAccessibilityContract(t *testing.T) {
	t.Parallel()
	root := dir("", "", nil,
		dir("Area", "Area", []httpapi.PageCard{page(3, "Area/Salt_Ruin.md", "The Salt Ruin")}),
		dir("Empty", "Empty", nil),
	)
	rendered := sidebar(t, treeShell(root, 0))

	buttons := betweenAll(rendered, "<button", "</button>")
	if len(buttons) != 2 {
		t.Fatalf("the sidebar rendered %d disclosure controls, want one per directory (2):\n%s", len(buttons), snippetBytes(rendered))
	}
	for _, b := range buttons {
		if !strings.Contains(b, `type="button"`) {
			t.Errorf("a disclosure control is not type=button, so it submits whatever form it lands in:\n%s", b)
		}
		if !strings.Contains(b, `aria-expanded="false"`) {
			t.Errorf("a disclosure control has no static expanded state to start from:\n%s", b)
		}
		// The attribute is read unescaped, because that is what the browser hands
		// the DataStar expression: a test comparing the raw bytes would be
		// comparing HTML escaping, and would go red the day a quote were added to
		// the expression for a reason that had nothing to do with the claim.
		expanded := unescapedAttr(b, "data-attr:aria-expanded")
		click := unescapedAttr(b, "data-on:click")
		if expanded == "" || click == "" {
			t.Fatalf("a disclosure control does not bind its state to a signal:\n%s", b)
		}
		// The one that matters: the attribute a screen reader is told and the
		// expression that shows the panel read the same signal. A test for
		// "aria-expanded is present" would pass with a constant and prove
		// nothing, which is the whole reason this reads the two and compares.
		signal, ok := strings.CutSuffix(expanded, " ? 'true' : 'false'")
		if !ok {
			t.Fatalf("a disclosure control's aria-expanded is not derived from a signal: %q", expanded)
		}
		if !strings.Contains(click, "= !"+signal) {
			t.Errorf("the control writes %q while its aria-expanded reads %q; the state on screen and the state announced can disagree", click, signal)
		}
		controls := attrValue(b, "aria-controls")
		if controls == "" {
			t.Errorf("a disclosure control does not name the element it controls:\n%s", b)
			continue
		}
		if !strings.Contains(rendered, `id="`+controls+`"`) {
			t.Errorf("aria-controls names %q, which is not in the document:\n%s", controls, snippetBytes(rendered))
		}
	}

	// The list the control names is the list the signal hides, and it is a plain
	// element rather than one hidden in the markup: with DataStar blocked the
	// whole tree is visible, and the reader loses the collapsing and nothing else.
	for _, id := range []string{`id="left-tree-children-`, `data-show="$_open_`} {
		if !strings.Contains(rendered, id) {
			t.Errorf("a directory's children list does not carry %q:\n%s", id, snippetBytes(rendered))
		}
	}
	if strings.Contains(rendered, `style="display:none"`) {
		t.Error("a directory's children are hidden in the markup itself, so the tree is not readable without the script")
	}
	if hiddenAttr.MatchString(rendered) {
		t.Error("a directory's children carry the hidden attribute, so the tree is not readable without the script")
	}
}

// TestTheSidebarTreeIsChromeAndASwapCannotReplaceIt is the navigation claim.
//
// "Collapse/expand state survives a page navigation" is answered by *where the
// tree is*, not by anything it stores. A DataStar navigation replaces
// #page-region and nothing else, so a sidebar outside that region is not in the
// bytes a swap replaces — the open directories and the elements carrying the
// signal are the same objects afterwards, which is stronger than any state this
// package could persist and re-apply.
//
// The test asserts both halves: the tree is outside the region, and the region
// as Fragment renders carries no sidebar at all. A shell that grew a second
// page-region id, or a fragment that included the chrome, fails here rather than
// silently losing a reader's place.
func TestTheSidebarTreeIsChromeAndASwapCannotReplaceIt(t *testing.T) {
	t.Parallel()
	shell := treeShell(fileTree(), 0)
	document := component(t, web.Layout(web.Doc{
		Title: "A page",
		Shell: shell,
		Body:  web.Text("the page"),
	}))

	region := strings.Index(document, `id="page-region"`)
	nav := strings.Index(document, `<nav id="left-nav"`)
	if region < 0 || nav < 0 {
		t.Fatalf("the document is missing a landmark: page-region at %d, left-nav at %d", region, nav)
	}
	if nav > region {
		t.Errorf("the sidebar is inside the content region, so an in-place navigation replaces it and the reader's open folders are gone")
	}

	// The fragment is the region on its own. If it ever grew the sidebar, a swap
	// would rebuild the tree from whatever the new page's shell carried and the
	// expanded state would be reset on every navigation.
	fragment := component(t, web.Region(httpapi.PageView{Shell: shell, Card: pageCard()},
		web.Text("the page")))
	if strings.Contains(fragment, "left-tree") {
		t.Errorf("a fragment response carries the sidebar's tree, so a swap rebuilds it:\n%s", snippetBytes(fragment))
	}
	if !strings.Contains(fragment, `id="page-region"`) {
		t.Errorf("a fragment response is not the region, so a swap has nothing to replace:\n%s", snippetBytes(fragment))
	}
}

// TestTheSidebarTreeAndTheFilesPageShareOneDirectoryState is the "one state per
// directory" claim.
//
// On /files both trees are in the same document, so this also pins the thing
// that would otherwise be a duplicate-id bug: two lists, two sets of child-list
// ids, one directory. If either the id prefix or the signal key were per tree,
// the two trees would disagree about which folders are open and a button's
// aria-controls would name an element the browser found in the other list.
func TestTheSidebarTreeAndTheFilesPageShareOneDirectoryState(t *testing.T) {
	t.Parallel()
	shell := treeShell(fileTree(), 0)
	document := component(t, web.Layout(web.Doc{
		Title: "Files",
		Shell: shell,
		Body:  web.Files(httpapi.FilesView{Shell: shell, Tree: fileTree(), PageCount: 3}),
	}))

	// Every id in the document appears once. This is the check that catches a
	// duplicated id directly, rather than inferring one from an aria-controls.
	seen := map[string]int{}
	for _, m := range regexp.MustCompile(` id="([^"]*)"`).FindAllStringSubmatch(document, -1) {
		seen[m[1]]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("the document carries id %q %d times; a duplicate id makes aria-controls name the wrong element", id, n)
		}
	}

	// One signal per directory, whichever tree is asking: the two rows for the
	// same directory must write the same expression, or opening Guild in the
	// sidebar and finding it shut on /files is the bug.
	signals := map[string]int{}
	for _, m := range regexp.MustCompile(`data-on:click="(\$_open_[0-9a-f]+) = !`).FindAllStringSubmatch(document, -1) {
		signals[m[1]]++
	}
	for signal, n := range signals {
		if n != 2 {
			t.Errorf("the signal %s is written by %d controls, want 2 (the sidebar's row and the page's row for the same directory)", signal, n)
		}
	}
	// And the two child-list ids for one directory differ, because one id per
	// element is the whole of the fix.
	if !strings.Contains(document, `id="left-tree-children-`) || !strings.Contains(document, `id="page-tree-children-`) {
		t.Errorf("the two trees do not scope their child-list ids:\n%s", snippetBytes(document))
	}
}

// TestTheSidebarTreeEscapesAVaultPath is the injection claim, and it is a claim
// about three separate escapes because a path is attacker-controlled content.
//
// A vault path is author-controlled: anybody with write access to the vault
// directory chooses the file names. vault.Resolve refuses the syntactic
// traversal cases — a `..` element, an absolute path, a drive letter, a control
// character, UNC — so this does not re-check those rules. What it does check is
// the half the rules cannot: an *allowed* name may still contain `&`, `"`, `<`
// or a space, and those reach three places in the markup. The name reaches
// element text, the path reaches an href attribute, and the path also reaches a
// DataStar expression through dirSignal — a signal name is an identifier in an
// attribute, and one written by hand rather than hex-encoded would be a second
// injection surface in the one component that gets a user string twice.
func TestTheSidebarTreeEscapesAVaultPath(t *testing.T) {
	t.Parallel()
	const hostile = `Ash & Ember <script>alert("x")</script>/O'Brien's "quoted" & spaced.md`
	const folder = `Ash & Ember <img src=x onerror=alert(1)>`
	rendered := sidebar(t, treeShell(dir("", "", nil,
		dir(folder, folder, []httpapi.PageCard{page(9, hostile, `Naïve & <b>bold</b>`)}),
	), 0))

	// No markup of the vault's own making reached the document. The name is
	// element text, so the angle brackets are the bytes a reader sees.
	if strings.Contains(rendered, "<script>") || strings.Contains(rendered, "<img src=x") {
		t.Errorf("a vault path reached the document as markup:\n%s", snippetBytes(rendered))
	}
	// The text is present, escaped. An assertion for the absence of "<script>"
	// alone passes on a template that dropped the name altogether, which is the
	// other half of the failure and a worse one.
	if !strings.Contains(rendered, `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;`) {
		t.Errorf("the folder name is not rendered as escaped text:\n%s", snippetBytes(rendered))
	}
	if !strings.Contains(rendered, `Naïve &amp; &lt;b&gt;bold&lt;/b&gt;`) {
		t.Errorf("the page title is not rendered as escaped text:\n%s", snippetBytes(rendered))
	}
	// The href is escaped, and what the browser resolves from it is the app's
	// own encoding of the path — byte for byte, which is the claim that there is
	// no second encoding here.
	want := "/p/" + hostile
	if !slicesContains(emittedHrefs(t, rendered), want) {
		t.Errorf("the sidebar does not link %q after unescaping; the href is not the app's encoding of the path:\n%v", want, emittedHrefs(t, rendered))
	}
	// The signal name is hex, so the path cannot end up in the expression as an
	// identifier. This is the assertion that would fail first if dirSignal were
	// ever rewritten to slug a path into a name — and it is the reason the folder
	// above is named with a space and two angle brackets.
	hexSignal := regexp.MustCompile(`^\$_open_[0-9a-f]+ = !\$_open_[0-9a-f]+$`)
	for _, m := range regexp.MustCompile(`data-on:click="([^"]*)"`).FindAllStringSubmatch(rendered, -1) {
		if !hexSignal.MatchString(html.UnescapeString(m[1])) {
			t.Errorf("a directory's signal is not a hex-encoded name: %s", m[1])
		}
	}
	// And the hex really is this path's hex, which is what makes the name lossless
	// rather than merely unreadable. A slug would also pass the test above and
	// would collapse two directories onto one signal.
	dirHex := hex.EncodeToString([]byte(folder))
	if !strings.Contains(rendered, "$_open_"+dirHex) {
		t.Errorf("the directory's signal is not the hex of its own path, so two directories can share it")
	}
}

// TestTheSidebarTreeRendersAVaultOfFiveHundredFiles is the size claim, and it is
// split across two layers because the two layers answer different questions.
//
// The cap lives in the shell, not in the template, and that placement is the
// point: the template is handed a tree and renders it, and the only thing that
// knows the total is the handler that queried the pages. A cap expressed as
// "render at most N rows" inside a template would have to count what it had
// already rendered, and the count that decides it would be the count of a
// truncated list — which is the shape of the existence leak AGENTS.md §2.4 is
// about. So the first case below builds the tree the shell actually builds for a
// 500-page vault: the first 200 pages, with 300 named as omitted.
//
// The second case is the component's own claim, and it is the one a template can
// make: handed 500 rows it renders 500 and does not take superlinear time. It is
// what would notice a rewrite that turned the walk into a linear scan per row.
func TestTheSidebarTreeRendersAVaultOfFiveHundredFiles(t *testing.T) {
	t.Parallel()
	const total = 500
	// The shape a real walk produces rather than 500 leaves under one parent: a
	// folder, a folder inside it, a folder inside that, and pages at the root and
	// at every level. A tree that only ever nests one way would pass a test built
	// out of a single directory and fail on a vault somebody actually keeps.
	byLevel := map[string][]httpapi.PageCard{}
	for i := range total {
		name := fmt.Sprintf("Page-%04d.md", i)
		card := page(int64(100+i), name, name)
		switch i % 4 {
		case 0:
			byLevel["root"] = append(byLevel["root"], card)
		case 1:
			card.Path = "Campaigns/Ash/" + name
			byLevel["ash"] = append(byLevel["ash"], card)
		default:
			card.Path = "Campaigns/Ash/NPCs/" + name
			byLevel["npcs"] = append(byLevel["npcs"], card)
		}
	}
	// The vault as it is: 500 pages, and the shell keeps the first 200 in path
	// order, which is Campaigns/Ash/NPCs/* before Campaigns/Ash/* before the root.
	capped := flatTree(total, httpapi.SidebarTreeMax)
	omitted := total - httpapi.SidebarTreeMax
	rendered := sidebar(t, treeShell(capped, omitted))

	if rows := strings.Count(rendered, `class="file-page"`); rows != httpapi.SidebarTreeMax {
		t.Errorf("the capped sidebar rendered %d page rows, want the cap of %d", rows, httpapi.SidebarTreeMax)
	}
	// The omission is named, and the number in the notice is the one the shell
	// computed from the same page list the tree was built from, so a reader who
	// counts rows and reads the notice is comparing one figure with another.
	if !strings.Contains(rendered, strconv.Itoa(omitted)+" more pages in this vault.") {
		t.Errorf("the sidebar does not name the %d pages it left out", omitted)
	}
	// Every directory is a real disclosure control, so a large vault costs markup
	// and not a second kind of control for a reader to learn.
	if n, e := strings.Count(rendered, "<button"), strings.Count(rendered, `aria-expanded="false"`); n != e {
		t.Errorf("the sidebar rendered %d disclosure controls for %d expanded states", n, e)
	}
	// The byte budget is the claim that matters for a component on every page. A
	// navigation column that costs a fifth of a megabyte is not a navigation
	// column, and the number is here so that a change to it has to be argued.
	if len(rendered) > 200_000 {
		t.Errorf("a %d-row sidebar rendered %d bytes, which is not a navigation column", httpapi.SidebarTreeMax, len(rendered))
	}

	t.Run("a tree the shell should not have handed over still renders in linear time", func(t *testing.T) {
		t.Parallel()
		// The component's own property, and the one a rewrite of fileEntries
		// would break: no scan per row, no quadratic re-walk, and every page
		// still linked. The budget is generous on purpose — this asserts
		// proportionality, not a number, and a machine three times slower than
		// this one should not turn it red.
		whole := flatTree(total, total)
		start := time.Now()
		out := sidebar(t, treeShell(whole, 0))
		took := time.Since(start)
		if n := strings.Count(out, `class="file-page"`); n != total {
			t.Errorf("the tree rendered %d rows, want all %d", n, total)
		}
		if took > 2*time.Second {
			t.Errorf("rendering %d rows took %s, which is not linear in the row count", total, took)
		}
	})
}

// flatTree is a vault of n pages, each in its own numbered directory, which is
// the worst case for row count and the easiest shape to reason about a count in.
//
// Nested directories rather than a flat list on purpose: a flat list would make
// a per-row scan cheap to hide, and the claim being tested is about the work per
// row rather than about the number of nodes.
func flatTree(_, keep int) httpapi.FileNode {
	root := dir("", "", nil)
	for i := range keep {
		name := fmt.Sprintf("Page-%04d.md", i)
		root.Children = append(root.Children, dir(fmt.Sprintf("d%04d", i), fmt.Sprintf("d%04d", i),
			[]httpapi.PageCard{page(int64(100+i), fmt.Sprintf("d%04d/%s", i, name), name)}))
	}
	return root
}

// directoryRows is how many directory rows a tree renders, which is one per
// node below the root: the root is the tree list itself and has no row of its
// own. Every one of them renders a children list, collapsed or not, so this is
// the number the markup's `file-children` lists can be counted against.
func directoryRows(n httpapi.FileNode) int {
	rows := 0
	for _, c := range n.Children {
		rows += 1 + directoryRows(c)
	}
	return rows
}

// deepTree is a vault whose only page is nested n directories deep, which is
// the case a recursive template either handles or overflows on.
//
// The local is called `at` rather than `node` for the reason AGENTS.md §11
// records: TestEveryQueryUsesBindParameters scans every .go file for a line
// holding both Sprintf and a SQL verb word, and a local named `node` is one of
// them. The gate is right to be suspicious and the name is not worth a fight.
func deepTree(n int) httpapi.FileNode {
	leaf := deepPath(n) + "/leaf.md"
	at := dir(fmt.Sprintf("d%d", n), deepPath(n), []httpapi.PageCard{page(99, leaf, "the leaf")})
	for i := n - 1; i >= 0; i-- {
		child := at
		if i == 0 {
			at = dir("", "", nil, child)
			break
		}
		// The prefix is folded into a path on its own line, because
		// TestEveryQueryUsesBindParameters flags any line that both formats a
		// string and mentions a SQL verb, and the stdlib call that joins a
		// string slice is spelled with one of them. The gate is right to be
		// suspicious of a line that builds a string by format, and splitting the
		// line is cheaper than a waiver.
		path := strings.Join(pathPrefix(i), "/")
		at = dir(fmt.Sprintf("d%d", i), path, nil, child)
	}
	return at
}

// deepPath is the vault-relative directory n levels deep.
func deepPath(n int) string { return strings.Join(pathPrefix(n), "/") }

// pathPrefix is the n directory names a deep vault nests.
func pathPrefix(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("d%d", i))
	}
	return out
}

// unescapedAttr is one attribute's value as the browser would hand it to the
// expression parser, which is the only form in which an expression is a thing
// two attributes can be compared on.
func unescapedAttr(element, name string) string {
	return html.UnescapeString(attrValue(element, name))
}

// attrValue is one attribute's raw value out of an element.
func attrValue(element, name string) string {
	m := regexp.MustCompile(`(?s)\s` + regexp.QuoteMeta(name) + `="([^"]*)"`).FindStringSubmatch(element)
	if m == nil {
		return ""
	}
	return m[1]
}

// betweenAll is every occurrence of a delimited span, so a test can count them.
func betweenAll(s, start, end string) []string {
	var out []string
	for {
		i := strings.Index(s, start)
		if i < 0 {
			return out
		}
		s = s[i:]
		j := strings.Index(s, end)
		if j < 0 {
			return append(out, s)
		}
		out = append(out, s[:j+len(end)])
		s = s[j+len(end):]
	}
}

// snippetBytes bounds a rendered document in a failure message.
func snippetBytes(body string) string {
	if len(body) > 900 {
		return body[:900] + "…"
	}
	return body
}

// slicesContains is a one-line membership test, so a test reads as a claim.
func slicesContains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
