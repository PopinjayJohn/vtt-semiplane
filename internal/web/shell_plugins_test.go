package web_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The plugin layer's contribution to the shell, and above all its absence.
//
// Every test here has the same shape: build the view model a handler would have
// built, render it, and look at the bytes. The subject is never a view model's
// field, because a field is what the author wrote and the subject is what a
// reader is left with — a heading with nothing under it, a link to a 404, an
// article with no body.

// pluginRegistry is a plugin.Registry holding whatever one test put in it.
//
// It is here because the interface is the seam the plugin package promised: a
// test that wants "the shell with one plugin's sidebar group on it" should not
// have to boot a vault, run a lifecycle and register a plugin to get there.
// Only the sidebar half is filled, because the sidebar is the one surface the
// shell reads straight out of a registry; panels and viewers are chosen by the
// handler, which this package cannot reach, and the view models those handlers
// build are what the rendering tests below are written against. Every other
// method returns the zero value, which is also what a registry with nothing
// registered means — an unimplemented method would panic, and a panic in a
// fixture is a worse way to learn that a test is wrong than an empty page is.
type pluginRegistry struct {
	// nav is what NavItems returns, in the order it returns it.
	nav []plugin.Owned[plugin.NavItem]
	// report is what Report returns.
	report plugin.Report
}

// Report returns the boot report.
func (r pluginRegistry) Report() plugin.Report { return r.report }

// PageType returns no registered page type.
func (r pluginRegistry) PageType(string) (plugin.PageType, bool) { return plugin.PageType{}, false }

// PageTypes returns no registered page types.
func (r pluginRegistry) PageTypes() []plugin.Owned[plugin.PageType] { return nil }

// Panels returns no registered panels.
func (r pluginRegistry) Panels() []plugin.Owned[plugin.Panel] { return nil }

// PanelsFor returns no panels, for this page type or any other.
func (r pluginRegistry) PanelsFor(string) []plugin.Owned[plugin.Panel] { return nil }

// NavItems returns every registered sidebar entry.
func (r pluginRegistry) NavItems() []plugin.Owned[plugin.NavItem] { return r.nav }

// SearchResolvers returns no resolvers.
func (r pluginRegistry) SearchResolvers() []plugin.Owned[plugin.SearchResolver] { return nil }

// Summaries returns no summary providers.
func (r pluginRegistry) Summaries() []plugin.Owned[plugin.SummaryProvider] { return nil }

// Routes returns no mounted sub-routers.
func (r pluginRegistry) Routes() []plugin.Owned[plugin.RouteMounter] { return nil }

// Extenders returns no markdown extenders.
func (r pluginRegistry) Extenders() []plugin.Owned[any] { return nil }

// Plugin returns no plugin.
func (r pluginRegistry) Plugin(string) (plugin.Plugin, bool) { return nil, false }

// Config returns no configuration.
func (r pluginRegistry) Config(string) (plugin.Config, bool) { return plugin.Config{}, false }

// panelBody is a plugin's rendered output as a fixture.
//
// It writes exactly the string it is given, which is the whole point: a panel's
// body is text that the host hands to the template, and the tests below need to
// put text in it that a template would be tempted to treat as markup.
type panelBody string

// Render writes the body.
func (p panelBody) Render(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, string(p))
	return err
}

// navShell is a shell with one campaign's worth of chrome and no plugins.
func navShell() httpapi.Shell {
	return httpapi.Shell{
		Title:          "The Drowned Lantern",
		CSRF:           testCSRF,
		Campaign:       "drowned-lantern",
		CurrentPageID:  12,
		CurrentPageURL: "/p/Tavern.md",
		Principal:      authz.ForUser(7, "thia", authz.RoleDM, false),
	}
}

// navFor projects a registry's sidebar entries the way a handler projects them.
//
// The projection is the handler's half of the rule and it is called here rather
// than written out, so that a test which asserts a link is *absent* is asserting
// about the bytes that reach the template and not about a copy of the filter
// living in a test file.
func navFor(t *testing.T, r plugin.Registry, who authz.Principal) []httpapi.PluginNavItem {
	t.Helper()
	return httpapi.PluginNavFor(r.NavItems(), who, authz.NewPolicy(false))
}

// TestNoPluginsMeansNoPluginNavGroup is the rule AGENTS.md §7 states in one
// sentence, asserted on the heading rather than on the items.
//
// A group with zero items and an <h2> over it is a heading promising a
// destination and offering none. It is a different failure from a missing item
// — the items are already absent by construction — and it is the one that looks
// like a broken page rather than like a build with nothing in it, so the
// assertion is about the heading's absence and a positive control proves the
// markup for that heading is really what is being looked for.
func TestNoPluginsMeansNoPluginNavGroup(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	dm := authz.ForUser(7, "thia", authz.RoleDM, false)

	// Nothing registered, which is the state of every binary built before a
	// plugin existed and of every boot whose lifecycle was not run.
	empty := navFor(t, pluginRegistry{}, dm)
	if empty != nil {
		t.Fatalf("an empty registry produced %d nav items, so the rendering below is not about the empty case", len(empty))
	}
	document := render(t, r, httpapi.HomeView{Shell: navShell()}, false)
	if strings.Contains(document, "plugin-nav-heading") {
		t.Errorf("the sidebar rendered a plugin heading with nothing under it:\n%s", between(document, `<nav id="left-nav"`, "</nav>"))
	}

	// The control: the same shell with one entry does render the heading, so the
	// assertion above is about the count rather than about a misspelled id.
	one := navFor(t, pluginRegistry{nav: []plugin.Owned[plugin.NavItem]{
		{Plugin: "dnd5e", Value: plugin.NavItem{ID: "dice", Label: "Dice", Href: "/plugin/dnd5e/dice", Icon: "i-d20"}},
	}}, dm)
	if len(one) != 1 {
		t.Fatalf("the control registry produced %d items, want 1", len(one))
	}
	withNav := render(t, r, httpapi.HomeView{Shell: shellWith(navShell(), one)}, false)
	if !strings.Contains(withNav, `id="plugin-nav-heading"`) {
		t.Fatalf("a sidebar with one plugin entry rendered no plugin heading:\n%s", between(withNav, `<nav id="left-nav"`, "</nav>"))
	}
	if !strings.Contains(withNav, `href="/plugin/dnd5e/dice"`) {
		t.Error("the plugin entry's own link is not in the document")
	}
}

// shellWith returns a shell carrying a plugin nav group.
func shellWith(shell httpapi.Shell, nav []httpapi.PluginNavItem) httpapi.Shell {
	shell.PluginNav = nav
	return shell
}

// TestAPluginNavItemWithABadHrefIsDropped is the same rule for the href, and it
// is asserted on the rendered document because the failure it prevents is a
// rendered one: a sidebar entry that navigates to a 404.
//
// The host is supposed to have refused an out-of-prefix nav item at
// registration, so this is the cheap second check — and the interesting case is
// the one a bare HasPrefix would let through, where a plugin whose id is a prefix
// of another's claims its neighbour's route by name resemblance.
func TestAPluginNavItemWithABadHrefIsDropped(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	dm := authz.ForUser(7, "thia", authz.RoleDM, false)
	registry := pluginRegistry{nav: []plugin.Owned[plugin.NavItem]{
		{Plugin: "dnd5e", Index: 0, Value: plugin.NavItem{ID: "dice", Label: "Dice", Href: "/plugin/dnd5e/dice", Icon: "i-d20"}},
		{Plugin: "dnd5e", Index: 1, Value: plugin.NavItem{ID: "lookalike", Label: "Impostor", Href: "/plugin/dnd5e-rogue/dice"}},
		{Plugin: "dnd5e", Index: 2, Value: plugin.NavItem{ID: "core", Label: "Escapee", Href: "/admin/users"}},
		{Plugin: "dnd5e", Index: 3, Value: plugin.NavItem{ID: "empty", Label: "Nowhere", Href: ""}},
	}}

	nav := navFor(t, registry, dm)
	document := render(t, r, httpapi.HomeView{Shell: shellWith(navShell(), nav)}, false)
	sidebar := between(document, `<nav id="left-nav"`, "</nav>")

	if !strings.Contains(sidebar, `href="/plugin/dnd5e/dice"`) {
		t.Fatalf("the one good entry is missing, so the omissions below prove nothing:\n%s", sidebar)
	}
	for _, gone := range []string{"/plugin/dnd5e-rogue", "/admin/users", "Impostor", "Escapee", "Nowhere"} {
		if strings.Contains(sidebar, gone) {
			t.Errorf("the sidebar still carries %q, and a link to nothing is a broken control:\n%s", gone, sidebar)
		}
	}
	// And the strongest form: an item that is entirely refused leaves no trace
	// at all, so a registry of bad hrefs is indistinguishable from no registry.
	onlyBad := navFor(t, pluginRegistry{nav: registry.nav[1:]}, dm)
	if onlyBad != nil {
		t.Fatalf("a registry of out-of-prefix hrefs produced %d items", len(onlyBad))
	}
	empty := render(t, r, httpapi.HomeView{Shell: shellWith(navShell(), onlyBad)}, false)
	if strings.Contains(empty, "plugin-nav-heading") {
		t.Errorf("a sidebar whose every plugin entry was refused still rendered a heading:\n%s", between(empty, `<nav id="left-nav"`, "</nav>"))
	}
}

// TestANavItemThePrincipalMayNotSeeIsNotRendered is the hard rule that a nav
// item with a role requirement is filtered by the handler, and never by the
// template.
//
// A sidebar is rendered on every page for every reader, so a DM-only entry that
// survived into the view model would be a control a player can see and cannot
// follow — a link to an authorisation failure, which is the same broken control
// as a link to a 404. The decision is made here in the projection, through the
// policy, which is the one place a role may be compared; the template renders
// what it is handed and cannot re-ask.
func TestANavItemThePrincipalMayNotSeeIsNotRendered(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	registry := pluginRegistry{nav: []plugin.Owned[plugin.NavItem]{
		{Plugin: "dnd5e", Index: 0, Value: plugin.NavItem{ID: "sheet", Label: "Campaign sheet", Href: "/plugin/dnd5e/sheet"}},
		{Plugin: "dnd5e", Index: 1, Value: plugin.NavItem{ID: "audit", Label: "Campaign audit", Href: "/plugin/dnd5e/audit", MinimumRole: "dm"}},
		{Plugin: "dnd5e", Index: 2, Value: plugin.NavItem{ID: "users", Label: "Plugin users", Href: "/plugin/dnd5e/users", MinimumRole: "admin"}},
		// A role nobody has. The entry is shown to nobody rather than to
		// everybody, because an entry that vanished for a DM and stayed for an
		// admin is a policy with a hole in it.
		{Plugin: "dnd5e", Index: 3, Value: plugin.NavItem{ID: "typo", Label: "Typo", Href: "/plugin/dnd5e/typo", MinimumRole: "wizard"}},
	}}
	player := authz.ForUser(7, "thia", authz.RolePlayer, false)
	dm := authz.ForUser(1, "mara", authz.RoleDM, false)
	admin := authz.ForUser(2, "ilse", authz.RoleAdmin, false)

	for _, tc := range []struct {
		who   authz.Principal
		shown []string
		gone  []string
	}{
		{who: player, shown: []string{"Campaign sheet"}, gone: []string{"Campaign audit", "Plugin users", "Typo"}},
		{who: dm, shown: []string{"Campaign sheet", "Campaign audit"}, gone: []string{"Plugin users", "Typo"}},
		{who: admin, shown: []string{"Campaign sheet", "Campaign audit", "Plugin users"}, gone: []string{"Typo"}},
	} {
		nav := navFor(t, registry, tc.who)
		sidebar := between(render(t, r, httpapi.HomeView{Shell: shellWith(navShell(), nav)}, false), `<nav id="left-nav"`, "</nav>")
		for _, want := range tc.shown {
			if !strings.Contains(sidebar, want) {
				t.Errorf("%s may not see %q, or the sidebar did not render it:\n%s", tc.who, want, sidebar)
			}
		}
		for _, gone := range tc.gone {
			if strings.Contains(sidebar, gone) {
				t.Errorf("%s may not see %q, and the sidebar rendered it anyway:\n%s", tc.who, gone, sidebar)
			}
		}
	}
}

// TestPanelsRenderInSlotOrder is the layout's half of the panel contract.
//
// The handler already sorts by slot, so a template that iterated the slice in
// the order it was handed would pass on that input and fail on the other one: a
// panel's position is chosen by the column, not by whatever order a registry
// happened to return. The fixture therefore hands the view model the slots
// backwards, and the assertion is on the rendered order.
func TestPanelsRenderInSlotOrder(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	view := httpapi.PageView{
		Shell: navShell(),
		Card:  httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Body:  "<p>The lantern gutters.</p>",
		Panels: []httpapi.PluginPanel{
			// Deliberately not in slot order, and not in the order a registry
			// documents: top, mid and bottom are what the column means by them.
			{Slot: "right-bottom", Title: "Below the page context", Body: "the bottom panel"},
			{Slot: "right-mid", Title: "Page context", Body: "the middle panel"},
			{Slot: "right-top", Title: "Above the page context", Body: "the top panel"},
		},
		Status: campaignStatus(),
	}
	document := render(t, r, view, false)

	slots := []string{"right-top", "right-mid", "right-bottom"}
	at := make([]int, len(slots))
	for i, slot := range slots {
		marker := `data-plugin-slot="` + slot + `"`
		at[i] = strings.Index(document, marker)
		if at[i] < 0 {
			t.Fatalf("the %s panel is not in the column:\n%s", slot, between(document, `<aside id="context"`, "</aside>"))
		}
	}
	for i := 1; i < len(at); i++ {
		if at[i-1] >= at[i] {
			t.Errorf("the %s panel is rendered after the %s one; the slot order is %v", slots[i], slots[i-1], slots)
		}
	}
	// Each panel is a labelled section rather than a floating block, and the
	// label is the one the handler derived from the slot.
	if !strings.Contains(document, ">Above the page context</h2>") {
		t.Error("a panel rendered without a heading")
	}
	// A slot with nothing in it renders nothing, so there is no empty section
	// standing where the left-bottom panel is not.
	if strings.Contains(document, "left-bottom") {
		t.Error("a slot with no panel in it still rendered something")
	}
}

// TestAPanelGroupIsAdditionalToTheSystemEmptyState keeps the two panel layers
// from eating each other.
//
// The campaign status panel's system row is a statement about the campaign —
// that no system is registered for it — and a plugin panel group is a statement
// about the page. One of them is a fact about the vault and the other is a
// contribution to a page, so a plugin's panel must not silence the host's
// sentence: a reader who sees a panel and no system note has been told the
// campaign has a system.
func TestAPanelGroupIsAdditionalToTheSystemEmptyState(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	document := render(t, r, httpapi.PageView{
		Shell: navShell(),
		Card:  httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Body:  "<p>The lantern gutters.</p>",
		Panels: []httpapi.PluginPanel{
			{Slot: "right-top", Title: "Above the page context", Body: "a panel that says something about this page"},
		},
		// The panel group is present and the system is not, which is the shape
		// that has to keep saying so.
		Status: httpapi.CampaignStatus{SystemNote: "No game system is registered for this campaign."},
	}, false)

	for _, want := range []string{
		`data-plugin-slot="right-top"`,
		"a panel that says something about this page",
		`data-status-field="system"`,
		"No game system is registered for this campaign.",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the document is missing %q:\n%s", want, between(document, `<aside id="context"`, "</aside>"))
		}
	}
}

// TestAPageRendersNormallyWithNoRegistry is the degradation test, and it is the
// one this stage exists to prevent.
//
// "No registry" is not a thing a view model can be handed — the registry is the
// handler's, and its absence reaches the template as an empty group and an empty
// panel list. So this renders every view model with both of those empty and
// asserts the page still has its title, its body, its contents, its backlinks
// and its campaign status. A shell that only works when a plugin is installed is
// a broken app, not a degraded one.
func TestAPageRendersNormallyWithNoRegistry(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	for _, v := range allViews() {
		t.Run(typeName(v), func(t *testing.T) {
			t.Parallel()
			document := render(t, r, v, false)

			// No plugin markup anywhere: a group or a panel that appeared with
			// nothing behind it would be the failure this test exists to catch,
			// and an empty heading is the shape it takes. The checks are on the
			// sidebar and the context column rather than on the whole document,
			// because /admin/plugins is a core surface whose whole job is to name
			// plugins and would fail a document-wide grep.
			sidebar := between(document, `<nav id="left-nav"`, "</nav>")
			column := between(document, `<aside id="context"`, "</aside>")
			if strings.Contains(sidebar, "data-plugin=") || strings.Contains(sidebar, "plugin-nav-heading") {
				t.Errorf("a sidebar with no plugins rendered a plugin group:\n%s", sidebar)
			}
			if strings.Contains(column, "data-plugin-slot") {
				t.Errorf("a context column with no panels rendered a panel:\n%s", column)
			}

			switch view := v.(type) {
			case httpapi.PageView:
				// The page itself: its title, its rendered body, its contents
				// and its backlinks, all of which are core's and all of which
				// have to survive the absence of a system plugin.
				for _, want := range []string{
					view.Card.Title,
					"The lantern gutters and the tide comes in.",
					`href="#the-room"`,
					"the-room",
					`href="/p/Index.md"`,
				} {
					if !strings.Contains(document, want) {
						t.Errorf("a page with no plugins is missing %q", want)
					}
				}
				// And the campaign panel, which is core's and says so.
				if !strings.Contains(document, "Campaign status") {
					t.Error("a page with no plugins has no campaign status panel")
				}
			case httpapi.HomeView, httpapi.ContextView:
				if !strings.Contains(document, "Campaign status") {
					t.Error("a view with no plugins has no campaign status panel")
				}
				if !strings.Contains(document, "Thia Vane") {
					t.Error("the party list is missing, so the campaign panel is not really there")
				}
			}
		})
	}
}

// TestEveryRegisteredPageTypeFallsBackToTheCoreViewer is the distinction between
// a registered page type and a page-type convention, which is the reason
// `type: houserule` works on a campaign with no plugin installed.
//
// A page whose frontmatter says `type: character` is a page a system plugin
// would normally own. With no plugin holding that type, the only viewer there
// is the core Markdown one, and rendering the empty article instead would make
// every page of a plugin-less campaign unreadable — the failure this rule
// prevents is not a missing feature, it is a missing page.
func TestEveryRegisteredPageTypeFallsBackToTheCoreViewer(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	const body = "<p>The lantern gutters and the tide comes in.</p>"

	// The type nobody registered, which is also what a campaign with no plugins
	// has for every type it names.
	unclaimed := httpapi.PageView{
		Shell:    navShell(),
		Card:     httpapi.PageCard{ID: 12, Path: "Party/Thia.md", Title: "Thia Vane", PageType: "character"},
		Body:     body,
		PageType: "character",
		Status:   campaignStatus(),
	}
	document := render(t, r, unclaimed, false)
	if !strings.Contains(document, body) {
		t.Fatalf("a page whose registered type no plugin claims did not render its Markdown body:\n%s", between(document, `<div class="prose-vtt`, "</div>"))
	}
	if !strings.Contains(document, "Thia Vane") {
		t.Error("the page has no title, so the body is on a page nobody can find")
	}

	// The other half of the same rule: a type that *does* have a viewer gets it.
	// A viewer is the one piece of plugin output that is markup, because it is a
	// templ.Component rather than a string — the plugin wrote it, it is the
	// plugin's own component, and the panel bodies' escaping does not apply to
	// it. What applies to both is that neither is vault content.
	claimed := unclaimed
	claimed.Viewer = panelBody("<p>a character sheet</p>")
	withViewer := render(t, r, claimed, false)
	if !strings.Contains(withViewer, "a character sheet") {
		t.Error("a registered viewer's own output is missing from the page")
	}
	if strings.Contains(withViewer, body) {
		t.Error("the core body was rendered beside the registered viewer, so the page says the same thing twice")
	}
	// The fallback is decided per request from the view model, so a campaign
	// with the same file and no plugin still gets the body.
	if got := render(t, r, unclaimed, false); !strings.Contains(got, body) {
		t.Error("rendering the same page twice gave different answers")
	}
}

// TestTheFragmentIsStillAStrictSubsetOfTheDocument keeps the negotiation
// contract intact over the markup this stage added.
//
// The plugin group is in the shell and the panels are in the right column, both
// of which a fragment does not carry, so the property under test is that adding
// them did not put any of it inside the swappable region: a fragment that
// rendered a plugin panel would be a second rendering of plugin output on a
// second code path.
func TestTheFragmentIsStillAStrictSubsetOfTheDocument(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	decorated := []httpapi.View{
		httpapi.PageView{
			Shell:  shellWith(navShell(), []httpapi.PluginNavItem{{ID: "dice", Plugin: "dnd5e", Label: "Dice", Href: "/plugin/dnd5e/dice", Icon: "i-d20"}}),
			Card:   httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
			Body:   "<p>The lantern gutters.</p>",
			Panels: []httpapi.PluginPanel{{Slot: "right-top", Title: "Above the page context", Body: "a panel"}},
			Status: campaignStatus(),
		},
		httpapi.ContextView{
			Shell:  shellWith(navShell(), []httpapi.PluginNavItem{{ID: "dice", Plugin: "dnd5e", Label: "Dice", Href: "/plugin/dnd5e/dice", Icon: "i-d20"}}),
			Card:   httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
			Panels: []httpapi.PluginPanel{{Slot: "right-mid", Title: "Page context", Body: "a panel"}},
			Status: campaignStatus(),
		},
	}
	for _, v := range append(allViews(), decorated...) {
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

// TestNoPluginPanelCanShipJavaScript is the security property of AGENTS.md §7
// and of the design plan's S21, and it is worth having even though the dnd5e
// plugin has no reason to emit a script: it is the property that makes "a plugin
// cannot ship JavaScript" a fact about the pipeline rather than a claim about
// the plugins currently in the tree.
//
// A panel body crosses the package boundary as a string, so a template that
// wanted to be helpful about it would reach for templ.Raw. This asserts that
// the body is escaped text instead, by comparing a document that has one with
// one that does not: a body that became markup would add a script element, and
// the shell's own two asset tags are the only script elements there are.
func TestNoPluginPanelCanShipJavaScript(t *testing.T) {
	t.Parallel()
	r := web.NewRenderer()
	const hostile = `<script>fetch("/api/session")</script><img src=x onerror=alert(1)>`
	base := httpapi.PageView{
		Shell:  navShell(),
		Card:   httpapi.PageCard{ID: 12, Path: "Tavern.md", Title: "The Drowned Lantern"},
		Body:   "<p>The lantern gutters.</p>",
		Status: campaignStatus(),
	}
	withBody := base
	withBody.Panels = []httpapi.PluginPanel{
		{Slot: "right-top", Title: "Above the page context", Body: hostile},
	}

	document := render(t, r, withBody, false)
	clean := render(t, r, base, false)

	// Each half of the body has to arrive inert. The test is on the tag rather
	// than on the payload, because escaping turns "<" into "&lt;" and leaves the
	// rest of an attribute alone: `onerror=alert(1)` survives as visible words
	// whether or not it is dangerous. What must not survive is the angle bracket
	// that would make a browser start parsing. The check is scoped to the
	// panel's own section because the document's two script tags are the shell's
	// asset references and are supposed to be there.
	panel := between(document, `<section aria-labelledby="plugin-panel-right-top-0"`, "</section>")
	if panel == "" {
		t.Fatal("the panel's section is not in the document, so the assertions below are vacuous")
	}
	for _, live := range []string{"<script", "<img", "</script>"} {
		if strings.Contains(panel, live) {
			t.Errorf("a panel body reached the document as markup (%q):\n%s", live, panel)
		}
	}
	if n, m := strings.Count(document, "<script"), strings.Count(clean, "<script"); n != m {
		t.Errorf("the document has %d script elements and the same page without a panel has %d; a panel added one", n, m)
	}
	// The escaped form is present rather than the text having been dropped: a
	// panel that silently rendered nothing would pass the assertions above.
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img src=x onerror=alert(1)&gt;"} {
		if !strings.Contains(document, escaped) {
			t.Errorf("the panel body is neither markup nor visible text; %q is missing:\n%s", escaped, between(document, `<aside id="context"`, "</aside>"))
		}
	}
	// The panel's own words are still there, so the escaping above is about the
	// body and not about the panel having been dropped.
	if !strings.Contains(document, "Above the page context") {
		t.Error("the panel's heading is missing, so the escaping above is not about a panel that rendered")
	}
}
