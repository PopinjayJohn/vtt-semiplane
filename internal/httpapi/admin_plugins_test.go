package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The report's two words that mean "this build is not doing what you expected".
//
// They are asserted by their presence rather than by their absence of the
// alternative, because the failure this page exists to prevent is a report that
// looks fine. An empty table under a heading is the shape of that failure.
const (
	// emptyReportPhrase is what the page says when no plugin is registered.
	emptyReportPhrase = "No plugins are registered with this build"
	// noRegistryPhrase is the warning a server with no registry at all carries.
	noRegistryPhrase = "booted without a plugin registry"
)

// reportRegistry is a plugin.Registry holding one hand-built report.
//
// It is a double rather than a real registry because the boot report is a
// property of the lifecycle, and a test of the page should not have to run one
// to get a report to read. That is what the Registry interface is for: the
// lifecycle can change completely without this file changing at all.
//
// Every method but Report answers "nothing was registered", which is the honest
// answer for a registry that was never loaded. The one thing this file asserts
// about the report is the report; it asserts nothing about the rest of the
// interface, which no route on this page reads.
type reportRegistry struct {
	report plugin.Report
}

func (r reportRegistry) Report() plugin.Report { return r.report }

func (r reportRegistry) PageType(string) (plugin.PageType, bool) { return plugin.PageType{}, false }

func (r reportRegistry) PageTypes() []plugin.Owned[plugin.PageType] { return nil }

func (r reportRegistry) Panels() []plugin.Owned[plugin.Panel] { return nil }

func (r reportRegistry) PanelsFor(string) []plugin.Owned[plugin.Panel] { return nil }

func (r reportRegistry) NavItems() []plugin.Owned[plugin.NavItem] { return nil }

func (r reportRegistry) SearchResolvers() []plugin.Owned[plugin.SearchResolver] {
	return nil
}

func (r reportRegistry) Summaries() []plugin.Owned[plugin.SummaryProvider] { return nil }

func (r reportRegistry) Routes() []plugin.Owned[plugin.RouteMounter] { return nil }

func (r reportRegistry) Extenders() []plugin.Owned[any] { return nil }

func (r reportRegistry) Plugin(string) (plugin.Plugin, bool) { return nil, false }

func (r reportRegistry) Config(string) (plugin.Config, bool) { return plugin.Config{}, false }

// withPlugins repoints a fixture at a second server carrying a plugin registry.
//
// The harness builds its own server from a fixed set of options, so a test that
// needs a registry cannot add one without editing harness_test.go — which every
// other test in this package shares — or standing up its own fixture here. This
// is the smaller of the two: the new server is over the same database, writer,
// indexer, policy and accounts as the one the fixture already booted, so a
// session signed in through it is a session of the same campaign, and the
// harness's session helpers work against it unchanged because they read fx.HTTP
// at call time. It has to be called before asUser for that to hold.
func withPlugins(t *testing.T, fx *fixture, reg plugin.Registry) *fixture {
	t.Helper()
	srv, err := httpapi.New(httpapi.Options{
		Config:        fx.cfg,
		DB:            fx.DB,
		Writer:        fx.Vault,
		Reindexer:     fx.Indexer,
		AuthorRetryer: fx.Indexer,
		Log:           fx.Log,
		Clock:         fx.Clock.obs(),
		Build:         app.Info(),
		Assets:        web.Assets(),
		Renderer:      web.NewRenderer(),
		Plugins:       reg,
	})
	if err != nil {
		t.Fatalf("build the server with a plugin registry: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	fx.Server = srv
	fx.HTTP = ts
	return fx
}

// adminSession is a fixture signed in as its administrator, with a registry.
func adminSession(t *testing.T, reg plugin.Registry) (*fixture, *session) {
	t.Helper()
	fx := newFixture(t)
	fx.accounts()
	fx = withPlugins(t, fx, reg)
	return fx, fx.asUser(adminName, adminPass)
}

// TestAdminPluginsIsAdminOnly is the authorization decision, asserted as
// behaviour rather than as a table.
//
// The route is PermAdmin and the Perm middleware is the only place a role is
// compared, so what this test is really checking is that the page carries no
// information at all to anybody the middleware refuses — a report that a
// non-admin cannot reach must not leak through the error page, the shell, or a
// count that survives in a title.
func TestAdminPluginsIsAdminOnly(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	admin := fx.asUser(adminName, adminPass)

	document := admin.getOK("/admin/plugins")
	if !strings.Contains(document, emptyReportPhrase) {
		t.Errorf("the administrator does not get the report:\n%.400s", document)
	}

	for _, tc := range []struct {
		name   string
		user   string
		pass   string
		status int
	}{
		// The three non-admin roles, one row each. A DM is the interesting one:
		// it is trusted with every secret in the campaign, and this page is
		// still not for it, because it describes what the host will do for whom.
		{"a player", playerName, playerPass, http.StatusForbidden},
		{"a second player", otherName, otherPass, http.StatusForbidden},
		{"the dungeon master", dmName, dmPass, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fx.asUser(tc.user, tc.pass)
			body := s.text(s.get("/admin/plugins"))
			if s.status(s.get("/admin/plugins")) != tc.status {
				t.Fatalf("GET /admin/plugins as %s: want %d", tc.name, tc.status)
			}
			if strings.Contains(body, emptyReportPhrase) {
				t.Errorf("the report reached %s:\n%.400s", tc.name, body)
			}
		})
	}

	// An unauthenticated client is offered the login form rather than a refusal,
	// because the request is a safe one and the router knows it can offer a way
	// to fix it. It is still not the report.
	t.Run("an unauthenticated client", func(t *testing.T) {
		s := fx.newSession()
		if got := s.status(s.get("/admin/plugins")); got != http.StatusSeeOther {
			t.Errorf("GET /admin/plugins unauthenticated: status %d, want 303", got)
		}
		body := s.text(s.get("/admin/plugins"))
		if strings.Contains(body, emptyReportPhrase) {
			t.Errorf("the report reached an unauthenticated client:\n%.400s", body)
		}
	})
}

// TestTheBootReportListsEveryRegisteredPluginIncludingSkippedOnes is the test
// this surface exists for.
//
// A report that lists only the healthy plugins is a report that hides the
// problem, and it is the obvious way to write this handler: filter to the rows
// that registered, and the page looks tidier. The skipped row is here with a
// reason, and the assertion is that the reason is on the page.
func TestTheBootReportListsEveryRegisteredPluginIncludingSkippedOnes(t *testing.T) {
	t.Parallel()
	_, admin := adminSession(t, reportRegistry{report: plugin.Report{Entries: []plugin.Entry{
		{
			ID: "dnd5e", Name: "Fifth Edition", Kind: plugin.KindSystem, Version: "0.4.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.All(),
			Count:        plugin.Contribution{PageTypes: 3, Panels: 2, NavItems: 1},
		},
		{
			ID: "linkpreview", Name: "Link preview", Kind: plugin.KindFeature, Version: "0.1.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.Capabilities(0).With(plugin.CapPageSummaries),
			Count:        plugin.Contribution{Summaries: 1},
		},
		{
			// A plugin on the compat shim is registered and not broken, which is
			// why it is its own status and not a flavour of ok.
			ID: "houserules", Name: "House rules", Kind: plugin.KindFeature, Version: "0.1.0",
			Status: plugin.StatusCompat, APILevel: 0, HostLevel: 1,
			Capabilities: plugin.Capabilities(0).With(plugin.CapUIPanels),
			Count:        plugin.Contribution{Panels: 1},
		},
		{
			ID: "maptool", Name: "Map tool", Kind: plugin.KindSystem, Version: "0.2.0",
			Status:   plugin.StatusSkipped,
			Reason:   "it claimed the reserved page type map without holding the maps capability",
			APILevel: 1, HostLevel: 1,
		},
	}}})

	document := admin.getOK("/admin/plugins")
	for _, want := range []string{
		"dnd5e", "Fifth Edition",
		"linkpreview", "Link preview",
		"houserules", "House rules",
		"maptool", "Map tool",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("the report omits %q", want)
		}
	}
	// The reason is the content of the row, and this is the whole assertion.
	if !strings.Contains(document, "it claimed the reserved page type map without holding the maps capability") {
		t.Errorf("the skipped row's reason is not on the page:\n%.2000s", document)
	}
	// The three counters partition the report, so a fourth row cannot hide
	// between two of them. 2 registered, 1 on the shim, 1 skipped.
	for _, want := range []string{"2 registered", "1 on the compat shim", "1 skipped"} {
		if !strings.Contains(document, want) {
			t.Errorf("the summary does not say %q", want)
		}
	}
	// The statuses are words, not colours. A reader who cannot see the badge's
	// colour has to be able to read what happened.
	if !strings.Contains(document, ">skipped<") || !strings.Contains(document, ">compat<") {
		t.Errorf("a status is carried by colour alone:\n%.2000s", document)
	}
}

// TestASkippedRowShowsItsWholeReason is the anti-truncation test.
//
// A reason is the one piece of text on this page that exists to be read, so
// shortening it is the failure that costs the most: a half-sentence is a
// sentence that names a problem and not its cause. The reason here is long
// enough that a truncation would have to be deliberate to be this short, and the
// assertion is the whole string, not a prefix of it.
func TestASkippedRowShowsItsWholeReason(t *testing.T) {
	t.Parallel()
	reason := "the host refused it: page type character is reserved for the character_sheet " +
		"capability, and this plugin declares ui_panels and sidebar_nav but not character_sheet, " +
		"so the claim was rolled back along with the two tables its migration had already created"
	_, admin := adminSession(t, reportRegistry{report: plugin.Report{Entries: []plugin.Entry{{
		ID: "forgesmith", Name: "Forgesmith", Kind: plugin.KindSystem, Version: "0.9.0",
		Status: plugin.StatusSkipped, Reason: reason, APILevel: 1, HostLevel: 1,
	}}}})

	document := admin.getOK("/admin/plugins")
	if !strings.Contains(document, reason) {
		t.Errorf("the reason was shortened or escaped into meaninglessness:\n%.2000s", document)
	}
	// And the last clause specifically: a prefix-only truncation is the shape
	// that passes the assertion above if the reason is compared loosely.
	if !strings.Contains(document, "rolled back along with the two tables") {
		t.Error("the end of the reason is missing, so the reason was cut")
	}
}

// TestAContributionOfNothingIsDistinguishableFromAPluginThatIsNotOffered is the
// "no contributions" rule.
//
// A plugin that registered and added nothing and a plugin this binary does not
// offer are different facts, and the second one is not in the report at all. If
// the first rendered as an empty cell, the page would show a list of names and
// the reader could not tell which of them did anything — which is the question
// the page is being opened to answer.
func TestAContributionOfNothingIsDistinguishableFromAPluginThatIsNotOffered(t *testing.T) {
	t.Parallel()
	_, admin := adminSession(t, reportRegistry{report: plugin.Report{Entries: []plugin.Entry{
		{
			ID: "dnd5e", Name: "Fifth Edition", Kind: plugin.KindSystem, Version: "0.4.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.All(),
		},
		{
			// Registered cleanly, contributed nothing.
			ID: "quietmode", Name: "Quiet mode", Kind: plugin.KindFeature, Version: "0.1.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.Capabilities(0),
		},
	}}})

	document := admin.getOK("/admin/plugins")
	if !strings.Contains(document, "quietmode") {
		t.Fatal("the plugin that contributed nothing is not on the page, so the assertion below is vacuous")
	}
	if !strings.Contains(document, "no contributions") {
		t.Errorf("a plugin that contributed nothing does not say so:\n%.2000s", document)
	}
	// The same reason applies to a granted set of nothing.
	if !strings.Contains(document, "none granted") {
		t.Errorf("a plugin granted nothing does not say so:\n%.2000s", document)
	}
	// A plugin that was never offered is not a row. It has no name, no id and
	// no row, and "quietmode" is not what it would be called. The scan is over the
	// page's own content: the sidebar is a navigation over the vault, so a
	// campaign that keeps its rules in a directory called houserules/ would
	// otherwise be reported as a plugin that was never offered. See
	// contentRegion.
	if strings.Contains(contentRegion(t, document), "houserules") {
		t.Errorf("a plugin that was never offered appears on the report:\n%.2000s", document)
	}
}

// TestTheCountsAreOnlyTheNonZeroOnes pins the summary cell.
//
// Two halves, and both matter. Only the non-zero counts are listed, because a
// row that contributed three page types and two panels does not become
// informative by also saying it contributed no routes. And the parts come out
// in a fixed order, because a cell whose order is whatever a map walk produced
// is a cell a reader cannot scan and a test cannot assert.
func TestTheCountsAreOnlyTheNonZeroOnes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		count       plugin.Contribution
		wantPresent string
		wantAbsent  []string
	}{
		{
			name:        "every kind but three",
			count:       plugin.Contribution{PageTypes: 2, Panels: 1, NavItems: 3, Migrations: 4},
			wantPresent: "2 page types, 1 panel, 3 nav items, 4 migrations",
			wantAbsent:  []string{"search resolver", "summary", "extender", "0 page types", "0 panels"},
		},
		{
			name:        "one of everything",
			count:       plugin.Contribution{PageTypes: 1, Panels: 1, NavItems: 1, SearchResolvers: 1, Summaries: 1, Routes: 1, Extenders: 1, Migrations: 1},
			wantPresent: "1 page type, 1 panel, 1 nav item, 1 search resolver, 1 summary, 1 route, 1 extender, 1 migration",
		},
		{
			name:        "a single contribution",
			count:       plugin.Contribution{Panels: 1},
			wantPresent: "1 panel",
			wantAbsent:  []string{"1 page type", "nav item"},
		},
		{
			name:        "nothing at all",
			count:       plugin.Contribution{},
			wantPresent: "no contributions",
			wantAbsent:  []string{"0 page types", "0 panels"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, admin := adminSession(t, reportRegistry{report: plugin.Report{Entries: []plugin.Entry{{
				ID: "counts", Name: "Counts", Kind: plugin.KindFeature, Version: "1.0.0",
				Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
				Count: tc.count,
			}}}})
			document := admin.getOK("/admin/plugins")
			if !strings.Contains(document, tc.wantPresent) {
				t.Errorf("the summary cell does not read %q:\n%.2000s", tc.wantPresent, document)
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(document, absent) {
					t.Errorf("the summary cell mentions %q, which this contribution does not have", absent)
				}
			}
		})
	}
}

// TestANilRegistryRendersAnExplicitEmptyState is the nil-safety rule, as a test
// rather than as a comment.
//
// s.plugins is nil on any server whose composition root did not hand one over,
// which today means this test's own fixture and cmd/semiplane. Calling Report on
// it is a nil-pointer panic, and a panic in a request path is a process down;
// answering 500 would be a page claiming the server broke, over a boot that was
// never attempted. The report is empty and says which of the two it is.
func TestANilRegistryRendersAnExplicitEmptyState(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	admin := fx.asUser(adminName, adminPass)

	document := admin.getOK("/admin/plugins")
	if !strings.Contains(document, emptyReportPhrase) {
		t.Errorf("a server with no registry does not say the report is empty:\n%.400s", document)
	}
	// The empty state is named, not implied: a heading with nothing under it is
	// a broken control, and this one exists so that a missing thing looks like a
	// missing thing.
	if strings.Contains(document, emptyReportPhrase+"</h1>") {
		t.Error("the empty report is a heading and nothing else")
	}
	// A nil registry and a registry holding nothing are different facts, and the
	// page tells them apart: the first says the lifecycle never ran.
	if !strings.Contains(document, noRegistryPhrase) {
		t.Errorf("a server with no registry does not say the plugin lifecycle never ran:\n%.2000s", document)
	}
	// And a registry holding nothing must not claim the same thing. This is the
	// other half of the distinction, and it is the half that would rot first,
	// because it is the one that reads like a bug report.
	_, emptyAdmin := adminSession(t, reportRegistry{})
	emptyDocument := emptyAdmin.getOK("/admin/plugins")
	if !strings.Contains(emptyDocument, emptyReportPhrase) {
		t.Errorf("a registry with no plugins does not render the empty state:\n%.400s", emptyDocument)
	}
	if strings.Contains(emptyDocument, noRegistryPhrase) {
		t.Errorf("a registry that ran and admitted nothing claims it never ran:\n%.2000s", emptyDocument)
	}
}

// TestTheBootReportWarningsAreShownWhenEveryPluginIsHealthy is the reason the
// warnings section is unconditional.
//
// A panel dropped for naming an unknown slot belongs to a plugin that otherwise
// registered perfectly, so a warnings list that only appeared alongside a
// skipped plugin would be silent in exactly the case it was written for. The
// fixture here has one healthy plugin and one warning, and the warning has to be
// on the page.
func TestTheBootReportWarningsAreShownWhenEveryPluginIsHealthy(t *testing.T) {
	t.Parallel()
	warning := "dnd5e contributed a panel for the slot right-far-side, which core does not render, so the panel was dropped"
	_, admin := adminSession(t, reportRegistry{report: plugin.Report{
		Entries: []plugin.Entry{{
			ID: "dnd5e", Name: "Fifth Edition", Kind: plugin.KindSystem, Version: "0.4.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.All(), Count: plugin.Contribution{Panels: 3},
		}},
		Warnings: []string{warning},
	}})

	document := admin.getOK("/admin/plugins")
	if !strings.Contains(document, "0 skipped") {
		t.Errorf("the fixture is not a healthy report, so the assertion below is vacuous:\n%.2000s", document)
	}
	if !strings.Contains(document, warning) {
		t.Errorf("a healthy report hides a boot warning:\n%.2000s", document)
	}
}

// TestTheFragmentIsAStrictSubsetOfTheDocument is the content negotiation
// contract, for this view model.
//
// The bytes a fragment writes are what a morph writes into a page a document
// produced, so the two cannot differ by even a row. A difference is not a
// cosmetic one: a fragment that rendered a different amount of the report than
// a document would be a second rendering of the boot report, and a second
// rendering is a second place for the report to be wrong.
func TestTheFragmentIsAStrictSubsetOfTheDocument(t *testing.T) {
	t.Parallel()
	_, admin := adminSession(t, reportRegistry{report: plugin.Report{
		Entries: []plugin.Entry{{
			ID: "dnd5e", Name: "Fifth Edition", Kind: plugin.KindSystem, Version: "0.4.0",
			Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
			Capabilities: plugin.All(), Count: plugin.Contribution{PageTypes: 3, Panels: 2},
		}},
		Warnings: []string{"one panel was dropped for an unknown slot"},
	}})

	document := admin.getOK("/admin/plugins")
	fragment := admin.text(admin.fragment("/admin/plugins"))
	if fragment == "" {
		t.Fatal("the fragment is empty, so the assertion below is vacuous")
	}
	if !strings.Contains(document, fragment) {
		t.Errorf("the fragment is not a substring of the document:\nfragment:\n%.600s", fragment)
	}
	if len(fragment) >= len(document) {
		t.Errorf("the fragment is %d bytes and the document is %d; the fragment carries no shell to be a subset of",
			len(fragment), len(document))
	}
}

// dataReportPluginRe finds the plugin id a report row carries, which is the
// report's own machine-readable name for it.
//
// The attribute is `data-report-plugin` and not `data-plugin` because the shell
// owns the shorter name for its own plugin chrome, and a page that used it for
// something else would make that test's "no plugin markup here" assertion
// impossible to satisfy honestly.
var dataReportPluginRe = regexp.MustCompile(`data-report-plugin="([^"]*)"`)

// TestNoPluginIdLeaksIntoThePageOutsideTheReport is the reverse check, and it
// is a reverse check because this page is the one surface where a plugin id is
// the content rather than a leak.
//
// Everywhere else in the app, a plugin id appearing in a response would be a
// bug: it is a name the reader is not supposed to learn, and a page-type id or a
// capability name in the markup is a description of what this binary can do for
// whom. Here the ids are the page. So the claim to check is the other one: every
// id on the page came out of the report, and nothing else about the host's
// configuration is on the page beside them.
//
// The three things checked are the ones that would be easiest to add by
// accident. A plugin id that is not in the report. A capability the host holds
// and did not grant to anybody — the granted set is a subset of what the host
// could grant, and rendering the superset would describe a host that is not this
// one. And the vault's own path, which is not this page's business.
func TestNoPluginIdLeaksIntoThePageOutsideTheReport(t *testing.T) {
	t.Parallel()
	fx, admin := adminSession(t, reportRegistry{report: plugin.Report{Entries: []plugin.Entry{{
		ID: "dnd5e", Name: "Fifth Edition", Kind: plugin.KindSystem, Version: "0.4.0",
		Status: plugin.StatusOK, APILevel: 1, HostLevel: 1,
		// Granted two of the eleven. The other nine are the host's own
		// capability, and none of them belongs on this page.
		Capabilities: plugin.Capabilities(0).With(plugin.CapCharacterSheet).With(plugin.CapUIPanels),
		Count:        plugin.Contribution{PageTypes: 1},
	}}}})

	document := admin.getOK("/admin/plugins")

	// Every id the page attributes to a row is in the report, and every id in
	// the report is on the page. Compared as sets rather than by counting, so
	// that a row printed twice and a row printed zero times cannot both pass.
	onPage := map[string]bool{}
	for _, m := range dataReportPluginRe.FindAllStringSubmatch(document, -1) {
		onPage[m[1]] = true
	}
	if len(onPage) == 0 {
		t.Fatalf("the page attributes no rows to plugins, so this test is looking at nothing:\n%.2000s", document)
	}
	if !onPage["dnd5e"] {
		t.Errorf("the one plugin in the report has no row:\n%.2000s", document)
	}
	for id := range onPage {
		if id != "dnd5e" {
			t.Errorf("the page carries a row for %q, which no report entry has", id)
		}
	}

	// Both scans below are over the page's own content and not over the whole
	// document, and that boundary is the correction rather than a convenience.
	// The left sidebar is a navigation over the vault: it links every page this
	// principal may read, by path. A campaign is free to keep its rules in
	// houserules/ and its maps in maps/, and this fixture's does, so a
	// whole-document substring test for a plugin id was measuring the shape of
	// somebody's vault rather than the shape of the report. The claim is "the
	// report does not describe a plugin that was not offered", and the report is
	// inside #page-region.
	//
	// The same reasoning is why the vault's path check below still reads the
	// document: the shell's own campaign name is a directory name and is on every
	// page by design, and its *path* is not.
	page := contentRegion(t, document)

	// A plugin that was never offered is nowhere on the page. These are the ids
	// the tree is most likely to grow, which is why they are the ones named.
	for _, id := range []string{"houserules", "linkpreview", "forgesmith", "maptool", "core"} {
		if strings.Contains(page, id) {
			t.Errorf("the page mentions %q, which is not in the report", id)
		}
	}

	// A capability the host holds and granted to nobody is not on the page
	// either. The granted set is a subset, and the superset describes a different
	// binary.
	for _, granted := range []plugin.Capability{
		plugin.CapMaps, plugin.CapDice, plugin.CapExporters, plugin.CapSearchResolvers,
	} {
		if !plugin.All().Has(granted) {
			t.Fatalf("the fixture's assumption about %q is wrong, so the assertion below is vacuous", granted)
		}
		if strings.Contains(page, string(granted)) {
			t.Errorf("the page names the capability %q, which the report granted to nobody", granted)
		}
	}

	// The vault's own path. The campaign's *name* is in the shell by design; the
	// directory it lives in is not this page's business.
	if strings.Contains(document, fx.Root) {
		t.Errorf("the page carries the vault's path:\n%.400s", fx.Root)
	}
}
