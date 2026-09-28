package plugin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// Fakes, written by hand.
//
// A plugin here implements every optional interface at once. That is
// deliberate: a test should say what a plugin *offered*, never which halves of
// the contract it happened to implement, because "the fake only implemented
// PluginUI" is a fact about the fake that no assertion about the lifecycle
// should depend on.

// fakePlugin is a hand-written plugin whose offer the test fills in.
type fakePlugin struct {
	desc Descriptor

	panels    []Panel
	nav       []NavItem
	summaries []SummaryProvider
	coreTypes []PageType
	extenders []any
	routes    []string
	// mounts are (pattern, router) pairs mounted instead of plain routes, so a
	// test can check that a reserved segment cannot be hidden one mount down.
	mounts map[string]http.Handler

	register func(ctx context.Context, h Host) error
	validate func(cfg Config) error

	registered bool
	mounted    []string
	hostSeen   Host
}

func (f *fakePlugin) Descriptor() Descriptor { return f.desc }

func (f *fakePlugin) Now() time.Time { return time.Unix(0, 0).UTC() }

func (f *fakePlugin) Register(ctx context.Context, h Host) error {
	f.registered = true
	f.hostSeen = h
	if f.register != nil {
		return f.register(ctx, h)
	}
	return nil
}

func (f *fakePlugin) Validate(cfg Config) error {
	if f.validate != nil {
		return f.validate(cfg)
	}
	return nil
}

func (f *fakePlugin) CoreTypes() []PageType { return f.coreTypes }

func (f *fakePlugin) MarkdownExtenders() []any { return f.extenders }

func (f *fakePlugin) ConfigSchema() map[string]any { return nil }

func (f *fakePlugin) Panels() []Panel { return f.panels }

func (f *fakePlugin) NavItems() []NavItem { return f.nav }

func (f *fakePlugin) Summaries() []SummaryProvider { return f.summaries }

func (f *fakePlugin) RegisterRoutes(sub RouteMounter) {
	for pattern, h := range f.mounts {
		sub.Mount(pattern, h)
		f.mounted = append(f.mounted, pattern)
	}
	for _, r := range f.routes {
		p := r
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		sub.Get(p, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		f.mounted = append(f.mounted, p)
	}
}

var _ Plugin = (*fakePlugin)(nil)
var _ PluginCore = (*fakePlugin)(nil)
var _ PluginUI = (*fakePlugin)(nil)

// newFake is a plugin that offers nothing, which is the starting point for
// every test that builds its own offer.
func newFake(id string, kind Kind) *fakePlugin {
	return &fakePlugin{desc: Descriptor{
		ID:       id,
		Name:     strings.ToUpper(id[:1]) + id[1:],
		Kind:     kind,
		Version:  "1.0.0",
		APILevel: APILevel,
	}}
}

// clean gives the plugin a full well-formed offer: a non-reserved page type, a
// panel, a nav item inside its own prefix, a search resolver, a summary
// provider, a route, a markdown extender and a migration.
func (f *fakePlugin) clean() *fakePlugin {
	id := f.desc.ID
	f.desc.Capabilities = []Capability{CapUIPanels, CapSidebarNav, CapPageSummaries, CapSearchResolvers}
	f.desc.PageTypes = []PageType{{ID: id + "page", Name: "Page"}}
	f.desc.NavItems = []NavItem{{ID: id + "nav", Label: "Nav", Href: PluginPrefix(id) + "/index"}}
	f.desc.SearchResolvers = []SearchResolver{{ID: id + "resolver"}}
	f.panels = []Panel{{Slot: SlotRightTop, Order: 1, Component: templ.NopComponent}}
	f.summaries = []SummaryProvider{fakeSummary{id: id + "summary"}}
	f.extenders = []any{"extender:" + id}
	f.routes = []string{"/index", "/rules"}
	f.desc.Migrations = []Migration{{Version: 1, Name: "init", SQL: "create table " + id}}
	return f
}

type fakeSummary struct{ id string }

func (s fakeSummary) ID() string { return s.id }

func (s fakeSummary) Summary(context.Context, int64) (templ.Component, bool, error) {
	return templ.NopComponent, true, nil
}

// recorder is the composition root's side of the fake: what the host asked of
// it, and what it was told to fail.
type recorder struct {
	now       time.Time
	migrate   map[string]error
	configs   map[string]Config
	configErr map[string]error
	migrated  []string
	routers   map[string]*chi.Mux
	logs      []string
	fs        fs.FS
}

func newDeps() (PluginDeps, *recorder) {
	rec := &recorder{
		now:       time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		migrate:   map[string]error{},
		configs:   map[string]Config{},
		configErr: map[string]error{},
		routers:   map[string]*chi.Mux{},
		fs:        fstest.MapFS{"public/readme.md": &fstest.MapFile{Data: []byte("public")}},
	}
	deps := PluginDeps{
		Now: func() time.Time { return rec.now },
		Log: func(_ context.Context, _ Level, msg string, kv ...KV) {
			if len(kv) == 0 {
				rec.logs = append(rec.logs, msg)
				return
			}
			parts := make([]string, 0, len(kv))
			for _, k := range kv {
				parts = append(parts, k.Key+"="+fmt.Sprint(k.Value))
			}
			rec.logs = append(rec.logs, msg+" "+strings.Join(parts, " "))
		},
		Config: func(id string) (Config, error) {
			if err := rec.configErr[id]; err != nil {
				return Config{}, err
			}
			return rec.configs[id], nil
		},
		FS: func() fs.FS { return rec.fs },
		Migrations: func(_ context.Context, id string, _ []Migration) error {
			rec.migrated = append(rec.migrated, id)
			return rec.migrate[id]
		},
		SubRouter: func(id string) RouteMounter {
			mux := chi.NewRouter()
			rec.routers[id] = mux
			return mux
		},
	}
	return deps, rec
}

func entryFor(t *testing.T, report Report, id string) Entry {
	t.Helper()
	for _, e := range report.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("the report has no entry for %q: %+v", id, report.Entries)
	return Entry{}
}

func requireStatus(t *testing.T, report Report, id string, want Status) Entry {
	t.Helper()
	e := entryFor(t, report, id)
	if e.Status != want {
		t.Fatalf("plugin %s status = %q (%s), want %q", id, e.Status, e.Reason, want)
	}
	return e
}

func requireSkipped(t *testing.T, report Report, id string) Entry {
	t.Helper()
	e := requireStatus(t, report, id, StatusSkipped)
	if strings.TrimSpace(e.Reason) == "" {
		t.Errorf("plugin %s is skipped with no reason: a skipped line with an empty reason is indistinguishable from a plugin that was never offered", id)
	}
	return e
}

func ownedIDs[T any](in []Owned[T]) []string {
	out := make([]string, 0, len(in))
	for _, o := range in {
		out = append(out, o.Plugin)
	}
	return out
}

func values[T any](in []Owned[T]) []T {
	out := make([]T, 0, len(in))
	for _, o := range in {
		out = append(out, o.Value)
	}
	return out
}

func containsLog(rec *recorder, sub string) bool {
	for _, l := range rec.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func hasWarning(report Report, sub string) bool {
	for _, w := range report.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestAPluginThatRegistersCleanlyIsOK(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem).clean()
	deps, rec := newDeps()
	reg, report := Load(t.Context(), deps, p)

	if len(report.Entries) != 1 {
		t.Fatalf("the report has %d entries, want 1", len(report.Entries))
	}
	e := requireStatus(t, report, "dnd5e", StatusOK)
	if e.Name != "Dnd5e" || e.Kind != KindSystem || e.Version != "1.0.0" {
		t.Errorf("entry = %+v, want the descriptor's own name, kind and version", e)
	}
	if e.APILevel != APILevel || e.HostLevel != APILevel {
		t.Errorf("entry levels = %d/%d, want %d/%d", e.APILevel, e.HostLevel, APILevel, APILevel)
	}
	if !e.Capabilities.Has(CapUIPanels) {
		t.Errorf("granted capabilities = %v, want the declared set", e.Capabilities.List())
	}
	if len(report.Warnings) != 0 {
		t.Errorf("a clean plugin produced warnings: %v", report.Warnings)
	}
	if got, want := e.Count, (Contribution{
		PageTypes: 1, Panels: 1, NavItems: 1, SearchResolvers: 1,
		Summaries: 1, Routes: 2, Extenders: 1, Migrations: 1,
	}); got != want {
		t.Errorf("contribution = %+v, want %+v", got, want)
	}

	if _, ok := reg.PageType("dnd5epage"); !ok {
		t.Error("the registered page type is not in the registry")
	}
	if got := len(reg.Panels()); got != 1 {
		t.Errorf("panels = %d, want 1", got)
	}
	if got := len(reg.NavItems()); got != 1 {
		t.Errorf("nav items = %d, want 1", got)
	}
	if got := len(reg.SearchResolvers()); got != 1 {
		t.Errorf("search resolvers = %d, want 1", got)
	}
	if got := len(reg.Summaries()); got != 1 {
		t.Errorf("summary providers = %d, want 1", got)
	}
	if got := len(reg.Extenders()); got != 1 {
		t.Errorf("markdown extenders = %d, want 1", got)
	}
	routes := reg.Routes()
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want one mounted sub-router however many patterns it carries", len(routes))
	}
	// The report counts patterns; the registry mounts one router.
	if got := RoutePatterns(routes[0].Value); strings.Join(got, ",") != "/index,/rules" {
		t.Errorf("route patterns = %v, want [/index /rules]", got)
	}
	if !p.registered {
		t.Error("Register was never called")
	}
	if len(rec.migrated) != 1 || rec.migrated[0] != "dnd5e" {
		t.Errorf("migrations run = %v, want [dnd5e]", rec.migrated)
	}
}

// TestPluginsAreRegisteredInSortedOrder is the test that would catch a map
// iteration anywhere in the lifecycle: the plugins are offered in an order that
// is not the sorted order, and every collection the registry hands out has to
// come back in the same order on every run.
func TestPluginsAreRegisteredInSortedOrder(t *testing.T) {
	t.Parallel()

	offered := []*fakePlugin{
		newFake("zulu", KindSystem).clean(),
		newFake("mike", KindSystem).clean(),
		newFake("alpha", KindSystem).clean(),
	}
	ps := make([]Plugin, 0, len(offered))
	for _, p := range offered {
		ps = append(ps, p)
	}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, ps...)

	want := []string{"alpha", "mike", "zulu"}
	var ids []string
	for _, e := range report.Entries {
		ids = append(ids, e.ID)
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("report order = %v, want %v", ids, want)
	}
	if got := ownedIDs(reg.PageTypes()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("page type owners = %v, want %v", got, want)
	}
	if got := ownedIDs(reg.Panels()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("panel owners = %v, want %v", got, want)
	}
	if got := ownedIDs(reg.Routes()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("route owners = %v, want %v", got, want)
	}
	// Markdown is order-sensitive, so the composite order is the one an author
	// has to be able to predict.
	var extenders []string
	for _, o := range reg.Extenders() {
		extenders = append(extenders, o.Value.(string))
	}
	if got := strings.Join(extenders, ","); got != "extender:alpha,extender:mike,extender:zulu" {
		t.Errorf("extender order = %s, want the sorted plugin order", got)
	}
}

func TestARefusedAPIVersionIsSkippedWithAReason(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		level  int
		expect string
	}{
		{"newer than the host", APILevel + 1, "requires host API level"},
		{"much newer than the host", APILevel + 7, "requires host API level"},
		{"too old", APILevel - APIWindow - 1, "this host supports"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newFake("skewed", KindSystem).clean()
			p.desc.APILevel = tc.level
			deps, _ := newDeps()
			reg, report := Load(t.Context(), deps, p)

			e := requireSkipped(t, report, "skewed")
			if !strings.Contains(e.Reason, tc.expect) {
				t.Errorf("reason = %q, want it to explain the version window (%q)", e.Reason, tc.expect)
			}
			if e.APILevel != tc.level {
				t.Errorf("the report says the plugin targets level %d, want %d", e.APILevel, tc.level)
			}
			if p.registered {
				t.Error("a refused plugin's Register was called")
			}
			if _, ok := reg.PageType("skewedpage"); ok {
				t.Error("a refused plugin left something in the registry")
			}
			if len(reg.Panels()) != 0 {
				t.Error("a refused plugin left panels in the registry")
			}
		})
	}
}

func TestAnOlderPluginIsRegisteredAsCompat(t *testing.T) {
	t.Parallel()

	p := newFake("old", KindSystem).clean()
	p.desc.APILevel = APILevel - 1
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "old", StatusCompat)
	if _, ok := reg.PageType("oldpage"); !ok {
		t.Error("a plugin inside the version window contributes nothing")
	}
	if got := len(report.OKs()); got != 1 {
		t.Errorf("OKs = %d, want the compat plugin counted as registered", got)
	}
}

func TestAFeaturePluginDeclaringPageTypesIsABootError(t *testing.T) {
	t.Parallel()

	feature := newFake("aardvark", KindFeature)
	feature.clean()
	feature.desc.PageTypes = []PageType{{ID: "houserule", Name: "House rule"}}
	other := newFake("zebra", KindSystem).clean()
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, feature, other)

	e := requireSkipped(t, report, "aardvark")
	if !strings.Contains(e.Reason, "page type") {
		t.Errorf("reason = %q, want it to name the rule that was broken", e.Reason)
	}
	if feature.registered {
		t.Error("the descriptor was checked before Register, so Register should never have been called")
	}
	if _, ok := reg.PageType("houserule"); ok {
		t.Error("a feature plugin's declared page type reached the registry")
	}
	// The point of the test: a boot error for one plugin is a boot error for
	// that plugin alone.
	requireStatus(t, report, "zebra", StatusOK)
	if _, ok := reg.PageType("zebrapage"); !ok {
		t.Error("a second plugin in the same Load did not register")
	}
}

func TestAFeaturePluginCallingRegisterPageTypesIsABootError(t *testing.T) {
	t.Parallel()

	p := newFake("aardvark", KindFeature)
	p.register = func(_ context.Context, h Host) error {
		h.RegisterPageTypes()
		return nil
	}
	deps, _ := newDeps()
	_, report := Load(t.Context(), deps, p)

	if !p.registered {
		t.Fatal("Register was never called, so the call under test never happened")
	}
	e := requireSkipped(t, report, "aardvark")
	if !strings.Contains(e.Reason, "page type") {
		t.Errorf("reason = %q, want it to name the rule that was broken", e.Reason)
	}
}

func TestAReservedPageTypeIsRefusedWithoutTheCapability(t *testing.T) {
	t.Parallel()

	// Both directions, because a check that refuses everything passes the
	// first half of this table and fails the campaign.
	cases := []struct {
		name       string
		kind       Kind
		caps       []Capability
		want       Status
		wantReason string
	}{
		{"a system without the capability", KindSystem, []Capability{CapUIPanels}, StatusSkipped, "character"},
		{"a system with the capability", KindSystem, []Capability{CapCharacterSheet}, StatusOK, ""},
		{"a system with some other capability", KindSystem, []Capability{CapMaps}, StatusSkipped, "character"},
		// A feature is refused a reserved name twice over, and the descriptor
		// rule is reached first, so the reason it reports is the stronger one.
		{"a feature with the capability", KindFeature, []Capability{CapCharacterSheet}, StatusSkipped, "may not declare page types"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newFake("claimer", tc.kind)
			p.desc.Capabilities = tc.caps
			p.desc.PageTypes = []PageType{{ID: "character", Name: "Character"}}
			deps, _ := newDeps()
			reg, report := Load(t.Context(), deps, p)

			requireStatus(t, report, "claimer", tc.want)
			_, ok := reg.PageType("character")
			if ok != (tc.want == StatusOK) {
				t.Errorf("the reserved page type is in the registry = %v, want %v", ok, tc.want == StatusOK)
			}
			if tc.want == StatusSkipped {
				e := entryFor(t, report, "claimer")
				if !strings.Contains(e.Reason, tc.wantReason) {
					t.Errorf("reason = %q, want it to explain the rule (%q)", e.Reason, tc.wantReason)
				}
			}
		})
	}
}

func TestAReservedRouteIsRefusedToAFeaturePluginEvenWithTheCapability(t *testing.T) {
	t.Parallel()

	// The rule is kind *and* capability, so holding the capability is not
	// enough for a feature: a capability says what a plugin may do and a kind
	// says what vocabulary it may speak.
	cases := []struct {
		name string
		kind Kind
		caps []Capability
		want Status
	}{
		{"a feature holding the capability", KindFeature, []Capability{CapMaps}, StatusSkipped},
		{"a system holding the capability", KindSystem, []Capability{CapMaps}, StatusOK},
		{"a system without the capability", KindSystem, []Capability{CapDice}, StatusSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newFake("router", tc.kind)
			p.desc.Capabilities = tc.caps
			p.routes = []string{"/map/{id}"}
			deps, _ := newDeps()
			reg, report := Load(t.Context(), deps, p)

			requireStatus(t, report, "router", tc.want)
			if got := len(reg.Routes()); (got == 1) != (tc.want == StatusOK) {
				t.Errorf("mounted sub-routers = %d, want %v", got, tc.want == StatusOK)
			}
			if tc.want == StatusSkipped {
				e := entryFor(t, report, "router")
				if !strings.Contains(e.Reason, "map") {
					t.Errorf("reason = %q, want it to name the reserved segment", e.Reason)
				}
			}
		})
	}
}

func TestARouteParameterIsNotAReservedSegment(t *testing.T) {
	t.Parallel()

	// Each case gets its own Load: "/{id}" and "/*" are different routes to
	// chi and both of them are the whole path, so putting them in one plugin
	// would be a genuine collision rather than a reserved-name question.
	for _, pattern := range []string{"{id}", "*", "{id}/summary"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			p := newFake("params", KindSystem)
			p.routes = []string{pattern}
			deps, _ := newDeps()
			reg, report := Load(t.Context(), deps, p)

			requireStatus(t, report, "params", StatusOK)
			routes := reg.Routes()
			if len(routes) != 1 {
				t.Fatalf("mounted sub-routers = %d, want 1", len(routes))
			}
			if got := RoutePatterns(routes[0].Value); len(got) != 1 || got[0] != "/"+pattern {
				t.Errorf("route patterns = %v, want one claim on %q", got, "/"+pattern)
			}
		})
	}
}

func TestAReservedRouteCannotBeHiddenBehindAMount(t *testing.T) {
	t.Parallel()

	sub := chi.NewRouter()
	sub.Get("/deep", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	p := newFake("sneaky", KindFeature)
	p.desc.Capabilities = []Capability{CapMaps}
	p.mounts = map[string]http.Handler{"/map": sub}
	deps, _ := newDeps()
	_, report := Load(t.Context(), deps, p)

	// The audit follows mounts, so a plugin cannot dodge the reserved-segment
	// rule by putting the route one Mount deeper.
	requireSkipped(t, report, "sneaky")
}

func TestACollisionDisablesOnlyTheCollidingPlugins(t *testing.T) {
	t.Parallel()

	first := newFake("aaa", KindSystem)
	first.desc.PageTypes = []PageType{{ID: "spell", Name: "Spell"}}
	second := newFake("bbb", KindSystem)
	second.desc.PageTypes = []PageType{{ID: "spell", Name: "Spell"}}
	bystander := newFake("zzz", KindSystem).clean()

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, second, first, bystander)

	requireStatus(t, report, "aaa", StatusOK)
	requireStatus(t, report, "zzz", StatusOK)
	e := requireSkipped(t, report, "bbb")
	if !strings.Contains(e.Reason, "spell") || !strings.Contains(e.Reason, "aaa") {
		t.Errorf("reason = %q, want it to name the page type and the plugin that holds it", e.Reason)
	}

	pt, ok := reg.PageType("spell")
	if !ok {
		t.Fatal("the winning page type is not in the registry")
	}
	if pt.Name != "Spell" {
		t.Errorf("page type = %+v, want the winner's", pt)
	}
	owners := ownedIDs(reg.PageTypes())
	if len(owners) != 2 || owners[0] != "aaa" || owners[1] != "zzz" {
		t.Errorf("page type owners = %v, want [aaa zzz] and nothing from bbb", owners)
	}
	if entryFor(t, report, "bbb").Count.Any() {
		t.Error("a skipped plugin reported a contribution")
	}
}

// TestARolledBackPluginLeavesNothingBehind is the containment test. A plugin
// that registers everything and then collides must leave no trace at all: a
// registry that marks a plugin disabled while keeping its page types is a
// registry that renders a page type no live plugin implements.
func TestARolledBackPluginLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	winner := newFake("alpha", KindSystem)
	winner.desc.PageTypes = []PageType{{ID: "spell", Name: "Spell"}}

	loser := newFake("bravo", KindSystem).clean()
	loser.desc.PageTypes = []PageType{
		{ID: "spell", Name: "Spell"},
		{ID: "monster", Name: "Monster"},
		{ID: "item", Name: "Item"},
	}
	loser.panels = []Panel{
		{Slot: SlotRightTop, Component: templ.NopComponent},
		{Slot: SlotRightMid, Order: 2, Component: templ.NopComponent},
	}
	loser.routes = []string{"/index", "/extra"}

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, loser, winner)

	requireSkipped(t, report, "bravo")
	requireStatus(t, report, "alpha", StatusOK)

	for _, id := range []string{"monster", "item"} {
		if pt, ok := reg.PageType(id); ok {
			t.Errorf("the rolled-back page type %q is still in the registry: %+v", id, pt)
		}
	}
	if got := ownedIDs(reg.PageTypes()); len(got) != 1 || got[0] != "alpha" {
		t.Errorf("page type owners = %v, want only the winner", got)
	}
	if got := ownedIDs(reg.Panels()); len(got) != 0 {
		t.Errorf("panels = %v, want none: a rolled-back plugin contributed panels", got)
	}
	if got := ownedIDs(reg.NavItems()); len(got) != 0 {
		t.Errorf("nav items = %v, want none", got)
	}
	if got := ownedIDs(reg.Routes()); len(got) != 0 {
		t.Errorf("routes = %v, want none", got)
	}
	if got := ownedIDs(reg.Extenders()); len(got) != 0 {
		t.Errorf("extenders = %v, want none", got)
	}
	if got := ownedIDs(reg.Summaries()); len(got) != 0 {
		t.Errorf("summaries = %v, want none", got)
	}
	if got := ownedIDs(reg.SearchResolvers()); len(got) != 0 {
		t.Errorf("search resolvers = %v, want none", got)
	}
	if _, ok := reg.Plugin("bravo"); ok {
		t.Error("the rolled-back plugin is still reachable through the registry")
	}
	if _, ok := reg.Config("bravo"); ok {
		t.Error("the rolled-back plugin still has configuration")
	}
	if e := entryFor(t, report, "bravo"); e.Count.Any() {
		t.Errorf("the report counts a contribution for a rolled-back plugin: %+v", e.Count)
	}
}

func TestAFailedMigrationDisablesThePluginAndNothingElse(t *testing.T) {
	t.Parallel()

	bad := newFake("broken", KindSystem).clean()
	good := newFake("solid", KindSystem).clean()
	deps, rec := newDeps()
	rec.migrate["broken"] = errors.New("duplicate column name")

	reg, report := Load(t.Context(), deps, bad, good)

	e := requireSkipped(t, report, "broken")
	if !strings.Contains(e.Reason, "schema step") {
		t.Errorf("reason = %q, want it to say which step failed", e.Reason)
	}
	if bad.registered {
		t.Error("a plugin whose migration failed was still given a host")
	}
	if _, ok := reg.PageType("brokenpage"); ok {
		t.Error("a plugin with a failed migration reached the registry")
	}
	requireStatus(t, report, "solid", StatusOK)
	if _, ok := reg.PageType("solidpage"); !ok {
		t.Error("the healthy plugin did not register")
	}
	if len(rec.migrated) != 2 {
		t.Errorf("migrations run = %v, want both attempted", rec.migrated)
	}
}

func TestAValidateFailureDisablesThePlugin(t *testing.T) {
	t.Parallel()

	bad := newFake("brittle", KindSystem).clean()
	bad.validate = func(Config) error { return errors.New("fog of war is enabled but no map id is configured") }
	good := newFake("solid", KindSystem).clean()

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, bad, good)

	e := requireSkipped(t, report, "brittle")
	if !strings.Contains(e.Reason, "fog of war") {
		t.Errorf("reason = %q, want the plugin's own explanation", e.Reason)
	}
	if got := ownedIDs(reg.PageTypes()); len(got) != 1 || got[0] != "solid" {
		t.Errorf("page type owners = %v, want the disabled plugin's contributions discarded", got)
	}
	// A bad Validate is a bad plugin, not a bad boot: the report came back and
	// the other plugin is serving.
	if len(report.Entries) != 2 {
		t.Errorf("the report has %d entries, want both plugins", len(report.Entries))
	}
	requireStatus(t, report, "solid", StatusOK)
}

func TestAPluginThatPanicsIsSkippedAndItsPanicValueIsLoggedNotReported(t *testing.T) {
	t.Parallel()

	const token = "TABLE-BODY-TOKEN-4f2a"
	p := newFake("panicky", KindSystem).clean()
	p.register = func(context.Context, Host) error { panic(token) }
	other := newFake("solid", KindSystem).clean()

	deps, rec := newDeps()
	reg, report := Load(t.Context(), deps, p, other)

	e := requireSkipped(t, report, "panicky")
	// The panic value is the plugin's own output and could be a line of vault
	// text, so it goes to the redacting log handler and not into a report that
	// is rendered for people.
	if strings.Contains(e.Reason, token) {
		t.Error("the panic value reached the boot report")
	}
	if !strings.Contains(e.Reason, "panicked") {
		t.Errorf("reason = %q, want it to say the plugin panicked", e.Reason)
	}
	if !containsLog(rec, token) {
		t.Errorf("the panic value is not in the log at all: %v", rec.logs)
	}
	requireStatus(t, report, "solid", StatusOK)
	if _, ok := reg.PageType("solidpage"); !ok {
		t.Error("the plugin after the panicking one did not register")
	}
}

func TestAnUnknownPanelSlotIsDroppedWithAWarning(t *testing.T) {
	t.Parallel()

	p := newFake("panelled", KindSystem)
	p.desc.Capabilities = []Capability{CapUIPanels}
	p.panels = []Panel{
		{Slot: SlotRightTop, Component: templ.NopComponent},
		{Slot: Slot("under-the-hood"), Component: templ.NopComponent},
	}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "panelled", StatusOK)
	panels := reg.Panels()
	if len(panels) != 1 || panels[0].Value.Slot != SlotRightTop {
		t.Fatalf("panels = %+v, want only the slot core renders", panels)
	}
	if !hasWarning(report, "under-the-hood") || !hasWarning(report, "panelled") {
		t.Errorf("warnings = %v, want one naming the plugin and the unknown slot", report.Warnings)
	}
	if got := entryFor(t, report, "panelled").Count.Panels; got != 1 {
		t.Errorf("the report counts %d panels, want the one that survived", got)
	}
}

func TestPanelsAreDiscardedWithoutTheCapability(t *testing.T) {
	t.Parallel()

	p := newFake("panelless", KindSystem)
	p.panels = []Panel{{Slot: SlotRightTop, Component: templ.NopComponent}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "panelless", StatusOK)
	if got := len(reg.Panels()); got != 0 {
		t.Errorf("panels = %d, want none: the whole set goes, not a filtered part", got)
	}
	if !hasWarning(report, string(CapUIPanels)) {
		t.Errorf("warnings = %v, want one naming the missing capability", report.Warnings)
	}
}

func TestSearchResolversAreDiscardedWithoutTheCapability(t *testing.T) {
	t.Parallel()

	p := newFake("resolver", KindSystem)
	p.desc.SearchResolvers = []SearchResolver{{ID: "spells"}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "resolver", StatusOK)
	if got := len(reg.SearchResolvers()); got != 0 {
		t.Errorf("search resolvers = %d, want none: the host must never call a resolver it refused", got)
	}
	if !hasWarning(report, string(CapSearchResolvers)) {
		t.Errorf("warnings = %v, want one naming the missing capability", report.Warnings)
	}
}

func TestANavItemOutsideThePluginsOwnPrefixIsDropped(t *testing.T) {
	t.Parallel()

	p := newFake("navigator", KindSystem)
	p.desc.Capabilities = []Capability{CapSidebarNav}
	p.routes = []string{"/index"}
	p.desc.NavItems = []NavItem{
		{ID: "inside", Label: "Inside", Href: "/plugin/navigator/index"},
		{ID: "elsewhere", Label: "Elsewhere", Href: "/tags"},
		{ID: "relative", Label: "Relative", Href: "index"},
		// The same id twice: a duplicate sidebar entry is dropped rather than
		// refused, because the rest of the sidebar still works.
		{ID: "inside", Label: "Inside again", Href: "/plugin/navigator/index"},
	}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	nav := reg.NavItems()
	if len(nav) != 1 || nav[0].Value.ID != "inside" {
		t.Fatalf("nav items = %+v, want only the one inside the plugin's own prefix", nav)
	}
	if !hasWarning(report, "elsewhere") || !hasWarning(report, "relative") || !hasWarning(report, "duplicate") {
		t.Errorf("warnings = %v, want one per dropped item", report.Warnings)
	}
}

func TestNavItemsAreDiscardedWithoutTheCapability(t *testing.T) {
	t.Parallel()

	p := newFake("navigator", KindSystem)
	p.routes = []string{"/index"}
	p.desc.NavItems = []NavItem{{ID: "index", Label: "Index", Href: "/plugin/navigator/index"}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "navigator", StatusOK)
	if got := len(reg.NavItems()); got != 0 {
		t.Errorf("nav items = %d, want none: the sidebar renders no plugin group at all", got)
	}
	if !report.HasKind(KindSystem) {
		t.Error("HasKind should report the plugin that is present, nav or not")
	}
}

func TestSummariesAreDiscardedWithoutTheCapability(t *testing.T) {
	t.Parallel()

	p := newFake("previews", KindSystem)
	p.summaries = []SummaryProvider{fakeSummary{id: "summary"}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "previews", StatusOK)
	if got := len(reg.Summaries()); got != 0 {
		t.Errorf("summaries = %d, want none: the preview affordance is not rendered without a provider", got)
	}
	if !hasWarning(report, string(CapPageSummaries)) {
		t.Errorf("warnings = %v, want one naming the missing capability", report.Warnings)
	}
}

func TestAnUnknownCapabilityIsAStartupError(t *testing.T) {
	t.Parallel()

	p := newFake("optimist", KindSystem).clean()
	p.desc.Capabilities = []Capability{"telepathy"}
	deps, _ := newDeps()
	_, report := Load(t.Context(), deps, p)

	e := requireSkipped(t, report, "optimist")
	if !strings.Contains(e.Reason, "telepathy") {
		t.Errorf("reason = %q, want it to name the capability that does not exist", e.Reason)
	}
	if p.registered {
		t.Error("a plugin with an unknown capability was given a host")
	}
}

func TestAnInvalidPluginIDIsSkipped(t *testing.T) {
	t.Parallel()

	p := newFake("Dnd 5e", KindSystem).clean()
	deps, _ := newDeps()
	_, report := Load(t.Context(), deps, p)

	requireSkipped(t, report, "Dnd 5e")
}

func TestNoPluginRegisteringNothingIsSilentlyOK(t *testing.T) {
	t.Parallel()

	p := newFake("quiet", KindFeature)
	deps, rec := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "quiet", StatusOK)
	e := entryFor(t, report, "quiet")
	if e.Count != (Contribution{}) {
		t.Errorf("contribution = %+v, want the zero value", e.Count)
	}
	if e.Count.Any() {
		t.Error("Any() is true for a plugin that contributed nothing")
	}
	if !p.registered {
		t.Error("Register was never called")
	}
	if len(rec.migrated) != 0 {
		t.Errorf("migrations run = %v, want none for a plugin that declares none", rec.migrated)
	}
	if len(reg.Routes()) != 0 {
		t.Error("a plugin that registered no route got a sub-router mounted anyway")
	}
}

func TestTheRegistryIsReadOnlyAfterLoad(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem).clean()
	deps, _ := newDeps()
	reg, _ := Load(t.Context(), deps, p)

	first := reg.Report()
	first.Entries[0].ID = "mutated"
	first.Entries[0].Status = StatusSkipped
	first.Entries = append(first.Entries, Entry{ID: "invented"})
	first.Warnings = append(first.Warnings, "invented")

	second := reg.Report()
	if len(second.Entries) != 1 {
		t.Fatalf("the report grew to %d entries: the caller mutated the registry's own slice", len(second.Entries))
	}
	if second.Entries[0].ID != "dnd5e" || second.Entries[0].Status != StatusOK {
		t.Errorf("entry = %+v, want the first call's mutation to have been on a copy", second.Entries[0])
	}
	if len(second.Warnings) != 0 {
		t.Errorf("warnings = %v, want the first call's append to have been on a copy", second.Warnings)
	}
}

func TestTheRegistryCollectionsAreCopies(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem).clean()
	deps, _ := newDeps()
	reg, _ := Load(t.Context(), deps, p)

	panels := reg.Panels()
	slicesSortPanels(panels)
	if again := reg.Panels(); len(again) != 1 {
		t.Fatalf("panels = %d after the caller sorted its own copy, want 1", len(again))
	}
}

func slicesSortPanels(in []Owned[Panel]) {
	for i := range in {
		for j := i + 1; j < len(in); j++ {
			if in[j].Plugin < in[i].Plugin {
				in[i], in[j] = in[j], in[i]
			}
		}
	}
}

func TestTheSubRouterIsTheOneTheHostBuilt(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem)
	p.routes = []string{"/index"}
	deps, rec := newDeps()
	reg, _ := Load(t.Context(), deps, p)

	built, ok := rec.routers["dnd5e"]
	if !ok {
		t.Fatal("the host never asked the composition root for a sub-router")
	}
	routes := reg.Routes()
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(routes))
	}
	if routes[0].Value != built {
		t.Error("the registry mounted a sub-router the host did not build")
	}
}

func TestTheHostHandsOverItsOwnClockFilesystemAndConfig(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem)
	p.desc.Capabilities = []Capability{CapMaps}
	p.desc.PageTypes = []PageType{{ID: "spell", Name: "Spell"}}
	deps, rec := newDeps()
	rec.configs["dnd5e"] = Config{Values: map[string]any{"fog": true}}

	var (
		gotNow    time.Time
		gotKind   Kind
		gotCaps   Capabilities
		gotFS     fs.FS
		gotCfg    Config
		gotPanels []Panel
		gotTypes  []PageType
	)
	p.register = func(_ context.Context, h Host) error {
		gotNow, gotKind, gotCaps = h.Now(), h.Kind(), h.Capability()
		gotFS, gotCfg = h.FS(), h.Config()
		gotPanels, gotTypes = h.RegisterPanels(), h.RegisterPageTypes()
		return nil
	}

	if _, _ = Load(t.Context(), deps, p); false {
		t.Fatal("unreachable")
	}
	if !gotNow.Equal(rec.now) {
		t.Errorf("Now() = %v, want the host clock %v: a plugin must never call time.Now", gotNow, rec.now)
	}
	if gotKind != KindSystem {
		t.Errorf("Kind() = %q, want system", gotKind)
	}
	if !gotCaps.Has(CapMaps) || gotCaps.Has(CapDice) {
		t.Errorf("Capability() = %v, want exactly what the plugin declared", gotCaps.List())
	}
	sameFS := gotFS != nil
	if !sameFS {
		t.Error("FS() returned nil, want the composition root's filesystem")
	} else if _, err := gotFS.Open("public/readme.md"); err != nil {
		t.Errorf("FS().Open: %v, want the composition root's filesystem verbatim", err)
	}
	if gotCfg.ID != "dnd5e" || !gotCfg.Bool("fog", false) {
		t.Errorf("Config() = %+v, want the plugin's own configuration stamped with its id", gotCfg)
	}
	if gotPanels != nil {
		t.Errorf("RegisterPanels() = %+v, want nil: this plugin holds no panel capability", gotPanels)
	}
	// The read-back is the same set the registry will hold, so a plugin can see
	// what the host kept without a second guess.
	if len(gotTypes) != 1 || gotTypes[0].ID != "spell" {
		t.Errorf("RegisterPageTypes() = %+v, want the plugin's own page types", gotTypes)
	}
}

func TestADuplicateIdInsideOnePluginIsRefused(t *testing.T) {
	t.Parallel()

	// A plugin that names the same id twice is the same accident as two
	// plugins naming it once each, and it is caught by the same check.
	sub := chi.NewRouter()
	sub.Get("/deep", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	cases := []struct {
		name  string
		build func(p *fakePlugin)
	}{
		{"a page type registered twice", func(p *fakePlugin) {
			p.desc.PageTypes = []PageType{{ID: "spell"}, {ID: "spell"}}
		}},
		{"a page type with an empty id", func(p *fakePlugin) {
			p.desc.PageTypes = []PageType{{Name: "Nameless"}}
		}},
		{"a search resolver registered twice", func(p *fakePlugin) {
			p.desc.Capabilities = []Capability{CapSearchResolvers}
			p.desc.SearchResolvers = []SearchResolver{{ID: "spells"}, {ID: "spells"}}
		}},
		{"a summary provider registered twice", func(p *fakePlugin) {
			p.desc.Capabilities = []Capability{CapPageSummaries}
			p.summaries = []SummaryProvider{fakeSummary{id: "s"}, fakeSummary{id: "s"}}
		}},
		{"a route reachable two ways", func(p *fakePlugin) {
			p.mounts = map[string]http.Handler{"/x": sub}
			p.routes = []string{"/x/deep"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newFake("dup", KindSystem)
			tc.build(p)
			deps, _ := newDeps()
			reg, report := Load(t.Context(), deps, p)

			requireSkipped(t, report, "dup")
			if len(reg.PageTypes()) != 0 || len(reg.Panels()) != 0 || len(reg.Routes()) != 0 {
				t.Error("a plugin with a duplicate id left something in the registry")
			}
		})
	}
}

func TestTheOptionalCoreInterfaceFillsTheGapsInTheDescriptor(t *testing.T) {
	t.Parallel()

	p := newFake("core", KindSystem)
	p.coreTypes = []PageType{
		{ID: "spell", Name: "From the interface"},
		{ID: "creature", Name: "Also from the interface"},
	}
	// Same id as the interface will supply, different value: the descriptor is
	// the one the version gate ran against, so it wins.
	p.desc.PageTypes = []PageType{{ID: "spell", Name: "From the descriptor"}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "core", StatusOK)
	spell, ok := reg.PageType("spell")
	if !ok || spell.Name != "From the descriptor" {
		t.Errorf("spell = %+v, want the descriptor's value", spell)
	}
	if _, ok := reg.PageType("creature"); !ok {
		t.Error("a page type only the interface contributed was dropped")
	}
}

func TestRoutePatternsOnNothingIsNothing(t *testing.T) {
	t.Parallel()

	if got := RoutePatterns(nil); got != nil {
		t.Errorf("RoutePatterns(nil) = %v, want nil", got)
	}
}

func TestAPluginMayOnlyMountOnTheSubRouterTheHostHandedIt(t *testing.T) {
	t.Parallel()

	p := newFake("escapee", KindSystem)
	p.register = func(_ context.Context, h Host) error {
		h.RegisterRoutes(chi.NewRouter())
		return nil
	}
	deps, _ := newDeps()
	_, report := Load(t.Context(), deps, p)

	e := requireSkipped(t, report, "escapee")
	if !strings.Contains(e.Reason, "prefix") {
		t.Errorf("reason = %q, want it to explain the prefix the router would have escaped", e.Reason)
	}
}

func TestAPluginMayMountOnTheSubRouterTheHostHandedIt(t *testing.T) {
	t.Parallel()

	// The same method, the argument the host actually built: the route is
	// audited and kept, which is the difference between the two branches.
	p := newFake("dnd5e", KindSystem)
	p.register = func(_ context.Context, h Host) error {
		h.RegisterRoutes(nil)
		return nil
	}
	p.routes = []string{"/index"}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "dnd5e", StatusOK)
	if got := len(reg.Routes()); got != 1 {
		t.Errorf("routes = %d, want 1", got)
	}
}

// TestTheHostIsAPluginsOnlyLoggingPath pins the two methods a plugin cannot get
// anywhere else. obs is on the forbidden-import list, so deps.Log is the whole
// story, and it is worth a test that the host hands the message and the
// attributes through without touching them: a host that formatted a value into
// the message would be doing the one thing the redacting handler downstream
// cannot undo.
func TestTheHostIsAPluginsOnlyLoggingPath(t *testing.T) {
	t.Parallel()

	p := newFake("chatty", KindFeature)
	var logged []string
	var seen []any
	p.register = func(_ context.Context, h Host) error {
		h.Log(t.Context(), LevelWarn, "roll of d20 came up short", KV{Key: "roll", Value: 3})
		return nil
	}
	deps, rec := newDeps()
	deps.Log = func(_ context.Context, l Level, msg string, kv ...KV) {
		logged = append(logged, fmt.Sprintf("%s|%s", l, msg))
		for _, k := range kv {
			seen = append(seen, k.Value)
		}
	}

	_, report := Load(t.Context(), deps, p)
	requireStatus(t, report, "chatty", StatusOK)

	if len(logged) != 1 || logged[0] != "warn|roll of d20 came up short" {
		t.Errorf("logged = %v, want the plugin's own message, unmodified, at its own level", logged)
	}
	if len(seen) != 1 || seen[0] != 3 {
		t.Errorf("logged attributes = %v, want the plugin's own value passed through as a value", seen)
	}
	if len(rec.logs) != 0 {
		t.Errorf("the plugin logged through the wrong handler: %v", rec.logs)
	}
}

func TestRegisterMarkdownShowsTheCompositeOrder(t *testing.T) {
	t.Parallel()

	first := newFake("aaa", KindSystem)
	first.extenders = []any{"aaa:one", "aaa:two"}
	second := newFake("bbb", KindSystem)
	second.extenders = []any{"bbb:one"}
	var seen []any
	second.register = func(_ context.Context, h Host) error {
		seen = h.RegisterMarkdown()
		return nil
	}

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, second, first)
	requireStatus(t, report, "bbb", StatusOK)

	// A plugin asking what the host will compose sees the earlier plugins
	// first, in sorted order, then its own.
	if got := fmt.Sprint(seen); got != "[aaa:one aaa:two bbb:one]" {
		t.Errorf("RegisterMarkdown() = %s, want the composite in sorted plugin order", got)
	}
	if got := len(reg.Extenders()); got != 3 {
		t.Errorf("extenders = %d, want every plugin's", got)
	}
}

func TestNavItemsFromTheOptionalInterfaceFillTheGapsInTheDescriptor(t *testing.T) {
	t.Parallel()

	p := newFake("navigator", KindSystem)
	p.desc.Capabilities = []Capability{CapSidebarNav}
	p.routes = []string{"/index"}
	// The same id twice: the descriptor wins, and the duplicate does not become
	// a second sidebar entry.
	p.desc.NavItems = []NavItem{{ID: "shared", Label: "From the descriptor", Href: "/plugin/navigator/index"}}
	p.nav = []NavItem{
		{ID: "shared", Label: "From the interface", Href: "/plugin/navigator/index"},
		{ID: "extra", Label: "Extra", Href: "/plugin/navigator/extra"},
	}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "navigator", StatusOK)
	nav := reg.NavItems()
	if len(nav) != 2 {
		t.Fatalf("nav items = %+v, want the descriptor's item plus the one only the interface contributed", nav)
	}
	for _, n := range nav {
		if n.Value.ID == "shared" && n.Value.Label != "From the descriptor" {
			t.Errorf("the descriptor and the interface both named %q and the interface won: %+v", "shared", n.Value)
		}
	}
}

func TestEveryReservedPageTypeNeedsItsCapability(t *testing.T) {
	t.Parallel()

	// The table as a test: adding a row to reserved.go without a capability to
	// claim it with is caught here, in both directions, rather than by the
	// first plugin that trips over it.
	for _, r := range ReservedPageTypes() {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()

			cases := []struct {
				name string
				kind Kind
				caps []Capability
				want Status
			}{
				{"system without the capability", KindSystem, []Capability{CapUIPanels}, StatusSkipped},
				{"system with the capability", KindSystem, []Capability{r.Capability}, StatusOK},
				{"feature with the capability", KindFeature, []Capability{r.Capability}, StatusSkipped},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					p := newFake("claimer", tc.kind)
					p.desc.Capabilities = tc.caps
					p.desc.PageTypes = []PageType{{ID: r.ID, Name: r.Name}}
					deps, _ := newDeps()
					reg, report := Load(t.Context(), deps, p)

					requireStatus(t, report, "claimer", tc.want)
					if _, ok := reg.PageType(r.ID); ok != (tc.want == StatusOK) {
						t.Errorf("the reserved page type %q is in the registry = %v, want %v", r.ID, ok, tc.want == StatusOK)
					}
				})
			}
		})
	}
}

func TestReservedRouteSegmentsAreAllRefusedToAFeature(t *testing.T) {
	t.Parallel()

	for _, r := range ReservedRoutes() {
		r := r
		t.Run(r.Segment, func(t *testing.T) {
			t.Parallel()

			feature := newFake("taker", KindFeature)
			feature.desc.Capabilities = []Capability{r.Capability}
			feature.routes = []string{"/" + r.Segment}
			deps, _ := newDeps()
			_, report := Load(t.Context(), deps, feature)

			requireSkipped(t, report, "taker")

			system := newFake("holder", KindSystem)
			system.desc.Capabilities = []Capability{r.Capability}
			system.routes = []string{"/" + r.Segment}
			deps2, _ := newDeps()
			reg, report2 := Load(t.Context(), deps2, system)

			requireStatus(t, report2, "holder", StatusOK)
			if len(reg.Routes()) != 1 {
				t.Errorf("the holder's own segment was refused: %+v", report2.Entries)
			}
		})
	}
}

func TestTheReportSkipsAPluginNothingWasOfferedFor(t *testing.T) {
	t.Parallel()

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps)

	if len(report.Entries) != 0 {
		t.Errorf("entries = %+v, want none: a plugin that was never offered is a fact about the build", report.Entries)
	}
	if len(reg.PageTypes()) != 0 {
		t.Error("an empty Load produced page types")
	}
	if report.HasKind(KindSystem) || report.HasKind(KindFeature) {
		t.Error("an empty Load reports a plugin group, so the sidebar would render a heading over nothing")
	}
}

func TestPanelsForPutsThePageTypesOwnPanelsFirst(t *testing.T) {
	t.Parallel()

	global := newFake("aaa-global", KindSystem)
	global.desc.Capabilities = []Capability{CapUIPanels}
	global.panels = []Panel{{Slot: SlotRightTop, Order: 1, Component: templ.NopComponent}}

	scoped := newFake("bbb-scoped", KindSystem)
	scoped.desc.Capabilities = []Capability{CapUIPanels}
	scoped.panels = []Panel{{Slot: SlotRightTop, Order: 2, PageType: "spell", Component: templ.NopComponent}}
	scoped.desc.PageTypes = []PageType{{ID: "spell", Name: "Spell"}}

	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, global, scoped)
	requireStatus(t, report, "bbb-scoped", StatusOK)

	panels := reg.PanelsFor("spell")
	if len(panels) != 2 {
		t.Fatalf("panels for a spell page = %+v, want the page's own and the global one", panels)
	}
	if panels[0].Value.PageType != "spell" {
		t.Errorf("first panel = %+v, want the page type's own panel first", panels[0].Value)
	}
	if got := reg.PanelsFor(""); len(got) != 1 || got[0].Value.PageType != "" {
		t.Errorf("the global panels = %+v, want the one with no page type scope", got)
	}
}

func TestAPanelScopedToAnUnknownPageTypeIsDroppedWithAWarning(t *testing.T) {
	t.Parallel()

	p := newFake("panelled", KindSystem)
	p.desc.Capabilities = []Capability{CapUIPanels}
	p.panels = []Panel{{Slot: SlotRightTop, PageType: "spell", Component: templ.NopComponent}}
	deps, _ := newDeps()
	reg, report := Load(t.Context(), deps, p)

	requireStatus(t, report, "panelled", StatusOK)
	if got := len(reg.Panels()); got != 0 {
		t.Errorf("panels = %+v, want the panel for a page type nobody registers to be dropped", values(reg.Panels()))
	}
	if !hasWarning(report, "spell") {
		t.Errorf("warnings = %v, want one naming the unknown page type", report.Warnings)
	}
}

func TestAMissingConfigDependencyDoesNotStopTheBoot(t *testing.T) {
	t.Parallel()

	p := newFake("dnd5e", KindSystem).clean()
	deps, rec := newDeps()
	rec.configErr["dnd5e"] = errors.New("no such table")

	reg, report := Load(t.Context(), deps, p)

	e := requireSkipped(t, report, "dnd5e")
	if !strings.Contains(e.Reason, "no such table") {
		t.Errorf("reason = %q, want the configuration store's own error", e.Reason)
	}
	if p.registered {
		t.Error("a plugin whose configuration could not be read was given a host")
	}
	if reg == nil {
		t.Error("Load returned no registry: a broken plugin must not stop the boot")
	}
}

func TestHostDependenciesAreOptional(t *testing.T) {
	t.Parallel()

	// A composition root that forgot every dependency gets a boot report and a
	// working registry, not a nil dereference nobody can read a report from.
	p := newFake("dnd5e", KindSystem)
	p.routes = []string{"/index"}
	var (
		now time.Time
		got fs.FS
	)
	p.register = func(_ context.Context, h Host) error {
		now, got = h.Now(), h.FS()
		return nil
	}
	reg, report := Load(t.Context(), PluginDeps{}, p)

	if !now.IsZero() {
		t.Errorf("Now() = %v, want the zero time when the host was built without a clock", now)
	}
	if _, err := got.Open("anything"); err == nil {
		t.Error("FS() should fail every read when the host was built without a filesystem")
	}
	// Without a sub-router a plugin cannot mount, and that costs it its routes
	// and nothing else.
	//
	// It used to be a boot error for the whole plugin, and that was wrong in a
	// way only running it could show: the router is assembled by the caller and
	// handed to Boot as an opaque handler, so a boot that loaded plugins before
	// the router existed disabled every plugin in the build. A missing
	// dependency that costs one capability should cost that capability, exactly
	// as a missing FS costs a filesystem rather than the plugin.
	if len(reg.Routes()) != 0 {
		t.Error("routes were mounted without a sub-router dependency")
	}
	e := entry(t, report, "dnd5e")
	if e.Status == StatusSkipped {
		t.Errorf("a plugin that wanted routes and could not mount was refused outright: %s. "+
			"Its page types, panels and navigation do not need a URL, and refusing it discards all of them.",
			e.Reason)
	}
	// And it is still *visible*, which is the other half: a plugin that silently
	// loses a capability is a capability nobody is maintaining.
	if !warningsMention(report, "sub-router") {
		t.Errorf("the boot report does not mention the missing sub-router: %v", report.Warnings)
	}
}

// entry returns a plugin's report line, registered or not.
func entry(t *testing.T, r Report, id string) Entry {
	t.Helper()
	for _, e := range r.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("the report has no entry for %q: %+v", id, r.Entries)
	return Entry{}
}

// warningsMention reports whether any boot warning names a word.
//
// It is a substring test because a warning is a sentence written for a person
// and a test that pinned the whole sentence would break every time somebody
// improved the punctuation.
func warningsMention(r Report, word string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, word) {
			return true
		}
	}
	return false
}
