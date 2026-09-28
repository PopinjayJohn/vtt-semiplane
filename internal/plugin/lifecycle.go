package plugin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// The registration lifecycle: §2.4 of the plan, in that order, with the
// containment rule made structural rather than aspirational.
//
// The one decision everything else follows from: **a plugin's contributions are
// staged, validated, and only then committed.** Nothing a plugin says reaches
// the live registry until the host has decided to keep it, so "roll that plugin
// back" is "drop the staging area" and cannot be incomplete. The alternative —
// register, then remove what went wrong — is a compensating action with one
// path per contribution kind, and a registry that marks a plugin disabled while
// keeping its page types renders a page type no live plugin implements.
//
// The second decision: **boot never fails because of a plugin.** Every refusal
// is a line in the report with a reason, including a panic inside a plugin's
// own Register, and the next plugin registers.

// Load runs the registration lifecycle over the offered plugins and returns the
// registry and the boot report.
//
// The offered plugins are sorted by id before anything else happens. That is
// the whole reason the step exists: a lifecycle that iterates a map produces a
// different winner for every collision on every boot, and a failure that
// reproduces once in ten is a failure nobody can fix.
//
// **What the host grants.** A plugin is granted exactly what it declared. The
// host's own policy for a first-party in-tree plugin is All(), so the grant is
// the declaration narrowed by nothing, and the gates that actually decide are
// CheckReservedPageType and CheckReservedRoute, which ask for the kind *and*
// the grant. Two arguments settled it: a capability the host silently withheld
// is a plugin that half-works and a report that says ok, and a capability the
// host granted that the plugin never declared would make holding it and
// declaring it two different things — which is how a permission system grows a
// second answer. A plugin that misspells a capability is a startup error
// rather than a silent omission, so a typo cannot become a claim it believes it
// holds. A future subprocess host narrows this in one place: the bitmask here.
func Load(ctx context.Context, deps PluginDeps, plugins ...Plugin) (Registry, Report) {
	ordered := make([]Plugin, len(plugins))
	copy(ordered, plugins)
	// Stable, so two plugins claiming the same id resolve the same way too:
	// the one offered first wins, and "offered first" is the one thing the
	// caller controls.
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Descriptor().ID < ordered[j].Descriptor().ID
	})

	reg := &registry{
		plugins:   map[string]Plugin{},
		configs:   map[string]Config{},
		typeIndex: map[string]int{},
	}
	claimed := newClaims()

	var (
		all      []*admission
		live     []*admission
		warn     warnings
		priorExt []any
	)

	for _, p := range ordered {
		a := &admission{plugin: p, desc: p.Descriptor()}
		all = append(all, a)

		if err := admit(a.desc); err != nil {
			a.refuse(err)
			continue
		}
		grants, err := ParseCapabilities(a.desc.Capabilities)
		if err != nil {
			// An unknown capability name is a startup error rather than a
			// silent omission: a plugin that misspells a capability believes
			// it holds something it does not, and every check it then fails is
			// a check it cannot explain.
			a.refuse(err)
			continue
		}
		a.grants = grants

		cfg, err := loadConfig(deps, a.desc.ID)
		if err != nil {
			a.refuse(err)
			continue
		}
		a.cfg = cfg

		if err := registerPlugin(ctx, deps, a, priorExt); err != nil {
			a.refuse(err)
			continue
		}
		if err := claimed.claim(a); err != nil {
			a.refuse(err)
			continue
		}
		live = append(live, a)
		priorExt = append(priorExt, a.host.extend...)
	}

	for _, a := range live {
		reg.commit(a)
		warn = append(warn, a.warn...)
	}
	reg.dropPanelsForUnknownPageTypes(&warn)
	reg.order()
	reg.report = buildReport(all, live, reg, warn)
	return reg, reg.Report()
}

// admit is §2.4's version gate followed by the descriptor checks that can be
// made before a plugin is handed anything. Each is a boot error for that plugin
// alone, and each is raised before Register is called, so a plugin that would
// misbehave never runs.
//
// The version gate comes first because it is the gate the plan puts first, and
// because a plugin written against a host that does not exist is refused for
// that reason whatever else is wrong with it.
func admit(d Descriptor) error {
	if ok, reason := Admit(APILevel, d.APILevel); !ok {
		return errors.New(reason)
	}
	if err := d.ValidateID(); err != nil {
		return err
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("plugin %s declares the unknown kind %q, so the host cannot decide which rules apply to it", d.ID, d.Kind)
	}
	if d.Kind == KindFeature && len(d.PageTypes) > 0 {
		return fmt.Errorf("a %s plugin may not declare page types: a page type is a game system's vocabulary, and a feature expresses content through frontmatter conventions", KindFeature)
	}
	return nil
}

// loadConfig reads one plugin's configuration, stamping the id so a
// composition root that returned a config for the wrong plugin cannot hand a
// plugin its neighbour's settings under its own name.
func loadConfig(deps PluginDeps, id string) (Config, error) {
	if deps.Config == nil {
		return Config{ID: id}, nil
	}
	cfg, err := deps.Config(id)
	if err != nil {
		return Config{}, fmt.Errorf("reading configuration: %w", err)
	}
	cfg.ID = id
	return cfg, nil
}

// registerPlugin is one plugin's whole per-plugin transaction, and it is the
// containment boundary: a migration that fails, a Register that returns an
// error, a claim the host refuses on kind or grant, a Validate that fails, and
// a panic inside the plugin's own code all leave the same way — this plugin
// does not register and the next one is tried.
//
// The id-collision check that follows it in Load is part of the same
// transaction, but it is one step later because it is the only check that has
// to see what the earlier plugins kept.
//
// Validate runs here rather than in the plan's later step because the plan's
// ordering puts it after the contribution registries are built, and building
// them is exactly what this function refuses to do before it is sure. A
// Validate failure therefore discards a staging area rather than removing
// things from a live registry, which is the only version of the rollback that
// cannot be incomplete.
func registerPlugin(ctx context.Context, deps PluginDeps, a *admission, priorExt []any) (err error) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		// The panic value is the plugin's own output and could be a line of
		// vault text, so it goes to the redacting log handler and not into the
		// report: the report is rendered and read by people. The type alone
		// is enough to tell a nil dereference from a bad assertion in the
		// report, and the value is one log line away.
		if deps.Log != nil {
			deps.Log(ctx, LevelError, "plugin panicked while registering",
				KV{Key: "plugin", Value: a.desc.ID},
				KV{Key: "panic", Value: fmt.Sprint(v)})
		}
		err = fmt.Errorf("plugin %s: panicked while registering: %T", a.desc.ID, v)
	}()

	// The host is built inside the recovery scope because it asks the plugin
	// for its markdown extenders, and a plugin's own code is the thing the
	// boundary is for.
	a.host = newHost(deps, a.desc, a.plugin, a.grants, a.cfg, &a.warn, priorExt)

	if n := len(a.desc.Migrations); n > 0 {
		if deps.Migrations == nil {
			return fmt.Errorf("plugin %s: the host was built without a migration runner, so its %d schema step(s) cannot be applied", a.desc.ID, n)
		}
		// The migration transaction is the runner's to roll back, per
		// PluginDeps.Migrations. What the host guarantees is the other half:
		// a plugin whose migrations failed is never committed, so there is
		// never a registry entry without the tables it expected.
		if err := deps.Migrations(ctx, a.desc.ID, a.desc.Migrations); err != nil {
			return fmt.Errorf("applying %d schema step(s): %w", n, err)
		}
	}
	if err := a.plugin.Register(ctx, a.host); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	a.host.gather()
	if err := a.host.firstFault(); err != nil {
		return err
	}
	if err := a.plugin.Validate(a.cfg); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	return nil
}

// admission is one plugin's staged offer. It is not the registry: nothing here
// is reachable from a request until commit copies it in.
type admission struct {
	plugin Plugin
	desc   Descriptor
	grants Capabilities
	cfg    Config
	host   *host
	warn   warnings
	reason string
}

func (a *admission) refuse(err error) { a.reason = err.Error() }

// claims is the collision index over everything staged so far, and it is the
// answer to "who already has this id". The first plugin in sorted order wins,
// because the sort is what makes that the same winner on every boot.
type claims struct {
	ids       map[string]string
	pageTypes map[string]string
	nav       map[string]string
	resolvers map[string]string
}

func newClaims() *claims {
	return &claims{
		ids:       map[string]string{},
		pageTypes: map[string]string{},
		nav:       map[string]string{},
		resolvers: map[string]string{},
	}
}

// claim is §2.4 step 4c. It runs last in a plugin's lifecycle and it either
// passes, in which case the plugin is committed, or the plugin is discarded
// whole — so a plugin is never half-registered because it lost a race on its
// third page type.
func (c *claims) claim(a *admission) error {
	id := a.desc.ID
	if owner, taken := c.ids[id]; taken {
		return fmt.Errorf("the plugin id %q is already claimed by the plugin %s, which sorted first", id, owner)
	}

	pageTypes := map[string]bool{}
	for _, pt := range a.host.pageTypes {
		if pageTypes[pt.ID] {
			return fmt.Errorf("the page type %q is registered twice by one plugin", pt.ID)
		}
		pageTypes[pt.ID] = true
		if owner, taken := c.pageTypes[pt.ID]; taken {
			return fmt.Errorf("the page type %q is already registered by the plugin %s", pt.ID, owner)
		}
	}

	navIDs := map[string]bool{}
	for _, n := range a.host.nav {
		if n.ID == "" || navIDs[n.ID] {
			return fmt.Errorf("the sidebar item %q is registered twice by one plugin", n.ID)
		}
		navIDs[n.ID] = true
		if owner, taken := c.nav[n.ID]; taken {
			return fmt.Errorf("the sidebar item %q is already registered by the plugin %s", n.ID, owner)
		}
	}

	resolverIDs := map[string]bool{}
	for _, r := range a.host.resolvers {
		if r.ID == "" || resolverIDs[r.ID] {
			return fmt.Errorf("the search resolver %q is registered twice by one plugin", r.ID)
		}
		resolverIDs[r.ID] = true
		if owner, taken := c.resolvers[r.ID]; taken {
			return fmt.Errorf("the search resolver %q is already registered by the plugin %s", r.ID, owner)
		}
	}

	// A summary provider's id and a route pattern are scoped to their plugin
	// and are not compared across plugins: plugin.go says a provider's ID
	// identifies it *within its plugin*, and a sub-router is mounted under the
	// plugin's own prefix, so neither can reach another's namespace. What
	// still has to hold is that a plugin does not register either twice.
	summaryIDs := map[string]bool{}
	for _, s := range a.host.summaries {
		if s == nil {
			return errors.New("a nil summary provider is not a summary provider")
		}
		if summaryIDs[s.ID()] {
			return fmt.Errorf("the summary provider %q is registered twice by one plugin", s.ID())
		}
		summaryIDs[s.ID()] = true
	}
	routeKeys := map[string]string{}
	for _, rc := range a.host.routes {
		if first, taken := routeKeys[rc.key]; taken {
			return fmt.Errorf("the route %q collides with %q, which this plugin already registered", rc.pattern, first)
		}
		routeKeys[rc.key] = rc.pattern
	}

	c.ids[id] = id
	for name := range pageTypes {
		c.pageTypes[name] = id
	}
	for name := range navIDs {
		c.nav[name] = id
	}
	for name := range resolverIDs {
		c.resolvers[name] = id
	}
	return nil
}

// registry is the live, read-only-after-Load collection. Every accessor returns
// a copy, because a caller that sorted a panel slice in place would otherwise
// reorder the sidebar for every subsequent request until the next boot — a bug
// that is invisible in a test and permanent in a campaign.
type registry struct {
	report    Report
	plugins   map[string]Plugin
	configs   map[string]Config
	types     []Owned[PageType]
	typeIndex map[string]int
	panels    []Owned[Panel]
	nav       []Owned[NavItem]
	resolvers []Owned[SearchResolver]
	summaries []Owned[SummaryProvider]
	routes    []Owned[RouteMounter]
	extend    []Owned[any]
}

var _ Registry = (*registry)(nil)

func (r *registry) commit(a *admission) {
	id := a.desc.ID
	for i, pt := range a.host.pageTypes {
		r.typeIndex[pt.ID] = len(r.types)
		r.types = append(r.types, Owned[PageType]{Plugin: id, Index: i, Value: pt})
	}
	for i, p := range a.host.panels {
		r.panels = append(r.panels, Owned[Panel]{Plugin: id, Index: i, Value: p})
	}
	for i, n := range a.host.nav {
		r.nav = append(r.nav, Owned[NavItem]{Plugin: id, Index: i, Value: n})
	}
	for i, s := range a.host.resolvers {
		r.resolvers = append(r.resolvers, Owned[SearchResolver]{Plugin: id, Index: i, Value: s})
	}
	for i, s := range a.host.summaries {
		r.summaries = append(r.summaries, Owned[SummaryProvider]{Plugin: id, Index: i, Value: s})
	}
	for i, e := range a.host.extend {
		r.extend = append(r.extend, Owned[any]{Plugin: id, Index: i, Value: e})
	}
	// A plugin that registered no route gets no sub-router mounted: an empty
	// router under /plugin/{id} is a prefix that serves 404 for everything,
	// which is the one thing a nav item and a preview affordance must not
	// point at.
	if len(a.host.routes) > 0 && a.host.mux != nil {
		r.routes = append(r.routes, Owned[RouteMounter]{Plugin: id, Value: a.host.mux})
	}
	r.plugins[id] = a.plugin
	r.configs[id] = a.cfg
}

// dropPanelsForUnknownPageTypes removes panels scoped to a page type nobody
// registered, after every plugin has committed — a panel may name a page type a
// later plugin in sorted order registers. A panel nothing can render is not a
// broken control, but it is a contribution that silently does nothing, and a
// report that counts it is a report that lies.
func (r *registry) dropPanelsForUnknownPageTypes(w *warnings) {
	kept := r.panels[:0]
	for _, p := range r.panels {
		if p.Value.PageType != "" {
			if _, ok := r.typeIndex[p.Value.PageType]; !ok {
				w.addf("plugin %s: dropped a panel scoped to the unknown page type %q", p.Plugin, p.Value.PageType)
				continue
			}
		}
		kept = append(kept, p)
	}
	r.panels = kept
}

// order sorts the two registries a renderer reads in an order that has to be
// predictable: panels by slot, then the plugin's own Order, then the owning
// plugin; nav items by Order then owning plugin.
//
// Slot order is by name because KnownSlots is a map and the declaration order of
// the Slot constants is not recoverable from it; a panel that needs a specific
// position inside a slot says so with Order.
func (r *registry) order() {
	slices.SortStableFunc(r.panels, func(a, b Owned[Panel]) int {
		return cmpChain(
			strings.Compare(string(a.Value.Slot), string(b.Value.Slot)),
			cmpInt(a.Value.Order, b.Value.Order),
			strings.Compare(a.Plugin, b.Plugin),
			cmpInt(a.Index, b.Index),
		)
	})
	slices.SortStableFunc(r.nav, func(a, b Owned[NavItem]) int {
		return cmpChain(
			cmpInt(a.Value.Order, b.Value.Order),
			strings.Compare(a.Plugin, b.Plugin),
			cmpInt(a.Index, b.Index),
		)
	})
}

func (r *registry) Report() Report {
	return Report{
		Entries:  slices.Clone(r.report.Entries),
		Warnings: slices.Clone(r.report.Warnings),
	}
}

func (r *registry) PageType(id string) (PageType, bool) {
	i, ok := r.typeIndex[id]
	if !ok {
		return PageType{}, false
	}
	return r.types[i].Value, true
}

func (r *registry) PageTypes() []Owned[PageType] { return slices.Clone(r.types) }

func (r *registry) Panels() []Owned[Panel] { return slices.Clone(r.panels) }

// PanelsFor returns the panels a page of this type shows: the page type's own
// panels first, then the global ones, each in the order Panels returns.
func (r *registry) PanelsFor(pageType string) []Owned[Panel] {
	var own, global []Owned[Panel]
	for _, p := range r.panels {
		switch p.Value.PageType {
		case pageType:
			own = append(own, p)
		case "":
			global = append(global, p)
		}
	}
	return append(own, global...)
}

func (r *registry) NavItems() []Owned[NavItem] { return slices.Clone(r.nav) }

func (r *registry) SearchResolvers() []Owned[SearchResolver] {
	return slices.Clone(r.resolvers)
}

func (r *registry) Summaries() []Owned[SummaryProvider] { return slices.Clone(r.summaries) }

func (r *registry) Routes() []Owned[RouteMounter] { return slices.Clone(r.routes) }

func (r *registry) Extenders() []Owned[any] { return slices.Clone(r.extend) }

func (r *registry) Plugin(id string) (Plugin, bool) {
	p, ok := r.plugins[id]
	return p, ok
}

func (r *registry) Config(id string) (Config, bool) {
	c, ok := r.configs[id]
	return c, ok
}

// buildReport is every plugin that was offered, healthy or not, in id order.
//
// A plugin that was not offered at all is not here: its absence is a fact
// about the build and the build reports it. A plugin that was offered and
// refused is here with a reason, because "skipped" without a reason is
// indistinguishable from "not installed" and a failure that looks like a
// missing feature is a failure nobody chases.
func buildReport(all, live []*admission, r *registry, warn warnings) Report {
	ok := make(map[string]bool, len(live))
	for _, a := range live {
		ok[a.desc.ID] = true
	}
	entries := make([]Entry, 0, len(all))
	for _, a := range all {
		e := Entry{
			ID:           a.desc.ID,
			Name:         a.desc.Name,
			Kind:         a.desc.Kind,
			Version:      a.desc.Version,
			APILevel:     a.desc.APILevel,
			HostLevel:    APILevel,
			Capabilities: a.grants,
		}
		switch {
		case !ok[a.desc.ID]:
			e.Status = StatusSkipped
			e.Reason = a.reason
		case Compat(APILevel, a.desc.APILevel):
			e.Status = StatusCompat
		default:
			e.Status = StatusOK
		}
		if e.Status == StatusOK || e.Status == StatusCompat {
			e.Count = r.contribution(a.desc.ID, len(a.desc.Migrations), len(a.host.routes))
		}
		entries = append(entries, e)
	}
	return Report{Entries: entries, Warnings: []string(warn)}
}

// contribution counts what a plugin actually left in the registry, which is
// asked after the commit rather than before it: a count taken from the staging
// area is a count of an intention, and the panels for a page type nobody
// registered are dropped on the way in.
//
// Routes are counted as patterns, not as mounted sub-routers: a plugin has one
// router and as many patterns as it registered, and the report is about what
// the plugin registered.
func (r *registry) contribution(id string, migrations, routes int) Contribution {
	c := Contribution{Migrations: migrations, Routes: routes}
	for _, v := range r.types {
		if v.Plugin == id {
			c.PageTypes++
		}
	}
	for _, v := range r.panels {
		if v.Plugin == id {
			c.Panels++
		}
	}
	for _, v := range r.nav {
		if v.Plugin == id {
			c.NavItems++
		}
	}
	for _, v := range r.resolvers {
		if v.Plugin == id {
			c.SearchResolvers++
		}
	}
	for _, v := range r.summaries {
		if v.Plugin == id {
			c.Summaries++
		}
	}
	for _, v := range r.extend {
		if v.Plugin == id {
			c.Extenders++
		}
	}
	return c
}

func cmpChain(cmps ...int) int {
	for _, c := range cmps {
		if c != 0 {
			return c
		}
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
