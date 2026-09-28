package plugin

import (
	"context"
	"io/fs"
	"time"
)

// The registry, the boot report, and the host implementation.
//
// This file is the seam between the plugin vocabulary in plugin.go and the two
// things that use it: the composition root, which runs the lifecycle, and the
// request path, which reads what the lifecycle collected. The types here are
// the contract between those three, and the lifecycle itself is in lifecycle.go.
//
// Three decisions are baked in and are worth stating before the code, because
// each of them is a place where the obvious implementation is wrong:
//
//  1. **A plugin's failure is contained, and containment means rollback.** A
//     plugin that collides with another, or claims a reserved name, or whose
//     migration fails, is disabled — and everything it added to the shared
//     registries is *removed*, not merely ignored. A registry that records
//     "this plugin was disabled" but keeps the page types it contributed is a
//     registry that renders a page type no live plugin implements.
//
//  2. **Boot never fails because of a plugin.** Every refusal is recorded in the
//     boot report with a reason. A campaign that boots with the dice system
//     missing is a worse campaign than one that does not boot, and the report is
//     where the difference becomes visible.
//
//  3. **The report is the product.** A plugin that fails silently is a plugin
//     that fails permanently. The report distinguishes admitted, skipped with a
//     reason, and admitted-but-needing-the-compat-shim, because "skipped"
//     without a reason is indistinguishable from "not installed".

// Status is a plugin's outcome at boot.
type Status string

const (
	// StatusOK is a plugin that registered cleanly.
	StatusOK Status = "ok"
	// StatusSkipped is a plugin the host refused or that failed, with a reason.
	// It is always accompanied by Reason; a skipped line with an empty reason
	// is a bug in the host and not a plugin problem.
	StatusSkipped Status = "skipped"
	// StatusCompat is a plugin that registered but was written against an older
	// host interface, and is running with the shim. It is visibly distinct from
	// StatusOK because version skew that is not visible gets shimmed forever.
	StatusCompat Status = "compat"
)

// Entry is one plugin's line in the boot report.
type Entry struct {
	// ID is the plugin's id.
	ID string
	// Name is its human label.
	Name string
	// Kind discriminates it in the report, because a skipped system and a
	// skipped feature are different problems with different fixes.
	Kind Kind
	// Version is the plugin's own semver.
	Version string
	// Status is its outcome.
	Status Status
	// Reason is why it was skipped, and is empty for StatusOK and StatusCompat.
	// It carries ids, reasons and counts — never a line of vault content.
	Reason string
	// APILevel is the level the plugin was written against, and HostLevel is
	// the one this binary implements. Both are shown so that a compat line is
	// explainable without leaving the page.
	APILevel  int
	HostLevel int
	// Capabilities is what the plugin was granted, which is a subset of what it
	// declared. A declaration the host refused is not an error, but it is not
	// invisible either.
	Capabilities Capabilities
	// Count is what the plugin contributed: page types, panels, nav items,
	// search resolvers, route patterns, markdown extenders, migrations. It is
	// here so that a plugin registering nothing is visible as having
	// registered nothing, rather than as a name in a list.
	Count Contribution
}

// Contribution counts what a plugin added, for the report and for a rollback.
//
// It is a value and not a set because the report counts, and a set would make
// the count a walk of a map whose order is a test's problem. The registry keeps
// the actual contents; this is only ever their size.
type Contribution struct {
	// PageTypes is how many page types the plugin registered.
	PageTypes int
	// Panels is how many panels it contributed.
	Panels int
	// NavItems is how many sidebar entries it contributed.
	NavItems int
	// SearchResolvers is how many it contributed.
	SearchResolvers int
	// Summaries is how many summary providers it contributed.
	Summaries int
	// Routes is how many route patterns it registered.
	Routes int
	// Extenders is how many markdown extenders it contributed.
	Extenders int
	// Migrations is how many schema steps it applied.
	Migrations int
}

// Any reports whether the plugin contributed anything at all.
func (c Contribution) Any() bool { return c != Contribution{} }

// Report is the whole boot, in a form /admin/plugins renders verbatim.
//
// It is a value rather than a logger call because a boot report that only
// exists in the log is a boot report nobody reads, and the one reader who
// needs it is an administrator asking why a panel is missing.
type Report struct {
	// Entries is every registered plugin, sorted by id, whether it succeeded or
	// not. A plugin that was not offered to the host at all is not here — the
	// registry is what the host was given, and its absence is a fact about the
	// build, reported by the build.
	Entries []Entry
	// Warnings are the refusals that are not about a specific plugin: a
	// capability a plugin declared and did not receive, a panel dropped for
	// naming an unknown slot, a nav item dropped for pointing outside its
	// prefix. They are separate from Entries because the plugin itself is fine.
	Warnings []string
}

// OKs returns the entries that registered, compat included. A caller that needs
// only the healthy ones filters on Status rather than on this.
func (r Report) OKs() []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Status == StatusOK || e.Status == StatusCompat {
			out = append(out, e)
		}
	}
	return out
}

// Skipped returns the entries the host refused, with their reasons.
func (r Report) Skipped() []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Status == StatusSkipped {
			out = append(out, e)
		}
	}
	return out
}

// HasKind reports whether any registered plugin of a kind is present. It is how
// the sidebar decides whether to render a plugin group at all, rather than
// rendering a heading and nothing under it.
func (r Report) HasKind(k Kind) bool {
	for _, e := range r.Entries {
		if e.Status != StatusSkipped && e.Kind == k {
			return true
		}
	}
	return false
}

// Registry is the host's collected view of the plugins that registered.
//
// It is built once at boot and read from every request afterwards, so every
// method is a pure read and none of them takes a lock. That is safe because a
// registry is never mutated after Load returns — a plugin cannot register at
// request time, and the API-level window exists so that "reload the host" is
// never a thing a plugin can ask for mid-request.
//
// The interface exists so that httpapi can depend on what it needs without
// depending on the lifecycle, and so that a test can hand httpapi a registry
// containing one plugin without booting a vault.
type Registry interface {
	// Report returns the boot report.
	Report() Report
	// PageType returns the page type a plugin registered for an id, or false.
	PageType(id string) (PageType, bool)
	// PageTypes returns every registered page type, ordered by owning plugin
	// id then declaration order, so that a render is reproducible.
	PageTypes() []Owned[PageType]
	// Panels returns every registered panel, ordered by slot then order then
	// owning plugin id. Panels naming an unknown slot were dropped at load, so
	// every Slot here is one core renders.
	Panels() []Owned[Panel]
	// PanelsFor returns the panels a page of this type should show, in slot
	// order: the page type's own panels first, then the global ones. An empty
	// pageType means the global panels only.
	PanelsFor(pageType string) []Owned[Panel]
	// NavItems returns every registered sidebar entry, ordered by Order then
	// owning plugin id then declaration index.
	NavItems() []Owned[NavItem]
	// SearchResolvers returns every registered resolver, in owning-plugin order.
	SearchResolvers() []Owned[SearchResolver]
	// Summaries returns every summary provider, in owning-plugin order.
	Summaries() []Owned[SummaryProvider]
	// Routes returns the mounted sub-routers, so the router can install them
	// under a prefix the plugin cannot escape.
	Routes() []Owned[RouteMounter]
	// Extenders returns every markdown extender, in owning-plugin order. The
	// host composes them into one parser; the order is the sort order, because
	// markdown is order-sensitive and "whichever plugin registered first" is
	// not an order a reader can predict.
	Extenders() []Owned[any]
	// Plugin returns a registered plugin by id, so the boot report's panel and
	// the config page can ask it for its ConfigSchema.
	Plugin(id string) (Plugin, bool)
	// Config returns a plugin's configuration.
	Config(id string) (Config, bool)
}

// Owned is a value a plugin contributed, stamped with its owner.
//
// The owner is carried on the value rather than looked up, because a renderer
// asking "which plugin contributed this panel" is a renderer that would
// otherwise need a reverse index over everything the registry holds.
type Owned[T any] struct {
	// Plugin is the contributing plugin's id.
	Plugin string
	// Index is the plugin's own declaration index within the slice, which is
	// what makes a duplicate detectable: two plugins contributing the same id
	// collide on (kind, id), not on pointer identity.
	Index int
	// Value is the contribution.
	Value T
}

// PluginDeps is what the composition root hands the host to build a plugin's
// environment with.
//
// The shape is deliberate. `plugin` sits *below* `vault`, `auth` and `secrets`
// in the dependency order, so the host cannot import them to build a page
// store or a vault-relative filesystem — it would close a cycle. What it can do
// is accept the already-built pieces as values, and the composition root, which
// imports everything, is the only place that can construct them.
//
// That is also why `FS` is an fs.FS and not a vault type. The host hands a
// plugin a filesystem it does not know how to resolve paths in, and the one
// guarantee that matters — public spans only, no secret body — is a property of
// whatever `app` built, not something the host can enforce by calling a
// method. So the field's doc comment carries the obligation, and the
// architecture test is what checks that the thing built here cannot reach a
// secret.
type PluginDeps struct {
	// Now is the host clock. A plugin never calls time.Now: a frozen clock is
	// what makes a plugin's output reproducible in a test.
	Now func() time.Time
	// Log writes through the host's redacting handler. A plugin cannot log
	// through obs directly — it is on the forbidden list — so this is the only
	// way it logs, and therefore the only way a secret could reach a log line
	// through a plugin.
	Log func(ctx context.Context, l Level, msg string, kv ...KV)
	// Config returns a plugin's persisted configuration.
	Config func(pluginID string) (Config, error)
	// FS returns a read-only, vault-relative filesystem of **public content
	// only**. The host hands this to plugins verbatim. It is the composition
	// root's obligation to build it so, and the reason is not a convention: it
	// is the only path by which a plugin could reach a secret body, so
	// TestTheHostFSCannotReachASecretBody is the test that holds the obligation.
	FS func() fs.FS
	// Migrations runs a plugin's declared migrations, tracked, in the caller's
	// transaction. The host does not run DDL itself: a plugin migration that
	// fails must roll back with everything else that plugin did.
	Migrations func(ctx context.Context, pluginID string, migs []Migration) error
	// SubRouter builds a sub-router already mounted at /plugin/{id} and
	// already wrapped in the host's session and role middleware. The plugin
	// receives it and cannot escape the prefix, because it is a value the host
	// already mounted rather than a router the plugin configures.
	SubRouter func(pluginID string) RouteMounter
}
