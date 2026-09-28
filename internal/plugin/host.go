package plugin

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// The capability-scoped surface one plugin is given.
//
// A plugin is first-party code compiled into the binary, so nothing here is a
// sandbox and every method is a check against accidental damage. The shape of
// the check is always the same: the host asks one question — may *this* plugin,
// of *this* kind, holding *these* grants, do this — and answers it with the
// tables in reserved.go rather than with a rule written out a second time here.
//
// Two halves, worth keeping apart. The methods a plugin calls are gates: each
// returns what the host accepted, which may be less than what the plugin asked
// for and may be nothing. The unexported collect/audit steps are the host's own
// view of the plugin's offering, and lifecycle.go decides which parts of it
// reach the registry.

// host is the Host implementation handed to exactly one plugin.
type host struct {
	deps   PluginDeps
	d      Descriptor
	grants Capabilities
	cfg    Config
	owner  Plugin
	warn   *warnings
	// priorExtend is what earlier plugins in sorted order contributed, so that
	// RegisterMarkdown can show a plugin the order the host will compose in.
	priorExtend []any
	mux         RouteMounter

	pageTypes []PageType
	panels    []Panel
	nav       []NavItem
	resolvers []SearchResolver
	summaries []SummaryProvider
	extend    []any
	routes    []routeClaim

	faults []error
}

// routeClaim is one registered pattern: what the plugin asked for, and the
// normalised key it collides on.
type routeClaim struct {
	pattern string
	key     string
}

// newHost builds the host for one plugin. grants is what the host decided to
// grant, which for an in-tree first-party plugin is the plugin's whole
// declaration (see Load for why). The sub-router is built here rather than
// handed to the plugin to build, because a sub-router the host did not make is
// one that was never prefixed at /plugin/{id} and never wrapped in the host's
// session and role middleware.
func newHost(deps PluginDeps, d Descriptor, owner Plugin, grants Capabilities, cfg Config, warn *warnings, prior []any) *host {
	h := &host{
		deps:        deps,
		d:           d,
		grants:      grants,
		cfg:         cfg,
		owner:       owner,
		warn:        warn,
		priorExtend: prior,
	}
	if deps.SubRouter != nil {
		h.mux = deps.SubRouter(d.ID)
	}
	// Extenders are static data, like the descriptor, so they are collected
	// before Register rather than after it. That is what lets a plugin ask
	// RegisterMarkdown what the composite will be and get a truthful answer
	// during its own Register.
	h.extend = h.ownExtenders()
	// The same goes for everything else that is a declaration rather than an
	// act: the page types, the panels, the resolvers and the summary providers
	// are all read here, before the plugin runs, so a plugin's contribution
	// cannot depend on the order its own Register happened to do things in.
	// Where a value arrives from two places the descriptor wins, because it is
	// the one the version gate already applied to; the optional interfaces
	// fill the gaps.
	h.pageTypes = h.declaredPageTypes()
	h.panels = h.gatedPanels()
	h.resolvers = h.gatedResolvers()
	h.summaries = h.gatedSummaries()
	return h
}

// Log writes through the host's redacting handler, which is a plugin's only
// logging path: obs is on the forbidden-import list.
//
// The message goes through byte for byte. The host cannot tell a plugin's
// string from a line of vault text, and a transformation invented here would be
// a filter a plugin formats its own message around anyway. What the host can do
// is refuse to help: nothing here stringifies a value into msg, and KV.Value is
// any, so a plugin can put a body in a value. That is why the guard is
// downstream — the redacting handler drops a content, body, snippet or raw
// attribute and truncates anything over 256 bytes — and it is why a plugin that
// logs a secret body loses the value rather than the line.
func (h *host) Log(ctx context.Context, l Level, msg string, kv ...KV) {
	if h.deps.Log == nil {
		return
	}
	h.deps.Log(ctx, l, msg, kv...)
}

// Capability returns what this plugin was granted, which is never more than it
// declared.
func (h *host) Capability() Capabilities { return h.grants }

// Kind returns the plugin's own kind, so a plugin branches once at register
// time rather than at every render.
func (h *host) Kind() Kind { return h.d.Kind }

// Config returns the plugin's namespaced configuration, stamped with its id by
// the lifecycle whatever the configuration store returned.
func (h *host) Config() Config { return h.cfg }

// Now returns the host clock. A plugin never calls time.Now, which is what
// makes a plugin's output reproducible in a test. A composition root that
// supplied no clock gets the zero time rather than a panic, so the failure is a
// wrong timestamp in a log line instead of a boot crash nobody can read a boot
// report from.
func (h *host) Now() time.Time {
	if h.deps.Now == nil {
		return time.Time{}
	}
	return h.deps.Now()
}

// FS returns the read-only, vault-relative filesystem the composition root
// built, verbatim: the host has no filesystem of its own and cannot narrow one
// further.
//
// The guarantee that matters — public spans only, no secret body reachable from
// here — is a property of whatever app built it, not something this method can
// enforce by calling a method, which is why PluginDeps.FS carries the
// obligation in its own doc comment. A composition root that supplied no
// filesystem gets an empty one rather than a nil, so a plugin's read finds
// nothing instead of dereferencing nil.
func (h *host) FS() fs.FS {
	if h.deps.FS == nil {
		return emptyFS{}
	}
	return h.deps.FS()
}

// Pages returns the authz-filtered page read surface, or an empty one.
//
// The empty store is the same degradation FS makes and for the same reason: a
// host built without a page store must hand a plugin something it can call, so
// "there is nothing to read" is a value rather than a nil dereference. Every
// method answers zero values and store.ErrNoRows, which is what a store with no
// pages behind it would answer anyway.
func (h *host) Pages() PageStore {
	if h.deps.Pages == nil {
		return emptyPageStore{}
	}
	return h.deps.Pages
}

// RegisterRoutes audits the routes mounted for this plugin.
//
// The plugin mounts; the host audits. chi has no unregister, so a pattern that
// reached a router cannot be taken back, which is why a reserved-segment
// violation found here disables the whole plugin rather than dropping one
// pattern from a list. sub is the sub-router the plugin already holds and nil
// means the one the host built; a router that is not that value is refused,
// because a plugin mounting on a router of its own is mounting outside the
// prefix and the middleware the host wrapped around this one.
func (h *host) RegisterRoutes(sub RouteMounter) {
	if h.mux == nil {
		// A warning, not a fault, and the distinction is the whole point.
		//
		// A host with no sub-router can still hand a plugin its page types, its
		// panels and its migration: none of those need a URL. Faulting here
		// disabled every plugin in a build whose router is constructed after the
		// boot, which is the ordinary order, and the whole system plugin shipped
		// as dead code on disk while the report said it was refused.
		//
		// The same rule the rest of this package follows: the absence of a
		// capability degrades to a smaller working app, never to a broken one. A
		// plugin with no route serves nothing at its own URL and everything
		// everywhere else, and the warning is how that is visible rather than
		// silent.
		h.warn.addf("no sub-router was supplied, so this plugin contributes no routes: its page types, panels and navigation are unaffected, and any nav item pointing at an unregistered route is dropped")
		return
	}
	if sub != nil && sub != h.mux {
		h.faultf("a plugin may mount only on the sub-router the host handed it, which is already prefixed at /plugin/%s and already wrapped in the host's middleware", h.d.ID)
		return
	}
	h.auditRoutes()
}

// RegisterPageTypes returns the page types the host accepted for this plugin.
//
// A feature plugin calling it is a boot error for that plugin. The lifecycle
// already refuses a feature plugin that *declared* page types before Register
// is ever called, so the path this guards is a feature plugin that built a page
// type at register time and declared none — the same rule reached by the other
// road.
func (h *host) RegisterPageTypes() []PageType {
	if h.d.Kind == KindFeature {
		h.faultf("a %s plugin may not register page types: a page type is a game system's vocabulary, and a feature expresses content through frontmatter conventions", KindFeature)
		return nil
	}
	return slices.Clone(h.pageTypes)
}

// RegisterPanels returns the panels the host accepted, which is nil without
// CapUIPanels. The whole set goes rather than a filtered part of it: a plugin
// that ships one panel it was refused the capability for has still shipped a
// panel, and the report should say so.
func (h *host) RegisterPanels() []Panel { return slices.Clone(h.panels) }

// RegisterMarkdown returns the extenders in the order the host will compose
// them: what earlier plugins in sorted order contributed, then this plugin's.
//
// The order is the sort order rather than the registration order because
// markdown is order-sensitive and "whichever plugin happened to register first"
// is not an order a page author can predict. The element type is any because
// goldmark.Extender cannot be named here without pulling goldmark into this
// package's import graph to no purpose: a plugin already imports goldmark to
// write an extender, and the composition happens in md, which does import it.
func (h *host) RegisterMarkdown() []any {
	out := make([]any, 0, len(h.priorExtend)+len(h.extend))
	out = append(out, h.priorExtend...)
	out = append(out, h.extend...)
	return out
}

// gather is what cannot be known until the plugin has run: the routes it
// mounted, and the nav items, which are gated on those routes because a nav
// item for a plugin that registered no route cannot resolve. It runs once,
// after Register returns, and it never calls the plugin again.
func (h *host) gather() {
	h.mountRoutes()
	// Audited unconditionally, because a plugin may mount routes from inside
	// Register without implementing PluginUI, and the audit has to reflect
	// everything mounted rather than the last thing the host called.
	h.auditRoutes()
	h.nav = h.gatedNav()
}

// declaredPageTypes returns the page types the host accepted, and is the
// feature-plugin rule's other half: a feature is refused a page type whether it
// declared one or built one at register time.
func (h *host) declaredPageTypes() []PageType {
	if h.d.Kind == KindFeature {
		if len(h.d.PageTypes) > 0 || h.coreTypes() > 0 {
			h.faultf("a %s plugin may not register page types: a page type is a game system's vocabulary, and a feature expresses content through frontmatter conventions", KindFeature)
		}
		return nil
	}
	seen := map[string]bool{}
	var out []PageType
	add := func(pt PageType) {
		if pt.ID == "" {
			h.faultf("a registered page type has an empty id")
			return
		}
		if seen[pt.ID] {
			h.faultf("the page type %q is registered twice", pt.ID)
			return
		}
		seen[pt.ID] = true
		if err := CheckReservedPageType(pt.ID, h.d.Kind, h.grants); err != nil {
			h.fault(err)
			return
		}
		out = append(out, pt)
	}
	for _, pt := range h.d.PageTypes {
		add(pt)
	}
	if pc, ok := h.owner.(PluginCore); ok {
		for _, pt := range pc.CoreTypes() {
			if seen[pt.ID] {
				continue
			}
			add(pt)
		}
	}
	return out
}

func (h *host) gatedPanels() []Panel {
	var all []Panel
	for _, pt := range h.pageTypes {
		all = append(all, pt.SidePanels...)
	}
	if ui, ok := h.owner.(PluginUI); ok {
		all = append(all, ui.Panels()...)
	}
	if len(all) == 0 {
		return nil
	}
	if !h.grants.Has(CapUIPanels) {
		h.warn.addf("plugin %s: %d panel(s) discarded, it does not hold the %q capability", h.d.ID, len(all), CapUIPanels)
		return nil
	}
	var out []Panel
	for _, p := range all {
		// An unknown slot is dropped whatever the capability is: core owns
		// the slot containers, so a panel in a slot core does not render has
		// nowhere to go, and a report that counts it is a report that lies.
		if !KnownSlots[p.Slot] {
			h.warn.addf("plugin %s: dropped a panel in the unknown slot %q", h.d.ID, p.Slot)
			continue
		}
		out = append(out, p)
	}
	return out
}

func (h *host) gatedNav() []NavItem {
	items := slices.Clone(h.d.NavItems)
	if ui, ok := h.owner.(PluginUI); ok {
		for _, n := range ui.NavItems() {
			if !hasNavID(items, n.ID) {
				items = append(items, n)
			}
		}
	}
	if len(items) == 0 {
		return nil
	}
	if !h.grants.Has(CapSidebarNav) {
		h.warn.addf("plugin %s: %d sidebar item(s) discarded, it does not hold the %q capability; the sidebar renders no plugin group at all", h.d.ID, len(items), CapSidebarNav)
		return nil
	}
	if len(h.routes) == 0 {
		h.warn.addf("plugin %s: %d sidebar item(s) discarded, it registered no route for them to point at", h.d.ID, len(items))
		return nil
	}
	prefix := PluginPrefix(h.d.ID)
	seen := map[string]bool{}
	var out []NavItem
	for _, n := range items {
		if n.ID == "" {
			h.warn.addf("plugin %s: dropped a sidebar item with an empty id", h.d.ID)
			continue
		}
		if seen[n.ID] {
			h.warn.addf("plugin %s: dropped a duplicate sidebar item %q", h.d.ID, n.ID)
			continue
		}
		// A violation is a dropped item rather than a disabled plugin: the
		// remaining items still work, and a nav link to a page nobody serves is
		// the bug the rule exists to prevent.
		if n.Href != prefix && !strings.HasPrefix(n.Href, prefix+"/") {
			h.warn.addf("plugin %s: dropped the sidebar item %q, its href %q is outside the plugin's own prefix %q", h.d.ID, n.ID, n.Href, prefix)
			continue
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out
}

func (h *host) gatedResolvers() []SearchResolver {
	if len(h.d.SearchResolvers) == 0 {
		return nil
	}
	if !h.grants.Has(CapSearchResolvers) {
		h.warn.addf("plugin %s: %d search resolver(s) discarded, it does not hold the %q capability and the host will never call them", h.d.ID, len(h.d.SearchResolvers), CapSearchResolvers)
		return nil
	}
	return slices.Clone(h.d.SearchResolvers)
}

func (h *host) gatedSummaries() []SummaryProvider {
	ui, ok := h.owner.(PluginUI)
	if !ok {
		return nil
	}
	all := ui.Summaries()
	if len(all) == 0 {
		return nil
	}
	if !h.grants.Has(CapPageSummaries) {
		h.warn.addf("plugin %s: %d summary provider(s) discarded, it does not hold the %q capability, so the link-preview affordance is not rendered for it", h.d.ID, len(all), CapPageSummaries)
		return nil
	}
	return slices.Clone(all)
}

func (h *host) ownExtenders() []any {
	pc, ok := h.owner.(PluginCore)
	if !ok {
		return nil
	}
	var out []any
	for i, e := range pc.MarkdownExtenders() {
		if e == nil {
			h.warn.addf("plugin %s: dropped a nil markdown extender at index %d", h.d.ID, i)
			continue
		}
		out = append(out, e)
	}
	return out
}

func (h *host) mountRoutes() {
	ui, ok := h.owner.(PluginUI)
	if !ok {
		return
	}
	if h.mux == nil {
		// A warning, not a fault, and the distinction is the whole point.
		//
		// A host with no sub-router can still hand a plugin its page types, its
		// panels and its migration: none of those need a URL. Faulting here
		// disabled every plugin in a build whose router is constructed after the
		// boot — which is the ordinary order, because the router is assembled by
		// the caller and handed in as an opaque handler — and the whole system
		// plugin shipped as dead code on disk while the report said it was
		// refused.
		//
		// The rule the rest of this package already follows: the absence of a
		// capability degrades to a smaller working app, never to a broken one. A
		// plugin with no route serves nothing at its own URL and everything
		// everywhere else, and the warning is how that stays visible rather than
		// silent.
		h.warn.addf("plugin %s: no sub-router was supplied, so this plugin contributes no routes: its page types, panels and navigation are unaffected, and any nav item pointing at an unregistered route is dropped", h.d.ID)
		return
	}
	ui.RegisterRoutes(h.mux)
}

// auditRoutes reads back what the plugin actually mounted and checks every
// pattern, because a check against what a plugin *said* it would mount is not a
// check.
func (h *host) auditRoutes() {
	if h.mux == nil {
		return
	}
	patterns := flattenRoutes(h.mux.Routes(), "")
	// chi groups endpoints by pattern into a map when it builds its route
	// listing, so the order it hands back is map order. Sorting here is what
	// keeps the boot report's route list the same on every boot.
	slices.Sort(patterns)

	claims := make([]routeClaim, 0, len(patterns))
	seen := map[string]string{}
	for _, p := range patterns {
		if err := CheckReservedRoute(p, h.d.Kind, h.grants); err != nil {
			h.fault(err)
			continue
		}
		key := routeKey(p)
		if first, taken := seen[key]; taken {
			h.faultf("the route %q collides with %q, which this plugin already registered", p, first)
			continue
		}
		seen[key] = p
		claims = append(claims, routeClaim{pattern: p, key: key})
	}
	h.routes = claims
}

// fault records a boot error that disables the plugin. The error is stored as
// its own text: the reserved-name checks already name the plugin's kind and
// what it needed, and a second "plugin <id>:" in front of that is stutter.
func (h *host) fault(err error) { h.faults = append(h.faults, err) }

// faultf records a boot error the host wrote itself, prefixed with the plugin
// id so the reason is readable on its own and not only from the report's row.
func (h *host) faultf(format string, args ...any) {
	h.faults = append(h.faults, fmt.Errorf("plugin %s: %s", h.d.ID, fmt.Sprintf(format, args...)))
}

// firstFault returns the first boot error the host found. The first is the one
// reported because it is the cause; the rest follow from it.
func (h *host) firstFault() error {
	if len(h.faults) == 0 {
		return nil
	}
	return h.faults[0]
}

func (h *host) coreTypes() int {
	pc, ok := h.owner.(PluginCore)
	if !ok {
		return 0
	}
	return len(pc.CoreTypes())
}

func hasNavID(items []NavItem, id string) bool {
	for _, n := range items {
		if n.ID == id {
			return true
		}
	}
	return false
}

// warnings is one plugin's append-only record of the refusals that are not the
// plugin's fault. They are kept per plugin rather than in the boot report
// directly, because a plugin that is then disabled takes its own noise with it:
// a warning about a dropped panel is meaningless next to a line saying the
// plugin never registered.
type warnings []string

func (w *warnings) addf(format string, args ...any) {
	*w = append(*w, fmt.Sprintf(format, args...))
}

// PluginPrefix is the route prefix the host mounts a plugin's sub-router at.
// It is exported because a plugin, the router and the boot report all have to
// agree on it, and a nav item's href is checked against it.
func PluginPrefix(id string) string { return "/plugin/" + id }

// RoutePatterns returns the patterns a mounted plugin sub-router serves, sorted,
// with chi's mount wildcards left where chi put them. It is how the boot report
// shows what the host saw a plugin register: Entry counts the routes, and a
// count is not a list.
func RoutePatterns(sub RouteMounter) []string {
	if sub == nil {
		return nil
	}
	out := flattenRoutes(sub.Routes(), "")
	slices.Sort(out)
	return out
}

// flattenRoutes returns every pattern a router serves, following mounts. chi
// reports a mount as a wildcard pattern carrying a handle to the mounted
// router, and that router's own patterns are relative, so the prefix is joined
// on the way down. Following the mount is what stops a plugin from dodging the
// reserved-segment check by mounting its own sub-router.
func flattenRoutes(rts []chi.Route, prefix string) []string {
	var out []string
	for _, r := range rts {
		full := r.Pattern
		if prefix != "" && !strings.HasPrefix(r.Pattern, prefix) {
			full = strings.TrimSuffix(prefix, "/") + r.Pattern
		}
		out = append(out, full)
		if r.SubRoutes != nil {
			out = append(out, flattenRoutes(r.SubRoutes.Routes(), full)...)
		}
	}
	return out
}

// routeKey normalises a pattern for collision detection. The mount wildcard chi
// inserts is routing bookkeeping rather than a path segment, so "/x/*/deep" and
// "/x/deep" are one route to a reader, and a chi parameter names a value rather
// than a segment.
//
// A pattern registered twice on the same method is invisible here: chi's tree
// groups endpoints by pattern, so the second registration replaces the first
// and the listing shows one endpoint. The first handler wins, which is chi's
// rule and not the host's to change.
func routeKey(pattern string) string {
	parts := make([]string, 0, 4)
	for _, p := range strings.Split(pattern, "/") {
		if p == "" || p == "*" || strings.HasPrefix(p, "{") {
			continue
		}
		parts = append(parts, p)
	}
	return "/" + strings.Join(parts, "/")
}

// emptyFS is what a plugin sees when the composition root supplied no
// filesystem. Every read fails the way a missing file fails, which is a
// diagnostic a plugin author can act on, rather than a nil dereference in the
// middle of a render.
type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// emptyPageStore is what a plugin sees when the composition root supplied no page
// store. It answers the way a store with no indexed pages answers — an empty
// list, a zero count, and ErrNoRows for one page — so that "the host built no
// page store" and "the vault has no pages" are indistinguishable from the plugin
// side, which is what keeps the absence from becoming a diagnostic a plugin
// author has to special-case.
type emptyPageStore struct{}

func (emptyPageStore) GetPageSummary(context.Context, authz.Principal, int64) (store.PageSummary, error) {
	return store.PageSummary{}, store.ErrNoRows
}

func (emptyPageStore) ListPagesByType(context.Context, authz.Principal, string) ([]store.Page, error) {
	return nil, nil
}

func (emptyPageStore) CountPagesByType(context.Context, authz.Principal, string) (int, error) {
	return 0, nil
}

func (emptyPageStore) ListTags(context.Context, authz.Principal) ([]store.TagCount, error) {
	return nil, nil
}

// EmptyPageStore returns the page store a host hands out when the composition
// root supplied none.
//
// It is exported because "implementing plugin.Host" is something every test
// double has to do, and a double that returns nil forces every plugin under
// test to guard every read — which is the one thing the empty store exists to
// stop. A double that does not care about pages returns this and its plugin
// sees the same "nothing to read" the real host produces in that configuration.
func EmptyPageStore() PageStore { return emptyPageStore{} }

var _ PageStore = emptyPageStore{}

var _ Host = (*host)(nil)
