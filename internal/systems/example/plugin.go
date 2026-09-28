package example

import (
	"context"
	"net/http"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
)

// ID is the plugin id every constructor returns. It is an ordinary legal
// kebab-case id that nothing else claims, so every refusal below is a refusal
// of behaviour and never of a name the host would have rejected on its own
// account — which matters, because a demo refused for a boring reason would
// still look like a working demonstration.
const ID = "example"

// Version is this plugin's own semver, and like everything else here it is
// unremarkable: a host that treated the demo specially would make the
// demonstrations meaningless.
const Version = "0.1.0"

// The names this package claims, one per rule it is aimed at.
//
// Each is either a name the host holds, or a name nothing holds, and the
// difference is the whole point: a name the host holds can only be refused by
// the reserved-name rule, and a name nothing holds can only be refused by a
// collision. Mixing the two would make every demonstration ambiguous.
const (
	// reservedPageType is held for CapCharacterSheet, so the only way to claim
	// it is as a KindSystem declaring that capability.
	reservedPageType = "character"

	// reservedRoute is held for CapMaps, and the leading slash is part of the
	// pattern the host matches on: RouteReservation splits a pattern into
	// segments, so `/map` and `map` are the same claim and only the first looks
	// like a route.
	reservedRoute = "/map"

	// collisionPageType is held by nothing and reserved for nothing. The plugin
	// claiming it is refused because a second plugin claims it too, which is a
	// registry check and not a reservation.
	collisionPageType = "example-collision"

	// featurePageType is held by nothing. Nothing about the name is wrong; the
	// kind of the plugin claiming it is.
	featurePageType = "example-feature-page"
)

// example is the single plugin type, parameterised by what it declares and by
// the routes and panels it offers. Every constructor returns this type with a
// different wrong declaration, so the host sees one shape in all five cases and
// refuses each for a different reason.
type example struct {
	// d is the declaration. Descriptor hands it out by value, so a host that
	// kept or mutated the copy cannot reach this one and cannot affect the next
	// boot.
	d plugin.Descriptor
	// routes are the patterns the plugin asks the host to mount. They are not
	// in the Descriptor because Descriptor is static data the host reads
	// *before* calling Register: a pattern is only discoverable by walking the
	// sub-router the plugin builds.
	routes []string
	// panels are the sidebar contributions, for the same reason routes are not
	// in the Descriptor.
	panels []plugin.Panel
	// host is whatever Register was handed, nil until then. A refused plugin may
	// never reach Register, so nothing here may assume a host exists.
	host plugin.Host
}

// The three interfaces the vocabulary defines, asserted rather than assumed: a
// demo that quietly implemented less than a real plugin would be refused for
// the wrong reason, and the whole point is that the refusal is specific.
var (
	_ plugin.Plugin     = (*example)(nil)
	_ plugin.PluginUI   = (*example)(nil)
	_ plugin.PluginCore = (*example)(nil)
)

// ReservedPageTypeWithoutCapability returns a system plugin that claims the
// reserved page type "character" while declaring only CapMaps.
//
// Aimed at plugin.CheckReservedPageType, the capability half of the reserved
// name rule. It is the right kind with the wrong grant, and it holds CapMaps
// legitimately, so the refusal cannot be explained away as an empty
// declaration or by the kind check.
func ReservedPageTypeWithoutCapability() plugin.Plugin {
	return &example{
		d: plugin.Descriptor{
			ID:           ID,
			Name:         "Example (reserved page type, no capability)",
			Kind:         plugin.KindSystem,
			Version:      Version,
			APILevel:     plugin.APILevel,
			Capabilities: []plugin.Capability{plugin.CapMaps, plugin.CapSidebarNav},
			PageTypes: []plugin.PageType{{
				ID:   reservedPageType,
				Name: "Character sheet",
			}},
			NavItems: []plugin.NavItem{sidePanelNavItem()},
		},
	}
}

// ReservedRouteAsFeature returns a feature plugin that holds CapMaps and
// registers the reserved route "/map" anyway.
//
// Aimed at plugin.CheckReservedRoute, the kind half of the same rule, and this
// is the half a simpler implementation forgets: the plugin holds exactly the
// capability the segment is reserved for, so a check that tested only the
// capability would admit it. It is a feature — a link-preview or an import tool
// has no business mounting a map system surface however much it likes maps.
func ReservedRouteAsFeature() plugin.Plugin {
	return &example{
		d: plugin.Descriptor{
			ID:           ID,
			Name:         "Example (reserved route as a feature)",
			Kind:         plugin.KindFeature,
			Version:      Version,
			APILevel:     plugin.APILevel,
			Capabilities: []plugin.Capability{plugin.CapMaps, plugin.CapUIPanels},
		},
		routes: []string{reservedRoute},
		panels: []plugin.Panel{rightTopPanel()},
	}
}

// FeatureDeclaringPageTypes returns a feature plugin whose declaration names a
// page type. The id it claims is held by nothing, so the reserved-name rule
// cannot refuse it and the kind rule is the only thing that can.
//
// Aimed at the host's KindFeature check: there is no second code path for
// features, and a feature that registers a page type is a feature deciding what
// a game's vocabulary means. This is what makes `type: houserule` render with
// the core viewer a convention rather than a registration.
func FeatureDeclaringPageTypes() plugin.Plugin {
	return &example{
		d: plugin.Descriptor{
			ID:           ID,
			Name:         "Example (a feature declaring page types)",
			Kind:         plugin.KindFeature,
			Version:      Version,
			APILevel:     plugin.APILevel,
			Capabilities: []plugin.Capability{plugin.CapUIPanels},
			PageTypes: []plugin.PageType{{
				ID:   featurePageType,
				Name: "Feature page",
			}},
		},
		panels: []plugin.Panel{rightTopPanel()},
	}
}

// CollidingPlugin returns a system plugin that claims a page-type id nothing
// holds, along with a route, a nav item, a panel and a migration of its own.
//
// Aimed at the registry's collision check rather than at reserved.go: a second
// CollidingPlugin() in the same boot claims the same id, and one of the two has
// to lose. The point of the contributions beyond the page type is that they are
// the evidence the rollback test needs — a host that marks a plugin skipped and
// then keeps its panel and its migration has not contained anything.
func CollidingPlugin() plugin.Plugin {
	return &example{
		d: plugin.Descriptor{
			ID:       ID,
			Name:     "Example (colliding page type)",
			Kind:     plugin.KindSystem,
			Version:  Version,
			APILevel: plugin.APILevel,
			Capabilities: []plugin.Capability{
				plugin.CapRules, plugin.CapDice, plugin.CapUIPanels,
				plugin.CapSidebarNav, plugin.CapSearchResolvers,
				plugin.CapPageSummaries,
			},
			PageTypes: []plugin.PageType{{
				ID:   collisionPageType,
				Name: "Colliding example page",
			}},
			NavItems: []plugin.NavItem{sidePanelNavItem()},
			Migrations: []plugin.Migration{{
				Version: 1,
				Name:    "example plugin table",
				SQL: "CREATE TABLE IF NOT EXISTS example_thing (" +
					"id INTEGER PRIMARY KEY, note TEXT)",
			}},
		},
		routes: []string{"/run-example"},
		panels: []plugin.Panel{rightTopPanel()},
	}
}

// TwoBadThings returns a plugin that breaks three rules at once: it is a feature
// that declares page types, it claims the reserved page type "character"
// without the capability, and it registers the reserved route "/map" while
// holding the capability that route is reserved for.
//
// Aimed at the *report*, not at a single check. A host that stops at the first
// failure still contains the plugin, so this is not a safety case; it is the
// case that shows a refusal is a diagnosis rather than a verdict, because an
// author who fixes one violation and reboots deserves to be told about the
// other two in the same report line.
func TwoBadThings() plugin.Plugin {
	return &example{
		d: plugin.Descriptor{
			ID:       ID,
			Name:     "Example (three violations at once)",
			Kind:     plugin.KindFeature,
			Version:  Version,
			APILevel: plugin.APILevel,
			Capabilities: []plugin.Capability{
				plugin.CapMaps, plugin.CapUIPanels, plugin.CapSidebarNav,
			},
			PageTypes: []plugin.PageType{{
				ID:   reservedPageType,
				Name: "Character sheet",
			}},
			NavItems: []plugin.NavItem{sidePanelNavItem()},
		},
		routes: []string{reservedRoute},
		panels: []plugin.Panel{rightTopPanel()},
	}
}

// Descriptor returns the declaration this constructor built, by value.
func (e *example) Descriptor() plugin.Descriptor { return e.d }

// Register hands the host this plugin's routes and returns no error.
//
// The polarity is deliberate and is the reason these tests mean anything. If
// this method failed, every demonstration here would pass against a host that
// checks nothing at all, because the plugin would be refusing itself. So it
// hands over everything it can and lets the host decide — and a host that
// admits any of these plugins fails the tests beside this file, which is the
// entire purpose.
//
// It passes nil rather than a router of its own, and that is not a detail. A
// sub-router the host did not make is one that was never prefixed at
// /plugin/{id} and never wrapped in the host's session and role middleware, so
// the host refuses it — and a demonstration that handed over its own router
// would be refused for that instead of for the violation it exists to show. The
// patterns are mounted through PluginUI.RegisterRoutes, on the router the host
// hands the plugin, and the host audits whatever it finds there.
func (e *example) Register(ctx context.Context, h plugin.Host) error {
	e.host = h
	h.RegisterRoutes(nil)
	h.Log(ctx, plugin.LevelInfo, "example plugin registering",
		plugin.KV{Key: "plugin", Value: e.d.ID})
	return nil
}

// Panels is the PluginUI hook: the sidebar contributions this plugin declares.
func (e *example) Panels() []plugin.Panel { return e.panels }

// NavItems is the PluginUI hook for the left sidebar. The example declares
// these in the Descriptor as well, so a host that reads either surface sees the
// same nav item and a rollback that missed one of them is visible.
func (e *example) NavItems() []plugin.NavItem { return e.d.NavItems }

// Summaries is the PluginUI hook for link previews. The example supplies none,
// because a summary provider is a live surface rather than a declaration: the
// demonstration is about what a refused plugin leaves behind, and a provider
// that returned content would be a much larger claim to make.
func (e *example) Summaries() []plugin.SummaryProvider { return nil }

// RegisterRoutes is the PluginUI hook, and it is the only way a plugin gets its
// patterns mounted. The host calls it with a sub-router it built, already
// prefixed at /plugin/{id} and already wrapped in its session and role
// middleware, which is the only arrangement in which a plugin genuinely cannot
// register outside its own prefix.
func (e *example) RegisterRoutes(sub plugin.RouteMounter) {
	for _, pattern := range e.routes {
		sub.Get(pattern, http.HandlerFunc(serveNothing))
	}
}

// CoreTypes is the PluginCore hook: the page-type descriptors without their
// components. The example declares the same ids here as in its Descriptor
// because a host that consulted only one of the two would see no violation at
// all, and a demonstration the host can miss is not a demonstration.
func (e *example) CoreTypes() []plugin.PageType { return e.d.PageTypes }

// MarkdownExtenders is the PluginCore hook. None, because a goldmark extender
// is a live parser this host would compose into the request path — the
// containment being demonstrated is about the registry, and a demo that reached
// into the parser would be a different and much larger claim.
func (e *example) MarkdownExtenders() []any { return nil }

// ConfigSchema is the PluginCore hook. None, for the same reason: configuration
// is persisted, and a demo that wrote rows would leave them behind.
func (e *example) ConfigSchema() map[string]any { return nil }

// Validate accepts any configuration, because a demo that failed validation
// would be testing its own validation rather than the host's registration
// rules.
func (e *example) Validate(plugin.Config) error { return nil }

// Now returns the host clock. Even a plugin that is never meant to run
// delegates: a plugin that called time.Now directly would be untestable, and an
// untestable clock is how a timestamp ends up in a rendered page untested.
func (e *example) Now() time.Time {
	if e.host == nil {
		// Never registered, because the host refused the plugin before handing
		// it one. A zero clock is the honest answer for a plugin with no host,
		// and better than inventing one.
		return time.Time{}
	}
	return e.host.Now()
}

// serveNothing answers every request with 204. These routes exist to be
// enumerated and refused, never to be served; a body would only ever be
// reachable if the host mounted the routes of a plugin it had already refused,
// which is the specific failure the containment test looks for.
func serveNothing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// sidePanelNavItem is the nav contribution each example makes besides its page
// type. The href is inside this plugin's own prefix, because a nav item
// pointing outside it is a *different* violation and this package refuses one
// thing at a time.
func sidePanelNavItem() plugin.NavItem {
	return plugin.NavItem{
		ID:          ID + ".panel",
		Label:       "Example",
		Href:        "/plugin/" + ID + "/run",
		Icon:        "i-d20",
		MinimumRole: "player",
	}
}

// rightTopPanel is the panel contribution. The component is nil on purpose: the
// panel exists to be counted and then rolled back, never rendered, and a host
// that rendered it would panic on a nil component — which is the right way for a
// demo to fail loudly rather than ship a panel with no plugin behind it.
func rightTopPanel() plugin.Panel {
	return plugin.Panel{
		Slot:  plugin.SlotRightTop,
		Order: 0,
	}
}
