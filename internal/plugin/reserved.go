package plugin

import (
	"fmt"
	"sort"
	"strings"
)

// Reserved names, and the one rule that governs them.
//
// A reserved name is a page-type id or a route segment the host owns until a
// plugin of the right kind and the right capability claims it. The rule is
// deliberately narrow and deliberately checked in one place:
//
//	a reserved name may be claimed only by a KindSystem that declares the
//	matching capability.
//
// Both halves matter. The kind, because a feature plugin has no business
// registering a game system's vocabulary — `houserules` claiming `character`
// would be a feature plugin deciding what a character sheet is. The capability,
// because a system plugin that does not hold CapMaps has no business mounting
// `/map` however much it wants to: holding the capability *is* the grant, and
// making the grant a separate concept from the declaration is how a permission
// system grows a second answer.
//
// The check lives here rather than in the registry because this is the table
// the registry consults, and a rule that lives next to the thing it decides
// cannot be forgotten by an agent adding a plugin.
//
// **What the check is for.** It is not a sandbox — §11 of the design plan is
// explicit that a compiled-in plugin shares the address space and can read
// whatever it likes. It is a check against *accidental* collision: two
// first-party plugins both deciding that `character` is theirs, or a feature
// plugin shipping a `/roll` route that the dice system also ships, and one of
// them winning at random depending on map iteration order.

// ReservedPageType is a page-type id held for a capability.
type ReservedPageType struct {
	// ID is the frontmatter `type:` value.
	ID string
	// Name is the human label, for the error message.
	Name string
	// Capability is the grant a KindSystem must declare to claim it.
	Capability Capability
}

// ReservedRoute is a path segment held for a capability.
//
// The segment is matched anywhere in a plugin's registered pattern, not just at
// the start, because the shapes that collide are nested: `/character/{id}/hp`
// collides with `/character` just as surely as `/character` does.
type ReservedRoute struct {
	// Segment is the path segment, without slashes.
	Segment string
	// Name is the human label, for the error message.
	Name string
	// Capability is the grant a KindSystem must declare to claim it.
	Capability Capability
}

// reservedPageTypes is every page-type id the host holds.
//
// These are the types a future VTT, map or encounter work will need, and they
// are reserved now rather than when they are needed: a name that is reserved
// after a plugin has claimed it is a name that is already claimed.
var reservedPageTypes = []ReservedPageType{
	{ID: "character", Name: "character sheet", Capability: CapCharacterSheet},
	{ID: "map", Name: "map", Capability: CapMaps},
	{ID: "token", Name: "token", Capability: CapMaps},
	{ID: "encounter", Name: "encounter", Capability: CapEncounters},
	{ID: "rule", Name: "rules reference", Capability: CapRules},
}

// reservedRoutes is every route segment the host holds.
var reservedRoutes = []ReservedRoute{
	{Segment: "map", Name: "map", Capability: CapMaps},
	{Segment: "fog", Name: "fog of war", Capability: CapMaps},
	{Segment: "token", Name: "tokens", Capability: CapMaps},
	{Segment: "encounter", Name: "encounter", Capability: CapEncounters},
	{Segment: "initiative", Name: "initiative", Capability: CapEncounters},
	{Segment: "roll", Name: "dice roll", Capability: CapDice},
	{Segment: "character", Name: "character sheet", Capability: CapCharacterSheet},
}

// ReservedPageTypes returns the reserved page-type ids, sorted, for the boot
// report and the authoring guide. It returns a copy: the table is package state
// and a caller that could sort it in place could corrupt every later check.
func ReservedPageTypes() []ReservedPageType {
	out := make([]ReservedPageType, len(reservedPageTypes))
	copy(out, reservedPageTypes)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ReservedRoutes returns the reserved route segments, sorted, for the same
// reason ReservedPageTypes returns a copy.
func ReservedRoutes() []ReservedRoute {
	out := make([]ReservedRoute, len(reservedRoutes))
	copy(out, reservedRoutes)
	sort.Slice(out, func(i, j int) bool { return out[i].Segment < out[j].Segment })
	return out
}

// ReservedPageTypeFor returns the reservation for a page-type id, if any.
func ReservedPageTypeFor(id string) (ReservedPageType, bool) {
	for _, r := range reservedPageTypes {
		if r.ID == id {
			return r, true
		}
	}
	return ReservedPageType{}, false
}

// RouteReservation reports the first reserved segment a pattern claims.
//
// "First" is in table order rather than in the pattern's own order, so that two
// colliding patterns produce the same error whichever is registered first — the
// alternative is a boot report whose contents depend on map iteration order,
// which makes a reproducible failure unreproducible.
//
// An empty pattern matches nothing and is not a reservation violation; a
// malformed pattern is a different error, raised by the caller, because
// "reserved" and "invalid" are different problems with different fixes.
func RouteReservation(pattern string) (ReservedRoute, bool) {
	trimmed := strings.Trim(pattern, "/")
	if trimmed == "" {
		return ReservedRoute{}, false
	}
	for _, part := range strings.Split(trimmed, "/") {
		// A chi parameter or wildcard is not a literal segment, so it cannot
		// collide with a reserved one: `/plugin/dnd5e/{id}` reserves nothing, and
		// refusing it would make every parameterised route illegal.
		if part == "" || strings.HasPrefix(part, "{") || part == "*" {
			continue
		}
		for _, r := range reservedRoutes {
			if part == r.Segment {
				return r, true
			}
		}
	}
	return ReservedRoute{}, false
}

// Claimable reports whether a plugin of this kind and these capabilities may
// claim a reserved page-type id or route segment.
//
// It is exported because the registry and the test both need the same answer,
// and two implementations of "may this plugin claim that" is the failure this
// table exists to prevent.
func Claimable(kind Kind, granted Capabilities, need Capability) bool {
	// Both conditions, and the kind check is not a formality: a feature plugin
	// is refused every reserved name even when it holds the capability, because
	// a capability says what a plugin may *do* and a kind says what vocabulary
	// it may *speak*. `linkpreview` holding CapMaps would still not make it a
	// map system.
	return kind == KindSystem && granted.Has(need)
}

// CheckReservedPageType reports the error a KindSystem without the matching
// capability gets for claiming a reserved page-type id.
func CheckReservedPageType(id string, kind Kind, granted Capabilities) error {
	r, reserved := ReservedPageTypeFor(id)
	if !reserved {
		return nil
	}
	if Claimable(kind, granted, r.Capability) {
		return nil
	}
	return fmt.Errorf("plugin %s may not claim the reserved page type %q: it is held for the %q capability, and only a %s declaring that capability may claim it",
		kind, id, r.Capability, KindSystem)
}

// CheckReservedRoute reports the error for a registered pattern that claims a
// reserved route segment.
func CheckReservedRoute(pattern string, kind Kind, granted Capabilities) error {
	r, reserved := RouteReservation(pattern)
	if !reserved {
		return nil
	}
	if Claimable(kind, granted, r.Capability) {
		return nil
	}
	return fmt.Errorf("plugin %s may not register the route %q: the %q segment is reserved for the %q capability, and only a %s declaring that capability may claim it",
		kind, pattern, r.Segment, r.Capability, KindSystem)
}
