package main

import (
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/systems/dnd5e"
)

// The registry: one map entry per shipped plugin.
//
// This is the whole of "adding a plugin is one map entry", and its location is
// not arbitrary — it is forced by three constraints that no other package
// satisfies at once.
//
//   - It cannot be in `internal/plugin`. A plugin imports the package that
//     defines its interface, so `internal/systems/dnd5e` imports
//     `internal/plugin`, and a map naming `dnd5e.New()` there would close a
//     cycle. The vocabulary cannot know the implementations.
//   - It cannot be in `internal/systems/` or `internal/plugins/`. Those are
//     held to the plugin import boundary, which permits `plugin`, `md`,
//     `store`, `web`, `authz` and `secrets` — and deliberately not a sibling
//     plugin. A plugin that could import another plugin could import a plugin
//     that has been given something it should not have, and the boundary would
//     stop being a boundary.
//   - So it is here. `cmd` is outside `internal/`, so nothing in the dependency
//     order constrains it, and the only other package that could import both
//     sides is `app` — which cannot, because a plugin may import `web`, `web`
//     imports `httpapi`, and `httpapi` imports `app` for the build metadata.
//
// "Which plugins ship in this binary" is a statement about the build rather than
// about the library, and the package that builds the binary is the one place
// that fact belongs. `TestNoPluginSwitchInCore` scans here too — see the note
// below on why that is not automatic.
//
// The consequence worth stating: the registry is the one place in the codebase
// that may name a plugin id, and `TestNoPluginSwitchInCore` fails the build if a
// second one appears. That test is the reason this file is legible as the only
// place to add a system — and it is worth knowing that the test's scan set is
// derived from the dependency order, which does not list `cmd`. The gate was
// widened to cover it, because a registry the gate cannot see is a registry
// somebody can duplicate.
//
// `example` is deliberately absent. It is a plugin built to be refused, and
// offering it to the host would put a known failure in the boot report of every
// running campaign. Its own package drives `plugin.Load` directly to prove each
// refusal, which is the honest place for that evidence.
func builtinPlugins() map[string]plugin.Plugin {
	// The key is a string literal, not `dnd5e.ID`, and that is deliberate: the
	// architecture gate recognises a map literal of this exact type as a
	// registry, so writing the id out makes this file the one place the gate can
	// see. Referencing the constant instead would hide the registry from the very
	// test whose job is to say there is only one of it.
	return map[string]plugin.Plugin{
		"dnd5e": dnd5e.New(),
	}
}
