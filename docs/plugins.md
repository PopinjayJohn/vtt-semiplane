# Plugins

The plugin contract is **type vocabulary**, and this document is a map to it.
Every fact below is owned by a file in the tree; the table in each section names
the owner. Where the design proposes something the code does not contain, this
document says **not implemented** and says so again in
[What is not built yet](#10-what-is-not-built-yet).

**State of the tree, stated first, because a reader who assumes otherwise will
mis-plan:** the `internal/plugin` package — `doc.go`, `plugin.go`,
`plugin_test.go` — is the whole of it. No registry, no `Host` implementation, no
reserved-name table, no plugin route, no `/admin/plugins`. The only file outside
`internal/plugin` that imports the package is
[`internal/web/components_templ.go`](../internal/web/components_templ.go), and it
uses exactly one symbol, `plugin.WikiLink`.

## 1. What a plugin is, and what it is not

A plugin is **first-party Go code compiled into the binary**. Not loaded, not
fetched, not interpreted. `internal/plugin/doc.go` states this, and so does
`AGENTS.md` §7.

**There is no sandbox and no isolation.** A plugin shares the process address
space. It can read the database file, exfiltrate a secret, or crash the process.
Go's `plugin` stdlib package would not change that — same address space, and
unsupported on Windows, which is a release target. A Wasm host would cost the
`templ.Component` values that make the UI contract usable.

**This is not a security boundary, and no document should imply it is.** What the
contract actually buys is narrower, and worth stating precisely:

- **Capability narrowing against *accidental* damage.** A plugin that is handed a
  narrow surface cannot reach for something by habit. This is ergonomics, not
  containment.
- **One property that matters more than the rest: a plugin cannot ship
  JavaScript, a stylesheet, or a DOM handle.** `plugin.Host` has no method that
  contributes a script, a stylesheet, or a DOM enhancer. A plugin returns
  `templ.Component` values and Go values; the app shell and the stylesheet are
  core-owned. That is a property of the interface, not a review rule — a
  reviewer cannot forget to check for a method that does not exist. It is also
  why the link-preview interaction is implemented once in core rather than once
  per plugin.

**The security boundaries are elsewhere, and they are all enforced:**

| Boundary | Owner |
|---|---|
| Secret visibility — one predicate, no hand-rolled copies | [`internal/authz/predicate.go`](../internal/authz/predicate.go), `authz.SecretVisibleSQL` |
| No hand-rolled `visibility = 'literal'` anywhere | `TestNoHandRolledVisibilityPredicates` in [`internal/architecture_test.go`](../internal/architecture_test.go) |
| Response bodies scanned for unread secret plaintext | the tripwire; see `AGENTS.md` §6 |
| No outbound network in the request path | `AGENTS.md` §2 rule 5 |
| A plugin may not import `httpapi`, `auth`, `obs`, `sync`, `config`, `app` | `TestPluginImportsAreWithinBoundary` — see [§6](#6-the-import-boundary) |
| No core package branches on a plugin id | `TestNoPluginSwitchInCore` — see [§6](#6-the-import-boundary) |

## 2. The contract

Every type below is declared in
[`internal/plugin/plugin.go`](../internal/plugin/plugin.go). That file is the
contract; this table is an index of it.

| Type | What it is |
|---|---|
| `Plugin` | The one interface every plugin implements, of either kind. `Descriptor()`, `Register(ctx, Host)`, `Validate(Config)`, `Now()`. |
| `PluginCore` | The process-agnostic half: `CoreTypes()`, `MarkdownExtenders()`, `ConfigSchema()`. Produces data, not markup. |
| `PluginUI` | The in-process half: `Panels()`, `RegisterRoutes(RouteMounter)`, `NavItems()`, `Summaries()`. |
| `Descriptor` | Everything a plugin declares about itself. Static data; the version gate and the `Kind` rules run against it before `Register` is called. |
| `Kind` | `KindSystem` or `KindFeature`. See [§3](#3-kind-system-and-feature). |
| `Capability` / `Capabilities` | A declared name, and the `uint16` bitmask the host checks. See [§4](#4-capabilities). |
| `Host` | The narrow, capability-scoped surface a plugin is given. Shape fixed; **no implementation exists yet**. |
| `RouteMounter` | A named alias for `*chi.Mux`, so the import-boundary test has one name to look for. |
| `PageType` | A registered page type with an optional custom editor and viewer. |
| `SchemaField` | One editable frontmatter field: `Key`, `Name`, `Type`, `Options`, `Required`, `Help`. `Type` is one of `text`, `textarea`, `number`, `bool`, `select`, `tags`. |
| `Panel` | A panel for a named slot: `Slot`, `Order`, `Component templ.Component`, `PageType`. The component is escaped by construction; a plugin can still write `templ.Raw`, which is why the review checklist mentions it. |
| `Slot` / `KnownSlots` | The six regions core renders: `right-top`, `right-mid`, `right-bottom`, `left-bottom`, `editor-toolbar`, `page-actions`. |
| `NavItem` | One sidebar link. `Badge` is evaluated per request with the request's own principal, so it is authz-filtered by construction. `MinimumRole` is the role needed for the item to appear. |
| `SearchResolver` | Contributes derived rows to search. Requires `CapSearchResolvers`. |
| `IndexRow` | One such row: `Kind`, `Title`, `Href`, `Summary`, `Score`, `Ref`. `Summary` is a short public excerpt and is never secret-derived. |
| `SummaryProvider` | Serves an authz-filtered summary of one page for the core link preview. `ID()`, `Summary(ctx, pageID)`. |
| `Migration` | One plugin-owned schema step, applied by the host inside the host's migration transaction. `Version`, `Name`, `SQL`. Additive only. |
| `Config` | A plugin's namespaced configuration, already typed. `Get`, `Bool`, `Int`. |
| `KV` / `Level` | The log key/value pair and severity handed to `Host.Log`. |
| `WikiLinkAttr` / `WikiLink` | `data-wikilink`, and the attribute map for a link to a page id. See [§7](#7-link-previews). |

**Why the interface is split in two.** `PluginCore` is everything a plugin does
that produces data rather than markup; `PluginUI` is the part that needs Go in
process. The split exists so a future subprocess or Wasm host can implement
`PluginCore` alone, without `templ.Component` values crossing the boundary. It
is done now, while nothing depends on the unsplit shape, because an interface
split later is a breaking change and `APILevel` would have to be bumped for it.

## 3. `Kind`: system and feature

`KindSystem` models a roleplaying game — registered page types, sheets, rules.
`KindFeature` adds system-agnostic functionality. One interface, one lifecycle,
one route prefix; `Kind` exists only so the host can enforce the rules that
actually differ.

**The one rule that differs: a `KindFeature` plugin may not register page
types.** `Descriptor.PageTypes` MUST be empty when `Kind` is `KindFeature`; a
violation is a boot error for that plugin alone. `Kind.Valid()` is the check on
the value itself; nothing enforces the `PageTypes` rule yet, because nothing
reads a `Descriptor` yet.

**The alternative that needs no plugin at all.** A *page-type convention* — a
plain `type:` string in frontmatter that the core markdown viewer renders like
any other page — is free-form and is not a registered page type. So
`type: houserule` works with no game system installed: the page is indexed, it
produces backlinks, and it renders in Obsidian with the app closed. The
`PageType` doc comment in `plugin.go` draws exactly this distinction.

## 4. Capabilities

A plugin declares capabilities; the host gates what it may actually do.
Declaration is checked against the host's own grant, and declaring something the
host does not hold is a startup error for that plugin. At runtime a capability
is a bitmask (`type Capabilities uint16`); the `[]Capability` slice is
declaration sugar. `ParseCapabilities` rejects an unknown name rather than
ignoring it.

The eleven constants, in `AllCapabilities` order:

| Capability | Grants |
|---|---|
| `CapCharacterSheet` | the character page type and per-field rolls |
| `CapMaps` | the map page type, tokens and fog |
| `CapEncounters` | the encounter builder and initiative tracker |
| `CapDice` | dice notation and the roll UI |
| `CapRules` | rules reference pages |
| `CapUIPanels` | contributing sidebar and editor panels |
| `CapSidebarNav` | contributing left-sidebar navigation items |
| `CapPageSummaries` | serving per-page summaries for link previews |
| `CapSearchResolvers` | contributing derived search rows |
| `CapBacklinks` | contributing extra related-entity resolvers |
| `CapExporters` | contributing export formats |

**What the host discards without a capability — designed, not implemented.** The
rules below are stated in the doc comments of `Descriptor`, `Panel` and
`Host`, which is the owner:

| Capability absent | The host discards |
|---|---|
| `CapUIPanels` | `Host.RegisterPanels` results, with a warning. A `Panel` naming a slot outside `KnownSlots` is dropped regardless of capability. |
| `CapSidebarNav` | `Descriptor.NavItems` at boot, with a warning — and the sidebar renders no plugin group at all, not an empty one. |
| `CapSearchResolvers` | `Descriptor.SearchResolvers`; the host never calls them. |
| `CapPageSummaries` | the plugin's summary endpoint is never mounted, and the core link-preview interaction does not bind. |
| `CapMaps`, `CapEncounters`, `CapDice`, `CapCharacterSheet`, `CapRules`, `CapBacklinks`, `CapExporters` | the matching reserved page-type ids and route segments (see [§5](#5-reserved-names)); the host is to refuse a page type whose id is reserved and to refuse a route pattern under a reserved segment. |

None of the above is implemented. `Capabilities` is a type, a bitmask, and a
parse function; nothing outside `internal/plugin` reads one.

**The absence-degrades rule.** When no plugin holds `CapSidebarNav`, the sidebar
renders no plugin group rather than an empty heading. When no plugin holds
`CapPageSummaries`, the preview interaction does not bind and links behave as
plain links. A nav link that navigates to a 404, or a hover affordance with
nothing behind it, is a bug. **The absence of a plugin must degrade to a working
app, never to a broken control.**

## 5. Reserved names

**The rule, as designed:** a plugin may claim a reserved page-type id or a
reserved route segment only if it is `KindSystem` *and* declares the matching
capability. A `KindFeature` plugin may claim none of them, regardless of which
capabilities it holds. The check runs before anything is added to a registry, so
a violation disables that one plugin and rolls its own migration transaction
back — a contained failure, not a corrupt boot.

**Where the table lives: nowhere yet.** The design says the reserved
page-type ids and route segments are defined once, in
`internal/plugin/reserved.go`. **That file does not exist.** The package is
`doc.go`, `plugin.go`, `plugin_test.go` and nothing else, and `plugin.go`
mentions the reserved names in exactly two places: the `Descriptor.ValidateID`
doc comment ("not one of the reserved names") and `doc.go`'s statement that the
reserved-name table arrives in the plugin phase.

So: **the rule is designed; the table and the check are not implemented.**
`Descriptor.ValidateID` currently checks that an id is non-empty, lowercase, and
made only of `a`–`z`, `0`–`9` and `-`. It does not check the reserved set.

## 6. The import boundary

Enforced by `TestPluginImportsAreWithinBoundary` in
[`internal/architecture_test.go`](../internal/architecture_test.go), which walks
`internal/systems/**` and `internal/plugins/**` — skipping either directory that
does not exist, so the test is vacuous until the first plugin lands.

A plugin **may** import:

| Package | |
|---|---|
| `plugin` | the contract itself |
| `md` | the markdown pipeline |
| `store` | read-only constructors and typed queries |
| `web` | templ components |
| `authz` | the policy and the canonical predicate |
| `secrets` | fence parse/serialise, redaction |
| `templ`, `goldmark`, `chi`, stdlib | the rest |

A plugin **may not** import, and the test carries the reason so a failure
explains the rule:

| Package | Why not |
|---|---|
| `httpapi` | it would bypass the host's per-request redaction and the `Perm` middleware |
| `auth` | it would bypass session handling and the `Principal` capture |
| `obs` | it would bypass the redacting log handler |
| `sync` | it would write the index behind the indexer's back |
| `config` | it would read core configuration a plugin has no business seeing |
| `app` | it is the composition root, not a library |

Note the difference from the design plan, which allowed `plugin`, `md`, `store`,
`web`, `templ`, `goldmark`, `chi` and stdlib, and forbade `httpapi`, `sync`,
`auth` and `obs`. The code adds `authz` and `secrets` to the allow-list — the
redactor and the policy have to be reachable for a panel to be authz-filtered by
construction — and adds `config` and `app` to the forbidden list. **The test is
the authority; the plan is out of date here.**

The companion test is `TestNoPluginSwitchInCore`: no core package may contain
the string `"<plugin-id>"`. It walks `app`, `httpapi`, `web`, `vault`, `store`,
`md`, `search`, `sync`, `authz`, `secrets`, `auth`, `obs` and `config` for the
ids of registered plugins. **It currently skips** — `registeredPluginIDs` finds
no `ID: "…"` literal in a non-test file under `internal/systems/` or
`internal/plugins/`, because `internal/systems/core` and
`internal/systems/dnd5e` contain only a `doc.go` each. Adding the first real
plugin turns it on.

## 7. Link previews

**The division of labour: the plugin supplies content, core owns behaviour.**
Core renders every internal link carrying `data-wikilink="{pageID}"` — the
attribute is `plugin.WikiLinkAttr`, and `plugin.WikiLink(pageID)` builds the
attribute map. The value is an integer page id, never a title, a path, or any
content; `TestWikiLinkCarriesOnlyThePageID` pins that. A plugin that wants its
links previewable emits the attribute and never emits its own hover behaviour.

Core then owns hover, keyboard focus, the transient card, the pin toggle, the
floating pane, `Esc`, and the ARIA wiring — once, for every link. The plugin
mounts `GET /plugin/{id}/summary/{pageID}` and returns a `templ.Component` card
body through `SummaryProvider`.

The alternative — a plugin injecting its own JS and DOM enhancer — would mean N
implementations of focus management, an arbitrary-script hole in the CSP, and
per-plugin accessibility bugs. That is why this is core.

**A summary of a page the viewer may not read must return 404, byte-identical
to navigating to it.** A preview must not become a way to probe for pages. The
summary text is produced by the same redactor and the same
`authz.SecretVisibleSQL` as a page render, and its length is capped so a page of
hidden secrets cannot be inferred from response size.

**None of this is implemented.** There is no `SummaryProvider` implementation,
no summary route, and `web/static/app.js` contains no preview code. What exists
is the vocabulary: `plugin.SummaryProvider`, `plugin.WikiLinkAttr`,
`plugin.WikiLink`, and `CapPageSummaries`.

## 8. A worked example

**Illustrative only.** The `houserules` plugin is not in this repository. This
sketch shows the shape a `KindFeature` takes against the real contract, and every
identifier in it exists in `internal/plugin/plugin.go`.

A feature plugin that adds a curated index of house rules, where the rules
themselves are ordinary pages carrying `type: houserule` in frontmatter and need
no page-type registration at all:

```go
// Illustrative. Not in this repository.
package houserules

import (
	"context"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
)

type Plugin struct{ host plugin.Host }

func (*Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:           "houserules",
		Name:         "House Rules",
		Kind:         plugin.KindFeature,
		Version:      "0.1.0",
		APILevel:     plugin.APILevel,
		Capabilities: []plugin.Capability{plugin.CapSidebarNav, plugin.CapSearchResolvers},
		// PageTypes stays empty: a KindFeature may not register page types,
		// and `type: houserule` is a frontmatter convention, not a
		// registered type.
		PageTypes: nil,
		NavItems: []plugin.NavItem{{
			ID:          "houserules",
			Label:       "House Rules",
			Href:        "/plugin/houserules",
			Order:       40,
			MinimumRole: "player",
			Badge: func(ctx context.Context) (string, bool) {
				// Evaluated per request with the request's own
				// principal, so the count is authz-filtered by
				// construction. A hidden rule is absent from the
				// number, not greyed out.
				return "12", true
			},
		}},
	}
}

func (p *Plugin) Register(ctx context.Context, h plugin.Host) error {
	p.host = h
	// h.Capability().Has(plugin.CapSidebarNav) is a check the host has
	// already made: it discards NavItems without the capability. So this
	// is about branching, not about being believed.
	if !h.Capability().Has(plugin.CapSidebarNav) {
		return nil
	}
	h.RegisterPanels()
	return nil
}

func (*Plugin) Validate(cfg plugin.Config) error { return nil }

// Now returns the host clock, never time.Now(), so a test can freeze it.
func (p *Plugin) Now() time.Time { return p.host.Now() }
```

The parts that matter, and why:

- **No page types.** The content model is a frontmatter convention, so the
  feature plugin needs no `type: houserule` registration, and the pages keep
  working in Obsidian with the app closed.
- **The badge is a closure over the request's context**, not a number computed at
  register time. That is what makes it authz-filtered by construction rather than
  by a filter someone remembered to apply.
- **Every route sits under `/plugin/{id}/`.** `NavItem.Href` and `Host.RegisterRoutes`
  both state that the host validates this and that a violation is a registration
  error rather than a broken link. **Not implemented yet** — there is no sub-router.
- **The rule list filters in SQL** with `authz.SecretVisibleSQL`, and its `COUNT`
  uses the identical predicate. A list that shows one row while counting three is
  an existence leak.
- **A hidden rule is absent, not greyed out.**

## 9. Adding a plugin — checklist

The design says a plugin requires exactly: one directory under
`internal/systems/<id>/`, one map entry in the registry, and sample content if it
needs any. No core file changes.

- [ ] Pick an id: kebab-case, lowercase, stable forever.
- [ ] Choose `KindSystem` or `KindFeature`. If feature, `Descriptor.PageTypes` is
      empty.
- [ ] Set `APILevel` to `plugin.APILevel`.
- [ ] Declare only the capabilities you use, and check each at the point of use
      via `h.Capability().Has(...)`.
- [ ] Every route under `/plugin/{id}/`. The host is to validate the prefix; a
      violation should be a registration error, not a broken link.
- [ ] Every query that can return a secret-derived row carries
      `authz.SecretVisibleSQL`, and its `COUNT` carries the identical predicate.
- [ ] No `os`, `net` or `exec` outside `app`; no reach-through into `store`'s
      unexported internals; no reflection into `Principal`.
- [ ] No `templ.Raw` on anything vault-derived. `Panel` is a `templ.Component`
      and is escaped by construction; do not opt out.
- [ ] No JavaScript, CSS, or DOM handle. There is no method for it.
- [ ] `Plugin.Now()` returns the host clock, never `time.Now()`, so a test can
      freeze it.
- [ ] Sample content, if the plugin needs any.

## 10. What is not built yet

Everything below is designed and absent. If you are planning against it, the
cost is in the gap, not in the interface.

| Thing | State |
|---|---|
| `Plugin`, `Descriptor`, `Kind`, `Capability`, `Capabilities`, `PluginCore`, `PluginUI`, `Host` (interface), `PageType`, `SchemaField`, `Panel`, `Slot`, `NavItem`, `SearchResolver`, `IndexRow`, `SummaryProvider`, `Migration`, `Config`, `KV`, `Level`, `RouteMounter`, `WikiLinkAttr`, `WikiLink` | **exist** in [`internal/plugin/plugin.go`](../internal/plugin/plugin.go) |
| The plugin registry (a map id → `Plugin`, iterated deterministically at boot) | **not implemented** |
| `Host` — the *implementation*. The interface shape is fixed and stated; no type implements it. | **not implemented** |
| The reserved-name table, `internal/plugin/reserved.go` | **not implemented** |
| The registration lifecycle: version gate, per-plugin migration transaction, id-collision detection, rollback, the boot report | **not implemented** |
| Capability enforcement at the host (anything discarding a panel, nav item, resolver, or route) | **not implemented** |
| Plugin routes under `/plugin/{id}/`, and the sub-router already prefixed and middleware-wrapped | **not implemented** |
| `/admin/plugins` (the boot report) | **not implemented** |
| The link-preview interaction in `web/static/app.js` | **not implemented** |
| The `houserules` and `linkpreview` feature plugins, and any real `dnd5e` system plugin | **not implemented**; `internal/systems/core` and `internal/systems/dnd5e` contain a `doc.go` each and nothing else |

**Two tests that would pass vacuously today,** which the design treats as worse
than no test: `TestPluginImportsAreWithinBoundary` skips both
`internal/systems` and `internal/plugins` if the directory is absent (it walks
`internal/systems`, which exists, but finds only `doc.go`), and
`TestNoPluginSwitchInCore` calls `t.Skip("no plugins registered yet")`.

## Where the design lives

The reasoning behind this contract — the `Plugin` interface as the plan first
sketched it, the capability-enforcement table, the registration lifecycle, the
three example plugins, and the isolation analysis — is in the design plan at
`.kilo/plans/1790590471729-ttrpg-wiki-vtt-architecture.md` (§2, §9.5, §11,
§12). **`.kilo/` is gitignored, so the plan is not in the repository and this
document is the durable copy of what survives into the code.** Where the two
disagree, the code is right and the plan is a bug — see `AGENTS.md` §0 for the
recorded case where that was not academic.
