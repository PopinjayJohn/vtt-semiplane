# Plugins

The plugin contract is **type vocabulary**, and this document is a map to it.
Every fact below is owned by a file in the tree; the table in each section names
the owner. Where the design proposes something the code does not contain, this
document says **not implemented** and says so again in
[What is not built yet](#10-what-is-not-built-yet).

**State of the tree, stated first, because a reader who assumes otherwise will
mis-plan:** this document is a map, and the state moves. [§10](#10-what-is-not-built-yet)
records what exists; the *enforcement* claims below are each owned by a named
test in [`internal/architecture_test.go`](../internal/architecture_test.go), and
a claim in this document that no test backs is a bug in this document — see
`AGENTS.md` §0 for the recorded case where that was not academic.

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
| No core package dispatches on a plugin id | `TestNoPluginSwitchInCore` — see [§6](#6-the-import-boundary) |
| …and that neither of the two above is checking nothing | `TestTheArchitectureGatesHaveSomethingToCheck` — see [§6](#6-the-import-boundary) |
| A reserved name is claimable only with its capability | `TestEveryReservedNameIsClaimableOnlyWithItsCapability` — see [§5](#5-reserved-names) |

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
the value itself, and the rule on the declaration is enforced twice over — once
on the static `Descriptor` in
[`internal/plugin/lifecycle.go`](../internal/plugin/lifecycle.go), and once at
registration in [`internal/plugin/host.go`](../internal/plugin/host.go), because
a plugin that registers page types without having declared them has to be
refused too. Both refusals disable that one plugin and boot continues.

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

**What the host discards without a capability.** The table below is an index
into the code that decides it, not a restatement of it: each row's rule is
written down once, in the doc comment of the `Descriptor`, `Panel` or `Host`
field it is about, and enforced in
[`internal/plugin/host.go`](../internal/plugin/host.go). A refusal is a warning
in the boot report, not a silent discard.

| Capability absent | The host discards |
|---|---|
| `CapUIPanels` | `Host.RegisterPanels` results, with a warning. A `Panel` naming a slot outside `KnownSlots` is dropped regardless of capability. |
| `CapSidebarNav` | `Descriptor.NavItems` at boot, with a warning — and the sidebar renders no plugin group at all, not an empty one. |
| `CapSearchResolvers` | `Descriptor.SearchResolvers`; the host never calls them. |
| `CapPageSummaries` | the plugin's summary endpoint is never mounted, and the core link-preview interaction does not bind. |
| `CapMaps`, `CapEncounters`, `CapDice`, `CapCharacterSheet`, `CapRules`, `CapBacklinks`, `CapExporters` | the matching reserved page-type ids and route segments (see [§5](#5-reserved-names)); the host refuses a page type whose id is reserved and a route pattern under a reserved segment, via `plugin.CheckReservedPageType` and `plugin.CheckReservedRoute`. |

Two of those rows are not implemented yet, and the table says which: the
`CapPageSummaries` row describes behaviour that needs the link-preview
interaction, and the absence-degrades rule below depends on the same missing
piece. `Capabilities` itself is a bitmask with a parse function that rejects an
unknown name, and the host now reads one — the reserved-name half of the last
row is the part with a test behind it.

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

**Where the table lives: `internal/plugin/reserved.go`**, which is also where
`Claimable` lives, so the registry and the rule that decides what the registry
may hold cannot drift apart. The tables themselves are the authority; this
document does not restate them, for the reason in `AGENTS.md` §0 — a document
that repeats a table the code owns can be wrong while looking authoritative.

Two things the table's shape is easy to get wrong, both of which the code
handles and neither of which this document needs to repeat:

- A reserved route segment is matched **anywhere** in a registered pattern, not
  only at the start, because the shapes that collide are nested.
- A `map[string]plugin.Plugin` keyed by plugin id is *the registry's own type*,
  which is what makes a second one outside `internal/plugin` detectable at all.

**Two tests in
[`internal/architecture_test.go`](../internal/architecture_test.go) hold the
tables to the rule**, and they are the reason this section can say the rule is
enforced rather than designed:

- `TestEveryReservedNameIsClaimableOnlyWithItsCapability` walks **every** entry in
  both tables and asserts all three of `Claimable(KindSystem, All(), need)` is
  true, `Claimable(KindFeature, All(), need)` is false, and
  `Claimable(KindSystem, All() minus need, need)` is false. An entry that is
  claimable by nobody is a name the host holds for no one, and the third case is
  what makes holding the capability *be* the grant.
- `TestTheReservedTablesHaveNoDuplicates` exists because a duplicate is a table
  where the second row silently wins: `ReservedPageTypeFor` and
  `RouteReservation` both return the first match, so a segment listed twice
  leaves the second capability unable to claim a name it appears to own.

**One gap worth knowing, because the test works around it rather than on top of
it:** `plugin.Capabilities` has `With` but no `Without`, so the test builds the
"missing one" set by omission over the exported `plugin.AllCapabilities`. A
`Without` method is the natural API and belongs to the plugin package; until it
exists, the omission is spelled out in the test rather than hidden.

## 6. The import boundary

Enforced by `TestPluginImportsAreWithinBoundary` in
[`internal/architecture_test.go`](../internal/architecture_test.go), which walks
`internal/systems/**` and `internal/plugins/**`. The walk **recurses**, which is
load-bearing rather than tidy: a plugin is a *directory*
(`internal/systems/dnd5e/`), and the first version of this gate listed one
directory and stopped, so it reported zero plugins no matter what was on disk and
skipped forever. The test skips only when no plugin package has a source file
beyond a `doc.go`, and [the test below](#the-tests-that-would-otherwise-pass-vacuously)
fails while that is true.

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

The companion test is `TestNoPluginSwitchInCore`: no core package may dispatch on a
plugin id. **What it scans, and how, is the part worth reading**, and the code
comment on `findPluginIDMentions` is the authority.

- The set of scanned packages is **derived** from the dependency order plus the
  exempt packages, not written out, and `TestNoPluginSwitchScansEveryCorePackage`
  checks the derivation against the directories that are actually on disk. A
  hand-written list is a rule that quietly narrows the day a core package is
  added, and a narrowed rule is indistinguishable from a rule that held.
- The plugin ids come from **parsing** each plugin's `plugin.Descriptor`
  literals with `go/parser` and resolving `ID: ID` through the package's own
  string constants. Both spellings are ordinary Go, and a scan that read only
  the inline literal would go quiet on the tidier of them. A `Descriptor` whose
  `ID` is neither a literal nor a package const is **reported**, not skipped:
  a plugin the gate cannot read is a gate that has stopped applying to it.
- The match is over **dispatch sites**, not over occurrences of the word: a
  comparison, a switch arm, an index expression, or a key of a
  `map[string]plugin.Plugin` literal. That last one is the registry's own type,
  so a copy of the registry outside `internal/plugin` is exactly the failure the
  rule is for.
- **The reason it is not a substring or word-boundary match is empirical, and
  the counter-example is in the tree:** `internal/md/callout.go` contains
  `"example": true` in a table of callout *kinds*, and a literal-substring scan
  reports that file as branching on the plugin `example`. A gate that reports a
  lie is worse than one that stays quiet, because the habit it teaches is to
  ignore it. `TestNoPluginSwitchGateFires` pins both directions over synthetic
  files in `t.TempDir()`, including that counter-example.

### The tests that would otherwise pass vacuously

Both gates above **skip** when the tree holds no plugin, because there is
nothing to check. A skip is honest, and it is also indistinguishable from a rule
that held — so a third test makes skipping impossible to mistake for passing:

**`TestTheArchitectureGatesHaveSomethingToCheck` fails, rather than skips, while
the tree holds no plugin.** It asserts that the id extraction finds at least one
plugin id and that the boundary walk finds at least one plugin source file beyond
a `doc.go`, and its failure message names the directories that would satisfy it.
A guard that skips is the thing it was written to prevent.

This is the whole reason the two gates are trustworthy rather than merely
present: the day someone deletes the last plugin, this test fails and says they
deleted the *evidence* the gates run on, not that the gates went quiet.

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

- [ ] Pick an id: kebab-case, lowercase, stable forever. Declare it as a string
      literal or a package-level string const in your `Descriptor` — the
      architecture tests read your `Descriptor` with `go/parser`, and an `ID`
      that is neither is reported rather than skipped, because a plugin the
      boundary gate cannot read is a plugin the gate has stopped covering.
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
| The reserved-name table and `Claimable` | **exist** in [`internal/plugin/reserved.go`](../internal/plugin/reserved.go); held to the rule by the two tests named in [§5](#5-reserved-names) |
| The plugin registry, the boot report, and the `Host` implementation | **exist** in [`internal/plugin/registry.go`](../internal/plugin/registry.go) and [`internal/plugin/host.go`](../internal/plugin/host.go) — see the file for what it guarantees |
| The registration lifecycle: version gate, per-plugin migration transaction, id-collision detection, rollback | **exists** in [`internal/plugin/lifecycle.go`](../internal/plugin/lifecycle.go) |
| `/admin/plugins` (the boot report), registered in the route table per `AGENTS.md` §2.7 | **exists** — [`internal/httpapi/admin_plugins.go`](../internal/httpapi/admin_plugins.go) |
| `internal/systems/example` — a deliberately-refusing plugin that demonstrates each refusal rule | **exists**, and is what the two boundary gates in [§6](#6-the-import-boundary) run on |
| A real `dnd5e` system plugin | **not implemented**; `internal/systems/dnd5e` holds a `doc.go` and nothing else |
| The `houserules` and `linkpreview` feature plugins | **not implemented** |
| The link-preview interaction in `web/static/app.js` | **not implemented**; `plugin.WikiLink` and `SummaryProvider` are the vocabulary it will use |

**The two tests this document used to have to apologise for are now enforced.**
`TestPluginImportsAreWithinBoundary` and `TestNoPluginSwitchInCore` each skip
when there is no plugin to check, and each is now backed by
`TestTheArchitectureGatesHaveSomethingToCheck`, which **fails** rather than skips
while the tree holds none. See
[§6](#the-tests-that-would-otherwise-pass-vacuously). The rule of thumb: a skip
here means the gate had nothing to say, and the guard test is what says so out
loud.

## Where the design lives

The reasoning behind this contract — the `Plugin` interface as the plan first
sketched it, the capability-enforcement table, the registration lifecycle, the
three example plugins, and the isolation analysis — is in the design plan at
`.kilo/plans/1790590471729-ttrpg-wiki-vtt-architecture.md` (§2, §9.5, §11,
§12). **`.kilo/` is gitignored, so the plan is not in the repository and this
document is the durable copy of what survives into the code.** Where the two
disagree, the code is right and the plan is a bug — see `AGENTS.md` §0 for the
recorded case where that was not academic.
