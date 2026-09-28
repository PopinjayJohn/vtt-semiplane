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
| `CapSearchResolvers` | `Descriptor.SearchResolvers`; the rows are merged into `/search` and `/api/search` under the resolver's own kind badge. |
| `CapPageSummaries` | the provider is contributed to the registry, core's summary route dispatches to it, and with none registered the preview interaction does not bind. |
| `CapMaps`, `CapEncounters`, `CapDice`, `CapCharacterSheet`, `CapRules`, `CapBacklinks`, `CapExporters` | the matching reserved page-type ids and route segments (see [§5](#5-reserved-names)); the host refuses a page type whose id is reserved and a route pattern under a reserved segment, via `plugin.CheckReservedPageType` and `plugin.CheckReservedRoute`. |

`Capabilities` is a bitmask with a parse function that rejects an unknown name,
and the host reads one. The `CapPageSummaries` row and the absence-degrades rule
below both depend on the link-preview interaction, which is in
`web/static/app.js` and is bound only when the shell's `previews` signal says a
provider is registered.

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
supplies a `templ.Component` card body through `SummaryProvider`.

The alternative — a plugin injecting its own JS and DOM enhancer — would mean N
implementations of focus management, an arbitrary-script hole in the CSP, and
per-plugin accessibility bugs. That is why this is core.

**A summary of a page the viewer may not read must return 404, byte-identical
to navigating to it.** A preview must not become a way to probe for pages. The
summary text is produced from `page_text.body`, which the indexer writes from
`md.Doc.PublicBody()` and nothing else — so a secret body is not in the table to
be selected, and the guarantee is a property of what is stored rather than of a
filter a caller has to remember. Its length is capped in SQL (`substr`, at
`store.SummaryExcerptMaxChars` characters) so a page of hidden secrets cannot be
inferred from response size, and a summary of a page with no public text is
declined rather than served empty.

**The route is core's, and that is a deliberate divergence from the plan.** §2.8.2
of the plan describes the *plugin* mounting `GET /plugin/{id}/summary/{pageID}`.
The code does not do that, because the byte-identical 404 above is enforced by
`httpapi.writeError`, which is unexported and renders a fixed copy table with
nothing in the model that could differ between two renderings. A plugin cannot
reach it — `httpapi` is on the import boundary's forbidden list — so a
plugin-owned summary route could only approximate the requirement, and a preview
that renders a distinguishable 404 is the probe the requirement exists to
prevent. So core owns the route, applies the policy and the rate limit, and
decline means one answer: `writeError(404)`. The plugin supplies content; core
owns behaviour, one layer further in than the plan says.

Implemented in `internal/httpapi/preview.go` (the route) and
`internal/systems/linkpreview` (the card). The summary path is a core constant
in `web/static/app.js`, and the shell seeds `data-signals` with a `previews`
boolean so a build with no provider binds no hover handler at all.

## 8. A worked example

`internal/systems/houserules` is in this repository and is the `KindFeature`
worked example: a sidebar nav group, a `GET /` index and a
`GET /api/rules?tag=&q=` fragment, and a `SearchResolver` contributing rows to
`/search` under a `House rule` badge. It registers **no page type, no table and
no migration** — its content is the frontmatter convention `type: houserule`,
read through `Host.Pages().ListPagesByType`, so the rules are ordinary pages that
stay readable with the plugin absent.

Its ten sample rules live in `internal/systems/houserules/testdata/` rather than
in a sample campaign, because `internal/sample` is a package doc and the
extraction that populates it lands in a later stage. The property that the
testdata is there to demonstrate — a `type: houserule` page renders with the
core viewer, and a list built from the convention is exactly the pages carrying
it — is asserted directly, so the fixture and the sample campaign cannot drift
into being two different demonstrations.

**The index ships one section, not the Shared / DM-only split the plan asks for,
and that is a divergence rather than an omission.** The plan (§3 of P9b) asks
for both halves. A DM-only *house-rule page* is not a thing this data model can
express, and the reason is a schema fact rather than a design preference:
`pages` has no visibility column, and `authz.PermReadPage` is a resource-free
permission — v1 has no per-page ACL. A page is a file; anyone who may read
public content may open it at `/p/{path}`, and it is listed in the file tree,
the tag cloud, the command palette and every backlink under the same rules.

So a DM-only section would need a `visibility:` frontmatter key that nothing
else in the app enforces — a key that hides a rule in one index and not in the
five other places the same page is reachable from. That is worse than not
shipping it, because the index would advertise rules it does not protect. The
plugin ships one section, says so in the page, and points at the mechanism that
*does* hide content: a `visibility=dm` fence in the page body, which the normal
secret machinery renders as a lock to a non-DM.
`TestTheIndexShipsOneSectionAndSaysWhy` pins all of it, including that
`visibility` is not among the frontmatter keys the plugin reads — so a future
change that starts honouring it has to update a test that explains why.

```

The implementation is `internal/systems/houserules`, and it is worth reading
rather than a transcription of it here — this document points at code, and a
copy of a plugin in a document is a copy that can be wrong while looking
authoritative (AGENTS.md §0). What the sketch established, and the real plugin
confirms:

- **A `KindFeature` may not register page types.** `Descriptor.PageTypes` is
  empty and the host refuses the plugin at boot if it is not, so the content
  model has to be a frontmatter convention. That is why `type: houserule`
  works with the plugin absent, and why the rules stay readable in Obsidian
  with the app closed.
- **The badge is a closure over the request's context**, not a number computed
  at register time. A count taken at boot is a count nobody filtered, and a
  hidden rule would be in it.
- **`Host.Pages()` is the only data surface a plugin gets**, and every one of
  its methods takes the principal as a parameter and applies the visibility
  predicate itself. A plugin that forgets to filter gets the right answer,
  because there is no predicate left for it to get wrong.
- **A hidden rule is absent, not greyed out.**

The parts that matter, and why:

- **No page types.** The content model is a frontmatter convention, so the
  feature plugin needs no `type: houserule` registration, and the pages keep
  working in Obsidian with the app closed.
- **The badge is a closure over the request's context**, not a number computed at
  register time. That is what makes it authz-filtered by construction rather than
  by a filter someone remembered to apply.
- **Every route sits under `/plugin/{id}/`.** `NavItem.Href` and
  `Host.RegisterRoutes` both state that the host validates this and that a
  violation is a registration error rather than a broken link. The host audits
  the patterns the plugin mounted and refuses the whole plugin on a reserved
  segment; the prefix itself is applied by `httpapi` at mount time, from the
  registry's own record of which plugin owns the router, so a plugin cannot
  mount at a prefix it does not own.
- **A mounted sub-router inherits nothing from the route table.** `chain` wraps
  the router, so a mount is already behind Session, but `checkCSRF` and `permit`
  are applied per row inside the table loop and a mount is not a row.
  `httpapi.mountPluginRoutes` re-applies both, at `PermSession` — the plugin's
  least requirement, because the host has no vocabulary for "the permission this
  route needs" and inventing one would let a plugin name its own gate. Without
  that function a plugin's POST would run with no CSRF check and no permission
  at all, and neither `TestCSRFRequiredOnAllMutations` nor
  `TestTheMatrixCoversEveryRoute` would see it: both read the static route table,
  not the mounted chi tree. `httpapi.TestAPluginSubRouterIsMountedBehindTheSameGatesAsATableRoute`
  is the test that closes the gap, and it exists because the gap is invisible to
  the gates that are supposed to cover it.
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
| A real `dnd5e` system plugin | **exists** — [`internal/systems/dnd5e`](../internal/systems/dnd5e) registers a page type, panels and nav; it declines `SummaryProvider` with the reason in `hostcall.go` |
| The `houserules` and `linkpreview` feature plugins | **exist** — [`internal/systems/houserules`](../internal/systems/houserules) and [`internal/systems/linkpreview`](../internal/systems/linkpreview) |
| The link-preview interaction in `web/static/app.js` | **exists** — delegated hover/focus on `[data-wikilink]`, the transient `role="tooltip"` card, the pin, the pinned pane, `Esc`, refetch on `semiplane-refresh`, self-close on 404 |
| The core-owned `GET /plugin/{id}/summary/{pageID}` route | **exists** — [`internal/httpapi/preview.go`](../internal/httpapi/preview.go); see [§7](#7-link-previews) for why the route is core's rather than the plugin's |
| `plugin.PageStore` — the authz-filtered page read surface a plugin is given | **exists** — declared in `internal/plugin/plugin.go`, implemented by `store` in `internal/store/pagestore.go`, wired in `internal/app/plugins.go` |
| `authz.WithPrincipal` / `authz.PrincipalFrom` — the context carrier a plugin reads | **exists** — [`internal/authz/context.go`](../internal/authz/context.go) |

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
