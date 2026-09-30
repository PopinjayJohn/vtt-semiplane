# Writing a plugin

**Read [`plugins.md`](plugins.md) for the contract. This page is the procedure.**
`plugins.md` says what the boundary *is* and which test enforces each part of it;
this says what to type, in what order, and what will refuse you. It is written
against the three plugins in the tree, so every identifier below exists:

| Plugin | Kind | What it demonstrates |
|---|---|---|
| [`internal/systems/dnd5e`](../internal/systems/dnd5e) | `KindSystem` | page types, panels, migrations, a declined `SummaryProvider` |
| [`internal/systems/houserules`](../internal/systems/houserules) | `KindFeature` | a frontmatter convention, mounted routes, a search resolver |
| [`internal/systems/linkpreview`](../internal/systems/linkpreview) | `KindFeature` | a summary provider, and the authz-filtered read behind it |
| [`internal/systems/example`](../internal/systems/example) | both | five ways to be refused, on purpose |

## Before you write anything

**One map entry and one directory is the whole of it** — plus sample content if
the plugin needs any. Adding a plugin is *not* supposed to touch a core file, and
if you find yourself editing one, the feature is probably in the wrong package
(AGENTS.md §3).

If you do need a core change, stop and say so before making it. The two core
changes this stage needed — a page read surface and a mounted sub-router — each
had a security property attached that no plugin could supply for itself, and both
took a day to get right. That is the signal: a plugin cannot express it, so it is
core's.

## 1. Pick the kind first, because it decides your content model

```
KindSystem  → may register PageTypes, may own tables, may run migrations
KindFeature → PageTypes must be empty; no tables, no migrations
```

**This is the decision that is expensive to reverse.** A `KindFeature` that
declares a page type is refused at boot — a feature plugin expresses content
through frontmatter conventions, and `type: houserule` is one. A convention is
strictly better than a page type for feature content anyway: the page is an
ordinary Markdown file that renders with the core viewer, works in Obsidian with
the app closed, and keeps working when the plugin is not installed.

## 2. The descriptor

```go
func (*Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:           "houserules",
		Name:         "House Rules",
		Kind:         plugin.KindFeature,
		Version:      "0.1.0",
		APILevel:     plugin.APILevel,   // exactly this, not a number
		Capabilities: []plugin.Capability{plugin.CapSidebarNav, plugin.CapSearchResolvers},
		NavItems:     []plugin.NavItem{{ /* ... */ }},
	}
}
```

- **`APILevel` is `plugin.APILevel`, the constant.** A plugin is admitted iff
  `host.APILevel-2 <= level <= host.APILevel`. Refusing a *newer* plugin matters:
  it may rely on a host that does not exist. Version skew is always visible in the
  boot report (`ok | skipped(reason) | compat`).
- **`ID` must be readable by `go/parser`.** A string literal or a package-level
  string const. Anything else and the architecture gates *report* rather than
  skip, because a plugin the boundary gate cannot read is a plugin the gate has
  stopped covering. This is not hypothetical; it is the same class of bug as the
  non-recursive walker that emptied the plugin id set in stage 3.
- **Declare only the capabilities you use.** The host discards what you declare
  without; declaring `CapMaps` because it sounds useful means a future reserved
  name you do not control is yours.

## 3. Choose your kind of plugin before you choose a capability

A `KindSystem` implements both halves. A `KindFeature` implements only
`PluginCore` — the in-process `PluginUI` half is optional, and a feature plugin
that has no panels or routes to offer does not implement it.

## 4. Read data through `Host.Pages()`, and only that way

```go
who := authz.PrincipalFrom(r.Context())
rules, err := h.Pages().ListPagesByType(ctx, who, "houserule")
```

`Host.Pages()` is a `plugin.PageStore` with four methods, and every one takes the
principal **as a parameter**. Three consequences, and they are the reason the
surface is shaped this way:

1. **You cannot forget to filter.** There is no predicate left for you to get
   wrong, because there is no SQL to write. A plugin handed a `*sql.DB` would be
   one `WHERE` clause away from every secret in the vault.
2. **`authz.PrincipalFrom(ctx)` gives you the request's own principal.** The
   key is owned by `authz` (`internal/authz/context.go`) and written once per
   request by the session middleware. A context that never went through
   `WithPrincipal` reads as the **zero** `Principal` — anonymous, and
   `CanReadPublic() == false`. That is the safe direction, so a lost context
   degrades to "no rows" rather than to "everything".
3. **Never fabricate a principal.** Handing `PageStore` `authz.ForUser(1, ...,
   RoleDM, ...)` to "make it work" puts DM-visible content in a player's card,
   and no test will catch it because every test you wrote used the same
   fabricated value.

**Branch on `who.IsDM()`, never on `who.Role == "..."`.** A role comparison
outside `internal/authz` is refused by `TestNoRoleComparisonOutsidePerm` in
[`../internal/architecture_test.go`](../internal/architecture_test.go), and it
is a second answer to a question that has exactly one home. The gate scans the
syntax tree rather than grepping, so it catches a switch on a role and a lookup
keyed by one as well as `==`, and prose that mentions a role cannot trip it —
which is why `internal/systems/houserules/plugin.go` can warn you about this in a
comment. `internal/authz` is its single exemption, because it owns the `Role`
type and the policy table; there is nothing to add to the exemption list without
arguing for it first.

## 5. Mount routes, and know what you inherit

```go
h.RegisterRoutes(sub)
sub.Get("/", ...)
sub.Get("/api/rules", ...)
```

`sub` is a bare `*chi.Mux` built by the host and handed to you. `httpapi` mounts
it at `/plugin/{id}`, derived from the registry's record of which plugin owns the
router — **not** from anything you said — so you cannot mount at someone else's
prefix.

What a mount inherits is worth stating precisely, because the answer is
counter-intuitive and it is a real hole if you assume otherwise:

| Gate | Inherited? |
|---|---|
| `Recoverer`, `RequestID`, `RequestLogger`, `SecureHeaders`, `Session`, `RateLimit` | **yes** — `chain` wraps the whole router |
| `checkCSRF` | **no** — applied per row inside the table loop; a mount is not a row |
| `permit` | **no** — same reason |

`httpapi.mountPluginRoutes` re-applies the last two at `PermSession`. You cannot
influence either, and that is deliberate: the host has no vocabulary for "the
permission this route needs", and inventing one would let a plugin name its own
gate.

**The CSRF half is asked per request, because a mount is not a row.** A row knows
its method when it is wrapped, so the table asks once and gets one answer. Your
sub-router serves several methods and the mount is registered once for all of
them, so asking there answers for the mount's placeholder method — and the shape
that produced was `403` on every `GET`, including as an administrator, which
made a plugin nav item a link nobody could follow. The mount therefore gates on
the request's own method, from the same predicate `Route.Mutating` uses.
`TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest` in
[`../internal/httpapi/pluginmount_test.go`](../internal/httpapi/pluginmount_test.go)
drives the mounted tree and pins all three states; the table-derived CSRF gate
cannot see a mount at all, because no row of the table describes one.

**A nav item is dropped if you mounted no route.** `host.gatedNav` discards nav
items from a plugin that registered none, on the grounds that a link to nothing is
a broken control. If you want a sidebar entry, mount the index it points at.

## 6. Link previews: you supply the card, core owns the behaviour

```go
func (p *Plugin) Summary(ctx context.Context, pageID int64) (templ.Component, bool, error) {
	sum, err := p.host.Pages().GetPageSummary(ctx, authz.PrincipalFrom(ctx), pageID)
	if errors.Is(err, store.ErrNoRows) {
		return nil, false, nil        // the documented degradation
	}
	if err != nil {
		return nil, false, err
	}
	return card(sum), true, nil
}
```

**You do not mount the summary route.** Core does, at
`GET /plugin/{id}/summary/{pageID}`, and the reason is the 404: a summary of a
page the viewer may not read must be byte-identical to navigating to it, and that
byte-identity is enforced by `httpapi.writeError`, which you cannot reach.
`plugins.md` §7 has the full argument. Decline with `ok == false` and core writes
the 404; do not try to render your own.

**Your card body is content and nothing else.** No ids, no classes core must
target, and **no interactive elements** — the pin button is core's, because it
needs JS and a plugin cannot ship JS. See `internal/systems/linkpreview` for the
element shape the app.js agent binds against.

### Emitting the attribute is your job, and it is one call

A link previews because it carries `data-wikilink="{pageID}"`, and core attaches
it in **two** places, a plugin in neither:

- **The shell's own links carry it** — the file tree, the dashboard and tag
  lists, search hits, backlink chips, the broken-links panel, the campaign-status
  panels. Those are core templates, and they render `web.Wikilink(card.ID)`
  themselves.
- **A link inside a rendered page body carries it** because the handler rewrites
  the finished anchors after the Markdown renderer has run. That is a rewrite of
  core's own output, and it never sees your component.

So for a link in a `templ.Component` you return, you emit the attribute
yourself, through the one function that owns its name:

```go
<a href={ rule.Href() } { web.Wikilink(rule.ID)... }>{ rule.Title }</a>
```

`web` is on the import list, and `web.Wikilink` is `plugin.WikiLink`, so the name
the shell binds to and the name you emit are one string with one definition. The
value is an integer page id — never a title, a path, or anything a reader of
the page could learn from it, because the attribute is the only thing that came
out of a vault file. **No plugin in the tree does this yet**; `houserules` links
each rule by bare `href` and so its links navigate rather than preview. That is
allowed — an ordinary link is not a broken control — it is just not a preview.

## 7. What you may not do, and which test says so

Import only `plugin`, `md`, `store`, `web`, `authz`, `secrets` — plus `templ`,
goldmark, chi and stdlib. Enforced by `TestPluginImportsAreWithinBoundary`.

| Forbidden | Why | Gate |
|---|---|---|
| `httpapi` | bypasses redaction and `Perm` | `TestPluginImportsAreWithinBoundary` |
| `auth` | bypasses session handling | same |
| `obs` | bypasses the redacting handler | same |
| `sync` | writes the index behind the indexer's back | same |
| `config`, `app` | the composition root, not a library | same |
| `os`, `net`, `exec` | — | `TestNoProcessExecution`, `TestNoOutboundNetwork` |
| `templ.Raw` on a vault-derived string | stored XSS | your own test; see below |
| `<script>`, `onclick=`, `data-on:`, `data-bind:`, `javascript:` | a plugin ships no JS and no DOM handle | your own test; `dnd5e` has the token table |
| naming a plugin id outside `cmd/semiplane/registry.go` | one registry | `TestNoPluginSwitchInCore` |
| hand-rolling `visibility = '...'` | a second copy of the policy | `TestNoHandRolledVisibilityPredicates` |

**A plugin cannot ship CSS either.** Return `templ.Component` and Go values.
`app.js` and the stylesheet are core-owned, and a plugin class that is not in
`web/src/input.css` simply does not exist — so use core's tokens.

## 8. templ footgun you will hit

**`continue` inside a templ `for` compiles to the literal word "continue"** in
templ v0.3.1020. No compile error, no test failure — your panel renders in every
slot with the word "continue" between the sections. Write the skip as an `if`
inside the `for` instead. See `internal/web/context.templ` for the shape.

## 9. Testing

- Copy the `recordingHost` fake from
  [`internal/systems/dnd5e/dnd5e_test.go`](../internal/systems/dnd5e/dnd5e_test.go)
  — including its `gather()`, which reproduces the host's post-`Register` step.
  A fake that skips that step tests a plugin that never got audited.
- `t.Parallel()` on everything, table-driven, subtests named for the case.
- **Keep the anti-vacuity test** (`TestTheSourceFilesAreAllChecked`): a new
  source file in your package must be a failure, or a whole file can go unchecked
  while every test still passes.
- **The security assertions are not optional.** For a plugin that reads pages:
  the list and the `COUNT` must agree for every principal in the matrix; a
  principal with no right to a row must not receive it, its badge, or its tag
  counts; and a rendered body must contain no fixture secret the principal may
  not read.
- `continue` on to the root: `go test ./...` **bare will exhaust this machine's
  RAM**. Use `make test`, or a targeted `go test -p 1 -run ... ./pkg/`.

## 10. The order to do it in

1. Copy the closest of the three plugins as a directory, not a file.
2. Get `Descriptor` right and run `make generate` — the gates read the
   descriptor through `go/parser`, so a wrong `ID` is reported immediately.
3. `Register` → store the `Host` → register what you hold a capability for.
4. Data reads, via `Host.Pages()`, principal as a parameter.
5. Routes, if you have a URL. A nav item without one is dropped.
6. Tests, including the anti-vacuity one, before you add surface rather than after.
7. One map entry in `cmd/semiplane/registry.go`. `TestNoPluginSwitchInCore`
   fails the moment the directory exists without it — that is the gate working.
8. `make check`.
