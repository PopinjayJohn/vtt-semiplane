# AGENTS.md

Working agreement for this repository. Every rule here is either enforced by a
test in `internal/architecture_test.go` or by a CI gate. If a rule is not
enforceable, it is marked as such — do not add unenforceable rules, and do not
weaken an enforced one to make a change convenient.

## 0. Documentation

The design plan is not in this repository — it lives in `.kilo/`, which is
gitignored. `docs/` is the durable copy, and it is the only place a new agent
can find the design. Start at `docs/README.md`, which says what to read for
which task, and read `docs/pitfalls.md` before running anything: three of the
traps there present as a silent hang rather than an error.

**The code is the specification; the documents point at it.** Do not restate a
table, a parser, a policy or a test in a document that the code already owns.
A document that repeats a fact the code owns can be wrong while looking
authoritative, and this repository has a recorded case of exactly that: the plan
documented the secret fence as `title=<optional>` with no quoting requirement,
the parser read an unquoted value containing a space as an unknown key, and
unknown keys meant public passthrough — so an author who followed the
documentation served a DM's secret body in plaintext to a player, and a test
pinned the unsafe behaviour. When a document and the code disagree, the code is
right and the document is a bug.

## 1. What this is

`vtt-semiplane` is a LAN-hosted TTRPG wiki and player+DM tool. A vault of
Obsidian-compatible Markdown files is the campaign; the app indexes it, renders
it, and serves it to a small group of authenticated users with per-page
authorization.

**The Markdown file is canonical. Every derived artefact — the SQLite index, the
FTS tables, the rendered HTML, the search results, the backlinks, the campaign
status panel — is derived and disposable.** The only way content enters the
index is by reading a file. The only way content leaves the app is through
`vault.Writer`, which is hash-checked and byte-preserving. The app never
normalises, reflows or reformats user Markdown.

## 2. Hard security rules

These are not style preferences. Each has a test or a grep that fails the build.

1. **Never construct SQL by string formatting.** Ever. Every user value is a
   bind parameter. Fragment assembly is allowed only from constant strings
   defined in the same package. `TestNoSQLBuiltByStringFormatting`,
   `TestEveryQueryUsesBindParameters`.
2. **Never log or render vault content outside `store`, `md` and `vault`.** If
   you need content for debugging, log a hash and a length. The `obs` handler
   refuses a `content`, `body`, `snippet` or `raw` attribute and strips any
   value over 256 bytes, so a careless log line loses its value rather than the
   secret.
3. **Never return a secret body without going through
   `authz.CanReadSecret`.** There is no other path. For a single secret,
   `Secret.CanRead`; for a query, `authz.SecretVisibleSQL` verbatim.
4. **Every query that can return a secret-derived row applies
   `authz.SecretVisibleSQL` — and its `COUNT` uses the identical predicate.** A
   panel that lists one row while counting three is an existence leak.
   `TestNoHandRolledVisibilityPredicates` fails any hand-rolled
   `visibility = 'literal'`.
   **The predicate alone is not sufficient, and the grep cannot catch you
   forgetting.** `SecretVisibleSQL`'s table clause has no authentication term —
   it says `s.visibility = 'table'` and nothing about a session — so it and
   `authz.CanReadSecret` disagree on exactly one case: an anonymous request
   asking for a `table` secret. `store.publicOnlySQL`, `store`'s per-query
   principal check and `search.Query`'s `p.Authenticated()` guard close it
   today. A new secret-derived query that uses the canonical predicate *and*
   forgets the principal check passes `TestNoHandRolledVisibilityPredicates`,
   because it wrote no visibility comparison of its own. So: if your query can
   return a `table` row, it needs the authentication check too, and
   `TestPredicateMatrixAgrees` — which evaluates every such query as an
   anonymous principal among others — is the gate that will notice.
5. **Never add an HTTP client to the request path.** No telemetry, no
   analytics, no CDN fetches, no font or script from a remote origin. Every
   asset is embedded and served from `/_/assets/`. Enforced by
   `TestNoOutboundNetwork`, which greps for client-side capability rather than
   for the `net/http` import, because a server legitimately imports net/http
   and a background goroutine dialling home would never appear in a rendered
   page. `TestNoProcessExecution` is the sibling rule: only `internal/app` may
   run a process.
6. **Never call `templ.Raw` on a vault-derived string.** And never enable
   goldmark's `html.WithUnsafe()`. Raw HTML in vault content is disabled.
6a. **Two matrix rows where the code and the plan differ, recorded so neither is
   a surprise.**
   *Trigger a reindex or a backup* is admin-only in the plan and `PermDM` in
   `authz.Policy` and the route table, so a DM may do both. That is accepted: a
   DM is already trusted with every secret in plaintext, a backup is a copy of
   what they can already read, and a reindex changes nothing. If that trust
   boundary is ever tightened, the fix is one matrix row and one route's `Perm`.
   *See the `secret_events` audit* **had** no permission constant at all, and
   `secrets.Service.Events(ctx, secretID)` took no principal, so a route added
   for it would have inherited no gate. **That gap is closed, and the surface is
   mounted**: the constant is `authz.PermAuditSecrets` with its own row in
   `authz.Policy` (DM or admin — the events are metadata, but they do disclose
   that a secret exists and who has touched it), `secrets.Service.EventsFor(ctx,
   actor, secretID)` asks the policy **before** the lookup so a refused
   principal cannot enumerate ids, and `GET /admin/secrets`
   ([`internal/httpapi/auditsecrets.go`](internal/httpapi/auditsecrets.go))
   mounts the per-account form, `secrets.Service.AllEventsFor`, passing the
   principal rather than an id. The constant is deliberately its own and not a
   fold-in of `PermDM`: folding it in would have closed the gap by accident and
   left the name lying about what it grants. What the page cannot leak is kept
   by not selecting the columns — `httpapi.SecretEventRow` projects a store row
   that holds no title, no author and no length, so there is nothing in the
   view model for a template to render.
7. **Any new route must be added to the route table in
   `internal/httpapi/routes.go` and to `TestAuthorizationMatrix`.** The only
   place a role is compared is the policy, and
   `TestNoRoleComparisonOutsidePerm` fails the build on a comparison, a switch
   or a lookup keyed by a role anywhere else. It is a scan of the syntax tree,
   not a grep, for the reason `TestNoOutboundNetwork` gives: prose cannot trip
   it, so a file may explain the rule, and a comparison split across a line
   break is still a comparison. `internal/authz` is the single exemption,
   because it owns the `Role` type and the policy table — its comparisons are
   the rule rather than a copy of it.
   **The `Perm` column is asked with a zero `authz.Resource`, so its name is not
   always what it grants.** `Server.permit` calls `Policy.Check` with
   `Resource{}`, so a `PermWritePage` column is answered "is this a DM or an
   admin" and the ownership arm of the policy is unreachable through it. The
   page-scoped write rows are therefore `PermSession` in the table and the real
   decision is `httpapi.mayWritePage` inside the handler, which is the one that
   carries the page's ownership. The other direction is the trap: putting
   `PermWritePage` on one of those rows makes §8.9's redacted editor
   unreachable over HTTP, because a DM's hidden set is empty by definition and
   the only principal it exists for is a page owner.
8. **A rendered-page cache does not exist in v1, and adding one requires
   keying by `(pageID, userID, authz_generation)`.** There is deliberately no
   cache: it is a whole class of secret-leak bugs for no measurable gain on a
   local SQLite vault.
9. **A surface that takes a page path from a request asks `vault.Ignored` on it
   before it touches the vault.** `vault.Resolve` establishes containment and
   nothing more: `.semiplane/semiplane.lock` is inside the vault, so a DM
   holding `PermDeletePage` could otherwise name it and release the
   single-instance lock the running process still believes it holds, which lets a
   second instance open the same vault. The page-scoped read and write surfaces
   go through `httpapi.readablePage` and `httpapi.writablePage`, which do it;
   the raw view and the rename's own target check do it themselves, and
   `internal/secrets` refuses the same case from the other side with
   `ErrAppState`. Pinned by `TestPathTraversalRejected`,
   `TestSaveRefusesTheAppsOwnState` and `TestRenameRefusesTheAppsOwnState`.

## 3. Architecture

```
cmd/semiplane/          main, flags, signals, lifecycle
internal/
  app/                  composition root: config → store → vault → plugins → router
  config/               flags + env + defaults + validation
  obs/                  slog wrapper, redaction filter, request log, audit log
  auth/                 users, argon2id, sessions, invites
  authz/                Principal, Permission, the policy, the canonical predicate
  store/                sqlite open, pragmas, migrations, typed queries
  search/               FTS5 query building, ranking, snippets, merge
  md/                   frontmatter split, secret segmentation, goldmark, extractor
  vault/                Path, atomic read/write, watcher, backup, lock, attachments
  sync/                 indexer, invalidation bus, rename detection
  secrets/              fence parse/serialise, redaction, reveal, audit
  plugin/               Plugin, Descriptor, Kind, Capability, Host, registry
  systems/core/         built-in system (notes, tags, search, backlinks)
  systems/dnd5e/        reference system plugin
  diff/                 hand-rolled line diff, change script and hunks
  httpapi/              chi router, middleware chain, handlers
  web/                  templ components, layouts, DataStar handlers
  sample/               embedded sample campaign
  testutil/             temp vaults, a deterministic clock, small fixtures
web/src/input.css       Tailwind v4 entry
web/static/             generated css, app shell js, vendored datastar
tools/                  Makefile, goreleaser, pinned versions
docs/                   ADRs and plugin authoring guide
```

**Dependency order, lowest first. A package may import itself and anything
earlier; never later.**

```
config < obs < authz < store < md < plugin < vault < auth < secrets < sync < search < diff < httpapi < web
```

`diff` sits immediately below `httpapi` because `httpapi` is its only consumer —
the conflict page a save shows when it loses an optimistic-concurrency race. It
imports nothing of ours, so its position is otherwise free, and the comment on
its entry in `order` says why it is deliberately absent from the plugin
boundary.

`app` is exempt and imports everything — it is the composition root.
`testutil` is exempt and *may* import everything, which is the permission rather
than a report: it imports nothing of ours, and the app-booting harnesses are
per-package test files rather than a shared one.
`sample` imports nothing internal. `internal/systems/**` and
`internal/plugins/**` are plugins and are held to the plugin boundary below.

Two deliberate deviations from the original plan's ordering, both to break a
cycle the plan contains:

- `authz` sits **below** `store`, because store's own queries embed
  `authz.SecretVisibleSQL` verbatim. `authz` imports nothing of ours: it takes
  a `Resource` struct handed to it by the service that already has the row, so
  it never queries a database and holds no `*sql.DB`.
- The arrow between `authz` and `secrets` runs **`secrets` → `authz`**, so the
  redactor can ask `authz.CanReadSecret`. `authz` may not import `secrets`.
  `authz` owns the canonical `Visibility` constants so both packages name the
  same three values.

**Where a new feature goes.** Not in `httpapi` and not in `app`. A new query
goes in `store`. A new markdown construct goes in `md`. A new page type goes in
a plugin. If a feature needs data from two packages that are not adjacent in the
order, the feature is in the wrong package.

## 4. Coding conventions

- Go 1.26. `go tool templ` for templ; the version is pinned in `go.mod` via
  the `tool` directive and must not float.
- `context.Context` is the first parameter of anything that does I/O, and is
  never stored in a struct.
- Errors are wrapped with `%w` and read `lowercase, no trailing punctuation`.
  Error messages carry ids, paths and reasons — never file content, never a
  line of vault text, never a secret body.
- No global mutable state. Package-level `var` is for a constant table or a
  `sync/atomic` counter, never for configuration.
- Prefer concrete types over interfaces. An interface with one implementation
  is a mistake; an interface at a package boundary is the point.
- No `interface{}` in an exported signature. Use a named type.
- Table-driven tests. `t.Parallel()` on every test that touches a temp
  directory. Subtests named for the case, not the index.
- Comments explain **why**, never what. If a comment restates the line below
  it, delete it.
- Every exported identifier has a doc comment that starts with its name.

## 5. Testing expectations

Every new package ships with tests in the same commit. Every test that touches
a temp vault calls `t.Parallel()` and uses `testutil.NewVault(t)`.

Security-relevant code is coverage-gated. A change to `internal/secrets`,
`internal/authz` or `internal/sync` that drops their coverage is a failed
change, not a follow-up.

Required suites, by area — the full table is in the plan's §18, and these are
the ones that must exist before a phase is called done:

- Markdown round trip: `TestRoundTripGolden` (≥40 fixtures × every write path),
  `FuzzNeverCorrupt`, `FuzzMalformedMarkdown`.
- Vault sync: `TestIndexIsIdempotent`, `TestWatchAndReconcileAgree`,
  `TestWatcherSuppressesSelfWritesButNotExternalEdits`,
  `TestReconcileScanFindsMissedEvent`,
  `TestConcurrentSaveSamePath`.
- Authorisation: `authz.TestAuthorizationMatrix` (the policy table),
  `authz.TestCanReadSecretOverTheWholeMatrix` (the Go rule),
  `store.TestPredicateMatrixAgrees` (the SQL and the Go rule against one
  expectation, which is the cross-check that matters), `httpapi.TestAuthorizationMatrix`
  and `httpapi.TestTheMatrixCoversEveryRoute` (the routes), `TestNoHandRolledVisibilityPredicates`,
  `TestCSRFRequiredOnAllMutations`.
- Secret redaction: `TestNoSecretLeaksThroughAnyPath`,
  `TestSecretFixturesNeverLeakThroughSearch`, `TestSecretStringCarriesNoBody`,
  `TestProblemErrorCarriesTheIdNotTheContent`,
  `TestTheRawViewLocksWhatTheReaderMayNotRead`,
  `TestCampaignStatusIsFieldLevelAuthorized`.
- The leak walk over the **whole route table** is
  [`internal/httpapi/leaksuite_test.go`](internal/httpapi/leaksuite_test.go),
  and it is derived from `Routes()` rather than written out as a list of URLs:
  a table row no step names is a failure, and so is an exclusion that is not
  argued in the file. `leaktripwire_test.go` is the scanner's own proof that it
  has teeth — **a test instrument, and nothing more**; there is no runtime
  response scanner in the server and there never was. §6 says what the walk is
  for and what the demo-path tripwire still adds.
- The secret lifecycle at the service and store layers:
  [`internal/secrets/stage5_test.go`](internal/secrets/stage5_test.go) (the
  reveal/revoke cycle and everything a hidden body can derive — a heading, a
  live link, a dangling one, tags; the index purge; who may reveal; the fence
  syntax edge cases) and
  [`internal/store/stage5_test.go`](internal/store/stage5_test.go) (the audit
  row and the `authz_generation` bump as one unit of work, and the backlink and
  related-page counts a visibility change moves). These are the claims §2 and
  §6 make that no HTTP-level test can establish, because they are about what
  is *absent* from an index.
- Live push: `TestPushNeverLeaksSecret`,
  `TestPushAndFetchProduceIdenticalFragments`, `TestPushTerminatesOnRoleChange`,
  `TestPushDropsSlowConsumer`, `TestPushCoalescesBurst`,
  `TestPushRevokeSendsReloadEvent`, `TestTripwireAlsoCoversPushWrites`.
- The editor and the write paths it added: `TestEditorRedactedRoundTrip` (the
  `secrets` half, over a real `secrets.Service`), `TestSaveRejectsStaleHash`,
  `TestConflictResolutionProducesExpectedBytes`,
  `TestThePageScopedWriteGateIsARefusalAndNotADecoration`.
  `TestRoundTripGolden` carries the byte-level claim on its own: every fixture,
  every write path, including the redacted round trip and the link rewriter.
- Revisions and renames: `TestRevisionRevocationIsAuthorised`,
  `TestRevisionHistoryAndRevert`, `TestARenameCarriesThePageOwners`,
  `TestStalePreviewIsHarmless`, `TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks`.
- Schema changes: `store.TestMigrationsFromEveryVersion` builds each historical
  fixture from migrations `1..V` **cumulatively**, not one file in isolation —
  see §11. An indexer that writes new rows needs the write side pinned too, or
  the route that reads them has nothing to read.
- A hand-rolled algorithm needs a property suite, not a fixture suite:
  `internal/diff`'s `TestHandRolledIsMinimal` compares the script against a
  brute-force LCS on generated pairs, and `TestRoundTripProjection` checks the
  two projections a consumer relies on.

A test that passes vacuously — because the code path it claims to cover does
not exist yet — is worse than no test. When a surface arrives in a later phase,
its secret tests live in that phase, where the code is. **A test that passes
because the fixture did not set up what it asserts is the same failure wearing a
different hat**, and it is the more dangerous one: see §11. **And a list that
names a test that does not exist reads as a gate and enforces nothing** — this
one carried four such names until stage 4, and a sweep of every test name in
this file and in `docs/` at stage 5 found two more, both in
[`docs/security.md`](docs/security.md)'s table of rules a test enforces. So
check a name against `rg "func <Name>\("` before relying on it.

## 6. Secret handling

Checklist, restated so it can be read without the plan:

- On-disk syntax is a fenced block: ` ```secret id=<12 hex> visibility=private|dm|table author=<username> created=<RFC3339> title="<quoted>" `.
- **A `title` or any other value containing a space must be quoted.** An
  unquoted `title=The cellar key` scans as `title=The` plus two unknown keys,
  and a fence whose directive cannot be read is **hidden, not demoted** — so the
  body is never served, and the problem is reported instead. That is fail-closed
  by design (`TestAnUnunderstoodSecretFenceNeverBecomesPublic`): a fence that
  claims secrecy gets it, whatever its directive says. The cost is that a
  malformed fence is invisible even to the DM until it is fixed.
- **Reveal is a file mutation, not a DB mutation.** It rewrites only the
  `visibility=` token inside that fence's directive line, byte-surgically.
  Everything else in the file is untouched. `TestVaultRoundTripPreservesSecretBytes`.
- `visibility=table` is the only value that may enter `secret_fts`. The DB
  mirrors the file; the file is authoritative.
- Only a DM or an admin may reveal or revoke — over HTTP, that is the `PermDM`
  column on the two rows in [`internal/httpapi/routes.go`](internal/httpapi/routes.go),
  and the button on the page is filled by asking the policy the same question
  (`httpapi.mayChangeSecretVisibility`) so the control and the gate are one
  answer. A page owner may create and edit their own secrets; ownership grants
  authoring rights, not broadcast rights.
- Redacted editing: an unreadable secret becomes the sentinel
  `‹s:<id>:<bodyLen>:<bodySHA256first8>›`. On save, each sentinel is recomputed
  from the current on-disk body; a match is spliced back byte for byte, a
  mismatch rejects the whole save. Never detect sentinels by regex over the
  buffer — match by position against the known secret set. The grammar and the
  splice are `md.Redact`, `md.Sentinel`, `md.ParseSentinel` and `md.Splice` in
  [`internal/md/sentinel.go`](internal/md/sentinel.go); `secrets.Service.Save`
  is what calls them.
- **A sentinel is a restore token, not a display token.** It carries the hidden
  body's length and an eight-hex-character digest, which is a fingerprint and a
  fixed size but is still a measurement of something the reader was refused. The
  editor needs it because a save has to put the body back. Every surface that
  renders a buffer to be *looked at* — the raw view, the conflict page — replaces
  the whole fence with `secrets.LockPlaceholder` instead, and
  `TestTheConflictPageCarriesNoBodyTheReaderWasRefused` is the gate. If you
  reach for `secrets.EditView` outside the editor, that is the reason not to.
- An attachment referenced only from inside a secret is served only to
  principals who may read that secret. There is deliberately no global
  `/attachments/{name}` route; the only route is page-scoped.
- Revisions are re-segmented and re-authorised at **read** time, so a revision
  from before a revoke cannot be read afterwards.
- A live-push stream carries a **trigger, never content**, and terminates on
  any authorization change. The bytes the client receives are produced by the
  ordinary handler with the subscriber's own captured principal.
- The `obs` handler refuses `content`, `body`, `snippet` and `raw` attributes
  and truncates anything over 256 bytes. The audit log is a separate
  allow-list handler.
- **The leak walk is derived from the route table, not written out as a list of
  URLs.** `TestSecretFixturesNeverLeak` in
  [`internal/httpapi/leaksuite_test.go`](internal/httpapi/leaksuite_test.go)
  walks every page in the campaign — one per registered and per conventional
  page type — as seven principals, over every row of `Routes()`, and a row no
  step names is a failure rather than a gap. It is the test this line used to
  *claim* existed: `TestSecretFixturesNeverLeak` was carried here for several
  stages with no test ever answering to it. It exists now, and the honest
  reading of this bullet is the shape, not the name: `TestNoSecretLeaksThroughAnyPath`
  in `tripwire_test.go` still walks the demo path and the new suite walks the
  table, so neither replaces the other, and **neither may ever be skipped**. Both
  assert the response body, **every response header** and **every `data-signals`
  payload**, and the suite's per-role positive control asserts that a body the
  principal *is* entitled to really arrived — a leak suite that finds nothing
  because it looked at nothing is indistinguishable from a clean one. One
  principal the demo path cannot reach is walked only by the new suite: the
  anonymous reader with `--allow-anonymous-read` **on**, against the `table`
  visibility, which is the one case §2.4 is about and the one a redirect-to-login
  row never tested.
  `TestSecretBodyNeverInErrorsOrLogs` covers the two places a body escapes
  without being rendered to anybody — the 500 page and the request and audit
  logs — and each case provokes a failure the application can genuinely hit and
  asserts the log stream grew, so a clean capture cannot pass it.
  **The name-checking advice stays, and the name that motivated it is now
  closed.** `TestNoRoleComparisonOutsidePerm` was carried here and in
  [`docs/PLUGIN_AUTHORING.md`](docs/PLUGIN_AUTHORING.md) §4 for several stages
  with no test answering to it; it exists as of stage 6, and writing it found a
  real violation on its first run — a switch on a role in `httpapi`, outside the
  policy — which is the argument for the habit rather than against it. A name
  nobody checked is a rule with no enforcement behind it.

## 7. Plugin development

Adding a plugin — a game system or a feature — requires exactly: one directory
under `internal/systems/<id>/`, one map entry in the registry, and sample
content if it needs any. No core file changes, and a grep test
(`TestNoPluginSwitchInCore`) fails the build if a plugin id appears anywhere
else.

**The boundary is enforced now, and one of the gates that enforces it was
itself broken until stage 3.** `internal/plugin` holds the vocabulary, the
`Host` implementation, the registry and the lifecycle; `reserved.go` holds the
reserved names; `internal/systems/dnd5e` is a working system plugin and
`internal/systems/example` is one that refuses to register, five different ways,
on purpose. `TestNoPluginSwitchInCore` and
`TestPluginImportsAreWithinBoundary` no longer skip.

Worth knowing before you trust that: `registeredPluginIDs` used a walker that
listed one directory and did not recurse, and a plugin *is* a directory. The id
set was therefore empty no matter what was on disk, and the gate would have
skipped silently and forever — with no message, because there was no skip
either. If you add a gate, make its "nothing to check" state **loud**;
`TestTheArchitectureGatesHaveSomethingToCheck` is the pattern.

The scan is over **dispatch sites** (`==`, `case "x":`, `expr["x"]`, a
`map[string]plugin.Plugin` key), not over quoted literals: `internal/md` has a
callout kind called `example`, and a literal grep reports that core file as
branching on a plugin. A bare `dnd5e.New()` is not flagged on purpose — a
package selector cannot branch, and matching it would make the rule
unsatisfiable rather than stricter.

- One `Plugin` interface, one registry, one lifecycle, one route prefix, and a
  `Kind` discriminator (`system` / `feature`). There is no second code path for
  features.
- The interface is split into `PluginCore` (process-agnostic: page-type
  schemas, markdown extenders, config, search resolvers) and `PluginUI`
  (in-process: `templ.Component` panels, editors, viewers, routes). The split
  exists so a future subprocess host can implement `PluginCore` alone.
- A plugin is **first-party Go code compiled into the binary**. There is no
  sandbox and no isolation. What the contract does give is capability
  narrowing against *accidental* damage, and one property that matters most:
  **a plugin cannot ship JavaScript, CSS, or a DOM handle.** Plugins return
  `templ.Component` values and Go values. `app.js` and the stylesheet are
  core-owned. This is why the link-preview interaction is implemented once in
  core rather than once per plugin.
- **A `KindFeature` plugin may not register page types** — it is a boot error
  for that plugin. Features express content through frontmatter conventions
  (`type: houserule` renders with the core viewer and needs no plugin at all).
- **A reserved name may be claimed only by a `KindSystem` holding the matching
  capability.** Reserved page-type ids and route segments are defined once, in
  `internal/plugin/reserved.go`. The check runs in `Register()` before anything
  is added to a registry, so a violation disables that one plugin and rolls its
  migration transaction back — it is a contained failure, not a corrupt boot.
- `Descriptor.APILevel` is admitted iff `host.APILevel-2 <= level <= host.APILevel`.
  Refusing a *newer* plugin matters: it may rely on a host that does not exist.
  Version skew is always visible in the boot report (`ok | skipped(reason) | compat`).
- **The absence of a plugin must degrade to a working app, never to a broken
  control.** A nav link that 404s, or a hover affordance with nothing behind it,
  is a bug. When no plugin holds `CapSidebarNav`, the sidebar renders no plugin
  group at all rather than an empty heading.
- Import boundary: a plugin may import only `plugin`, `md`, `store`, `web`,
  `authz`, `secrets`, plus `templ`, goldmark, chi and stdlib. It may **not**
  import `httpapi` (bypasses redaction and `Perm`), `auth` (bypasses session
  handling), `obs` (bypasses the redacting handler), `sync` (writes the index
  behind the indexer's back) or `app`. Enforced by
  `TestPluginImportsAreWithinBoundary`.
- No `os`, `net` or `exec` outside `app`. No reach-through into `store`'s
  unexported internals. No reflection into `Principal`.
- `Host` exposes no `*sql.DB`, no accessor returning secret text, no route
  outside `/plugin/{id}`, and no way to remove middleware (the sub-router is
  already prefixed and wrapped).
- Link previews: the plugin supplies a `templ.Component` **card body** and core
  owns the route, the behaviour, and the 404. The route is core's —
  `GET /plugin/{id}/summary/{pageID}` in `internal/httpapi/routes.go` — because
  AGENTS.md §7 requires a summary of a page the viewer may not read to be
  **byte-identical to navigating to it**, and that byte-identity is enforced by
  the unexported `httpapi.writeError`, which no plugin may reach. A
  plugin-owned route could only approximate it, and a distinguishable 404 is the
  probe the requirement exists to prevent. A `SummaryProvider` therefore
  declines with `ok == false` and never renders an error of its own.
- **`newHost` collects before `Register` runs.** `lifecycle.go` builds the host
  — and reads `PageTypes`, `Panels`, `SearchResolvers` and `SummaryProviders` —
  *before* `plugin.Register`. So a contribution that captures host state at
  construction captures it before the plugin has been registered. Hold a
  `func() plugin.PageStore` and call it at request time; do not store
  `h.Pages()` by value. A fake host that registers first will not catch this, so
  the ordering is asserted against the real sequence in
  `internal/systems/linkpreview`.
- **A mount is not a row.** `chain` wraps the whole router, so a mounted
  sub-router inherits session, headers, rate limiting and the request log — but
  `checkCSRF` and `permit` are applied *per row* inside the table loop, and a
  mount is not a row. `httpapi.mountPluginRoutes` re-applies both at
  `PermSession`. Neither `TestCSRFRequiredOnAllMutations` nor
  `TestTheMatrixCoversEveryRoute` can catch a missing re-application: both read
  the static route table, not the mounted chi tree. The table-derived gates also
  cannot answer *which methods* a mount gates, because a mount is registered
  once for every method its sub-router serves and the answer is a property of
  each request — asking it at mount time answered for the mount's placeholder
  method and refused every plugin read with 403, for every principal including an
  administrator. `TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest` in
  [`internal/httpapi/pluginmount_test.go`](internal/httpapi/pluginmount_test.go)
  is the test that can: it drives the mounted tree and asserts that a safe method
  is served without a token, that a mutation without one is refused, and that the
  same mutation with one is served. Plugin surfaces are therefore for signed-in
  readers, which is a deliberate ceiling — the host has no vocabulary for "the
  permission this route needs", and inventing one would let a plugin name its own
  gate.
- **A plugin cannot reach the principal without `authz`.** The context carrier is
  `authz.WithPrincipal` / `authz.PrincipalFrom` (`internal/authz/context.go`),
  one unexported key with one writer — the session middleware. `httpapi` keeps a
  `PrincipalFrom` pass-through, and its own key is gone. A context that never
  went through `WithPrincipal` reads as the **zero** `Principal`: anonymous,
  `CanReadPublic() == false`. It is deliberately *not* `authz.Anonymous(true)`;
  `TestTheZeroPrincipalIsNotAnonymousWithRead` fails first if someone "fixes"
  that, because a one-word change there grants public read to every caller that
  ever loses its principal. Never fabricate a principal for `PageStore` — a DM
  principal handed to a player is the leak every other rule here prevents.
- **A summary's excerpt is secret-free because of what is *stored*, not what is
  filtered.** It comes from `page_text.body`, which the indexer writes from
  `md.Doc.PublicBody()` and nothing else, so a secret body is not in the table to
  be selected. It is capped in SQL (`substr`, `SummaryExcerptMaxChars`
  *characters*, not bytes) so a 400 KiB page costs 200 characters rather than
  being read whole.
- **A page has no visibility.** `pages` has no visibility column and
  `authz.PermReadPage` is resource-free: v1 has no per-page ACL, and a page is a
  file that anyone who may read public content may open at `/p/{path}`. So there
  is no such thing as a DM-only *page* to hold back from a list — a plugin
  feature that needs one would have to invent a frontmatter key that nothing else
  enforces, which hides content in one place and five others. The mechanism that
  *does* hide content is a `visibility=` fence in the body. See `docs/plugins.md`
  §8.
- **A plugin is not on the Tailwind `@source` list.** `internal/systems/**` is
  not scanned, so a utility class a plugin uses that no core file uses renders
  unstyled and errors nowhere. Use core's existing tokens, or add a rule to
  `web/src/input.css`; the houserules tests assert every class it uses is one
  core's scan surface already knows. The same failure has one more shape now:
  a class that *is* on the scan surface but has no rule behind it. See §11.
- **`internal/diff` is not on the plugin import list.** It is deliberately
  absent from `pluginBoundary`, and the comment on its entry in `order` says
  why: a diff of two byte slices is a pure function with no reach into the
  request path, but nothing in the plugin contract needs one either, and an
  allow-list entry is a grant rather than a prohibition. A plugin that needs it
  gets one line added, deliberately.
- **A 404 comparison must be within one build and one session.** Two servers
  differ in their shell's CSRF token and in any build-fact signal, so comparing
  a preview 404 against a 404 from a second fixture compares two different shells
  and reports a leak that is not there. `preview_test.go` takes both responses
  from the same fixture and the same session, which is also the harder
  comparison — it is the same shell in both.

## 8. Generated files

`*_templ.go`, `web/static/app.css` and `web/static/vendor/datastar.js` are
generated and committed. Never hand-edit any of them. `make generate` and
`make css` refresh them; CI regenerates and diffs, and a stale artefact fails
`generate-check` / `css-check`.

## 9. Local commands

| Command | What it does |
|---|---|
| `make setup` | modules, pinned tools, templ generate |
| `make generate` | `go tool templ generate ./...` |
| `make css` | rebuild the committed Tailwind stylesheet |
| `make build` | static binary in `dist/semiplane` |
| `make build-fast` | build without regenerating assets (inner loop) |
| `make run` | run against `./vault` |
| `make dev` | run in development mode |
| `make test` / `make test-race` | unit tests / race detector |
| `make test-integration` | integration-tagged tests |
| `make cover` | coverage summary |
| `make fuzz` | 30s of each fuzz target |
| `make lint` | golangci-lint |
| `make fmt` | gofmt + templ fmt |
| `make check` | **the CI gate**: fmt-check, generate-check, css-check, lint, targets-check, test |
| `make embed-check` | fail if the built binary is missing an embedded payload — **not** in `make check` |
| `make coverage-check` | fail if a package lost coverage against `.coverage-baseline` — a ratchet, and **not** in `make check` |
| `make cross` | six release binaries |
| `make clean` | remove build output |

A test that writes into the repository fails CI on purpose: after every test
job, `git status --porcelain` must be empty.

## 10. Contribution workflow

- One phase of the plan's task breakdown per PR. Never two phases.
- Branch: `p<phase>-<slug>`, e.g. `p2-markdown-pipeline`.
- Commit: Conventional Commits, `type(scope): subject`, imperative, ≤72 chars.
- **Currently: one commit per stage**, not per phase. A stage is the unit in
  §21 of the plan (P0–P3 and P6 make stage 1), and while the phases are being
  built in parallel by several agents a per-phase history would be fiction — the
  phases do not build in isolation and a phase-sized commit would not compile
  on its own. Revisit this once the stages land and there is a reliable way to
  split them; `git rebase --interactive` over a stage boundary is the honest
  tool for that, and guessing at it from a squashed history is not.
- The definition of done is the phase's own **Accept** list in the plan, all of
  it, in the same PR. Not "follow-up PR".
- Where two phases touch the same file, the later one rebases. The phase order
  in the plan's §17 *is* the conflict-resolution policy.

## 11. Known footguns

- **`modernc.org/libc` version pin.** `modernc.org/sqlite` requires the exact
  same `modernc.org/libc` version in our `go.mod` as in its own. Bump one and
  not the other and the build fails in a way that reads like a compiler bug.
- **templ is pinned in `go.mod` via the `tool` directive.** templ's generated
  code is version-sensitive; a floating version causes spurious
  `generate-check` failures. templ v0.3.1020 requires Go ≥ 1.26, which is why
  the `go` directive is 1.26.0 rather than the 1.25.0 originally planned.
- **DataStar 1.0 syntax is `data-on:click`, not the beta `data-on-click`.**
- **fsnotify is not recursive** and its events can be dropped. `vault.Watcher`
  keeps a set of watched directories and adds new ones on create; the 60 s
  reconciliation scan is the correctness guarantee, the watcher is a latency
  optimisation.
- **`os.Rename` is not an atomic replace on Windows.** `atomicReplace` is
  build-tagged: `os.Rename` on unix, `MoveFileExW` with
  `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH` on Windows.
- **`html.WithUnsafe()` must stay off.** It is not a default worth revisiting;
  turning it on makes every vault file a stored-XSS vector.
- **Case-insensitive filesystems hide colliding paths.** A Linux-created vault
  can hold both `Gundren.md` and `gundren.md`; on macOS or Windows one is
  invisible to the walk and the page appears to have vanished. Detected before
  indexing, a hard error by default, escapable only with
  `--allow-case-collisions`, which still reports what it skipped.
- **Only one process may hold a vault.** The exclusive advisory lock on
  `.semiplane/semiplane.lock` is taken before any file or DB is opened.
- **The temp file for an atomic write must be in the same directory as the
  target.** A temp file in the system temp dir is a different filesystem and
  `os.Rename` across a filesystem boundary is a copy, not a rename.
- **FTS5 query syntax is an injection surface.** User input never reaches
  `MATCH`; `search.BuildMatchQuery` re-tokenises it.
- **A scanner or parser must always move its cursor.** Both hangs that shipped
  in the markdown pipeline were the same bug: a branch that recognised a token
  and then did not advance the read position. goldmark re-enters a parser that
  consumed nothing, on the same bytes, and appends to the block buffer each
  time — so the symptom is not "wrong output", it is a test run that eats 8 GiB
  and then the machine. The two sites were an unterminated `%%` comment and a
  secret fence with an unparseable directive. Every `for` over a byte range
  needs an explicit progress assertion, and any branch that records a problem
  must still move the cursor.
- **`source(none)` on the Tailwind import is load-bearing.** `@import "tailwindcss"`
  without `source(none)` leaves automatic source detection on, and detection
  walks the whole project root — including
  `internal/md/testdata/wikilink-flood.md`, a megabyte of wikilinks on one
  unbroken line. Candidate extraction on that is a single-threaded CPU spin: the
  build finished all its reads within seconds, then sat at 100% CPU with zero
  further I/O for over fifteen minutes. This was long recorded here as a
  `/mnt/gamedrive` filesystem-walk problem, which was wrong — it reproduces
  identically on tmpfs, and the same command with `source(none)` finishes in
  ~70 ms in the repo and in ~0 s on tmpfs. The `@source` list below the import is
  *additive* to detection, not a replacement for it, so narrowing that list
  cannot fix a slow build and the import itself is the only thing that can.
  Keep the `@source` list explicit: `internal/md/*.go` is on it because the
  markdown renderers emit class attributes for passthrough blocks, callouts and
  mermaid, and dropping that line silently removes those classes on the next
  rebuild. A build that reads like it is stuck is this bug, not a slow mount —
  check it with `strace -c` or `/proc/<pid>/io` before looking anywhere else.
- **Never run `go test ./...` bare on this machine.** It links and runs one
  test binary per package, up to `NumCPU` at a time, and every package that
  pulls in `modernc.org/sqlite` links a very large pure-Go libc. That exhausted
  RAM *and* zram swap. Use `make test` / `scripts/test.sh`, which pins `-p 1`,
  bounds subtest parallelism, sets `GOMEMLIMIT` and puts a timeout on every test
  so a spin panics with a stack trace naming the spinning frame.
- **`continue` inside a templ `for` becomes the literal word "continue".**
  templ v0.3.1020 compiles a `continue` whose loop body contains markup into
  the body text. A panel loop written the obvious way rendered its panel in
  *every* slot and printed the word "continue" between the sections, with no
  compile error and no test failure. Write the skip as an `if` inside the
  `for` instead, and say why at the call site — see
  `internal/web/context.templ` for the shape.
- **An architecture gate that skips is not a gate, and one that skips for a
  reason nobody reads is worse than a failure.** `TestNoPluginSwitchInCore`
  collected plugin ids with a walker that listed one directory and did not
  recurse, so the id set was empty regardless of what was on disk: it would
  have skipped forever, silently, with no message to read. A gate's failure
  mode should be a **loud** one — a test that asserts the gate has something to
  check, and fails naming what is missing when it does not.
- **A migration test that applies one file in isolation tests a property of the
  current series, not of the mechanism.**
  `TestMigrationsFromEveryVersion` used to build each historical fixture from
  that version's own SQL and nothing earlier. It passed with one file in the
  series and started failing the day there were two, which is the point: the
  form only works while every migration is a complete `CREATE` script, and an
  `ALTER` is not one. The fixture is now built from migrations `1..V`
  **cumulatively** (`newDBAtVersion` in
  [`internal/store/store_test.go`](internal/store/store_test.go)) and every table
  a later migration touches is seeded first, so the delta is proved over data
  rather than over an empty schema. A migration whose SQL only runs on an empty
  table is a migration that loses rows.
- **A fixture that a later step undoes is a test that cannot fail.**
  `TestAWriterMayNotReadADMSecret` asserted the *opposite* of what the policy
  does — that a page owner may not read another author's `private` secret on a
  page they own — and it passed for three stages. The fixture wrote the
  ownership grant *before* the reindex that resolves each fence's `author=` to a
  user id, and `reindexAll` drops the derived index first, so the grant named a
  page row that no longer existed and `IsPageOwner` answered false for the
  duration of the test. The assertion was never exercised. The ordering is now
  reindex-then-grant and the comment on `accountsFor` says it is load-bearing.
  **An assertion is only as strong as the state its fixture built, and nothing
  fails when the state was never there.**
- **`ON DELETE CASCADE` on an ownership table turns a rename into a permission
  change.** `page_owners.page_id` cascades, and a rename is implemented as
  "reindex the departed path, reindex the new one", so the departed row's
  cascade takes every owner with it. Without the carry the rename reports
  success and silently strips the page of the people who could write it and
  read the `private` secrets authored on it. `httpapi.RenamePage` copies the
  owners from a read taken *before* the move, and `TestARenameCarriesThePageOwners`
  pins it. Ask, for every `CASCADE` in the schema: what does removing the row
  take with it, and is that right for the operation that removes the row?
- **A gate asked with the wrong resource is a gate that means something else.**
  `Server.permit` calls `authz.Policy.Check` with a zero `authz.Resource`, so
  the route table's `PermWritePage` column is answered "is this a DM or an
  admin" and the policy's ownership arm is unreachable through it. The name on
  the row is the thing a reader trusts, and the resource is the thing that
  decides. `PermSession` on the page-scoped write rows plus `mayWritePage`
  inside the handler is what §8.9 needs; the reasoning is in the comment on
  those rows in [`internal/httpapi/routes.go`](internal/httpapi/routes.go).
- **chi v5 cannot route a suffix on a catch-all.** All three obvious spellings
  were measured, and `TestTheCatchAllAndItsSuffixesAreUnambiguous` re-measures
  them so a dependency bump cannot pass unnoticed: `/p/*/raw` **panics at
  registration**, `/p/{path...}` matches one segment and returns an empty value
  (worse than useless — it looks like it works), and `/p/{raw}` cannot span a
  `/`. A page-scoped suffix is therefore a property of the catch-all's *value*,
  handled by `internal/httpapi/pagedispatch.go`. Do not register a second chi
  pattern for a page surface: `chi` silently overwrites a handler registered
  twice for the same method and pattern.
- **A gate that measures a proxy for the thing is not a gate.**
  `TestTheCatchAllAndItsSuffixesAreUnambiguous` measured the three *routing
  spellings* of a page-scoped suffix, and it could not see that
  `selector.bind` in [`internal/httpapi/pagedispatch.go`](internal/httpapi/pagedispatch.go)
  required `len(tail) == len(sel.segments)`. The file's own comment said the
  greedy `{name...}` segment exists precisely so a subdirectory attachment can
  be served — and so every subdirectory attachment was refused, for every
  principal including an administrator, while the same filename at the vault's
  root was served. The code disagreed with the comment that explains it, and a
  test that read only the routing agreed with both. The generalisable form: ask
  what a gate *does not look at*, and if the answer is "the thing", it is
  measuring something adjacent to it. Fixed and pinned by
  [`internal/httpapi/catchall_test.go`](internal/httpapi/catchall_test.go),
  which drives a multi-segment name through the real router and — the half a
  careless fix skips — pins every name the loosening must still refuse.
- **An HTTP-level test that calls the handler proves the handler works, not
  that anything points at it.** `md.VaultResolver` emitted a *relative* `src`
  for an attachment embed, so every attachment in the app was a broken image
  and `TestAttachmentInSecretIsNotServed` passed the whole time: it requested
  the route directly instead of following the link the page emits.
  `TestThePagePointsAtTheAttachmentItServes` in
  [`internal/httpapi/attachmenturl_test.go`](internal/httpapi/attachmenturl_test.go)
  reads the `src` off the rendered page and follows *that*. Note where the fix
  could not live, because both are constraints rather than preferences: the
  reference is not always a wikilink (`![alt](x.png)` is an `ast.Image` and
  never reaches the resolver at all), and `md.Renderer` is built once at boot
  and shared, so a page-aware resolver would need mutable state on a shared
  object — a data race. It is `md.scopeAttachments`, a walk over the AST.
- **A test local named `where` fails `TestEveryQueryUsesBindParameters`.** The
  grep flags any line containing `Sprintf` *and* a SQL verb word, and `where` is
  one of the words in that pattern — so `where := fmt.Sprintf(...)` trips a
  gate it has nothing to do with. It scans test files too; only
  `architecture_test.go` is exempt. Name it `sites`, or `at`.
- **`EditView.BaseHash` is already `vault.Hash`'s output, not hex of it.** A
  form field wants `hex.EncodeToString(view.BaseHash)`; `vault.HashHex(BaseHash)`
  is the hash of the hash, and every save built that way comes back 409 — which
  in a walk that only asserts what is *absent* from a response is a green suite
  over a write that never happened.
- **`scripts/test.sh` scales its `-timeout` to 600s under `-race`.** The race
  build makes the `httpapi` suite — a whole application boot plus an argon2id
  derivation per fixture — several times slower, so the uninstrumented 180s
  reports a spin on a suite that is merely working. The timeout exists to *name*
  a spin, not to hold a budget; `SEMIPLANE_TEST_TIMEOUT` still overrides it.
- **A boundary with no row behind it is a rule nobody wrote down.**
  `secret_events` had no permission constant at all, and
  `secrets.Service.Events(ctx, id)` took no principal, so a route mounted for
  the audit view would have inherited no gate. Nothing leaked only because
  nothing was mounted. It is closed — `authz.PermAuditSecrets` plus a policy
  row, and `EventsFor` checks the policy *before* the lookup so a refused
  principal cannot enumerate ids — and the constant is deliberately not
  `PermDM`, because folding it in would have closed the gap by accident and left
  the constant's name lying about what it grants. `GET /admin/secrets` mounts
  the per-account form and passes the principal, so the gate is exercised
  rather than theoretical. When you add a surface, ask which policy row answers
  it; if none does, adding the row is part of the change, not a follow-up.
- **An exported class with no rule behind it renders unstyled and errors
  nowhere.** Three components carried `class="card"` for a long time with
  nothing in `web/src/input.css` matching it, so they rendered as unframed
  divs and no build, no test and no lint said so — the failure mode is a
  component that is present and legible, just not the shape its own class name
  promises. `.card` now has a rule; the trap is that the scan surface (§7) and
  the rule surface are different sets, and a class on the first with nothing on
  the second is invisible from Go.
- **Two linters whose requirements conflict, and the one shape that satisfies
  both.** `errcheck` wants a checked close, so the obvious fix is
  `defer func() { _ = resp.Body.Close() }()`. That satisfies `errcheck` and makes
  `bodyclose` *worse*: `bodyclose` builds its interprocedural summary from the
  shape of the close inside the callee, and a func literal is invisible to it, so
  `internal/httpapi` went from 20 findings to 86. The shape that satisfies both is
  a bare `defer resp.Body.Close() //nolint:errcheck` with the reason written
  beside it. The generalisable part is worth more than the instance: **`bodyclose`
  summarises methods but not free functions, and it summarises the *shape* of the
  close, not the fact of it** — so a helper that closes correctly and completely
  still reports every call site that used it. Nothing in Go tells you that; the
  only way to find it is to run both linters.
- **A rule the code owns twice is a rule that disagrees.** `internal/httpapi`
  re-derived `md`'s link-URL rule as `internalHref` so it could match rendered
  hrefs, and the two copies drifted twice, both silently: a link with a heading
  never previewed, because the renderer percent-encodes the fragment and the
  mirror did not; and a link naming a file never previewed, because the renderer
  had by then started routing that href at the attachment route. Neither failure
  threw, neither logged, and both looked exactly like "the preview is not
  configured". The fix was to export `md.LinkHref` so the rule has one owner, and
  to compare the two sides decoding-insensitively rather than byte for byte. Same
  family as the `EditView.BaseHash` entry above and the same lesson: when a
  document *or a function* restates a fact another package owns, the restatement
  is a second answer waiting to become a second opinion.
- **`golangci-lint` runs, and it is green at 0 issues.** The entry that used to
  say otherwise is gone: the tool now builds against this module's Go, and
  `golangci-lint run` reports `0 issues` over the whole tree with
  `max-issues-per-linter: 0` and `max-same-issues: 0`, so nothing is being
  hidden by a cap. It is part of `make check`. Do not report lint as passing
  without running it — the two entries above are enforced by it and by nothing
  else, which is what makes them rules rather than advice.
