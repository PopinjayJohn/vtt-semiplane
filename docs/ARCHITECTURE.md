# Architecture

A map for an engineer who has never seen this repository. It names the owning
artefact for everything it mentions and explains why the shape is what it is.
It deliberately does not transcribe a table, a policy, a parser or a route list:
each of those has exactly one owner in the code, and a copy here would be a
copy that can be wrong while looking authoritative. Where this document says
"read X", X is the specification.

The two documents it leans on hardest are
[`ADR-0001-canonical-dependency-order.md`](ADR-0001-canonical-dependency-order.md),
which owns the dependency order and the two deviations that break the cycles the
design plan contains, and [`spec.md`](spec.md), which owns the data model, the
Markdown pipeline, the index and an itemised account of what is not built.

## The one rule everything else follows from

**The Markdown file is canonical. Every derived artefact is derived and
disposable.**

That is not a slogan with three corollaries; it is a constraint that decides
most of the rest of this document, and it holds in both directions.

- **Content enters the index only by reading a file.** There is no write path
  into SQLite that does not start at a `vault.Read`. The indexer's whole
  contract is in [`../internal/sync/doc.go`](../internal/sync/doc.go).
- **Content leaves the app only through `vault.Writer`**, which is
  hash-checked — the caller states the hash of what it read and the write is
  refused if the file moved underneath it — and byte-preserving. A reveal
  rewrites one token inside one fence's directive line and leaves every other
  byte in the file alone, including its line endings and its spacing. The
  writer is [`../internal/vault/writer.go`](../internal/vault/writer.go).
- **Nothing normalises user Markdown.** No reflow, no reformatting, no
  frontmatter rewriting. `TestRoundTripGolden`
  ([`../internal/md/golden_test.go`](../internal/md/golden_test.go)) runs every
  fixture through every write path, which is what holds that claim down.
- **A boot that trusts the index is a boot serving whatever the last crash left
  behind.** The indexing pass is therefore unconditional, and `--reindex` drops
  every derived row and rebuilds rather than taking a delta; an index database
  that cannot be read is quarantined and replaced, not repaired, because there
  is nothing in it that the files do not already say.

Almost every "why" in the rest of the codebase reduces to this. A derived
artefact is allowed to be wrong until a pass has fixed it, and the security
design leans on that: a secret body is only ever *withheld* from a response,
never deleted from a file, so a stale or broken index is a miss rather than a
loss.

## The packages, and why the order is the order

Every package has a `doc.go` that says what it owns and why its boundaries sit
where they do. Read those rather than this list; this list exists so the graph
is visible at a glance, and the graph is a *search* structure, not a summary.

| Package | Owns | Its own `doc.go` says why its edges are where they are |
|---|---|---|
| `internal/config` | flags, environment, defaults, validation | [`doc.go`](../internal/config/doc.go) |
| `internal/obs` | the slog wrapper, the redacting handler, the request log, the audit log | [`doc.go`](../internal/obs/doc.go) |
| `internal/authz` | `Principal`, `Permission`, `Resource`, the policy, the canonical visibility predicate | [`doc.go`](../internal/authz/doc.go) |
| `internal/store` | the database, the pragmas, the embedded migration series, the typed queries, both FTS tables | [`doc.go`](../internal/store/doc.go) |
| `internal/md` | the Markdown and frontmatter pipeline; the one point where a byte range becomes public or secret | [`doc.go`](../internal/md/doc.go) |
| `internal/plugin` | the extension contract, the registry, the lifecycle, the reserved names | [`doc.go`](../internal/plugin/doc.go) |
| `internal/vault` | contained paths, atomic read/write, the watcher, backup, the single-instance lock, attachments | [`doc.go`](../internal/vault/doc.go) |
| `internal/auth` | accounts, Argon2id, sessions, invites, CSRF | [`doc.go`](../internal/auth/doc.go) |
| `internal/secrets` | the fence syntax, the secret write path, redaction, reveal, the audit trail | [`doc.go`](../internal/secrets/doc.go) |
| `internal/sync` | the indexer and the invalidation bus | [`doc.go`](../internal/sync/doc.go) |
| `internal/search` | FTS5 query building, ranking, snippets, the authz-filtered merge | [`doc.go`](../internal/search/doc.go) |
| `internal/diff` | the line diff the conflict page renders | [`doc.go`](../internal/diff/doc.go) |
| `internal/httpapi` | the route table, the middleware chain, the handlers, the view models | [`doc.go`](../internal/httpapi/doc.go) |
| `internal/web` | the templ component library, the layouts, the renderer | [`doc.go`](../internal/web/doc.go) |
| `internal/app` | the composition root: sequence, lifetime, report | [`doc.go`](../internal/app/doc.go) |
| `internal/sample` | the campaign the binary carries | [`doc.go`](../internal/sample/doc.go) |
| `internal/testutil` | temp vaults, fixtures, the in-process harness | [`doc.go`](../internal/testutil/doc.go) |
| `internal/systems/**` | plugins: `dnd5e` works, `houserules` and `linkpreview` are features, `example` is built to be refused | — |

**The order itself is not restated here.** It is
[`ADR-0001`](ADR-0001-canonical-dependency-order.md), and the machine-checked
copy is `order` in
[`../internal/architecture_test.go`](../internal/architecture_test.go);
`TestDependencyDirection` walks every package and fails on an import that goes
upward. `app` and `testutil` are exempt because they are the composition root
and the test harness; `sample` and the plugin roots are held to the plugin
boundary instead, and the boundary is a shorter list than the order — it is the
six packages a plugin needs and nothing else.

Two of the edges in that order exist because of the security design rather than
because of convenience, and they are the two ADR-0001 was written for: `authz`
sits below `store` because store's own queries embed the canonical predicate
verbatim, and the arrow between `authz` and `secrets` runs `secrets → authz` so
that the redactor can ask the one question that decides. `authz` is safe to
place that low because it imports nothing of ours — it takes a `Resource`
struct handed to it by a service that already holds the row, so it never holds
a `*sql.DB` and never queries anything.

**The order is a design signal.** A feature that needs data from two packages
that are not adjacent is in the wrong package.

## Where a new thing goes

This is the question the order exists to answer, so it is worth stating flatly
rather than leaving to a reader who has to infer it.

- **A new query goes in `store`.** Not in `httpapi`, not in `app`. A query
  written outside `store` is a query the store's own cross-checks cannot see,
  and `store.TestPredicateMatrixAgrees` — which evaluates every secret-derived
  query as every principal and compares each result against one transcribed
  expectation, and asserts that each list and its count agree — is the
  cross-check that matters.
- **A new markdown construct goes in `md`.** `md` is the single point where a
  byte range of a vault file is classified as public or secret. Every fact
  extracted from a document carries the `md.Span` it came from, and therefore a
  secret id or the empty string. That single classification point is what makes
  "a secret never enters a derived index" implementable rather than aspirational.
- **A new page type goes in a plugin.** A system plugin registers page-type
  schemas; a feature plugin may not, and says what it wants through a
  frontmatter convention instead.
- **A new route is a row in the route table** in
  [`../internal/httpapi/routes.go`](../internal/httpapi/routes.go), and nothing
  else. The table is the contract, and two tests read it: the CSRF check *is*
  derived from it — `Route.Mutating()` is the condition the gate applies to, and
  `TestCSRFRequiredOnAllMutations` walks every row the method makes mutating —
  while the authorization matrix is a second, hand-written table in
  [`../internal/httpapi/matrix_test.go`](../internal/httpapi/matrix_test.go)
  that `TestTheMatrixCoversEveryRoute` holds in step with `Routes()`. A route
  added to one and forgotten in the other is a hole in the evidence, and a hole
  in the evidence is worse than a failing feature: the feature is not known to be
  safe.
- **A new permission is a constant plus a row in `authz.Policy`, in the same
  change.** A boundary with no policy row behind it is a rule nobody wrote
  down, and the `secret_events` audit is the recorded case: it had no
  permission constant at all, so a route mounted for it would have inherited no
  gate, and nothing leaked only because nothing was mounted.
- **A new panel, a new search resolver, a new nav item is a plugin
  contribution**, and the vocabulary that admits it is `internal/plugin`.

## Boot order

`Boot` in [`../internal/app/boot.go`](../internal/app/boot.go) is the one place
a vault is opened, and the order is a contract rather than a preference. The
step names are constants in that file so that
`TestBootTakesTheOrderItClaims` ([`../internal/app/boot_test.go`](../internal/app/boot_test.go))
can assert the sequence **by name**: a reordered boot is a security bug rather
than a style question, and a renamed step should fail that test rather than stop
being checked.

The order and its reasons, briefly, because the reasons are the content and
the list is short:

- **The path is resolved, then the single-instance lock is taken, and nothing
  else happens in between or before.** Nothing in a vault is opened before the
  claim. Two processes over one vault would each hold an index and a watcher
  over the same files, and the loser's writes would be overwritten by the
  winner's watcher with no trace of the conflict. The lock is released on the
  way out of every failure path too, because a process that exits on a boot
  failure must not leave a vault a second instance cannot open.
- **The bundled campaign is extracted next**, because it is the first step that
  writes a vault file and it must finish before the migration and the index —
  a fresh vault's first restore point should not be an empty directory. It never
  overwrites a file that is already there; see
  [`ADR-0005`](ADR-0005-sample-is-bytes-extraction-is-in-app.md).
- **The audit log is a file in the vault**, so it cannot be opened before the
  lock, and it comes after the campaign because "wrote the files the app already
  had" is a boot fact rather than a security record.
- **Then the database, the components that write it, a backup if one is due, the
  migration, the search-index rebuild if the schema generation moved, the pass,
  the housekeeping, the plugins, the watcher, the banner, the listener.**
  `bind` precedes `print` so the banner can name an address a client can
  actually reach, and printing precedes `Serve` so the report is out before the
  first request.

Two things are worth knowing because they are not visible from the list. The
plugin phase runs **after** the index and before anything serves, so a page type
a plugin registered is available to the first request rather than appearing on
the second — and it never fails the boot: a plugin that cannot register is
recorded in the report with a reason and the campaign runs without it, because
a campaign that will not start is a worse outcome than a missing panel. And the
boot has no `WriteTimeout` on the `http.Server`, deliberately, because the
live-push stream is a legitimate response that never ends and a write deadline
is the wrong way to kill it.

The one-shot commands — `reindex`, `backup`, `vault info`, `plugins list` — are
the same boot without a handler. That is why `Options.Handler` may be nil.

## The request lifecycle

The chain is assembled in `chain`
([`../internal/httpapi/middleware.go`](../internal/httpapi/middleware.go)) and
its own comment is the specification; `TestTheMiddlewareChainIsInOrder`
([`../internal/httpapi/csrf_test.go`](../internal/httpapi/csrf_test.go)) walks
it so a reordering fails rather than shipping. Read that comment for the list
and the reason each layer is where it is. Two of the properties it buys are
load-bearing elsewhere:

- **`SecureHeaders` is outside `Session`**, so even a response produced by a
  failure to resolve a session carries the Content-Security-Policy.
- **`Session` is outside the per-route gates**, because `Perm` and CSRF both
  need the principal. It is a single unexported context key with a single
  writer, [`../internal/authz/context.go`](../internal/authz/context.go); a
  context that never went through it reads as the **zero** `Principal`, which is
  anonymous *and* has no public read. That is deliberately not
  `authz.Anonymous(true)`, and `TestTheZeroPrincipalIsNotAnonymousWithRead`
  fails first if somebody "fixes" it.

### The route table, and the two places a role is compared

`Routes()` returns the table. The router mounts every row behind the two
per-row gates inside the loop, so the gates are a property of the row rather
than of the call site, and both the CSRF check and the authorization matrix are
held against the same list.

**`authz` is the only package that compares a role.** Everything else asks the
policy. In `httpapi` that is two points, and the second one is the one that is
easy to get wrong:

1. **The `Perm` middleware** — `Server.checkPerm` calls `Policy.Check` with the
   row's permission. It calls it with a **zero `authz.Resource`**, so a
   resource-scoped permission is answered as its coarse form and the policy's
   ownership arm is unreachable through it. The page-scoped write rows are
   `PermSession` in the table for exactly that reason, and the reasoning is in
   the comment on those rows in
   [`../internal/httpapi/routes.go`](../internal/httpapi/routes.go).
2. **`httpapi.mayWritePage`**, inside the handler, which is the one that carries
   the page's ownership: it reads `store.IsPageOwner` and asks the policy with
   `authz.Page(pageID, owner)`. It is also the check the secrets service makes
   before it writes.

`internal/secrets` asks the policy again, inside the service, before it looks
anything up — the ordering is the security property, because a principal that
may not reveal must get the same answer in the same time for every id and cannot
use the difference as an oracle. That is why
[`../internal/httpapi/secretsroute.go`](../internal/httpapi/secretsroute.go)
decides nothing: the permission, the byte-surgical rewrite, the audit row, the
generation bump and the reindex all live in `secrets.Service.SetVisibility`.

**The rule is enforced, and the gate is a scan of the syntax tree rather than a
grep.** `TestNoRoleComparisonOutsidePerm` in
[`../internal/architecture_test.go`](../internal/architecture_test.go) reads
every non-test file in the module and refuses three shapes: a `==` or `!=`
between two role expressions, a `switch` over a role, and a container indexed by
a role. A grep would not do the job for the reasons
`TestNoOutboundNetwork` gives — prose cannot trip a syntax scan, so a file may
explain the rule (and `internal/systems/houserules/plugin.go` does), and a
comparison split across a line break is still a comparison. One package is
exempt, `internal/authz`, and the exemption is not a hole: it owns the `Role`
type and the policy table, so its comparisons are the rule rather than a copy of
it, and the length of that list is itself a test. The gate carries a 21-case
self-test and two vacuity guards, and it refused a real violation when it was
written — a switch on a role in `httpapi`, which is now
`authz.PermissionForRole` in
[`../internal/authz/vocabulary.go`](../internal/authz/vocabulary.go). Two Go
comments still call it a grep; the code is the specification, and the gate is
real.

### From a handler to a response

A handler receives a resolved principal and a view model, and never inspects a
role. It negotiates its shape with one function and ends at one choke point:

- `Negotiate` ([`../internal/httpapi/negotiate.go`](../internal/httpapi/negotiate.go))
  is a **single header** and nothing else. There is no query parameter, no
  alternate URL and no second route, so the link in a rendered page and the
  same link followed by hand produce the same URL and the same permission check.
- `Server.Render` ([`../internal/httpapi/server.go`](../internal/httpapi/server.go))
  is the one place a response is produced, and the fragment is the same
  component the document nests, so the two cannot drift.

That choke point is what lets the live-push path call an ordinary handler
verbatim: the bytes a subscriber receives are the bytes the ordinary handler
would have produced under **that subscriber's own captured principal**. The
stream itself carries a trigger and never content, and it terminates on any
authorization change — which is what `authz_generation` is for.

Two error properties that several surfaces depend on: `httpapi.writeError`
renders from a fixed copy table with nothing in the model that could differ
between two renderings, which is why a page the viewer may not read, a secret
the viewer may not read and a thing that does not exist all answer with the
same bytes. And a plugin-owned route could not reach `writeError` at all,
because it is unexported and `httpapi` is on the plugin boundary's forbidden
list — which is why the link-preview summary route is core's.

## The plugin boundary

A plugin is **first-party Go code compiled into the binary**. There is no
sandbox and no isolation, and the contract says so plainly. What it buys is
capability narrowing against accidental damage, and one property that matters
more than the rest: **a plugin cannot ship JavaScript, a stylesheet or a DOM
handle.** Plugins return `templ.Component` values and Go values; the app shell
and the stylesheet are core-owned. That is why the link-preview interaction is
implemented once in core rather than once per plugin, and it is a property of
the pipeline rather than a claim about the plugins in the tree.

`AGENTS.md` §7 and [`plugins.md`](plugins.md) are the specification; this
section says only what a new engineer needs in order not to walk into the
traps, each of which is recorded where it lives.

- **Where a plugin may put things.** Page types, panels, nav items, search
  resolvers, summary providers, migrations and a sub-router under its own
  prefix — and nowhere else. The prefix is applied by `httpapi` at mount time
  from the registry's own record of which plugin owns the router, so a plugin
  cannot mount at a prefix it does not own. A `KindFeature` may not register a
  page type; that is a boot error for that plugin.
- **The import allow-list is six of our packages** — `plugin`, `md`, `store`,
  `web`, `authz`, `secrets` — and `internal/diff` is deliberately not one of
  them: an allow-list entry is a grant, and a plugin that needs a diff gets one
  line added on purpose. `TestPluginImportsAreWithinBoundary` enforces the list,
  and `forbiddenInPlugins` carries the reason each forbidden package is
  forbidden, so a failure explains the rule rather than printing a list diff.
- **The one registry is [`../cmd/semiplane/registry.go`](../cmd/semiplane/registry.go)**,
  and it is there because three constraints meet at once and nowhere else:
  `internal/plugin` cannot name implementations without a cycle, the plugin roots
  cannot name a sibling plugin without letting a plugin reach something it was
  given, and `app` cannot import a plugin at all — a plugin imports `web`, `web`
  imports `httpapi`, and `httpapi` imports `app` for the build metadata in the
  footer. `TestNoPluginSwitchInCore` fails the build if a second place names a
  plugin id, and the test's own acknowledgement is worth reading before you trust
  it — one of its collectors once listed a directory without recursing, and a
  plugin *is* a directory, so the gate skipped silently forever.
  `TestTheArchitectureGatesHaveSomethingToCheck` is the pattern that fixes that
  class of failure.
- **A mount is not a row.** `chain` wraps the whole router, so a mounted
  sub-router inherits session, headers, rate limiting and the request log — but
  the CSRF and `Perm` gates are applied *per row inside the table loop*, and a
  mount is not a row. `httpapi.mountPluginRoutes` re-applies both at
  `PermSession`, and neither `TestCSRFRequiredOnAllMutations` nor
  `TestTheMatrixCoversEveryRoute` can notice if it is dropped, because both read
  the static table rather than the mounted chi tree.
  `TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest` in
  [`../internal/httpapi/pluginmount_test.go`](../internal/httpapi/pluginmount_test.go)
  is the test that can, and it has to ask the CSRF question per request rather
  than once at mount time — [`plugins.md`](plugins.md) §8 has why, and what
  shipped when it did not.
- **`newHost` collects before `Register` runs**, so a contribution that captures
  host state at construction captures it before the plugin exists. Hold a
  `func() plugin.PageStore` and call it at request time.
- **The plugin's `fs.FS` is deliberately `nil`.** The redaction it would need
  exists in exactly one place, the page view, and extracting it under time
  pressure is the most likely way to put a secret where a plugin can see it. The
  reason is in [`../internal/app/plugins.go`](../internal/app/plugins.go).
- **`Host.Pages()` is four named methods, not a `*sql.DB`.** Every one takes the
  principal and applies the canonical predicate itself, so there is no predicate
  left for a plugin to get wrong — a hand-rolled OR-chain is how a `dm` secret
  reaches a page owner.

Adding a plugin is one directory, one map entry, and sample content if it needs
any. [`PLUGIN_AUTHORING.md`](PLUGIN_AUTHORING.md) is the procedure, and
[`ADR-0006`](ADR-0006-fences-not-frontmatter.md) is the one design constraint
that has already bitten: a plugin cannot hide a *page*, only a span of its body.

## Generated files

`*_templ.go`, [`../web/static/app.css`](../web/static/app.css) and
`../web/static/vendor/datastar.js` are generated and committed. They are never
hand-edited, and CI regenerates and diffs them, so a stale artefact fails
`generate-check` or `css-check` rather than shipping. The Makefile is the
specification for the targets; `make check` is the gate.

The reason they are committed rather than built on demand is the deployment
promise in [`ADR-0002-pure-go-sqlite.md`](ADR-0002-pure-go-sqlite.md): one
static binary a DM can move to a thumb drive. A build step is a step somebody
has to have.

Two of the three embeds live outside `internal/`, which surprises people:
[`../web/embed.go`](../web/embed.go) holds the assets, because an embed pattern
may not contain `..`, and the alternative the package's own comment records
having had is a hand-synced copy of the generated tree beside its code — a
duplicate that is a divergence waiting to be reported by somebody else. The
migration series is embedded from `../internal/store/migrate.go`. The sample
campaign is the third embed; see
[`ADR-0005`](ADR-0005-sample-is-bytes-extraction-is-in-app.md).

## What is deliberately absent

This project is unusually deliberate about its non-features, and a reader who
does not know about them will assume they were overlooked. Each of these is a
decision with a reason; none of them is a gap.

- **There is no rendered-page cache**, and there is no plan to add one without
  a key of `(pageID, userID, authz_generation)`.
  [`ADR-0003`](ADR-0003-no-rendered-page-cache.md) is the whole argument, and
  `TestNoRenderedPageCache` is the gate — it passes while there is no cache and
  fails the moment one appears. The invalidation bus exists instead.
- **A page has no visibility.** v1 has no per-page ACL, and the mechanism that
  does hide content is a `visibility=` fence in a page's body. Anything
  describing a "DM-only page" is describing something this model cannot
  express: [`ADR-0006`](ADR-0006-fences-not-frontmatter.md).
- **There is no runtime tripwire.** The design plan describes a response-writer
  wrapper that scans outgoing bodies for secret plaintext; nothing like it
  exists in non-test code, and there never was. What exists is test-level
  equivalents, which are arguably stronger for what they can prove: the demo-path
  walk in
  [`../internal/httpapi/tripwire_test.go`](../internal/httpapi/tripwire_test.go)
  and the wider walk **derived from the route table** in
  [`../internal/httpapi/leaksuite_test.go`](../internal/httpapi/leaksuite_test.go).
  The scanner's own proof that it has teeth is a test instrument and nothing
  more — do not read it as evidence that a leak in production would be caught
  at runtime. `spec.md`'s divergences are the record.
- **There is no outbound network of any kind.** No telemetry, no analytics, no
  CDN, no remote font or script; every asset is embedded and served from
  `/_/assets/`. `TestNoOutboundNetwork` greps for client-side *capability*
  rather than for the `net/http` import, because a server legitimately imports
  `net/http` and a background goroutine dialling home would never appear in a
  rendered page.
- **There is no campaign-wide export, and no create, delete or `/admin/users`
  route.** The router mounts what the table lists. `vault.Writer`'s `Delete` and
  `Move` verbs exist and are tested directly, and the rename is the only one a
  route reaches. The vault-wide export is refused on the argument in
  [`../internal/httpapi/export.go`](../internal/httpapi/export.go): it has no
  per-page authorization question to ask, so it would be a copy of the plaintext
  ADR-0004 already accepts is on the disk.
- **A plugin's `fs.FS` is `nil`**, deliberately, for the reason in
  `internal/app/plugins.go`.
- **The plugin's summary route is core's**, not the plugin's, so that a summary
  of a page the viewer may not read is byte-identical to navigating to that page.
  A distinguishable 404 is the probe the requirement exists to prevent.
- **`internal/systems/core` is a `doc.go` and nothing else.** There is no core
  system plugin, because core behaviour is core. The package exists so a reader
  looking for "where is the built-in game system" finds a statement rather than
  an empty directory.
- **The VTT — maps, initiative, dice — is not built**, and neither is the
  remainder of the create/delete/user-management work. `spec.md` §6 lists what is
  concretely absent from the tree so that nobody goes looking.
- **A file that is not a page still gets a `pages` row**, and the indexer
  writes one for every file in the vault. That is an open, security-relevant
  finding rather than an accepted design, it is recorded in `spec.md`'s
  divergences, and a test asserts the behaviour in *both* directions so it
  fires the day it is closed. It is named here because the honest reading of
  "what does not exist" is not the same as "what has no bug".

## Divergences

Where this document and the code could disagree, the code is right. Two places
where a reader of this document should go to the source rather than to me:

1. **The dependency order is not written out here.** It is
   [`ADR-0001`](ADR-0001-canonical-dependency-order.md) and the `order` slice
   in the architecture test. If those two ever disagree with each other, the
   test is what the build runs.
2. **The boot order is summarised, not enumerated.** The step constants and the
   comment on each are in `internal/app/boot.go`, and
   `TestBootTakesTheOrderItClaims` asserts the sequence by name.
