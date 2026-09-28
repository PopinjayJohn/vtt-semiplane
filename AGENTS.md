# AGENTS.md

Working agreement for this repository. Every rule here is either enforced by a
test in `internal/architecture_test.go` or by a CI gate. If a rule is not
enforceable, it is marked as such — do not add unenforceable rules, and do not
weaken an enforced one to make a change convenient.

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
5. **Never add an HTTP client to the request path.** No telemetry, no
   analytics, no CDN fetches, no font or script from a remote origin. Every
   asset is embedded and served from `/_/assets/`.
6. **Never call `templ.Raw` on a vault-derived string.** And never enable
   goldmark's `html.WithUnsafe()`. Raw HTML in vault content is disabled.
7. **Any new route must be added to the route table in
   `internal/httpapi/routes.go` and to `TestAuthorizationMatrix`.** The `Perm`
   middleware is the only place a role is compared; a grep test fails the build
   on a `Role ==` comparison in a handler.
8. **A rendered-page cache does not exist in v1, and adding one requires
   keying by `(pageID, userID, authz_generation)`.** There is deliberately no
   cache: it is a whole class of secret-leak bugs for no measurable gain on a
   local SQLite vault.

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
  httpapi/              chi router, middleware chain, handlers
  web/                  templ components, layouts, DataStar handlers
  sample/               embedded sample campaign
  testutil/             temp vaults, fixtures, in-process harness
web/src/input.css       Tailwind v4 entry
web/static/             generated css, app shell js, vendored datastar
tools/                  Makefile, goreleaser, pinned versions
docs/                   ADRs and plugin authoring guide
```

**Dependency order, lowest first. A package may import itself and anything
earlier; never later.**

```
config < obs < authz < store < md < plugin < vault < auth < secrets < sync < search < httpapi < web
```

`app` is exempt and imports everything — it is the composition root.
`testutil` is exempt and imports everything — it boots the app in-process.
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
  `TestWatcherSuppressesSelfWrites`, `TestReconcileScanFindsMissedEvent`,
  `TestConcurrentSaveSamePath`.
- Authorisation: `TestAuthorizationMatrix`, `TestSecretVisiblePredicateMatchesMatrix`,
  `TestOnlyPermMiddlewareIsConsulted`, `TestNoHandRolledVisibilityPredicates`,
  `TestCSRFRequiredOnAllMutations`.
- Secret redaction: `TestSecretFixturesNeverLeak`, `TestTripwireFiresOnLeak`,
  `TestSecretBodyNeverInErrorsOrLogs`, `TestRawViewRedactsSecrets`,
  `TestCampaignStatusIsFieldLevelAuthorized`.
- Live push: `TestPushNeverLeaksSecret`,
  `TestPushAndFetchProduceIdenticalFragments`, `TestPushTerminatesOnRoleChange`,
  `TestPushDropsSlowConsumer`, `TestPushCoalescesBurst`,
  `TestPushRevokeSendsReloadEvent`, `TestTripwireAlsoCoversPushWrites`.

A test that passes vacuously — because the code path it claims to cover does
not exist yet — is worse than no test. When a surface arrives in a later phase,
its secret tests live in that phase, where the code is.

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
- Only a DM or an admin may reveal or revoke. A page owner may create and edit
  their own secrets; ownership grants authoring rights, not broadcast rights.
- Redacted editing: an unreadable secret becomes the sentinel
  `‹s:<id>:<bodyLen>:<bodySHA256first8>›`. On save, each sentinel is recomputed
  from the current on-disk body; a match is spliced back byte for byte, a
  mismatch rejects the whole save. Never detect sentinels by regex over the
  buffer — match by position against the known secret set.
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
- `TestSecretFixturesNeverLeak` runs on every CI run, over every page type in
  the sample campaign, as every role, asserting the response body, the headers
  and the `data-signals` payload contain no fixture secret the principal may
  not read. Never mark it skipped.

## 7. Plugin development

Adding a plugin — a game system or a feature — requires exactly: one directory
under `internal/systems/<id>/`, one map entry in the registry, and sample
content if it needs any. No core file changes, and a grep test
(`TestNoPluginSwitchInCore`) fails the build if a plugin id appears anywhere
else.

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
- Link previews: the plugin supplies `GET /plugin/{id}/summary/{pageID}` and
  core owns hover, focus, the pin toggle, `Esc` and the ARIA wiring. A summary
  of a page the viewer cannot read returns **404**, byte-identical to
  navigating to it — a preview must not become a way to probe for pages.

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
| `make check` | **the CI gate**: fmt-check, generate-check, css-check, lint, test |
| `make cross` | five release binaries |
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
- **`make css` needs a local filesystem.** The Tailwind v4 scanner takes about
  a second on local disk and exceeds four minutes anywhere under
  `/mnt/gamedrive`, with identical binary, input and components — the mount's
  filesystem walk is the cost, not the CSS, so neither narrowing the `@source`
  globs nor building in a temp directory helps. The stylesheet is committed and
  `web/static/app.css` is the artefact of record. Keep the `@source` list in
  `web/src/input.css` explicit: `internal/md/*.go` is on it because the markdown
  renderers emit class attributes for passthrough blocks, callouts and mermaid,
  and dropping that line silently removes those classes on the next rebuild.
- **Never run `go test ./...` bare on this machine.** It links and runs one
  test binary per package, up to `NumCPU` at a time, and every package that
  pulls in `modernc.org/sqlite` links a very large pure-Go libc. That exhausted
  RAM *and* zram swap. Use `make test` / `scripts/test.sh`, which pins `-p 1`,
  bounds subtest parallelism, sets `GOMEMLIMIT` and puts a timeout on every test
  so a spin panics with a stack trace naming the spinning frame.
