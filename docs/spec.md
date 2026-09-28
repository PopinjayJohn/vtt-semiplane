# Specification: what the code does today

This is the durable copy of what the design plan says and what the tree
implements, for an agent that has neither. The plan itself is **not in the
repository** — it lives in `.kilo/`, which is gitignored — so [`docs/README.md`](README.md)
and the documents beside this one are the only design a new agent can find.

## The rule this document follows

**A fact the code owns is pointed at, not restated.** Where the code has a file,
a parser, a type or a test that is the authority, this document names it and
links it. A document that repeats a fact the code owns can be wrong while
looking authoritative, and this repository has a recorded case of exactly that:
the plan documented the secret fence's `title` as optional and unquoted, the
parser read an unquoted value containing a space as an unknown key, and an
unknown key meant public passthrough — so an author who followed the
documentation served a DM's secret body in plaintext to a player, and a test
pinned the unsafe behaviour. **When this document and the code disagree, the
code is right and this document is the bug.**

Rules that are enforced rather than described are enforced by a test in
[`../internal/architecture_test.go`](../internal/architecture_test.go) or by a
CI gate; they are in [`../AGENTS.md`](../AGENTS.md), which is the working
agreement and is correct about the present tense.

---

## 1. What this is

`vtt-semiplane` is a LAN-hosted TTRPG wiki and a player+DM tool. A vault of
Obsidian-compatible Markdown files **is** the campaign; the app indexes it,
renders it, and serves it to a small group of authenticated users with per-page
authorization. The design plan is settled on this point in its decisions table
(one vault = one campaign, plaintext secrets at rest, invite-based real
accounts) and the code has not moved from it.

**The one-line contract: the Markdown file is canonical; every derived artefact
is derived and disposable.**

That has exactly three consequences, and every rule in the repository falls out
of one of them.

| Consequence | What it means in the code |
|---|---|
| Content enters the index only by reading a file. | `internal/sync` never writes to the vault. The only write path is `vault.Writer` — see [`../internal/vault/writer.go`](../internal/vault/writer.go), whose `Save` is hash-checked and atomic. |
| Content leaves the app only through `vault.Writer`. | Nothing else may write a vault file the user can reach. The bytes are never reflowed, normalised or re-serialised; the renderer is a *view*, not a formatter. |
| SQLite, FTS, rendered HTML, backlinks, the dashboard are caches. | The whole index can be deleted and rebuilt from the vault. `semiplane reindex` is that rebuild — see [`../internal/app/commands.go`](../internal/app/commands.go). |

Concretely, per-file: `vault.Read` returns the bytes, `md.Parse` classifies
them, `sync.Indexer.Index` writes one transaction of derived rows, and the
secret's reveal state is expressed **in the file** as a `visibility=` token in
the fence directive — never in the database. The database mirrors it.

**Where the plan's §1 request-lifecycle diagram is out of date:** it lists a
"redact filter over the response body" as the last step. There is no such
runtime filter. See [Divergences](#divergences).

---

## 2. The data model

**The authority is [`../internal/store/migrations/0001_init.sql`](../internal/store/migrations/0001_init.sql).**
Read that file; it is the whole §6.2 schema plus three documented additions, and
each addition is commented at its own definition with the reason it was forced.
Do not take the shape from this section or from the plan — take it from the
migration, and check the migration's comments for the deltas.

What follows is *why* the shape is what it is. Nothing here restates a column.

### Two FTS tables, and the property is structural

`page_fts` holds public content only. `secret_fts` holds a secret body **only
while its visibility is `table`**. The barrier is not a filter that a predicate
bug can defeat: `store.IndexSecretText` refuses any visibility but `table`
before it writes, and `store.CheckSecretIndexInvariant` counts the rows that
should not be there — `app.Boot` runs it on every boot, rebuilds the search
tables if it is not zero, and re-asserts it afterwards, so a poisoned cache is
repaired rather than served. A page's public text is the only thing `page_text`
ever sees, and a test asserts the absence of each fixture secret from
`page_text`, `page_fts` rowids, a real `MATCH` query and the rendered snippet.

### `page_owners` is the ownership source of truth

`pages.owner_id` records the *primary* owner for the common single-owner case
and is always mirrored as a `page_owners` row. Authorization reads
`page_owners`; the `pages` column is a convenience that is never the authority.
The two are kept in step only by the caller that manages the primary owner,
inside its own transaction — see `store.AddPageOwner` and
`store.RemovePageOwner` in [`../internal/store/page.go`](../internal/store/page.go),
whose doc comments state the constraint.

**Ownership is currently never populated by the indexer.** There is no
frontmatter convention for it in the tree. The effect is fail-closed: on a
fresh vault a `private` secret is readable by its author, DMs and admins only.

### `links.secret_id` is the whole design

Every fact extracted from a document — a link, a heading, a tag — carries the
secret it was written in, or the empty string for public. That single
classification is what makes "a secret never enters a derived index"
implementable rather than aspirational, and it is why a heading inside a secret
is filtered out of the table of contents: **a heading's existence is itself a
leak.**

The span that carries it is `md.Span` — see §3. The rows are `store.Link`,
`store.Heading` and the secret-aware `page_tags` rows; their Go shapes are in
[`../internal/store/page.go`](../internal/store/page.go).

### The one predicate

`authz.SecretVisibleSQL` in
[`../internal/authz/predicate.go`](../internal/authz/predicate.go) is the only
secret-visibility predicate. Every query that can return a secret-derived row
uses it **verbatim**, and its `COUNT` uses the identical statement rather than a
paraphrase — `store.BacklinkCount` and `store.HeadingCount` are literally the
same SQL wrapped in `SELECT COUNT(*) FROM (…)`, which is why there is nothing
in them that can drift from the list beside them. The Go-level equivalent for a
single secret is `authz.CanReadSecret`, in the same file, and both are denied an
unknown visibility.

`TestNoHandRolledVisibilityPredicates` fails the build on a
`visibility = '…'` literal anywhere outside `internal/authz`. The constant's own
doc comment explains why `dm` deliberately falls through every clause: only the
`:is_dm` branch can see it, and that is the row an OR-chain gets wrong.

**One caveat a new agent must know.** The SQL predicate's table-visibility
clause has no authentication guard, while `authz.CanReadSecret` requires an
authenticated principal for the same visibility — so **the two are not the same
predicate for an anonymous request.** The gap is closed structurally, not by
the predicate: `store.publicOnlySQL` appends a public-only clause for every
unauthenticated principal, `store.maySeeAnySecret` refuses one outright, and
`search.Query` skips the secret statements entirely for an unauthenticated
principal. All three say so in their own comments. Any new query that touches a
secret-derived row must go through `publicOnlySQL` or it reopens the gap.

### Migrations

`store.Migrate` takes a **backup hook** and refuses to run without one, then
applies each pending embedded file in its own transaction, then updates
`user_version`. A database newer than the binary is refused at boot with
`store.ErrSchemaTooNew`. See
[`../internal/store/migrate.go`](../internal/store/migrate.go).

---

## 3. The Markdown pipeline

Everything is in [`../internal/md/`](../internal/md/), whose package comment
states the package's one job: it is the single place where a byte range of a
vault file becomes classified public or secret.

### The order of operations

1. **Frontmatter split.** `md.SplitFrontmatter` locates the leading fence block
   by byte range *before* any parsing, and keeps three ranges on the `md.Doc`:
   the whole fenced block, the YAML inside it, and the body after it. A UTF-8
   BOM is held separately on `md.Doc.BOM` so it survives — it belongs to
   neither range. `md.ParseFields` then reads the YAML for use; the raw bytes
   are what is stored and re-emitted, and the parsed map is read-only
   downstream. Invalid YAML is a `md.Problem` on the document, and the document
   is still indexed and still rendered.
2. **Secret segmentation.** `md.Parse` (and `md.Segment`, which is the same
   thing without a path) runs a **byte-level** scanner over the body and
   partitions it into `md.Span` values, one per byte, ascending, never
   overlapping. It is a byte scanner and not the AST on purpose: goldmark has
   thrown the offsets away by the time an AST exists, and a misparse that
   reaches the renderer becomes a *rendered* secret.
3. **Rendering.** `md.New` builds one composite goldmark parser — the only place
   the parser is assembled, so it is the only thing to audit. `RenderDoc` takes
   a `*md.Doc`, and the renderer sees only what `Doc.PublicSpans()` produced.
   Raw HTML in vault content is disabled (`html.WithUnsafe` is **not** set, and
   `md.Renderer`'s doc comment says why); `TestRawHTMLIsNotRendered` is the gate.
   Unsupported Obsidian syntax renders as an escaped passthrough block
   captioned `md.PassthroughLabel`.
4. **Extraction.** `md.Extract` walks the AST and returns `md.Extracted` —
   title, aliases, tags, links, headings, attachments, page type, code
   languages — where every field that could have come from inside a secret
   carries the `md.Span` it came from.
5. **Link resolution.** `md.NewResolver` / `md.Resolver` implement §5.6's
   order: exact path, then basename, then alias, with shortest-path and
   lexicographic tie-breaks decided **once at construction** so `Resolve` is a
   map lookup and two runs over the same pages always agree. Aliases match
   case-insensitively. The indexer is what actually resolves against the
   database; `internal/sync` owns that half.

### The secret fence

**The syntax is defined by the parser, not by this document.**
[`../internal/md/secret.go`](../internal/md/secret.go) holds
`md.IsSecret`, `md.ParseFenceDirective` and `md.Directive`, and the key set is
the closed set of constants at the top of that file (`md.KeyID`,
`md.KeyVisibility`, `md.KeyAuthor`, `md.KeyCreated`, `md.KeyTitle`). One
implementation of the grammar, shared by the reader and the writer, is the whole
point — two implementations of a closed grammar drift, and the drift shows up as
a secret rendered in plaintext.

Two rules a writer must know, both of which are enforced by tests rather than
by convention:

- **A value containing a space must be quoted.** `title="The Vault Door"`, not
  `title=The Vault Door`. `md.scanDirectiveFields` is quote-aware for exactly
  this reason and its comment names the failure it prevents. The regression
  tests are
  [`TestQuotedDirectiveValueDoesNotDemoteASecretToPublic`](../internal/md/secret_demotion_test.go)
  and `TestQuotedDirectiveValueStillSegmentsAsSecret` in
  [`../internal/md/segment_test.go`](../internal/md/segment_test.go).
- **A fence that claims secrecy gets it, whatever its directive says.** An
  unparseable directive, an unknown key, an unterminated fence, a nested fence:
  the block is secret and a `md.Problem` is recorded, with the one documented
  exception in `md`'s own `ProblemSecretUnknownKey` comment. A fence the
  segmenter cannot read is *hidden, not demoted* — see
  `TestAnUnunderstoodSecretFenceNeverBecomesPublic`.

The consequence of "hidden, not demoted" is that a malformed fence is invisible
even to its author until it is fixed. That is fail-closed by design, and it is
why the problems are surfaced by the indexer rather than swallowed.

### Byte-preserving edits

`md` owns every structured edit, and each is a splice on a bounded range rather
than a re-serialisation: `md.PatchFrontmatter`, `md.AddTags`, `md.AddAliases`,
and `md.SetVisibility` (with `md.Reveal` and `md.Revoke` as its two named
specialisations). `md.Resave` is a no-op that returns the file verbatim, which
is what "unchanged means no write" looks like.

`md.SetVisibility`'s doc comment is the specification of reveal: **only the
`visibility=` token changes**; the fence, its id, its author, its created
timestamp, its title and the body are untouched, because the fence is what
carries the id, the audit trail and the revocability. The regression test is
`TestVaultRoundTripPreservesSecretBytes` in
[`../internal/md/reveal_test.go`](../internal/md/reveal_test.go), and
`TestRevealPreservesSecretID` in
[`../internal/md/secret_demotion_test.go`](../internal/md/secret_demotion_test.go)
is the one that kills the "unwrap the fence" implementation.

`internal/secrets` owns everything above that: authorization, the write, the
audit and the re-derivation of the index. See
[`../internal/secrets/service.go`](../internal/secrets/service.go) and
[`../internal/secrets/fence.go`](../internal/secrets/fence.go).

---

## 4. The index

[`../internal/sync/`](../internal/sync/) turns files into rows. Its package
comment names the two properties that are the whole contract; both are
structural, and both have tests that would fail if either stopped being true.

**Idempotence.** A file whose sha256 already matches its indexed row costs one
read and one comparison and writes nothing, and the result reports
`Result.Unchanged` so a subscriber is not woken for it. A reconciliation scan
over an unchanged vault is free, and a pass may run as often as the watcher
likes. Pinned by `TestIndexIsIdempotent` and `TestIndexIsIdempotentAfterAReconcile`.

**One transaction per changed file.** The page row, its aliases, tags, links,
headings, revisions, `page_text` and the FTS rows are written through the same
transaction, so a reader never sees a page without its derived rows. A crash
mid-transaction rolls back and the next scan re-derives the file from bytes that
are still on disk, because the file is canonical. Pinned by
`TestConcurrentIndexOfOneFileHasOneWriter`.

The passes are `Indexer.Index` (one path — and a path whose file has gone is a
deletion, because the watcher reports the two with the same shape),
`Indexer.IndexBatch`, `Indexer.Reconcile` (a `vault.Scanner` diff over the whole
vault) and `Indexer.Walk`. `Indexer.RemoveMissing` is what makes `--reindex`
actually rebuild, and **`Reconcile` does not reset it**: deleting every page row
and then re-running a delta pass reports "nothing changed". Anything that means
"rebuild the index" must use the full walk — see `app.reindexPass`.

**Rename detection** is `Indexer.RenameDetect`, and it acts only on a
content-hash match inside `sync.DefaultRenameWindow` (60 s). A copy is not a
rename and a same-content coincidence a week apart is not a rename; a confirmed
rename records the old name as a `page_aliases` row and nothing else, and never
rewrites the user's prose. Pinned by
`TestRenameDetectionRequiresContentMatch` and
`TestAliasResolutionSurvivesARename`.

**Publication** is the invalidation bus: `sync.Bus`, `sync.Publish`,
`sync.PageInvalidated`, `sync.ChangeKind`. An event carries **a page id, a path,
a hash and a kind — never content, and never an authorization decision.** A
subscriber fetches the page with its own captured principal. The bus coalesces
per page and is bounded (`sync.DefaultQueueDepth`); a panic in one subscriber
detaches it and leaves the others running. Pinned by
`TestPublishNeverBlocks` and `TestTheQueueIsBounded`.

**Self-write suppression** is hash-based, not time-based
([`../internal/sync/selfwrite.go`](../internal/sync/selfwrite.go)), so a genuine
external edit to the same path inside the window still lands. The watcher
itself is a latency optimisation; the reconciliation scan is the correctness
guarantee, because fsnotify is not recursive and inotify watches can be dropped.

A fence naming an author that is not a known account is **reported and not
indexed** rather than indexed against a fabricated author, because
`secrets.author_id` is a foreign key and a sentinel user is a principal that
could come to own things. `Indexer.RetryUnresolvedAuthors` exists so that an
account created after the first read can be applied without a full reindex.

---

## 5. The request lifecycle

[`../internal/httpapi/`](../internal/httpapi/). One request, one transaction,
one view model — and the middleware chain is written down as a contract in
[`../internal/httpapi/middleware.go`](../internal/httpapi/middleware.go)'s
`chain`, outermost first, and `TestTheMiddlewareChainIsInOrder` walks it.

**The route table is the contract.** `Server.Routes` in
[`../internal/httpapi/routes.go`](../internal/httpapi/routes.go) is a function
returning `[]Route`; `router()` mounts it, wrapping each handler in CSRF (for
a mutation) and then `Perm`. The matrix test and the CSRF test are both
*derived* from that one list, so neither can drift from what is served. A route
that is not in the table does not exist.

`Perm` is the only place a role is compared. `Server.permit` calls
`authz.Policy.Check` with the route's `authz.Permission`; a handler receives a
resolved `authz.Principal` and a view model and never inspects a role. Two
refusals are worth knowing because they are deliberate: a closed `/setup` is a
**404, not a 403** (`authz.ErrSetupClosed`), and an unauthenticated *safe*
request is redirected to `/login` while an unauthenticated mutation is a 403.

**The response shape is negotiated by one header.** `httpapi.Negotiate` reads
`httpapi.DataStarRequestHeader`; `ShapeFragment` means "the content region on
its own", anything else is `ShapeDocument`. There is no query parameter, no
alternate URL and no second route, so a link in a rendered page and the same
link followed by hand produce the same URL and the same permission check.

**One choke point.** Every handler ends by handing one view model to
`Server.Render`, which calls `httpapi.Renderer` — an interface with a document
method and a fragment method, implemented by `web.Renderer` in
[`../internal/web/view.go`](../internal/web/view.go). The fragment is the same
templ component the document nests, so the two cannot drift. That single choke
point is what a later phase's live-push path needs: it can call a handler
verbatim and the bytes a subscriber receives are the bytes the ordinary handler
would have produced under that subscriber's own principal.

**The page view reads the file, not the index.** `Server.page` looks the page
up in the index for its identity and then reads the bytes from the vault through
`vault.Resolve` + `vault.Read`. A file that has gone or cannot be read is a 404,
because a page the viewer may not read is a 404 too and the two must not be
distinguishable — `TestA404IsTheSameAnswerForEveryKindOfNothing` asserts that
byte for byte across every kind of "nothing here", and the error model has no
field in which a path or a title could differ
([`../internal/httpapi/errors.go`](../internal/httpapi/errors.go)).

**Secrets are decided twice, independently.** Every query in the page view is
filtered in SQL by the canonical predicate. The one decision made in Go is the
per-secret one, made by `authz.CanReadSecret`, and the body is then read through
`secrets.Service.Load`, which applies the predicate again. Two gates, neither a
re-statement of the other's logic. A secret the viewer may not read renders as
`secrets.LockPlaceholder` — an opaque id and the word "hidden", and nothing
else, not a length, an author or a title.

**Two rendering hazards, both closed.** goldmark's inline loop is quadratic in
the length of a single line, so the page view clips the renderable body to a
fixed cap and says so in the view model rather than truncating silently. And
`web.PreRendered` / `web.Escaped` in
[`../internal/web/html.go`](../internal/web/html.go) are the only two
`templ.Raw` call sites in the tree;
`TestOnlyThisPackageMarksHTMLRaw` walks `internal/` and fails on any other.

**Everything is embedded.** `/_/assets/*` serves the committed
`web/static/` tree out of the binary via the module-root `web` package, and a
test asserts that no rendered page contains a remote asset reference.

---

## 6. What stage 1 delivers, and what is not built yet

Stage 1 is the plan's **P0–P3 and P6** — every package in the module, from
`cmd/semiplane` to `internal/web`. It is one binary that boots, takes the vault
lock, indexes Markdown, authenticates a real account, and serves a page — with
its table of contents, its backlinks, its tags and its secret boxes,
authorization-filtered.

Delivered and enforced today:

| Area | Where |
|---|---|
| Package skeleton, dependency order, CI greps | [`../internal/architecture_test.go`](../internal/architecture_test.go) |
| SQLite: two pools, the embedded migration series, the FTS tables, the typed queries | [`../internal/store/`](../internal/store/) |
| The whole Markdown pipeline, byte-preserving edits, two fuzz targets, 132 golden fixtures | [`../internal/md/`](../internal/md/) |
| FTS5 query building, ranking, snippets, the two-query merge | [`../internal/search/`](../internal/search/) |
| Vault: contained paths, atomic writes, the watcher, backup/restore, the single-instance lock, the case-collision gate | [`../internal/vault/`](../internal/vault/) |
| Indexer, invalidation bus, rename detection, self-write suppression | [`../internal/sync/`](../internal/sync/) |
| The secret write path: reveal, revoke, audit, the authorised body read | [`../internal/secrets/`](../internal/secrets/) |
| Accounts, Argon2id, sessions, invites, CSRF | [`../internal/auth/`](../internal/auth/) |
| The policy and the canonical predicate | [`../internal/authz/`](../internal/authz/) |
| Router, middleware chain, route table, view models, negotiation | [`../internal/httpapi/`](../internal/httpapi/), [`../internal/web/`](../internal/web/) |
| Composition root, boot order, one-shot commands, CLI | [`../internal/app/`](../internal/app/), [`../cmd/semiplane/`](../cmd/semiplane/) |

**Not built. Treat every row as a proposal, not as behaviour.** The plan's
remaining phases are P4 (tags/file tree surfaces beyond the dashboard), P5 (the
full UI shell, the campaign-status panel, live push), P7's remaining surfaces
(the reveal/revoke *controls* and the admin audit view — the write path itself
is built), P8 (the editor, revisions, renames through the app, the bulk link
updater, the attachment-serve route), P9a/P9b (the plugin registry, the host
implementation, the reserved-name table, the example plugins), P10 (the VTT) and
P12.

Concretely absent from the tree, so that nobody goes looking:

- **No plugin is registered.** `internal/plugin` is vocabulary only — the
  interface, the `Kind`, the capabilities, the `Descriptor`. There is no
  `reserved.go`, no registry, no `Host` implementation, and
  `internal/systems/core` and `internal/systems/dnd5e` are a `doc.go` each.
  `TestNoPluginSwitchInCore` skips while the registry is empty.
- **No sample campaign.** `internal/sample` is a `doc.go`; the embedded
  campaign and its first-boot extraction are not written. The leak suite runs
  against a harness-seeded vault instead.
- **No attachment rows.** The `attachments` table and `store`'s queries exist;
  the indexer writes none, because `md` yields attachment *names* with no mime
  or size, and inventing a sniffing table would be worse than leaving it to the
  page route's phase.
- **No `/_/events`, no SSE, no live push.** `sync.Bus` is built and has no
  subscriber.
- **No editor, no reveal/revoke route, no `/admin`, no plugin routes.** The route
  table has fourteen entries over eleven distinct patterns, and they are all in
  §5 above.
- **No DataStar binding.** The bundle is vendored and served, and the server
  answers a fragment, but no template emits a `data-on:` attribute and
  `app.js` selects `[data-on:click]`, so **every navigation in stage 1 is a
  full page load.** That is the plan's §4.1 default column, not a gap.

---

## 7. Where each part of the plan lives

Subject → owning package → the document that explains it. Every `doc.go` states
what its package owns and what it may import; that is the per-package contract
and this table does not replace it.

| Subject | Owning package | Read |
|---|---|---|
| Composition root, boot order, one-shot commands | `internal/app` | [`../internal/app/doc.go`](../internal/app/doc.go) |
| Flags, environment, defaults, validation | `internal/config` | [`../internal/config/doc.go`](../internal/config/doc.go) |
| Redacting log handler, request log, audit log | `internal/obs` | [`../internal/obs/doc.go`](../internal/obs/doc.go) |
| Principal, Permission, policy, the canonical predicate | `internal/authz` | [`../internal/authz/doc.go`](../internal/authz/doc.go), [`ADR-0001`](ADR-0001-canonical-dependency-order.md) |
| SQLite, the schema, the FTS tables, typed queries | `internal/store` | [`../internal/store/doc.go`](../internal/store/doc.go) |
| The Markdown and frontmatter pipeline | `internal/md` | [`../internal/md/doc.go`](../internal/md/doc.go) |
| FTS5 query building, ranking, snippets, merge | `internal/search` | [`../internal/search/doc.go`](../internal/search/doc.go) |
| Plugin vocabulary (no registry yet) | `internal/plugin` | [`../internal/plugin/doc.go`](../internal/plugin/doc.go) |
| The canonical file store: paths, atomic writes, watcher, backup, lock | `internal/vault` | [`../internal/vault/doc.go`](../internal/vault/doc.go) |
| Accounts, sessions, invites, CSRF | `internal/auth` | [`../internal/auth/doc.go`](../internal/auth/doc.go) |
| The secret fence write path, redaction, reveal | `internal/secrets` | [`../internal/secrets/doc.go`](../internal/secrets/doc.go), [`ADR-0004`](ADR-0004-plaintext-secrets.md) |
| The indexer and the invalidation bus | `internal/sync` | [`../internal/sync/doc.go`](../internal/sync/doc.go) |
| Route table, middleware chain, handlers, view models | `internal/httpapi` | [`../internal/httpapi/doc.go`](../internal/httpapi/doc.go) |
| templ components, layouts, the renderer | `internal/web` | [`../internal/web/doc.go`](../internal/web/doc.go) |
| The embedded asset tree | `web` (module root) | [`../web/embed.go`](../web/embed.go) |
| The pure-Go SQLite decision | — | [`ADR-0002`](ADR-0002-pure-go-sqlite.md) |
| The dependency order and why it differs from the plan | — | [`ADR-0001`](ADR-0001-canonical-dependency-order.md) |
| The rules a change must satisfy | — | [`../AGENTS.md`](../AGENTS.md) |

The dependency order itself is **not restated here.** It is
`order` in [`../internal/architecture_test.go`](../internal/architecture_test.go)
— the one list a test reads — and it is argued in
[`ADR-0001`](ADR-0001-canonical-dependency-order.md). Read those two.

---

## Divergences

Where the plan and the code disagree, the code is what happens. Each row says
what the plan said, what the code does, and where the code says so for itself.

1. **goldmark v2 → goldmark v1.8.2.** Plan §5.2 names
   `github.com/yuin/goldmark/v2`. The tree uses `github.com/yuin/goldmark
   v1.8.2`, and `goldmark/v2` survives in `go.mod` only as an unused indirect.
   v2's root package exports no `Markdown` façade and no `Extender` contract, so
   goldmark-obsidian, wikilink, hashtag and mermaid — all of which implement
   `Extend(goldmark.Markdown)` — cannot compose against it. Stated in
   `md.New`'s doc comment in [`../internal/md/render.go`](../internal/md/render.go).
2. **Go 1.25 → `go 1.26.0`.** The plan's header and U20 say 1.25. The `go`
   directive is `1.26.0` because the pinned templ (v0.3.1020, via the `tool`
   directive) requires it, so a 1.25 floor is unachievable with the pin.
3. **The dependency order.** The plan's §1 list and its parenthetical partial
   order disagree with each other and with the code. The code's order, and the
   two deviations that break the cycles the plan contains, are
   [`ADR-0001`](ADR-0001-canonical-dependency-order.md); the machine-checked
   copy is `order` in the architecture test.
4. **`md.Segmenter` is not a type.** Plan §5.4 says "`md.Segmenter` splits the
   body". The code has `md.Segment([]byte)` and `md.Parse(path, []byte)`,
   free functions returning a `*md.Doc`. `md.Span` and `md.SpanKind` are as
   the plan has them.
5. **`page_tags.secret_id` was added.** The plan's §6.2 has no such column.
   §5.4 requires every extracted fact to carry its secret and §6.4 requires tag
   counts to run the canonical predicate, which needs a `secrets` row to
   evaluate. Commented at the column in
   [`0001_init.sql`](../internal/store/migrations/0001_init.sql).
6. **`secrets.title` was added.** The plan's §6.2 omits it; the fence directive
   carries an optional `title=`. Commented at the column.
7. **`secret_text` is keyed on an INTEGER, not on the secret id.** The plan's
   §6.2 has `secret_text(secret_id TEXT PRIMARY KEY …)` with
   `content_rowid='secret_id'`. FTS5's `content_rowid` must name an INTEGER
   key, so every insert fails with a datatype mismatch and every `MATCH`
   returns nothing. The migration adds `fts_rowid INTEGER PRIMARY KEY` and
   makes `secret_id` a `UNIQUE` foreign key. This is a correction, not a
   preference; the comment at the column says so.
8. **The `meta` key set is longer than the plan's list.** The migration's
   comment lists seven keys, adding `last_change_at` and `authz_generation`.
   Note that `last_change_at` holds an RFC 3339 timestamp, not the integer the
   key's neighbours suggest — read it with `store.MetaGet`, not `MetaGetInt`.
9. **`authz.Principal` has neither a `campaignID` nor an `isDM` field.** Plan
   §1 writes `Principal {userID, role, campaignID, isDM}`. The code has
   `UserID`, `Username`, `Role`, `SessionID`, `AuthzGeneration` and
   `AllowAnonymousRead`; `IsDM()` is a method. There is no campaign id because
   one vault is one campaign, and `AuthzGeneration` is there because a live
   stream whose generation falls behind must be terminated.
10. **The package is `secrets`, not `secretsvc`.** The plan's §4.5 sample names
    a `secretsvc` package. The tree's is `internal/secrets`.
11. **There is no runtime tripwire.** Plan §1 and §4.5 describe
    `secretsvc.Tripwire` as an `http.ResponseWriter` wrapper that scans outgoing
    bodies for secret plaintext. Nothing like it exists in non-test code. What
    stage 1 has instead is a test-level equivalent that is arguably stronger
    for this stage — `TestNoSecretLeaksThroughAnyPath` in
    [`../internal/httpapi/tripwire_test.go`](../internal/httpapi/tripwire_test.go)
    walks the whole demo path as every role and asserts no forbidden secret
    token appears in any body, any header value or any `data-signals` payload.
    A runtime response-scanner is **not yet implemented**; do not describe one
    as protection that exists.
12. **Golden fixtures are at `internal/md/testdata/*.md`, flat — 132 of them.**
    The plan's §5.3 says "≥40 … in `testdata/vault/`". The corpus is larger
    than specified and lives next to the package; `golden_test.go` walks that
    directory.
13. **`internal/sample` vs the plan's two names.** Plan §1 lists
    `internal/sample/`, §2.6 lists `internal/samplecampaign/`; the tree has
    `internal/sample/` and it is a `doc.go`. Either name is unimplemented.
14. **`internal/plugin/reserved.go` does not exist.** Plan §2.2 defines the
    reserved page-type ids and route segments there, and §2.4 gates on them.
    P0 shipped the vocabulary; the reserved table is part of the plugin phase
    (P9a) and is **not yet implemented**.
15. **`links.secret_id` is `""` in Go, not `NULL`.** The plan's §6.2 comment
    says `NULL ⇒ public` for `links.secret_id` and `headings.secret_id`; the
    columns are indeed nullable, but `store.Link.SecretID` is a `string` and
    every projection is `COALESCE(secret_id, '')`. Write `""`, read `""`.
16. **The two authorization gates are not the same predicate, and the gap is
    closed in two other places.** Worth stating because it is the one spot where
    "use the canonical predicate" is not by itself sufficient.
    `authz.SecretVisibleSQL`'s table-visibility clause has no authentication
    guard — it says `s.visibility = 'table'`, with nothing requiring a session —
    while `authz.CanReadSecret` requires an authenticated principal. An anonymous
    request that reached a query using only the SQL predicate would therefore
    see `table` secrets, which is why `authz.Principal.Bind` binds `:uid` to
    `-1` for an anonymous principal (never a real owner or author id) and why
    `store.publicOnlySQL` and `search.Query`'s `p.Authenticated()` guard exist.
    Both are commented where they are.

    The cross-check that would catch the two gates drifting apart **does exist**:
    `store.TestPredicateMatrixAgrees` evaluates every secret-derived query as
    every principal in its fixture — including an anonymous one — and compares
    each result against §8.2's table transcribed by the test itself, rather than
    by calling the policy it is checking. It also asserts count/list agreement
    per principal, because that is where a leak would show: a panel that lists
    one row while counting three.

    An earlier draft of this document claimed that test did not exist. It does;
    the name was wrong, and the wrong name came from `AGENTS.md` §5, which
    listed a required suite by a name no test had ever had. Both are fixed. It
    is worth recording as a reminder that a required-suite list naming a test
    that does not exist is worse than no list, because it reads as a gate.
