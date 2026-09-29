# Documentation index

Read what you need, not everything. The design plan this project was built from
lives outside the repository (in `.kilo/`, which is gitignored), so these
documents are the durable copy of the design and the only place a new agent can
find it.

## The rule that governs all of them

**The code is the specification. These documents point at it.**

Every technical fact — a table, a parser, a policy, a test name, a constant —
has exactly one owning artefact, and the job of a document is to name the owner
and explain *why*, never to restate the content. A document that repeats a fact
the code owns is a document that can be wrong while looking authoritative, and
this project has paid for that already: the plan documented the secret fence as
`title=<optional>` with no quoting requirement, the parser read an unquoted value
containing a space as an unknown key, unknown keys meant "public passthrough",
and so an author who followed the documentation served a DM's secret body in
plaintext to a player. A test pinned the unsafe behaviour, so it was defended.

When a document and the code disagree, the code is right and the document is a
bug. Each document below ends with a short **Divergences** section for exactly
this case.

## What to read

| Document | What is in it | Read it when |
|---|---|---|
| [`spec.md`](spec.md) | the data model, the Markdown pipeline, the index, the request lifecycle, what each stage delivered, and what does not exist yet | you are changing how a file becomes a page, or a page becomes a response |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | the package map, where a new query / markdown construct / page type / route goes, the boot order and why it is that order, the request lifecycle, the plugin boundary, and **what is deliberately absent and why** | you are new to the repository, or you are about to add something and want to know which package refuses you |
| [`SECRETS.md`](SECRETS.md) | how to write a secret in your own vault: the fence syntax, the three visibilities, the account-resolution rule, reveal and revoke, attachments — written for a game master, not for a reader of the source | you are a DM putting a real campaign in this, or you want to explain a secret fence to somebody else |
| [`security.md`](security.md) | the threat model, the canonical visibility predicate, the authorization matrix, the secret lifecycle, the tripwire, and what is deliberately not defended | you are touching anything that can read, write, log or render a secret |
| [`plugins.md`](plugins.md) | the plugin contract, kinds, capabilities, the version gate, the import boundary, link previews | you are deciding **whether** to write a plugin, or what the boundary is |
| [`PLUGIN_AUTHORING.md`](PLUGIN_AUTHORING.md) | the procedure: which kind, what the host inherits, what you may not import, and the order to build in | you are writing a game system, a feature, or a route under `/plugin/` |
| [`search.md`](search.md) | the two FTS tables, the two-query authz-filtered merge, query building, ranking, snippets, the secret invariant | you are touching indexing, search or a snippet |
| [`pitfalls.md`](pitfalls.md) | the traps that have already cost time here, with the reason each one bites | **before you run anything** — the test runner, the CSS build and the vault lock all have non-obvious behaviour on this machine |
| [`AGENTS.md`](../AGENTS.md) | the working agreement: hard rules, conventions, testing expectations, local commands | you are about to write code |
| [`ADR-0001`](../docs/ADR-0001-canonical-dependency-order.md) | the dependency order and the two cycle-breaking deviations from the plan | you want to add a package, or an import looks wrong |
| [`ADR-0002`](../docs/ADR-0002-pure-go-sqlite.md) | why `modernc.org/sqlite` and what it costs | you touch the database, or hit a `libc` version error |
| [`ADR-0004`](../docs/ADR-0004-plaintext-secrets.md) | why secrets are plaintext at rest and what that forecloses | you are tempted to add encryption, or a backup |
| [`ADR-0003`](../docs/ADR-0003-no-rendered-page-cache.md) | why there is no rendered-page cache, and the key one would have to have | you are about to make a page render faster |
| [`ADR-0005`](../docs/ADR-0005-sample-is-bytes-extraction-is-in-app.md) | why `internal/sample` is an embedded filesystem and the first-boot extraction walk lives in `internal/app` | you are adding content that has to reach a vault, or you are tempted to give `sample` a writer |
| [`ADR-0006`](../docs/ADR-0006-fences-not-frontmatter.md) | why content hides through a body fence and never through a frontmatter key, and what that forecloses | you want a page — rather than a span of one — to be private |

## The shortest useful summary

The Markdown file is canonical; every derived artefact is disposable. Content
enters the index only by reading a file and leaves the app only through
`vault.Writer`, which is hash-checked and byte-preserving. A secret body reaches
a response through exactly one decision — `authz.CanReadSecret`, or the SQL
predicate `authz.SecretVisibleSQL` that mirrors it — and the whole
authorization design exists to make that one decision hard to get wrong, because
a hand-rolled OR-chain leaks a `dm` secret to the page owner.

## What exists

Every package in the module is green, from `cmd/semiplane` to `internal/web`: the store
and its migrations, the Markdown pipeline, vault I/O with an atomic writer and a
single-instance lock, the indexer and the invalidation bus, Argon2id accounts
with sessions and invites, the authorization policy, the router, the templ
view layer, and the six stages built on top of them.

**Stage 1** is the data layer through to a readable page: the store and its
migrations, the Markdown pipeline, vault I/O, the indexer and bus, accounts and
the policy, the router, search, and the templ view layer.

**Stage 2** is everything a reader navigates by: the tag cloud and tag pages,
the file tree, the campaign status panel, the three-column shell with its
keyboard model and accessibility work, the command palette, and the live-update
stream at `/_/events` with its coalescing window, its buffer bound, its
per-user and global caps, and its termination on any authorization change.

**Stage 3** is the plugin boundary, and it is enforced rather than designed.
`internal/plugin` holds the vocabulary, the `Host`, the registry and the
lifecycle; `reserved.go` holds the reserved page-type ids and route segments;
`cmd/semiplane/registry.go` is the one map entry; `/admin/plugins` is the boot
report. `internal/systems/dnd5e` is a working system plugin and
`internal/systems/example` is one built to be refused, five different ways, on
purpose. **Stage 3b** is the other side of the same boundary: two
`KindFeature` plugins, `houserules` and `linkpreview`, exist so the `Kind` split
is something a build runs rather than something a document claims — together
they exercise a nav group, mounted routes, a search resolver, a summary
provider, and the rule that a feature plugin may not register page types.

**Stage 4** is the write half, and it is the stage that made a secret legible
to two people at once. It added the redacted editing path (`md.Redact`,
`md.Splice`, `secrets.Service.EditView`/`Save`), the revision read paths and
their read-time re-authorisation, the page-scoped surfaces in
[`../internal/httpapi/pagedispatch.go`](../internal/httpapi/pagedispatch.go) —
raw, editor, history, one revision, revert, page-scoped attachment, the
broken-links panel — and the three §5.6 rename/link-updater routes. It also
added `internal/diff` (hand-rolled, no dependency, argued in its own
`doc.go`), `vault.Writer.Delete`/`Move`, the two migrations that made the
attachment rows and the link byte offsets real, and the audit permission that
[`../AGENTS.md`](../AGENTS.md) §2.6a had recorded as missing.

**Stage 5** is the secret lifecycle, and what it made legible is the *shape* of
the authorization rule rather than the rule: reveal and revoke are reachable over
HTTP as the same service call they always were, and the per-page export and the
`secret_events` audit view are mounted on permissions the policy already had. The
evidence is the part that changed most. The leak walk in
[`../internal/httpapi/leaksuite_test.go`](../internal/httpapi/leaksuite_test.go)
derives its requests from the route table instead of a written-out list, so a
surface added tomorrow is covered by *failing* rather than by being forgotten,
and it walks every principal the design admits — including the anonymous reader
with anonymous read on, which is the one case a redirect-to-login row can never
reach. Two bugs it did **not** catch are recorded in
[`../AGENTS.md`](../AGENTS.md) §11 anyway, because both were the same mistake in
two guises: a test that asked a question beside the one it meant to ask.

Two of the three surfaces stage 3 left unwired are now wired, and one is
deliberately still `nil`:

- **`Host.Pages()`** is the authz-filtered page read surface, declared in
  `internal/plugin`, implemented by `store` in `internal/store/pagestore.go`,
  wired in `internal/app/plugins.go`. It is four named methods rather than a
  `*sql.DB` so that a plugin cannot compose its own visibility predicate.
- **The plugin route mounter** returns a bare mux; `httpapi` mounts it at
  `/plugin/{id}` behind session, CSRF and `PermSession`. See
  [`plugins.md`](plugins.md) §7 for why the link-preview summary route is
  core-owned rather than plugin-mounted.
- **A plugin's `fs.FS` is still `nil`**, and `internal/app/plugins.go` records
  why: the redaction it would need exists in exactly one place, the page view,
  and extracting it under time pressure is the most likely way to put a secret
  where a plugin can see it.

**Stage 6** is **P11**: the two ends of shipping a campaign — the one an
operator finds in a fresh vault, and the one they run it in.
[`../internal/sample/`](../internal/sample/) embeds a written campaign as
ordinary Markdown, and [`../internal/app/sample.go`](../internal/app/sample.go)
extracts it on **every** boot without ever touching a file that is already
there: the vault is canonical, and a first boot that overwrote a page would be
the one write in the app that destroys what it is derived from. A walk that
re-checks costs one `Resolve` and one `Read` per file, and a gate would buy no
work while adding a state file whose loss skips the campaign silently.
`.goreleaser.yaml` and the release workflow are the other end, and they exist
for ADR-0002's promise rather than for convenience: a DM who cannot move one
signed static binary to a thumb drive has the design and none of the
deployment.

Still **not** built: **P10**, the VTT — maps, initiative and dice — and the
remainder of **P12**. [`spec.md`](spec.md) §6 is the one place that lists what
is concretely absent from the tree, so that nobody goes looking: the create,
delete and `/admin/users` routes are in that list and they are P12's, and
alongside them it carries the three things stage 6 left open — the
table-of-contents anchors, an `e2e` job, and `vault.Restore`'s manifest
containment check on the read side.

The editor, which was the reason the shell had no edit affordance, exists:
`PageView.EditHref` is filled from `mayWritePage`, `home.templ` renders the link
when it is set, and `app.js` implements the `e` key against it. **A whole-vault
export is not on the list above and is not going to be on it:**
[`../internal/httpapi/export.go`](../internal/httpapi/export.go) argues that the
vault-wide form has no authorization question to ask, so it would be a copy of
the plaintext on disk rather than a feature.

## Adding a document

Give it one subject, link it from the table above, and follow the rule: name the
owner, explain why, and never restate what the code already says.
