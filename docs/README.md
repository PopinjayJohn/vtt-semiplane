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
| [`spec.md`](spec.md) | the data model, the Markdown pipeline, the index, the request lifecycle, what stage 1 delivers and what does not exist yet | you are changing how a file becomes a page, or a page becomes a response |
| [`security.md`](security.md) | the threat model, the canonical visibility predicate, the authorization matrix, the secret lifecycle, the tripwire, and what is deliberately not defended | you are touching anything that can read, write, log or render a secret |
| [`plugins.md`](plugins.md) | the plugin contract, kinds, capabilities, the version gate, the import boundary, link previews | you are writing a game system, a feature, or a route under `/plugin/` |
| [`search.md`](search.md) | the two FTS tables, the two-query authz-filtered merge, query building, ranking, snippets, the secret invariant | you are touching indexing, search or a snippet |
| [`pitfalls.md`](pitfalls.md) | the traps that have already cost time here, with the reason each one bites | **before you run anything** — the test runner, the CSS build and the vault lock all have non-obvious behaviour on this machine |
| [`AGENTS.md`](../AGENTS.md) | the working agreement: hard rules, conventions, testing expectations, local commands | you are about to write code |
| [`ADR-0001`](../docs/ADR-0001-canonical-dependency-order.md) | the dependency order and the two cycle-breaking deviations from the plan | you want to add a package, or an import looks wrong |
| [`ADR-0002`](../docs/ADR-0002-pure-go-sqlite.md) | why `modernc.org/sqlite` and what it costs | you touch the database, or hit a `libc` version error |
| [`ADR-0004`](../docs/ADR-0004-plaintext-secrets.md) | why secrets are plaintext at rest and what that forecloses | you are tempted to add encryption, or a backup |

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
with sessions and invites, the authorization policy, the router, and the templ
view layer. The live-push path, the plugin registry and `Host`, the campaign
status panel, the editor, the sample campaign extraction and the release
pipeline are **not** built. `spec.md` says so per section.

## Adding a document

Give it one subject, link it from the table above, and follow the rule: name the
owner, explain why, and never restate what the code already says.
