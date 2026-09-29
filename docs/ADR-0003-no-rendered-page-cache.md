# ADR-0003: No rendered-page cache

Status: accepted · Date: 2026-09-29

## Context

A page render is a read: segments the file, filters the secret spans against the
requesting principal, renders the rest, and asks the store for a table of
contents, backlinks and related pages. On the deployment this project is built
for — one process, one SQLite file on the same machine, a handful of people on
a LAN — the work is bounded by a local read of a file the operating system has
already in its page cache. The obvious optimisation is therefore available and
unnecessary at the same time, which is the situation in which a cache gets added
by somebody who is not thinking about what is in the response.

The reason it is dangerous here is specific. A rendered page is not a function
of the page. It is a function of the page **and** of who is asking **and** of
the authorization state at the moment of the ask, and the third of those changes
without the page changing at all. Revealing a fence rewrites one token in one
file; revoking one purges a search row; a role change, a page-ownership change
and a sign-out all change what the *same* principal may be shown. Every one of
those is a file mutation or a database row, and none of them produces a new
page.

This is why the absence is recorded as a decision and not as an omission. A
reader who has not been told will assume a cache exists, will not look for the
one, and will not think about the key when they add one.

## Decision

**There is no rendered-page cache in v1.** Every page render reads the file and
re-derives the response.

Adding one requires a key of
`(pageID, userID, authz_generation)` and nothing shorter. The third term is the
one that is easy to leave out: `authz_generation` is the counter the vault
already bumps for exactly this purpose, a live-push stream whose generation
falls behind is terminated by it, and a cache that does not carry it serves a
correct answer to a question that has since changed.

`TestNoRenderedPageCache` in
[`../internal/httpapi/csrf_test.go`](../internal/httpapi/csrf_test.go) is the
gate, and it is the gate in the unusual direction: it passes while there is no
cache and **fails the moment one appears**. It asks the same server, warm, for
the same page as two principals who may see different amounts of it, in both
orders and concurrently, and fails if the two bodies are byte-identical.

## Alternatives considered

1. **A cache keyed by page id alone.** The obvious implementation and the one
   that fails silently everywhere else: the functional tests, the leak walk and
   the authorization matrix all pass, because every one of them asks a single
   principal for a page and a page-id key gives that principal the right answer.
   It is caught by exactly one test, and only if that test is not skipped.

2. **A per-user cache keyed by `(pageID, userID)`.** This fixes the leak between
   principals and nothing else. It serves a player a body they were entitled to
   at the moment it was rendered and are not entitled to now, after a revoke, a
   role change or a sign-out — which is a live reader, not a forensic one.

3. **Caching the rendered *public* part of a page, and splicing secrets in
   afterwards.** The only shape that is actually safe on the key, and it is
   refused for a different reason: the expensive half of a render is the
   segmentation and the extraction, and the index already holds their output in
   rows. The half a "public part" cache would hold is the cheap half, so it buys
   the part that was not slow and leaves the redaction path — the part that must
   not be wrong — as untested as before.

4. **Letting a reverse proxy cache the app.** The app's own
   `Cache-Control: no-store` and `Vary: Cookie` on every
   authorization-dependent response exist to make this the wrong idea, and a
   deployment that strips those headers has also stripped the Content-Security-
   Policy and the session cookie flags.

5. **No decision, and simply not doing it.** That is what this ADR records, with
   the key written down so that the person who eventually needs one has to
   confront the third term rather than rediscover it.

## Consequences

- **Every page render is a read.** That is the intended cost, and the thing that
  makes it affordable is that the alternative answers a question the current
  authorization state has already invalidated.
- **The invalidation bus is the mechanism instead.** A subscriber is told
  *that* something changed and refetches the page under its own captured
  principal; the stream carries a trigger and never content. That design is the
  direct consequence of having no shared rendered artefact to update — see
  [`../internal/httpapi/events.go`](../internal/httpapi/events.go) and its own
  preambles.
- **Adding a cache later is a security change, not a performance change.** It
  needs the three-part key, an invalidation story for every writer that moves
  `authz_generation`, and a `TestNoRenderedPageCache` that has been reasoned
  about rather than deleted — which test it is, and what the new key would have
  to contain to satisfy it.
- **The absence forecloses nothing else.** Nothing in the read path assumes
  there is no cache; the cost is the repeated render, and the measurements that
  would justify a change are the ones
  [`ADR-0002-pure-go-sqlite.md`](ADR-0002-pure-go-sqlite.md) records as still
  missing on the write side.
