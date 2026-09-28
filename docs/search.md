# Search

Search is two queries merged in Go, each filtered in SQL. The facts here are
owned by [`internal/search/`](../internal/search) (the query builder, ranking,
snippets, merge) and by
[`internal/store/fts.go`](../internal/store/fts.go) plus
[`internal/store/migrations/0001_init.sql`](../internal/store/migrations/0001_init.sql)
(the tables and the index writes). This document is a map to them.

## 1. The model

Two content-backed FTS5 tables, deliberately.

```sql
-- internal/store/migrations/0001_init.sql
CREATE TABLE page_text (page_id INTEGER PRIMARY KEY, title, headings, body);
CREATE VIRTUAL TABLE page_fts USING fts5(
  title, headings, body,
  content='page_text', content_rowid='page_id',
  tokenize = "unicode61 remove_diacritics 2 tokenchars '_-'",
  prefix = '2 3 4'
);

CREATE TABLE secret_text (fts_rowid INTEGER PRIMARY KEY, secret_id TEXT NOT NULL UNIQUE, body TEXT NOT NULL);
CREATE VIRTUAL TABLE secret_fts USING fts5(
  body, content='secret_text', content_rowid='fts_rowid',
  tokenize = "unicode61 remove_diacritics 2 tokenchars '_-'",
  prefix = '2 3 4'
);
```

| Property | `page_fts` | `secret_fts` |
|---|---|---|
| Holds | public content only | a secret body, **only while that secret is `table`** |
| Columns | `title` (weight 10), `headings` (weight 5), `body` (weight 1) | `body` only |
| Base table | `page_text` | `secret_text` |
| Written by | `store.ReplacePageText` / `store.DeletePageText` | `store.IndexSecretText` / `store.DeleteSecretText` |

**External content, not contentless.** `content='…'` means the FTS table is an
index over a real table rather than a copy, so `snippet()` and `rebuild` work and
the index is never the only copy of the text. It also means the write order
matters and is the whole difficulty of a content-backed table: replay the **old**
values through `'delete'`, then update the content table, then insert the **new**
values. Sending `'delete'` for a rowid that is not indexed corrupts the index,
which is why that step is conditional on the row existing; skipping it leaves
stale terms behind. `ReplacePageText` says this at length, and a caller that
writes `page_text` directly has broken search in a way only a rebuild will fix.

**`secret_text.fts_rowid` is a deliberate divergence from the plan**, and the
migration comment says why: FTS5's `content_rowid` must name an INTEGER key, so
`secret_id TEXT` as the content rowid makes every insert fail with
`datatype mismatch (20)` and every `MATCH` return nothing. `secret_id` remains
the primary key and the foreign key; the surrogate is written by the same
statement that populates the body and is never exposed outside the pair of
tables.

**The tokenizer.** `unicode61 remove_diacritics 2 tokenchars '_-'`, on both
tables. `'tokenchars '_-'` is what keeps `Red-Dragon` and `goblin_scouts` whole
instead of splitting them into four fragments. `prefix = '2 3 4'` declares that
prefix matches of 2, 3 and 4 characters are available — but
`TestFTSUsesTheSchemasTokenizer` records the important consequence:
**`BuildMatchQuery` never emits one.** A quoted term is exact, and `*` is an
operator the query builder refuses to pass through, so `"obsidian"` does not
match `"obs"*` or vice versa. The prefix option is there for an autocomplete
path that would build its own validated prefix expression; **that path does not
exist**, so today the prefix indexes are declared and unused.

The same test pins the diacritic folding precisely, including where it stops:
`Grüße aus Köln` is found by `koln` (so `ü` folds to `u`) but not by `grusse`
(so `ß` does not fold to `ss`).

**Regeneration.** `store.NeedsFTSRebuild` compares `meta.fts_generation` with
`meta.schema_version` (`store.KeyFTSGeneration`, `store.KeySchemaVersion`) and
reports a mismatch; `store.MarkFTSGeneration` records that a rebuild happened.
`store.RebuildPageFTS` runs `INSERT INTO page_fts (page_fts) VALUES ('rebuild')`;
`store.RebuildSecretFTS` first drops every non-`table` secret from `secret_text`,
then repopulates it from `secrets` where the visibility is `table`, then rebuilds.
The rebuild selects on visibility with `authz.VisibilityTable` as a **bind
parameter**, not a literal — so it cannot drift from the constant the read path
uses.

## 2. Why two queries, not one

`search.Query` is the merge, and the reason for its shape is in its doc comment.

- A **page hit** needs no secret predicate. `page_fts` holds public content only,
  so whether the principal may read public content at all is decided before any
  statement runs: `if !p.CanReadPublic()` returns an empty result without
  touching the database.
- A **secret hit** carries `authz.SecretVisibleSQL` anyway, because a `table`
  secret is still subject to the authenticated-user rule. `secret_fts` holds a
  body only while that secret is table-visible, but *visible* is not *readable*.
- The two are filtered by **different** predicates, so they cannot be one
  statement. They are fetched separately and concatenated.

**The filter is in SQL, not in Go post-processing**, so a bug in post-processing
cannot widen the result set. This is the load-bearing property and it is stated in
the package doc.

**The merge is pages-then-secrets, not a global sort.** The two `bm25` scores are
not comparable — one is a three-column weighted score, the other a single-column
one — so interleaving them by number would be a claim about relevance that the
ranking does not support. `Hit.Score` is the raw bm25 rank, lower is better, and
it is deliberately not normalised.

**The count agrees with the rows by construction.** Each source has a `COUNT`
statement assembled from the *same* constant as its hit statement
(`pageFTSFrom`, `secretFTSFrom`), so there is no second copy of the predicate,
the join, or the filter to fall out of step. `Result.Total` is the sum of the two
separately filtered counts. A panel that lists one row while counting three is an
existence leak, and here that cannot be written.

**An unauthenticated request is not merely filtered — it is not sent.** The two
secret statements are skipped entirely when `!p.Authenticated()`. The canonical
predicate cannot enforce this on its own: its table-visibility clause has no
authentication guard, while `authz.CanReadSecret` requires an authenticated
principal for the same visibility. The check is on the principal, not on a
visibility value, so it can only remove rows.

## 3. `BuildMatchQuery` — the injection surface

**A raw user string never reaches the `MATCH` operator.** FTS5 query syntax is a
small programming language — `NEAR(...)`, `^`, `*`, column filters, and the
`AND`/`OR`/`NOT` keywords — and handing it a user's raw keystrokes is handing it
a program. `search.BuildMatchQuery` is the boundary.

It does not escape. **It tokenises.** Everything that is not a token character
under the index's own tokenizer is a separator and simply vanishes, so the
output can contain nothing but quoted string literals joined by `OR`. A token
the FTS5 phrase syntax could not hold is dropped rather than escaped, because
every escape route is another parser to get wrong.

The output has exactly one shape, and `assertSafeMatch` in
[`internal/search/query_test.go`](../internal/search/query_test.go) checks the
**shape** rather than grepping for banned substrings — a grep for `NEAR(` would
pass on `"NEAR"("`, and one for a colon would fail on a legitimate `http://`
inside a quoted literal.

| Input | Output | What it demonstrates |
|---|---|---|
| `NEAR(a b)` | `"NEAR" OR "a" OR "b"` | the operator is a word, not an operator |
| `^x` | `"x"` | the prefix operator is dropped |
| `a*` | `"a"` | a trailing star is dropped, not passed through |
| `a AND b` | `"a" OR "AND" OR "b"` | a bare keyword is a word |
| `a:b` | `"a" OR "b"` | a column filter is split, not honoured |
| `title：x` | `"title" OR "x"` | a full-width colon is a separator too |
| `"unterminated` | `"unterminated"` | an unbalanced quote cannot escape |
| `()` | (empty string) | punctuation-only input yields no expression |
| `a\x00b` | `"a" OR "b"` | a NUL byte is a separator |
| `Red-Dragon goblin_scouts` | `"Red-Dragon" OR "goblin_scouts"` | `tokenchars` keep a compound whole |
| `a--b` | `"a--b"` | a run of dashes is one token |
| `Grüße` | `"Grüße"` | accents stay in the token; the *index* folds them |

`TestBuildMatchQueryHasNoUnquotedOperator` states the same property over the full
adversarial corpus — `"`, `""`, `""""`, `a**b`, `***`, `a OR OR OR b`, `col:val`,
`a AND (b OR c)`, `((()))`, `"a" OR "b`, `DROP TABLE pages`, `\xff\xfe`, `--a` and
more — by checking that everything *outside* the quotes is the joiner this
package emits and nothing else.

**Case is preserved, deduplication is case-sensitive**: `vault vault VAULT door`
yields `"vault" OR "VAULT" OR "door"`. Repeating a word adds nothing to recall
and does add to the FTS5 planner's work.

**The tokeniser is a deliberate *subset* of the index's.** Matching `unicode61`
exactly would mean trusting `unicode.IsLetter` to agree with SQLite's own tables
for every codepoint, and the failure mode is a query token the index splits
differently. A subset has the opposite failure mode — a dropped character, a
narrower query. **A missed hit is a bug report; a widened result is a leak.**
`TestTokeniseRoundTripsThroughTheRealTokenizer` asserts the two tokenisers agree
by running the expression against the real FTS5 tokenizer, since SQLite's notion
of a token character is its own table rather than Go's.

An input with no tokens yields an empty expression, and an empty expression is
the caller's cue to return no rows rather than to run `MATCH ""`, which is a
syntax error.

## 4. Ranking and snippets

```sql
-- page hits
SELECT p.id, p.title, p.path, p.updated_at,
       snippet(page_fts, 2, '', '', ' … ', ?),
       bm25(page_fts, 10.0, 5.0, 1.0)
FROM page_fts JOIN pages p ON p.id = page_fts.rowid
WHERE page_fts MATCH ?
ORDER BY rank, p.updated_at DESC
LIMIT ? OFFSET ?

-- secret hits: the same shape, bm25(secret_fts, 1.0), plus authz.SecretVisibleSQL
```

**`snippet(page_fts, 2, …)`** — column 2 is `body`, the only column snippet is
ever taken from, and the two `` `` `` arguments strip FTS5's own `<b>` markers
because the result is escaped rather than highlighted. `snippetTextTokens` is 12
tokens of context on each side; `search.SnippetMaxChars` is 400 and is exported,
because a caller clamping a limit should not hard-code a different number.

**Snippets are escaped at the boundary**, in `escapeSnippet`, not at the render
site. The doc comment says why: the snippet is assembled from vault text, and the
render site is templ, where the safe default is escaping but the first thing a
future contributor does when they want the match highlighted is to stop escaping.
Escaping in the search package means there is **one** place that can get it wrong.
Truncation is by rune, so a cut cannot land mid-rune and produce invalid UTF-8.

`internal/web/html.go` has `Escaped`, one of exactly two functions in the
codebase that call `templ.Raw` (`PreRendered` is the other);
`TestOnlyThisPackageMarksHTMLRaw`, in
[`internal/httpapi/tripwire_test.go`](../internal/httpapi/tripwire_test.go), keeps
it to two named functions. It exists for snippets and nothing else: letting templ
escape them again would turn `&` into `&amp;`.

**A secret hit carries no snippet at all.** `secretHitsSQL` never calls
`snippet()`, `Hit.Snippet` is always empty for `KindSecret`, and the hit is
pinned by `TestSecretHitCarriesNoSnippet`. The reason is not only §8.5's rule
that `snippet()` is only ever called on `page_fts`: any excerpt of a secret body
risks carrying text the author did not intend to publish even when the body
itself is revealed. The hit names the page, and the page is where the reader
goes. A secret hit's `Title` is the **owning page's** title, never the secret's
own title, because a secret's identity is not something a list needs to expose.

**`Hit.Kind` is part of the result, not a presentation detail.** `KindPage` and
`KindSecret` are "different trust levels and the UI must not blur them".
`internal/web/search.templ` branches on it. `Result.Query` carries the MATCH
expression that was executed, so a test can assert on the normalisation and an
operator reading a bug report can see what the user's keystrokes became.

## 5. Bounds

| Bound | Value | Where | Behaviour past it |
|---|---|---|---|
| `search.MaxQueryBytes` | 1024 | `internal/search/query.go` | **refused** with `search.ErrQueryTooLong`. A query long enough to be a denial-of-service attempt is not one whose first kilobyte deserves an answer. |
| `search.MaxTokens` | 32 | `internal/search/query.go` | tokens are **truncated** to the first 32. The FTS5 planner cost grows with the number of OR-ed terms, so a megabyte of single letters must not become a megabyte-long `MATCH`. |
| `search.DefaultLimit` | 20 | `internal/search/search.go` | the page size when `Options.Limit` is unset. |
| `search.MaxLimit` | 200 | `internal/search/search.go` | **clamped**. A search response is a page render, and a page render has a size; an unbounded `LIMIT` is an unbounded allocation. |
| `Options.Offset` | — | `internal/search/search.go` | a negative offset is set to 0. |
| `snippetTextTokens` | 12 | `internal/search/search.go` | unexported; context on each side of a match. |
| `SnippetMaxChars` | 400 | `internal/search/search.go` | truncated by rune, with an ellipsis. |

`MaxQueryBytes` refuses and `MaxTokens` truncates, deliberately differently: a
caller can tell "you typed nonsense" from "you typed too much".
`TestBuildMatchQueryIsBounded` pins both, and pins that a query of *exactly*
`MaxQueryBytes` is accepted. The HTTP layer re-clamps the limit before it reaches
`Query` and returns `ErrQueryTooLong` as a field error
([`internal/httpapi/search.go`](../internal/httpapi/search.go)).

**Performance: no measured figures are recorded in the tree.** There are two
benchmarks, and neither carries a recorded result in a comment:

- `BenchmarkSearch1kPages` — 1000 pages, ten queries, reports p50/p95/p99/max
  because a search box is typed into and a single slow response is felt where a
  fast median is not.
- `BenchmarkSearch1kPagesSecretMiss` — the cost of a term that matches nothing,
  which is what a player typing a secret word they cannot see produces. It
  asserts the result is empty as well as fast.

`docs/ADR-0002-pure-go-sqlite.md` records the **budget**: p99 page render under
50 ms and search under 20 ms on a 2000-page vault. It names
`BenchmarkIndex1kPages` as the other half of the measurement; **that benchmark
does not exist.** If you are quoting a number, run the benchmarks.

## 6. The secret invariant

**The rule: no non-`table` secret body is in any search index.** It is
structural, not a filter — a hidden secret is not filtered out of a result, it is
never in the index to begin with.

It is enforced at three levels:

1. **The write refuses.** `store.IndexSecretText` takes an `authz.Visibility` and
   returns `store.ErrSecretNotIndexable` for anything that is not
   `authz.VisibilityTable`. It is a hard error rather than a silent skip: a
   caller that indexes a hidden secret has a bug, and hiding that bug behind a
   no-op would leave the leak in place and the symptom invisible. The check is in
   Go, not SQL, so `internal/store` contains no SQL comparison against a
   visibility value at all.
2. **The revoke deletes.** `store.DeleteSecretText` removes the row, so the terms
   in a revoked secret become unsearchable immediately rather than at the next
   restart.
3. **The read asserts.** `store.CheckSecretIndexInvariant` returns the number of
   `secret_text` rows whose secret is not table-visible, and it must always be
   zero. `search.Query` runs its own copy of the assertion and returns
   `search.ErrSecretIndexInvariant` if it is not.

**The assertion is an assertion, not a filter.** Nothing is removed from the
result set because of it — a row that violated the invariant would be a bug, and
hiding the bug behind a working query would leave the leak in place. It is an
error rather than a filtered-out row because the only two possible causes are a
write-side bug and a corrupted database, and both deserve to stop the request.
`search.Query` binds the visibility value from `authz.VisibilityTable` rather
than writing a literal, so it cannot drift from the constant the read path uses,
and no principal is involved: it runs at query time against the index, not
against a user.

`app.Boot` checks the same invariant at boot — `enforceSecretIndexInvariant` in
[`internal/app/boot.go`](../internal/app/boot.go).

The tests:

| Test | File | What it pins |
|---|---|---|
| `TestSecretIndexHoldsOnlyTableSecrets` | `internal/store/fts_test.go` | the write path indexes only `table` |
| `TestRebuildSecretFTSOnlyIndexesTableSecrets` | `internal/store/fts_test.go` | the rebuild path agrees |
| `TestCheckSecretIndexInvariantCatchesALeak` | `internal/store/fts_test.go` | the assertion has teeth — it finds a leak planted behind `store`'s back |
| `TestSecretIndexInvariantHolds` | `internal/sync/secret_test.go` | a mixed corpus, through the indexer, is clean |
| `TestNoSecretEverEntersPageText` | `internal/sync/secret_test.go` | no secret reaches the public index |
| `TestSecretIsFoundByThePublicIndexOnlyWhenRevealed` | `internal/sync/secret_test.go` | reveal populates, revoke removes, immediately |
| `TestSecretIndexInvariantIsAsserted` | `internal/search/search_test.go` | `Query` returns `ErrSecretIndexInvariant` rather than results |
| `TestSearchNeverReturnsAHiddenSecret` | `internal/search/search_test.go` | as every role, over every visibility |
| `TestRevokePurgesTheIndex` | `internal/secrets/service_test.go` | the revoke path |
| `TestSecretHitCarriesNoSnippet` | `internal/search/search_test.go` | no excerpt of a revealed secret body |
| `TestFTSBasicSearch`, `TestFTSSnippetIsHTMLSafe`, `TestSnippetIsBounded` | `internal/search/search_test.go` | the ordinary paths |

The predicate itself is `authz.SecretVisibleSQL` in
[`internal/authz/predicate.go`](../internal/authz/predicate.go), and the
canonical predicate is the subject of `TestNoHandRolledVisibilityPredicates` and
`TestVisibilityPredicateShape` in `internal/architecture_test.go`. See
[`docs/ADR-0004-plaintext-secrets.md`](ADR-0004-plaintext-secrets.md) for the
at-rest risk this invariant does not address.

## 7. Divergences from the design plan

The plan is not in the repository (`.kilo/` is gitignored), so this is the
durable record. Where the code and the plan disagree, the code is right.

| Plan | Code | Note |
|---|---|---|
| §6.3: "user input is tokenised with the same unicode61 rules and **OR-joined with `AND` between phrases**" | `BuildMatchQuery` emits single quoted literals OR-joined. There is no phrase, and the string `AND` never appears in the output. | The plan's sentence is self-contradictory; the code is unambiguous. `TestBuildMatchQueryHasNoUnquotedOperator` asserts only `OR` is ever emitted. |
| §6.3: "Ties are broken by **recency and title-prefix**" | `ORDER BY rank, p.updated_at DESC`. Recency only. | No title-prefix tiebreak exists in either hit statement. |
| §8.5: "`secret_fts` snippets are **computed** only after the row-level authz check, and the surrounding text is discarded" | `secretHitsSQL` never calls `snippet()`. A secret hit has no snippet, ever. | The code tightened the rule. Computing a secret excerpt at all is the thing §8.5 was avoiding. `TestSecretHitCarriesNoSnippet` pins it. |
| §6.2: `CREATE TABLE secret_text (secret_id TEXT PRIMARY KEY …)` with `content_rowid='secret_id'` | `secret_text` has an extra `fts_rowid INTEGER PRIMARY KEY` surrogate, and `content_rowid='fts_rowid'`. | Not cosmetic: with the plan's schema every insert fails with `datatype mismatch (20)` and every `MATCH` returns nothing. The migration says so in a comment. |
| §6.3: `bm25(page_fts, 10.0, 5.0, 1.0)` | `bm25(page_fts, 10.0, 5.0, 1.0)` | **No divergence.** The weights are as designed, and `store.PageText` documents the same 10/5/1 per column. The plan says nothing at all about the secret side, which uses `bm25(secret_fts, 1.0)`. |
| §6.3: no bounds at all | `MaxQueryBytes`, `MaxTokens`, `DefaultLimit`, `MaxLimit`, `SnippetMaxChars` | All added during implementation. They are in the tables above. |
| §12 S4: "fuzz-tested" | `FuzzBuildMatchQuery` and `TestFTSSearchInjectionFuzz` | The claim holds. |

## Where the design lives

The reasoning behind this design — the two-table decision, why Porter stemming
is off, the regeneration story, the link between search and the secret
visibility rules — is in the design plan at
`.kilo/plans/1790590471729-ttrpg-wiki-vtt-architecture.md` (§6.3, §6.4, §8.5,
§12). **`.kilo/` is gitignored, so the plan is not in the repository and this
document is the durable copy of what survives into the code.**
