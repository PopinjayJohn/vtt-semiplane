# Security

The security design of `vtt-semiplane`, written so that a reader can find the
rule and then read the code that owns it.

**The code is the specification.** Every technical fact below is a pointer to the
file that decides it, not a restatement of it. Where this document and the code
disagree, the code is right and this document is the bug — see
[Divergences from the plan](#divergences-from-the-plan). The durable
cross-references for the whole repository are [`../AGENTS.md`](../AGENTS.md) §2
and §6; this document does not replace them, it is the long form of the security
half of §2.

## Threat model

The app is a LAN-hosted wiki and player tool for one small authenticated group,
served from one machine, with **secret bodies stored in plaintext** — in the
Markdown file and in the SQLite index. There is no encryption at rest, on
purpose; the reasoning is in
[`ADR-0004-plaintext-secrets.md`](ADR-0004-plaintext-secrets.md) and the summary
here is one sentence: encryption with a key the binary can read does not survive
anyone who can read the disk.

**In scope.**

- A **player** in the group reading a body they were not shown. This is the
  threat the whole design exists for, and it is the one the tripwire tests.
- A **player probing for what exists** — a page, a secret, a route — by watching
  status codes, bodies, headers or counts.
- A **browser** rendering vault Markdown as markup: XSS through a note.
- **Derived artefacts** leaking what the file does not: the FTS tables, the
  backlinks, the TOC, the counts, the logs, the audit trail, the error text, the
  DOM.

**Out of scope, and stated rather than papered over** — see
[Deliberately not defended](#deliberately-not-defended). A stolen disk is a full
compromise. So is a copied backup, and so is a player who was online when a
secret was revealed.

**The blast radius of a mistake** is bounded by two structural properties, not by
care. A secret body is in the search index *only* while its visibility is
`table`, and the shipped request path has no outbound network capability, so
there is no exfiltration path to reason about. The first is asserted at query
time by `search.Query` (`secretIndexInvariantSQL`,
[`../internal/search/search.go`](../internal/search/search.go)) and by
`TestSecretIndexInvariantIsAsserted`
([`../internal/search/search_test.go`](../internal/search/search_test.go)), which
plants a hidden body behind `store`'s back to prove the assertion has teeth. The
second is `TestNoOutboundNetwork`
([`../internal/architecture_test.go`](../internal/architecture_test.go)), which
greps the tree for client-side capability; the output-side half of the same rule
is `TestNoRemoteAssetReference`, which scans every page the server can render
plus the committed stylesheet, shell script, sprite and vendored DataStar
([`../internal/httpapi/render_test.go`](../internal/httpapi/render_test.go)).

## The canonical predicate

The rule that decides who may read a secret body exists **once**, as a SQL
fragment:

```go
// internal/authz/predicate.go
const SecretVisibleSQL = `(...)`
```

It binds exactly two parameters, `:uid` and `:is_dm`, and
`Principal.Bind` ([`../internal/authz/predicate.go`](../internal/authz/predicate.go))
supplies them; an anonymous principal binds `uid` to `-1`, so it can never match
an author or an owner id by accident. The fragment is embedded **verbatim** —
never re-derived, never reformatted — by every query that can return a
secret-derived row. `grep -rn SecretVisibleSQL --include=*.go internal/` is the
list of those queries, and every one of them is a constant plus this fragment
plus bind parameters.

**Why one predicate, and what a second implementation costs.** The `dm`
visibility deliberately falls through every positive clause: only the
`:is_dm = 1` branch can see it. That is the negative case, and negative cases
are what an `OR`-chain forgets. A hand-rolled predicate of the obvious shape —
*DM, or the page is public, or the reader owns the page, or the reader wrote it*,
with `dm` folded into the "or the reader is a DM" clause and a `private` branch
that treats ownership as sufficient — is wrong in exactly one place, and the
wrong place is the one that serves a DM's hidden note to the player who owns the
page it sits on. The player has every other permission on that page. They are not
supposed to have this one.

So the negative case is stated three times over, in code, because stating it once
is not enough:

- The fragment omits `s.visibility = 'dm'` entirely, and
  `TestVisibilityPredicateShape`
  ([`../internal/architecture_test.go`](../internal/architecture_test.go)) reads
  the file and fails the build if that line ever appears. The comment on
  `VisibilityDM` in
  [`../internal/authz/principal.go`](../internal/authz/principal.go) says the
  same thing.
- The Go twin, `authz.CanReadSecret`, switches on the visibility value and
  `default:`s to **deny** — an unknown visibility is not a licence
  ([`../internal/authz/predicate.go`](../internal/authz/predicate.go)). A test
  that permits everything an unrecognised input is not is a test that will
  eventually be handed one.
- The policy's own `PermReadSecret` case spells the negative out in words before
  it checks anything else, and the matrix row for it is annotated as the one an
  `OR`-chain gets wrong
  ([`../internal/authz/policy_test.go`](../internal/authz/policy_test.go)).

**The predicate is not a filter, and the count is not a different filter.** A
panel that lists one row while counting three is an existence leak, so every
query that uses the fragment uses the *identical* fragment for its `COUNT`. The
agreement is tested from both sides: `TestBacklinkCountMatchesList` and the
count/list half of `TestPredicateMatrixAgrees`
([`../internal/store/rows_test.go`](../internal/store/rows_test.go)), and
`TestListPageAndCountPageAgree`
([`../internal/secrets/service_test.go`](../internal/secrets/service_test.go)).

**A second implementation is also forbidden by a grep.**
`TestNoHandRolledVisibilityPredicates` fails the build on any line outside
`internal/authz` that compares a `visibility` column to a quoted string literal,
whatever the literal says.

### Known gap: the fragment has no authentication term

`SecretVisibleSQL` admits a `table` secret on the strength of its visibility
alone, with nothing requiring the reader to hold a session. The plan's §8.2 says
an anonymous request sees no secret under any visibility, and
`authz.CanReadSecret` enforces that — so **the SQL fragment and the Go check
disagree for one case: anonymous plus `table`.** Consumers compensate with a
check on the principal rather than on a visibility value, so a compensation can
only ever remove rows:

- `store.publicOnlySQL` and `store.maySeeAnySecret`
  ([`../internal/store/secret.go`](../internal/store/secret.go)) — used by the
  secret, tag, backlink and TOC queries.
- `if p.Authenticated()` around the two secret statements in `search.Query`
  ([`../internal/search/search.go`](../internal/search/search.go)).

The compensation is reported as a finding in the code rather than folded in,
because `authz` is not that package's to change and the fragment is pinned by a
test. **The honest statement of the current state: the fragment is not
self-sufficient, and every consumer has to remember a rule the fragment does not
carry.** A consumer that forgets is not caught by the grep tests, because it did
not write a visibility comparison. Stage 4 added a new consumer — the
broken-links panel, `store.ListVisibleUnresolvedLinks` in
[`../internal/store/link.go`](../internal/store/link.go) — and it took the
compensation as well as the fragment, which is the shape a new consumer is
expected to have.

## The authorization matrix

Roles: **anon** (unauthenticated), **player**, **owner** (a player who owns the
page in question), **dm**, **admin**. `owner` is a player *relative to a
resource*, not a role — which is why it is expressed through
`authz.Resource.IsPageOwner` rather than by a `Role` value
([`../internal/authz/principal.go`](../internal/authz/principal.go)). `dm` implies
every `player` permission; `admin` implies every `dm` permission, because
`Principal.IsDM` is `RoleDM || RoleAdmin`.

**This table is for reading. The executable version is
[`TestAuthorizationMatrix` in `../internal/authz/policy_test.go`](../internal/authz/policy_test.go)
for the policy and
[`TestAuthorizationMatrix` in `../internal/httpapi/matrix_test.go`](../internal/httpapi/matrix_test.go)
for the HTTP surface, and those two are the authority.** The table below was
checked cell by cell against them; the last column records what each row is
actually verified by, and says so where the answer is "nothing yet".

| Resource / action | anon | player | owner | dm | admin | Verified by |
|---|---|---|---|---|---|---|
| Read public page | ✅¹ | ✅ | ✅ | ✅ | ✅ | `authz` matrix + `httpapi` matrix; anon-off in `TestAnonymousReadIsOffByDefault` |
| Read `table` secret | ❌ | ✅ | ✅ | ✅ | ✅ | `authz` matrix, `TestAWriterMayNotReadADMSecret` |
| Read `private` secret | ❌ | ❌ | ✅ | ✅ | ✅ | `authz` matrix, `TestPrivateSecretIsReadableByItsAuthorAndDMOnly` |
| Read `dm` secret | ❌ | ❌ | ❌ | ✅ | ✅ | `authz` matrix, `TestAWriterMayNotReadADMSecret` |
| Search results (authz-filtered) | ✅¹ | ✅ | ✅ | ✅ | ✅ | `httpapi` matrix (`/search`, `/api/search`); `TestSearchNeverReturnsAHiddenSecret` |
| Backlinks / related (authz-filtered) | ✅¹ | ✅ | ✅ | ✅ | ✅ | served inside the page view; `TestPredicateMatrixAgrees`, `TestBacklinkCountMatchesList` |
| TOC (secret headings filtered) | ✅¹ | ✅ | ✅ | ✅ | ✅ | served inside the page view; `TestPredicateMatrixAgrees` |
| Open the raw view of a page | ✅¹ | ✅ | ✅ | ✅ | ✅ | `httpapi` matrix (`/p/*/raw`); `TestTheRawViewLocksWhatTheReaderMayNotRead` |
| Create a page | ❌ | ✅ | ✅ | ✅ | ✅ | `authz` matrix (`PermWriteAny`); **no route mounted in v1** |
| Edit a page you own, including the public parts | ❌ | ✅ own | ✅ | ✅ | ✅ | `httpapi` matrix (`/p/*/edit`); `TestThePageScopedWriteGateIsARefusalAndNotADecoration` |
| Edit someone else's public page | ❌ | ❌ | ❌ | ✅ | ✅ | `httpapi` matrix (`/p/*/edit` by role); `authz` matrix (`PermWritePage`) |
| Edit a `dm` secret | ❌ | ❌ | ❌ | ✅ | ✅ | `authz` matrix (`PermWriteSecret`); `TestAVisibilityChangeThroughASaveIsADMOnly` |
| Create a secret | ❌ | ✅ own | ✅ | ✅ | ✅ | `authz` matrix (`PermWriteSecret`); `TestAuthoringANewSecretNeedsWritePermission` |
| Rename a page, and opt in to rewriting the links that point at it | ❌ | ✅ own | ✅ | ✅ | ✅ | `httpapi` matrix (three §5.6 rows); `TestUpdaterRespectsWritePermissionPerPage`, `TestARenameCarriesThePageOwners` |
| Read the history and one revision of a page | ✅¹ | ✅ | ✅ | ✅ | ✅ | `httpapi` matrix (`/p/*/history`, `/p/*/revisions/{revID}`); `TestRevisionRevocationIsAuthorised` |
| Revert a page to a revision | ❌ | **not exercised** | **not exercised** | ✅ | ✅ | `TestRevisionHistoryAndRevert` (DM 303, a player who owns nothing 403); the matrix row can only reach a 404, so the owner cell is unproven |
| Serve a page's attachment | **404 in the fixture** | ✅ | ✅ | ✅ | ✅ | `httpapi` matrix (`/p/*/attachment/{name...}`); `TestAttachmentInSecretIsNotServed`. The fixture's name is deliberately unrecorded, so the matrix's cells are 404s and prove the gate, not the grant |
| List the campaign's broken links | ✅¹ | ✅ | ✅ | ✅ | ✅ | `httpapi` matrix (`/broken`); `TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks` |
| Reveal to table | ❌ | ❌ | ❌ | ✅ | ✅ | `TestOnlyADMCanReveal`, `TestAPlayerOwningThePageStillCannotReveal`; **no HTTP route** |
| Revoke | ❌ | ❌ | ❌ | ✅ | ✅ | `TestRevokeIsRevealToPrivate`, `TestAPageOwnerMayNotRevealADMSecret`; **no HTTP route** |
| Delete a page | ❌ | ❌ | own only | ✅ | ✅ | `authz` matrix (`PermDeletePage`); `vault.Writer.Delete` exists; **no route** |
| Manage users / invites | ❌ | ❌ | ❌ | ❌ | ✅ | `authz` matrix (`PermAdmin`), `TestOnlyAnAdminMayCreateAnInvite`; **no admin route** |
| Change a role | ❌ | ❌ | ❌ | ❌ | ✅ | `authz` matrix (`PermManageUser`), `TestANonAdminIsRefusedAdminSurface` |
| Trigger reindex / backup | ❌ | ❌ | ❌ | ❌ | ✅ | **disputed — see below**; `PermDM` in `authz` matrix |
| Trigger a restore | ❌ | ❌ | ❌ | ❌ | ✅ | **no route, no test row**; `PermAdmin` is admin-only |
| See `secret_events` audit | ❌ | ❌ | ❌ | ✅ | ✅ | `authz` matrix (`PermAuditSecrets`), `secrets.TestEventsRequiresPermission`; **no HTTP route** |
| Read the DB file / `.semiplane/` over HTTP | ❌ | ❌ | ❌ | ❌ | ❌ | no such route; `TestA404IsTheSameAnswerForEveryKindOfNothing` |
| Plugin routes | per plugin | per plugin | per plugin | per plugin | per plugin | mounted at `PermSession`; `TestTheMatrixCoversEveryRoute` does not read the mounted tree, so the ceiling is asserted in `mountPluginRoutes` and the plugin packages' own tests |
| Read `/setup` after bootstrap | ❌ | ❌ | ❌ | ❌ | ❌ | `TestSetupRouteDisappearsAfterBootstrap` — 404, byte-identical to an unrouted URL |

¹ only with `--allow-anonymous-read`; the flag is off by default and the policy
is its own authority, so a principal cannot widen itself past it
(`TestPolicyIsTheAuthorityForAnonymousRead`).

**The `private` row's `owner` cell is the one to read twice.** A page owner may
read another author's `private` secret on a page they own. That is the plan's
§8.2 table, `authz.CanReadSecret` and `authz.SecretVisibleSQL` all agree on it,
and the "ownership grants authoring rights, not broadcast rights" line in
[`../AGENTS.md`](../AGENTS.md) §6 governs **reveal and revoke** — a separate
permission with a separate answer — not reading. The row was asserted the other
way round by `TestAWriterMayNotReadADMSecret` for three stages, and it passed
because the fixture wrote its ownership grant before a reindex that deleted the
row it named, so `IsPageOwner` answered false throughout and the assertion was
never exercised. The ordering is fixed and the test now says so; the general
form of the trap is in [`../AGENTS.md`](../AGENTS.md) §11.

Three more rows need their own paragraph, because the plan's version of them and
the code's version do not agree.

**Reindex and backup.** The plan puts both at admin-only. The executable matrix
bundles them with reveal and revoke under one `PermDM` row named "reveal to
table, revoke, trigger a reindex or backup", and `PermDM` admits a DM as well as
an admin ([`../internal/authz/policy_test.go`](../internal/authz/policy_test.go),
[`../internal/authz/policy.go`](../internal/authz/policy.go)). The code is the
authority and this table follows it, while recording the disagreement. There is
no route for either operation in v1, so nothing is exposed either way; a
decision is owed before a route is added.

**The audit trail.** This was a live gap and is now closed. The plan gives the
page owner their own `secret_events`; the code does not, and never did: the
method that reads the trail is `secrets.Service.EventsFor(ctx, actor, secretID)`,
it takes a principal, and it asks `authz.PermAuditSecrets` **before** the
lookup — so a refused principal gets the same answer for every id and cannot
enumerate them. The constant is deliberately its own rather than a fold-in of
`PermDM`, because folding it in would have closed the gap by accident and left
the constant's name lying about what it grants. No route is mounted, so nothing
is served. An audit row records *that* a secret changed visibility and never
*what it said*.

**`/setup` after bootstrap.** The matrix says "forbidden for everyone". The code
answers something stronger: the route answers 404, and the body is
byte-identical to the answer for a URL that was never routed, so an outsider
cannot confirm that a semiplane exists here, let alone that it is set up
(`ErrSetupClosed` is deliberately distinct from `ErrDenied` for this reason).

**The route table's `Perm` column is not the whole authorization, and for the
page-scoped write rows it is not even the interesting half.** `Server.permit`
asks the policy with a zero `authz.Resource`, so a `PermWritePage` column is
answered "is this a DM or an admin" and the policy's ownership arm is
unreachable through it. Those rows are `PermSession`; the page-scoped decision
is `httpapi.mayWritePage` inside the handler, and `secrets.Service.Save` makes
the same check before it writes. The reasoning, and the trap in the other
direction, is in [`../AGENTS.md`](../AGENTS.md) §2.7.

**Three answers exist and only three:** 200, 403, 404. A 303 to `/login` is the
unauthenticated variant of "no". A principal that cannot read a page gets the
same answer as a principal asking for a page that does not exist, byte for byte
(`TestA404IsTheSameAnswerForEveryKindOfNothing`).

## The secret lifecycle

### On disk

A secret is a fenced block. Fences rather than callouts because they are
unambiguous, arbitrary in length, and byte-exact for round-tripping:

````markdown
```secret id=7f3a91c40d2e visibility=private author=johan created=2026-09-28T10:04:11Z title="The cellar door"
The vault door is warded. Opening it deals 3d6 necrotic damage.
```
````

The grammar, the key set and the quoting rule are
[`../internal/md/secret.go`](../internal/md/secret.go) — `ParseFenceDirective`,
the key constants `KeyID` / `KeyVisibility` / `KeyAuthor` / `KeyCreated` /
`KeyTitle`, and `scanDirectiveFields`. Read that file rather than the table
above: the key set is closed, and a fence carrying a key outside it is treated
differently from a fence carrying a bad value.

**A value containing a space must be quoted**, and the quotes may be single or
double with backslash escapes. This is the requirement the plan omits, and the
omission has a recorded cost — see
[Divergences](#divergences-from-the-plan). `title=The cellar key` scans as
`title=The` plus two unknown keys.

### Segmentation

`md.Segment` classifies every byte of a document as public or secret
([`../internal/md/segment.go`](../internal/md/segment.go)). There is no third
state, so there is nothing to forget. Its behaviour on malformed input is
fail-closed, and every branch is pinned:

| Situation | Behaviour | Test |
|---|---|---|
| Unknown directive key | stays a secret, synthetic id, problem reported | `TestUnknownDirectiveKeyIsHiddenNotDemoted`, `TestAFenceMayNotBeReadAsPublicBecauseItsDirectiveIsOdd` |
| Unparseable directive | same, with an id prefixed `unparsable-` so it can never collide with a real 12-hex id | `TestAnUnunderstoodSecretFenceNeverBecomesPublic`, `TestAnUnparseableSecretFenceGetsAnID` |
| `visibility=` names an unknown value | falls back to `private` (redact harder) | `TestKnownKeyWithAnUnusableValueStaysSecret` |
| Unterminated fence | the span runs to EOF, problem reported | `TestUnterminatedSecretRecovers` |
| Fence nested in a fence | the inner fence is literal text, the outer span continues | `TestSegmenterNestedSecretRejected` |
| Quoted value with a space | still a secret | `TestQuotedDirectiveValueDoesNotDemoteASecretToPublic` |

The cost of fail-closed is that a malformed fence is invisible even to the DM
until it is fixed. The alternative was a disclosed secret. `sync` surfaces the
problem rather than dropping the fence
(`TestAFenceThatCannotBeIndexedIsReportedAndSkipped`).

### Indexing

Only non-secret spans reach `page_text` and `page_fts`
(`TestNoSecretEverEntersPageText`). **A secret body enters `secret_fts` only
while its visibility is `table`, ever** — that is structural, not a filter, so
no SQL bug can return a hidden body from search
(`TestSecretIndexHoldsOnlyTableSecrets`, `TestRebuildSecretFTSOnlyIndexesTableSecrets`).
A `table` secret's *hit* names the owning page and carries no snippet
(`TestSecretHitCarriesNoSnippet`); snippets come from `page_fts` only, and are
HTML-escaped where they are built (`TestFTSSnippetIsHTMLSafe`).

### Reveal and revoke

Reveal is a **file mutation of one token**, not a database mutation, and this is
the reason a revealed secret stays revocable at all.
`Service.SetVisibility`
([`../internal/secrets/service.go`](../internal/secrets/service.go)) reads the
file, calls `md.SetVisibility` ([`../internal/md/edit.go`](../internal/md/edit.go))
to rewrite **only the `visibility=` token inside that fence's directive line**,
and writes atomically through `vault.Writer`. The fence survives, so the secret
keeps its id, its audit trail and its revocability; the bytes outside the token
are untouched
(`TestRevealTouchesNothingButTheVisibilityToken`, `TestVaultRoundTripPreservesSecretBytes`,
`TestRevealPreservesSecretID`).

The policy check happens **before any lookup**, so a principal that may not
reveal gets the same answer for every id and cannot time its way to an inventory.

Revoke is the same operation towards `private`, plus a purge: the
`secret_text` and `secret_fts` rows are deleted rather than filtered
(`TestRevokePurgesTheIndex`), the event and the `authz_generation` bump commit
in one transaction, and the page is reindexed afterwards — so a crash leaves the
file right and the index stale, and the reconciliation scan rebuilds from the
file. A lost race returns `RaceLostError`, which matches `vault.ErrConflict` so
the caller still renders a conflict while carrying no bytes: `vault.ConflictError`
holds both versions of a page, and on a page with a secret fence those bytes
*are* the secret.

### Reading one secret

`secrets.Service.Load` is the only read path for a body, and it decides with the
canonical SQL predicate rather than a Go re-statement of it. An invisible secret
is reported as *no rows*, not as a denial, because the existence of the id is
itself the thing being hidden (`TestASecretThatWasNeverIndexedIsNotFound`).
`secrets.Service.ListPage` returns no bodies at all, so a panel that lists a
page's secrets cannot leak one by a mistake in the renderer.

### What a placeholder may contain

A secret the reader may not see is replaced by a lock affordance. It may carry
**the fence id and a generic label, and nothing else** — never the body, the byte
length, the author, the title, the visibility, or any excerpt.
`secrets.Secret.Redacted` drops the body *and* the body hash rather than
replacing the body with a same-length placeholder, because response size is
observable and a length is a disclosure
([`../internal/secrets/secret.go`](../internal/secrets/secret.go)). The rendered
markup is walked attribute by attribute in `TestSecretPlaceholdersCarryNoMetadata`
([`../internal/httpapi/tripwire_test.go`](../internal/httpapi/tripwire_test.go)),
which fails on a lock with an extra attribute as firmly as on an extra word.

### Revisions, attachments, the editor

- **Revisions** are re-segmented and re-authorised **at read time**, so a
  revision from before a revoke cannot be read afterwards. Both the revision's
  own bytes and the current fence are asked, because each alone gets a case
  wrong: authorizing only the present makes a revoke change only the present,
  and authorizing only the bytes makes a deleted `dm` secret readable again.
  A fence the file no longer holds falls back to its own copy, so deletion is
  not treated as a revocation — `TestARevisionHoldingASecretTheFileNoLongerHasStillReads`
  pins that, because it looks like a hole and is not. The read paths are
  `secrets.Service.History`, `secrets.Service.Revision` and
  `secrets.Service.Revise` in
  [`../internal/secrets/revision.go`](../internal/secrets/revision.go);
  `TestRevisionRevocationIsAuthorised` is the gate. Retention is
  `store.AppRevisionRetention` and `store.ExternalRevisionRetention`
  ([`../internal/store/revision.go`](../internal/store/revision.go)), which also
  covers `create` and `delete` as app-made writes — a third bucket would let an
  external tool churn a page into unbounded rows. The history rows carry no
  content at all, so a list cannot leak a body; the `Visible` column on a row is
  a metadata-only approximation that never gates one.
- **Attachments.** Visibility is a property of the *reference*, not the file, and
  there is deliberately no global `/attachments/{name}` route. The row is written
  by the indexer, one per *referencing page* rather than one per file, which is
  why the schema's constraint is `UNIQUE(path, page_id)` — see the migration's
  own comment. The page-scoped route resolves the requested name against that
  page's rows and never against the filesystem, compares it exactly, answers
  "you may not have it" and "there is no such file" as one 404, and serves the
  bytes under `default-src 'none'; sandbox`. The whole thing is
  [`../internal/httpapi/pageattachment.go`](../internal/httpapi/pageattachment.go).
  An attachment referenced only from inside a secret is therefore served only
  to a principal who may read that secret
  (`TestAttachmentInSecretIsNotServed`).
- **The editor and the redacted sentinel.** The sentinel grammar
  `‹s:<id>:<bodyLen>:<bodySHA256first8>›`, its byte-splice save, and the
  position-matching that makes a forged or stale token a refusal rather than a
  restore, are [`../internal/md/sentinel.go`](../internal/md/sentinel.go);
  `secrets.Service.EditView` and `secrets.Service.Save` are what decide the mode
  and call them. **A sentinel is a restore token, not a display token** — it
  carries a length and a digest of a body the reader was refused, which is
  exactly what the raw view and the conflict page must not hand out, so both
  replace the whole fence with `secrets.LockPlaceholder` instead.
  `TestTheConflictPageCarriesNoBodyTheReaderWasRefused` is the gate, and
  `TestEditorRedactedRoundTrip` is the byte-level one.

### Audit and generations

`meta['authz_generation']` is bumped on every authorization change — a reveal, a
revoke, a role change, an invite, a bootstrap, a disable
([`../internal/store/meta.go`](../internal/store/meta.go),
[`../internal/auth/session.go`](../internal/auth/session.go)). `Principal` carries
the value it was minted with. **The consumer that would act on it — terminating
a live-push stream whose captured principal is stale — is not implemented in v1.**
The counter is maintained now because retrofitting it would mean replaying
history.

## Rules enforced by a test

Each row is a rule with a test that fails the build when the rule is broken. If
a rule is not in this table, nothing enforces it.

| Rule | Test | File |
|---|---|---|
| No SQL built by string formatting | `TestNoSQLBuiltByStringFormatting` | [`internal/architecture_test.go`](../internal/architecture_test.go) |
| Every query uses bind parameters | `TestEveryQueryUsesBindParameters` | same |
| No hand-rolled visibility predicate outside `authz` | `TestNoHandRolledVisibilityPredicates` | same |
| `SecretVisibleSQL` never grants `dm` by comparison | `TestVisibilityPredicateShape` | same |
| The request path never talks to the network | `TestNoOutboundNetwork` | same |
| Nothing shells out except the composition root | `TestNoProcessExecution` | same |
| A plugin id appears only in the registry | `TestNoPluginSwitchInCore` (skips until a plugin exists) | same |
| The plugin import boundary | `TestPluginImportsAreWithinBoundary` | same |
| The dependency order holds | `TestDependencyDirection`, `TestPackageListIsComplete` | same |
| The policy answers the whole matrix | `TestAuthorizationMatrix` | [`internal/authz/policy_test.go`](../internal/authz/policy_test.go) |
| The router answers the whole matrix | `TestAuthorizationMatrix`, `TestTheMatrixCoversEveryRoute` | [`internal/httpapi/matrix_test.go`](../internal/httpapi/matrix_test.go) |
| A page owner may not read a `dm` secret on their own page | `TestAWriterMayNotReadADMSecret`, `TestAPageOwnerMayNotRevealADMSecret` | same |
| A page owner **does** read another author's `private` secret on a page they own | `TestAWriterMayNotReadADMSecret`, `authz.TestCanReadSecretOverTheWholeMatrix`, `store.TestPredicateMatrixAgrees` | same, [`../internal/authz/authz_test.go`](../internal/authz/authz_test.go) |
| The page-scoped write gate is made with the page's real ownership, not a zero `Resource` | `TestThePageScopedWriteGateIsARefusalAndNotADecoration` | [`internal/httpapi/pageedit_internal_test.go`](../internal/httpapi/pageedit_internal_test.go) |
| A surface that takes a page path from a request asks `vault.Ignored` before writing | `TestPathTraversalRejected`, `TestSaveRefusesTheAppsOwnState`, `TestRenameRefusesTheAppsOwnState` | [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go), [`internal/secrets/editor_test.go`](../internal/secrets/editor_test.go), [`internal/httpapi/rename_test.go`](../internal/httpapi/rename_test.go) |
| The raw view and the conflict page replace a hidden fence whole, with a fixed label | `TestTheRawViewLocksWhatTheReaderMayNotRead`, `TestTheConflictPageCarriesNoBodyTheReaderWasRefused` | [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go), [`internal/web/surfaces_test.go`](../internal/web/surfaces_test.go) |
| A redacted save restores a body byte for byte, and refuses the whole save on a mismatch | `TestEditorRedactedRoundTrip`, `TestSaveRefusesToWriteThroughAHiddenSecret`, `TestSaveRefusesAStaleHash` | [`internal/secrets/editor_test.go`](../internal/secrets/editor_test.go), [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go) |
| A revision from before a revoke is refused after it | `TestRevisionRevocationIsAuthorised`, `TestARevisionHoldingASecretTheFileNoLongerHasStillReads` | [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go), [`internal/secrets/revision_test.go`](../internal/secrets/revision_test.go) |
| A rename carries the page's owners, aliases and references | `TestARenameCarriesThePageOwners`, `TestRenameMovesTheFileAndRecordsTheAlias` | [`internal/httpapi/rename_test.go`](../internal/httpapi/rename_test.go) |
| The bulk link updater is per-page authorized, and a stale preview rewrites nothing | `TestUpdaterRespectsWritePermissionPerPage`, `TestStalePreviewIsHarmless`, `TestUpdaterSkipsLinksInsideHiddenSecretsForNonDM` | same |
| An attachment referenced only from a secret is not served to somebody who may not read it | `TestAttachmentInSecretIsNotServed`, `sync.TestAttachmentScopeIsPerPage` | [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go), [`internal/sync/attachment_test.go`](../internal/sync/attachment_test.go) |
| A dangling link inside a secret the reader may not read is neither listed nor counted | `TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks`, `store.TestUnresolvedLinksExcludeSecretOnlyDanglingLinks` | [`internal/httpapi/pageroutes_test.go`](../internal/httpapi/pageroutes_test.go), [`internal/store/stage4_test.go`](../internal/store/stage4_test.go) |
| Reading a secret's audit trail needs a principal, and a refused one learns nothing | `TestEventsRequiresPermission` | [`internal/secrets/editor_test.go`](../internal/secrets/editor_test.go) |
| A page-scoped suffix is unambiguous, and chi cannot be talked into routing one | `TestTheCatchAllAndItsSuffixesAreUnambiguous` | [`internal/httpapi/catchall_test.go`](../internal/httpapi/catchall_test.go) |
| A disabled account has no session | `TestADisabledAccountGetsNoSession` | same |
| No admin route exists yet, and the policy already refuses the surface | `TestANonAdminIsRefusedAdminSurface` | same |
| Every predicate agrees, and every count matches its list | `TestPredicateMatrixAgrees`, `TestBacklinkCountMatchesList` | [`internal/store/rows_test.go`](../internal/store/rows_test.go) |
| A hidden secret body is never in the search index | `TestSecretIndexHoldsOnlyTableSecrets`, `TestCheckSecretIndexInvariantCatchesALeak` | [`internal/store/fts_test.go`](../internal/store/fts_test.go) |
| A hidden secret answers no search | `TestSearchNeverReturnsAHiddenSecret`, `TestSecretHitCarriesNoSnippet` | [`internal/search/search_test.go`](../internal/search/search_test.go) |
| User input never reaches FTS `MATCH` | `TestFTSSearchInjectionFuzz`, `TestBuildMatchQueryQuotesEveryToken` | same, [`internal/search/query_test.go`](../internal/search/query_test.go) |
| Only a DM or admin reveals | `TestOnlyADMCanReveal`, `TestAPlayerOwningThePageStillCannotReveal` | [`internal/secrets/service_test.go`](../internal/secrets/service_test.go) |
| Revoke purges the index rather than filtering it | `TestRevokePurgesTheIndex`, `TestSecretIndexInvariantHolds` | same, [`internal/sync/secret_test.go`](../internal/sync/secret_test.go) |
| A reveal touches nothing but the visibility token | `TestRevealTouchesNothingButTheVisibilityToken`, `TestVaultRoundTripPreservesSecretBytes`, `TestRevealPreservesSecretID` | [`internal/md/secret_demotion_test.go`](../internal/md/secret_demotion_test.go), [`internal/md/reveal_test.go`](../internal/md/reveal_test.go) |
| A fence whose directive is not understood is hidden, not public | `TestAnUnunderstoodSecretFenceNeverBecomesPublic`, `TestUnknownDirectiveKeyIsHiddenNotDemoted` | [`internal/md/unparseable_secret_test.go`](../internal/md/unparseable_secret_test.go), [`internal/md/segment_test.go`](../internal/md/segment_test.go) |
| A secret never enters `page_text` | `TestNoSecretEverEntersPageText` | [`internal/sync/secret_test.go`](../internal/sync/secret_test.go) |
| Log attributes named for content are refused; long values truncated; the audit log is an allow-list | `TestHandlerRefusesContentAttributes`, `TestHandlerTruncatesLongValues`, `TestAuditHandlerIsAnAllowList`, `TestWithAttrsFiltersAtAttachTime` | [`internal/obs/obs_test.go`](../internal/obs/obs_test.go) |
| No passphrase, and no credential value, in an error or a log | `TestPassphraseNeverAppearsInAnErrorOrLog`, `TestFailedCredentialErrorsCarryNoValue`, `TestTheSuccessPathAlsoKeepsThePassphraseOutOfTheLog` | [`internal/auth/leak_test.go`](../internal/auth/leak_test.go) |
| Argon2id cost is pinned; a hostile row cannot exhaust memory | `TestArgon2ParametersAreTheAgreedOnes`, `TestVerifyRefusesAHashThatWouldExhaustMemory` | [`internal/auth/password_test.go`](../internal/auth/password_test.go) |
| Only the token hash is stored; expiry is absolute; rotation revokes | `TestOnlyTheRawTokenIsStored`, `TestSlidingRefreshNeverExtendsPastTheAbsoluteLimit`, `TestARotatedLoginRevokesTheOldToken` | [`internal/auth/session_test.go`](../internal/auth/session_test.go) |
| A role change invalidates existing sessions | `TestRoleChangeInvalidatesOldSessions`, `TestADisabledAccountGetsNoSession` | same, `internal/httpapi/matrix_test.go` |
| An invite is single-use, grants the invited role not the actor's, and is indistinguishable from unknown | `TestInviteIsSingleUseAndUndistinguishableFromUnknown`, `TestInviteGrantsTheInvitedRoleNotTheActors` | [`internal/auth/invite_test.go`](../internal/auth/invite_test.go) |
| The last admin cannot be demoted or disabled | `TestTheLastAdminCannotBeDemotedOrDisabled` | [`internal/authz/policy_test.go`](../internal/authz/policy_test.go) |
| An unknown permission fails closed | `TestUnknownPermissionFailsClosed` | same |
| CSRF is required on every non-GET route, derived from the route table | `TestCSRFRequiredOnAllMutations` | [`internal/httpapi/csrf_test.go`](../internal/httpapi/csrf_test.go) |
| The middleware chain is in the documented order and sets the security headers | `TestTheMiddlewareChainIsInOrder` | same |
| Rate limits: 10 logins/min, a lower search budget, a general budget; dev mode disables them | `TestRateLimitRefusesTheEleventhLoginInAMinute`, `TestTheSearchBudgetIsLowerThanTheGeneralOne` | same |
| There is no rendered-page cache | `TestNoRenderedPageCache` | same |
| Every asset comes from the binary; no remote origin in any rendered page | `TestAssetsAreServedFromTheBinary`, `TestNoRemoteAssetReference` | [`internal/httpapi/render_test.go`](../internal/httpapi/render_test.go) |
| No asset mirror outside the committed set | `TestThereIsNoAssetMirror`, `TestAssetsAreTheCommittedFiles` | [`internal/web/assets_test.go`](../internal/web/assets_test.go) |
| `templ.Raw` has exactly two call sites, both in one file | `TestOnlyThisPackageMarksHTMLRaw`, `TestPreRenderedIsTheOnlyWayToEmitRawHTML` | [`internal/httpapi/tripwire_test.go`](../internal/httpapi/tripwire_test.go), [`internal/web/view_test.go`](../internal/web/view_test.go) |
| Raw HTML in vault Markdown is not rendered; unknown syntax is escaped passthrough | `TestRawHTMLIsNotRendered`, `TestUnsupportedSyntaxIsEscapedPassthrough` | [`internal/md/render_test.go`](../internal/md/render_test.go) |
| XSS fixtures are escaped in a real response | `TestXSSFixturesAreEscaped` | [`internal/httpapi/render_test.go`](../internal/httpapi/render_test.go) |
| A path outside the vault is refused | `TestResolveRejectsAdversarialInput`, `TestWalkRefusesASymlinkOutOfTheVault`, `TestSaveRefusesAPathThatEscapes` | [`internal/vault/`](../internal/vault/) |
| One process per vault | `TestSecondInstanceOnSameVaultIsRefused`, `TestSecondInstanceIsRefused` | [`internal/vault/lock_test.go`](../internal/vault/lock_test.go), [`internal/app/boot_test.go`](../internal/app/boot_test.go) |
| A colliding path is a hard error, not a silent loss | `TestCaseCollisionHaltsIndexing` | [`internal/vault/walk_test.go`](../internal/vault/walk_test.go) |
| An empty bind address is refused rather than bound to every interface | `TestAWildcardBindIsRefused` | [`internal/app/boot_test.go`](../internal/app/boot_test.go) |
| The boot banner carries no vault content | `TestBannerPrintsNoVaultContent` | same |
| Backups are `0600` and say they hold secrets; a restore is verified against the manifest | `TestBackupIsPrivateAndSaysItHoldsSecrets`, `TestRestoreVerifiesTheManifestHash`, `TestRestoreRefusesAPathOutsideTheBackups` | [`internal/vault/backup_test.go`](../internal/vault/backup_test.go) |
| A parse problem carries an id, never the content | `TestProblemErrorCarriesTheIdNotTheContent` | [`internal/md/span_test.go`](../internal/md/span_test.go) |
| A secret's `String` carries no body | `TestSecretStringCarriesNoBody` | [`internal/secrets/fence_test.go`](../internal/secrets/fence_test.go) |

**One rule in the plan that still has no test.** The plan names
`TestOnlyPermMiddlewareIsConsulted`, a grep for `Role ==` in the handler
packages. It does not exist. A `Role ==` comparison does happen in exactly two
places — `Principal.IsDM` and `Principal.IsAdmin` in
[`../internal/authz/principal.go`](../internal/authz/principal.go) — and the
route table's `Perm` column is the only place a route is gated
([`../internal/httpapi/routes.go`](../internal/httpapi/routes.go)), so the rule
holds today by construction rather than by enforcement. The two companion rules
the plan also named, `TestNoOutboundNetwork` and `TestNoProcessExecution`, are
now in `internal/architecture_test.go`; the first greps for client-side
capability (`http.Get`, `http.Client{`, `net.Dial`, `"net/smtp"`, …) rather than
for the `net/http` import, because a server legitimately imports it and a
background goroutine dialling home would never appear in a rendered page.

## The tripwire

`internal/httpapi/tripwire_test.go` is the compensating control for the whole
design, and the highest-value test in the repository. It is not a consequence of
the design; it is the evidence for it.

**`TestNoSecretLeaksThroughAnyPath`** walks the full demo path as every role —
admin, DM, page owner, player, and an anonymous visitor with read off — and
asserts that no secret body the principal may not read appears in the response
body, in **any response header**, or in **any `data-signals` payload**. The
headers count as much as the body: a clean body and a `Location` or `Link` header
carrying the text is still a leak. The campaign is seeded with one
distinguishable token per secret across all three visibilities, so a finding
names the secret that leaked rather than the page it leaked on.

**`TestSecretFixturesNeverLeakThroughSearch`** runs the same assertion over the
search index, which is a different surface: a secret that never reaches a page
can still reach a result, and the result is a snippet. It also carries a
**positive control** — the index really does hold the `table` secret, so a search
for a word inside it does find a hit, and an ordinary page still appears in
search. Without that control the negative assertions could be passing because the
query was broken.

**The rule about the tripwire's own expectations.** The tripwire writes its model
of the visibility rule out by hand rather than calling `authz`, and the reason is
in the test:

> "It is deliberately not a call into authz: a tripwire that shares the
> implementation it is testing cannot catch that implementation being wrong."

The same sentence appears on the `leakPrincipal` type. Anything else the tripwire
covers on the same principle: `TestA404IsTheSameAnswerForEveryKindOfNothing`
(byte-identical 404s, with a positive control so it is not vacuous),
`TestAnUnauthenticatedPrincipalCannotDistinguishAPageFromItsAbsence`, and
`TestSecretPlaceholdersCarryNoMetadata`.

**These tests must never be skipped, and no test above may be deleted to make a
build green.** A leak tripwire that has been narrowed to the case that currently
passes is worse than no tripwire, because it reports coverage that does not
exist.

## Deliberately not defended

| Not defended | Why, and where it is stated |
|---|---|
| **A compromised host.** Anyone who can read the vault directory or the `.semiplane/` database file has every DM secret in plaintext. | Accepted by design. [`ADR-0004-plaintext-secrets.md`](ADR-0004-plaintext-secrets.md). `secrets.Secret.Body` is a plaintext field ([`../internal/secrets/secret.go`](../internal/secrets/secret.go)). The mitigations in scope are the file modes: the state directory `0700` and the database `0600` (`TestStateDirPermissions`, [`../internal/store/store_test.go`](../internal/store/store_test.go)); a backup directory `0700` with every file `0600` (`TestBackupIsPrivateAndSaysItHoldsSecrets`). |
| **A leaked backup.** A backup is a byte-for-byte copy of the vault plus the database, so it is exactly as sensitive as the live thing, and the database carries secret bodies as rows. | Accepted, and it follows from the row above. The backup directory is `0700` and every file `0600`, and the manifest is hash-verified on restore ([`../internal/vault/backup.go`](../internal/vault/backup.go)). Revoking a secret does not reach bytes already written to a backup taken before the revoke. |
| **A player who saw a secret before it was revoked.** No system can un-send bytes. | Accepted and documented rather than hidden. Everything *after* the revoke is clean — index purged, generation bumped, every subsequent fetch, search and export re-authorised — and that is what `TestRevokePurgesTheIndex` proves. The residue is on the player's screen and in their memory. |
| **Encryption at rest.** | Out of scope for v1 and designed for, not deferred: the `visibility=` token is a stable key on the fence line, and a future `storage=aesgcm:<nonce>` token needs no syntax change beyond one new key, no migration of the body column, and no change to any authorization path — only the read and write in one place. That is the whole argument in [`ADR-0004-plaintext-secrets.md`](ADR-0004-plaintext-secrets.md). |

Two more that are easy to assume are covered and are not:

- **Plugins are trusted code.** There is no sandbox; a plugin shares the process.
  The controls that exist are the import boundary, capability narrowing, and the
  fact that the `Host` interface has no method to contribute a script, a
  stylesheet or a DOM handle. See [`../AGENTS.md`](../AGENTS.md) §7 for the
  contract. A plugin's own routes are mounted at `PermSession` behind
  re-applied CSRF and permission checks
  ([`../internal/httpapi/routes.go`](../internal/httpapi/routes.go),
  `mountPluginRoutes`) — a deliberate ceiling, because the host has no
  vocabulary for "the permission this route needs" and inventing one would let
  a plugin name its own gate.
- **A public internet deployment.** The defaults are a loopback bind, a small
  authenticated group, and rate limits sized for a LAN. An empty bind address is
  refused rather than bound to every interface (`TestAWildcardBindIsRefused`).

## Not yet implemented

Everything in this section is in the design and not in the tree. A claim about it
is a claim about the future.

- **The secret's audit view.** `secrets.Service.EventsFor` is built and gated on
  `authz.PermAuditSecrets`; the route that would render it is not mounted.
- **Create, delete, reveal, revoke, export, and the whole `/admin` surface
  except the plugin boot report.** The services behind them exist and are tested
  directly (`TestAPageOwnerMayNotRevealADMSecret` says so in its own comment);
  the router mounts only what
  [`../internal/httpapi/routes.go`](../internal/httpapi/routes.go) lists.
- **The a11y and end-to-end gates**, and the CI jobs beyond the Go suite.

## Divergences from the plan

Recorded here rather than silently corrected, because the plan is not in git and
this is the durable record of where it and the code part company.

1. **The fence syntax omits the quoting requirement that now matters.** The plan
   documents `title` as "free text" with no quoting rule. The code requires a
   value containing a space to be quoted, and the plan's own grammar would have
   parsed `title=The cellar key` as `title=The` plus two unknown keys. Combined
   with the plan's rule that an unknown key makes the block public, a DM who
   followed the plan served their secret body in plaintext to a player. The code
   now fails closed — an unknown key is **hidden, not demoted**
   (`TestAnUnunderstoodSecretFenceNeverBecomesPublic`) — and the quoting rule
   makes the demotion unreachable. The lesson is recorded in the source comment
   at [`../internal/md/segment.go`](../internal/md/segment.go) and in
   [`../AGENTS.md`](../AGENTS.md) §0, and it is why this document points at code
   rather than restating it.
2. **Unknown directive key: the plan demotes to public, the code fails closed.**
   §8.1 says "Unknown keys → the block is treated as **public passthrough**". The
   code treats such a fence as a secret with a synthetic id and reports a
   problem. The code is right, per the row above.
3. **The predicate does not exclude anonymous readers from `table` secrets on
   its own.** §6.4 presents the fragment as the single place that decides;
   §8.2 says secrets are never available to anonymous users under any visibility.
   The fragment has no authentication term, so the Go and SQL answers differ for
   that one case and each consumer compensates. Described in full under
   [Known gap](#known-gap-the-fragment-has-no-authentication-term). The right fix
   belongs in the fragment; the code declines to patch it locally and says so.
4. **Reindex and backup are admin-only in the plan, `PermDM` in the code.** The
   executable matrix has one `PermDM` row whose name is "reveal to table, revoke,
   trigger a reindex or backup", and it admits a DM as well as an admin. The
   plan drew the line one row earlier, putting reindex and backup behind
   `PermAdmin`. The table above follows the code. No route exists for either
   operation, so nothing is exposed either way; a decision is owed before a route
   is added.
5. **The `secret_events` audit row the plan gives to page owners does not
   exist, and the plan's gap is closed with a constant of its own.** The plan
   gives the page owner their own audit rows; the code gives them to a DM or an
   admin and to nobody else. `secrets.Service.Events` — which took a context and
   an id and no principal — was removed rather than wrapped, and replaced by
   `EventsFor`, which asks `authz.PermAuditSecrets` before the lookup. The
   events are metadata, never a body, so a player is refused even for a secret
   they authored: the trail still says that a secret exists and who has touched
   it. No route is mounted, so nothing is served either way.
6. **CSRF is presented in a header or a form field, not in `data-signals`.** §12
   S7 describes a per-session token in a `data-signals` field. The code accepts it
   in the `X-CSRF-Token` header or a `csrf` form field, and for the two forms a
   visitor reaches before having a session it falls back to a stateless
   double-submit cookie rather than to a session token
   ([`../internal/httpapi/middleware.go`](../internal/httpapi/middleware.go),
   [`../internal/auth/csrf.go`](../internal/auth/csrf.go)). The plan's rationale
   — that a token in a form or a header cannot be read cross-origin — holds, and
   the header is what an enhanced form submission actually sends.
7. **The indexer does not rewrite a fence to add an id.** §8.1 says a missing or
   malformed `id` causes the sync to "assign a fresh id and rewrite the fence
   directive in place". The code assigns a synthetic id in memory
   (`anon-…`/`unparsable-…`) and leaves the file alone. The consequence is the
   safer one: an unparsable fence's placeholder id can never be mistaken for a
   real 12-hex id by the index, the tripwire, or a reveal.
8. **Test names in the plan that do not exist in the tree.** Notably
   `TestSecretVisiblePredicateMatchesMatrix` (the code has
   `TestPredicateMatrixAgrees`), `TestSecretFixturesNeverLeak` (the code has
   `TestNoSecretLeaksThroughAnyPath` and `TestSecretFixturesNeverLeakThroughSearch`),
   `TestRevokePurgesAllIndexes` (`TestRevokePurgesTheIndex`),
   `TestNoSecretInErrors`, `TestOnlyPermMiddlewareIsConsulted`, and the seven
   `TestPush…` tests — which the code *does* have, under
   `TestPushNeverLeaksSecret` and its six siblings in
   [`../internal/httpapi/events_test.go`](../internal/httpapi/events_test.go).
   `TestEditorRedactedRoundTrip` arrived with stage 4. Where a plan-named rule
   has no test at all, this document says so rather than borrowing the name.
   (`TestNoOutboundNetwork` and `TestNoProcessExecution` were named by the plan,
   absent from the tree, and have since been written under those names.)
9. **Cookie `SameSite` is `Strict`, not `Lax`.** §12 S7 specifies `Lax`; the
   code uses `Strict` ([`../internal/httpapi/middleware.go`](../internal/httpapi/middleware.go)),
   and the reason is in the comment there: `Strict` is what makes the
   double-submit CSRF comparison worth having, and nothing in the app has a reason
   to be submitted from another origin.
10. **`Referrer-Policy` is `same-origin`, not `no-referrer`.** Same file, same
    middleware. The CSP is otherwise as §12 specifies, with no `unsafe-inline` and
    no remote origin, and the code adds `Cross-Origin-Opener-Policy` and
    `Cross-Origin-Resource-Policy`, which the plan does not name.
11. **`Strict-Transport-Security` is conditional.** It is set only when the bind
    address is not loopback, because HSTS on `127.0.0.1` would pin the loopback
    origin to HTTPS and break it permanently. The plan does not mention HSTS at
    all; the plan's `Permissions-Policy` is a subset of the code's.
12. **Ownership resolves from `page_owners`, never from `pages.owner_id`.** The
    plan's §6.4 says `pages.owner_id` "is always mirrored as a `page_owners`
    row", which makes the two interchangeable. The code treats `page_owners` as
    the single source of truth and `Resource.IsPageOwner` is always built from
    it, so a divergence between the two is not representable rather than
    impossible.
13. **A route's `Perm` column is a coarse gate, and the page-scoped write rows
    say so.** The plan treats the route table's permission as the decision. It
    cannot be, for the page-scoped surfaces: the middleware asks the policy with
    a zero `authz.Resource`, so a `PermWritePage` column is answered "DM or
    admin" and the ownership arm is unreachable through it. Those rows are
    `PermSession` and the real decision — the one carrying the page's ownership
    — is `httpapi.mayWritePage` inside the handler, mirrored by the check
    `secrets.Service.Save` makes before it writes. The other direction is the
    trap: the plan's shape, taken literally, answers 403 to exactly the
    principal §8.9's redacted editor exists for, because a DM's hidden set is
    empty by definition and the only principal the redacted mode has a use for
    is a page owner.
14. **`attachments.path` is `UNIQUE(path, page_id)`, not `UNIQUE(path)`.** The
    plan's §6.2 makes the row a claim about the file; §8.8's rule is about the
    *reference*. A campaign-wide unique path means a second page referencing an
    image the first page already recorded cannot have a row of its own, so the
    serve route authorizes against that page's links and then has no row to serve
    from — an image a reader can plainly see on page two is a 404 on page two.
    The migration is
    [`../internal/store/migrations/0003_attachment_scope.sql`](../internal/store/migrations/0003_attachment_scope.sql)
    and its comment says the same thing at greater length.
