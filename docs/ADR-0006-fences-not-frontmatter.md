# ADR-0006: Content hides through a body fence, never a frontmatter key

Status: accepted · Date: 2026-09-29

## Context

The design plan's `houserules` feature asks for two sections on the house-rules
index: a **"Shared with the table"** section listing the rules every player can
see, and below it a **"DM only"** section that appears for DMs and lists the
`private` and `dm` rules. The plan is explicit that the authorization behind it
is structural: the list is `WHERE pages.page_type = 'houserule' AND
<SecretVisibleSQL>` over the page's secrets, so a hidden rule is *absent* from
the list, from the count and from the tag chips rather than greyed out.

What the plan does not check is what a "hidden rule" **is**. In this data model
a rule is an ordinary page, and a page is a file, and the `pages` table has no
visibility column — the only visibility in the schema is `secrets.visibility`,
on a row that describes a *span of a page's body*. A page is reachable at
`/p/{path}` under `authz.PermReadPage`, a permission that takes no resource,
and it is listed in the file tree, the tag cloud, the command palette, the
search results and every backlink, all under the same rule. There is no
per-page ACL in v1, and no seam at which one could be introduced without a
change to the table every page query in the app reads.

So the request is not a missing feature in the plugin. It is a category the data
model does not contain, and the question is what to do when a requested section
would have to be built out of a primitive that does not exist.

## Decision

**A page has no visibility. What hides is a region of a page's body: a
`visibility=` secret fence.** The house-rules index ships one section, says so
in prose on the page, and points at the mechanism that does hide content.

The reasoning is the one `internal/systems/houserules/index.templ` gives in its
own preamble, and it is worth restating because it is the general form: a
"DM only" section would have to filter on a key the plugin invented and nothing
else in the app enforces. The page would still be openable at `/p/{path}` and
still listed in five other places, so the section would advertise rules it does
not protect — under a heading that tells a reader exactly which side of the line
they are on. A section whose contents are readable by everyone is a section
that must not be rendered.

The same shape generalises to any plugin. A DM-only *page* is not a thing this
model can express; a page that is mostly a secret **is**. The five
house rules the sample campaign keeps between the game master and the page
owners are not hidden by a key — they are ordinary pages whose interesting
paragraph is a fence, and the fence is what the normal secret machinery already
redacts, indexes, audits, reveals and revokes.

`TestTheIndexShipsOneSectionAndSaysWhy` pins all of it, **including that
`visibility` is not among the frontmatter keys the plugin reads**, so a future
change that starts honouring an invented key has to update a test that explains
why it must not.

## Alternatives considered

1. **A `visibility:` frontmatter key on the page.** The minimal-looking answer,
   and the one rejected for the reason the whole design is built around: it
   hides content in one place and five others. The file tree, the tag cloud, the
   command palette, the search results, the backlinks and `/p/{path}` would each
   have to learn the key, every one of them would be a separate place to get it
   wrong, and no existing test would notice the one that was missed. It is worse
   than not shipping the section, because the section's whole purpose is to be
   a trustworthy list.

2. **A `pages.visibility` column.** A schema and predicate change on the table
   every page query reads, and — this is the part that decides it — v1 has no
   per-page ACL anywhere else. A column would be the first and only page-scoped
   authorization in the application, with no matrix row describing who holds it,
   no ownership arm in `authz.Policy` to carry it, and no route `Perm` that
   would answer the right question. It would also have to answer the harder
   question of what a *search hit inside a `dm` fence* looks like on a page
   whose frontmatter says `visibility: table`.

3. **A plugin-private list of hidden paths, in the plugin's own config.** The
   hidden set would be data the host cannot see, so the file tree, the search
   and the palette would all still list the page, and a plugin that forgot an
   entry — or a DM who moved a file — would leak. It also makes the plugin the
   only component that knows which of its pages are private, which is the
   property the fence exists to avoid.

4. **Two directories: `House Rules/` and a second, DM-only one.** The same
   defect with a different spelling. A path prefix is a convention, and the five
   other places a page is reachable would have to know the convention rather
   than a property of the page; a page the operator drags to the wrong folder
   stops being hidden with no error anywhere.

5. **Ship the section and let it be empty for players.** Rejected because it is
   indistinguishable from the bug: a section headed "DM only" that is empty for
   a player and non-empty for a DM tells the player that hidden rules exist, and
   a list that grows is a list whose contents somebody may open. The fence's
   model — *absent, not greyed out* — is the one that discloses nothing.

## Consequences

- **The house-rules index has one section, permanently, and says why on the
  page.** The count, the tag chips and the search rows are all filtered by the
  canonical predicate with an identical count, so there is nothing for them to
  disagree about; `TestTheListAndItsCountAgreeOverTheWholeMatrix` and
  `TestNoChipCountsARuleTheReaderMayNotOpen` are the gates.
- **The fence is the *only* hiding mechanism, so its fail-closed behaviour is
  load-bearing everywhere.** A directive that cannot be read is hidden from
  everybody rather than demoted to public — the direction this decision depends
  on, and the one
  `TestAnUnunderstoodSecretFenceNeverBecomesPublic` in
  [`../internal/md/unparseable_secret_test.go`](../internal/md/unparseable_secret_test.go)
  pins.
- **A plugin that needs a DM-only *page* has no primitive and must express the
  content as a fence instead.** That is a real constraint and it is a feature of
  the model rather than a gap in it: the fence is audited, revocable, re-checked
  at revision read time and purged from the search index on revoke, and none of
  those is available to a frontmatter key.
- **It forecloses a per-page ACL.** Whoever wants one will have to argue for it
  at the schema, at `authz.Policy`, at the route table and at the five derived
  surfaces at once, and the first two of those are where a page-scoped
  authorization that is only half-wired belongs — which is the exact failure
  AGENTS.md §11 records for the `secret_events` audit, and the reason that gap
  was closed with its own permission constant rather than folded into an
  existing one.
