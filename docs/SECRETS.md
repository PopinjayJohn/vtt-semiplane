# Writing and using secrets

This document is for the game master. It assumes you have a vault and an
account, and it explains how to write a secret in it, who will see it, and what
happens when something goes wrong. It is written to travel with the binary, so
nothing in it depends on you having read the source.

## Before you put a real campaign in here

**Secrets are stored in plaintext.** The body of a secret is ordinary text in an
ordinary Markdown file, in the folder you keep the campaign in, and it is also
in plaintext in the app's index database. There is no at-rest encryption in
this version.

What protects a secret is the **file permissions on the vault** and the
**server-side authorization** on every read. If somebody gets a copy of the
vault directory, a backup, or the database file, they have every secret in it,
in clear text, and no feature of this application will stop that. The backup
command says so on its own output every time it runs.

This is a deliberate decision, with its reasoning — including what it costs and
how it would be revisited — in
[`ADR-0004-plaintext-secrets.md`](ADR-0004-plaintext-secrets.md). You should
read it before you decide what this vault is allowed to hold. The short version
is that the realistic loss is a stolen disk or a copied folder rather than a
network attacker, and that encrypting the body would make the file unreadable
in Obsidian — which is the property that makes a vault worth keeping.

## What a secret is

A secret is a fenced block in an ordinary Markdown file that the app **hides**
from anyone not entitled to read it and **shows in full** to anyone who is.
Nothing is moved out of the file: the fence stays where it is, readable in
Obsidian and in a text editor, with all of its bytes. What the app controls is
what it *serves*.

The body's Markdown — headings, lists, tables, links — is extracted and indexed
against the secret it came from, so a link or a heading inside a hidden fence
does not turn up in somebody's search results or backlinks.

## Writing one

A secret fence is a code block whose info string is the single word `secret`,
opened and closed with three backticks exactly like any other fence. The **first
line after the opening backticks is the directive**, and it is the only line
that matters. Shown here as a bare directive line rather than as a live fence,
because the scanner that finds secret fences reads every line in a file, not
only the lines inside a Markdown fence — a sample spelled with real backticks
becomes a real secret (see *Showing an example of a fence*, below):

```markdown
id=4e5b8c2a17f39 visibility=dm author=dungeonmaster created=2026-06-14T21:03:00Z title="The bell was rung by the town"
```

In your vault, that line goes directly after the opening ```` ```secret ```` and
the body follows it, closed by three backticks like any other fence.

The key set is **closed**. These five, and no others:

| Key | Required | What it means |
|---|---|---|
| `id` | yes | Twelve lowercase hexadecimal characters. The secret's identity, permanently. |
| `visibility` | no | `private` (the default), `dm`, or `table`. |
| `author` | yes | The **username** of the account that wrote it. Read the section below before you skip this. |
| `created` | no | An RFC 3339 timestamp, e.g. `2026-06-14T21:03:00Z`. |
| `title` | no | A label. Shown where a secret is listed. |

`id` is how a secret is referred to in a reveal, and it does not change if you
edit the body, the title or the visibility. **No two fences in the vault may
share one.** A duplicate is refused: the second fence keeps its own text but is
not treated as a well-formed secret, because the app cannot tell which of the
two was meant. Any twelve hex characters will do — a clock, a roll, the md5sum
of a phrase.

**A sixth key makes the whole directive unreadable**, and an unreadable
directive is not a formatting problem to shrug at. It is treated as *this fence
claims to be secret and could not be proven to say what it claims*, and the
fence is hidden from **everyone**. The bundled campaign carries one, broken on
purpose, with the two mistakes that break a fence spelled out beside it — see
*What the bundled sample campaign demonstrates* below.

### Quote anything with a space in it

This is the single most common way to break a fence, and it breaks it quietly:

```markdown
title=The bell was rung by the town
```

That is not a title with spaces. The value of `title` ends at the first space,
so the parser reads `title=The`, then `bell`, then `was`, then `rung`, then
`by`, then `the`, then `town` as seven more keys it does not recognise. The
directive is unreadable and the fence goes dark.

**Quote every value that contains a space.** Either kind of quote works:

```markdown
title="The bell was rung by the town"
title='The bell was rung by the town'
```

A value with no space needs no quotes: `visibility=dm`, `author=dungeonmaster`.
A backslash escapes whatever follows it inside quotes, so a title that contains
its own quote character is still one field.

This is quiet because the fence still *looks* right when you read it in a text
editor. It is the mistake this project has already made once, and the reason
the app now fails closed rather than open.

### Showing an example of a fence

Do not write the triple backticks around a sample `secret` directive, even
inside a longer code block. The scanner that finds secret fences reads **every
line in a file**, not only the lines inside a Markdown fence, so a sample
spelled with real backticks becomes a real, empty secret on the page —
invisible, and reported as a directive with no body. Show the directive line on
its own, as in the example above.

## The three visibilities

Three values, and the one that is missing is the safe one.

- **`private`** — the default. The author, the game master, any administrator,
  and the owners of the page the secret sits on. Nobody else. Use it for a
  player's own secret, a thing one character knows, or anything the table must
  not read.
- **`dm`** — game masters and administrators only. Not the page's owners, and not
  the author if the author is a player. This is the "true motive of the villain"
  visibility: a game master can put a secret for themselves on a page the
  players own and it still will not appear on their screen.
- **`table`** — everyone who is signed in, and nobody who is not. Reach for it
  when the secret is not a secret any more: a reveal you have decided to make, an
  ambiguity the whole table is allowed to disagree about, a piece of text meant
  to be read aloud.

An unrecognised value is treated as `private` and reported on the page.
Misspelling `dm` as `dms` does not widen the fence; it narrows it, and it says
so.

**`table` still means signed in.** A `table` secret is not public. A visitor
who is not signed in does not get it, and does not get a page saying they may
not have it either — the request fails exactly as it would for a secret they
were never entitled to, so the response cannot be used to find out whether a
particular secret exists.

## The accounts rule — read this before you write your first secret

**`author` is a username, and the username has to belong to an account that
actually exists.** It is not a label and it is not remembered anywhere else. A
fence whose author cannot be resolved is not indexed at all, and a secret that
is not in the index is shown to nobody.

**So on a brand-new vault, where no account exists yet, every secret you have
written is hidden from everybody — the table and you alike.** That is the first
thing that will confuse you, and it is deliberate. A secret whose author cannot
be resolved is a secret nobody can be shown to be entitled to, and the only safe
answer to *who is entitled to read this?* when the answer is *nobody knows* is
*nobody*.

What to do about it:

1. **Claim the first account at `/setup`.** Give it the username your fences
   name — the bundled sample campaign uses `dungeonmaster` — because the first
   account is the administrator and the fences will name it. The setup route
   answers 404 once any account exists, so it is not confirmable from outside.
2. **Create the other usernames your fences name**, as accounts of their own. An
   invite carries the *role* and not the username: the person redeeming it picks
   their own username on the form, so tell them which one to pick, or a fence
   naming `thia` stays hidden until somebody's account is actually called
   `thia`.
3. **The fences come back on their own.** The application re-checks the fences
   whose author was not yet an account at the moment an account is created and
   again on every boot; a full reindex also does it. **Nothing in your files
   needs editing** — the author name was always right, the index just could not
   resolve it before.

**The bundled sample campaign ships with authors that do not exist yet.** That
is not an oversight in the campaign; it is a demonstration of exactly this rule,
on a vault where nobody has claimed an account. The campaign's own pages say so
and name the three usernames to create. A fence whose author is never created
stays hidden and is reported on the page as an unattributable secret — it does
not become public.

## What a reader sees when they cannot read a secret

A locked box, in the place the secret was. It carries a lock icon, the word
**Hidden**, and the secret's id. That is all.

There is no length, no author, no title and no excerpt, deliberately: each of
those is a fact about a secret this reader was refused, and a response whose
*size* varies with the secret is a disclosure with no text in it. And there is
no view anywhere in the app that shows a reader a secret's title while
withholding its body, because that is how a secret's existence leaks.

Hiding is not deleting. The bytes are still in the file and still in the index;
the app refuses to render a body it may not show. Hiding also covers search,
backlinks, the table of contents and the campaign status panel — a hidden secret
is **absent** from them, not greyed out, and any count beside it counts the same
set its list would return.

**In the editor only**, a secret you may not read appears as a restore token
instead — a short bracketed string carrying the secret's id, the length of its
body and a short digest of it. That is not an obfuscation and it is not a
disclosure of the body; it is how a save puts the original bytes back, and it is
matched by position against the file's own fences rather than by searching the
buffer, so a body you cannot read cannot be restored by typing the right text.
A token that does not match what is on disk **rejects the whole save** rather
than writing your guess over the real thing.

Older versions of a page are re-checked the moment they are read, against the
reader asking right now. A secret that was visible before you hid it does not
stay readable through an old revision.

## Revealing and hiding a secret

Two controls appear on a page, for a game master or administrator only. They
change a secret between `table` and `private`:

- **Reveal to the table** — the fence becomes `table` and every signed-in
  account can read it.
- **Hide it again** — the fence becomes `private` and the app **deletes** its
  copy from the search index rather than filtering it, so the terms in it stop
  being findable immediately rather than at the next restart.

**A page owner cannot do this.** Ownership buys the right to write a secret on
that page; it does not buy the right to broadcast one to everybody else. A
player may author and edit their own secrets, and that is all.

**Revealing is a file edit, and you can see it.** It rewrites the `visibility=`
token inside that one fence's directive line and touches nothing else in the
file — no reflow, no reformatting, no normalisation. Open the vault in Obsidian
afterwards and you will see the token change. That is intentional: the file is
the campaign, and the app does not get to be the author of it. It is also why
revealing keeps the fence, and therefore the secret's id, its audit trail and
its revocability; deleting the fence instead would leave plaintext that could
never again be hidden, audited or revoked.

Every change is recorded. `/admin/secrets`, for game masters and administrators,
shows who revealed or hid what and when. It deliberately carries no title, no
author, no length and no body, because the data behind it holds none of those
either.

If the file changed on disk between the moment the app read it and the moment it
wrote, the change is refused and nothing is written. Refresh and try again.

## Attachments

Put images and other files in your vault beside the pages, however you like, and
reference them with the ordinary Markdown image syntax. The app records which
page referenced which file, and serves it through a page-scoped URL.

**A file referenced only from inside a secret is served only to readers of that
secret.** There is deliberately no global "attachments by name" route, because
such a route would have to answer that question without knowing which page a
name came from, and the only answer it could give is yes. A player asking for a
file that lives inside a hidden fence gets the same answer as for a file that
does not exist.

One honest caveat. The indexer currently records a page row for every file in
the vault, including images, and a page has no visibility — so a file referenced
only from inside a secret can have its **filename** appear in the campaign
status panel, which is a small metadata disclosure rather than a broken control.
The file itself is not served, and the reference renders as the hidden box. This
is a known, recorded, unfixed finding rather than an accepted design, and it is
written up in [`spec.md`](spec.md)'s divergences; the test that will fire when
it is fixed is named there.

## Editing a secret by hand

You can edit a fence's directive line in Obsidian, in a text editor, or through
the app's own editor. Two rules, both of which are the same rule twice:

1. **Keep the five keys.** A sixth hides the fence from everyone, the game
   master included — which is the worst possible outcome for a document you were
   trying to hide from somebody else.
2. **Keep the quoting.** An unquoted value with a space is the same failure
   wearing a different hat.

**When a fence breaks, the page tells you.** The page's **Problems** list names
each fence whose directive could not be read and says in a plain sentence what
was wrong with it, and the editor shows the same list. That list is why the
failure is survivable: you find out immediately, on the page, rather than by
wondering next Thursday why a secret you wrote last month is not there.

The bundled sample campaign ships with a deliberately broken fence so you can
see exactly what this looks like — see below.

## What the bundled sample campaign demonstrates

A fresh vault is not empty. On the first boot the application writes a complete
written campaign into `Campaigns/Ashes of the Hollow Crown/` and never
overwrites a file that is already there, so the campaign is there to read,
click through and break before you have written anything of your own.

It is written as ordinary Markdown and is not special to this application. It
demonstrates:

- **A real campaign**, with pages of every type the app knows — characters, NPCs,
  places, factions, quests, maps, encounters, items, house rules, session logs —
  wired together with links and tags, including a map image served through the
  ordinary attachment path.
- **Every visibility**, so you can see the difference between a `table` secret,
  a `private` one, a `dm` one, and one whose author is a player.
- **A file referenced only from inside a secret** — a picture in a `dm` fence.
- **A deliberately broken fence**, on its own page, with the two mistakes that
  break one spelled out next to it, the fixed version shown beside it, and an
  explanation of why the app hides an unreadable directive instead of guessing
  at it. It is broken on purpose. Leave it broken if you like; the point is that
  you can see the failure before it happens to you.
- **Its own documentation.** The campaign contains a `README` page and a
  `Notes/Writing secrets` page that answer the same questions this document
  does, in the vault itself, where you will actually look.

Every secret in it names an author that does not exist yet, so every one of them
is hidden until you create the accounts the campaign names. That is the accounts
rule, demonstrated rather than described.

## Where the answers live

Three documents, and they are not equal:

- **The grammar on this page is a convenience.** The parser —
  `md.ParseFenceDirective` in
  [`../internal/md/secret.go`](../internal/md/secret.go) — is the
  specification, and if this page and it ever disagree, the parser is right and
  this page is a bug.
- **The campaign's `Notes/Writing secrets` page is the reference** for an
  author working in their vault. It is the fuller of the two campaign pages, it
  ships inside the vault where you are already looking, and it is linked from the
  campaign's own front page as *the* reference.
- **This document is the one meant to ship with the binary**, for a game master
  who has not extracted a vault yet or whose vault predates the bundled
  campaign. It is a copy, and a copy is the thing that goes stale; that is why it
  points at the parser rather than pretending to be one.

Nothing here describes a fence you can check from outside the application. What
is externally checkable is the account rule: `/setup` answers 404 once any
account exists, and the Problems list is on the page itself.

## Divergences

Three places where a reader of this document should go to the code instead:

1. **The key set, the quoting and the unquoted-value failure** are the parser's,
   not this page's. The parser is one implementation of one closed grammar
   precisely so that two descriptions of it cannot drift; this page is the second
   description, and it is the one that is more likely to be wrong.
2. **The account rule's consequences** — which is, a fence whose author does not
   exist is *absent from the index* rather than present and hidden — are the
   indexer's, in
   [`../internal/sync/author.go`](../internal/sync/author.go), and the reason
   for the retry after an account is created is in that file's own comment.
3. **This document now ships in the release archive, and the entry that used to
   carry it could not have worked.** `archives.files` in
   [`.goreleaser.yaml`](../.goreleaser.yaml) lists `LICENSE`, `README.md` and
   this file as plain strings. The entry that was there first was
   `src: docs/SECRETS.md` alongside an `if: exists` guard, and it was removed
   because the document did not exist *and* because `if` is not a field
   goreleaser v2's file entry has — the whole config failed to load. A guarded
   reference to a file the repository owns is how a release ships without its
   own documentation while still looking like one.
