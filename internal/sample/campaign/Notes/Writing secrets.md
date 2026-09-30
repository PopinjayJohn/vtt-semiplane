---
type: note
title: Writing secrets
aliases: [Secret fences, The fence syntax, Fences]
tags: [hollow-crown, secrets, reference]
---

# Writing secrets

A game master writes two different campaigns at once: the one the table plays,
and the one that is true. A stat block for a villain's private motive, the real
name of the traitor, the map with the room circled on it — that second campaign
is in the same folder as the first, in the same plain text, in files a player
with a file browser can read.

This is what the `secret` fence is for. A secret block is a region of an ordinary
Markdown file that the app **hides** from anyone not entitled to read it, and
**shows** in full to anyone who is. Nothing is moved out of the file. The file
stays where it is, with all of its bytes, and the fence stays readable in Obsidian
and in a text editor. What the app controls is what it *serves*.

> [!warning] This is a demonstration vault, freshly extracted
> Every secret on this vault names an author that does not exist yet, because the
> vault is new and no account has been created. An author that does not resolve
> means the fence is hidden from **everybody, including the game master** — see
> [Accounts](#accounts) below. Create the three accounts and reindex, and the
> table sees exactly the set of secrets described in the campaign overview and
> nothing else.

## The syntax

A secret is a fenced code block opened and closed with three backticks, exactly
like any other fence in Markdown. Everything after the opening backticks — on
that same line — is the **directive**: the word `secret`, and then the keys. It
is the only line that matters, and a directive written on the *following* line
is not read at all, which leaves the fence dark rather than open. Written out
here as a plain directive line so that this page does not itself contain a
secret:

```markdown
id=4e5b8c2a17f39 visibility=private author=dungeonmaster created=2026-06-14T21:03:00Z title="The ferryman's real cargo"
```

The body is ordinary Markdown. It can have headings, lists, tables and links in
it, and the app extracts all of them — attributed to this secret, so they never
appear in a search result or a backlink for a reader who may not see this.

> [!tip] Writing an example of a fence
> Do not write out the triple backticks around a sample `secret` directive, even
> inside a longer code block. The scanner that finds secret fences reads every
> line in the file rather than only the lines inside a Markdown fence, so a
> sample spelled with real backticks becomes a **real, empty secret** on the page
> — withheld from every reader, and reported in the editor's Problems list as a directive with no
> body. Show the directive line on its own, as above. That is the only reason
> this page has no live fence in it.

### The five keys

The key set is **closed**. These five, and no others:

| Key | Required | What it means |
|---|---|---|
| `id` | yes | Twelve lowercase hexadecimal characters. A fence's identity, permanently. |
| `visibility` | no | `private` (the default), `dm`, or `table`. |
| `author` | yes | The username of the account that wrote it. |
| `created` | no | An RFC 3339 timestamp, e.g. `2026-06-14T21:03:00Z`. |
| `title` | no | A label for the secret. Shown where a secret is listed. |

**Any sixth key makes the whole directive unreadable**, and an unreadable
directive is not treated as a formatting problem to shrug at. It is treated as
*this fence claims to be secret and could not be proven to say what it claims*,
and the fence is hidden from everyone. See
[[A fence that will not open]] for what that looks like and how it is fixed.

### Quote anything with a space in it

This is the single most common way to break a fence, and it breaks it in a way
that is quiet:

```markdown
title=The ferryman's real cargo
```

That is not a title with spaces. The value of `title` ends at the first space,
so the parser reads `title=The`, then `ferryman's`, then `real`, then `cargo` as
three more keys it does not recognise. Three unknown keys make the directive
unreadable, and the fence goes dark.

**Quote every value that contains a space.** Either kind of quote works:

```markdown
title="The ferryman's real cargo"
title='The ferryman\'s real cargo'
```

A value that contains **its own quote character** needs a backslash in front of
it, because a backslash is the only escape there is. `title='The ferryman\'s
real cargo'` is one value; writing the quote twice instead, the way a
spreadsheet would, closes the value at the first of them and leaves the title as
`The ferryman` with three unknown keys behind it — which darkens the fence just
as thoroughly as forgetting the quotes.

A value with no space needs no quotes: `visibility=dm`, `author=dungeonmaster`.

### The `id`

Exactly twelve lowercase hex characters, and **no two fences in the vault may
share one**. A duplicate is refused: the second fence keeps its own text but is
not treated as a well-formed secret, because the app cannot tell which of the two
was meant. The id is how a secret is referred to in a reveal or a revoke, and it
does not change if you edit the body, the title, or the visibility.

To invent one, take twelve hex characters from anywhere — a clock, a hash, a
roll. `md5sum` of the file's own name is plenty:

```sh
printf '%s' "the ferryman's real cargo" | md5sum
```

### The `visibility`

Three values, and the one that is missing is the safe one.

- **`private`** — the default. The author, the game master, any administrator,
  and the owners of the page the secret sits on. Nobody else. This is what you
  want for a player's own secret, a thing one character knows, or anything the
  table must not read.
- **`dm`** — game masters and administrators only. Not the page's owners, not
  the author if the author is a player. This is the "true motive of the villain"
  visibility: a game master who writes a secret for themselves can put it on a
  page the players own and it still will not appear on their screen.
- **`table`** — everyone who is signed in, and nobody who is not. This is the
  one to reach for when the secret is not a secret any more: a reveal a game
  master has decided to make, an ambiguity the whole table is allowed to
  disagree about, a piece of text the table is meant to read aloud.

An unrecognised value is treated as `private` and reported on the page as an
invalid visibility. Misspelling `dm` as `dms` does not widen the fence; it
narrows it, and it says so.

> [!important] `table` still means *signed in*
> A `table` secret is not public. A visitor who is not signed in does not get it,
> and does not get a page saying they may not have it either — the request fails
> exactly as it would for a secret they are not entitled to, so the response
> cannot be used to find out whether a particular secret exists.

## Accounts

**`author` is a username, and the username has to belong to an account that
actually exists.** This is not a formality and it is not cached anywhere.

On a brand-new vault there are no accounts, so every fence on this campaign is
hidden from everybody — the table and the game master alike. That is deliberate.
A secret whose author cannot be resolved is a secret nobody can be shown to be
entitled to, and the only safe answer to *who is entitled to this?* when the
answer is *nobody knows* is *nobody*.

Once the accounts exist the fences come back, on the next reindex. Nothing in
the files needs editing; the author name was always right, the index just could
not resolve it before.

This vault uses three usernames, and they are the same three the app's own test
vault uses:

| Username | Who | What they author |
|---|---|---|
| `dungeonmaster` | the game master | most of the table's secrets, all the DM material |
| `thia` | a player | their character's own secret, and two table rules they argued for |
| `bram` | a player | a house rule about their own character's death |

Create those three accounts, then reindex. The campaign overview lists the set
of secrets that becomes visible, which is how you can check the result.

## What the app does with a secret

- **Hiding is per-visibility, not per-page.** A secret is hidden in the page
  view, in search results, in backlinks, in the table of contents, and in the
  campaign status panel. There is no view that shows a player a secret's title
  while withholding its body, because that is how a secret's existence leaks.
- **Hiding is not deleting.** A hidden secret is still in the file, still in the
  index, and still counted. The app refuses to render a body it may not show, and
  leaves the bytes where they are.
- **Revealing is a file edit, not a database flag.** Changing a secret's
  visibility rewrites the `visibility=` token inside that one fence's directive
  line, byte-surgically, and touches nothing else in the file. The Markdown you
  wrote stays the Markdown you wrote — no reflow, no reformatting, no
  normalisation. The file is the campaign; the app does not get to be the author
  of it.
- **A file referenced only from inside a secret is served only to readers of
  that secret.** An image in a DM-only fence is not a picture with a URL on it;
  it is a page-scoped reference, and a player asking for it gets the same answer
  as for a file that does not exist. See [[The Greywake Basin]] for a chart with a picture on it, which is the same question answered differently.
- **Older versions of a page are re-checked.** A secret that was public before
  the game master hid it does not stay readable through an old revision. The
  revision is re-segmented and re-authorised at the moment it is read, against
  the reader asking right now.

## Editing a secret by hand

A secret's directive line is plain text and you may edit it in Obsidian, in a
text editor, or through the app's own editor. Two rules:

1. **Keep the five keys.** A sixth makes the fence unreadable and hides it from
   everyone — the game master included, which is the worst possible outcome for
   a document you were trying to hide from somebody else.
2. **Keep the quoting.** An unquoted value with a space is the same failure
   wearing a different hat.

If you break a fence and the block goes dark, the page tells you. The
**Problems** list names the fence and what was wrong with its directive. That list is the reason the failure is survivable: you find out
immediately, and you find out on the page rather than by wondering why a secret
you wrote last month is not there any more.

See [[A fence that will not open]] for a worked example, which ships in this
vault on purpose.
