---
type: note
title: Welcome to this vault
aliases: [Start Here, Reading Order]
tags: [hollow-crown, reference]
---

# Welcome to this vault

This is a vault of plain Markdown files. Everything you are reading is a `.md` file
in a folder, and the file is the thing — not a database row, not a copy the app
made of it. If you open this vault in [Obsidian](https://obsidian.md) or any text
editor, you have the whole campaign.

The app on top of it is an index and a viewer. It watches the folder, reads the
files, and serves them back with backlinks, search and a few things a folder of
Markdown cannot do on its own. It never rewrites your prose.

## Where things are

| Folder | What lives there |
|---|---|
| [[Overview]] | What this campaign is and how to run it. Read this second. |
| `People/Characters` | The four player characters, one page each. |
| `People/NPCs` | Everyone else the table will meet. |
| `Locations` | The places. Each one is a place, not a dungeon stat block. |
| `Factions` | The groups with an interest in the party. |
| `Quests` | What the party is trying to do, and what it costs. |
| `House Rules` | How this table plays, ten rules, all of them argued about. |
| `Maps` | Charts and what is on them. |
| `Encounters` | Set pieces, with the numbers the table needs. |
| `Items` | The things worth stealing. |
| `Sessions` | What happened, written down afterwards. |
| `Notes` | This page, and the housekeeping around it. |

## How the frontmatter works

Every page starts with a block of `key: value` pairs between `---` lines. It is
optional; a page without one is still a page, and it is a note.

```yaml
---
type: character
title: Thia Vantage
aliases: [Thia, The Cartwright]
tags: [party, rogue]
---
```

Only four keys mean anything to the app:

- **`type`** — what kind of page this is. The known values are `note` (the
  default, used when you leave it out), `character`, `rule`, `map`, `token`,
  `encounter`, `houserule` and `session`. `houserule` and `session` are
  conventions with no special viewer — they render as ordinary notes — and
  `character` and `rule` open a sheet. An unrecognised `type:` is treated as a
  note, so a typo costs you the sheet and nothing else.
- **`title`** — the page's display name. It is a **fallback**: if the page's body
  has a `# Heading` at the top, that heading is the title and this key is ignored.
  Put the real name in the heading. Use this key on a page with no heading of its
  own, or when the name should differ from the file name.
- **`aliases`** — other names the page answers to. `[[Thia]]` and `[[The Cartwright]]` and `[[people/characters/Thia Vantage]]` all reach the same page.
  This is the thing to use when a name is long and you do not want to type it.
- **`tags`** — free-form labels. Any page can carry any number. The app reads
  them for the campaign panel and the tag list; nothing is validated.

A character page also wants a few keys the 5e sheet reads: `name`, `class`,
`level`, `hp_max`, `ac` and `speed`. A house rule wants `system` so the rules
index can group it. A session log wants `date` and `session`, and the campaign
panel shows the newest one.

## How linking works

Write `[[Page Name]]` to link to a page by name, `[[Folder/Page Name]]` if you
want to be exact, and `[[Page Name|what to call it here]]` when the sentence
wants different words. A link to a heading is `[[Page Name#The Part You Mean]]`.

The app resolves a link by trying, in order: the exact vault-relative path, the
same path with `.md` on the end, the file's base name, then any alias, and
finally the same three case-insensitively. So `[[Thia Vantage]]` works from
anywhere in the vault even though the file is three folders down, and so does
`[[Thia]]` once the alias is there. The last step matters: a link that is
off by a capital somewhere still resolves, which is a courtesy to a human
typing and a nuisance to nobody.

A link that resolves to nothing is reported on the page, in the **Broken links**
list, and the page it came from keeps working. Nothing about a broken link
damages the file.

## Secrets

Some of what a game master writes is not for the table. That is what the
`secret` fence is for, and it is the reason this app exists. A secret block is a
region of an ordinary Markdown file that the app **hides** from anyone not
entitled to read it and **shows** in full to anyone who is. Nothing is moved out
of the file — the fence stays readable in Obsidian and in a text editor. What the
app controls is what it *serves*.

### The syntax

A secret is a fenced code block opened with three backticks. Everything after
them, on that same line, is the **directive** — the word `secret` and then the
keys — and it is the only line that matters. Shown here as a plain directive
line rather than a live fence, because the scanner that finds secret fences
reads every line in a file, not only the lines inside a Markdown fence:

```markdown
id=5d1f0a7c93e2 visibility=dm author=dungeonmaster created=2026-06-14T21:03:00Z title="The bell was rung by the town"
```

The key set is **closed**. Five keys, and no others:

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Twelve lowercase hex characters. Permanent identity. No two fences in the vault may share one. |
| `visibility` | no | `private` (the default), `dm`, or `table`. |
| `author` | yes | The username of the account that wrote it. |
| `created` | no | An RFC 3339 timestamp. |
| `title` | no | A label. Shown where a secret is listed. |

**Quote every value that contains a space.** `title=The bell` is not a title with
spaces: the value ends at the first space, and the remaining words are read as
further keys. Unknown keys make the directive unreadable, and an unreadable
directive is not treated as public — it is hidden from everybody, the game master
included. [[A fence that will not open]] is a worked example of exactly that, and
it ships in this vault on purpose.

An unrecognised `visibility` is treated as `private` and reported on the page,
so misspelling `dm` narrows a fence rather than widening it. `table` still means
*signed in*: a visitor who is not signed in does not get it, and gets the same
answer as for a secret they were never entitled to.

### Accounts, and why nothing is visible yet

**`author` is a username, and the username must belong to an account that
exists.** It is not a label and it is not cached anywhere.

This vault is new, so there are no accounts, so **every secret on it is hidden
from everybody** — the table and the game master alike. That is deliberate: a
secret whose author cannot be resolved is a secret nobody can be shown to be
entitled to, and the only safe answer to *who may read this?* when the answer is
*nobody knows* is *nobody*.

Create these three accounts and the fences open on the next reindex. Nothing in
the files needs editing.

| Username | Who | What they author |
|---|---|---|
| `dungeonmaster` | the game master | the DM secrets, the `table` clause text, most of the house rules |
| `thia` | a player | their character's own secret, and a house rule they wrote |
| `bram` | a player | — reserved, so the set is the one the app's own test vault uses |

### What the app does with a secret

- **Hiding is per-visibility, not per-page.** Hidden in the page view, in
  search, in backlinks, in the table of contents and in the campaign panel. There
  is no view that shows a reader a secret's title while withholding its body,
  because that is how a secret's existence leaks.
- **Hiding is not deleting.** The bytes are still in the file and still in the
  index; the app refuses to render a body it may not show.
- **Revealing is a file edit.** Changing a visibility rewrites that one
  `visibility=` token, byte-surgically, and touches nothing else. The file is the
  campaign and the app does not get to be the author of it.
- **A file referenced only from inside a secret is served only to readers of
  that secret.** A picture in a `dm` fence is not a file with a URL on it.
- **Old versions are re-checked at read time**, so a secret that was public
  before it was hidden does not stay readable through an old revision.

The full reference, including the exact failure modes and the page-level Problems
list, is [[Writing secrets]].
