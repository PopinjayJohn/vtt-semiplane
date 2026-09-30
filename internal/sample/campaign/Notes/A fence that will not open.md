---
type: note
title: A fence that will not open
aliases: [Broken Fence, Malformed Fence, The Malformed One]
tags: [hollow-crown, secrets, reference]
---

# A fence that will not open

This page ships a **deliberately broken** secret block, at the bottom, on
purpose, so that the failure mode described in [[Writing secrets]] is something
you can look at rather than something you have to imagine.

When you first boot this vault, every fence on this page is closed, because no
account exists yet and a fence names an author who is not there. Create the three
accounts and reindex, and the healthy fences open. The broken one does not, and
this page tells you why.

> [!tip] How to read what follows
> The directive is shown here as a **plain line**, not as a fenced block. That is
> not a stylistic choice: the scanner that finds secret fences reads every line
> in a file, not only the lines inside a Markdown fence, so a sample written
> with real triple backticks becomes a real, empty secret. See
> [[Writing secrets]].

## What is wrong with it

The fence at the bottom of this page carries this directive:

```markdown
id=5d1f0a7c93e2 visibility=dm author=dungeonmaster created=2026-08-02T23:40:00Z title=The bell was rung by the town expires=never
```

Count the keys: `id`, `visibility`, `author`, `created`, `title`, and then
**`expires`**. The key set is closed. `expires` is not one of the five, so the
directive cannot be read, and a directive that cannot be read is not treated as
public. It is treated as a fence that *claims* secrecy and cannot prove it says
what it claims, and its body is withheld from **everybody**:

- not from the table — the point of it;
- not from the page's owners;
- not from the game master.

What you *can* see is that a fence is there: the page shows a locked box in its
place, because a lock has to be visible for "there is a secret here" to mean
anything. That is the whole of it — the body is not rendered to anyone, and it is
not in the page's HTML, so there is nothing to read out of the page source
either.

The author name is still in the file, and the id is still in the file, and the
body is still in the file. Nothing has been deleted or moved. The fence is
closed because the app could not establish what closing it means.

## The second thing that is wrong with it

`title=The bell was rung by the town` is **unquoted**, and it contains spaces.
So the value of `title` is `The`, and the words `bell`, `was`, `rung`, `by`,
`the` and `town` are each read as a further directive key — six more unknown
keys stacked on top of `expires`.

This is the mistake that costs the most, because it is invisible. The fence
still *looks* right. The line is one line, the keys are lowercase, the values
look like values. But `title` is now `The`, and a fence with a one-word title
called `The` tells you nothing about which of a hundred fences on a page you are
looking at.

## The fix

Quote the value, and delete the key that does not exist. Six keys become five,
one quoted value, and the fence opens on the next reindex:

```markdown
id=5d1f0a7c93e2 visibility=dm author=dungeonmaster created=2026-08-02T23:40:00Z title="The bell was rung by the town"
```

## Why this is in the vault

Because the alternative is a game master discovering this at 11pm the night
before a session, with a secret they cannot see, in a file they wrote themselves
and have not touched in three weeks. The failure is not a crash and it is not a
leak. It is *nothing happening*, and nothing happening is the hardest kind of
bug to notice from the inside.

The app's answer to it is the **Problems** list at the top of the **editor** for
this page. Every fence whose directive cannot be read is reported there, naming
the fence and saying in a plain sentence what was wrong with the directive. It
is in the editor rather than on the rendered page because a problem is a
statement about a file, and everyone who can open this page can already see that
there is a locked box on it — while the editor is the place a person goes
precisely to change what is wrong with a file, and a report they have to go
somewhere else to read is a report they will not have seen.

> [!note] One fence, two faults
> A fence may be unreadable for more than one reason at once. The one at the
> bottom of this page has both an unknown key and an unquoted value, deliberately,
> so that the report is worth reading. Fixing either one alone will not open it.

## What a healthy fence looks like

For comparison, the `table` secret on [[The Ninefold Oath]] is well formed: five
keys, a quoted title, a twelve-hex id, and an author that resolves once the
account exists. When the accounts are made and the vault reindexed, that fence
opens for every signed-in reader and this one still does not.

## Links

- The syntax: [[Writing secrets]].
- The secret it was written for, once it is fixed, is the finding of the session
  in [[Session Zero - The Wetting]] — the bell that rang and had no cause.

<!-- The fence below is the demonstration. It is deliberately malformed. -->

```secret id=5d1f0a7c93e2 visibility=dm author=dungeonmaster created=2026-08-02T23:40:00Z title=The bell was rung by the town expires=never
The bell on the eighth waymarker was not struck by a hand.

It was struck from underneath, from the reading room, by the Compact's own
tide-gauge, which had been sounding the third bell every high water since the
crown broke because nobody thought to stop it. Pell Ammond came down off the
hills at 21:00 to find out why the eighth marker was going and took the bell off
it in the dark, and the fourth bell rang on the same note, and he took that one
too, and neither of the two men who went out with him wrote down which.

Nine years later a party that has read this page knows more about the third bell
than the fen-watch file ever did, and the fen-watch file is the only other
account of it in existence.
```
