# vtt-semiplane

A TTRPG wiki and player+DM tools for creating and running campaigns.
One binary, one vault, no network calls at runtime.

## The one rule

**The Markdown file is canonical. Everything else is derived.**

SQLite is a cache that can be deleted at any moment and rebuilt from the vault.
Nothing that matters lives only in the database, and nothing is ever written
back to a file except through `vault.Writer`, which is hash-checked and
byte-preserving. See `AGENTS.md` for the full contract and
`docs/ARCHITECTURE.md` for the package graph.

## What it is

A LAN-hosted Obsidian-compatible wiki for a tabletop campaign, with a
per-user authorization model: a DM writes hidden `private`, `dm` and `table`
secret blocks into ordinary Markdown, a player sees the page without them, and
a wikilink to a hidden page still resolves without revealing anything.

## Build

```bash
make setup     # modules, pinned tools, templ generate
make build     # static binary in dist/semiplane
make check     # the CI gate: fmt, generate, css, lint, test
```

Go 1.26+ is required. `CGO_ENABLED=0` produces a genuinely static binary:
SQLite is `modernc.org/sqlite`, the SQLite driver is pure Go.

## Run

```bash
./dist/semiplane --vault ./vault
```

First boot creates the vault `0700`, extracts the sample campaign without
overwriting anything, takes an exclusive single-instance lock, and prints the
resolved vault path, listen address, campaign name, indexed page count and the
plugin boot report. Then open the URL and claim the admin account at `/setup`.

To serve the LAN, pass `--host 0.0.0.0` deliberately. The default is
`127.0.0.1` because the vault holds plaintext DM secrets and guest wifi is not
a trusted network.

## Status

Stage 1 of the implementation plan: a binary that boots, locks the vault,
indexes Markdown, authenticates a user, and serves a page with a backlink.

## Security notes

- Secrets are **plaintext in Markdown** on disk. The protection is filesystem
  permissions (`0700` vault, `0600` database and backups) plus server-side
  authorization, not encryption. A stolen disk is a full compromise. This is a
  deliberate decision, recorded in ADR-0004.
- There are no outbound network calls at runtime. No telemetry, no CDN, no
  analytics. A test enforces it.
- Plugins are first-party Go code compiled into the binary. There is no sandbox
  and no isolation; see `AGENTS.md` §11 of the plan for what is and is not
  enforced.

## License

MIT. See `LICENSE`.
