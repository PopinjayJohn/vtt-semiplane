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

A LAN-hosted Obsidian-compatible wiki for a tabletop campaign. Authorization is
per-user: a DM writes hidden `private`, `dm` and `table` secret blocks into
ordinary Markdown, and a reader sees the page without the bodies they are not
entitled to. What is withheld is the *secret body* — a page is a file, and any
reader who may read public content may open it and follow its links.

## Build

```bash
make setup     # modules, pinned tools, templ generate
make build     # static binary in dist/semiplane
make check     # the CI gate; AGENTS.md §9 lists what it runs
```

Go 1.26+ is required. `CGO_ENABLED=0` produces a genuinely static binary:
SQLite is `modernc.org/sqlite`, the SQLite driver is pure Go.

## Run

```bash
./dist/semiplane --vault ./vault
```

First boot creates the vault `0700`, takes an exclusive single-instance lock,
extracts the bundled sample campaign without overwriting a file that is already
there — the walk re-checks on every boot rather than remembering that it ran —
and prints the resolved vault path, listen address, the vault directory's own
name, the indexed page count and how many plugins registered. Then open the URL
and claim the first admin account at `/setup` — that route answers 404 once an
admin exists, so it is not confirmable from outside.

To serve the LAN, pass `--host 0.0.0.0` deliberately. The default is
`127.0.0.1` because the vault holds plaintext DM secrets and guest wifi is not
a trusted network.

## Status

A working campaign server: a vault, an index, accounts, and a per-user
authorization model over secret blocks in ordinary Markdown. Read, edit, reveal
and revoke are all in; the map and dice surfaces are not. What exists and what
does not is [`docs/README.md`](docs/README.md), and the design is
[`docs/spec.md`](docs/spec.md).

## Security notes

- Secrets are **plaintext in Markdown** on disk. The protection is filesystem
  permissions (`0700` vault, `0600` database and backups) plus server-side
  authorization, not encryption. A stolen disk is a full compromise. This is a
  deliberate decision, recorded in ADR-0004.
- There are no outbound network calls at runtime. No telemetry, no CDN, no
  analytics. A test enforces it.
- Plugins are first-party Go code compiled into the binary. There is no sandbox
  and no isolation. `AGENTS.md` §7 and
  [`docs/PLUGIN_AUTHORING.md`](docs/PLUGIN_AUTHORING.md) say what the boundary
  does and does not enforce.

## License

MIT. See `LICENSE`.
