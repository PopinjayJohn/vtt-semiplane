# ADR-0002: Pure-Go SQLite

Status: accepted · Date: 2026-09-28

## Context

The application is a single static binary per platform, cross-compiled for five
targets including Windows, that a DM can download and run from a thumb drive
with no runtime present. That is the deployment promise: a LAN wiki a group
actually uses, not a service someone has to operate.

`github.com/mattn/go-sqlite3` is the default Go SQLite driver and is faster.
It is also cgo, which means one thing at a time: either a C toolchain on every
build machine, a prebuilt static library per platform, or a dynamic dependency
on the user's machine. It also needs per-platform build tags to get FTS5
compiled in.

## Decision

`modernc.org/sqlite`, with `CGO_ENABLED=0`.

- `WAL` journalling, so a reindex does not block reads.
- A write pool with `SetMaxOpenConns(1)` and a separate read pool with
  `N = NumCPU` in `mode=ro`.
- `foreign_keys=ON` so `ON DELETE CASCADE` actually fires — it is off by default
  in SQLite, which would turn every cascade in the schema into a no-op.
- `trusted_schema=0`, which blocks functions in schema definitions.
- `busy_timeout=5000` rather than failing the first concurrent writer.

FTS5 is bundled in the driver, so the search design needs no build flag.

## Consequences

- **The cost is real and measured, not assumed.** Pure-Go SQLite is expected to
  be 2–5× slower than cgo SQLite. `BenchmarkIndex1kPages` and
  `BenchmarkSearch1kPages` exist to put a number on it. The budget is p99 page
  render under 50 ms and search under 20 ms on a 2,000-page vault; if that
  fails, the first levers are prepared statements and the connection split, not
  switching drivers. Switching to cgo would forfeit the static-binary promise,
  which is the product.
- **A version footgun ships with the driver.** `modernc.org/sqlite` requires the
  exact same `modernc.org/libc` version in our `go.mod` as in its own. Bump one
  and not the other and the build fails in a way that reads like a compiler bug.
  It is in `AGENTS.md` §11 and in the CI gate list.
- The dependency tree is large. That is a supply-chain cost accepted in exchange
  for no cgo, mitigated by `govulncheck`, `osv-scanner`, `trivy`, CodeQL and
  dependabot in CI.
- Windows and macOS builds are the real test of the claim. `make cross` builds
  all five and `TestNoDynamicDependencies` asserts the artifact is not a dynamic
  executable.
