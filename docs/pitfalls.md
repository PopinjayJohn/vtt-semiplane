# Pitfalls

Traps that have already cost time in this repository, and the reason each one
bites. Read this before running anything: three of the four failures below
present as a silent hang or a silent kill, not as an error message.

## `go test ./...` will exhaust this machine

`go test ./...` links and runs one test binary per package, up to `-p`, which
defaults to `NumCPU`. Every package that pulls in `modernc.org/sqlite` links a
very large pure-Go libc. Four packages at once on a 23 GiB machine exhausted
RAM *and* the zram swap, and the session died with no useful error — the runner
is killed, not the test.

```bash
./scripts/test.sh                          # every package, bounded
./scripts/test.sh ./internal/md/           # one package
./scripts/test.sh -race ./internal/sync/   # the race detector
./scripts/test.sh -fuzz=FuzzNeverCorrupt -fuzztime 30s ./internal/md/
```

`scripts/test.sh` pins `-p 1`, bounds subtest parallelism with `-parallel`,
sets `GOMEMLIMIT=3GiB` and `GOGC=50`, and gives every test a timeout. It is
wired into `make test`, `test-race`, `cover`, `fuzz` and all three CI test jobs.
The link step is what bites, not the run step — that is why `-p 1` is the
setting that matters.

## A spinner is a memory leak that never reports itself

Two infinite loops shipped in the Markdown pipeline, and both had the same
shape: a branch that recognised a token and then **failed to move the read
cursor**. Neither hung quietly. Each spun *while appending*, so it presented as
a slow test and read as a memory leak.

1. `commentParser.Parse` — an unterminated `%%` comment restored the reader
   position and returned nil, so goldmark re-entered on the same bytes and
   appended to the block buffer. A 24-byte fixture reached 8 GiB. The EOF guard
   could not have saved it either: `text.Reader.Position()` returns
   `(line, segment)`, not a byte offset, and `PeekLine` past the last line
   returns a **live** segment, so `seg.Stop >= len(src)` was unreachable.
2. `segmentBody` — only the `default` branch of its switch advanced the cursor.
   The bad-directive and unknown-key branches appended a `Problem` and re-read
   the same fence forever.

**Every `for` over a byte range or a slice needs an explicit progress
assertion**, and any branch that records a problem must still move the cursor.
`segmentBody` now carries `if next <= pos { break }` as a standing assertion.
A parser that makes no progress is how a 24-byte file eats a machine.

## `make css` needs a local filesystem

The Tailwind v4 scanner takes about a second on local disk and **exceeds four
minutes anywhere under `/mnt/gamedrive`**, with identical binary, input and
component files. It is the mount's filesystem walk, not the CSS: narrowing the
`@source` globs did not help, and neither did building in a temp directory. The
decisive test is to run the same command in `/tmp` and in the repo.

`web/static/app.css` is committed and is the artefact of record.
`.tools/tailwindcss` is a fast-failing stub on this machine and the real binary
sits beside it as `tailwindcss.real`. CI runs on a local filesystem and is
unaffected. If you must regenerate here, copy the sources to `/tmp`, build, and
copy the single output file back.

Keep the `@source` list in `web/src/input.css` explicit rather than pointing at
`internal/`. It is on `internal/md/*.go` because the renderers emit class
attributes for passthrough blocks, callouts and mermaid from Go — dropping that
line silently removes those classes on the next rebuild. Narrowing it to the
`.templ` files alone once did exactly that.

## A background process still holds the tool call open

`nohup … & disown` detaches from the shell's **job table**, not from the
**process group**, so the harness waits on the child and the call stays open for
as long as the process lives. A dev server started that way blocks a turn
indefendibly, and a board message will not interrupt it.

```bash
timeout 20 ./semiplane --vault /tmp/v --port 8139 --no-open >/tmp/serve.log 2>&1 &
SRV=$!
sleep 2
curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8139/setup
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
```

`curl --max-time` on every probe, so a request that hangs fails in five seconds
rather than blocking the call.

## The single-instance lock will refuse a second process

Only one process may hold a vault. The lock is taken on
`.semiplane/semiplane.lock` **before any file or database is opened**, and the
refusal names the holding pid. Two consequences worth knowing:

- Killing a server with `kill` on a `timeout` wrapper can leave the real
  process alive, and the next boot then fails with `vault is already open by
  another semiplane process`. `pkill -f "semiplane --vault /path"` before
  restarting.
- Because the lock is taken first, a boot that fails afterwards must release it,
  or the vault stays wedged until the OS reclaims it. `app.Boot` runs
  `Shutdown` on a `defer` for exactly this reason.

## One unreadable file must not stop the app

`indexOne` degrades gracefully for a missing file, a directory and an oversize
file. It once did not for a **permission** failure: the raw read error propagated
through `IndexBatch`, and the boot walk is a single batch, so one `chmod 000` on
one file stopped the app from starting. A denial of service created by one mode
bit, and it inverted the rule that unreadable files are warnings in the sync
panel. If you add a failure path to the indexer, ask what an unauthenticated or
unprivileged user can trigger with it, and make the answer a recorded `Problem`
rather than a returned error.

## Two things that will be fine until they are not

- **A full reindex drops `page_owners` and every revision**, because
  `RemoveMissing(nil)` cascades from `pages`. Harmless today because nothing
  populates `page_owners`; the moment ownership exists a rebuild will silently
  drop it, and ownership is an authorization input. Decide before any page gets
  an owner.
- **The unresolved-author retry is in-memory.** The boot call closes the warm
  restart case; the call that closes first boot is next to account creation in
  `internal/httpapi`. A secret fence naming an account that did not exist at
  index time is shown to nobody — fail-closed, never a leak — but it stays
  invisible until a full reindex if that second call is missing.

## Tooling that has never run here

`make lint` — golangci-lint is not installed on this machine and is not
fetchable. CI runs it. The gates that do work here are `go build ./...`,
`go vet ./...`, `gofmt -l .`, `go tool templ generate ./...` reporting
`updates=0`, and `./scripts/test.sh`. Do not report lint as passing.
