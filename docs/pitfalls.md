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

**A flag that takes a value has to push that value onto the extra-args list, and
`-fuzz` did not.** It set a mode flag and discarded the target name, so the
target fell through to the package list and the script died with "takes exactly
one package" for the package it had been given. The fix is one line in
`scripts/test.sh`; the reason it is written down is that a correctly typed
invocation reported a *usage* error about an argument that was there, which reads
as the caller's mistake and is not. The fix is in `scripts/test.sh`.

## A test can fail a security gate by naming a variable

`TestEveryQueryUsesBindParameters` fails any line containing `Sprintf` **and** a
SQL verb word — and `where` is one of the words in that pattern. So a test local
called `where`, on a line that also formats a string, trips a gate about
interpolating a value into a query, in a file that has no query. It scans test
files too; only `architecture_test.go` is exempt.

The failure names a line in a test about nothing, and the honest reaction —
"that is a false positive" — is the trap. Name it `sites`, or `at`. The
generalisable form is the one `AGENTS.md` §11 keeps arriving at from several
directions: **a gate that can fire for a reason unrelated to what it is guarding
is a gate whose failures have to be argued rather than read**, and a reader who
argues one away is one reader closer to arguing away a real one.

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

## `source(none)` on the Tailwind import is load-bearing

Tailwind's automatic source detection walks the project root looking for
candidate class names. In this repository that walk reads
`internal/md/testdata`, whose largest fixture is a megabyte of wikilinks on a
single unbroken line, and a line that long is pathological for candidate
scanning.

**The cost is CPU, not the filesystem, and this repository got that wrong for a
while.** The build finished all of its reads within seconds and then sat at
100% CPU with zero further I/O; the same symptom was recorded here as a
`/mnt/gamedrive` mount problem, which was wrong. It reproduces identically on
tmpfs, and the same command with `source(none)` finishes in ~70 ms both in the
repo and in `/tmp`. A build that reads like it is stuck is this bug, not a slow
mount — check it with `strace -c` or `/proc/<pid>/io` before looking anywhere
else.

The fix is one token:

```css
@import "tailwindcss" source(none);
@source "../../internal/web/*.templ";
@source "../../internal/web/*.go";
@source "../../internal/md/*.go";
@source "../../web/static/app.js";
```

`source(none)` turns automatic detection off entirely and the explicit list
supplies the candidates. Narrowing the `@source` list alone does *not* fix it —
the walk still happens, it just collects less. If the build ever hangs again,
check that `source(none)` is still on the import before looking at anything
else.

Two things the explicit list must keep:

- **`internal/md/*.go` is on it because the renderers emit class attributes from
  Go** — `passthrough`, `callout`, `mermaid`, `secret-locked`. Dropping that
  line silently removes those rules on the next rebuild, and nothing fails: the
  build is clean, the CSS is just wrong.
- **`web/static/app.css` is the artefact of record** and is committed. Never
  hand-edit it; run `make css`. `css-check` in CI regenerates and diffs it, so
  a build that cannot run locally is a build that fails only in CI.

The trap has a second shape, and it is invisible from Go: **the scan surface and
the rule surface are different sets.** A class nothing on the `@source` list
mentions renders unstyled; so does a class that *is* scanned but has no rule
behind it. Three components carried `class="card"` for a long time with nothing
in `input.css` matching it, so they rendered as unframed divs and no build, no
test and no lint said so. `.card` has a rule now; the way to catch the next one
is to grep the templates for a class and grep `input.css` for it, because
nothing in the Go toolchain will.

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

## A `templ`/`DataStar` pair that looks wired and is not

Two of stage 2's integrations were built against a vendored DataStar bundle
(v1.0.4, in `web/static/vendor/`) and were silently wrong. Both fail *quietly*:
the element is never replaced, nothing is logged, and the feature simply does
nothing.

- **An `application/json` response is a signals patch, not a render.** The bundle
  branches on the response content type before anything else and dispatches
  `datastar-patch-signals`, merging the body into the reactive signal store. A
  command palette returning its rows as JSON therefore did not render a palette
  — it wrote every matched page's *title* into the document's signal state,
  where any signal expression can read it.
- **`datastar-patch-elements` cannot be written from outside with confidence.**
  Its reader joins every `data:` line of the SSE frame into one message with a
  **space**, then splits that message on newlines. A frame of three `data:` lines
  therefore arrives as a single field named `selector` whose value is the rest of
  the frame, and the client patches with the string ` mode inner elements
  <section…`. There is no header-based targeting in 1.0 either —
  `datastar-selector` and `datastar-mode` do not exist in this bundle at all.

The command palette therefore uses a plain `fetch` and a `DOMParser`
(`web/static/app.js`, `wireTypeaheads`), against a `?fragment=1` query parameter
the server answers with `text/html`. The bytes still come from the same templ
component through the same authorized handler under the same principal; only the
envelope is ours, and the envelope is the part that is guesswork. The reasoning
lives at the top of `internal/httpapi/datastar.go` and
`TestTheVendoredDataStarStillRoutesJSONToSignals` fails if a dependency bump
removes the branch that motivated it.

The general lesson is the one this repository has already paid for twice: a
contract you cannot verify from the outside is a contract you have guessed, and a
guessed contract that only fails by not happening is the most expensive kind.

## `gofmt` does not run on `.templ`, and a stray tab silently breaks generation

A `templ` file's declarations belong at column 0. One tab in front of a single
`templ` declaration makes `templ generate` fail with a Go parser error reading
`expected declaration, found templ` — a message that points at Go syntax inside a
file that is not Go, and at a line number that has nothing to do with the cause.

Two habits that would have caught it:

- **`gofmt -l .` covers `.go` only.** A `.templ` file is not valid Go, so gofmt
  leaves it alone and reports nothing, clean or not. `make fmt-check` is the gate
  for those, and it is `go tool templ fmt -fail .`.
- **`templ fmt` is the formatter, and it is not `templ fmt -check`.** v0.3.1020
  spells it `-fail`. The old `fmt-check` used `-check`, which printed a usage
  error to stderr for every file it was handed; the shell test then read that
  output as "unformatted templ" and the gate was red on a clean tree for a reason
  nobody could see.

## A document must not describe what the code already owns — but a finding is not a fact

Stage 2 produced two findings that are worth recording because they are *not*
things a reader of the code would find:

- `TestNoOutboundNetwork` refused `http.NewRequestWithContext` in
  `internal/httpapi/events.go`, where it builds a synthetic request to call the
  ordinary handler with a subscriber's captured principal. The grep was
  over-broad: a request constructor is not a client. Rather than delete the
  symbol from the list, the exemption is granted **per file** and held by
  `TestSyntheticRequestFilesAreStillOnlySynthetic`, which requires the file to
  name the RFC 2606 reserved host `push.invalid` and to contain no client symbol
  at all.
- The matrix row for `GET /tag/{name}` on a tag nobody carries expects **200 with
  no rows, not 404**. A 404 would tell a reader without rights to the tag's pages
  that the tag does not exist, which is a statement about the campaign they are
  not entitled to.

## `make lint` cannot run on this machine's Go toolchain

Two separate problems, and only the first one is worth remembering.

The obvious one: `make lint` runs `golangci-lint` from `$(go env GOPATH)/bin`,
which is **not on `PATH` by default**, so it fails with `command not found` on a
healthy tree.

The one that does not have a workaround: the **pinned version cannot parse this
module at all**. `GOLANGCI_LINT_VERSION=2.5.0` in
[`../tools/versions.env`](../tools/versions.env) is built with go1.25 and
refuses a module whose `go` directive is 1.26 ("the Go language version used to
build golangci-lint is lower than the targeted Go version"), and lowering
`run.go` to get past that then panics in `go/types`. The `go` directive is 1.26
because templ v0.3.1020 requires it, so this is a circular pin rather than a
configuration mistake: it needs a newer golangci-lint in `tools/versions.env`,
not a flag.

CI runs it, so a red lint there is a real finding. The gates that do work here
are `go build ./...`, `go vet ./...`, `gofmt -l .`, `go tool templ generate
./...` reporting `updates=0`, `go tool templ fmt -fail .`, and
`./scripts/test.sh`. **Do not report lint as passing when it did not run.**

