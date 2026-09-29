#!/usr/bin/env bash
# Boot the real binary against a generated 2000-page vault and measure the two
# routes the P12 budget names: GET /p/… and GET /api/search.
#
#   scripts/loadtest.sh [--pages N] [--requests N] [--concurrency N] [--path URL]
#
# **This is a report, not a gate, and that is the decision rather than the
# absence of one.** The P12 accept is "p99 page render under 50 ms and search
# under 20 ms on a 2k-page vault", and a gate for it would have to be a number
# that a machine other than the one that measured it can be held to. A GitHub
# hosted runner is a shared vCPU: the same binary on the same vault measures
# anywhere from 1.5x to 4x the p99 depending on what else the host is doing, so a
# threshold written from one observation is a coin flip that fails a build for a
# reason that has nothing to do with the code. A flaky gate is worse than no
# gate, because the first thing a team does with a flaky gate is retry it, and
# the second thing it does is stop reading it. So this prints the distribution,
# exits 0 on a completed run, and reserves a non-zero exit for a run that could
# not happen at all: the build failed, the server never came up, `hey` is not
# installable. The comparison against the budget is the reader's, by hand, from
# the numbers printed — and the numbers are printed for that reason.
#
# ## Why `hey` and not a load driver written here
#
# The plan names `hey`. It is a single static Go binary with no cgo and no Node,
# it installs with `go install …@v0.1.5` into a throwaway GOBIN, and it prints
# p50/p75/p90/p95/p99 from its own latency histogram. The alternative — a driver
# in this repository — is a new Go package in a repository whose architecture
# argument is about exactly which packages may exist and depend on what, and it
# would have to carry its own percentile implementation, which is code nothing
# else here would ever exercise. Adding `hey` as a *tool* keeps the dependency
# out of go.mod entirely, which is the property the static-binary promise
# depends on.
#
# ## Why the server runs with --dev and --allow-anonymous-read
#
# Both are load-bearing and neither is cosmetic:
#
#   - --dev turns the rate limiter off. The general budget is 300 requests a
#     minute per address (config.RateSessionPerMinute) and the search budget is
#     30 (config.RateSearchPerMinute), so a load test against the default
#     configuration spends most of its run measuring 429s. This is the
#     operator's own documented switch for the problem, and it is the same
#     switch `make dev` uses.
#   - --allow-anonymous-read is what lets an unauthenticated request reach
#     /p/… at all. With it off, a GET /p/… is answered 303 to the login form and
#     a load test against the default configuration measures a redirect.
#
# Together they mean this measures the *cheapest* principal: an anonymous reader
# sees public content and a lock placeholder for every fence. The DM's render is
# strictly more work and is measured where it can be measured without a
# password — internal/httpapi/bench_test.go, through the real router, with a
# signed-in principal and no argon2 spent. Read the two together; neither
# replaces the other.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source tools/versions.env

PAGES=2000
REQUESTS=2000
CONCURRENCY=8
ROUTE="/p/Campaigns/Ash/Page-0001.md"
PORT_BASE=$(( 18000 + (RANDOM % 8000) ))
KEEP=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--pages) PAGES="$2"; shift 2 ;;
	--requests) REQUESTS="$2"; shift 2 ;;
	--concurrency) CONCURRENCY="$2"; shift 2 ;;
	--path) ROUTE="$2"; shift 2 ;;
	--keep) KEEP=1; shift ;;
	-h | --help) sed -n '2,45p' "$0"; exit 0 ;;
	*) echo "loadtest.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/semiplane-loadtest.XXXXXX")"
VAULT="$WORK/vault"
BIN="$WORK/semiplane"
SERVER_PID=""

cleanup() {
	# pkill before kill: the server is started under a timeout-free background
	# shell, and a kill that reaches the wrapper and not the process leaves the
	# vault lock held, which makes the *next* boot of this vault fail with
	# "vault is already open by another semiplane process" (docs/pitfalls.md).
	if [[ -n "$SERVER_PID" ]]; then
		pkill -f "semiplane --vault $VAULT" 2>/dev/null || true
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if [[ "$KEEP" == 1 ]]; then
		echo "==> kept $WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT INT TERM

command -v go >/dev/null || {
	echo "loadtest.sh: no go on PATH; this script builds the binary it measures" >&2
	exit 2
}
command -v curl >/dev/null || {
	echo "loadtest.sh: no curl on PATH; the readiness probe needs it" >&2
	exit 2
}

# --- the driver -------------------------------------------------------------
# Installed into the work directory rather than the user's GOPATH: a load test
# should not leave a tool behind, and the version comes from tools/versions.env
# so a bump is one line in one file.
HEY="$WORK/hey"
if [[ ! -x "$HEY" ]]; then
	echo "==> installing hey v$HEY_VERSION"
	GOBIN="$WORK/bin" GOFLAGS= go install "github.com/rakyll/hey@v$HEY_VERSION"
	HEY="$WORK/bin/hey"
fi

# --- the binary -------------------------------------------------------------
echo "==> building ./cmd/semiplane"
CGO_ENABLED=0 go build -trimpath -o "$BIN" ./cmd/semiplane
"$BIN" version

# --- the vault --------------------------------------------------------------
echo "==> generating a $PAGES-page vault"
./scripts/vaultgen.sh "$VAULT" "$PAGES"

# One `vault info` before the server starts: it takes the lock, walks and indexes
# the corpus, prints how many files it indexed, and shuts down. The number it
# prints is what the latency below is a latency *of*, and doing it here means the
# server's own boot finds every hash matching and spends its first seconds on
# nothing.
echo "==> indexing (semiplane vault info)"
INFO="$("$BIN" --vault "$VAULT" vault info)"
INDEXED="$(printf '%s\n' "$INFO" | sed -n 's/^files:[[:space:]]*\([0-9]*\).*/\1/p')"
printf '%s\n' "$INFO"
if [[ -z "$INDEXED" ]]; then
	echo "loadtest.sh: could not read an indexed-file count out of 'vault info'" >&2
	exit 2
fi

# --- the server -------------------------------------------------------------
# Five candidate ports: a port that is already bound is a one-line retry here
# and a confusing failure in the readiness probe.
BASE=""
for attempt in 0 1 2 3 4; do
	PORT=$(( PORT_BASE + attempt ))
	echo "==> starting the server on 127.0.0.1:$PORT"
	"$BIN" --vault "$VAULT" --host 127.0.0.1 --port "$PORT" \
		--no-open --dev --allow-anonymous-read >"$WORK/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 1 60); do
		if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null; then
			BASE="http://127.0.0.1:$PORT"
			break
		fi
		# The process is gone: the port was taken, or the boot failed. Read the
		# log rather than waiting out the full probe window on a dead server.
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
		sleep 1
	done
	if [[ -n "$BASE" ]]; then break; fi
	echo "    attempt $attempt did not come up; the server said:"
	sed 's/^/    /' "$WORK/server.log" | tail -20
done
if [[ -z "$BASE" ]]; then
	echo "loadtest.sh: the server never became healthy; see $WORK/server.log" >&2
	exit 2
fi

# The rendered page is the thing being measured, so prove the route answers one
# before the driver sends two thousand requests at it. A 404 here would otherwise
# be reported as a very fast page render.
CODE="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$BASE$ROUTE")"
if [[ "$CODE" != 200 ]]; then
	echo "loadtest.sh: GET $ROUTE answered $CODE, want 200: the route under test is not serving a page" >&2
	exit 2
fi

# --- the measurement --------------------------------------------------------
#
# Two concurrency levels per route, and the distinction is the point rather than
# thoroughness.
#
# Concurrency 1 is the row the P12 budget is comparable to. "p99 page render
# under 50 ms and search under 20 ms" says nothing about how many readers it
# assumes, and the only reading under which a latency budget is a statement
# about the code rather than about the machine is one reader at a time — which
# is also how a table of six actually reads the wiki. That row is what a
# regression is visible in.
#
# The second row is saturation. At concurrency N on an N-cpu host every core is
# busy, so the p99 it reports is dominated by queueing: eight requests sharing
# eight cores means the seventh waits for the first. A saturated p99 that misses
# the budget says the budget assumed a different concurrency, not that a page
# render regressed — and printing only the saturated row would make that
# indistinguishable from a real regression, which is the failure mode this
# script exists to avoid.
for route in "$ROUTE" "/api/search?q=vault"; do
	echo
	echo "==> GET $route"
	for c in 1 "$CONCURRENCY"; do
		if [[ "$c" == 1 ]]; then
			label="concurrency 1  (the row the P12 budget is comparable to)"
		else
			label="concurrency $c  (saturated: this p99 is mostly queueing)"
		fi
		echo "--- $REQUESTS requests at $label"
		# hey's own output is a histogram, a latency distribution, a breakdown of
		# where the time went and a status-code table. The percentiles and the
		# status codes are the two parts of that a reader of this script needs,
		# and a status line that is not 200 would make every number below it
		# meaningless — so the status table stays in and the histogram goes.
		#
		# No -q: hey's -q is a rate limit in queries per second per worker, not
		# quiet, and there is no quiet flag. Two details the pattern below has to
		# carry: the percentile lines print their percent sign doubled (`50%% in
		# 0.0072 secs`), and the status line is indented two spaces rather than
		# starting the line.
		"$HEY" -n "$REQUESTS" -c "$c" "$BASE$route" |
			grep -E '^  (Total|Slowest|Fastest|Requests/sec):|^  [0-9]+%%? in |^[[:space:]]*\[[0-9]{3}\]'
	done
done

echo
echo "==> budget, for the reader to compare by hand (docs/ADR-0002-pure-go-sqlite.md):"
echo "    page render p99 < 50 ms, search p99 < 20 ms, on a 2000-page vault"
echo "    compare the CONCURRENCY 1 rows above; the saturated rows answer a"
echo "    different question and a saturated p99 is not a regression"
echo "    this run indexed $INDEXED files on $(uname -sr), $(nproc) cpus"
echo "==> this is a report. A shared runner's p99 is a statement about the host,"
echo "    not about the code, so nothing here fails a build on a number."
