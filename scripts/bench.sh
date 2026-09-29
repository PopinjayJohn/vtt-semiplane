#!/usr/bin/env bash
# Run the three hardening benchmarks and print the distributions.
#
#   scripts/bench.sh [package…]
#
# With no arguments it runs the three the P12 work added or extended:
# internal/sync (the indexer, which is the half of ADR-0002 that had no
# measurement), internal/search (at 1k and 2k pages) and internal/httpapi (a page
# render through the real router). The Makefile is not this repository's to edit,
# so this is the entry point instead of a target.
#
# ## The bounds, and why each one is here
#
# AGENTS.md §11: never `go test ./...` bare on a machine with a large RAM-to-cpu
# ratio. Every package that pulls in modernc.org/sqlite links a very large
# pure-Go libc, and `-p 1` plus a GOMEMLIMIT is what keeps three of them resident
# at a time from exhausting RAM *and* swap. scripts/test.sh sets the same bounds
# and this mirrors them rather than inventing its own.
#
# Per-benchmark `-benchtime`, because one global value cannot serve both:
#
#   * A full 1000-page reindex is ~8.6 seconds. At `-benchtime=1s` Go would pick
#     b.N=1 and every percentile would be the same number, so this one is given
#     `-benchtime=10x`: ten real samples of the thing it reports a distribution
#     over, for about a hundred seconds. Measured on the machine these numbers
#     were taken, ten passes is 115 pages/s with a p50 of 8.5 s and a p99 of
#     9.2 s — and at b.N=3 the p50, the p95 and the p99 all resolve to the same
#     of three samples, which is a number with the shape of a distribution and
#     none of its information.
#   * The rest are single-request or per-file measurements where Go's own ramp to
#     a one-second run is the right behaviour, and 1s is given.
#
# `-p 1` per package for the same reason as the test script, `-timeout` because a
# spin should name itself (the httpapi fixture indexes 2000 pages before its first
# iteration, so its suite is not a fast suite), and `GOGC=50` to keep the heap
# predictable next to a GOMEMLIMIT.
#
# **These report; they do not assert.** There is no threshold in any of them and
# there should not be: a latency gate written from a number observed on one
# machine is a gate that reports that machine's load as a regression. The budget
# in docs/ADR-0002-pure-go-sqlite.md — p99 page render under 50 ms, search under
# 20 ms, on a 2000-page vault — is compared by a reader, from these numbers, by
# hand.
set -euo pipefail

cd "$(dirname "$0")/.."

export GOMEMLIMIT="${GOMEMLIMIT:-3GiB}"
export GOGC="${GOGC:-50}"

# -run='^$' because a benchmark binary that also ran the package's tests would
# spend its time in them; -p 1 and -parallel 1 for the RAM reason above;
# -timeout 30m because the httpapi fixture's 2000-page setup is not quick.
run() {
	local dir="$1" bench="$2" benchtime="$3"
	echo
	echo "==> ${dir}  -bench=${bench}  -benchtime=${benchtime}"
	echo "    (nproc=$(nproc), GOMEMLIMIT=${GOMEMLIMIT}, GOGC=${GOGC})"
	go test -run='^$' -bench="$bench" -benchtime="$benchtime" -count=1 \
			-p 1 -parallel 1 -timeout 30m "./$dir" |
		grep -E '^(Benchmark|goos|goarch|cpu|pkg|PASS|FAIL|ok)' || true
}

if [[ $# -gt 0 ]]; then
	for pkg in "$@"; do
		run "$pkg" '.' 1s
	done
	exit 0
fi

# Order matters only for a truncated run: the slowest measurement is first, so a
# run that is cut short has still said the thing that takes nine seconds to say.
run internal/sync    'BenchmarkIndex1kPages$'                                  10x
# The per-file and the reconcile-scan measurements. Both are cheap — a
# millisecond-scale iteration — and both are the numbers that answer "what does
# one change cost" and "what does the 60-second scan cost", which the full pass
# cannot.
run internal/sync    'BenchmarkIndex1kPagesPerFile|BenchmarkIndex1kPagesIncremental' 3s
run internal/search  'BenchmarkSearch'                                         1s
run internal/httpapi 'BenchmarkPageRender2kPages'                               1s
