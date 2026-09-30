#!/usr/bin/env bash
# Memory-bounded test runner.
#
# Why this exists: `go test ./...` links and runs one test binary per package, up
# to -p (NumCPU) at a time. Every package that pulls in modernc.org/sqlite links
# a very large pure-Go libc, so a parallel run can hold four or five
# multi-hundred-megabyte binaries and their compiler processes at once. On this
# machine that exhausted 23 GiB of RAM plus zram swap and killed the whole
# session. The failure mode is silent: the runner is killed, not the test.
#
# So the rules are:
#   -p 1          one test binary at a time. The parallelism that actually bites
#                 is in the *link* step, not the run step.
#   -parallel N   bounded subtest parallelism inside a binary, so a table-driven
#                 test with t.Parallel() cannot fan out into N processes' worth
#                 of live fixtures.
#   GOMEMLIMIT    a soft ceiling on the Go heap, so an allocation-churn bug
#                 spends time in the collector instead of eating the machine.
#   -timeout      a hung test panics with a full goroutine dump naming the frame
#                 that is spinning, instead of sitting there until something
#                 else OOMs first.
#
# Usage:
#   scripts/test.sh                      every package, bounded
#   scripts/test.sh ./internal/md/       one package
#   scripts/test.sh -run TestRoundTrip   one test (extra args pass through)
#   scripts/test.sh -race                race detector (slower, same bounds)
#   scripts/test.sh -short               skip slow tests
#   scripts/test.sh -fuzz FuzzNeverCorrupt -fuzztime 30s   one fuzz target
set -euo pipefail

cd "$(dirname "$0")/.."

# 3 GiB soft heap ceiling. The pure-Go SQLite and the 1 MiB markdown corpus both
# fit comfortably; a runaway allocation does not.
export GOMEMLIMIT="${GOMEMLIMIT:-3GiB}"
# A more aggressive GC costs a little CPU and buys a lot of headroom. This is
# the right trade for a test run on a shared machine.
export GOGC="${GOGC:-50}"

# -timeout: a spinning test dumps its stack and names the culprit.
TIMEOUT="${SEMIPLANE_TEST_TIMEOUT:-180s}"
# -parallel: how many t.Parallel subtests run at once.
PARALLEL="${SEMIPLANE_TEST_PARALLEL:-4}"

FUNDUZZ=""
SHORT=""
TIMEOUTFLAG=()
RACE=""
declare -a EXTRA=()
declare -a PACKAGES=()

# Flags that take a separate value argument. Without this list, `go test -run
# Foo ./pkg` has "Foo" misread as a package name, which fails with a message
# that blames a package that does not exist.
value_flags=(-run -timeout -parallel -fuzz -fuzztime -tags -coverprofile -covermode -cpuprofile -memprofile -o -bench -exec)

for arg in "$@"; do
	# A value belonging to the previous flag.
	if [[ ${#EXTRA[@]} -gt 0 ]]; then
		prev="${EXTRA[$((${#EXTRA[@]} - 1))]}"
		for vf in "${value_flags[@]}"; do
			if [[ "$prev" == "$vf" ]]; then
				EXTRA+=("$arg")
				continue 2
			fi
		done
	fi
	case "$arg" in
		-fuzz)
			# The target name is this flag's value, so it has to reach EXTRA as
			# well as setting the mode. Recording the flag alone let the target
			# fall through to the package list, and the package path through to
			# a second failure — so a correctly typed invocation reported
			# "takes exactly one package" for the package it was given.
			FUNDUZZ=1
			EXTRA+=("$arg")
			;;
	-short)
		SHORT="-short"
		;;
	-race)
		RACE="-race"
		# A race build instruments every memory access, and the httpapi suite
		# boots a whole application per fixture with an argon2id derivation in
		# each. That is a few times slower than the same suite uninstrumented, so
		# the uninstrumented timeout reports a spinning test on a suite that is
		# simply working. The timeout exists to name a spin, not to hold a
		# budget, so it is scaled rather than raised for everyone.
		[[ -n "${SEMIPLANE_TEST_TIMEOUT:-}" ]] || TIMEOUT="600s"
		;;
	-*)
		EXTRA+=("$arg")
		;;
	*)
		PACKAGES+=("$arg")
		;;
	esac
done

# A fuzz target takes one package, one target, and no parallelism knobs: the
# fuzzing engine manages its own workers and its own memory.
if [[ -n "$FUNDUZZ" ]]; then
	[[ ${#PACKAGES[@]} -eq 1 ]] || {
		echo "test.sh: -fuzz takes exactly one package" >&2
		exit 2
	}
	exec go test "${PACKAGES[0]}" -run=XXX ${EXTRA[@]+"${EXTRA[@]}"} -timeout 10m
fi

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
	PACKAGES=("./...")
fi

echo "==> test ${PACKAGES[*]} (p=1 parallel=${PARALLEL} GOMEMLIMIT=${GOMEMLIMIT} timeout=${TIMEOUT})"

# -p 1 is the important one. -parallel bounds subtests inside a binary.
#
# ${EXTRA[@]+"${EXTRA[@]}"} rather than "${EXTRA[@]}": under `set -u` an empty
# array expansion is an error on bash 3.2, which is what macOS ships, and legal
# only from bash 4.4. Every macOS unit job failed on exactly that, on a tree
# whose Go tests all passed — the +test form expands to nothing when the array
# is empty and to the elements when it is not, on every bash this is run under.
exec go test \
	-p 1 \
	-parallel "${PARALLEL}" \
	-timeout "${TIMEOUT}" \
	${SHORT} ${RACE} \
	${EXTRA[@]+"${EXTRA[@]}"} \
	-count=1 \
	"${PACKAGES[@]}"
