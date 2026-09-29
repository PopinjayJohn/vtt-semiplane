#!/usr/bin/env bash
# Boot the real binary, claim the first administrator through the real form, and
# walk the routes in pa11y.config.js in both themes, with pa11y from pa11y-ci's tree.
#
#   scripts/pa11y.sh [--pages N] [--port N] [--keep] [--record]
#
# **This is a gate, and it is one for a specific reason.** An accessibility error
# is a property of the markup: the same bytes in the same browser produce the same
# axe verdict on any machine, so a statement about a *change* in that number is a
# statement about the code rather than about the host. That is the exact opposite
# of the latency budget, which is why scripts/loadtest.sh is a report and this is
# not.
#
# It is a **ratchet**, not a threshold of zero. `.pa11y-baseline` records the
# measured error count per route per theme; a count that gets worse fails and
# prints both numbers, and a count that gets better passes and says to re-record
# it. A fixed threshold would be the purer claim and would be red forever on a
# codebase with real findings — and a light that never turns green is a light
# nobody reads. `make coverage-check` is the same shape for the same reason.
#
# ## The session
#
# Four of the six routes are behind a permission an anonymous request does not
# hold — `/p/*` is PermReadPage and `/plugin/houserules` is mounted at
# PermSession — and with --allow-anonymous-read off an unauthenticated walk of
# them measures the login form six times. There is no flag that hands a browser a
# session, so this script does what a person does: GET /setup for the form and
# the pre-session CSRF cookie, POST /setup with the token, and read the
# semiplane_session cookie out of the response.
#
# That is also why pa11y.config.js is a JavaScript file. A committed JSON config
# would have to carry a session token, and a token in a committed file is a
# credential in git; a JS config reads it out of the environment, and refuses to
# run at all if it is absent rather than walking nothing and calling it clean.
#
# ## What is NOT covered, and why
#
# Only one account can be created through this application: /setup claims the
# first administrator and there is no route, command or boot step anywhere that
# calls auth.Service.CreateInvite — the invite *redemption* form exists and
# nothing mints a token to redeem. So the walk runs as an administrator, and an
# administrator is in the reader set of every visibility, which means the
# `secret-locked` placeholder is never rendered and is not audited here. Covering
# it needs a second account, which needs an invite surface, which is a product
# change rather than a test change. internal/httpapi/leaksuite_test.go covers the
# placeholder's *markup* in Go; its *appearance to a reader refused a fence* is
# currently unmeasured by anything.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source tools/versions.env

PAGES=40
PORT=0
KEEP=0
RECORD=0
# The account the walk signs in as. It is also the author of every fence in the
# generated corpus, so those fences resolve to a real user and the walk sees
# revealed bodies rather than a vault of unresolved placeholders.
ADMIN_USER=dungeonmaster
ADMIN_PASS='a passphrase long enough to be worth hashing'

while [[ $# -gt 0 ]]; do
	case "$1" in
	--pages) PAGES="$2"; shift 2 ;;
	--port) PORT="$2"; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--record)
		# Rewrite .pa11y-baseline from what this run measured. It is a separate,
		# explicit word rather than a default because re-recording is the one action
		# that makes the gate stop complaining, so it must never be something a run
		# does on its own. The report is printed first and in full, and a run that
		# regressed still says so before the baseline is overwritten with the worse
		# number.
		RECORD=1
		shift
		;;
	-h | --help) sed -n '2,47p' "$0"; exit 0 ;;
	*) echo "pa11y.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/semiplane-pa11y.XXXXXX")"
VAULT="$WORK/vault"
BIN="$WORK/semiplane"
SERVER_PID=""

cleanup() {
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

for tool in go curl node npm; do
	command -v "$tool" >/dev/null || {
		echo "pa11y.sh: no $tool on PATH (need go, curl, node, npm)" >&2
		exit 2
	}
done

# --- pa11y-ci ---------------------------------------------------------------
# A throwaway install into the work directory, at the version tools/versions.env
# pins. `npx` is not used because it resolves a version at run time from a
# registry, and a gate whose runner's version is decided by whatever the registry
# served that morning is not a gate.
PKG="$WORK/pa11y"
mkdir -p "$PKG"
echo "==> installing pa11y-ci@$PA11Y_CI_VERSION into $PKG"
(cd "$PKG" && npm install --silent --no-audit --no-fund --loglevel=error \
	"pa11y-ci@$PA11Y_CI_VERSION")

# --- the binary and the vault ----------------------------------------------
echo "==> building ./cmd/semiplane"
CGO_ENABLED=0 go build -trimpath -o "$BIN" ./cmd/semiplane

echo "==> generating a $PAGES-page vault"
./scripts/vaultgen.sh "$VAULT" "$PAGES"

# --dev turns the rate limiter off. Not for a walk of twelve pages, but because
# the alternative is a gate whose flakiness is a function of how many pages it
# happens to walk; the flag is the operator's own documented switch.
echo "==> starting the server"
"$BIN" --vault "$VAULT" --host 127.0.0.1 --port "$PORT" \
	--no-open --dev >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

# The port is not known in advance when --port 0, so it is read out of the
# banner the process prints on stdout. Anything else means guessing a port and
# racing another process for it.
BASE=""
for _ in $(seq 1 60); do
	# The banner prints `listen:  <addr> (<url>)`, and it is the url in the
	# parentheses that a client can actually reach. Matching the bare address
	# would hand curl a host:port with no scheme.
	BASE="$(sed -n 's/^listen:.*(\(http[^)]*\)).*/\1/p' "$WORK/server.log" | head -1)"
	[[ -n "$BASE" ]] && break
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
	sleep 1
done
if [[ -z "$BASE" ]]; then
	echo "pa11y.sh: the server never announced an address; its log said:" >&2
	tail -30 "$WORK/server.log" >&2
	exit 2
fi
# The banner's url has a trailing slash and every path below is appended to it,
# so "$BASE/setup" would otherwise be a request for "//setup" — which the catch-all
# answers 404, and which reads exactly like a closed setup.
BASE="${BASE%/}"
echo "==> listening on $BASE"

# --- the first administrator -------------------------------------------------
# The real form, the real CSRF double-submit, the real argon2id. This is the only
# account the application can create, and the walk's cookie comes from it.
JAR="$WORK/cookies.txt"
echo "==> claiming the first administrator through /setup"
FORM="$(curl -fsS --max-time 10 -c "$JAR" "$BASE/setup")"
TOKEN="$(printf '%s' "$FORM" | sed -n 's/.*name="csrf" value="\([0-9a-f]\{64\}\)".*/\1/p' | head -1)"
if [[ -z "$TOKEN" ]]; then
	echo "pa11y.sh: /setup returned no CSRF token; the form the walk assumed is not the form that is served" >&2
	exit 2
fi
SETUP_CODE="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" \
	-X POST "$BASE/setup" \
	--data-urlencode "username=$ADMIN_USER" \
	--data-urlencode "displayname=The Dungeon Master" \
	--data-urlencode "passphrase=$ADMIN_PASS" \
	--data-urlencode "csrf=$TOKEN")"
if [[ "$SETUP_CODE" != "303" && "$SETUP_CODE" != "302" ]]; then
	echo "pa11y.sh: /setup answered $SETUP_CODE, want a redirect to a signed-in session" >&2
	exit 2
fi
SESSION="$(sed -n 's/.*\tsemiplane_session\t\(.*\)$/\1/p' "$JAR" | tail -1)"
if [[ -z "$SESSION" ]]; then
	echo "pa11y.sh: /setup did not set a semiplane_session cookie, so nothing behind PermSession can be walked" >&2
	exit 2
fi
# The token is a bearer credential. It is not printed, and it is not written into
# a file that outlives the run except the cookie jar, which the trap removes.
echo "==> signed in as $ADMIN_USER; holding a session"

# --- the walk ----------------------------------------------------------------
# Probe every route first, as the account the walk signs in as, and collect the
# ones the server refuses. A 303 to the login form here would mean the cookie did
# not take and pa11y would then audit the login form a dozen times and report
# twelve clean pages; a 403 or a 404 means the route is broken for a reason that
# has nothing to do with accessibility.
#
# The list comes from the config rather than being written out here. A
# hand-maintained second copy is how a route ends up audited in the place of its
# Forbidden page: a 403 does not redirect, so nothing downstream can tell a
# refused route from a rendered one, and the report would be clean.
#
# An unreachable route is reported and skipped rather than being fatal, and the
# skip is not silent: pa11y.config.js prints a NOT COVERED block naming it, and
# refuses to run at all if more than half the routes are gone. The distinction
# matters — the alternative is a job that is red for a router bug until somebody
# fixes it, and a gate that is always red is a gate nobody reads. A loud hole in
# a green report is more useful than a red light that says nothing about
# accessibility.
export SEMIPLANE_BASE_URL="$BASE"
export SEMIPLANE_SESSION="$SESSION"
SKIP=""
PROBED=0
WANTED="$(node -e 'process.stdout.write(String(require("./pa11y.config.js").probes.length))')"
while IFS= read -r probe; do
	[[ -z "$probe" ]] && continue
	CODE="$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE$probe")"
	PROBED=$(( PROBED + 1 ))
	if [[ "$CODE" == 200 ]]; then
		continue
	fi
	echo "NOT COVERED  GET $probe answered $CODE to the administrator" >&2
	SKIP="${SKIP:+$SKIP,}$probe"
	# The trailing newline on the last line is load-bearing. `while read` returns
	# non-zero for a final line with no newline, so the loop ends *and* that line
	# is dropped — and the line it drops is the last route in the config, which is
	# then never probed and never skipped. This loop counted four probes against
	# five on the first run for exactly that reason, and the assertion below is
	# what makes it a failure rather than a quietly smaller walk.
done < <(node -e 'process.stdout.write(require("./pa11y.config.js").probes.join("\n") + "\n")')
if [[ "$PROBED" -ne "$WANTED" ]]; then
	echo "pa11y.sh: probed $PROBED routes but pa11y.config.js declares $WANTED." >&2
	echo "          The probe list and the route list have diverged, so the" >&2
	echo "          coverage this run reports is not the coverage it names." >&2
	exit 2
fi
export SEMIPLANE_UNREACHABLE="$SKIP"
if [[ -n "$SKIP" ]]; then
	REACHABLE=$(( PROBED - $(awk -F, '{print NF}' <<<"$SKIP") ))
	echo "==> $REACHABLE of $PROBED probed routes are reachable; pa11y.config.js will name the rest" >&2
fi

echo
echo "==> walking every reachable route in both themes (pa11y 9, axe + htmlcs, WCAG2AA)"
REPORT="$WORK/pa11y.json"
set +e
node scripts/pa11y-run.js "$PKG/node_modules" "$REPORT"
DRIVER_STATUS=$?
# The report is checked before it is believed, by a script that knows which pages
# were asked for. A row that lands somewhere else is a row that audited a
# different page, and no exit code from the engine can see that.
node scripts/pa11y-report.js "$REPORT"
STATUS=$?
set -e

echo
case "$STATUS" in
0)
	echo "==> pa11y: no route got worse than the recorded baseline."
	if [[ -n "$SKIP" ]]; then
		echo "==> NOT a pass over the whole claim: the routes named above were not"
		echo "    walked, and their baseline rows are reported SKIPPED rather than"
		echo "    counted. This says 'no accessibility regression on the rows that ran',"
		echo "    which is a smaller statement than 'pa11y clean'."
	fi
	;;
2)
	echo "==> pa11y: at least one route got WORSE than the baseline, or a recorded"
	echo "    route is no longer walked. The lines above name the route, the theme and"
	echo "    both numbers."
	echo "    Fix the template; do not narrow the standard or the runner list to make"
	echo "    this green, and do not re-record the baseline to silence it."
	;;
3)
	echo "==> pa11y: the baseline itself is unusable — a duplicated key, a row this"
	echo "    reader cannot parse, or a route that is recorded and gone. That is a"
	echo "    fault in the gate, not an accessibility result, and NOT a pass."
	echo "    Regenerate it deliberately: node scripts/pa11y-baseline.js <report.json>"
	;;
1)
	echo "==> pa11y: the run cannot be accounted for. The table above is missing, has" >&2
	echo "    a page that was not requested, has a row that was redirected, or has a" >&2
	echo "    positive control that does not agree with the row — so a different page" >&2
	echo "    was audited, or the browser never presented the session. This is a" >&2
	echo "    harness failure, not an accessibility result, and it is NOT a pass." >&2
	;;
*) echo "pa11y.sh: the run exited $STATUS, which is none of 0, 1, 2 or 3:" >&2
	echo "          the driver exited $DRIVER_STATUS and the report check exited $STATUS." >&2
	echo "          That is a harness failure, not an accessibility result." >&2
	;;
esac

if [[ "$RECORD" == 1 ]]; then
	# Only a run that was accounted for may be recorded. Recording an
	# unaccountable one would write the number for a page nobody can vouch for
	# into the file every future run is compared against, which is the one way
	# this ratchet can be made to say anything at all.
	if [[ "$STATUS" == 0 || "$STATUS" == 2 ]]; then
		echo
		node scripts/pa11y-baseline.js "$REPORT"
		echo "==> re-recorded .pa11y-baseline from this run. The gate will compare the next"
		echo "    run against these numbers, so a re-record is a decision about what this"
		echo "    codebase is allowed to be — not a way to make the output above go away."
		STATUS=0
	else
		echo
		echo "==> NOT re-recording: the run could not be accounted for (exit $STATUS), so" >&2
		echo "    there is nothing here worth recording." >&2
	fi
fi

exit "$STATUS"
