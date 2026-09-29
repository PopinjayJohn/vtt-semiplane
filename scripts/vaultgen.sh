#!/usr/bin/env bash
# Write a synthetic campaign into a directory. Deterministic, no network, no Go.
#
#   scripts/vaultgen.sh <root> [pages]
#
# Both scripts that need a booted server need a vault to boot against, and a
# vault is content. This is that content, in one place, so the load test and the
# accessibility runner are walking the same corpus rather than two corpora that
# have quietly drifted.
#
# The corpus mirrors internal/sync/bench_test.go's and internal/httpapi's on
# purpose: a page is a frontmatter block, three headings, prose and fifteen
# wikilinks, and every twentieth page carries a secret fence. The fifteen links
# are the point — the aside column and the resolver are where a page render and
# an index pass actually spend their time, and a corpus of link-free pages would
# make every number in this repository look better than it is.
#
# The fence bodies are synthetic text written for this script. They are not
# campaign content and nothing in this repository should read a real one.
#
# The fences name `dungeonmaster` as their author, which is the account
# scripts/pa11y.sh claims through /setup. A caller that wants them resolved under
# a different name should say so in the corpus rather than hope.
#
# It is a plain executable rather than a sourceable library so that its shell
# options do not leak into a caller's `set -euo pipefail`.
set -euo pipefail

ROOT="${1:?usage: vaultgen.sh <root> [pages]}"
PAGES="${2:-2000}"

mkdir -p "$ROOT/Campaigns/Ash" "$ROOT/houserules"

# A fixed vocabulary and a fixed word choice, so two runs of this script produce
# byte-identical files. A corpus that differs between runs cannot be compared
# against a run before it, which is the whole reason the Go fixtures use a
# seeded rand.
WORDS=(vault door warded necrotic damage gundren dwarf goblin scouts raid
       traps pressure plate darts tiamat baphomet lolth portrait session
       zero notes obsidian cloakwork kobold ambush bridge dnd5e ash)

pick() { echo "${WORDS[$(( $1 % ${#WORDS[@]} ))]}"; }

write_page() {
	local i="$1"
	local title a b c
	a="$(pick $((i * 7 + 3)))"
	b="$(pick $((i * 13 + 5)))"
	c="$(pick $((i * 29 + 11)))"
	title="$a $b $i"
	{
		printf -- '---\ntitle: %s\ntype: note\ntags: [area/wild]\n---\n\n' "$title"
		printf '# %s\n\n' "$title"
		local h p w l
		for h in 0 1 2; do
			printf '## %s %d\n\n' "$(echo "${WORDS[$(( (i + h * 5) % ${#WORDS[@]} ))]}" | tr '[:lower:]' '[:upper:]')" "$h"
			for p in 0 1; do
				for w in $(seq 0 11); do
					printf '%s ' "$(pick $(( i * 3 + w * 17 + h )))"
				done
				printf '\n\n'
			done
			for l in $(seq 0 14); do
				printf '[[Page-%04d]]\n' "$(( (i + l * 7 + h) % PAGES ))"
			done
			printf '\n'
		done
		if (( i % 20 == 0 )); then
			# 12 hex characters, the on-disk id shape. visibilities rotate so a
			# walk sees all three, which is what makes a redaction question
			# answerable from the rendered page rather than assumed.
			case $(( (i / 20) % 3 )) in
				0) vis=private ;;
				1) vis=dm ;;
				*) vis=table ;;
			esac
			printf '```secret id=%012x visibility=%s author=dungeonmaster created=2026-09-28T10:04:11Z\n' \
				"$i" "$vis"
			printf 'synthetic fixture body %s\n```\n' "$(pick $i)"
		fi
	} >"$ROOT/Campaigns/Ash/$(printf 'Page-%04d.md' "$i")"
}

seq 0 $((PAGES - 1)) | while read -r i; do
	write_page "$i"
done

# Ten house rules, always. internal/systems/houserules renders pages carrying
# `type: houserule` and nothing else, so an accessibility walk of
# /plugin/houserules over a vault with none is a walk of an empty page — which
# would pass for the same reason a page with no headings passes.
r=0
while (( r < 10 )); do
	{
		printf -- '---\ntitle: Rule %d\ntype: houserule\nsource: synthetic fixture\n---\n\n' "$r"
		printf '# Rule %d\n\n' "$r"
		printf 'A synthetic house rule written so the houserules plugin has something to\n'
		printf 'render, link and navigate. It is fixture text, not a rule anybody plays by.\n\n'
		printf '## Detail\n\n'
		for w in $(seq 0 11); do printf '%s ' "$(pick $(( r * 11 + w )))"; done
		printf '\n\n'
		printf 'See also [[Page-%04d]].\n' "$((r * 3))"
		# Two of the ten carry a fence, so the plugin's page shows the locked and
		# the revealed form side by side — the case the accessibility claim is
		# actually about, since the placeholder markup is a component a reader
		# can see.
		if (( r == 3 || r == 7 )); then
			printf '\n```secret id=%012x visibility=table author=dungeonmaster created=2026-09-28T10:04:11Z\n' "$((9000 + r))"
			printf 'synthetic fixture body for rule %d\n```\n' "$r"
		fi
	} >"$ROOT/houserules/Rule-$r.md"
	r=$((r + 1))
done

printf 'wrote %d pages and 10 house rules to %s\n' "$PAGES" "$ROOT"
