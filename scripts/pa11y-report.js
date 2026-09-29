#!/usr/bin/env node
// Check what pa11y actually measured, and hold the result to a committed ratchet.
//
//   scripts/pa11y-report.js <report.json>
//
// pa11y exits 0 for "every row passed" and 2 for "some row had an error". Both
// are silent about *which pages* were measured, and a row that is redirected is
// reported under the URL it landed on rather than the one that was asked for.
//
// That is not a hypothetical. The first run of this gate set a `cookies` option,
// which pa11y 9 does not have and therefore ignored, so every authenticated row
// was answered 303 to the login form — and pa11y-ci reported **10/10 URLs
// passed**, because the login form really is an accessible page. A gate that
// audits nothing and reports a pass is worse than no gate, and AGENTS.md §5 has
// been recording exactly this failure wearing different hats for six stages.
//
// So this script refuses to describe a run it cannot account for. It requires the
// config, recomputes the exact URL list that config asked for, and then asserts
// on the report:
//
//   1. one key per requested URL, which is also one key per row — two rows that
//      landed on the same page would collapse into one key and a row would
//      vanish from the count;
//   2. no key that was not requested (a redirect produces one);
//   3. no requested URL missing from the keys (a timeout or a crash produces
//      one);
//   4. no row whose page URL is not the URL it was asked for;
//   5. every row's positive control: the theme the row claims, and a signed-in
//      page that carries the shell's logout form and no login form. The
//      anonymous row is checked the other way round, so the control cannot pass
//      by finding nothing at all.
//
// Any of those is a harness failure, printed as such and exited 1, whatever
// pa11y's own exit code was. Then the per-row error table, then the ratchet.
//
// ## The ratchet
//
// `.pa11y-baseline` is one measured error count per route per theme. A row that
// got worse fails; a row that got better or stayed equal passes. This is the same
// shape `make coverage-check` uses, and for the same reason: an accessibility
// error is a property of the markup, so what is enforceable is a statement
// about a change, and a fixed threshold of zero on a codebase with real findings
// is a red light that never turns green and therefore never gets read.
//
// A duplicated key in the baseline is a hard failure, and the check exists
// because the failure it prevents is invisible: `key -> value` reads as
// last-one-wins, so appending a re-recorded number instead of replacing the old
// one leaves the gate comparing against a stale value and passing. That is the
// bug the coverage ratchet shipped once (see the Makefile's coverage-baseline
// target) and it is not repeated here.
//
// It requires the same environment pa11y.config.js does, so scripts/pa11y.sh runs
// it in the same shell with the same exports.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const reportPath = process.argv[2];
if (!reportPath) {
	console.error('usage: pa11y-report.js <report.json>');
	process.exit(2);
}

const config = require(path.join(__dirname, '..', 'pa11y.config.js'));
const expected = new Map(config.rows.map(r => [r.url, r]));
const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
const measured = new Map(Object.entries(report.results));

const missing = [...expected.keys()].filter(u => !measured.has(u));
const unexpected = [...measured.keys()].filter(u => !expected.has(u));
// The driver records the URL the engine reported it tested for every row. A row
// that was redirected audited a different page, and the accessibility verdict
// belongs to that other page.
const wandered = [...expected.keys()].filter(u => report.landed && report.landed[u] !== u);
// A result whose shape is not what this script expects is a version skew between
// the driver and pa11y, and reading it as "no issues" would turn a broken
// report into a clean one.
const malformed = [...measured.keys()].filter(u => !Array.isArray(measured.get(u)));

let failed = false;

if (report.total !== expected.size) {
	console.error(
		`FAIL  the driver was asked for ${expected.size} rows and reports ${report.total}. ` +
			'The two must agree before any number below means anything.'
	);
	failed = true;
}

if (malformed.length > 0) {
	console.error(
		'FAIL  these rows have no issue list at all. pa11y 9 resolves a result ' +
			'object rather than an array, and a shape that is not an array here ' +
			'means the driver and the engine disagree — not that the page is clean:'
	);
	for (const url of malformed) console.error(`        ${url}`);
	failed = true;
}

if (missing.length > 0) {
	console.error('FAIL  these rows were requested and never measured:');
	for (const url of missing) console.error(`        ${url}`);
	failed = true;
}

if (unexpected.length > 0) {
	console.error('FAIL  these pages were measured but not requested:');
	for (const url of unexpected) console.error(`        ${url}`);
	failed = true;
}

if (wandered.length > 0) {
	console.error(
		'FAIL  these rows did not end on the page they asked for — a row was ' +
			'redirected, so a different page was audited:'
	);
	for (const url of wandered) {
		console.error(`        asked for ${url}`);
		console.error(`        landed on  ${report.landed[url]}`);
	}
	failed = true;
}

// The positive control. Every row answers the same two questions about the
// document the engine actually measured, so a row that was measured as somebody
// else, or in the wrong theme, cannot be reported as clean.
for (const [url, row] of expected) {
	const c = (report.control || {})[url];
	if (!c) {
		console.error(
			`FAIL  ${url}\n        no positive control was recorded. A run without one ` +
				'cannot say whether it measured the page as a signed-in reader or in the ' +
				'theme it claims, so it cannot be a pass.'
		);
		failed = true;
		continue;
	}
	if (c.themeClass !== row.theme) {
		console.error(
			`FAIL  ${url}\n        the row claims the ${row.theme} theme and the page's root ` +
				`element carries class="${c.themeClass}". Two theme rows that are one ` +
				'measurement are two clean rows, which is the failure this gate has already produced twice.'
		);
		failed = true;
	}
	// Two-sided, and only about the login form. The anonymous row is *supposed* to
	// render one and must; every other row must not, because a page served in
	// place of a signed-in one renders the login form without changing the URL,
	// which is the case the redirect check cannot see.
	//
	// It deliberately does not require the shell's logout form on a signed-in row.
	// A plugin mount is a document without the shell — no header, no logout form —
	// so requiring it would be a control that measures "is this the shell" and
	// calls it "is this a session". It failed on `/plugin/houserules` for exactly
	// that reason, and the fix was to the control rather than to the gate.
	const wantsLoginForm = Boolean(row.anonymous);
	if (wantsLoginForm !== c.loginForms > 0) {
		console.error(
			`FAIL  ${url}\n        the row is ${wantsLoginForm ? 'anonymous' : 'signed in'} and the page carries ` +
				`${c.loginForms} login form(s) (title "${c.title}"). ` +
				(wantsLoginForm
					? 'The control that says no row may render a login form has nothing to be right about unless one does, so this row proves nothing rather than passing.'
					: 'A page served in place of the one that was asked for carries no accessibility verdict for it, and a login form is an accessible login form.')
		);
		failed = true;
	}
}

if (failed) {
	console.error(
		'\nA row that lands somewhere else is not a pass over what was asked for. ' +
			'A login form is an accessible login form.'
	);
	process.exit(1);
}

// --- the table a reader wants -----------------------------------------------

const themeOf = url => /[?&]__theme=([^&]+)/.exec(url);
// The theme moves to the end of the line rather than into the query, so the
// light and dark rows of one page are two distinguishable lines and the rest
// of the query — `?q=vault` on a search row — is still visible.
const labelOf = url => {
	const t = themeOf(url);
	return url.replace(/[?&]__theme=([^&]+)/, '') + (t ? `  [${t[1]}]` : '');
};

console.log('');
console.log(
	`pa11y measured ${report.total} rows, and every one of them is the page it asked for, ` +
		'as the subject it claims to be, in the theme it claims.'
);
console.log('');
const width = Math.max(...[...expected.keys()].map(u => labelOf(u).length));
for (const [url, issues] of measured) {
	const verdict = issues.length === 0 ? 'clean' : `${issues.length} error(s)`;
	console.log(`  ${labelOf(url).padEnd(width)}  ${verdict}`);
	// Grouped by code, because forty-five instances of one contrast failure is
	// one defect and a wall of identical lines would bury the other kinds of
	// finding on the same page.
	const byCode = new Map();
	for (const issue of issues) {
		if (!byCode.has(issue.code)) byCode.set(issue.code, []);
		byCode.get(issue.code).push(issue);
	}
	for (const [code, group] of byCode) {
		// pa11y reports axe's *incomplete* results — "needs review", not a proven
		// failure — at the same level as its violations, because the runner has no
		// level cap unless one is configured. Naming it here is the difference
		// between "46 contrast failures" and "46 findings, of which N axe declined
		// to decide", and the distinction decides what the next hour of work is.
		const undecided = group.filter(i => i.runnerExtras && i.runnerExtras.needsFurtherReview).length;
		console.log(`      ${code}  x${group.length}${undecided ? `  (${undecided} of them "needs review", not a proven failure)` : ''}`);
		for (const issue of group.slice(0, 3)) {
			if (issue.selector) console.log(`        ${issue.selector}`);
			// pa11y 9's axe runner does not carry axe's `data` — the two computed
			// colours and the ratio — through into the issue, so there is no
			// colour pair to print here. The selector is what a fix starts from.
			const detail = issue.data && issue.data.fgColor
				? `${issue.data.fgColor} on ${issue.data.bgColor} = ${Number(issue.data.contrastRatio).toFixed(2)}:1`
				: (issue.message || '');
			if (detail && !detail.startsWith('Elements must meet')) {
				console.log(`          ${detail}`);
			}
		}
		if (group.length > 3) console.log(`        … and ${group.length - 3} more with the same code`);
	}
}
console.log('');
console.log(
	`${report.passes} of ${report.total} rows clean, ${report.errors} accessibility error(s).`
);

// --- the ratchet ------------------------------------------------------------

const keyOf = row => `${row.path}\t${row.theme}`;

function readBaseline() {
	// MALFORMED is its own outcome and its own exit code. "The baseline is
	// unusable" and "the app regressed" are different facts, and a gate that
	// reports them with the same word teaches its reader to ignore it.
	if (!fs.existsSync(config.baseline)) {
		return { error: `${config.baseline} does not exist. Record one with: node scripts/pa11y-baseline.js <report.json>` };
	}
	const rows = new Map();
	const malformed = [];
	const seen = new Map();
	for (const raw of fs.readFileSync(config.baseline, 'utf-8').split('\n')) {
		const line = raw.trim();
		if (line === '' || line.startsWith('#')) continue;
		const fields = line.split(/\s+/);
		if (fields.length !== 3 || !/^\d+$/.test(fields[2])) {
			malformed.push(`        ${line}`);
			continue;
		}
		const key = `${fields[0]}\t${fields[1]}`;
		// The duplicate check, before the assignment: a second row for the same
		// route and theme would otherwise overwrite the first and the gate would
		// compare against whichever came last.
		seen.set(key, (seen.get(key) || 0) + 1);
		rows.set(key, Number(fields[2]));
	}
	for (const [key, n] of seen) {
		if (n > 1) malformed.push(`        ${key.replace('\t', ' ')}  (${n} rows)`);
	}
	if (malformed.length) {
		return { error: `${path.basename(config.baseline)} has rows this reader cannot use:`, malformed };
	}
	return { rows };
}

const baseline = readBaseline();
if (baseline.error) {
	console.error('');
	console.error(`BASELINE  ${baseline.error}`);
	for (const line of baseline.malformed || []) console.error(line);
	process.exit(3);
}

const walked = new Set([...expected.values()].map(keyOf));
const declared = new Set(config.allRows.map(keyOf));
const current = new Map([...expected.values()].map(r => [keyOf(r), measured.get(r.url).length]));

const regressions = [];
const lost = [];
const improvements = [];
const untracked = [];
for (const [key, now] of current) {
	const [route, theme] = key.split('\t');
	if (!baseline.rows.has(key)) {
		untracked.push(`  UNTRACKED ${route} [${theme}]: ${now} error(s), and no row for it in ${path.basename(config.baseline)}.`);
		continue;
	}
	const was = baseline.rows.get(key);
	if (now > was) {
		regressions.push(
			`  WORSE     ${route} [${theme}]: ${now} error(s) now, ${was} recorded in ${path.basename(config.baseline)}.`
		);
	} else if (now < was) {
		improvements.push(
			`  BETTER    ${route} [${theme}]: ${now} error(s) now, ${was} recorded in ${path.basename(config.baseline)} — re-record with: ./scripts/pa11y.sh --record`
		);
	}
}
const skipped = [];
for (const key of baseline.rows.keys()) {
	if (walked.has(key)) continue;
	const [route, theme] = key.split('\t');
	if (declared.has(key)) {
		// The route is still in the config and the server refused it. Named, and
		// deliberately not a pass: a page that cannot be measured must not be
		// reported as one with no errors.
		skipped.push(
			`  SKIPPED   ${route} [${theme}]: ${baseline.rows.get(key)} recorded, not measured — the server refused this route.`
		);
		continue;
	}
	lost.push(
		`  MISSING   ${route} [${theme}]: ${baseline.rows.get(key)} recorded, and the route is not in pa11y.config.js at all. It was renamed or dropped; drop the row if that was deliberate.`
	);
}

console.log('');
for (const line of improvements) console.log(line);
for (const line of untracked) console.log(line);
for (const line of skipped) console.log(line);

if (regressions.length || lost.length) {
	console.error('');
	for (const line of regressions) console.error(line);
	for (const line of lost) console.error(line);
	console.error(
		`\n${regressions.length} route(s) got worse and ${lost.length} recorded route(s) are gone, ` +
			`against ${path.basename(config.baseline)}.`
	);
	process.exit(2);
}
console.log(
	`==> accessibility ratchet: no route got worse than ${path.basename(config.baseline)} ` +
		`(${[...current.values()].reduce((a, b) => a + b, 0)} error(s) across ${current.size} rows, ` +
		`${report.passes} of them clean).`
);
process.exit(0);
