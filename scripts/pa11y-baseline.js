#!/usr/bin/env node
// Rewrite .pa11y-baseline from a report, keeping its comment header.
//
//   scripts/pa11y-baseline.js <report.json>
//
// This exists as its own script rather than as a flag on scripts/pa11y-report.js
// because the Makefile owns the coverage ratchet and is not this gate's to edit;
// a re-record step that needs a build-system change is a step nobody takes, and a
// ratchet that is never tightened is a ratchet that only ever fails.
//
// ## Why the duplicate check is here and not only in the reader
//
// The reader rejects a duplicated key, which is the property that matters. This
// script is what stops one from being written: the first version kept the whole
// old file as the "header" — comments *and* value rows — and regenerating twice
// appended the value rows a second time. Because a duplicate reads as
// last-one-wins, the gate then compared against the first (stale) number and
// passed. That is the same bug the coverage ratchet shipped once.
//
// So the writer drops everything from the first non-comment line onwards and
// re-checks what it wrote with the same rule the reader uses. A writer that can
// emit a file its own reader rejects is a writer that has to be fixed first.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const reportPath = process.argv[2];
if (!reportPath) {
	console.error('usage: pa11y-baseline.js <report.json>');
	process.exit(2);
}

const config = require(path.join(__dirname, '..', 'pa11y.config.js'));
const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

const rows = config.allRows.map(row => {
	const url = config.rows.find(r => r.path === row.path && r.theme === row.theme);
	const issues = url ? report.results[url.url] : undefined;
	// A route that was not measured is recorded as `-1`, not as `0`. Recording
	// zero would let a page that cannot be measured look like a page with no
	// errors, which is the whole failure mode this gate keeps running into.
	const count = Array.isArray(issues) ? issues.length : -1;
	return `${row.path}\t${row.theme}\t${count}`;
});

const header = fs.existsSync(config.baseline)
	? fs.readFileSync(config.baseline, 'utf-8').split('\n').filter(l => l.startsWith('#') || l === '').join('\n')
	: '# Per-route accessibility baseline — a ratchet, not a floor.';

fs.writeFileSync(config.baseline, `${header.replace(/\n+$/, '')}\n${rows.sort().join('\n')}\n`);

// The reader's rule, applied to what was just written.
const seen = new Map();
for (const line of rows) {
	const key = line.split('\t').slice(0, 2).join(' ');
	seen.set(key, (seen.get(key) || 0) + 1);
}
const dup = [...seen].filter(([, n]) => n > 1);
if (dup.length) {
	console.error(
		`pa11y-baseline.js: wrote a file with ${dup.length} duplicated key(s) ` +
			`(${dup.map(d => d[0]).join(', ')}). The reader rejects this file; the writer is wrong.`
	);
	process.exit(3);
}
console.log(
	`==> wrote ${path.basename(config.baseline)}: ${rows.length} rows, ` +
		`${rows.filter(r => r.endsWith('-1')).length} of them not measured this run.`
);
