#!/usr/bin/env node
// The pa11y driver: one Chromium, one fresh context per row, real cookies.
//
//   node scripts/pa11y-run.js <node_modules-dir> <report.json>
//
// ## Why this exists rather than `pa11y-ci` doing the whole job
//
// pa11y-ci is the queue, the reporter and the exit code. It cannot set a cookie,
// and this application's theme is applied by JavaScript **reading
// `document.cookie`** — `web/static/app.js`'s watchTheme() copies
// `semiplane_theme` onto `documentElement` and the stylesheet's custom dark
// variant reads that class. Three consequences, each established by measurement
// rather than by reading the docs:
//
//   1. pa11y 9 has no `cookies` option at all. It is not documented and it is
//      not implemented; passing one is silently ignored. The first run of this
//      gate did that, every authenticated row was answered 303 to the login
//      form, and pa11y-ci reported **10/10 URLs passed** — the login form is an
//      accessible login form.
//   2. A `Cookie` *request header*, which is pa11y's documented alternative,
//      gets the session through and the theme still does not arrive: a request
//      header is not in the browser's cookie jar, so `document.cookie` is empty
//      to the page. Measured: with a `Cookie` header the root element's class
//      list is `""` and the computed `color-scheme` is `dark` for *both* the
//      light row and the dark row. Two theme rows that are one measurement.
//   3. pa11y-ci overwrites any `browser` a per-URL config supplies
//      (`config.browser = testBrowser.createBrowserContext()`), so a config
//      cannot smuggle in a context whose cookies were set by the driver
//      either. pa11y 9's `setBrowser` *does* accept a pre-configured browser and
//      page; only pa11y-ci's wrapper removes that door.
//
// So the queue is replaced by sixty lines and the engine is not: this requires
// `pa11y` (which is what pa11y-ci requires in turn, and which is what actually
// runs axe and HTML CodeSniffer) and drives it directly. pa11y-ci is still
// installed at the version tools/versions.env pins, and the browser it would
// have launched is the browser this launches.
//
// The routes, the themes, the standard, the runner list and the unreachable-route
// accounting all live in pa11y.config.js, which is the committed config and the
// thing a reader should change.
//
// ## What is checked beyond pa11y's own verdict
//
// Three things, and each of them is a thing a green run must not be able to say
// by accident:
//
//   1. **The page is the page.** Every row records the URL pa11y reports it
//      tested, so a row that was redirected is a row that audited something
//      else.
//   2. **The session reached the browser.** A 303 to the login form is usually a
//      redirect the URL check above catches — the login form is a real page at a
//      real URL — but not always, so each row also counts the login forms in the
//      document it ended on. No signed-in page has one, and the anonymous row is
//      required to have one: two-sided, because a check that only ever asserted
//      "no login form" would pass on a document that rendered nothing at all.
//      That is exactly the vacuous pass this gate has already produced twice.
//      What it deliberately does *not* assert is that a signed-in page carries
//      the shell's logout form: a plugin mount is a document without the shell,
//      and a control that assumes the shell is a control measuring a proxy. It
//      failed on `/plugin/houserules` for exactly that reason.
//   3. **The theme reached the browser.** The root element's class is read back
//      and compared with the row's declared theme. Without this, a dark row that
//      was really measured in light is indistinguishable from a dark row that was
//      not, and both are reported as clean.
//
// The session cookie is `HttpOnly` (internal/httpapi/middleware.go), so it
// cannot be read back out of `document.cookie` — hence the form count rather
// than a cookie read.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const modulesDir = process.argv[2];
const reportPath = process.argv[3];
if (!modulesDir || !reportPath) {
	console.error('usage: pa11y-run.js <node_modules-dir> <report.json>');
	process.exit(2);
}

// Required by absolute path, from the throwaway install scripts/pa11y.sh made.
// The repository has no node_modules of its own and must not grow one: nothing
// in the build, the stylesheet or the test suite uses Node.
const puppeteer = require(path.join(modulesDir, 'puppeteer'));
const pa11y = require(path.join(modulesDir, 'pa11y'));

const config = require(path.join(__dirname, '..', 'pa11y.config.js'));

async function main() {
	const browser = await puppeteer.launch(config.defaults.chromeLaunchConfig || {});
	const results = {};
	const landed = {};
	const control = {};
	let errors = 0;
	let passes = 0;

	try {
		for (const row of config.rows) {
			// A context per row, not just a page: an incognito context has its own
			// cookie jar, so the theme one row set cannot reach the next row. A
			// shared context would make the dark run a second light run whenever
			// the second row's cookie were not written, which is exactly the
			// failure this file is here to prevent.
			const context = await browser.createBrowserContext();
			try {
				if (!row.anonymous) {
					await context.setCookie({
						name: config.sessionCookie,
						value: process.env.SEMIPLANE_SESSION,
						url: config.baseURL,
						path: '/',
					});
				}
				// Always, for every row including the anonymous one: the theme is a
				// preference and the walk is about both themes, not about the
				// stranger's OS.
				await context.setCookie({
					name: config.themeCookie,
					value: row.theme,
					url: config.baseURL,
					path: '/',
				});

				const page = await context.newPage();
				const result = await pa11y(row.url, {
					// pa11y's setBrowser takes a pre-configured browser and
					// setPage takes a pre-configured page, and when both are given
					// it uses them and closes neither. That is the door pa11y-ci
					// closes; the engine behind it is unchanged.
					browser,
					page,
					standard: config.defaults.standard,
					runners: config.defaults.runners,
					viewport: config.defaults.viewport,
					timeout: config.defaults.timeout,
					log: { debug() {}, error() {}, info() {} },
				});

				// pa11y 9's promise form resolves a result object — {pageUrl,
				// documentTitle, issues} — and not the bare array its callback form
				// hands over. `pageUrl` is the URL it tested, which is the page
				// the verdict belongs to, so it is a better answer than reading
				// page.url() here: it is the engine's own account of where it was.
				landed[row.url] = result.pageUrl;
				results[row.url] = result.issues;
				control[row.url] = await page.evaluate(() => ({
					// app.js writes the resolved theme onto the root element, so this
					// is the browser's own answer to "which theme is this page in"
					// rather than the cookie the driver set.
					themeClass: document.documentElement.className,
					// The shell's own answer to "is this a signed-in page". Only the
					// login form is counted, and only as something a signed-in page
					// must not have; see the header for why the logout form is not.
					loginForms: document.querySelectorAll('form[action="/login"]').length,
					title: document.title,
				}));
				if (result.issues.length === 0) {
					passes++;
				} else {
					errors += result.issues.length;
				}
				await page.close();
			} catch (error) {
				// A row that could not run is a row that did not pass, and it is
				// reported as an issue on the URL that was requested so the report
				// cannot be read as if the page had been found accessible.
				landed[row.url] = '(no page)';
				control[row.url] = null;
				results[row.url] = [
					{ code: 'row-failed', message: String(error && error.message), selector: '' },
				];
				errors++;
			} finally {
				await context.close();
			}
		}
	} finally {
		await browser.close();
	}

	fs.writeFileSync(
		reportPath,
		JSON.stringify(
			{ total: config.rows.length, passes, errors, landed, control, results },
			null,
			1
		)
	);
	process.exit(errors > 0 ? 2 : 0);
}

main().catch(error => {
	console.error(`pa11y-run.js: ${error && error.stack ? error.stack : error}`);
	process.exit(1);
});
