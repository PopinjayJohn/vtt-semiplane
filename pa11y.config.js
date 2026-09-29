// The accessibility gate's configuration: the routes, the themes, the standard,
// the runner list, and the accounting for a route the server refuses.
//
// It is a JavaScript module rather than JSON because of the one thing a JSON
// config cannot do: read the environment. A session token is a bearer value that
// exists only in the response to a real /setup POST, and five of the six routes
// below are behind a permission an anonymous request does not hold — a walk
// without a cookie measures the login form and reports it as a clean page. A
// token pasted into a committed JSON config is a credential in git; here it is
// read from the environment, and the file refuses to load at all without it
// rather than walking nothing and calling it a pass.
//
// Run it with scripts/pa11y.sh, which boots a real binary, claims the first
// administrator through the real form, and hands the result to
// scripts/pa11y-run.js. Running this file with nothing set throws, on purpose;
// see `requireEnv` below.
//
// ## The gate is a ratchet, not a threshold
//
// `.pa11y-baseline` holds one measured error count per route per theme. A count
// that gets worse fails and prints both numbers; a count that gets better passes
// and says to re-record it; a count that is equal passes. A threshold of zero
// would be the purer claim and it would be a permanently red gate on a codebase
// that has real findings — and a red light nobody reads is worse than a tracked
// number. This is the shape `make coverage-check` uses, for the same reason: a
// statement about a *change* is enforceable, an absolute level is not.
//
// ## pa11y-ci, and where it stops
//
// pa11y-ci is the tool the plan names, and the version tools/versions.env pins
// is the one that gets installed. It cannot be the thing that runs this walk,
// for a reason worth knowing rather than working around quietly: this
// application's theme is applied by web/static/app.js **reading
// `document.cookie`**, pa11y 9 has no `cookies` option at all, pa11y's
// documented alternative — a `Cookie` request header — does not put a cookie in
// the browser's jar and so is invisible to that script, and pa11y-ci overwrites
// any `browser` a config supplies. So the row count and the theme rows above
// would be real but the theme would be one measurement presented as two.
// scripts/pa11y-run.js is that queue, with the one thing pa11y-ci lacks; the
// engine underneath is pa11y itself, which is what pa11y-ci requires in turn.
//
// ## What this file is and is not
//
// These are the Go-side markup assertions, and they are NOT an audit:
//
//   internal/web/shell_test.go  TestEveryPageHasOneH1AndLandmarks
//                              TestSkipLinkIsTheFirstFocusableElement
//                              TestEveryIconOnlyButtonHasAName
//                              TestTabsBindSelectionToOneSignal
//                              TestAPagesBodyCannotAddASecondH1
//   internal/web/icons_test.go  TestEveryReferencedIconIsDefinedInTheSprite
//
// Those read rendered markup. They know nothing about colour contrast, because
// a contrast failure is a relationship between two computed styles rather than
// a property of either, and nothing at all about whether a colour pair resolves
// under the *other* theme — which is the whole reason the two runs below are
// separate rows rather than one run. They are complementary: they catch a
// second `<h1>` in CI in a second and on every `go test`, where a browser does
// not; this catches what only a browser can see. Neither substitutes for the
// other, and a green Go suite is not a passing audit.
//
// ## The standard
//
// `WCAG2AA` is the only AA string pa11y 9 accepts — its `allowedStandards` are
// WCAG2A, WCAG2AA and WCAG2AAA, and there is no `WCAG21AA`. That is a spelling
// rather than a coverage gap: pa11y 9's axe runner builds its `runOnly` tag set
// as wcag2a, wcag21a, wcag2aa, wcag21aa and best-practice unconditionally, so
// **WCAG 2.1 A and AA are both covered** by the `WCAG2AA` string. Note the fifth
// tag: axe best-practice rules are in scope too, which makes the claim stronger
// than WCAG and means a failure may be a best-practice finding rather than a
// conformance one.
//
// Both of pa11y's default runners are named explicitly rather than inherited,
// because "the default" is a decision nobody made: axe for the rules and the
// best-practice set, and HTML CodeSniffer for the WCAG success criteria
// themselves, which is what emits the `WCAG2AA.Principle1.Guideline1_1…` codes a
// conformance finding is identified by. An axe's own rules are named by their
// rule id instead (`color-contrast`, `link-name`). Both runners report, so a
// failure says which produced it.
//
// Warnings and notices are off, which are pa11y's defaults: the gate is on
// errors, and every error counts. A single error on a single row is compared
// against that row's recorded number rather than against zero — see the ratchet
// paragraph at the top.

const path = require('node:path');

const THEMES = [
	{ name: 'light', cookie: 'semiplane_theme', value: 'light' },
	{ name: 'dark', cookie: 'semiplane_theme', value: 'dark' },
];

// The routes, and why each one is here.
//
// `/p/…` and `/plugin/houserules` are the two the earlier accept items name. The
// other four are here because a claim of "4 routes" that silently covers a page
// view and a plugin index and nothing else is a claim about two pages, not about
// the app: `/` is the first screen every reader sees, `/search` is the only form
// with a live result list, `/tags` is the only list surface, and `/login` is the
// only route a stranger can reach at all.
const ROUTES = [
	{
		path: '/',
		what: 'the dashboard: the sidebar, the nav group a plugin contributes, and the file tree',
	},
	{
		path: '/p/Campaigns/Ash/Page-0000.md',
		what: 'a page view: frontmatter, three headings, fifteen wikilinks, the aside column, and a secret fence this account may read',
	},
	{
		path: '/plugin/houserules',
		what: 'the houserules plugin index — the route the earlier accept item names, behind PermSession',
		// This route carries `class="dark-forced"` on <html> and loads no script, so
		// the class is permanent and the page is dark whatever the cookie says.
		// Auditing a "light" row here would be one measurement printed twice —
		// the exact defect this gate has produced three times now — so the row is
		// declared with the theme the page actually renders in, and
		// scripts/pa11y-report.js still asserts that the root element carries it.
		// If the plugin ever stops forcing its theme the control fails, loudly,
		// and the route goes back to two rows.
		forcedTheme: 'dark-forced',
	},
	{
		path: '/search?q=vault',
		what: 'the search page: a labelled form, a result list, and a highlighted snippet',
	},
	{
		path: '/tags',
		what: 'the tag index: a list of links and nothing else',
	},
	{
		path: '/login',
		what: 'the only route a stranger reaches, so it is the one walked with no session at all',
		anonymous: true,
	},
];

function requireEnv(name) {
	const value = process.env[name];
	if (!value) {
		// Loud, and fatal. A config that quietly falls back to an empty URL list,
		// or to a walk with no cookie, is a gate that reports success for having
		// audited nothing — and that is the one failure mode this whole file
		// exists to make impossible.
		throw new Error(
			`pa11y.config.js: ${name} is not set. Boot a server and claim the ` +
				'first administrator with scripts/pa11y.sh; nothing here works ' +
				'without a real session, because /p/…, /plugin/houserules, /, ' +
				'/search and /tags are all behind a permission an anonymous ' +
				'request does not hold.'
		);
	}
	return value;
}

const baseURL = requireEnv('SEMIPLANE_BASE_URL').replace(/\/+$/, '');
const session = requireEnv('SEMIPLANE_SESSION');

const SESSION_COOKIE = 'semiplane_session';

// SEMIPLANE_UNREACHABLE is a comma-separated list of route paths that the server
// refused to serve to the account this walk signs in as.
//
// It exists because a route can be unreachable for a reason that has nothing to
// do with accessibility, and a walk that quietly dropped it would report "clean"
// over five routes while the claim it exists to support says six. scripts/pa11y.sh
// probes every route first and sets this; the point of the list is that a skip is
// a *named, visible* fact in the run's output rather than a hole in it.
//
// Three rules keep it from becoming the thing it exists to prevent:
//
//   - a name in the list that is not a route in ROUTES is a hard error, so the
//     list cannot rot into a no-op after a route is renamed;
//   - the skip is printed to stderr, in the run's own output, before the walk;
//   - a skipped route is reported against its baseline row rather than silently
//     dropping that row's number, so a router bug cannot turn an error into a
//     zero by making the page unmeasurable (scripts/pa11y-report.js, SKIPPED).
//
// **The list is empty.** The previous run carried `/plugin/houserules` here,
// because `mountPluginRoutes` applied the CSRF gate to the whole mounted
// sub-router rather than to a mutating method and answered 403 to every GET. That
// is fixed (`checkCSRFOnMutations` in internal/httpapi/middleware.go), the route
// probes 200 to the administrator this walk signs in as, and it is measured in
// both themes. The mechanism above stays: it is a standing guard for the next
// route that is unreachable for a reason that is not an accessibility result, and
// a gate that has never been able to report one has not been tested.
const unreachable = new Set(
	(process.env.SEMIPLANE_UNREACHABLE || '')
		.split(',')
		.map(p => p.trim())
		.filter(p => p !== '')
);
for (const skipped of unreachable) {
	if (!ROUTES.some(r => r.path === skipped)) {
		throw new Error(
			`pa11y.config.js: SEMIPLANE_UNREACHABLE names ${skipped}, which is not ` +
				'a route in ROUTES. A skip list that can name a route that does not ' +
				'exist is a skip list that can silently stop skipping.'
		);
	}
}

// withTheme appends the theme as a query parameter.
//
// It is inert — no route on this list reads it, and the request log redacts the
// query string anyway — and it exists so that each row's URL is unique. Without
// it a report groups the light and the dark run of the same route under one
// heading, and a dark-theme contrast failure is then reported as a failure of a
// URL that was measured twice with the light theme's colours. A report that
// cannot name which run failed is a report nobody can act on.
function withTheme(path, themeName) {
	return `${baseURL}${path}${path.includes('?') ? '&' : '?'}__theme=${themeName}`;
}

// The rows, and the rows the walk did not get to.
//
// `allRows` is the full cross product, built before the unreachable filter, and
// `rows` is what survived it. scripts/pa11y-report.js compares the two: a route
// that was skipped is reported against its baseline row as SKIPPED, so the
// ratchet cannot be satisfied by a page becoming unmeasurable. Building both from
// one loop is also what keeps a new route from arriving with a baseline row that
// nothing ever produces.
const allRows = [];
const rows = [];
let skipped = 0;
for (const route of ROUTES) {
	for (const theme of route.forcedTheme ? [{ name: route.forcedTheme, value: route.forcedTheme }] : THEMES) {
		allRows.push({
			// /login deliberately gets no session: it is the row that is supposed to
			// be anonymous, and sending it one would audit the signed-in variant of
			// the page whose accessibility claim is about the form a stranger sees.
			path: route.path,
			url: withTheme(route.path, theme.name),
			theme: theme.value,
			anonymous: Boolean(route.anonymous),
		});
	}
	if (unreachable.has(route.path)) {
		skipped++;
		process.stderr.write(
			`pa11y.config.js: NOT COVERED  ${route.path}  (${route.what})\n` +
				'  the server refused this route to the account the walk signs in as.\n' +
				'  It is absent from the run and from every count below; the claim this\n' +
				'  walk supports does not include it.\n'
		);
	}
}
for (const row of allRows) {
	if (!unreachable.has(row.path)) rows.push(row);
}

// Half the routes went uncovered: the walk would report a pass over a quarter of
// what it names, which is the shape of a gate nobody should trust. A named claim
// is either measured or the run says so loudly enough that nobody can call it a
// pass.
if (skipped * 2 > ROUTES.length) {
	throw new Error(
		`pa11y.config.js: ${skipped} of ${ROUTES.length} routes are unreachable, so ` +
			'more than half the walk is missing. That is a broken server, not an ' +
			'accessibility result; fix it before reading anything this run reports.'
	);
}

module.exports = {
	baseURL,
	sessionCookie: SESSION_COOKIE,
	themeCookie: THEMES[0].cookie,
	rows,
	allRows,
	// The committed ratchet: one line per route per theme, and the error count
	// that was measured when it was recorded. Named here rather than hard-coded
	// in the reader because a path written down twice is a path that can be
	// wrong once.
	baseline: path.join(__dirname, '.pa11y-baseline'),
	// The routes to prove reachable before handing twelve browser contexts to them,
	// derived rather than written out.
	//
	// A hand-maintained probe list is a second copy of ROUTES, and the failure it
	// produces is the one this whole gate exists to prevent: a route that 403s is
	// not redirected, so its row is reported under the URL that was requested and
	// the Forbidden page is audited in the route's place — the same "measured
	// something else" as the login-form run, reached by omission instead of by a
	// cookie that was ignored. scripts/pa11y.sh reads this list, so adding a
	// route to ROUTES adds its probe in the same edit.
	probes: ROUTES.filter(r => !r.anonymous).map(r => r.path),
	defaults: {
		standard: 'WCAG2AA',
		runners: ['axe', 'htmlcs'],
		// 30s. A page render is single-digit milliseconds, so anything near this is
		// a boot that had not finished, and a timeout reported as an accessibility
		// error is a finding about the harness.
		timeout: 30000,
		viewport: { width: 1280, height: 900 },
		// Undefined unless PA11Y_CHROME names a Chrome. Left as the escape hatch
		// pa11y 4 documents for a runner where puppeteer's downloaded browser is
		// not the one on the PATH, and deliberately not set to anything: a
		// hard-coded browser path is a path that stops existing.
		chromeLaunchConfig: process.env.PA11Y_CHROME
			? { executablePath: process.env.PA11Y_CHROME }
			: undefined,
	},
};
