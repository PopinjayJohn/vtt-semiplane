package httpapi_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
)

// matrixRoute is one row of the table the authorization matrix walks.
//
// It names both the route *pattern* from the table and a concrete *path* that
// fills the pattern in, because the two answer different questions: the pattern
// is what coverage is checked against, and the path is what a request is built
// from. TestTheMatrixCoversEveryRoute compares the pattern sets, so a route
// added to the table and forgotten here is a failure.
type matrixRoute struct {
	// name is the subtest label.
	name string
	// method and pattern identify the row of the route table.
	method  string
	pattern string
	// path fills the pattern in.
	path string
	// form is the body for a mutation. It carries every field a form of this
	// shape needs, so a refusal is about authorization and not about a parameter
	// the handler never read.
	form url.Values
	// openToAnonymous is the status a principal with no session gets when
	// anonymous read is on.
	openToAnonymous int
	// closedToAnonymous is the status a principal with no session gets when
	// anonymous read is off. It is 303 for a safe request, because a safe
	// request can be sent to the login form and come back; a mutation cannot,
	// because a redirected POST loses its body and a retry would be an untokened
	// mutation.
	closedToAnonymous int
	// authenticated is the status a signed-in principal of any role gets.
	authenticated int
	// byRole overrides that, per role name, for the rows whose answer depends on
	// which role is asking rather than on whether there is a session.
	//
	// It exists because /admin/plugins is the first route in this table whose
	// answer is role-dependent: every earlier row is "signed in, or not", which
	// one field can express. An admin-only surface is "admin, or not", and folding
	// that into `authenticated` would have meant either asserting 200 for a dm —
	// which is the bug this field prevents — or exempting the row from the table,
	// which is the hole AGENTS.md §2.7 is about.
	//
	// A role absent from the map gets `authenticated`. That default is the safe
	// one: a new role added to matrixRoles is checked against the ordinary answer
	// and fails loudly if the route should have refused it.
	byRole map[string]int
	// extra marks a row that is not a row of the table.
	extra bool
	// timeout bounds the request for a route whose response never ends. The
	// status line is written before such a response begins, so the deadline still
	// observes the authorization decision — which is all a matrix row asks of it.
	timeout time.Duration
}

// The status codes a matrix row asserts. Only four answers exist, and each is
// one of them:
//
//   - 200: allowed.
//   - 303: allowed by a redirect the router chose. An unauthenticated safe
//     request for something that needs an account is sent to the login form, and
//     a sign-out is sent to it too.
//   - 403: refused by the policy, with the route's existence not in question.
//   - 404: the route is not there for this principal, or the resource is not
//     there at all. The two are deliberately indistinguishable: a page a viewer
//     may not read must not be confirmable by its status code.
//
// 429 never appears here, because a matrix that tripped the rate limiter would
// be testing the limiter; TestRateLimitRefusesTheEleventhLoginInAMinute tests
// that instead.
const (
	ok200 = http.StatusOK
	ok303 = http.StatusSeeOther
	no403 = http.StatusForbidden
	no404 = http.StatusNotFound
)

// Method is the row's HTTP method, named for the coverage check.
func (r matrixRoute) Method() string { return r.method }

// matrixRoutes is every route in the table.
//
// The /setup rows are here as well, and their answers differ by whether an
// account exists rather than by role, so their expectation is a function of the
// fixture's state rather than a constant.
var matrixRoutes = []matrixRoute{
	{name: "dashboard", method: http.MethodGet, pattern: "/", path: "/", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "page", method: http.MethodGet, pattern: "/p/*", path: "/p/Index.md", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	// The two "there is nothing here" rows answer 303 rather than 404 to a
	// principal with no session, and that is the stronger property: the route
	// gate runs before the handler, so an unauthenticated request cannot tell a
	// page that does not exist from a page it may not read, because it is sent to
	// the login form for both.
	{name: "page that does not exist", method: http.MethodGet, pattern: "/p/*", path: "/p/Nope.md", authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	{name: "page traversal", method: http.MethodGet, pattern: "/p/*", path: "/p/../../etc/passwd", authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// A signed-in visitor is sent to the campaign instead of being shown a second
	// way in, so that following a stale bookmark to /login lands somewhere
	// useful. An anonymous one gets the form, which is the whole point of it.
	{name: "login form", method: http.MethodGet, pattern: "/login", path: "/login", authenticated: ok303, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "logout", method: http.MethodPost, pattern: "/logout", path: "/logout",
		form: url.Values{"csrf": {"{csrf}"}}, authenticated: ok303, openToAnonymous: no403, closedToAnonymous: no403},
	// The three pre-session forms. Their permission is PermNone, which is
	// deliberate: a visitor who cannot sign in is exactly the person who has to
	// be able to reach the form, and a form that is gated on being able to read
	// the campaign locks out the accounts configured not to be able to.
	{name: "login submit", method: http.MethodPost, pattern: "/login", path: "/login",
		form:          url.Values{"username": {playerName}, "passphrase": {playerPass}, "csrf": {"{csrf}"}},
		authenticated: ok303, openToAnonymous: ok303, closedToAnonymous: ok303},
	{name: "setup submit", method: http.MethodPost, pattern: "/setup", path: "/setup",
		form:          url.Values{"username": {"someone"}, "passphrase": {"a passphrase long enough"}, "csrf": {"{csrf}"}},
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: no404},
	{name: "invite accept", method: http.MethodPost, pattern: "/invite/{token}", path: "/invite/whatever",
		form:          url.Values{"username": {"someone"}, "passphrase": {"a passphrase long enough"}, "csrf": {"{csrf}"}},
		authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "setup before bootstrap", method: http.MethodGet, pattern: "/setup", path: "/setup", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "invite form", method: http.MethodGet, pattern: "/invite/{token}", path: "/invite/whatever", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "search", method: http.MethodGet, pattern: "/search", path: "/search?q=lantern", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "search api", method: http.MethodGet, pattern: "/api/search", path: "/api/search?q=lantern", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	// The contextual-navigation surfaces. All four are PermAnonRead, so an
	// anonymous reader with the flag on sees the campaign's structure and one with
	// it off is sent to the login form — the same three answers as /search, and for
	// the same reason: a tag, a file tree and a command palette are all public
	// navigation over content the reader can already read.
	{name: "tags", method: http.MethodGet, pattern: "/tags", path: "/tags", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	// A tag nobody carries, and a tag every page of which is hidden from this
	// reader, are deliberately the same answer: 200 with no rows. A 404 would say
	// "this tag does not exist", which is a statement about the campaign that a
	// reader with no right to the tag's pages is not entitled to, and the two
	// would differ only in whether the reader guessed right. The row is here to
	// pin that, because the other row above it pins the case where the tag does
	// exist and this reader can see a page under it.
	{name: "tag that does not exist", method: http.MethodGet, pattern: "/tag/{name}", path: "/tag/nothing-carries-this", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "files", method: http.MethodGet, pattern: "/files", path: "/files", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	// The context column in one call. It is PermReadPage, and the page id is a
	// real one, so this row is asserting that the right to read a page is also the
	// right to read what links to it and what is on it.
	{name: "page context api", method: http.MethodGet, pattern: "/api/pages/{id}/context", path: "/api/pages/1/context", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "page context api for a page that does not exist", method: http.MethodGet, pattern: "/api/pages/{id}/context", path: "/api/pages/999999/context", authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// The command palette is PermSession, and both anonymous answers are the
	// login redirect: the palette is an affordance for somebody who has signed in,
	// not a capability anonymous read grants.
	{name: "commands", method: http.MethodGet, pattern: "/_/commands", path: "/_/commands?q=lantern", authenticated: ok200, openToAnonymous: ok303, closedToAnonymous: ok303},
	// The live-update stream, with a deadline because its response is written
	// incrementally and never ends. The row exists to prove the gate, not the
	// stream: the status line is on the wire before the first trigger would be.
	{name: "events", method: http.MethodGet, pattern: "/_/events", path: "/_/events?page=Index.md", timeout: 2 * time.Second,
		authenticated: ok200, openToAnonymous: ok303, closedToAnonymous: ok303},

	// The boot report. Admin-only, and unlike the anonymous rows above both
	// anonymous answers are 403 rather than 303: /admin/plugins is not a
	// navigation target, so there is nothing to redirect a reader to and
	// answering 303 would confirm that the path is a real one.
	// The one row in the table whose answer is a role rather than a session, and
	// the reason `byRole` exists. A dm is not an admin: the plan's matrix says
	// admin implies dm, never the other way round, and a table that could only
	// say "signed in" would have papered over that by asserting 200 for a dm.
	//
	// The anonymous answers are 303, not 403, and that is the whole answer for a
	// principal with no session: a safe request can be sent to the login form and
	// come back. 403 is reserved for a principal who *is* signed in and is still
	// refused, because a 303 tells an anonymous client "sign in and ask again"
	// while a 403 tells it "this exists and you may not have it". An admin surface
	// must not be the thing that teaches that difference.
	{name: "admin plugins", method: http.MethodGet, pattern: "/admin/plugins", path: "/admin/plugins",
		authenticated: ok200, openToAnonymous: ok303, closedToAnonymous: ok303,
		byRole: map[string]int{
			"dm":                         no403,
			"player who owns the tavern": no403,
			"player who owns nothing":    no403,
		}},
	// A link preview's content. It is PermReadPage, and there are two rows
	// because there are two answers that must not be told apart: a page the
	// viewer may read, and one they may not. A summary that refused the second
	// with a body of its own would be a way to probe for pages, which is the
	// whole reason the route is core-owned — the byte-identity is in
	// TestTheSummaryRouteDeclinesInEveryWayThatIsNotYes, and this pair is what
	// pins the statuses the router gives for each.
	{name: "page summary", method: http.MethodGet, pattern: "/plugin/{id}/summary/{pageID}", path: "/plugin/linkpreview/summary/1",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// A build with no linkpreview plugin. The route exists whether or not a
	// plugin registered a provider, and a request for it is a 404 rather than a
	// 405 — a build with no previews is a working build, and its summary route
	// answering "there is nothing here" is that.
	{name: "page summary with no provider registered", method: http.MethodGet, pattern: "/plugin/{id}/summary/{pageID}", path: "/plugin/nosuchplugin/summary/1",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},

	// The page-scoped surfaces of §9.2–§9.4. Each is one row of the route table
	// with its own address, which is also the URL a reader types; all of them
	// mount on the one chi catch-all and are told apart by their trailing
	// segments, which pagedispatch.go explains and catchall_test.go measures.
	//
	// The three /p/*/edit rows are the coarse gate, and the middle one is the
	// whole cost of it: PermWritePage is asked by the permit middleware with a
	// zero Resource, so authz sees no ownership and a player who owns the page
	// and a player who owns nothing are refused identically. That is a DM-or-
	// admin gate wearing a page-scoped permission's name, and it is why the two
	// write rows below are PermSession with the page-scoped decision made inside
	// the handler.
	//
	// The byRole pair is the row that makes the property enforced rather than
	// argued: a page owner is allowed to open the editor for her own page and a
	// player who owns nothing is refused by the same handler, one page apart. It
	// cannot be written as a single `authenticated` value, and the day somebody
	// moves the ownership check back into the table it fails here rather than
	// quietly narrowing the feature.
	{name: "page raw", method: http.MethodGet, pattern: "/p/*/raw", path: "/p/Tavern.md/raw",
		authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "page raw for a page that does not exist", method: http.MethodGet, pattern: "/p/*/raw", path: "/p/Nonexistent.md/raw",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// An anonymous principal is answered with the login redirect rather than a
	// 403 whatever the route's permission is: a safe request can be sent to the
	// login form and come back, and a 403 would teach an anonymous client that
	// the path is a real one. checkPerm decides that, in the middleware, for
	// every route at once.
	{name: "page editor", method: http.MethodGet, pattern: "/p/*/edit", path: "/p/Tavern.md/edit",
		authenticated: ok200, openToAnonymous: ok303, closedToAnonymous: ok303,
		byRole: map[string]int{
			"player who owns the tavern": ok200,
			"player who owns nothing":    no403,
		}},
	// A page that does not exist is a 404 for a principal the gate admits and a
	// 403 for one it does not. Which is the order the two run in: the page-scoped
	// check is inside the handler and it is the first thing the handler does, so a
	// player never learns whether the page is there.
	//
	// The two anonymous answers are 303 for a GET and 403 for a POST, which is
	// checkPerm's rule and not this test's: a redirected POST loses its body, so
	// only a safe request is offered the login form. The disabled player is a
	// POST-shaped 403 for the same reason — its session is never established, so
	// it is an unauthenticated principal, and a mutation by one is refused
	// rather than redirected.
	// A page that does not exist is a 404 for everybody, and that is not a
	// compromise on the ordering. A principal who cannot write a page is refused
	// with 403 rather than 404, because they have been let past the table's gate
	// and already know the page is there — but a page that is not there is
	// nobody's to own, so a player who does not own it has no more claim to it
	// than a DM does, and the page's existence is not a secret from either:
	// PermReadPage lets any signed-in reader open it, and it is in the file tree
	// and every backlink. The rule that would leak is the one this row is not
	// asserting — a 404 must not stand in for a 403 on a page that *is* there,
	// and the editor row above is what pins that.
	{name: "page editor for a page that does not exist", method: http.MethodGet, pattern: "/p/*/edit", path: "/p/Nonexistent.md/edit",
		authenticated: no404, openToAnonymous: ok303, closedToAnonymous: ok303,
		byRole: map[string]int{
			"player who owns the tavern": no404,
			"player who owns nothing":    no404,
		}},
	// A stale hash is refused with 400 and the file is unchanged, so the control
	// state a CSRF run leaves behind is the one every refusal after it expects.
	{name: "page save", method: http.MethodPost, pattern: "/p/*/edit", path: "/p/Tavern.md/edit",
		form:          url.Values{"base_hash": {"not-a-hash"}},
		authenticated: http.StatusBadRequest, openToAnonymous: no403, closedToAnonymous: no403,
		byRole: map[string]int{
			"player who owns the tavern": http.StatusBadRequest,
			"player who owns nothing":    no403,
			"disabled player":            no403,
		}},
	{name: "page history", method: http.MethodGet, pattern: "/p/*/history", path: "/p/Tavern.md/history",
		authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},
	{name: "page history for a page that does not exist", method: http.MethodGet, pattern: "/p/*/history", path: "/p/Nonexistent.md/history",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// A revision the page has not got. The indexer records no revision at boot,
	// so a fresh vault has none and the only answer available to a fixture is
	// the absence — which is also the answer a revoked one is, deliberately.
	{name: "page revision", method: http.MethodGet, pattern: "/p/*/revisions/{revID}", path: "/p/Tavern.md/revisions/999999",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	{name: "page revert", method: http.MethodPost, pattern: "/p/*/revert/{revID}", path: "/p/Tavern.md/revert/999999",
		authenticated: no404, openToAnonymous: no403, closedToAnonymous: no403,
		byRole: map[string]int{
			"player who owns the tavern": no404,
			"player who owns nothing":    no403,
			"disabled player":            no403,
		}},
	// An attachment the index has not recorded. The fixture vault holds an
	// image and the route still answers 404, because the name is resolved
	// against the attachments table and not against the filesystem: a name that
	// was never indexed is a name this route will not serve.
	{name: "page attachment", method: http.MethodGet, pattern: "/p/*/attachment/{name...}", path: "/p/Tavern.md/attachment/tavern-map.png",
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: ok303},
	// The broken-links panel. PermReadPage in the table, for the reason
	// broken.go gives: every row it shows is a page a reader may already open, so
	// it is navigation over content rather than content, and a reader who may
	// not read the campaign is sent to the login form. The open/closed pair
	// below is the same either way, because one policy case answers both — which
	// is exactly why the comment has to name the table rather than the answer.
	{name: "broken links", method: http.MethodGet, pattern: "/broken", path: "/broken",
		authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok303},

	// Renaming a page and the opt-in bulk link updater (§5.6), on the same
	// two-layer gate as the editor. The byRole pair is the assertion that makes
	// that gate honest: a page owner renames her own page and a player who owns
	// nothing is refused by the same handler. Page 3 is Tavern.md, which the
	// fixture grants thia ownership of, so the owner row is a real 200 against a
	// page that really is owned rather than a claim about a page nobody owns.
	//
	// The 404 rows are the other half: a page that is not there is a 404 for a
	// principal entitled to look and a 403 for one that is not, and the second
	// must not be reordered into a 404 by a handler that resolves the page before
	// it checks the principal.
	{name: "page rename", method: http.MethodPost, pattern: "/api/pages/{id}/rename", path: "/api/pages/3/rename",
		form:          url.Values{"new": {"The Drowned Lantern Inn"}},
		authenticated: ok200, openToAnonymous: no403, closedToAnonymous: no403,
		byRole: map[string]int{
			"player who owns the tavern": ok200,
			"player who owns nothing":    no403,
			"disabled player":            no403,
		}},
	{name: "page rename for a page that does not exist", method: http.MethodPost, pattern: "/api/pages/{id}/rename", path: "/api/pages/999999/rename",
		form:          url.Values{"new": {"Whatever"}},
		authenticated: no404, openToAnonymous: no403, closedToAnonymous: no403},
	// The preview is a read of the same decision and is checked per page rather
	// than per route, so an owner's preview of a page other people refer to
	// reports them as unwritable and still lists them.
	{name: "rename preview", method: http.MethodGet, pattern: "/api/pages/{id}/rename-preview", path: "/api/pages/3/rename-preview?new=The%20Inn",
		authenticated: ok200, openToAnonymous: ok303, closedToAnonymous: ok303,
		byRole: map[string]int{
			"player who owns the tavern": ok200,
			"player who owns nothing":    no403,
		}},
	{name: "rename preview for a page that does not exist", method: http.MethodGet, pattern: "/api/pages/{id}/rename-preview", path: "/api/pages/999999/rename-preview?new=Whatever",
		authenticated: no404, openToAnonymous: ok303, closedToAnonymous: ok303},
	{name: "link updater", method: http.MethodPost, pattern: "/api/pages/{id}/update-links", path: "/api/pages/3/update-links",
		form:          url.Values{"new": {"The Inn"}, "confirmed": {"true"}},
		authenticated: ok200, openToAnonymous: no403, closedToAnonymous: no403,
		byRole: map[string]int{
			"player who owns the tavern": ok200,
			"player who owns nothing":    no403,
			"disabled player":            no403,
		}},
	{name: "link updater for a page that does not exist", method: http.MethodPost, pattern: "/api/pages/{id}/update-links", path: "/api/pages/999999/update-links",
		form:          url.Values{"new": {"Whatever"}, "confirmed": {"true"}},
		authenticated: no404, openToAnonymous: no403, closedToAnonymous: no403},
	// An unconfirmed updater touches nothing and answers 400, which is the
	// property §5.6 relies on when it says the rewrite is "always an explicit,
	// previewed, diffed, permission-checked action".
	{name: "link updater without confirmation", method: http.MethodPost, pattern: "/api/pages/{id}/update-links", path: "/api/pages/3/update-links",
		form:          url.Values{"new": {"The Inn"}},
		authenticated: http.StatusBadRequest, openToAnonymous: no403, closedToAnonymous: no403},

	{name: "healthz", method: http.MethodGet, pattern: "/healthz", path: "/healthz", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "readyz", method: http.MethodGet, pattern: "/readyz", path: "/readyz", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "stylesheet", method: http.MethodGet, pattern: "/_/assets/*", path: "/_/assets/app.css", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "script", method: http.MethodGet, pattern: "/_/assets/*", path: "/_/assets/app.js", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "sprite", method: http.MethodGet, pattern: "/_/assets/*", path: "/_/assets/icons.svg", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "datastar", method: http.MethodGet, pattern: "/_/assets/*", path: "/_/assets/vendor/datastar.js", authenticated: ok200, openToAnonymous: ok200, closedToAnonymous: ok200},
	{name: "asset outside the table", method: http.MethodGet, pattern: "/_/assets/*", path: "/_/assets/../assets.go", authenticated: no404, openToAnonymous: no404, closedToAnonymous: no404},
	// extra marks a row that is not a route at all. It has no pattern, so the
	// coverage check skips it: it exists to prove the router's NotFound answer is
	// the same 404 the resource handlers produce, not to cover a route.
	{name: "unrouted url", method: http.MethodGet, pattern: "", path: "/admin/users", extra: true,
		authenticated: no404, openToAnonymous: no404, closedToAnonymous: no404},
}

// roleCase is one row of the authorization matrix: who is making the request,
// and what state the world is in for that row.
type roleCase struct {
	// name identifies the row. A failing subtest names it.
	name string
	// signIn is the account this row signs in as, or "" for none.
	signIn string
	// pass is that account's passphrase.
	pass string
	// disable turns the account off after the session was minted, which must
	// leave the client with a cookie that resolves to nothing rather than with a
	// session that fails later on a page.
	disable bool
	// anonymousRead turns --allow-anonymous-read on for the whole fixture, so the
	// anonymous rows are exercised both ways.
	anonymousRead bool
	// noAccounts leaves the vault without any account, which is the only state in
	// which /setup exists.
	noAccounts bool
	// signedIn reports whether the row ends up holding a session.
	signedIn bool
	// loginSubmit is the status the login submission answers for this role, when
	// it is not the same as the row's other answers.
	//
	// Only the disabled role needs it: a disabled account is refused, so its login
	// comes back as the form again rather than as the redirect a successful one
	// produces. That distinction is the point of the row — a disabled account that
	// got a 303 would have a session.
	loginSubmit int
}

// matrixRoles is every role, plus the two states that change what a role may see.
var matrixRoles = []roleCase{
	{name: "admin", signIn: adminName, pass: adminPass, signedIn: true},
	{name: "dm", signIn: dmName, pass: dmPass, signedIn: true},
	{name: "player who owns the tavern", signIn: playerName, pass: playerPass, signedIn: true},
	{name: "player who owns nothing", signIn: otherName, pass: otherPass, signedIn: true},
	{name: "disabled player", signIn: otherName, pass: otherPass, disable: true, signedIn: false, loginSubmit: ok200},
	{name: "anonymous with read off"},
	{name: "anonymous with read on", anonymousRead: true},
}

// TestAuthorizationMatrix is the single most important test in the project.
//
// It is a table over the authorization model of AGENTS.md §2 — every role, every
// state that changes what a role may see, and every route in the table — and it
// asserts the status code for every cell. Two of its cells are the ones the
// design exists for: a player who owns a page may read that page and must not
// read the dm secret on it, and an anonymous principal sees nothing
// content-bearing unless --allow-anonymous-read is on. Those are asserted here
// as statuses and then, where a status is not enough, promoted to their own
// tests below.
func TestAuthorizationMatrix(t *testing.T) {
	t.Parallel()
	// One fixture and one client per *role*, not per cell.
	//
	// The state the matrix depends on is the role, the accounts and the
	// anonymous-read setting — not the route — so a fixture per cell would boot
	// 133 vaults, migrate 133 schemas and spend 133 × 4 argon2id derivations to
	// assert the same 133 answers. That is not a faster test; it is a slower one
	// that is also less honest, because it makes every cell look independent when
	// the only thing that varies is which row of the table was asked about.
	//
	// The rows that do change the world are handled where they need to be: the
	// session's CSRF token is refreshed before every row, so a row that signs in
	// (POST /login) cannot leave the next row holding a token its own session has
	// stopped honouring.
	for _, role := range matrixRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, func(c *config.Config) { c.AllowAnonymousRead = role.anonymousRead })
			if !role.noAccounts {
				fx.accountsFor()
			}
			s := fx.newSession()
			raw := ""
			if role.signIn != "" {
				resp := s.login(role.signIn, role.pass)
				if resp.StatusCode != http.StatusSeeOther {
					body := s.read(resp)
					t.Fatalf("sign %s in: status %d, want 303\n%s", role.signIn, resp.StatusCode, body)
				}
				// Captured before the account is turned off, because a disabled
				// account's row is about a cookie that no longer resolves.
				raw = fx.cookieValue(s, httpapi.SessionCookie)
				if role.disable {
					fx.disable(role.signIn)
				}
			}
			for _, rt := range matrixRoutes {
				t.Run(rt.name, func(t *testing.T) {
					// A fresh client per row, holding its own copy of the session
					// token. A row that signs out therefore destroys only its own
					// session, and the next row is unaffected — which is what makes
					// one fixture per role sound rather than merely fast.
					// The token this row starts from, so that the adoption below can
					// tell "this row signed in again" from "this row was anonymous and
					// its login row gave it a session". Adopting the second would turn
					// the anonymous rows into signed-in rows, which is a different
					// question than the one they ask.
					before := raw
					row := fx.sessionFor(before)
					got, want := performMatrixRow(t, row, rt, role)
					if got != want {
						t.Errorf("%s %s as %s: status %d, want %d", rt.method, rt.path, role.name, got, want)
					}
					// A row that signed in again minted a new session and retired
					// the old one, so the next row has to arrive with the new token.
					// A browser's cookie jar does this by itself; a table that
					// held one token for every row would fail the row after a
					// successful login, and the failure would be about the table's
					// shape rather than about the router.
					if next := fx.cookieValue(row, httpapi.SessionCookie); before != "" && next != "" {
						raw = next
					}
				})
			}
		})
	}
}

// performMatrixRow performs one matrix request and computes what it should have
// answered.
//
// Two things decide the answer, and both are state rather than role: whether the
// principal holds a session, and whether the vault is configured to serve
// anonymous readers. A row that got either of them wrong would be a test of the
// test's own setup, so the answer is derived from the same two facts the server
// derives it from.
func performMatrixRow(t *testing.T, s *session, rt matrixRoute, role roleCase) (got, want int) {
	t.Helper()

	// /setup is a function of the vault's state, not of the role: it exists until
	// an account is claimed and is absent afterwards, for everyone.
	if rt.pattern == "/setup" && !role.noAccounts {
		return statusOf(s, rt, role), no404
	}
	if rt.pattern == "/login" && rt.method == http.MethodPost && role.loginSubmit != 0 {
		return statusOf(s, rt, role), role.loginSubmit
	}
	if role.signedIn {
		if want, ok := rt.byRole[role.name]; ok {
			return statusOf(s, rt, role), want
		}
		return statusOf(s, rt, role), rt.authenticated
	}
	if role.anonymousRead {
		return statusOf(s, rt, role), rt.openToAnonymous
	}
	return statusOf(s, rt, role), rt.closedToAnonymous
}

// statusOf performs a matrix request and returns the status code.
//
// The form is filled in for the role under test: {username} and {passphrase}
// become that role's own account, and {csrf} is the marker a form always carries
// (the real token travels in the header, the way a script would send it).
func statusOf(s *session, rt matrixRoute, role roleCase) int {
	c := &call{method: rt.method, path: rt.path, timeout: rt.timeout}
	if rt.form != nil {
		form := url.Values{}
		for k, v := range rt.form {
			form[k] = v
		}
		if role.signIn != "" {
			form.Set("username", role.signIn)
			form.Set("passphrase", role.pass)
		}
		c.form = form
	}
	resp := s.do(c)
	defer drain(resp)
	return resp.StatusCode
}

// statusOfRoute performs a route-table request with a valid token, for the CSRF
// test's control run.
func statusOfRoute(fx *fixture, s *session, rt httpapi.Route, method string, withToken bool) int {
	c := &call{method: method, path: concretePath(fx, rt), form: routeFormFor(fx, rt)}
	if !withToken {
		c.noCSRF = true
	}
	resp := s.do(c)
	defer drain(resp)
	return resp.StatusCode
}

// TestTheMatrixCoversEveryRoute fails when the route table and the matrix have
// drifted apart.
//
// This is the test that keeps the matrix honest. A route added to the table and
// forgotten in the matrix is a hole in the evidence, and a hole in the evidence
// is worse than a failing feature: the feature is not known to be safe.
func TestTheMatrixCoversEveryRoute(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)

	covered := make(map[string]int, len(matrixRoutes))
	for _, rt := range matrixRoutes {
		if rt.extra {
			continue
		}
		covered[rt.Method()+" "+rt.pattern]++
	}
	table := make(map[string]int, len(fx.Server.Routes()))
	for _, route := range fx.Server.Routes() {
		table[route.Name()]++
		if _, ok := covered[route.Name()]; !ok {
			t.Errorf("the authorization matrix has no row for %s (permission %q)", route.Name(), route.Perm)
		}
	}
	for key, n := range covered {
		if table[key] == 0 {
			t.Errorf("the matrix has a row for %s, which the route table does not contain", key)
		}
		// Two patterns carry several rows on purpose: one per file for the
		// assets, one per kind of absence for a page, one per answer for a tag,
		// for the context API, and for a link summary — a page the viewer may
		// read and one they may not, which have to be indistinguishable.
		// Anything else with two rows is a duplicate that would make a coverage
		// count a lie.
		//
		// The three page-scoped read surfaces are here for the same reason as
		// "page that does not exist": a 200 with an empty body and a 404 must not
		// be interchangeable, and the way to say that is to assert both. A raw
		// view of a page that is not there, an editor for one and a history list
		// for one are each two different answers to the same URL, and each pair
		// is the surface's own version of the page row's two absences.
		if n > 1 && key != "GET /p/*" && key != "GET /_/assets/*" &&
			key != "GET /tag/{name}" && key != "GET /api/pages/{id}/context" &&
			key != "GET /p/*/raw" && key != "GET /p/*/edit" && key != "GET /p/*/history" &&
			key != "POST /api/pages/{id}/rename" &&
			key != "GET /api/pages/{id}/rename-preview" &&
			key != "POST /api/pages/{id}/update-links" &&
			key != "GET /plugin/{id}/summary/{pageID}" {
			t.Errorf("the matrix has %d rows for %s", n, key)
		}
	}
}

// TestSetupRouteDisappearsAfterBootstrap covers the one route whose answer is a
// function of the database rather than of the role.
//
// The requirement is stronger than "refused": once an account exists the route
// must be indistinguishable from one that was never routed, or an outsider can
// confirm both that this is a semiplane and that it is already set up.
func TestSetupRouteDisappearsAfterBootstrap(t *testing.T) {
	t.Parallel()

	t.Run("the form exists on a vault with no accounts", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t)
		s := fx.newSession()
		if got := s.status(s.get("/setup")); got != http.StatusOK {
			t.Errorf("GET /setup before bootstrap: status %d, want 200", got)
		}
	})

	for _, name := range []string{"admin", "dm", "player", "anonymous"} {
		t.Run("absent afterwards for the "+name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t)
			fx.accountsFor()
			s := fx.newSession()
			switch name {
			case "admin":
				s = fx.asUser(adminName, adminPass)
			case "dm":
				s = fx.asUser(dmName, dmPass)
			case "player":
				s = fx.asUser(otherName, otherPass)
			}

			resp := s.do(s.get("/setup"))
			body := s.read(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET /setup after bootstrap as %s: status %d, want 404\n%s", name, resp.StatusCode, body)
			}
			other := s.do(s.get("/no-such-route-at-all"))
			otherBody := s.read(other)
			if other.StatusCode != http.StatusNotFound || otherBody != body {
				t.Errorf("GET /setup after bootstrap as %s is not byte-identical to an unrouted URL:\nsetup: %d, %d bytes\nunrouted: %d, %d bytes",
					name, resp.StatusCode, len(body), other.StatusCode, len(otherBody))
			}
		})
	}
}

// TestAWriterMayNotReadADMSecret is the matrix's most important single cell,
// promoted to its own test because it is the one people get wrong.
//
// A page owner has *authoring* rights on a page, not broadcast rights. Thia owns
// the Tavern page, so she reads the page and her own private secret, and she
// must not read the dm secret on the very page she owns — ownership is not a key
// that opens everything in the room.
//
// What ownership does buy, and what the phrase is about, is §8.4 rule 1: she may
// not *reveal* another author's private secret to the table. That is the rule
// this test was reaching for and it is asserted below, because a private secret
// written by somebody else on a page she co-owns is one she may read — §8.2 says
// so in a table, and a co-owned page is a shared room by construction. Reading it
// and broadcasting it to the table are different permissions and the difference
// between them is the whole content of the rule.
func TestAWriterMayNotReadADMSecret(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	t.Run("the owner reads the page but not the dm secret on it", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(playerName, playerPass).getOK("/p/Tavern.md")
		assertNoToken(t, body, "DM-BODY-TOKEN-7b1e4d", "the dm secret on a page the reader owns")
		if !strings.Contains(body, "Hidden") {
			t.Error("the owner saw no lock affordance at all for a secret she may not read")
		}
	})

	// §8.2's page-owner column for `private`, stated as its own case because it
	// is the one a reader of the policy is most likely to get backwards. The
	// previous version of this test asserted the opposite, and it passed for
	// three stages only because the fixture's ownership grant was written before
	// the reindex that dropped it, so the assertion was never exercised: a test
	// that cannot fail is worse than no test.
	t.Run("the owner reads another author's private secret on the page they share", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(playerName, playerPass).getOK("/p/Tavern.md")
		assertHasToken(t, body, "PRIVATE-BODY-TOKEN-9f3a2c",
			"another author's private secret on a page the reader owns")
	})

	t.Run("the owner reads her own private secret", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(playerName, playerPass).getOK("/p/Tavern.md")
		assertHasToken(t, body, "OWNER-BODY-TOKEN-2a6e10", "the reader's own private secret")
	})

	t.Run("a dm reads every secret on the page", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(dmName, dmPass).getOK("/p/Tavern.md")
		for _, want := range []string{
			"PRIVATE-BODY-TOKEN-9f3a2c",
			"DM-BODY-TOKEN-7b1e4d",
			"OWNER-BODY-TOKEN-2a6e10",
			"TABLE-BODY-TOKEN-5d0a8f",
		} {
			assertHasToken(t, body, want, "a secret a dm may read")
		}
	})

	t.Run("an admin reads every secret on the page", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(adminName, adminPass).getOK("/p/Tavern.md")
		for _, want := range []string{
			"PRIVATE-BODY-TOKEN-9f3a2c",
			"DM-BODY-TOKEN-7b1e4d",
			"TABLE-BODY-TOKEN-5d0a8f",
		} {
			assertHasToken(t, body, want, "a secret an admin may read")
		}
	})

	t.Run("a player who owns nothing reads nothing hidden", func(t *testing.T) {
		t.Parallel()
		body := fx.asUser(otherName, otherPass).getOK("/p/Tavern.md")
		for _, forbidden := range bodyTokens {
			if forbidden == tableToken {
				continue
			}
			assertNoToken(t, body, forbidden, "a secret on a page the reader does not own")
		}
		// The one body a player may read: a table-visible secret is for the table.
		assertHasToken(t, body, tableToken, "a table-visible secret")
	})
}

// TestADisabledAccountGetsNoSession is the "disabled" row of the matrix,
// promoted because the failure mode is subtle: the cookie is still presented,
// and the answer must be anonymous rather than a page with the content removed.
func TestADisabledAccountGetsNoSession(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()

	s := fx.asUser(playerName, playerPass)
	before := s.getOK("/p/Index.md")
	assertHasToken(t, before, "Index", "the dashboard page")

	fx.disable(playerName)

	// The cookie is still in the jar, so this request carries a session token
	// that no longer resolves. It must come back as anonymous, which for a page
	// is a redirect to the login form rather than a 403 that confirms the page
	// exists.
	resp := s.do(s.get("/p/Index.md"))
	drain(resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("a disabled account's session: status %d, want 303 to the login form", resp.StatusCode)
	}
	after := s.getOK("/login")
	if strings.Contains(after, "The Drowned Lantern") {
		t.Error("a disabled account was shown a page it can no longer read")
	}
}

// TestANonAdminIsRefusedAdminSurface is here because a test is what stops an
// /admin route appearing without a decision.
//
// Stage 1 wrote it as "no admin route is mounted", because there were none. That
// premise expired with /admin/plugins, and the correct response is to keep the
// test's purpose and replace its premise: the rule is not "there is no admin
// surface", it is "every admin surface is admin-only". The second is the rule
// that stays true as the surface grows, and it is checkable from the route table
// rather than from a list somebody has to remember to update.
func TestANonAdminIsRefusedAdminSurface(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	t.Run("every admin route is admin-only and refuses everyone else", func(t *testing.T) {
		t.Parallel()
		// A concrete path per route, because the table carries patterns and a
		// pattern with a {param} is not a path. A route added without a case here
		// is a route nobody has proved is gated, so the default is a failure
		// rather than a skip.
		paths := map[string]string{
			"GET /admin/plugins": "/admin/plugins",
		}
		var adminRoutes int
		for _, route := range fx.Server.Routes() {
			if !strings.HasPrefix(route.Pattern, "/admin") {
				continue
			}
			adminRoutes++
			if route.Perm != authz.PermAdmin {
				t.Errorf("%s is mounted at %q with %q, want %q: an admin surface that is not admin-only is the failure this test exists for",
					route.Name(), route.Pattern, route.Perm, authz.PermAdmin)
				continue
			}
			path, ok := paths[route.Method+" "+route.Pattern]
			if !ok {
				t.Errorf("%s is mounted at %q but this test has no path for it: add one, or the route is ungated as far as this suite knows", route.Name(), route.Pattern)
				continue
			}
			s := fx.asUser(playerName, playerPass)
			if got := s.status(s.get(path)); got != http.StatusForbidden {
				t.Errorf("GET %s as a player: status %d, want 403", path, got)
			}
			dm := fx.asUser(dmName, dmPass)
			if got := dm.status(dm.get(path)); got != http.StatusForbidden {
				t.Errorf("GET %s as a dm: status %d, want 403: the admin role is not a superset of dm", path, got)
			}
		}
		if adminRoutes == 0 {
			t.Fatal("no admin route is mounted, so this test proved nothing: /admin/plugins should be here by now")
		}
	})

	t.Run("an unmounted admin path is a 404, not a redirect", func(t *testing.T) {
		t.Parallel()
		// The distinction matters. A path under /admin that does not exist must
		// be indistinguishable from any other missing page, so that the existence
		// of the admin surface is not itself something a non-admin can probe.
		s := fx.asUser(playerName, playerPass)
		for _, path := range []string{"/admin", "/admin/users", "/admin/invites"} {
			if got := s.status(s.get(path)); got != http.StatusNotFound {
				t.Errorf("GET %s as a player: status %d, want 404", path, got)
			}
		}
	})

	t.Run("a player cannot create an invite", func(t *testing.T) {
		t.Parallel()
		who := authz.ForUser(fx.userID(playerName), playerName, authz.RolePlayer, false)
		if _, err := fx.Auth.CreateInvite(ctx, who, authz.RoleAdmin, 0); err == nil {
			t.Error("a player created an admin invite; the policy did not refuse it")
		}
	})

	t.Run("a dm cannot change a role", func(t *testing.T) {
		t.Parallel()
		who := authz.ForUser(fx.userID(dmName), dmName, authz.RoleDM, false)
		if err := fx.Auth.SetRole(ctx, who, fx.userID(otherName), authz.RoleAdmin); err == nil {
			t.Error("a dm changed a role to admin; the policy did not refuse it")
		}
	})
}

// TestAPageOwnerMayNotRevealADMSecret is the mutation half of the ownership rule.
//
// There is no reveal route in stage 1, so the test drives the secrets service
// directly — the same service the router would call — and asserts the policy
// refuses. What it is really checking is that the write path's gate is the
// policy and not the absence of a route.
func TestAPageOwnerMayNotRevealADMSecret(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	owner := authz.ForUser(fx.userID(playerName), playerName, authz.RolePlayer, false)
	if err := fx.Secrets.Reveal(ctx, owner, "b2b2b2b2b2b2"); err == nil {
		t.Error("a page owner revealed a dm secret; the policy did not refuse it")
	}
	dm := authz.ForUser(fx.userID(dmName), dmName, authz.RoleDM, false)
	if err := fx.Secrets.Reveal(ctx, dm, "b2b2b2b2b2b2"); err != nil {
		t.Errorf("a dm revealed a dm secret: %v", err)
	}
	if err := fx.Secrets.Revoke(ctx, dm, "b2b2b2b2b2b2"); err != nil {
		t.Errorf("a dm revoked a revealed secret: %v", err)
	}
	if err := fx.Secrets.Revoke(ctx, owner, "d4d4d4d4d4d4"); err == nil {
		t.Error("a page owner revoked a table secret; the policy did not refuse it")
	}
}

// assertNoToken fails when a secret's body appears in a response.
func assertNoToken(t *testing.T, body, token, what string) {
	t.Helper()
	if strings.Contains(body, token) {
		t.Errorf("%s leaked into a response: %q", what, token)
	}
}

// assertHasToken fails when a body a principal may read is missing, so that a
// test proving a leak cannot pass by rendering nothing at all.
func assertHasToken(t *testing.T, body, token, what string) {
	t.Helper()
	if !strings.Contains(body, token) {
		t.Errorf("%s is missing from a response that should carry it", what)
	}
}
