package httpapi_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The stage-5 leak suite: the plan's §18 "single highest-value test", written out
// over the whole route table and every page type rather than over the demo path.
//
// **What AGENTS.md §6 asks for, restated as this file's claim:** for every page
// type in the campaign, as every principal, the response body, every response
// header and every data-signals payload carries no fixture secret plaintext the
// principal may not read — and, because a suite that finds nothing because it
// looked at nothing is indistinguishable from a clean one, it also asserts that a
// body the principal *may* read really is there.
//
// Four things here are deliberately not what the earlier tripwire is:
//
//  1. The walk is derived from (*Server).Routes(), and a table row with no
//     request in it is a **failure**. A hand-picked list of URLs is a list that
//     is wrong the day a route is added, and AGENTS.md §11's rule about a gate
//     that skips applies to a walk that quietly stops covering something.
//  2. The expectations come from `bodyTokenReaders` — a data table beside the
//     fixture — and that table is **cross-checked against authz.CanReadSecret**
//     by the first subtest below. The other files in this package keep their
//     own hand-written models on purpose (tripwire_test.go says why: a tripwire
//     that shares the implementation it is testing has stopped being one), so
//     there are now four statements of the rule, and a disagreement between any
//     two of them is a finding.
//  3. Every step that can be answered in two shapes is driven in **both**. A
//     fragment request takes a different branch in Server.Render, and so does
//     every error page, so a walk that only asked for documents never exercised
//     half of it. tripwire_test.go had a `fragment` field on a step that nothing
//     read, which made its "page as a fragment" step a byte-identical duplicate
//     of its "page as a document" step.
//  4. The **anonymous-read-ON** principal is walked. With the flag off every
//     "anonymous" row in the existing suite is really a redirect-to-login row,
//     which means the `table` secret — the one visibility that exists for
//     anonymous readers under no circumstances — had never been tested against
//     the principal it was designed to be refused by. That is the one case
//     AGENTS.md §2.4 says authz.SecretVisibleSQL and authz.CanReadSecret
//     disagree on, and every consumer compensates for it separately
//     (store.publicOnlySQL, the per-query principal check, search.Query's
//     guard). A compensation that was removed would not fail a grep test.

// secondPlayerName is an account that no fence names and no page is owned by.
//
// It exists because "a player" is not one principal. The harness's own player
// (bram) is the *author* of the encounter page's `dm` fence, which makes him a
// genuinely interesting case: authorship buys the right to write a fence, not the
// right to read it back. A second player with no authorship at all is the other
// half. A leak that is a function of the reader's identity rather than of the
// reader's role shows up as a difference between the two, and a walk that only
// ever drove one account per role could not see it.
const (
	secondPlayerName = "wren"
	secondPlayerPass = "the second player's passphrase, long"
)

// leakRole is one principal the suite walks as.
//
// expect is the row of bodyTokenReaders that says what this principal may read.
// Two of these share a row on purpose and the cross-check below evaluates both,
// because the table's claim is about the role and the walk's claim is about the
// account.
type leakRole struct {
	name string
	// expect is the readerRole whose expectations this principal is walked
	// against.
	expect readerRole
	// user and pass are the account to sign in as, or "" for none.
	user, pass string
	// anonymousRead boots a fixture with --allow-anonymous-read on, which is the
	// only state in which an unauthenticated reader reaches a page at all.
	anonymousRead bool
	// minted says the account is created by this test rather than by the
	// harness, because no fixture helper creates it.
	minted bool
}

// leakRoles is every principal the suite walks as: the seven the plan's sentence
// names, with the anonymous principal walked twice — because with the flag off it
// is a redirect-to-login, and the only anonymous state that reaches content is
// the one with the flag on.
var leakRoles = []leakRole{
	{name: "admin", expect: roleAdmin, user: adminName, pass: adminPass},
	{name: "dm", expect: roleDM, user: dmName, pass: dmPass},
	{name: "page owner", expect: rolePageOwner, user: playerName, pass: playerPass},
	{name: "player", expect: rolePlayer, user: otherName, pass: otherPass},
	{name: "other player", expect: rolePlayer, user: secondPlayerName, pass: secondPlayerPass, minted: true},
	{name: "anonymous", expect: roleAnonymous},
	{name: "anonymous with read on", expect: roleAnonymous, anonymousRead: true},
}

// Constants the walk addresses by name rather than by reaching into the fixture
// for them. The reason is the one campaignFiles gives: a tripwire that reaches
// its expectations out of the fixture cannot catch the fixture being wrong, so
// the ids and names a step depends on are spelled here and a drift between them
// and the fixture is a failure rather than a silent success.
const (
	// tableFenceID is the campaign's one table-visible fence, revealed to the
	// table from the start. It is the fence the reveal and revoke steps act on,
	// and a revoke is immediately followed by the reveal that undoes it.
	tableFenceID = "d4d4d4d4d4d4"
	// unissuedInvite is a well-formed invite token that was never issued. A real
	// token would be redeemed, which creates an account and changes the campaign
	// the rest of the walk reads; the refusal is the same response and changes
	// nothing.
	unissuedInvite = "0123456789abcdef01234567"
	// renamedTavern is the name the rename step moves Tavern.md to.
	renamedTavern = "The Drowned Lantern Inn"
)

// mintPlayer creates an account the harness's own helpers do not.
//
// It goes through the invite path rather than writing a users row, for the reason
// accountsForAccounts gives: the role a principal holds must be one the invite
// path actually grants, or the walk is testing a state the application cannot
// produce.
func mintPlayer(t *testing.T, fx *fixture, user, pass string) {
	t.Helper()
	ctx := context.Background()
	token, err := fx.Auth.CreateInvite(ctx, fx.adminPrincipal(), authz.RolePlayer, time.Hour)
	if err != nil {
		t.Fatalf("mint an invite for %s: %v", user, err)
	}
	if _, err := fx.Auth.AcceptInvite(ctx, auth.RedeemRequest{
		Token: token, Username: user, DisplayName: "Wren", Passphrase: pass,
	}); err != nil {
		t.Fatalf("redeem the invite for %s: %v", user, err)
	}
}

// principalFor is the role's account as a Principal, read from the users row so
// that a fixture which changed a role would be refused rather than passing on a
// stale id.
func principalFor(t *testing.T, fx *fixture, role leakRole) authz.Principal {
	t.Helper()
	if role.user == "" {
		return authz.Anonymous(role.anonymousRead)
	}
	return fx.principalFor(role.user)
}

// leakStep is one request the suite drives.
//
// route names the row of the route table the step is walking, or "" for a step
// that covers a page rather than a route. It is the bookkeeping the coverage
// assertion reads: a route is covered because some step named it, and a step
// that names a route the table does not contain is a failure rather than a
// silently uncounted request.
type leakStep struct {
	route  string
	label  string
	method string
	path   string
	form   url.Values
	// bothShapes asks for the same request twice, once as a document and once
	// with the fragment header. Every step that renders is asked both ways: a
	// response shape is a branch in Server.Render, and the error page is one of
	// the shapes that branch.
	bothShapes bool
	// pathFor overrides path, for the one step whose address depends on a row
	// the walk itself creates.
	pathFor func() string
	// notStatus are statuses this step must not answer with.
	//
	// It exists because a leak check is satisfied by a refusal as happily as by
	// a success, so a step that was supposed to *do* something can stop doing it
	// and every assertion over its response still passes. The first version of
	// this walk had exactly that: the save's base hash was the hash of the hash,
	// so every role's save came back 409 — a conflict page, which carries no
	// secret — and the walk was green over a write that never happened.
	notStatus []int
}

// leakNeverWalked names the route rows this walk refuses to drive, and says why
// for each.
//
// It is a map rather than a comment because it is a *claim about coverage*, and a
// claim nothing checks is the AGENTS.md §11 shape: the excluded set is compared
// against the route table below, and a new exclusion has to be argued in here to
// take effect.
var leakNeverWalked = map[string]string{
	"GET /_/events": "the response is an event stream that stays open until the client leaves, so " +
		"reading its body to the end is exactly what a test must not do. Its secrets are owned by the " +
		"push suite — TestPushNeverLeaksSecret, TestPushAndFetchProduceIdenticalFragments and " +
		"TestTripwireAlsoCoversPushWrites, the last of which installs a scanner on the stream's writer.",
}

// leakPageSurfaces are the three page-scoped read surfaces, and the shape each
// one is asked for.
//
// Only the rendered view branches on the shape. A text response and a JSON
// response are the same bytes whatever the client asks for, so asking twice would
// be two identical requests and would spend the general rate budget for nothing.
var leakPageSurfaces = []struct {
	suffix string
	route  string
	shaped bool
}{
	{suffix: "", route: "GET /p/*", shaped: true},
	{suffix: "/raw", route: "GET /p/*/raw"},
	{suffix: "/export", route: "GET /p/*/export"},
}

// leakWalk is the ordered set of requests one principal is driven through.
//
// Order is a property of the test, not a detail. The read surface is walked
// first and in full, because that is where a body can be served by accident; the
// mutations come after, in an order chosen so that each one leaves the campaign
// as it found it — a save of the editor's own buffer, a revert to the revision
// that save recorded, a revoke immediately followed by the reveal that undoes it
// — so that one role's walk does not change what the next role's walk sees. The
// sign-out is last because it ends the session every earlier step used.
func leakWalk(t *testing.T, fx *fixture, w *leakWorld) []leakStep {
	t.Helper()
	var out []leakStep

	// Every page in the campaign, in every type, through the three page-scoped
	// read surfaces. This is where "for every page type" stops being a claim
	// about one renderer: campaignFiles carries one page per registered and per
	// conventional type, and the walk is built from that table rather than from
	// a list of URLs somebody liked.
	for i, p := range campaignPagePaths() {
		for _, surface := range leakPageSurfaces {
			// The route is claimed once, on the first page, because the
			// coverage check counts distinct routes and a second claim would
			// make it report a duplicate.
			route := ""
			if i == 0 {
				route = surface.route
			}
			out = append(out, leakStep{
				route:      route,
				label:      "page " + p + surface.suffix,
				method:     http.MethodGet,
				path:       "/p/" + p + surface.suffix,
				bothShapes: surface.shaped,
			})
		}
	}

	// Pages and paths that are not there, and one that names the app's own state.
	// A 404 is a rendered page and it branches on the shape like any other, so a
	// walk that only ever saw pages would never have looked at one.
	out = append(out,
		leakStep{route: "", label: "a page that does not exist", method: http.MethodGet, path: "/p/No-such-page.md", bothShapes: true},
		leakStep{route: "", label: "a path that traverses out of the vault", method: http.MethodGet, path: "/p/../../etc/passwd", bothShapes: true},
		leakStep{route: "", label: "a page-scoped read of the app's own state", method: http.MethodGet,
			path: "/p/.semiplane/semiplane.lock/export", bothShapes: true},
	)

	// The two attachments: the two answers §8.8 asks for, on one page, from one
	// principal. The public reference is in the page's public text; the other is
	// named only inside a dm fence on the same page.
	out = append(out,
		leakStep{route: "GET /p/*/attachment/{name...}", label: "attachment referenced from public text",
			method: http.MethodGet, path: "/p/characters/Thia.md/attachment/" + publicAttachment},
		leakStep{route: "", label: "attachment referenced only from inside a dm fence",
			method: http.MethodGet, path: "/p/characters/Thia.md/attachment/" + secretAttachment},
	)

	// The rest of the read surface.
	out = append(out,
		leakStep{route: "GET /", label: "dashboard", method: http.MethodGet, path: "/", bothShapes: true},
		leakStep{route: "GET /p/*/edit", label: "the editor", method: http.MethodGet, path: "/p/Tavern.md/edit", bothShapes: true},
		leakStep{route: "GET /p/*/history", label: "the page's history", method: http.MethodGet, path: "/p/Tavern.md/history", bothShapes: true},
		leakStep{route: "GET /p/*/revisions/{revID}", label: "one revision", method: http.MethodGet,
			path: "/p/Tavern.md/revisions/" + strconv.FormatInt(w.revision, 10), bothShapes: true},
		leakStep{route: "GET /broken", label: "the broken links panel", method: http.MethodGet, path: "/broken", bothShapes: true},
		leakStep{route: "GET /api/pages/{id}/rename-preview", label: "the rename preview", method: http.MethodGet,
			path: "/api/pages/" + strconv.FormatInt(w.tavern, 10) + "/rename-preview?new=The%20Drowned%20Lantern%20Inn", bothShapes: true},
		leakStep{route: "GET /api/pages/{id}/context", label: "the page context api", method: http.MethodGet,
			path: "/api/pages/" + strconv.FormatInt(w.tavern, 10) + "/context", bothShapes: true},
		leakStep{route: "GET /_/commands", label: "the command palette", method: http.MethodGet, path: "/_/commands?q=lantern", bothShapes: true},
		// The summary route is core-owned and reaches a plugin. A walk against a
		// build with no provider registered gets a 404 from it, which is a
		// response that cannot leak and therefore proves nothing; the fixture
		// registers a provider so this step drives a route that can serve
		// something. preview_test.go owns the summary's own properties.
		leakStep{route: "GET /plugin/{id}/summary/{pageID}", label: "a link preview of a page", method: http.MethodGet,
			path: "/plugin/linkpreview/summary/" + strconv.FormatInt(w.tavern, 10), bothShapes: true},
		leakStep{route: "", label: "a link preview of a page the provider declines", method: http.MethodGet,
			path: "/plugin/linkpreview/summary/" + strconv.FormatInt(w.absent, 10), bothShapes: true},
		leakStep{route: "GET /search", label: "the search page", method: http.MethodGet, path: "/search?q=lantern", bothShapes: true},
		leakStep{route: "GET /api/search", label: "the search api", method: http.MethodGet, path: "/api/search?q=lantern", bothShapes: true},
		leakStep{route: "GET /tags", label: "the tags panel", method: http.MethodGet, path: "/tags", bothShapes: true},
		leakStep{route: "GET /tag/{name}", label: "one tag", method: http.MethodGet, path: "/tag/area%2Fport", bothShapes: true},
		leakStep{route: "GET /files", label: "the file tree", method: http.MethodGet, path: "/files", bothShapes: true},
		leakStep{route: "GET /admin/plugins", label: "the plugin boot report", method: http.MethodGet, path: "/admin/plugins", bothShapes: true},
		leakStep{route: "GET /admin/secrets", label: "the secret audit trail", method: http.MethodGet, path: "/admin/secrets", bothShapes: true},
		leakStep{route: "GET /login", label: "the login form", method: http.MethodGet, path: "/login", bothShapes: true},
		leakStep{route: "GET /setup", label: "the setup form", method: http.MethodGet, path: "/setup", bothShapes: true},
		leakStep{route: "GET /invite/{token}", label: "the invite form", method: http.MethodGet, path: "/invite/" + unissuedInvite, bothShapes: true},
		leakStep{route: "GET /healthz", label: "the liveness probe", method: http.MethodGet, path: "/healthz"},
		leakStep{route: "GET /readyz", label: "the readiness probe", method: http.MethodGet, path: "/readyz"},
		leakStep{route: "GET /_/assets/*", label: "the stylesheet", method: http.MethodGet, path: "/_/assets/app.css"},
		leakStep{route: "", label: "the vendored datastar bundle", method: http.MethodGet, path: "/_/assets/vendor/datastar.js"},
	)

	// The mutations. Each one is driven with a request that is either the real
	// operation or a refusal of it, and both answers are leak-checked: a 403
	// carries the fixed error copy and a 200 carries the campaign, and neither
	// is interesting unless both have been looked at.
	//
	// The order is the matrix's, and the reason is a property of this table
	// rather than of its subjects: the reveal rows address Tavern.md by path, so
	// they have to run before the rename that moves it.
	out = append(out,
		// A login that fails. The successful login is every authenticated row's
		// own establishment, and driving it here would end the row's premise —
		// the next step would be looking at a different principal's answers under
		// this row's expectations.
		leakStep{route: "POST /login", label: "a login that does not match", method: http.MethodPost, path: "/login",
			form: url.Values{"username": {dmName}, "passphrase": {"not the passphrase"}}},
		// A setup the validator refuses, on a vault that has already been set up.
		// /setup is a 404 here; the point is that the route is walked.
		leakStep{route: "POST /setup", label: "a setup submission", method: http.MethodPost, path: "/setup",
			form: url.Values{"username": {"x"}, "display_name": {"X"}, "passphrase": {"a passphrase long enough"}}},
		leakStep{route: "POST /invite/{token}", label: "an invite redemption", method: http.MethodPost, path: "/invite/" + unissuedInvite,
			form: url.Values{"username": {"x"}, "passphrase": {"a passphrase long enough"}}},
		// The save. The buffer is the one this principal's own editor holds, so
		// for a page owner it carries sentinels rather than bodies and the save
		// exercises the splice; a no-op in bytes, which is what keeps the rest of
		// the walk looking at the campaign it started with.
		leakStep{route: "POST /p/*/edit", label: "saving the editor's own buffer", method: http.MethodPost,
			path: "/p/Tavern.md/edit", form: w.editorForm, notStatus: []int{http.StatusConflict}},
		leakStep{route: "POST /p/*/revert/{revID}", label: "reverting to the revision that save recorded", method: http.MethodPost,
			path: "/p/Tavern.md/revert/" + strconv.FormatInt(w.revision, 10), notStatus: []int{http.StatusConflict}}, // Revoke then reveal, so the fence is back to the visibility the campaign
		// was seeded with. Both responses are redirects that cannot carry a body,
		// and the walk asserts that rather than assuming it.
		leakStep{route: "POST /p/*/secrets/{secretID}/revoke", label: "revoking a table-visible secret", method: http.MethodPost,
			path: "/p/Tavern.md/secrets/" + tableFenceID + "/revoke"},
		leakStep{route: "POST /p/*/secrets/{secretID}/reveal", label: "revealing it again", method: http.MethodPost,
			path: "/p/Tavern.md/secrets/" + tableFenceID + "/reveal"},
		// The rename and the opt-in bulk updater. Tavern.md is the page the whole
		// walk is built on, it is the one the harness grants an owner, and two
		// other pages refer to it — one of them carrying a dm fence. So a
		// principal entitled to the rename gets a real link rewrite attempted on
		// a page with a secret on it, and a principal who is not gets the
		// refusal. Same target and same order as the matrix.
		leakStep{route: "POST /api/pages/{id}/rename", label: "renaming the page that carries the secrets", method: http.MethodPost,
			path: "/api/pages/" + strconv.FormatInt(w.tavern, 10) + "/rename",
			form: url.Values{"new": {renamedTavern}}},
		leakStep{route: "POST /api/pages/{id}/update-links", label: "rewriting the links that pointed at it", method: http.MethodPost,
			pathFor: func() string {
				// Whichever page the rename left behind. Naming the original when
				// the rename was refused is what keeps this step driving the
				// route rather than a 404 it was never asking about.
				id := w.tavern
				if renamed, ok := fx.pageIDByPath(renamedTavern + ".md"); ok {
					id = renamed
				}
				return "/api/pages/" + strconv.FormatInt(id, 10) + "/update-links"
			},
			form: url.Values{"new": {renamedTavern}, "confirmed": {"true"}}},
		// Last, because it ends the session every step above used.
		leakStep{route: "POST /logout", label: "signing out", method: http.MethodPost, path: "/logout"},
	)
	return out
}

// leakWorld is the state the walk's addresses depend on, resolved once before it
// runs.
type leakWorld struct {
	// tavern is the page id of Tavern.md, which every page-scoped write in the
	// walk addresses.
	tavern int64
	// revision is a revision of Tavern.md, produced by a real save before the
	// walk: the indexer records no revision at boot, so a walk that did not
	// write one would be asking the revision and revert routes about nothing.
	revision int64
	// absent is one past the highest page id, for the steps that need a page
	// that is not there.
	absent int64
	// editorForm is the save the editor step posts: this principal's own
	// redacted buffer and the hash of the bytes on disk.
	editorForm url.Values
}

// campaignPagePaths is every page in the campaign, in vault order.
func campaignPagePaths() []string {
	paths := make([]string, 0, len(campaignPageTypes))
	for p := range campaignPageTypes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// newLeakFixture boots a fixture for one role, with a link-preview provider
// registered so that the summary route is a route that can serve something.
func newLeakFixture(t *testing.T, role leakRole) *fixture {
	t.Helper()
	reg := previewRegistry{
		pluginID: "linkpreview",
		provider: &fixedProvider{id: "linkpreview", ok: true, body: providerBody{token: "<article>A card.</article>"}},
	}
	fx := newFixturePlugins(t, campaignFiles, reg, func(c *config.Config) { c.AllowAnonymousRead = role.anonymousRead })
	fx.accountsFor()
	if role.minted {
		mintPlayer(t, fx, role.user, role.pass)
	}
	return fx
}

// prepareLeakWorld produces the state the walk addresses: a revision to walk, a
// page id that is not there, and the editor's own buffer for this principal.
func prepareLeakWorld(t *testing.T, fx *fixture, role leakRole) *leakWorld {
	t.Helper()
	// Before the walk and not during it: the revision has to exist before the
	// revision and revert steps address it, and it is a real save because a
	// revision inserted by a test would be a document no writer produced.
	saveThroughTheEditor(t, fx, "/p/Tavern.md/edit")

	tavern, ok := fx.pageIDByPath("Tavern.md")
	if !ok {
		t.Fatal("the index has no page for Tavern.md, which every page-scoped step in the walk addresses")
	}
	return &leakWorld{
		tavern:     tavern,
		revision:   newestRevisionIDOf(t, fx, "Tavern.md"),
		absent:     absentPageID(t, fx),
		editorForm: editorSaveForm(t, fx, principalFor(t, fx, role), tavern, "Tavern.md"),
	}
}

// editorSaveForm is the save a principal's editor would post: the buffer
// EditView hands that principal, and the hash of the bytes on disk.
//
// It is read through the service rather than by parsing the rendered form,
// because the rendered form is a template's escaping of the same value and
// parsing it back would be a second implementation of "what is in that
// textarea". The route is still exercised — the walk posts these bytes to
// POST /p/*/edit and checks the response — and the rendering of the buffer is
// checked by the read-phase step for GET /p/*/edit, which is the step that is
// about it.
func editorSaveForm(t *testing.T, fx *fixture, who authz.Principal, pageID int64, rel string) url.Values {
	t.Helper()
	view, err := fx.Secrets.EditView(context.Background(), who, pageID)
	if err == nil {
		// hex, not HashHex. BaseHash is already the raw hash — vault.Hash's
		// output — and the form field wants its hexadecimal rendering, so
		// HashHex here would be the hash of the hash. A save built that way
		// conflicts with the file it was read from, which is a 409 and a
		// walk step that quietly asserted about a conflict page.
		return url.Values{"content": {string(view.Content)}, "base_hash": {hex.EncodeToString(view.BaseHash)}}
	}
	// A principal the editor refuses never gets a buffer, so the save step for
	// one posts the page's own bytes. The route answers the refusal before the
	// body matters, and what is under test is the response.
	src, rerr := os.ReadFile(filepath.Join(fx.Root, filepath.FromSlash(rel)))
	if rerr != nil {
		t.Fatalf("read %s for the save step: %v", rel, rerr)
	}
	return url.Values{"content": {string(src)}, "base_hash": {vault.HashHex(src)}}
}

// TestSecretFixturesNeverLeak is the plan's §18 leak test, in the form the
// design's own rule deserves.
//
// The name is the one AGENTS.md §6 and the plan's §18 cite, and it is the name
// the suite answers to: for every page type in the campaign, as every principal
// the harness can build, the response body, every response header and every
// data-signals payload carries no fixture secret plaintext the principal may not
// read.
//
// The claim has three halves and all three are load-bearing. The negative half
// is the whole point. The **expectation** half is bodyTokenReaders, cross-checked
// against the policy it claims to describe by the first subtest, so the walk is
// not asserting the absence of a string because a hand-written model said the
// string should be absent. And the **positive** half is the subtest per role
// that asserts a body the principal *is* entitled to really arrived, because a
// leak suite that finds nothing because it looked at nothing is the failure
// AGENTS.md §11 warns about twice and this file refuses to be it.
func TestSecretFixturesNeverLeak(t *testing.T) {
	t.Parallel()

	t.Run("the expectation table agrees with the policy it describes", func(t *testing.T) {
		t.Parallel()
		assertLeakExpectationsMatchThePolicy(t)
	})

	for _, role := range leakRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			fx := newLeakFixture(t, role)
			w := prepareLeakWorld(t, fx, role)
			s := signInForRole(t, fx, role)

			t.Run("a body this principal may read really is served", func(t *testing.T) {
				assertLeakPositiveControl(t, fx, role, s)
			})
			walk := leakWalk(t, fx, w)
			t.Run("the walk reaches every route in the table", func(t *testing.T) {
				assertLeakWalkCoversEveryRoute(t, fx, walk)
			})
			for _, st := range walk {
				st := st
				t.Run(st.label, func(t *testing.T) {
					driveLeakStep(t, s, role, st)
				})
			}
		})
	}
}

// signInForRole is the role's client: a session with the role's account signed
// in, or an anonymous one.
func signInForRole(t *testing.T, fx *fixture, role leakRole) *session {
	t.Helper()
	s := fx.newSession()
	if role.user == "" {
		return s
	}
	resp := s.login(role.user, role.pass)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign %s in: status %d, want 303", role.user, resp.StatusCode)
	}
	drain(resp)
	return s
}

// driveLeakStep performs one step in each shape it asks for and asserts the
// response carries nothing the principal may not read.
func driveLeakStep(t *testing.T, s *session, role leakRole, st leakStep) {
	t.Helper()
	shapes := []bool{false}
	if st.bothShapes {
		shapes = []bool{false, true}
	}
	for _, asFragment := range shapes {
		where := st.label
		if asFragment {
			where += " as a fragment"
		}
		c := &call{method: st.method, path: st.path, form: st.form}
		if st.pathFor != nil {
			c.path = st.pathFor()
		}
		if asFragment {
			c.headers = map[string]string{httpapi.DataStarRequestHeader: "true"}
		}
		resp := s.do(c)
		body := s.read(resp)
		// A rate-limited response is a 429 and nothing else, so every assertion
		// below it would be about an error page and would pass. The walk spends
		// the general budget for a minute's worth of requests, and this says so
		// out loud rather than letting the suite quietly lose its coverage.
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("%s: the walk exhausted a rate budget, so every assertion in this role is against a 429 rather than against the route", where)
		}
		for _, bad := range st.notStatus {
			if resp.StatusCode == bad {
				t.Fatalf("%s: the walk got %d, which is the answer for a step that did not do what it was driven to do; every assertion over this response is about a failure page", where, bad)
			}
		}
		assertNoLeaksForRole(t, body, resp.Header, role, where)
	}
}

// assertNoLeaksForRole is the assertion, over the body, every header value and
// every data-signals payload.
//
// It delegates to the existing assertNoLeaks so that there is one place in this
// package that knows how a response is searched, and passes it a model of the
// rule that is not the code's: the fixture's own table, keyed by role. The other
// suites here pass their own hand-written models for the same reason — a tripwire
// that asks the code it is testing whether a leak is a leak has stopped being
// one — and a disagreement between any of those models and this table is a
// finding about one of the two.
func assertNoLeaksForRole(t *testing.T, body string, header http.Header, role leakRole, where string) {
	t.Helper()
	mayRead := func(_ leakPrincipal, token string) bool { return bodyTokenReaders[token][role.expect] }
	assertNoLeaks(t, body, header, mayRead, leakPrincipal{name: role.name}, where)
}

// assertLeakWalkCoversEveryRoute is the coverage gate, and it is a gate rather
// than a note.
//
// A row of the route table that no step names is a route this suite claims to
// cover and does not. The failure names the route, because a leak suite that has
// quietly stopped covering a surface is worse than no leak suite: it reports
// coverage that does not exist.
func assertLeakWalkCoversEveryRoute(t *testing.T, fx *fixture, walk []leakStep) {
	t.Helper()
	covered := map[string]bool{}
	for _, st := range walk {
		if st.route == "" {
			continue
		}
		if covered[st.route] {
			t.Errorf("two steps claim the route %s, so the coverage count would be a lie", st.route)
		}
		covered[st.route] = true
	}
	table := fx.Server.Routes()
	for _, rt := range table {
		if covered[rt.Name()] {
			continue
		}
		if _, excluded := leakNeverWalked[rt.Name()]; excluded {
			continue
		}
		t.Errorf("the leak walk has no request for %s (permission %q), so this suite does not cover it: add a step, or add it to leakNeverWalked with the reason it cannot be walked",
			rt.Name(), rt.Perm)
	}
	for name := range leakNeverWalked {
		if !slices.Contains(routesNamed(table), name) {
			t.Errorf("leakNeverWalked excuses %s, which the route table does not contain: the exclusion has outlived the route it was written for", name)
		}
	}
	// The exclusions are a closed set on purpose. A second one that is not a
	// stream would be a surface quietly dropped from a leak suite, and this is
	// where that shows up.
	if len(leakNeverWalked) != 1 {
		t.Errorf("leakNeverWalked holds %d exclusions, want 1: every further exclusion is a surface this suite has stopped covering and needs its own argument", len(leakNeverWalked))
	}
	if len(covered) == 0 {
		t.Fatal("the walk claims no route at all, so its coverage assertion proved nothing")
	}
	// Both shapes have to be exercised somewhere, or the fragment half of the
	// walk is a claim rather than a walk.
	shaped := 0
	for _, st := range walk {
		if st.bothShapes {
			shaped++
		}
	}
	if shaped < 10 {
		t.Errorf("only %d steps are walked in both response shapes, want at least 10: a fragment is a different branch in Server.Render and so is every error page", shaped)
	}
}

// routesNamed is every route name in the table.
func routesNamed(table []httpapi.Route) []string {
	out := make([]string, 0, len(table))
	for _, rt := range table {
		out = append(out, rt.Name())
	}
	return out
}

// assertLeakPositiveControl is the half of the claim that keeps the other half
// honest.
//
// A leak test asserts that a string is absent. A string is absent from a
// response that rendered nothing at all, from a 404, from a 303, and from a page
// the fixture never seeded — so without this subtest the walk would pass against
// a server that answered every request with an error page, and AGENTS.md §11's
// "a test that passes because the fixture did not set up what it asserts is the
// same failure wearing a different hat" would be the description of this file.
//
// What each principal is entitled to see differs, and the difference is the
// point:
//
//   - Every authenticated principal may read a table-visible secret, and every
//     one of them must therefore be shown one. That is the assertion that would
//     fail if a page view redacted too much as readily as it would if one
//     leaked.
//   - A DM and an admin may read the dm secrets as well, and the walk asserts
//     they are shown those too, so the DMs' rows are not passing because the
//     positive control is satisfied by a table secret alone.
//   - An anonymous reader with the flag on may read the public body of a page and
//     must read none of the secrets on it — the §2.4 case, and the only positive
//     control available to a principal entitled to nothing secret.
//   - An anonymous reader with the flag off may read nothing at all, and the
//     control for that principal is that the campaign's front door answers it and
//     the login form renders, which is what "reached the server" means for a
//     client that is refused everything.
func assertLeakPositiveControl(t *testing.T, fx *fixture, role leakRole, s *session) {
	t.Helper()
	read := func(path string) (int, string) {
		resp := s.do(s.get(path))
		return resp.StatusCode, s.read(resp)
	}

	if role.expect == roleAnonymous && !role.anonymousRead {
		if status, _ := read("/"); status != http.StatusSeeOther {
			t.Errorf("the campaign's front door answered %d to an anonymous reader with anonymous read off, want 303 to the login form", status)
		}
		status, body := read("/login")
		if status != http.StatusOK {
			t.Errorf("the login form answered %d, want 200: a principal that may read nothing still has to be able to reach the server", status)
			return
		}
		if _, ok := csrfFrom(body); !ok {
			t.Error("the login form rendered without its form, so the positive control for this principal is measuring an error page")
		}
		return
	}

	// The tokens this principal must be shown somewhere in the campaign, and the
	// page each lives on. A token with no page would make the control vacuous
	// for that row, so the page is named rather than searched for. An anonymous
	// reader has no entry, because no secret body is owed to it; its control is
	// the public body of a page, below.
	wanted := map[string]string{}
	switch role.expect {
	case roleAdmin, roleDM:
		wanted[tableToken] = "Tavern.md"
		wanted[houseRuleBodyToken] = "houserules/Extended-rest.md"
		wanted[dmBodyToken] = "Tavern.md"
		wanted[ruinBodyToken] = "Ruin.md"
	case rolePageOwner:
		wanted[tableToken] = "Tavern.md"
		wanted[houseRuleBodyToken] = "houserules/Extended-rest.md"
		wanted[privateBodyToken] = "Tavern.md"
		wanted[ownerBodyToken] = "Tavern.md"
	case rolePlayer:
		// Nothing beyond the two table-visible bodies: this is the row with the
		// fewest, and it is the one §2.4 is about, because a `table` secret is
		// the only body a player is owed.
		wanted[tableToken] = "Tavern.md"
		wanted[houseRuleBodyToken] = "houserules/Extended-rest.md"
	}

	shown := 0
	for token, page := range wanted {
		status, body := read("/p/" + page)
		if status != http.StatusOK {
			t.Errorf("the positive control asked for /p/%s as %s and got %d, want 200: every negative assertion in this row would be unproven", page, role.name, status)
			continue
		}
		if !strings.Contains(body, token) {
			t.Errorf("/p/%s as %s does not carry the body of the %s secret this principal may read, so every negative assertion in this row is passing because nothing was served", page, role.name, visibilityOfToken(token))
			continue
		}
		shown++
	}

	if role.expect == roleAnonymous {
		// The one case where the control is a public body rather than a secret:
		// an anonymous reader with the flag on must see the page and must not see
		// anything behind a fence on it, and the walk's negative half for that
		// principal is the table secret, which §2.4 is about.
		status, body := read("/p/Tavern.md")
		if status != http.StatusOK {
			t.Errorf("an anonymous reader with anonymous read on got %d for a page, want 200", status)
			return
		}
		if !strings.Contains(body, "Drowned Lantern") {
			t.Error("the page rendered for an anonymous reader with read on and carried none of its public text, so the control is measuring an error page")
		}
		if strings.Contains(body, tableToken) || strings.Contains(body, houseRuleBodyToken) {
			t.Error("a table-visible secret reached an anonymous reader with read on: that is the one case authz.SecretVisibleSQL does not close on its own")
		}
		return
	}

	if shown == 0 {
		t.Errorf("no positive control fired for %s, so every negative assertion this role made is unproven", role.name)
	}
}

// visibilityOfToken is what a token is called in a failure message. It reads the
// fixture's own table, so a token cannot be mislabelled.
func visibilityOfToken(token string) string {
	switch {
	case token == tableToken || token == houseRuleBodyToken:
		return "table-visible"
	case token == dmBodyToken || token == ruinBodyToken || token == characterBodyToken || token == encounterBodyToken:
		return "dm"
	default:
		return "private"
	}
}

// fenceFacts is what the suite needs to know about one fence, read from the vault
// file rather than from the index.
//
// The file is canonical and the index is derived (AGENTS.md §1), so a leak suite
// that took its expectations from the index would be asserting about the index.
// Each fact is keyed by the body token the fence carries, which is the only
// handle that is simultaneously unique per fence and already in the forbidden
// list.
type fenceFacts struct {
	id         string
	token      string
	page       string
	visibility authz.Visibility
	author     string
	body       string
}

// fixtureFences is every fence in the campaign, keyed by the body token it
// carries.
//
// The count is asserted: a token whose fence this cannot find would make every
// assertion about that token pass, and a fence whose token is not in bodyTokens
// would make it unasserted. Both are the same bug wearing different hats.
func fixtureFences(t *testing.T) map[string]fenceFacts {
	t.Helper()
	out := map[string]fenceFacts{}
	for _, p := range campaignPagePaths() {
		doc := md.Parse(p, []byte(campaignFiles[p]))
		found, _ := secrets.Parse(doc)
		for _, f := range found {
			for _, token := range bodyTokens {
				if !strings.Contains(f.Body, token) {
					continue
				}
				if prev, dup := out[token]; dup {
					t.Errorf("the token %s is in a fence on %s and in one on %s; a finding could not name the secret that leaked",
						token, prev.page, p)
				}
				out[token] = fenceFacts{id: f.ID, token: token, page: p, visibility: f.Visibility, author: f.Author, body: f.Body}
			}
		}
	}
	if len(out) != len(bodyTokens) {
		var missing []string
		for _, token := range bodyTokens {
			if _, ok := out[token]; !ok {
				missing = append(missing, token)
			}
		}
		t.Fatalf("the campaign's fences carry %d of the %d body tokens; the walk's negative half would pass vacuously for %s",
			len(out), len(bodyTokens), strings.Join(missing, ", "))
	}
	return out
}

// fencesOnPage is the campaign's fences on one page, in fence-id order.
func fencesOnPage(all map[string]fenceFacts, page string) []fenceFacts {
	var out []fenceFacts
	for _, token := range bodyTokens {
		if f, ok := all[token]; ok && f.page == page {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// assertLeakExpectationsMatchThePolicy is the cross-check the rest of the suite
// stands on.
//
// bodyTokenReaders is the fixture's statement of what each fence is for, and it
// is data rather than a call into authz on purpose: a leak test that asks the
// code it is testing whether a leak is a leak has stopped being a leak test. That
// is a good reason for the table to exist and a bad reason for it to be unchecked,
// because a table that has drifted from the policy would make every walk in this
// file assert the wrong thing and pass.
//
// So this compares it against authz.CanReadSecret, evaluated over the real
// fixture state: the real page ids, the real ownership grants, the real author
// ids the indexer resolved. Both players are evaluated, because the table's
// player row is a claim about a role and the walk drives two accounts into it.
func assertLeakExpectationsMatchThePolicy(t *testing.T) {
	t.Helper()
	// The second player's account has to exist here as well, or the row for
	// "other player" would be evaluated against an account that is not there —
	// which is the AGENTS.md §11 failure wearing a role's name: the assertion
	// runs, it passes, and it measured nothing.
	fx := newLeakFixture(t, leakRole{
		name: "other player", expect: rolePlayer,
		user: secondPlayerName, pass: secondPlayerPass, minted: true,
	})
	fences := fixtureFences(t)
	ctx := context.Background()

	for _, token := range bodyTokens {
		f, ok := fences[token]
		if !ok {
			continue // fixtureFences has already failed with a better message.
		}
		pageID, ok := fx.pageIDByPath(f.page)
		if !ok {
			t.Errorf("the fence carrying %s is on %s and the index has no such page, so no principal's answer about it can be evaluated", token, f.page)
			continue
		}
		var authorID int64
		if f.author != "" {
			user, err := store.GetUserByUsername(ctx, fx.DB.Reader(), f.author)
			if err != nil {
				t.Errorf("the fence carrying %s names the author %q, which is not an account, so the indexer recorded no secrets row and the fence is hidden from everyone but a DM: the checks below would be measuring a fence the walk never serves",
					token, f.author)
			} else {
				authorID = user.ID
			}
		}
		for _, role := range leakRoles {
			who := principalFor(t, fx, role)
			owner := false
			if who.UserID != 0 {
				var err error
				owner, err = store.IsPageOwner(ctx, fx.DB.Reader(), pageID, who.UserID)
				if err != nil {
					t.Fatalf("read the ownership of %s: %v", f.page, err)
				}
			}
			got := authz.CanReadSecret(who, owner, authorID, f.visibility)
			want := bodyTokenReaders[token][role.expect]
			if got != want {
				t.Errorf("bodyTokenReaders says %s is %v for the %q role, and authz.CanReadSecret says %v for the same account (page %s, fence %s, visibility %s, page owner %v): one of the two is a lie, and the walks in this file assert against it",
					token, want, role.expect, got, f.page, f.id, f.visibility, owner)
			}
		}
	}
}

// TestSecretBodyNeverInErrorsOrLogs is the other half of "no fixture secret
// reaches a reader", and it is about the two places a body escapes without ever
// being rendered to a principal: the 500 page, and the request and audit logs.
//
// Nothing in this package could assert on either until stage 5 gave the harness
// an in-memory log at Debug level. Every test here used to throw its logs away,
// so a handler that logged a page's bytes would have been caught by nothing — and
// a log line is a worse leak than a response, because it is written for somebody
// who is not the reader and it outlives the request.
//
// The failure has to be **real**, which is the whole difficulty. A test that
// captures a clean log because the request succeeded is the worst outcome here:
// it passes, it says nothing, and it is indistinguishable from a clean one. So
// each case below provokes a failure the application can genuinely hit, asserts
// that a 500 came back, and only then reads the log — and each asserts that the
// stream it is reading is non-empty and grew during the request, so an empty
// capture cannot pass it.
func TestSecretBodyNeverInErrorsOrLogs(t *testing.T) {
	t.Parallel()

	t.Run("a store error while rendering a page that carries secrets", func(t *testing.T) {
		t.Parallel()
		role := leakRole{name: "player", expect: rolePlayer, user: otherName, pass: otherPass}
		fx := newLeakFixture(t, role)
		s := signInForRole(t, fx, role)
		// One warm request, so the log stream is known to be working before the
		// one under test and the "it grew" assertion has something to compare
		// against.
		s.getOK("/p/Tavern.md")
		before := len(fx.logs())

		// The real failure: the page renders — the file is read, the body is
		// parsed and handed to goldmark — and then the query that lists the
		// page's secrets fails, so the temptation to describe what the handler
		// was holding is at its highest and the response is a 500.
		//
		// Dropping a table is the honest way to provoke it. There is no seam for
		// a test to hand the router a failing store, and chmod would fail
		// differently for a privileged reader than for an unprivileged one,
		// which is a test whose result depends on who is running it.
		if _, err := fx.DB.Writer().Exec(`DROP TABLE secrets`); err != nil {
			t.Fatalf("break the store so the page view fails: %v", err)
		}

		resp := s.do(s.get("/p/Tavern.md"))
		body := s.read(resp)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("GET a page whose secrets table is gone: status %d, want 500. A test that captured a clean log because the request succeeded is worse than no test", resp.StatusCode)
		}
		stream := fx.logs()
		assertLeakLogIsLive(t, stream, before)
		assertNoFixtureBody(t, "the 500 page", body)
		assertNoFixtureBody(t, "the request and audit logs", stream)
	})

	t.Run("a save whose derivation failed, on a page that carries secrets", func(t *testing.T) {
		t.Parallel()
		role := leakRole{name: "dm", expect: roleDM, user: dmName, pass: dmPass}
		fx := newLeakFixture(t, role)
		w := prepareLeakWorld(t, fx, role)
		// The same database, the same writer, the same logger, the same campaign:
		// only the reindexer differs, so the 500 under test is the one the
		// ordinary server produces for a derivation that failed.
		fx2 := newFailingReindexFixture(t, fx)
		s := signInForRole(t, fx2, role)
		s.getOK("/p/Tavern.md")
		before := len(fx2.logs())

		// The other real failure, and the one with a body in hand: the write
		// succeeds, the file on disk is the page including its fences, and the
		// reindex that would have derived the index from it fails. The service
		// reports that rather than pretending the save did not happen, so the
		// error names the page — and an error that carries the page it is about
		// is one line away from carrying the body.
		saved := s.do(&call{method: http.MethodPost, path: "/p/Tavern.md/edit", form: w.editorForm, csrf: s.token()})
		body := s.read(saved)
		if saved.StatusCode != http.StatusInternalServerError {
			t.Fatalf("a save whose reindex failed: status %d, want 500. Without a real failure there is no log to read and this subtest would pass for nothing", saved.StatusCode)
		}
		stream := fx2.logs()
		assertLeakLogIsLive(t, stream, before)
		assertNoFixtureBody(t, "the 500 page of a failed save", body)
		assertNoFixtureBody(t, "the request and audit logs of a failed save", stream)
		// The route is on the record, so the failure is attached to the request
		// that caused it rather than to the test as a whole. It is the chi
		// pattern rather than the route table's name, because that is what
		// RouteFrom reads and therefore what the log carries.
		assertFailureWasRecorded(t, stream, `"/p/*/edit"`)
	})
}

// assertLeakLogIsLive is the negative control for every log assertion here.
//
// "Found nothing" and "was not reading anything" are the same observation, and a
// log assertion that cannot tell them apart is a log assertion that always
// passes. So: the stream is non-empty, it grew across the request under test,
// and it carries the record the handler wrote for it.
func assertLeakLogIsLive(t *testing.T, stream string, before int) {
	t.Helper()
	if len(stream) == 0 {
		t.Fatal("the log stream is empty, so an assertion over it cannot fail: the fixture is not capturing what the request path writes")
	}
	if len(stream) <= before {
		t.Fatalf("the log stream did not grow across the request under test (%d bytes before, %d after), so the request wrote nothing and this subtest is reading a stream the failure never reached",
			before, len(stream))
	}
	if !strings.Contains(stream, `"action":"http.fail"`) {
		t.Error("the log stream records no http.fail record although a 500 was returned, so the failure is not being recorded at all; a leak assertion over an unrecorded failure proves nothing")
	}
	// The failure's own value is reduced to a hash and a byte count by
	// logRecord, and this asserts that the reduction happened rather than that
	// the reduction would happen. A record carrying a length is a record that
	// cannot be carrying a page.
	if !strings.Contains(stream, `bytes)"`) {
		t.Error("the log stream holds no reduced error value, so the 500 was not recorded by s.fail and the absence of a body below is an absence of a log line rather than a property of it")
	}
}

// assertFailureWasRecorded asserts that the record naming this operation is in
// the stream, so that the absence of a body is attached to a real line.
func assertFailureWasRecorded(t *testing.T, stream, doing string) {
	t.Helper()
	if !strings.Contains(stream, doing) {
		t.Errorf("the log stream holds no record naming %q, so the failure that was provoked left nothing behind to have leaked from", doing)
	}
}

// assertNoFixtureBody is the assertion, over a body or a log stream, that no
// fixture body reached it.
//
// The messages name the token and never the body, deliberately: a failure in
// this suite prints to a CI log, and a test about bodies escaping must not put
// one in the failure output.
func assertNoFixtureBody(t *testing.T, what, text string) {
	t.Helper()
	for _, token := range bodyTokens {
		if strings.Contains(text, token) {
			t.Errorf("%s carries a fixture secret body: token %s, %d bytes of text scanned", what, token, len(text))
		}
	}
}

// TestExportNeverLeaks is the plan's §18 export test, and it is about three
// separate properties that a status code cannot carry.
//
//  1. **Exactly the right fences.** The export is a second spelling of the raw
//     view, so for every role it must contain every fence that role may read and
//     no other. "No other" is asserted against the fixture's own table; "every
//     one" is asserted too, because an export that redacted everything would
//     pass a suite that only checked for absence.
//  2. **The unreadable ones are locked, not blanked, and not measured.** A
//     replaced fence is secrets.LockPlaceholder, which carries the id and one
//     word. It is deliberately *not* md.Redact's sentinel: that carries the
//     hidden body's length and an eight-hex digest, which is a measurement of
//     something the reader was refused, and AGENTS.md §6 says so. So the sentinel
//     grammar must not appear in an export at all, the digest of a hidden body
//     must not appear, and — the assertion a fixed label cannot fake — two
//     exports of the same page whose hidden bodies have different lengths must be
//     byte-identical.
//  3. **The refusal is the whole of the refusal.** A page this reader may not
//     read must be the same answer as a page that is not there, byte for byte.
//
// That third one has a finding attached, and it is the reason this test says
// something rather than merely checking a header: in v1 there is no such page.
// `pages` has no visibility column, authz.PermReadPage is resource-free, and
// AGENTS.md §7 says a page has no visibility. So the export's entire refusal set
// is "there is no such page", and the test proves that by asserting the
// structural fact as well as the 404s — the export of a missing page, of a path
// that traverses out of the vault and of the app's own state must all be the
// same bytes, and the permission the route is mounted on must be one every reader
// who may read public content already holds.
func TestExportNeverLeaks(t *testing.T) {
	t.Parallel()
	fences := fixtureFences(t)

	for _, role := range leakRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			fx := newLeakFixture(t, role)
			prepareLeakWorld(t, fx, role)
			s := signInForRole(t, fx, role)

			// A principal that may not read public content gets nothing, and the
			// export is no exception: every page is a redirect to the login form
			// before the handler runs, so there are no fences to replace and the
			// only property left is the one that matters most for a client that is
			// refused everything — a page that exists and a page that does not are
			// the same answer. Asserting 200 here would be asserting a capability
			// the route does not have.
			if role.expect == roleAnonymous && !role.anonymousRead {
				t.Run("the redirect does not confirm that a page exists", func(t *testing.T) {
					existing := s.do(s.get("/p/Tavern.md/export"))
					existingBody := s.read(existing)
					missing := s.do(s.get("/p/There-is-no-such-page.md/export"))
					missingBody := s.read(missing)
					if existing.StatusCode != http.StatusSeeOther || missing.StatusCode != http.StatusSeeOther {
						t.Errorf("an unauthenticated export of a page that exists and one that does not: %d and %d; both must be 303",
							existing.StatusCode, missing.StatusCode)
					}
					if existingBody != missingBody {
						t.Errorf("the redirect for a page that exists differs from one for a page that does not (%d bytes against %d)",
							len(existingBody), len(missingBody))
					}
					assertNoLeaksForRole(t, existingBody, existing.Header, role, "the export redirect for a page that exists")
					assertNoLeaksForRole(t, missingBody, missing.Header, role, "the export redirect for a page that does not")
				})
				return
			}

			exported := 0
			for _, page := range campaignPagePaths() {
				onPage := fencesOnPage(fences, page)
				resp := s.do(s.get("/p/" + page + "/export"))
				body := s.read(resp)
				where := "the export of " + page
				if resp.StatusCode != http.StatusOK {
					t.Errorf("%s as %s: status %d, want 200. A refusal is not a leak, but a suite that only ever exports 404s is asserting about nothing",
						page, role.name, resp.StatusCode)
					continue
				}
				exported++
				assertNoLeaksForRole(t, body, resp.Header, role, where)

				if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
					t.Errorf("%s: Cache-Control is %q, want it to carry no-store. The bytes are authorization-dependent, so a shared cache holding this for one principal is where a full export and a redacted one would be confused", where, got)
				}
				// The sentinel grammar is the editor's restore token, not a
				// display token (AGENTS.md §6), and an export is a thing a reader
				// keeps.
				if strings.Contains(body, "‹s:") {
					t.Errorf("%s carries a redacted sentinel: that token carries the hidden body's length and a digest, which is a measurement of something this reader was refused", where)
				}
				for _, f := range onPage {
					may := bodyTokenReaders[f.token][role.expect]
					locked := secrets.LockPlaceholder(f.id)
					switch {
					case may && !strings.Contains(body, f.body):
						t.Errorf("%s does not carry the body of the %s fence on it, which this principal may read, so the negative half above would pass on an export that redacted everything", where, f.visibility)
					case may && strings.Contains(body, locked):
						t.Errorf("%s locks the %s fence on it, which this principal may read", where, f.visibility)
					case !may && !strings.Contains(body, locked):
						t.Errorf("%s does not replace the %s fence on it with its lock placeholder, so a reader who may not read it is not even told one is there", where, f.visibility)
					case !may && strings.Contains(body, f.body):
						t.Errorf("%s carries the body of the %s fence on it, which this principal may not read", where, f.visibility)
					case !may:
						// The digest is the second thing a sentinel would carry and
						// the first thing a lazy redaction would: eight hex
						// characters of the hidden body, which identifies it to
						// anyone holding the file.
						if digest := vault.HashHex([]byte(f.body))[:8]; strings.Contains(body, digest) {
							t.Errorf("%s carries the first eight hex characters of the digest of a body this principal may not read", where)
						}
					}
				}
				// A page with no fence on it must carry no lock at all: a
				// placeholder for a secret nobody was refused says there is one.
				if len(onPage) == 0 && strings.Contains(body, "⟨secret:") {
					t.Errorf("%s carries a lock placeholder, but it has no secret on it", where)
				}
			}
			if exported == 0 {
				t.Errorf("no export succeeded for %s, so every assertion in this row is about refusals", role.name)
			}

			t.Run("the refusal is the same document for every kind of nothing", func(t *testing.T) {
				first := ""
				for i, p := range []string{
					"/p/There-is-no-such-page.md/export",
					"/p/../../etc/passwd/export",
					"/p/.semiplane/semiplane.lock/export",
					"/p/characters/No-such-page.md/export",
				} {
					resp := s.do(s.get(p))
					body := s.read(resp)
					if resp.StatusCode != http.StatusNotFound {
						t.Errorf("%s as %s: status %d, want 404", p, role.name, resp.StatusCode)
					}
					if i == 0 {
						first = body
						continue
					}
					if body != first {
						t.Errorf("%s answers differently from a page that does not exist (%d bytes against %d): a distinguishable refusal is a probe",
							p, len(body), len(first))
					}
				}
				if strings.Contains(first, "export") || strings.Contains(first, "There-is-no-such-page") {
					t.Error("the export's 404 body names the surface or the page it was asked for, which confirms the answer was about it")
				}
			})

			t.Run("the route's permission is one every reader already holds", func(t *testing.T) {
				// The structural half of the property above, and the reason the
				// preceding subtest is not waiting for a page that cannot
				// currently exist. v1 has no per-page read restriction, so the
				// export's refusal set is exactly "there is no such page"; if that
				// ever changes, this is the assertion that fails first, because it
				// is the one that says the route cannot refuse a page at all.
				policy := authz.NewPolicy(role.anonymousRead)
				for _, who := range []authz.Principal{
					authz.ForUser(1, adminName, authz.RoleAdmin, role.anonymousRead),
					authz.ForUser(2, dmName, authz.RoleDM, role.anonymousRead),
					authz.ForUser(3, playerName, authz.RolePlayer, role.anonymousRead),
					authz.Anonymous(role.anonymousRead),
				} {
					if who.CanReadPublic() && !policy.Allows(who, authz.PermReadPage, authz.Resource{}) {
						t.Errorf("the export is mounted on PermReadPage and %s may read public content but is refused a page; this suite's export tests assume a page a reader cannot read does not exist yet, and that assumption is no longer true", who)
					}
				}
			})
		})
	}

	t.Run("an export does not measure the body it refused", func(t *testing.T) {
		t.Parallel()
		// The assertion a fixed label cannot satisfy: two vaults whose hidden
		// bodies have different lengths, exported to the same principal, must
		// produce the same bytes. A placeholder carrying a length or a digest
		// would make the two differ by exactly the thing it must not disclose.
		shortBody := "one."
		longBody := strings.Repeat("padding ", 64) + "and a little more."
		short := leakExportFixture(t, shortBody)
		long := leakExportFixture(t, longBody)
		if len(longBody) == len(shortBody) {
			t.Fatal("the two hidden bodies are the same length, so the comparison below would pass for the wrong reason")
		}
		a := signInForRole(t, short, leakRole{name: "player", expect: rolePlayer, user: otherName, pass: otherPass}).getOK("/p/Tavern.md/export")
		b := signInForRole(t, long, leakRole{name: "player", expect: rolePlayer, user: otherName, pass: otherPass}).getOK("/p/Tavern.md/export")
		if a == b {
			return
		}
		t.Errorf("two exports of the same page whose hidden body is %d bytes and %d bytes differ, so the export measures the body it refused: the short one is %d bytes, the long one is %d",
			len(shortBody), len(longBody), len(a), len(b))
		// The bodies differ, so name where they differ — the offset, not the
		// bytes, because a failure here may be the suite printing a secret body
		// to a CI log, which is the thing this whole file is about.
		t.Errorf("the two exports first disagree at byte %d, so the difference is in the redacted region rather than in the public text: the hidden bodies are %d and %d bytes",
			firstDifference(a, b), len(shortBody), len(longBody))
	})

	t.Run("the content-disposition filename cannot split a header", func(t *testing.T) {
		t.Parallel()
		// A page's name is an author's file name and is therefore whatever they
		// typed, so it is not something that can be pasted into a response header
		// unexamined. A quote is the character that matters: it ends the quoted
		// string the name is written into, and anything after it is parsed as a
		// new parameter. It is also legal in a POSIX file name, so an author can
		// produce one without trying.
		fx := newFixtureWith(t, map[string]string{
			"Index.md":          "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nSee the [[Odd]].\n",
			"Quote \"only\".md": "---\ntitle: Odd\ntype: note\n---\n\n# Odd\n\nA page with an awkward name.\n",
			// A backslash is refused, so it is here to be measured rather than
			// assumed: see the subtest below.
			"Back\\slash.md": "---\ntitle: B\ntype: note\n---\n\n# B\n\nAnother awkward name.\n",
		})
		// accounts and not accountsFor: this vault has no Tavern page, and
		// accountsFor grants ownership of one, which is a failure in the fixture
		// rather than in the route under test.
		fx.accounts()
		s := fx.asUser(otherName, otherPass)

		resp := s.do(s.get("/p/" + url.PathEscape("Quote \"only\".md") + "/export"))
		body := s.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the export of a page with a quote in its name: status %d, want 200", resp.StatusCode)
		}
		if len(body) == 0 {
			t.Error("the export of a page with a quote in its name is empty")
		}
		disposition := resp.Header.Get("Content-Disposition")
		if disposition == "" {
			t.Fatal("the export carries no Content-Disposition, so the filename assertion is measuring nothing")
		}
		if strings.ContainsAny(disposition, "\r\n") {
			t.Errorf("the Content-Disposition carries a line break, which is a split response header: %q", disposition)
		}
		if !strings.Contains(disposition, "attachment;") {
			t.Errorf("the Content-Disposition is %q, want an attachment", disposition)
		}
		if name := dispositionName(t, disposition); strings.ContainsAny(name, "\"\\\r\n") {
			t.Errorf("the Content-Disposition filename is %q, which still carries a quote, a backslash or a line break", name)
		}

		t.Run("a backslash in a page name is refused, not served", func(t *testing.T) {
			// Measured rather than assumed. A backslash is a path separator on
			// Windows and an escape character in a quoted string, so a page whose
			// name carries one is not servable by a route whose whole job is to
			// turn a name into a header parameter — and the answer it gets has to
			// be the same answer a page that is not there gets, or the refusal
			// confirms that something is.
			refused := s.do(s.get("/p/" + url.PathEscape("Back\\slash.md") + "/export"))
			refusedBody := s.read(refused)
			if refused.StatusCode != http.StatusNotFound {
				t.Errorf("the export of a page whose name carries a backslash: status %d, want 404", refused.StatusCode)
			}
			missing := s.do(s.get("/p/There-is-no-such-page.md/export"))
			if got := s.read(missing); got != refusedBody {
				t.Errorf("a refused page name answers differently from a page that does not exist (%d bytes against %d)",
					len(refusedBody), len(got))
			}
		})
	})
}

// leakExportFixture is a two-page vault whose one page carries a hidden fence
// whose body is the given text, for the length-independence comparison.
func leakExportFixture(t *testing.T, hidden string) *fixture {
	t.Helper()
	fx := newFixtureWith(t, map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
			"A public line.\n\n" +
			"```secret id=e1e1e1e1e1e1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The trap\"\n" +
			hidden + "\n```\n\n",
	})
	fx.accountsFor()
	return fx
}

// firstDifference is the offset of the first byte two exports disagree on.
func firstDifference(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// dispositionName is the filename parameter of a Content-Disposition header.
func dispositionName(t *testing.T, disposition string) string {
	t.Helper()
	const key = `filename="`
	i := strings.Index(disposition, key)
	if i < 0 {
		t.Fatalf("the Content-Disposition %q carries no quoted filename", disposition)
	}
	rest := disposition[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("the Content-Disposition %q has an unterminated filename", disposition)
	}
	return rest[:j]
}

// newFailingReindexFixture is a second view of the same fixture, pointed at a
// second server whose reindexer refuses.
//
// It exists for the log test and it is the shape internal/secrets/save_test.go
// uses for the same property one layer down: a save whose derivation failed must
// be reported, and the report must not carry the page. Everything else — the
// database, the writer, the policy, the logger, the assets, the renderer — is the
// fixture's own, so the response under test is the one the ordinary server
// produces. There is no production seam for a failing reindexer, and adding one
// would have been an edit to a file this work does not own.
func newFailingReindexFixture(t *testing.T, fx *fixture) *fixture {
	t.Helper()
	srv, err := httpapi.New(httpapi.Options{
		Config:        fx.cfg,
		DB:            fx.DB,
		Writer:        fx.Vault,
		Reindexer:     failingReindexer{},
		AuthorRetryer: fx.Indexer,
		Log:           fx.Log,
		Clock:         fx.Clock.obs(),
		Build:         app.Info(),
		Assets:        web.Assets(),
		Renderer:      web.NewRenderer(),
	})
	if err != nil {
		t.Fatalf("build the server with a failing reindexer: %v", err)
	}
	return viewOver(t, fx, srv.Handler())
}

// viewOver is a second view of the same fixture, pointed at another handler, so
// that a test can drive a client at something the fixture's own client cannot
// reach — a scanned handler, a reindexer that refuses. Every other field is the
// first fixture's, including the two log sinks, so a test can still read what the
// request path wrote.
//
// The view is a literal rather than a copy of the original: the fixture carries
// two sync.Once fields, and copying a struct that holds one is a vet failure and,
// worse, a copy of a lock that has already fired.
func viewOver(t *testing.T, fx *fixture, handler http.Handler) *fixture {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &fixture{
		t: t, dir: fx.dir, cfg: fx.cfg,
		DB: fx.DB, Auth: fx.Auth, Vault: fx.Vault, Root: fx.Root,
		Log: fx.Log, mainLog: fx.mainLog, auditLog: fx.auditLog, Clock: fx.Clock,
		Indexer: fx.Indexer, Secrets: fx.Secrets,
		HTTP: ts,
	}
}

// failingReindexer refuses to derive the index after a write.
type failingReindexer struct{}

func (failingReindexer) Reindex(context.Context, string) error {
	return errReindexUnavailable
}

// errReindexUnavailable is the reason the reindexer gives. It names the
// subsystem and nothing else, so that a log assertion over the failure cannot
// pass because the error happened to carry the page.
var errReindexUnavailable = errors.New("the indexer is not available")
