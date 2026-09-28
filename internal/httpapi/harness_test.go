// Package httpapi_test holds the tests for the router, the middleware chain and
// the handlers.
//
// This is the external test package on purpose: it may import internal/web,
// which imports internal/httpapi, and an internal test package could not. Every
// test here drives the real stack — a real store, a real vault in a temp
// directory, real argon2id accounts and a real index pass — because a matrix
// over stubs is a matrix over the stubs.
package httpapi_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// fixture is a booted application behind an httptest server: a real vault, a
// real index, real accounts and the real middleware chain.
type fixture struct {
	t     *testing.T
	dir   string
	cfg   config.Config
	DB    *store.DB
	Auth  *auth.Service
	Vault *vault.Writer
	Root  string
	Log   *obs.Logger
	Clock *testClock
	// Indexer is kept so a test can force a reindex after writing a file the way
	// the vault watcher would.
	Indexer *isync.Indexer
	// invite holds the one invite this fixture minted, and inviteOnce guards it,
	// because the route table has one /invite/{token} row and a test needs a
	// concrete token in the path to fill it in.
	inviteOnce sync.Once
	invite     string
	// Secrets is a second handle on the same service the router uses. It is the
	// same database, writer, policy and indexer, so what it reveals is what the
	// router will read.
	Secrets *secrets.Service
	Server  *httpapi.Server
	HTTP    *httptest.Server
}

// newFixture boots a server over the standard seeded campaign.
func newFixture(t *testing.T, mutate ...func(*config.Config)) *fixture {
	t.Helper()
	return newFixtureWith(t, campaignFiles, mutate...)
}

// newFixtureWith is newFixture with a caller-supplied vault, for the tests that
// need a hostile file, a huge one, or a specific set of pages.
func newFixtureWith(t *testing.T, files map[string]string, mutate ...func(*config.Config)) *fixture {
	t.Helper()
	dir := t.TempDir()
	writeVault(t, dir, files)

	// Default() rather than a literal: the struct has a dozen fields and a
	// literal would silently take this phase's defaults for the fields nobody
	// has thought about yet.
	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = 0
	cfg.Vault = dir
	cfg.NoOpen = true
	for _, m := range mutate {
		m(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the fixture's configuration is not valid: %v", err)
	}

	log := obs.NewLogger(io.Discard, obs.Options{Level: slog.LevelError})
	clock := &testClock{now: startTime}
	clockFn := clock.obs()

	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The schema is created here rather than by a boot, because the test owns
	// this vault: app.Boot's migration path also takes a backup and writes a boot
	// state, and a fixture that booted a whole application to get a table would
	// be a test of app rather than of the router.
	// Migrate insists on a backup hook even when there is nothing to back up,
	// which is the right rule for a real boot and is satisfied here by a hook
	// that records that it was asked and copies nothing: the vault is a temp
	// directory holding three files this test wrote.
	var backupCalls int
	if err := store.Migrate(context.Background(), db.Writer(), func(context.Context) error {
		backupCalls++
		return nil
	}); err != nil {
		t.Fatalf("migrate the index: %v", err)
	}
	if backupCalls != 1 {
		t.Fatalf("the migration ran with %d backup hooks, want 1", backupCalls)
	}

	writer := vault.NewWriter(dir, log)
	ix, err := isync.New(isync.Options{DB: db, Root: dir, Log: log, Clock: clockFn})
	if err != nil {
		t.Fatalf("build the indexer: %v", err)
	}
	// Walk lists the vault; IndexBatch is what derives rows from it. Both are
	// needed, and the distinction matters to anyone extending this fixture: the
	// walk on its own leaves an empty index and every page route a 404.
	// A booted application is a ready one, and the readiness probe answers from
	// this key rather than re-deriving readiness. A fixture that left it unset
	// would be testing a vault mid-boot, which is not what any of these tests are
	// about.
	if err := store.MetaSet(context.Background(), db.Writer(), store.KeyBootState, store.BootStateReady); err != nil {
		t.Fatalf("record the boot state: %v", err)
	}

	res, err := ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk the vault: %v", err)
	}
	if _, err := ix.IndexBatch(context.Background(), res.Files); err != nil {
		t.Fatalf("index the vault: %v", err)
	}

	policy := authz.NewPolicy(cfg.AllowAnonymousRead)
	accounts, err := auth.New(auth.Options{DB: db, Policy: policy, Log: log, Clock: clockFn})
	if err != nil {
		t.Fatalf("build the account service: %v", err)
	}
	secretSvc, err := secrets.NewService(secrets.Options{
		DB:        db,
		Writer:    writer,
		Policy:    policy,
		Reindexer: ix,
		Log:       log,
		Clock:     clockFn,
	})
	if err != nil {
		t.Fatalf("build the secrets service: %v", err)
	}

	srv, err := httpapi.New(httpapi.Options{
		Config:    cfg,
		DB:        db,
		Writer:    writer,
		Reindexer: ix,
		// The same indexer in both roles, exactly as the composition root
		// wires it. A fixture that left AuthorRetryer nil would silently test
		// the broken configuration, because the gap only shows up after a
		// setup request.
		AuthorRetryer: ix,
		Log:           log,
		Clock:         clockFn,
		Build:         app.Info(),
		Assets:        web.Assets(),
		Renderer:      web.NewRenderer(),
	})
	if err != nil {
		t.Fatalf("build the server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &fixture{
		t: t, dir: dir, cfg: cfg,
		DB: db, Auth: accounts, Vault: writer, Root: dir,
		Log: log, Clock: clock, Indexer: ix, Secrets: secretSvc,
		Server: srv, HTTP: ts,
	}
}

// campaignFiles is the campaign every fixture is seeded with.
//
// The four secret fences are what the leak tripwire walks: one readable only by
// DMs and its author, one readable by nobody but a DM, one readable by the page
// owner, and one revealed to the table. Each carries a token that appears
// nowhere else in the campaign, so finding one in a response cannot be an
// accident of vocabulary.
var campaignFiles = map[string]string{
	"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\n" +
		"The [[Tavern]] is where the party met. See also [[Ruin]] and the\n" +
		"[[Nowhere-at-all]] that was never written.\n",
	"Tavern.md": "---\ntitle: The Drowned Lantern\naliases: [the lantern]\ntags: [area/port]\n---\n\n" +
		"# The Drowned Lantern\n\nLandlord Orrin keeps the only dry room in [[Index]].\n\n" +
		fence("a1a1a1a1a1a1", "private", "dungeonmaster", "The cellar key", "PRIVATE-BODY-TOKEN-9f3a2c") +
		fence("b2b2b2b2b2b2", "dm", "dungeonmaster", "The true name", "DM-BODY-TOKEN-7b1e4d") +
		fence("c3c3c3c3c3c3", "private", "thia", "Thia's own", "OWNER-BODY-TOKEN-2a6e10") +
		fence("d4d4d4d4d4d4", "table", "dungeonmaster", "Shared with the table", "TABLE-BODY-TOKEN-5d0a8f"),
	"Ruin.md": "---\ntitle: The Salt Ruin\ntags: [area/wild]\n---\n\n" +
		"# The Salt Ruin\n\nReached from [[Index]]. The [[Tavern|the lantern]] is the last dry stop.\n\n" +
		fence("e5e5e5e5e5e5", "dm", "dungeonmaster", "The trap", "RUIN-BODY-TOKEN-2c8f61"),
}

// searchWord is a word that appears in the body of every secret in the fixture
// and in no page.
//
// It exists so the search tripwire can ask "what happens when a reader searches
// for something that only a hidden secret contains" without searching for the
// secret's own token: the search form echoes the term back, so a term that is
// itself a secret body would be found in the response for that reason alone and
// the assertion would prove nothing. With a shared word, one term distinguishes
// all five secrets and none of them is the term.
const searchWord = "obsidianquill"

// fence is one secret fence in the on-disk syntax.
//
// Two details are load-bearing and both cost a leak if they are wrong. The title
// is quoted, because an unquoted value ends at the first space and the leftover
// words are then read as further directive keys — and a directive with an unknown
// key is demoted to public, which means the body is served to everybody. And the
// author is a real username, because secrets.author_id is a foreign key: an
// author that does not resolve leaves the fence with no author, and every
// authorization question about it is then answered wrongly rather than refused.
func fence(id, visibility, author, title, body string) string {
	return "```secret id=" + id +
		" visibility=" + visibility +
		" author=" + author +
		" created=2026-01-01T00:00:00Z" +
		" title=" + strconv.Quote(title) +
		"\n" + body + " " + searchWord + "\n```\n\n"
}

// bodyTokens are the strings that must never appear in a response to a
// principal that may not read the secret holding them. Each appears in exactly
// one fence in exactly one file.
var bodyTokens = []string{
	"PRIVATE-BODY-TOKEN-9f3a2c",
	"DM-BODY-TOKEN-7b1e4d",
	"OWNER-BODY-TOKEN-2a6e10",
	"RUIN-BODY-TOKEN-2c8f61",
	"TABLE-BODY-TOKEN-5d0a8f",
}

// tableToken is the one body a player may read: a table-visible secret. It is
// in the list above because a *disabled* or anonymous principal must not see it
// either, and because the negative assertion for it is that no other principal
// outside the DM set reads it.
const tableToken = "TABLE-BODY-TOKEN-5d0a8f"

// Accounts created by setupFixtureAccounts. The usernames are fixed so that a
// failing matrix row names a known role.
const (
	dmName     = "dungeonmaster"
	playerName = "thia"
	otherName  = "bram"
	adminName  = "archivist"
	dmPass     = "correct horse battery staple"
	playerPass = "player passphrase, long enough"
	otherPass  = "another player passphrase, long"
	adminPass  = "the administrator passphrase here"
)

// onePlayer populates a fixture with an administrator and a single player.
//
// The cheaper sibling of accounts, for the tests that need a signed-in client and
// nothing else. Every account costs an argon2id derivation, so a test that only
// needs somebody to be signed in should not pay for a DM and a second player.
func (fx *fixture) onePlayer() {
	fx.t.Helper()
	fx.t.Helper()
	admin, err := fx.Auth.Setup(context.Background(), adminName, "The Archivist", adminPass)
	if err != nil {
		fx.t.Fatalf("claim the first administrator: %v", err)
	}
	token, err := fx.Auth.CreateInvite(context.Background(), admin, authz.RolePlayer, time.Hour)
	if err != nil {
		fx.t.Fatalf("invite a player: %v", err)
	}
	if _, err := fx.Auth.AcceptInvite(context.Background(), auth.RedeemRequest{
		Token: token, Username: otherName, DisplayName: "Bram", Passphrase: otherPass,
	}); err != nil {
		fx.t.Fatalf("redeem the player's invite: %v", err)
	}
	fx.reindexAll()
}

// accounts populates a fixture with one administrator, one DM and two players.
//
// It is separate from accountsFor because a test that seeds its own vault may not
// have a Tavern page, and a grant of ownership to a page that is not there is a
// failure in the fixture rather than in the code under test.
func (fx *fixture) accounts() {
	fx.t.Helper()
	fx.accountsForAccounts()
	// The reindex that resolves each fence's author= to a user id has to happen
	// after the accounts exist, whichever of the two entry points was used.
	fx.reindexAll()
}

// accountsFor populates a fixture with one administrator, one DM, a player who
// owns the Tavern page, and a second player who owns nothing.
//
// Ownership is granted explicitly rather than by who wrote the file: the index
// does not infer it, and the matrix has to be able to test "a page owner may
// write the page and may not read its dm secret" against a state the test
// actually set up.
func (fx *fixture) accountsFor() {
	fx.t.Helper()
	fx.accountsForAccounts()
	if err := fx.addOwner("Tavern.md", fx.userID(playerName)); err != nil {
		fx.t.Fatal(err)
	}
	fx.reindexAll()
}

// accountsForAccounts is the account half of both entry points.
func (fx *fixture) accountsForAccounts() {
	fx.t.Helper()
	ctx := context.Background()

	admin, err := fx.Auth.Setup(ctx, adminName, "The Archivist", adminPass)
	if err != nil {
		fx.t.Fatalf("claim the first administrator: %v", err)
	}
	// Accounts are created the way an operator creates them — an invite, then a
	// redemption — so the roles in the matrix are the ones the invite path
	// actually grants rather than ones a test assigned behind its back.
	for _, a := range []struct {
		user, display, pass string
		role                authz.Role
	}{
		{dmName, "The Dungeon Master", dmPass, authz.RoleDM},
		{playerName, "Thia", playerPass, authz.RolePlayer},
		{otherName, "Bram", otherPass, authz.RolePlayer},
	} {
		token, err := fx.Auth.CreateInvite(ctx, admin, a.role, time.Hour)
		if err != nil {
			fx.t.Fatalf("invite %s: %v", a.user, err)
		}
		if _, err := fx.Auth.AcceptInvite(ctx, auth.RedeemRequest{
			Token: token, Username: a.user, DisplayName: a.display, Passphrase: a.pass,
		}); err != nil {
			fx.t.Fatalf("redeem the invite for %s: %v", a.user, err)
		}
	}
}

// reindexAll drops the derived index and derives it again.
//
// It is needed because a secret fence names its author by username, and the
// indexer resolves that name to a user id. A vault indexed before the accounts
// exist therefore records no author for any secret, and every authorization
// question about that secret gets the wrong answer — which is exactly the sort
// of thing a test must not accidentally arrange. The sequence here is the one a
// real boot has: accounts are claimed, then the index is derived.
func (fx *fixture) reindexAll() {
	fx.t.Helper()
	ctx := context.Background()
	if _, err := fx.Indexer.RemoveMissing(ctx, nil); err != nil {
		fx.t.Fatalf("drop the derived index: %v", err)
	}
	res, err := fx.Indexer.Walk(ctx)
	if err != nil {
		fx.t.Fatalf("walk the vault: %v", err)
	}
	if _, err := fx.Indexer.IndexBatch(ctx, res.Files); err != nil {
		fx.t.Fatalf("reindex the vault: %v", err)
	}
}

// addOwner grants a user ownership of a page by path, through the writer, so
// that the grant is hash-checked and audited exactly as a real one would be.
func (fx *fixture) addOwner(path string, userID int64) error {
	row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), path)
	if err != nil {
		return err
	}
	return store.AddPageOwner(context.Background(), fx.DB.Writer(), store.PageOwner{
		PageID:  row.ID,
		UserID:  userID,
		IsOwner: true,
		AddedAt: fx.Clock.now,
	})
}

// session is one browser: its own cookie jar, so two principals in one test
// never see each other's cookie.
type session struct {
	t    *testing.T
	fx   *fixture
	jar  http.CookieJar
	http *http.Client
	// mu guards csrf, which the client re-reads from every response it is allowed
	// to see. A session that is driven from several goroutines at once — which the
	// concurrency test does deliberately — is writing the same value from all of
	// them, and "the same value" is still a data race.
	mu   sync.Mutex
	csrf string
}

// newSession returns an unauthenticated browser.
func (fx *fixture) newSession() *session {
	fx.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		fx.t.Fatalf("build a cookie jar: %v", err)
	}
	s := &session{
		t:   fx.t,
		fx:  fx,
		jar: jar,
		http: &http.Client{
			Jar: jar,
			// Redirects are not followed. A test asserting a status is asserting
			// the status the server sent, and a client that followed would be
			// asserting the second request instead.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return s
}

// call is one request, described.
type call struct {
	method  string
	path    string
	form    url.Values
	body    string
	ctype   string
	csrf    string
	noCSRF  bool
	badCSRF bool
	headers map[string]string
}

// get starts a GET.
func (s *session) get(path string) *call {
	return &call{method: http.MethodGet, path: path}
}

// post starts a form POST.
func (s *session) post(path string, form url.Values) *call {
	return &call{method: http.MethodPost, path: path, form: form}
}

// fragment starts a GET that asks for the content region on its own.
func (s *session) fragment(path string) *call {
	return &call{method: http.MethodGet, path: path, headers: map[string]string{
		httpapi.DataStarRequestHeader: "true",
	}}
}

// token is the session's current CSRF token.
func (s *session) token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csrf
}

// setToken replaces it.
func (s *session) setToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrf = token
}

// withJar adopts another session's cookie jar, the way a browser that has been
// copied from another profile would present the same cookies. It replaces the
// client too, because a client holds the jar it sends from and swapping only the
// field would send the old one — which is a subtle way for a test to assert
// something about a client that is not the one it thinks it is driving.
func (s *session) withJar(jar http.CookieJar) *session {
	s.jar = jar
	s.http.Jar = jar
	return s
}

// do performs the request.
//
// A session that has no CSRF token yet asks for one first, the way a browser
// does: it loads the form, reads the token out of the hidden field, and submits
// with it. A caller may supply its own token on the call — that is how a test
// presents another session's — and badCSRF and noCSRF are the two ways to supply
// a token that is wrong or absent.
func (s *session) do(c *call) *http.Response {
	s.t.Helper()
	if c.csrf == "" && s.token() == "" && !c.noCSRF && !c.badCSRF {
		s.prime()
	}
	switch {
	case c.csrf != "":
	case c.badCSRF:
		c.csrf = strings.Repeat("0", 64)
	case c.noCSRF:
		c.csrf = ""
	default:
		c.csrf = s.token()
	}
	return s.send(c)
}

// prime loads the login form so the session holds a token and the pre-session
// cookie a form must carry.
//
// It goes through send rather than through do, because do primes: a prime that
// went through do would call itself.
func (s *session) prime() {
	s.t.Helper()
	// The campaign is the page a signed-in session may always see, and the login
	// form is the page an anonymous one may. Asking for the first and falling
	// back to the second is one round trip for a signed-in session and two for an
	// anonymous one, which is the right order: the anonymous case is the one that
	// happens once, and the signed-in case happens before every mutation.
	s.send(s.get("/"))
	if s.token() == "" {
		s.send(s.get("/login"))
	}
}

// send performs the request without priming a token.
func (s *session) send(c *call) *http.Response {
	s.t.Helper()
	reader := io.Reader(strings.NewReader(""))
	switch {
	case c.body != "":
		reader = strings.NewReader(c.body)
		if c.ctype == "" {
			c.ctype = "application/x-www-form-urlencoded"
		}
	case c.form != nil:
		reader = strings.NewReader(c.form.Encode())
		c.ctype = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(context.Background(), c.method, s.fx.HTTP.URL+c.path, reader)
	if err != nil {
		s.t.Fatalf("build the request: %v", err)
	}
	if c.ctype != "" {
		req.Header.Set("Content-Type", c.ctype)
	}
	if c.csrf != "" {
		req.Header.Set(httpapi.CSRFHeader, c.csrf)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		s.t.Fatalf("perform %s %s: %v", c.method, c.path, err)
	}
	// The server mints the session-bound token at render time, so a session
	// that has just signed in has to read it out of a page it is allowed to see.
	// That is exactly what a browser does, and it is why the token never has to
	// be readable by a client that has not been given the page.
	if c.method == http.MethodGet {
		if body, err := io.ReadAll(resp.Body); err == nil {
			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			// A response the client is allowed to see carries the token for the
			// forms that follow it, so the client re-reads it rather than caching
			// one value: a session that rotated must not keep presenting the old
			// token, and a client that never re-reads one cannot submit anything.
			if token, ok := csrfFrom(string(body)); ok && resp.StatusCode == http.StatusOK {
				s.setToken(token)
			}
		}
	}
	return resp
}

// text performs a request and returns the body as a string.
func (s *session) text(c *call) string {
	s.t.Helper()
	return s.read(s.do(c))
}

// read returns a response's body as a string and closes it.
func (s *session) read(resp *http.Response) string {
	s.t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("read a response body: %v", err)
	}
	return string(body)
}

// status performs a request and returns only the status code.
func (s *session) status(c *call) int {
	s.t.Helper()
	resp := s.do(c)
	defer drain(resp)
	return resp.StatusCode
}

// get performs a GET and returns the body.
func (s *session) getOK(path string) string {
	s.t.Helper()
	resp := s.do(s.get(path))
	body := s.read(resp)
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("GET %s: status %d, want 200\n%s", path, resp.StatusCode, body)
	}
	return body
}

// login signs the session in and returns the response.
func (s *session) login(user, passphrase string) *http.Response {
	s.t.Helper()
	// prime() gives the session the pre-session token the login form needs.
	s.prime()
	resp := s.do(&call{
		method: http.MethodPost,
		path:   "/login",
		form:   url.Values{"username": {user}, "passphrase": {passphrase}},
		csrf:   s.token(),
	})
	// A successful login replaces the pre-session token with the session's own, so
	// the next page render is what refreshes it. A browser does that by following
	// the redirect; this client does not follow redirects, so it asks for the page
	// itself. Reading the token from a page the session may see is also the
	// honest way to do it: the token is not readable any other way.
	if resp.StatusCode == http.StatusSeeOther {
		s.setToken("")
		s.prime()
	}
	return resp
}

// asUser returns a session already signed in as one of the fixture's accounts.
func (fx *fixture) asUser(user, passphrase string) *session {
	fx.t.Helper()
	s := fx.newSession()
	resp := s.login(user, passphrase)
	body := s.read(resp)
	if resp.StatusCode != http.StatusSeeOther {
		fx.t.Fatalf("sign %s in: status %d, want 303\n%s", user, resp.StatusCode, body)
	}
	return s
}

// sessionFor returns an independent client presenting a given session token.
//
// It is how a table-driven test gets one row's isolation from the next without
// one fixture per cell: the row gets its own cookie jar holding its own copy of
// the token, so a row that signs out destroys its own session and the next row
// arrives with one still alive. No argon2id is spent, which is the whole point —
// the alternative is a vault boot and four key derivations per row.
//
// A disabled account is the case that makes this worth having: the token is
// captured *before* the account is turned off, so the client presents a cookie
// that no longer resolves, which is the state the "disabled" row of the matrix is
// about.
func (fx *fixture) sessionFor(raw string) *session {
	fx.t.Helper()
	s := fx.newSession()
	if raw == "" {
		return s
	}
	u, err := url.Parse(fx.HTTP.URL + "/")
	if err != nil {
		fx.t.Fatalf("parse the server url: %v", err)
	}
	s.jar.SetCookies(u, []*http.Cookie{{Name: httpapi.SessionCookie, Value: raw, Path: "/"}})
	return s
}

// asUserPass signs in and returns the response without asserting, for the tests
// that want to inspect a failure.
func (fx *fixture) asUserPass(user, pass string) *session {
	fx.t.Helper()
	s := fx.newSession()
	resp := s.login(user, pass)
	drain(resp)
	return s
}

// loginReq is the login request the harness builds.
func loginReq(user, pass string) auth.LoginRequest {
	return auth.LoginRequest{Username: user, Passphrase: pass}
}

// loginCall is the login form submission the harness builds.
func loginCall(user, pass, csrf string) *call {
	return &call{
		method: http.MethodPost, path: "/login",
		form: url.Values{"username": {user}, "passphrase": {pass}}, csrf: csrf,
	}
}

// disable turns an account off, which must leave it with no session at all.
func (fx *fixture) disable(username string) {
	fx.t.Helper()
	admin, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), adminName)
	if err != nil {
		fx.t.Fatalf("look up the administrator: %v", err)
	}
	if err := fx.Auth.Disable(context.Background(), authz.ForUser(admin.ID, admin.Username, authz.RoleAdmin, false), fx.userID(username)); err != nil {
		fx.t.Fatalf("disable %s: %v", username, err)
	}
}

// adminPrincipal is the first administrator, as a Principal the policy will
// accept. It is built from the row rather than from a constant so that a test
// which disabled the administrator would be refused rather than passing on a
// stale id.
func (fx *fixture) adminPrincipal() authz.Principal {
	fx.t.Helper()
	u, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), adminName)
	if err != nil {
		fx.t.Fatalf("look up the administrator: %v", err)
	}
	return authz.ForUser(u.ID, u.Username, authz.RoleAdmin, fx.cfg.AllowAnonymousRead)
}

// tryAdminPrincipal is adminPrincipal without the failure: on a vault with no
// administrator it returns the zero principal, which every administrative call
// refuses, which is the answer a stranger would get.
func (fx *fixture) tryAdminPrincipal() authz.Principal {
	u, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), adminName)
	if err != nil {
		return authz.Principal{}
	}
	return authz.ForUser(u.ID, u.Username, authz.RoleAdmin, fx.cfg.AllowAnonymousRead)
}

// cookieValue is one cookie a session is holding, or "".
func (fx *fixture) cookieValue(s *session, name string) string {
	fx.t.Helper()
	u, err := url.Parse(fx.HTTP.URL + "/")
	if err != nil {
		fx.t.Fatalf("parse the server url: %v", err)
	}
	for _, c := range s.jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// liveSessionCount is how many sessions the database still considers live for an
// account. It is read through the index rather than through the router, because
// the router has no way to enumerate sessions and a count taken from the client's
// own jar would only prove what the client did.
func (fx *fixture) liveSessionCount(userID int64) int {
	fx.t.Helper()
	// A revocation deletes the row rather than stamping it, so a live session is a
	// row that is still there and has not expired. Counting rows directly is
	// deliberate: a count taken from the client's own jar would prove only what
	// the client did.
	var rows int
	if err := fx.DB.Reader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = ? AND expires_at > ?`, userID, store.FormatTime(fx.Clock.now)).Scan(&rows); err != nil {
		fx.t.Fatalf("count the session rows: %v", err)
	}
	return rows
}

// sessionCountAll is how many session rows exist at all, across every account.
// It is for assertions that something was *not* written, where a per-account
// count would be a count of the wrong thing.
func (fx *fixture) sessionCountAll() int {
	fx.t.Helper()
	var n int
	if err := fx.DB.Reader().QueryRowContext(context.Background(), `SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		fx.t.Fatalf("count the session rows: %v", err)
	}
	return n
}

// sessionRows is a diagnostic rendering of every session row an account has, for
// a count that came out wrong. It prints ids and states, never a token: the id is
// a hash the client never sees, and a failing assertion that printed the raw
// cookie would be a second leak in a test about leaks.
func (fx *fixture) sessionRows(userID int64) string {
	fx.t.Helper()
	rows, err := fx.DB.Reader().QueryContext(context.Background(),
		`SELECT id, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return "could not read the rows: " + err.Error()
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, created, expires string
		if err := rows.Scan(&id, &created, &expires); err != nil {
			return "could not scan a row: " + err.Error()
		}
		out = append(out, id[:8]+"… created="+created+" expires="+expires)
	}
	if len(out) == 0 {
		return "no rows"
	}
	return strings.Join(out, "; ")
}

// userID is an account's id by name.
func (fx *fixture) userID(username string) int64 {
	fx.t.Helper()
	u, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), username)
	if err != nil {
		fx.t.Fatalf("look up %s: %v", username, err)
	}
	return u.ID
}

// csrfField matches the hidden CSRF input every form carries.
var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]{64})"`)

// csrfFrom pulls the CSRF token out of a rendered page, the way a browser reads
// it out of the form it is about to submit.
func csrfFrom(body string) (string, bool) {
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// writeVault seeds a vault directory.
func writeVault(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create the directory for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
}

// drain closes a response and reads whatever is left, so a test that only wants
// a status does not leak a connection.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// startTime is the instant every fixture's clock starts at.
//
// It is the real current time, truncated to the second, rather than a fixed
// date. The reason is the session cookie: its Expires attribute is computed from
// the server's clock, and a test client's cookie jar judges expiry against its
// own. A server clock set in the past therefore mints a cookie that is already
// expired, and the jar silently drops it — which looks exactly like a session
// that never worked. A test that needs a different instant moves the clock; the
// assertions that compare two responses byte for byte compare requests from the
// same run, so a real starting point costs them nothing.
var startTime = time.Now().UTC().Truncate(time.Second)

// testClock is a clock a test can move. obs.Clock is a func type, so a movable
// clock is a closure over this rather than a type implementing an interface.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// obs is the clock func the services take.
func (c *testClock) obs() obs.Clock {
	return func() time.Time {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.now
	}
}

// advance moves the clock forward. The rate limiter and the session lifetime are
// the two things a test needs to move it for.
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
