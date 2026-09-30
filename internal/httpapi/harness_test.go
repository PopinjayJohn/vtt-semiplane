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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// fixture is a booted application behind an httptest server: a real vault, a
// real index, real accounts and the real middleware chain.
//
// t is a testing.TB rather than a *testing.T so that bench_test.go drives this
// fixture rather than a second one. A page-render budget is a router + render +
// SQL number, and a benchmark that built its own server would be measuring a
// server that is not the one the routes run on.
type fixture struct {
	t     testing.TB
	dir   string
	cfg   config.Config
	DB    *store.DB
	Auth  *auth.Service
	Vault *vault.Writer
	Root  string
	Log   *obs.Logger
	// mainLog and auditLog are the two sinks obs writes to, held in memory. They
	// are captured rather than discarded because the assertion a test in this
	// package most needs to be able to make — that a request path leaked nothing
	// to the log — is impossible against io.Discard, and a discard is exactly the
	// failure that reads as a pass.
	//
	// Two buffers rather than one because obs keeps them apart: Audit is a second
	// handler with its own allow-list and its own level, so a leak test that
	// merged them would pass for the wrong reason on one and fail for the wrong
	// reason on the other.
	mainLog  *safeBuffer
	auditLog *safeBuffer
	Clock    *testClock
	// Indexer is kept so a test can force a reindex after writing a file the way
	// the vault watcher would.
	Indexer *isync.Indexer
	// invite holds the one invite this fixture minted, and inviteOnce guards it,
	// because the route table has one /invite/{token} row and a test needs a
	// concrete token in the path to fill it in.
	inviteOnce sync.Once
	invite     string
	// newestRevision is the id of the most recent revision of Index.md, and
	// revisionOnce guards producing it. It exists because the revert route's
	// address names a revision, and a vault has none until something writes one.
	revisionOnce   sync.Once
	newestRevision string
	// Secrets is a second handle on the same service the router uses. It is the
	// same database, writer, policy and indexer, so what it reveals is what the
	// router will read.
	Secrets *secrets.Service
	Server  *httpapi.Server
	HTTP    *httptest.Server
}

// newFixture boots a server over the standard seeded campaign.
func newFixture(t testing.TB, mutate ...func(*config.Config)) *fixture {
	t.Helper()
	return newFixtureWith(t, campaignFiles, mutate...)
}

// newFixtureWith is newFixture with a caller-supplied vault, for the tests that
// need a hostile file, a huge one, or a specific set of pages.
//
// The plugins argument is the registry the server is built with. It is a
// variadic for the same reason mutate is: most tests want no plugins, and a
// parameter they would have to write `nil` for is a parameter they will forget.
// A test that needs one passes a registry; a test that does not gets the nil
// registry a build with no plugin lifecycle produces, which is a real state
// rather than an unset one.
//
// The corpus is a map and the number of entries is not this function's business.
// It writes what it is given, walks it and indexes it, so a 2000-page campaign
// costs the same code path a three-page one does.
func newFixtureWith(t testing.TB, files map[string]string, mutate ...func(*config.Config)) *fixture {
	return newFixturePlugins(t, files, nil, mutate...)
}

// newFixturePlugins is the fixture with a plugin registry wired in, for the
// tests that need a mounted sub-router or a summary provider to exist.
func newFixturePlugins(t testing.TB, files map[string]string, plugins plugin.Registry, mutate ...func(*config.Config)) *fixture {
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

	// Debug, not Error. The level is what makes the capture above worth having: a
	// sink that only ever records ERROR is a sink a leak assertion over it can
	// pass vacuously, because a body written by an Info or a Warn is invisible to
	// the very test that exists to catch it. The audit handler picks its own level
	// and is always Info.
	mainLog, auditLog := &safeBuffer{}, &safeBuffer{}
	log := obs.NewLogger(mainLog, obs.Options{Level: slog.LevelDebug, Audit: auditLog})
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
	if migrateErr := store.Migrate(context.Background(), db.Writer(), func(context.Context) error {
		backupCalls++
		return nil
	}); migrateErr != nil {
		t.Fatalf("migrate the index: %v", migrateErr)
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
	if metaSetErr := store.MetaSet(context.Background(), db.Writer(), store.KeyBootState, store.BootStateReady); metaSetErr != nil {
		t.Fatalf("record the boot state: %v", metaSetErr)
	}

	res, err := ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk the vault: %v", err)
	}
	if _, indexBatchErr := ix.IndexBatch(context.Background(), res.Files); indexBatchErr != nil {
		t.Fatalf("index the vault: %v", indexBatchErr)
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
		Plugins:       plugins,
	})
	if err != nil {
		t.Fatalf("build the server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &fixture{
		t: t, dir: dir, cfg: cfg,
		DB: db, Auth: accounts, Vault: writer, Root: dir,
		Log: log, mainLog: mainLog, auditLog: auditLog, Clock: clock,
		Indexer: ix, Secrets: secretSvc,
		Server: srv, HTTP: ts,
	}
}

// logs is everything both sinks have been given, for the leak suite.
//
// Each buffer is copied under its own lock, so a test may read the stream while
// the server is still logging. That ordering is real — a handler that writes a
// line after the response body is written is a normal thing for a request log to
// do — and a harness that raced to assert would report that line as present when
// it was not or absent when it was.
//
// The two sinks are concatenated rather than merged, for the reason obs keeps
// them apart: a finding that names a leak into the request log and a finding
// that names one into the audit trail are different findings, and a single
// string cannot say which.
func (fx *fixture) logs() string {
	return fx.mainLog.String() + fx.auditLog.String()
}

// safeBuffer is a bytes.Buffer that a request handler may write to from any
// goroutine while a test reads it.
//
// The push tests drive several connections at once against one fixture, and
// obs.Logger is safe for concurrent use only as far as its handler is; a plain
// bytes.Buffer is not.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	// dropping makes Write a no-op. The logger holds the io.Writer it was given
	// at construction, so the mode has to live behind Write rather than in the
	// field the writer would have been read from.
	dropping bool
}

// Write implements io.Writer.
func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dropping {
		return len(p), nil
	}
	return b.buf.Write(p)
}

// String returns a copy of what has been written so far.
func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// campaignFiles is the campaign every fixture is seeded with.
//
// The five secret fences on the first three pages are what the leak tripwire
// walks: one readable by a DM and by the page's owner, one readable by nobody
// but a DM, one readable by its own author, one revealed to the table, and one
// DM's private secret on a second page. Each carries a token that appears
// nowhere else in the campaign, so finding one in a response cannot be an
// accident of vocabulary.
//
// Those five are frozen. Their ids, visibilities, authors, titles and body text
// are spelled out as literals in matrix_test.go, nav_test.go, tripwire_test.go,
// demo_test.go, pageroutes_test.go and events_test.go, and every one of those is
// a literal rather than a lookup — deliberately, because a tripwire that reads
// its expectations out of the fixture cannot catch the fixture being wrong. So a
// new case gets a new fence and a new token; it does not get a reworded one.
//
// The pages after those carry one page per page-type id the host knows about, so
// that "the walk covered every page type" is a claim about this vault rather
// than a claim about one renderer. campaignPageTypes below is the same fact as
// data.
//
// Two constraints on the new paths are load-bearing rather than tidy.
//
// Every one of them sorts after Tavern.md, and none is a file the vault walk
// would reach earlier. Page ids come from the walk's path order, and
// matrix_test.go names Tavern.md as page id 3; a file sorting before it moves
// the page out from under that row. Lowercase names sort after uppercase ones,
// which is the whole reason none of these is called Index or Rule.
//
// None of the new pages links to Index, Ruin or Tavern. The Tavern rename's
// link updater is asserted to plan exactly the two pages that already refer to
// it, and a third would move the count without moving anything under test.
//
// One row in matrix_test.go does not survive this extension, and it is worth
// writing down here because the cause is a property of the campaign rather than
// of the row. That test asks for /api/pages/3/rename-preview and
// /api/pages/3/update-links *after* its own /api/pages/3/rename row has run, and
// a rename deletes the departed page row and inserts the new one, so the page
// comes back under a fresh id — max(rowid)+1 over what is left. With three pages
// that is 3 again, because deleting Tavern.md left Index.md and Ruin.md as ids 1
// and 2. With eleven it is 12, and id 3 is a hole, so those two rows get the
// 404 they were never asking about. No arrangement of extra pages avoids it: the
// id is max(rowid)+1 whatever order the vault is walked in, so the row can only
// hold for a campaign of exactly three pages. The fix belongs in the test —
// resolve the id from the path (fx.pageIDByPath("Tavern.md")) instead of pinning
// a number — and is not made here, because this file does not own it.
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

	// character, which internal/systems/dnd5e registers with CapCharacterSheet.
	// It carries both halves of §8.8 on one page, because that is the shape the
	// rule has: one file referenced from the public text and another referenced
	// only from inside a dm fence are two different answers, and on two separate
	// pages a per-page answer would satisfy both.
	"characters/Thia.md": "---\ntitle: Thia\ntype: character\nname: Thia\nclass: Rogue\nlevel: 3\n---\n\n" +
		"# Thia\n\nWears the grey coat and owes money in three towns.\n\n" +
		"Orrin keeps this behind the bar: ![Orrin behind the bar](" + publicAttachment + ")\n\n" +
		fenceBody("f6f6f6f6f6f6", "dm", dmName, "Orrin's other name",
			"![Orrin's real face]("+secretAttachment+")\n\nCHARACTER-BODY-TOKEN-4b81ad"),

	// rule, the other id internal/systems/dnd5e registers, with CapRules. Its
	// secret is private and its page is owned by nobody, which is the case the
	// Tavern's private fences cannot make: Thia owns the Tavern, so a query that
	// answered "private, therefore the owners of this page" answers both of the
	// Tavern's correctly and this one wrongly.
	"rules/Halting.md": "---\ntitle: Halting\ntype: rule\nsource: house rule\n---\n\n" +
		"# Halting\n\nA rest ends early when something moves.\n\n" +
		fenceBody("a7a7a7a7a7a7", "private", dmName, "The real cost", "RULE-BODY-TOKEN-6a3f57"),

	// houserule, which internal/systems/houserules lists as a frontmatter
	// convention and deliberately does not register, because a feature plugin may
	// not register a page type. The core viewer is therefore the right renderer
	// here by design, which is what makes the fence worth having: it is
	// table-visible, so the walk has to see the core path deliver a secret to
	// every account and refuse it to an anonymous reader on a type with no plugin
	// anywhere behind it.
	"houserules/Extended-rest.md": "---\ntitle: Extended rest\ntype: houserule\n---\n\n" +
		"# Extended rest\n\nEveryone gets two more, once per session.\n\n" +
		fenceBody("b8b8b8b8b8b8", "table", dmName, "The short version", "HOUSERULE-BODY-TOKEN-1e7d92"),

	// map, which the host reserves for CapMaps and no shipped plugin claims, so
	// it renders through the core viewer like any unregistered type. The secret is
	// private and authored by thia on a page thia does not own: the author arm of
	// the policy with the ownership arm taken away, which no existing fence
	// reaches.
	"maps/Salt-coast.md": "---\ntitle: The salt coast\ntype: map\n---\n\n" +
		"# The salt coast\n\nReached on foot from the ruin. Surveyed badly.\n\n" +
		fenceBody("c9c9c9c9c9c9", "private", playerName, "Thia's own survey", "MAP-BODY-TOKEN-3f2a86"),

	// encounter, reserved for CapEncounters and likewise unclaimed. Its fence is
	// dm and is authored by bram, a player who owns nothing: ownership and
	// authorship grant the right to write a secret and never the right to
	// broadcast one, so the author of a dm fence is not among its readers.
	"encounters/Bridge-ambush.md": "---\ntitle: The bridge ambush\ntype: encounter\n---\n\n" +
		"# The bridge ambush\n\nFour of them, on the far bank.\n\n" +
		fenceBody("d1d1d1d1d1d1", "dm", otherName, "Who paid for it", "ENCOUNTER-BODY-TOKEN-5c40f9"),

	// token, the last reserved id, and the one new page with nothing hidden on
	// it. It is here so that a walk of the reserved types includes a page where
	// the right answer is that there is nothing to redact: a placeholder for a
	// secret nobody was refused, or a lock on a page that carries no fence, shows
	// on exactly this page and on no other.
	"tokens/Orrin.md": "---\ntitle: Orrin's token\ntype: token\n---\n\n" +
		"# Orrin's token\n\nA circle with a bar through it, for the map view.\n",

	// The two attachment files, at the vault root.
	//
	// The names carry no directory on purpose. selector.bind in pagedispatch.go
	// requires the captured tail to be exactly as long as the template, so the
	// {name...} in `/p/*/attachment/{name...}` binds exactly one segment however it
	// is written and a name under assets/ is refused for every principal — which
	// contradicts the reason that comment gives for the greedy form existing at all
	// (pagedispatch.go:154). A root-level name exercises §8.8's per-reference rule
	// end to end against the code as it is today, and the nested case is a router
	// finding rather than a fixture one.
	//
	// The bytes are not a PNG and nothing decodes them; what matters is that the
	// length is knowable and that a change to one is a change to that one.
	publicAttachment: "\x89PNG\r\n\x1a\nnot-really-a-png",
	secretAttachment: "\x89PNG\r\n\x1a\nnot-really-a-different-png",
}

// The two attachments the campaign carries, by the name the serve route matches.
//
// They are named rather than spelled at the call sites because the walk has to
// name both of them, and a walk that typed the path itself would be a second
// copy of the string that can quietly disagree with the reference the index
// recorded — which is the same class of bug the route's own equality check
// exists to make impossible. See campaignFiles for why neither carries a
// directory.
const (
	// publicAttachment is referenced from a page's public text, so it is served
	// to every principal that may read public content at all.
	publicAttachment = "orrin-at-the-bar.png"
	// secretAttachment is referenced only from inside a dm fence, so it is served
	// to a DM or an administrator and to nobody else. It is on the same page as
	// publicAttachment on purpose: one page, two answers, one rule.
	secretAttachment = "orrin-portrait.png"
)

// campaignPageTypes is every page in the campaign and the type the index gives
// it, by vault path.
//
// It is here so that a coverage claim is checkable rather than asserted. "The
// walk covered every page type" is only true if the set of types the vault
// carries is the set of types the host knows about, and this is the half of that
// comparison a reader can check without running anything; the other half is
// plugin.ReservedPageTypes, and the check is
// TestTheCampaignFixtureIsInternallyConsistent.
//
// Tavern.md and Ruin.md carry no `type:` and are therefore note. They are
// listed under it rather than omitted, because a sweep that only read frontmatter
// would call two pages untyped and report the most common type in the vault as
// the one it never covered.
var campaignPageTypes = map[string]string{
	"Index.md":                    "note",
	"Tavern.md":                   "note",
	"Ruin.md":                     "note",
	"characters/Thia.md":          "character",
	"rules/Halting.md":            "rule",
	"houserules/Extended-rest.md": "houserule",
	"maps/Salt-coast.md":          "map",
	"encounters/Bridge-ambush.md": "encounter",
	"tokens/Orrin.md":             "token",
}

// conventionPageTypes are the `type:` values that are conventions rather than
// registrations, with the constant that owns each one.
//
// A reservation is a name the host holds *for* a plugin, so it is not a name a
// page in this vault can be expected to carry for a viewer to exist. The two
// below are the other half of the vocabulary: the default, and a feature
// plugin's frontmatter convention that deliberately registers nothing because a
// feature may not register a page type.
var conventionPageTypes = map[string]string{
	"note":      "md.DefaultPageType",
	"houserule": "houserules.PageTypeHouseRule",
}

// searchWord is a word that appears in the body of every secret in the fixture
// and in no page.
//
// It exists so the search tripwire can ask "what happens when a reader searches
// for something that only a hidden secret contains" without searching for the
// secret's own token: the search form echoes the term back, so a term that is
// itself a secret body would be found in the response for that reason alone and
// the assertion would prove nothing. With a shared word, one term distinguishes
// all five original secrets and none of them is the term.
//
// Exactly five fences carry it, which is why fenceBody exists: a sixth fence
// joining the set would silently change what "one term finds every secret" means
// for every test that says it.
const searchWord = "obsidianquill"

// fence is one secret fence in the on-disk syntax, carrying the shared search
// word.
//
// Two details are load-bearing and both cost a leak if they are wrong. The title
// is quoted, because an unquoted value ends at the first space and the leftover
// words are then read as further directive keys — and a directive with an unknown
// key is demoted to public, which means the body is served to everybody. And the
// author is a real username, because secrets.author_id is a foreign key: an
// author that does not resolve leaves the fence with no author, and every
// authorization question about it is then answered wrongly rather than refused.
func fence(id, visibility, author, title, body string) string {
	return fenceBody(id, visibility, author, title, body+" "+searchWord)
}

// fenceBody is fence with its body written out whole, for a secret that must not
// carry the shared search word. See searchWord for why a new fence is one of
// these.
func fenceBody(id, visibility, author, title, body string) string {
	return "```secret id=" + id +
		" visibility=" + visibility +
		" author=" + author +
		" created=2026-01-01T00:00:00Z" +
		" title=" + strconv.Quote(title) +
		"\n" + body + "\n```\n\n"
}

// The fixture's body tokens.
//
// **This is the canonical definition of every one of these literals, and the
// names here are the ones a later cleanup should adopt.** Six files in this
// package spell the same strings out again as inline literals — events_test.go,
// demo_test.go, nav_test.go, matrix_test.go, pageroutes_test.go and
// web/shell_test.go outside it — and the duplication is deliberate in exactly one
// of them: a tripwire that reads its expectations out of the fixture cannot catch
// the fixture being wrong. What should not survive is six files that each hold
// their own copy of the *string*; they should hold their own copy of the *rule*
// and reach the string from here.
//
// Each token appears in exactly one fence in exactly one file, so finding one in
// a response names the secret that leaked rather than only the page it leaked on.
const (
	// privateBodyToken is the DM's private secret on the Tavern, a page thia
	// owns: the ownership arm on a fence whose author is not the reader.
	privateBodyToken = "PRIVATE-BODY-TOKEN-9f3a2c"
	// dmBodyToken is dm on the Tavern: DMs and admins, and not the page owner.
	dmBodyToken = "DM-BODY-TOKEN-7b1e4d"
	// ownerBodyToken is private, authored by thia, on a page thia owns: twice
	// over, and still only hers.
	ownerBodyToken = "OWNER-BODY-TOKEN-2a6e10"
	// ruinBodyToken is dm on the Ruin, which no player owns.
	ruinBodyToken = "RUIN-BODY-TOKEN-2c8f61"
	// tableToken is the one body a player may read: a table-visible secret. It is
	// in the list below because a *disabled* or anonymous principal must not see
	// it either, and because the negative assertion for it is that no principal
	// outside the DM set reads it.
	tableToken = "TABLE-BODY-TOKEN-5d0a8f"

	// characterBodyToken is dm on a `type: character` page, and the same fence
	// also references the secret-only attachment. One case, two rules.
	characterBodyToken = "CHARACTER-BODY-TOKEN-4b81ad"
	// ruleBodyToken is private on an unowned `type: rule` page, so the reader set
	// is DMs and the author with no page owner added to it.
	ruleBodyToken = "RULE-BODY-TOKEN-6a3f57"
	// houseRuleBodyToken is table-visible on `type: houserule`, a type the
	// houserules plugin lists as a convention and never registers. Every account
	// may read it; no anonymous reader may.
	houseRuleBodyToken = "HOUSERULE-BODY-TOKEN-1e7d92"
	// mapBodyToken is private and authored by a player on a page she does not
	// own: the author arm with the ownership arm removed.
	mapBodyToken = "MAP-BODY-TOKEN-3f2a86"
	// encounterBodyToken is dm and authored by a player. Authorship buys the right
	// to write the fence, never the right to read it back.
	encounterBodyToken = "ENCOUNTER-BODY-TOKEN-5c40f9"
)

// bodyTokens are the strings that must never appear in a response to a
// principal that may not read the secret holding them. Each appears in exactly
// one fence in exactly one file; TestTheCampaignFixtureIsInternallyConsistent is
// the gate that keeps that true, and it fails naming the token that drifted.
var bodyTokens = []string{
	privateBodyToken,
	dmBodyToken,
	ownerBodyToken,
	ruinBodyToken,
	tableToken,
	characterBodyToken,
	ruleBodyToken,
	houseRuleBodyToken,
	mapBodyToken,
	encounterBodyToken,
}

// readerRole is one of the principals the harness's own accounts are, under the
// names the leak suites use for them.
type readerRole string

const (
	roleAdmin     readerRole = "admin"
	roleDM        readerRole = "dm"
	rolePageOwner readerRole = "page owner"
	rolePlayer    readerRole = "player"
	roleAnonymous readerRole = "anonymous"
)

// bodyTokenReaders is who may read each body token, by fixture role.
//
// It is the fixture's own statement of what each fence is *for*, kept beside the
// tokens so that a new fence declares its case as data and not only as prose. It
// is deliberately not an implementation to call: tripwire_test.go, nav_test.go
// and events_test.go each answer from their own model of the rule, because a
// leak test that asks the code it is testing whether a leak is a leak has stopped
// being a leak test. A disagreement between one of those and this table is a
// finding about one of the two, which is the reason all four exist.
//
// The anonymous row is the one that is easiest to get wrong and the one §2.4 is
// about: authz.SecretVisibleSQL's table clause names no session, so an anonymous
// principal asking for a table secret is closed by store.publicOnlySQL, by the
// per-query principal check and by search.Query's guard — not by the predicate.
var bodyTokenReaders = map[string]map[readerRole]bool{
	privateBodyToken:   {roleAdmin: true, roleDM: true, rolePageOwner: true},
	dmBodyToken:        {roleAdmin: true, roleDM: true},
	ownerBodyToken:     {roleAdmin: true, roleDM: true, rolePageOwner: true},
	ruinBodyToken:      {roleAdmin: true, roleDM: true},
	tableToken:         {roleAdmin: true, roleDM: true, rolePageOwner: true, rolePlayer: true},
	characterBodyToken: {roleAdmin: true, roleDM: true},
	ruleBodyToken:      {roleAdmin: true, roleDM: true},
	houseRuleBodyToken: {roleAdmin: true, roleDM: true, rolePageOwner: true, rolePlayer: true},
	mapBodyToken:       {roleAdmin: true, roleDM: true, rolePageOwner: true},
	encounterBodyToken: {roleAdmin: true, roleDM: true},
}

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
	// The reindex comes first. reindexAll drops the derived index and derives it
	// again, so a page id is only stable for the length of one index — a grant
	// written before it names a page row that no longer exists, and IsPageOwner
	// answers false for the owner. The grant surviving is the whole point of this
	// fixture, so the ordering is load-bearing rather than incidental.
	fx.reindexAll()
	if err := fx.addOwner("Tavern.md", fx.userID(playerName)); err != nil {
		fx.t.Fatal(err)
	}
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
	t    testing.TB
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
	// timeout bounds the whole request, body included. It exists for the routes
	// whose response never ends: /_/events holds its connection open and writes
	// only when something changes, so a client that reads to EOF waits for ever.
	// The status line is written before the stream begins, so a deadline is
	// enough to assert on the authorization decision — which is all the matrix
	// asks of that route — without the test hanging on the body.
	timeout time.Duration
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
	drain(s.send(s.get("/"))) //nolint:bodyclose // drain closes the body it is handed
	if s.token() == "" {
		drain(s.send(s.get("/login"))) //nolint:bodyclose // drain closes the body it is handed
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
	ctx := context.Background()
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, c.method, s.fx.HTTP.URL+c.path, reader)
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
	resp := s.do(c) //nolint:bodyclose // s.read below closes the body it is handed
	// read closes the body, and so does the drain; the drain is here because
	// bodyclose only credits a close it can see at this call site, and it reads
	// what read does out of read's own shape.
	defer drain(resp)
	return s.read(resp)
}

// read returns a response's body as a string and closes it.
//
// The close is a deferred *call* and not a deferred closure over it. bodyclose
// summarises a function that closes the body it is handed from the shape of
// that close, and `defer func() { _ = resp.Body.Close() }()` — the shape
// errcheck wants — is invisible to it, so every `s.read(resp)` in the package
// would read as an unclosed response. The harness closes every body, and this
// line is what makes that visible to a linter rather than a claim.
func (s *session) read(resp *http.Response) string {
	s.t.Helper()
	defer resp.Body.Close() //nolint:errcheck // a read handle's close cannot fail in a way a test can act on
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

// getBody performs a GET and returns the body whatever it answered.
//
// It exists beside getOK because a test that asserts about a 404 or a redirect
// needs the bytes of that answer, and spelling it as s.read(s.do(s.get(p)))
// hands a response to a caller who must remember to close it. read does close
// it; writing it out anyway is a chance to forget, and bodyclose reports every
// one of those chances as though they were real.
//
// The suppression below is a limitation of the linter rather than a claim about
// the code: bodyclose derives its interprocedural summary from the shape of the
// close inside the callee, and it does not follow a call to read, which closes
// the body with a bare `defer resp.Body.Close()`. Every site that spells this
// out by hand reports the same finding, so the one suppression lives here where
// the close actually is.
func (s *session) getBody(path string) string {
	s.t.Helper()
	return s.read(s.do(s.get(path))) //nolint:bodyclose // s.read closes the body; see above
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

// principalFor is an account as a Principal, read from the row so that a test
// which disabled it or changed its role is refused rather than passing on a
// stale id.
func (fx *fixture) principalFor(username string) authz.Principal {
	fx.t.Helper()
	u, err := store.GetUserByUsername(context.Background(), fx.DB.Reader(), username)
	if err != nil {
		fx.t.Fatalf("look up %s: %v", username, err)
	}
	return authz.ForUser(u.ID, u.Username, authz.Role(u.Role), fx.cfg.AllowAnonymousRead)
}

// tryAdminSession signs in as the administrator, and reports whether it could.
//
// It is a helper rather than an inline asUser because the CSRF table runs in two
// states and one of them has no administrator at all: a vault with no accounts
// has nobody who may write a page, so a control run for a page-scoped write
// cannot exist there and must be skipped rather than attempted. A helper that
// says so is the difference between "this row is covered in the other state" and
// a panic in the middle of a table.
func (fx *fixture) tryAdminSession() (*session, bool) {
	fx.t.Helper()
	if fx.tryAdminPrincipal().UserID == 0 {
		return nil, false
	}
	return fx.asUser(adminName, adminPass), true
}

// pageIDByPath is the index's id for a vault-relative path, read through the
// same lookup the router does — bare first, then with the .md suffix — so that a
// test naming a page the way a URL names it finds the same row the route does.
func (fx *fixture) pageIDByPath(path string) (int64, bool) {
	fx.t.Helper()
	for _, cand := range []string{path, strings.TrimSuffix(path, ".md") + ".md"} {
		row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), cand)
		if err == nil {
			return row.ID, true
		}
	}
	return 0, false
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
	defer func() { _ = rows.Close() }()
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
func writeVault(t testing.TB, dir string, files map[string]string) {
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
// drain releases a response whose body no assertion will read.
//
// The close is a deferred *call* for the same reason read's is: bodyclose reads
// this function's shape to decide whether a caller that hands it a response
// closed the body, and a close inside a discarded closure is invisible to it.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close() //nolint:errcheck // a drained read handle's close is not actionable
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

// TestTheCampaignFixtureIsInternallyConsistent is the gate on the fixture the
// leak suites are armed from.
//
// Every leak test in this package is a claim about the same vault: that these
// tokens, on these pages, of these types, reach exactly the principals this table
// says. A claim of that shape fails silently when the fixture drifts — a token
// typed into the wrong fence, a page type the walk will never reach, a reference
// that moved out of its secret — and the silence is what makes it dangerous,
// because the walk still passes over the pages it was written against.
//
// So the four facts a walk depends on are checked here against the sources of
// truth rather than against themselves: the tokens against the files, the page
// types against plugin.ReservedPageTypes, the page table against the vault, and
// the two attachments against where they are referenced.
func TestTheCampaignFixtureIsInternallyConsistent(t *testing.T) {
	t.Parallel()

	paths := make([]string, 0, len(campaignFiles))
	for p := range campaignFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	t.Run("every body token is written in exactly one fence", func(t *testing.T) {
		t.Parallel()
		for _, token := range bodyTokens {
			// Not named where: TestEveryQueryUsesBindParameters flags any line
			// carrying Sprintf and a SQL verb, and a local that reads as a
			// WHERE clause fails a gate it has nothing to do with.
			var sites []string
			for _, p := range paths {
				if n := strings.Count(campaignFiles[p], token); n > 0 {
					sites = append(sites, fmt.Sprintf("%s x%d", p, n))
				}
			}
			if len(sites) != 1 {
				t.Errorf("the token %s is written %d times across the campaign (%s), want once: a body token that appears twice is a finding that cannot name the secret that leaked",
					token, len(sites), strings.Join(sites, ", "))
			}
		}
	})

	t.Run("every body token declares who may read it", func(t *testing.T) {
		t.Parallel()
		for _, token := range bodyTokens {
			readers, ok := bodyTokenReaders[token]
			if !ok {
				t.Errorf("the token %s has no entry in bodyTokenReaders, so a leak suite has no stated expectation to assert against", token)
				continue
			}
			if len(readers) == 0 {
				t.Errorf("the token %s is written to no principal at all, which is a fence nobody can read rather than a case", token)
			}
			// A table-visible secret that an anonymous reader may have is the one
			// row §2.4 is about, and it is the row a copy-paste into this table
			// gets wrong. It is checked here rather than in each leak suite so
			// that the correction is made once.
			if readers[roleAnonymous] {
				t.Errorf("the token %s is granted to the anonymous role, and no secret body is served to a principal with no session", token)
			}
		}
		for token := range bodyTokenReaders {
			if !slices.Contains(bodyTokens, token) {
				t.Errorf("bodyTokenReaders has an entry for %s, which is not in bodyTokens, so nothing walks it", token)
			}
		}
	})

	t.Run("the campaign carries every page type the host knows", func(t *testing.T) {
		t.Parallel()
		present := map[string]bool{}
		for _, typ := range campaignPageTypes {
			present[typ] = true
		}
		// The reserved half. A reservation is a name the host holds for a plugin
		// that may never ship, so a page of that type has no viewer behind it —
		// which is exactly why the campaign needs one: redaction that lives in a
		// plugin's viewer rather than in the core path passes on every other page
		// and fails on these.
		for _, r := range plugin.ReservedPageTypes() {
			if !present[r.ID] {
				t.Errorf("the campaign has no page of the reserved type %q, so a walk claiming to cover every page type would not: add one to campaignFiles and to campaignPageTypes", r.ID)
			}
		}
		// The convention half, and the refusal of a third category. A type that is
		// neither reserved nor a convention is one nothing in the tree accounts
		// for, and it renders as `note` whatever the author wrote.
		for id := range conventionPageTypes {
			if !present[id] {
				t.Errorf("the campaign has no page of the convention type %q", id)
			}
		}
		// The table, not the vault: a page the table has not listed is reported by
		// the subtest below, and reading its type from a map it is not in would
		// report the same gap a second time as a type of "".
		for path, typ := range campaignPageTypes {
			_, reserved := plugin.ReservedPageTypeFor(typ)
			_, convention := conventionPageTypes[typ]
			if !reserved && !convention {
				t.Errorf("%s is typed %q, which is neither a reserved page type nor one of the conventions %v: nothing renders it as anything but a note",
					path, typ, slices.Sorted(maps.Keys(conventionPageTypes)))
			}
		}
	})

	t.Run("the page type table and the vault name the same pages", func(t *testing.T) {
		t.Parallel()
		for path := range campaignPageTypes {
			if _, ok := campaignFiles[path]; !ok {
				t.Errorf("campaignPageTypes lists %s, which the vault does not have", path)
			}
		}
		for _, p := range paths {
			if !strings.HasSuffix(p, ".md") {
				continue
			}
			if _, ok := campaignPageTypes[p]; !ok {
				t.Errorf("the vault has a page at %s that campaignPageTypes does not list, so a walk built from that table would skip it", p)
			}
		}
	})

	t.Run("the two attachments are referenced, one outside a fence and one inside", func(t *testing.T) {
		t.Parallel()
		const fenceOpen = "```secret "
		for _, tc := range []struct{ name, file string }{
			{publicAttachment, publicAttachment},
			{secretAttachment, secretAttachment},
		} {
			if _, ok := campaignFiles[tc.name]; !ok {
				t.Errorf("the attachment %s is named but the vault has no such file, so the indexer records no row and the serve route answers 404 for every role", tc.name)
			}
		}
		referencing := []string{}
		for _, p := range paths {
			if !strings.HasSuffix(p, ".md") {
				continue
			}
			if strings.Contains(campaignFiles[p], publicAttachment) {
				referencing = append(referencing, p)
			}
		}
		if len(referencing) != 1 {
			t.Fatalf("%s is referenced from %d pages (%s), want exactly 1: the two attachment cases are one public reference and one secret-only reference, and a second public one would give the walk nothing to distinguish",
				publicAttachment, len(referencing), strings.Join(referencing, ", "))
		}
		page := campaignFiles[referencing[0]]
		publicAt := strings.Index(page, publicAttachment)
		secretAt := strings.Index(page, secretAttachment)
		if secretAt < 0 {
			t.Fatalf("%s is referenced from %s but %s is not, and the two cases only differ if both are on the same page", publicAttachment, referencing[0], secretAttachment)
		}
		open := strings.Index(page, fenceOpen)
		switch {
		case open < 0:
			t.Fatalf("%s carries no secret fence, so there is no secret-only reference on it", referencing[0])
		case publicAt > open:
			t.Errorf("%s references the public attachment from inside the fence, which makes it a secret-only reference and leaves the public case with nothing to test", referencing[0])
		case secretAt < open:
			t.Errorf("%s references the secret-only attachment from the public text, which makes it public and leaves the secret case with nothing to test", referencing[0])
		}
	})
}
