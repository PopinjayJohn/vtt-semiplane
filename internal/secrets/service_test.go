// Package secrets_test exercises the secret write path from outside the package.
//
// It is an external test package because the assertions need a real indexer, and
// internal/sync sits above internal/secrets in the dependency order: a test in
// package secrets that imported sync would be an import cycle. The seam that
// makes it work is secrets.Reindexer, which the indexer satisfies structurally.
package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// clockNow is the instant the harness clock reports, so a stored timestamp in an
// assertion is a literal.
var clockNow = time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)

// secretBody is the plaintext a fixture's fence holds. It appears in no other
// fixture, so "this string is not in the index" is a real assertion.
const secretBody = "The vault door is oak and the key is with the mayor."

const secretID = "abcdef012345"

const pageWithFence = "# The Page\n\nPublic before the fence.\n\n" +
	"```secret id=" + secretID + " visibility=dm author=dorn created=2026-09-28T10:04:11Z title=\"The Mayor's Door\"\n" +
	secretBody + "\n```\n\nPublic after the fence.\n"

type harness struct {
	t      *testing.T
	vault  *testutil.Vault
	db     *store.DB
	ix     *sync.Indexer
	svc    *secrets.Service
	writer *vault.Writer
	sw     *sync.Selfwrites
	log    *obs.Logger
	dmID   int64
	// reindexes counts the calls the service made back into the indexer, so a
	// test can assert the file and the index stayed in step.
	reindexes atomic.Int64
}

func newHarness(t *testing.T, files map[string]string) *harness {
	return newHarnessAs(t, files, false)
}

// newHarnessAs builds the same harness with --allow-anonymous-read set or not.
// The editor and revision paths have to be exercised against an anonymous
// principal as well, and a zero-value Policy would refuse it before any of the
// behaviour under test ran.
func newHarnessAs(t *testing.T, files map[string]string, allowAnonymousRead bool) *harness {
	t.Helper()
	v := testutil.WithVault(t, files)
	db, err := store.Open(v.Root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	if err := store.Migrate(context.Background(), db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := &harness{t: t, vault: v, db: db, log: obs.Discard()}
	ctx := context.Background()
	for _, u := range []struct{ name, role string }{{"mara", "admin"}, {"dorn", "dm"}, {"pia", "player"}} {
		if _, err := store.InsertUser(ctx, db.Writer(), store.User{
			Username: u.name, DisplayName: u.name, Role: u.role,
			PWSalt: []byte("salt"), CreatedAt: clockNow,
		}); err != nil {
			t.Fatalf("seed %s: %v", u.name, err)
		}
		if u.name == "dorn" {
			h.dmID = h.userID(u.name)
		}
	}
	ix, err := sync.New(sync.Options{
		DB: db, Root: v.Root, Log: h.log, Clock: func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatalf("indexer: %v", err)
	}
	h.ix = ix
	h.sw = sync.NewSelfwrites(db, h.log)
	h.sw.SetClock(func() time.Time { return clockNow })
	w := vault.NewWriter(v.Root, h.log)
	w.Store = h.sw
	w.Clock = func() time.Time { return clockNow }
	h.writer = w
	svc, err := secrets.NewService(secrets.Options{
		DB: db, Writer: w, Policy: authz.NewPolicy(allowAnonymousRead),
		Reindexer: countingReindexer{ix: ix, calls: &h.reindexes},
		Log:       h.log,
		Clock:     func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	h.svc = svc
	h.indexAll()
	return h
}

// countingReindexer is a Reindexer that counts the calls, so a test can assert
// the service re-derived the index rather than leaving the file ahead of it.
type countingReindexer struct {
	ix    *sync.Indexer
	calls *atomic.Int64
}

func (c countingReindexer) Reindex(ctx context.Context, path string) error {
	c.calls.Add(1)
	return c.ix.Reindex(ctx, path)
}

func (h *harness) userID(name string) int64 {
	h.t.Helper()
	u, err := store.GetUserByUsername(context.Background(), h.db.Reader(), name)
	if err != nil {
		h.t.Fatalf("user %s: %v", name, err)
	}
	return u.ID
}

func (h *harness) indexAll() {
	h.t.Helper()
	ctx := context.Background()
	walk, err := h.ix.Walk(ctx)
	if err != nil {
		h.t.Fatalf("walk: %v", err)
	}
	if _, err := h.ix.IndexBatch(ctx, walk.Files); err != nil {
		h.t.Fatalf("index: %v", err)
	}
	if _, err := h.ix.RemoveMissing(ctx, walk.Files); err != nil {
		h.t.Fatalf("remove missing: %v", err)
	}
}

func (h *harness) count(query string, args ...any) int64 {
	h.t.Helper()
	var n int64
	if err := h.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		h.t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func (h *harness) text(query string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		h.t.Fatalf("query %q: %v", query, err)
	}
	return s
}

func (h *harness) dm() authz.Principal {
	h.t.Helper()
	return authz.ForUser(h.dmID, "dorn", authz.RoleDM, false)
}

func (h *harness) player() authz.Principal {
	h.t.Helper()
	return authz.ForUser(h.userID("pia"), "pia", authz.RolePlayer, false)
}

func (h *harness) admin() authz.Principal {
	h.t.Helper()
	return authz.ForUser(h.userID("mara"), "mara", authz.RoleAdmin, false)
}

// TestNewServiceRefusesToStartHalfConfigured asserts the constructor's three
// required dependencies. A service with a nil reindexer is the dangerous one: it
// would write the file and leave the index behind, so the file would be right and
// the app would be wrong, and the next reconciliation would be the only thing to
// notice.
func TestNewServiceRefusesToStartHalfConfigured(t *testing.T) {
	t.Parallel()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	w := vault.NewWriter(t.TempDir(), obs.Discard())
	ok := countingReindexer{ix: nil, calls: &atomic.Int64{}}
	for name, opts := range map[string]secrets.Options{
		"no database":                  {Writer: w, Policy: authz.NewPolicy(false), Reindexer: ok},
		"no writer":                    {DB: db, Policy: authz.NewPolicy(false), Reindexer: ok},
		"no reindexer":                 {DB: db, Writer: w, Policy: authz.NewPolicy(false)},
		"a nil policy is not an error": {DB: db, Writer: w, Reindexer: ok},
	} {
		got, err := secrets.NewService(opts)
		switch name {
		case "a nil policy is not an error":
			if err != nil || got == nil {
				t.Errorf("%s: %v", name, err)
			}
		default:
			if err == nil {
				t.Errorf("%s: a service was constructed", name)
			}
		}
	}
}

// TestRevealIsAFileMutation is the §8.3 assertion: the file changed by exactly
// one token, and the fence, the id, the body and the audit trail all survive.
func TestRevealIsAFileMutation(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	before := h.vault.ReadFile(t, "Page.md")

	if err := h.svc.Reveal(context.Background(), h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	after := h.vault.ReadFile(t, "Page.md")

	// The only difference is the visibility token.
	want := bytes.Replace(before, []byte("visibility=dm"), []byte("visibility=table"), 1)
	if !bytes.Equal(want, after) {
		t.Fatalf("the reveal changed more than the visibility token\n--- before ---\n%s\n--- after ---\n%s",
			before, after)
	}
	if bytes.Equal(before, after) {
		t.Fatal("the reveal wrote nothing")
	}
	// The fence survives, so the secret keeps its id, its title, its author and
	// its revocability. A reveal that removed the fence would leave plaintext
	// that could never be hidden or audited again.
	if bytes.Count(after, []byte("```secret id="+secretID)) != 1 {
		t.Error("the fence did not survive the reveal")
	}
	if !bytes.Contains(after, []byte(`title="The Mayor's Door"`)) {
		t.Error("the directive lost its title")
	}
	if !bytes.Contains(after, []byte("author=dorn")) {
		t.Error("the directive lost its author")
	}
	if !bytes.Contains(after, []byte(secretBody)) {
		t.Error("the body was altered")
	}

	// The index followed the file.
	if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "table" {
		t.Errorf("the indexed visibility is %q, want table", got)
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, secretID); n != 1 {
		t.Error("a revealed secret did not reach the search index")
	}
	if n := h.count(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, "mayor"); n != 0 {
		t.Error("the body reached the public search index")
	}
	if h.reindexes.Load() != 1 {
		t.Errorf("the service re-indexed %d times, want once", h.reindexes.Load())
	}

	// The audit trail.
	events, err := h.svc.EventsFor(context.Background(), h.dm(), secretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %+v", events)
	}
	ev := events[0]
	if ev.Action != store.SecretActionReveal {
		t.Errorf("the action is %q, want reveal", ev.Action)
	}
	if ev.FromVis != "dm" || ev.ToVis != "table" {
		t.Errorf("the event says %q -> %q, want dm -> table", ev.FromVis, ev.ToVis)
	}
	if ev.ActorID != h.dmID {
		t.Errorf("the actor is %d, want the DM %d", ev.ActorID, h.dmID)
	}
	if !ev.At.Equal(clockNow) {
		t.Errorf("the event is timestamped %s, want %s", ev.At, clockNow)
	}
	// And the event carries no content, ever.
	row := h.text(`SELECT action || '|' || COALESCE(from_vis, '') || '|' || COALESCE(to_vis, '') FROM secret_events WHERE id = ?`, ev.ID)
	if strings.Contains(row, secretBody) || strings.Contains(row, "oak") {
		t.Fatalf("the audit row carries body text: %q", row)
	}
}

// TestRevokePurgesTheIndex asserts that hiding a secret removes its searchable
// copy rather than filtering it, and that the generation moves so every live
// stream is torn down.
func TestRevokePurgesTheIndex(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	ctx := context.Background()
	genBefore := mustGen(t, h)

	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, "mayor"); n != 1 {
		t.Fatal("a revealed secret is not findable, so revoke has nothing to purge")
	}

	if err := h.svc.Revoke(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, secretID); n != 0 {
		t.Error("the revoked secret still has a search-index row")
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, "mayor"); n != 0 {
		t.Error("a revoked secret is still findable")
	}
	if n, err := store.CheckSecretIndexInvariant(ctx, h.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d, want 0 (%v)", n, err)
	}
	if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "private" {
		t.Errorf("the indexed visibility is %q, want private", got)
	}
	// The body is still on disk and still in the vault. Revoke is not deletion.
	if !bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte(secretBody)) {
		t.Error("the revoke destroyed the secret instead of hiding it")
	}
	if n := h.count(`SELECT COUNT(*) FROM secrets WHERE id = ?`, secretID); n != 1 {
		t.Error("the revoke removed the secret row")
	}
	// The generation moved, twice: once for the reveal, once for the revoke.
	genAfter := mustGen(t, h)
	if genAfter < genBefore+2 {
		t.Errorf("the authorization generation moved from %d to %d, want at least two steps", genBefore, genAfter)
	}
	// Both events are on the trail.
	events, err := h.svc.EventsFor(ctx, h.dm(), secretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected two events, got %+v", events)
	}
	if events[0].Action != store.SecretActionRevoke || events[0].FromVis != "table" || events[0].ToVis != "private" {
		t.Errorf("the revoke event is %+v", events[0])
	}
}

func mustGen(t *testing.T, h *harness) int64 {
	t.Helper()
	n, err := store.MetaGetInt(context.Background(), h.db.Reader(), store.KeyAuthzGeneration)
	if err != nil {
		t.Fatalf("authz generation: %v", err)
	}
	return n
}

// TestOnlyADMCanReveal is the authorization matrix for the write path, against
// the real authz.Policy rather than a stand-in.
func TestOnlyADMCanReveal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		who     func(h *harness) authz.Principal
		allowed bool
	}{
		{"an admin may reveal", (*harness).admin, true},
		{"a dm may reveal", (*harness).dm, true},
		{"a player may not reveal", (*harness).player, false},
		{"an anonymous principal may not reveal", nil, false},
	}
	for _, tc := range cases {
		tc := tc
		for _, action := range []struct {
			name string
			do   func(*harness, authz.Principal) error
		}{
			{"reveal", func(h *harness, p authz.Principal) error { return h.svc.Reveal(context.Background(), p, secretID) }},
			{"revoke", func(h *harness, p authz.Principal) error { return h.svc.Revoke(context.Background(), p, secretID) }},
		} {
			t.Run(tc.name+"/"+action.name, func(t *testing.T) {
				t.Parallel()
				h := newHarness(t, map[string]string{"Page.md": pageWithFence})
				before := h.vault.ReadFile(t, "Page.md")
				var who authz.Principal
				if tc.who == nil {
					who = authz.Anonymous(false)
				} else {
					who = tc.who(h)
				}
				err := action.do(h, who)
				switch {
				case tc.allowed && err != nil:
					t.Fatalf("%s was refused: %v", tc.name, err)
				case !tc.allowed && err == nil:
					t.Fatalf("%s was allowed", tc.name)
				case !tc.allowed && !errors.Is(err, authz.ErrDenied):
					t.Fatalf("the refusal is %v, want authz.ErrDenied", err)
				}
				after := h.vault.ReadFile(t, "Page.md")
				if !tc.allowed && !bytes.Equal(before, after) {
					t.Fatalf("a refused %s changed the file", action.name)
				}
				// A refusal is not an existence oracle: it happens before any
				// lookup, so a principal that may not reveal learns nothing about
				// which ids exist. The counter below is the same for every id.
				if !tc.allowed && h.reindexes.Load() != 0 {
					t.Errorf("a refused %s still touched the index", action.name)
				}
			})
		}
	}
}

// TestAPlayerOwningThePageStillCannotReveal is the rule the policy table exists
// for: ownership grants authoring rights, not broadcast rights.
func TestAPlayerOwningThePageStillCannotReveal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	ctx := context.Background()
	pageID := h.count(`SELECT id FROM pages WHERE path = 'Page.md'`)
	pia := h.userID("pia")
	// The player owns the page and authored nothing, and the secret is `dm`.
	for _, owner := range []int64{pia, h.dmID} {
		if err := store.AddPageOwner(ctx, h.db.Writer(), store.PageOwner{
			PageID: pageID, UserID: owner, IsOwner: true, AddedAt: clockNow,
		}); err != nil {
			t.Fatalf("add owner: %v", err)
		}
	}
	before := h.vault.ReadFile(t, "Page.md")
	if err := h.svc.Reveal(ctx, h.player(), secretID); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("a page owner revealed a dm secret: %v", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("the refused reveal changed the file")
	}
	// A DM still can, so the refusal was about the principal and not the state.
	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("a dm was refused: %v", err)
	}
}

// TestAnIdempotentRevealWritesNothing asserts that revealing twice is one write
// and one audit row. A second event for a change nobody made turns the audit
// trail into noise, and an audit trail is only useful while it is true.
func TestAnIdempotentRevealWritesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	ctx := context.Background()
	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	after := h.vault.ReadFile(t, "Page.md")
	indexes := h.reindexes.Load()

	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("second reveal: %v", err)
	}
	if !bytes.Equal(after, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("the second reveal rewrote the file")
	}
	if got := h.reindexes.Load(); got != indexes {
		t.Errorf("the second reveal re-indexed (%d then %d)", indexes, got)
	}
	events, err := h.svc.EventsFor(ctx, h.dm(), secretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("the second reveal added an event: %+v", events)
	}
}

// TestRevokingAHiddenSecretWritesNothing is the same rule in the other
// direction, and it matters because `private` is the default: a revoke pressed
// on a secret that was never revealed would otherwise write the fence's default
// back into the file and record a revocation that never happened.
func TestRevokingAHiddenSecretWritesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Page.md": strings.Replace(pageWithFence, "visibility=dm", "visibility=private", 1),
	})
	before := h.vault.ReadFile(t, "Page.md")
	if err := h.svc.Revoke(context.Background(), h.dm(), secretID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("revoking a private secret rewrote the file")
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_events WHERE secret_id = ?`, secretID); n != 0 {
		t.Error("revoking a private secret recorded a revocation that never happened")
	}
}

// TestARevealOfASecretTheFileNoLongerHasIsRefused asserts the file is canonical:
// if the fence is gone, the index is wrong and the write must not invent a
// visibility token for a line that means something else.
func TestARevealOfASecretTheFileNoLongerHasIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	ctx := context.Background()
	// The fence is deleted from the file without the index learning about it.
	h.vault.WriteFile(t, "Page.md", "# The Page\n\nNo fence here any more.\n")
	before := h.vault.ReadFile(t, "Page.md")

	err := h.svc.Reveal(ctx, h.dm(), secretID)
	if !errors.Is(err, secrets.ErrNotInFile) {
		t.Fatalf("the error is %v, want ErrNotInFile", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a refused reveal changed the file")
	}
	if h.reindexes.Load() != 0 {
		t.Error("a refused reveal re-indexed")
	}
	// And the error names the path and the id, never a byte of the page.
	if strings.Contains(err.Error(), "fence") || strings.Contains(err.Error(), "oak") {
		t.Fatalf("the error carries file content: %q", err)
	}
}

// TestAnUnknownVisibilityIsRefused asserts the argument check, because a handler
// that passes an empty or a user-supplied string here would otherwise be asking
// the file to be rewritten with a visibility the format does not have.
func TestAnUnknownVisibilityIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	before := h.vault.ReadFile(t, "Page.md")
	for _, v := range []authz.Visibility{"", "everyone", "TABLE", "dm "} {
		err := h.svc.SetVisibility(context.Background(), h.dm(), secretID, v)
		if !errors.Is(err, secrets.ErrNotAVisibility) {
			t.Errorf("SetVisibility(%q) returned %v, want ErrNotAVisibility", v, err)
		}
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a refused visibility changed the file")
	}
	// The three that are values all work, and only one of them is a reveal.
	if err := h.svc.SetVisibility(context.Background(), h.dm(), secretID, authz.VisibilityDM); err != nil {
		t.Fatalf("setting dm: %v", err)
	}
	if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "dm" {
		t.Errorf("the indexed visibility is %q", got)
	}
}

// TestASecretThatWasNeverIndexedIsNotFound asserts the 404 shape: a missing id
// and an unknown id are the same answer.
func TestASecretThatWasNeverIndexedIsNotFound(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	err := h.svc.Reveal(context.Background(), h.dm(), "000000000000")
	if !errors.Is(err, store.ErrNoRows) {
		t.Fatalf("the error is %v, want store.ErrNoRows", err)
	}
}

// TestALostRaceIsSafe asserts the property a conflict has to have: the caller is
// told, and neither version of the file is handed to it.
//
// A vault page holds secret bodies, and vault.ConflictError carries both versions
// of the file. Returning one from a reveal would give the caller a way to read a
// secret through errors.As, so the service maps it to a type that matches
// errors.Is(vault.ErrConflict) and is not a ConflictError at all.
func TestALostRaceIsSafe(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	var err error = &secrets.RaceLostError{Path: "Page.md", SecretID: secretID, Reason: "reveal"}
	if !errors.Is(err, vault.ErrConflict) {
		t.Fatal("a lost race is not recognisable as one")
	}
	var conflict *vault.ConflictError
	if errors.As(err, &conflict) {
		t.Fatal("a lost race carries the file, which on a secret page is a secret body")
	}
	if strings.Contains(err.Error(), secretBody) {
		t.Fatalf("the error carries file content: %q", err)
	}
	if !strings.Contains(err.Error(), "Page.md") {
		t.Errorf("the error does not name the page: %q", err)
	}

	// And under a real race — a writer flipping the file while the service reads
	// it — every outcome is a success or a conflict, and the file always parses.
	flipper := make(chan struct{})
	stop := make(chan struct{})
	var flips atomic.Int64
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				close(flipper)
				return
			default:
			}
			n++
			flips.Add(1)
			_ = os.WriteFile(h.vault.Root+"/Page.md",
				[]byte("# The Page\n\nflipped "+strings.Repeat("x", n%64)+"\n"+pageWithFence[21:]), 0o600)
		}
	}()
	var conflicts int
	for range 40 {
		err := h.svc.Reveal(context.Background(), h.dm(), secretID)
		switch {
		case err == nil:
		case errors.Is(err, vault.ErrConflict):
			conflicts++
		case errors.Is(err, secrets.ErrNotInFile), errors.Is(err, store.ErrNoRows):
			// The flipper can remove the fence, which is the other correct
			// answer: the file is canonical.
		default:
			close(stop)
			t.Fatalf("a lost race produced %v", err)
		}
		select {
		case <-flipper:
		default:
		}
	}
	close(stop)
	<-flipper
	if flips.Load() == 0 {
		t.Fatal("the flipper never ran, so the race was not exercised")
	}
	t.Logf("%d of 40 attempts lost the race", conflicts)
	// Whatever happened, the file is a page the indexer can still read.
	walk, err := h.ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk after the race: %v", err)
	}
	if _, err := h.ix.IndexBatch(context.Background(), walk.Files); err != nil {
		t.Fatalf("the page is unindexable after the race: %v", err)
	}
}

// TestLoadUsesTheCanonicalPredicate asserts that reading a body back is decided
// by authz.SecretVisibleSQL and by nothing else, and that an invisible secret is
// reported as missing rather than as forbidden.
func TestLoadUsesTheCanonicalPredicate(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	ctx := context.Background()
	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	// table: every authenticated user may read it.
	sec, err := h.svc.Load(ctx, h.player(), secretID)
	if err != nil {
		t.Fatalf("a player cannot read a revealed secret: %v", err)
	}
	// The body is the fence's body verbatim, its trailing line terminator
	// included, because the index stores what the file says rather than a
	// trimmed copy of it.
	if !strings.Contains(sec.Body, secretBody) {
		t.Errorf("the body came back as %q", sec.Body)
	}
	if sec.Visibility != secrets.VisibilityTable {
		t.Errorf("the visibility is %q", sec.Visibility)
	}
	// An anonymous principal may not, and the answer is "no such row".
	if _, err := h.svc.Load(ctx, authz.Anonymous(true), secretID); !errors.Is(err, store.ErrNoRows) {
		t.Fatalf("an anonymous read returned %v, want ErrNoRows", err)
	}
	// private again: the author and the DM, not a player.
	if err := h.svc.Revoke(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := h.svc.Load(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("a DM cannot read a private secret: %v", err)
	}
	if _, err := h.svc.Load(ctx, h.player(), secretID); !errors.Is(err, store.ErrNoRows) {
		t.Fatalf("a player read a private secret: %v", err)
	}
}

// TestListPageAndCountPageAgree asserts the panel property: the number a panel
// shows is the number of rows it lists, from the identical predicate, and no list
// result carries a body.
func TestListPageAndCountPageAgree(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Page.md": pageWithFence + "\n```secret id=111111111111 visibility=table author=mara\nAn open one.\n```\n",
	})
	ctx := context.Background()
	pageID := h.count(`SELECT id FROM pages WHERE path = 'Page.md'`)

	for _, who := range []struct {
		name string
		p    authz.Principal
		want int
	}{
		{"a player", h.player(), 1},
		{"a dm", h.dm(), 2},
		{"an admin", h.admin(), 2},
		{"an anonymous visitor", authz.Anonymous(true), 0},
	} {
		list, err := h.svc.ListPage(ctx, who.p, pageID)
		if err != nil {
			t.Fatalf("%s: list: %v", who.name, err)
		}
		count, err := h.svc.CountPage(ctx, who.p, pageID)
		if err != nil {
			t.Fatalf("%s: count: %v", who.name, err)
		}
		if len(list) != who.want || count != who.want {
			t.Errorf("%s: listed %d, counted %d, want %d", who.name, len(list), count, who.want)
		}
		for _, sec := range list {
			if sec.Body != "" {
				t.Errorf("%s: a list result carried a body", who.name)
			}
		}
	}
}

// TestRevealDoesNotTouchAnythingElseInThePage asserts that a reveal is a mutation
// of one token in one file and of one secret's rows: the other page's facts are
// byte-identical afterwards.
func TestRevealDoesNotTouchAnythingElseInThePage(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Page.md":  pageWithFence,
		"Other.md": "# Other\n\nSee [[Page]] and #tagged.\n",
	})
	before := h.snapshotOther()
	if err := h.svc.Reveal(context.Background(), h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if after := h.snapshotOther(); after != before {
		t.Fatalf("the reveal disturbed another page\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

// snapshotOther renders every derived row of the page that is not the one under
// test, so a reveal of one secret can be shown to have disturbed nothing else.
func (h *harness) snapshotOther() string {
	h.t.Helper()
	var b strings.Builder
	for _, q := range []string{
		`SELECT path, hex(content_hash) FROM pages WHERE path = 'Other.md'`,
		`SELECT pg.path, a.alias FROM page_aliases a JOIN pages pg ON pg.id = a.page_id
			WHERE pg.path = 'Other.md'`,
		`SELECT pg.path, l.target_raw, COALESCE(l.secret_id, '') FROM links l
			JOIN pages pg ON pg.id = l.source_page_id WHERE pg.path = 'Other.md'`,
		`SELECT pg.path, h.text, COALESCE(h.secret_id, '') FROM headings h
			JOIN pages pg ON pg.id = h.page_id WHERE pg.path = 'Other.md'`,
		`SELECT pg.path, t.title, t.body FROM page_text t JOIN pages pg ON pg.id = t.page_id
			WHERE pg.path = 'Other.md'`,
		`SELECT pg.path, r.source, hex(r.content_hash) FROM revisions r
			JOIN pages pg ON pg.id = r.page_id WHERE pg.path = 'Other.md'`,
	} {
		rows, err := h.db.Reader().QueryContext(context.Background(), q)
		if err != nil {
			h.t.Fatalf("query: %v", err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				h.t.Fatalf("scan: %v", err)
			}
			for _, v := range vals {
				switch value := v.(type) {
				case []byte:
					b.WriteString(string(rune(' ')) + string(value))
				case string:
					b.WriteString(" " + value)
				}
				b.WriteString("|")
			}
			b.WriteString("\n")
		}
		rows.Close()
	}
	return b.String()
}
