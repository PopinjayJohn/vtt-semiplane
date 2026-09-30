package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// secretBody builds a fence body carrying this package's leak token, so one
// string serves as both the body and the thing that must not appear in a public
// table. The token is a single word with no FTS punctuation in it, so
// `MATCH 'zephyrite'` is a term and not a phrase.
//
// taggedSecretBody takes its own token because a test that has to tell one
// secret from another needs to tell one leak from another.
func secretBody(what string) string { return taggedSecretBody(what, leakToken) }

func taggedSecretBody(what, token string) string {
	return "The door bears the " + token + " of " + what + "."
}

// pendingCount is how many paths the indexer is still waiting on an account for.
func pendingCount(ix *Indexer) int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.unresolved)
}

// pendingHas reports whether a path is in the pending set.
func pendingHas(ix *Indexer, rel string) bool {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	_, ok := ix.unresolved[rel]
	return ok
}

// assertAbsentFromPublic fails if a secret body is anywhere a principal who may
// not read that secret could see it. It is the page half: page_text, which is
// what the public search index is built from.
func assertAbsentFromPublic(t *testing.T, h *harness, what, token string) {
	t.Helper()
	like := "%" + token + "%"
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE body LIKE ?`, like); n != 0 {
		t.Errorf("%s: the secret body reached page_text.body (%d rows)", what, n)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE title LIKE ? OR headings LIKE ?`, like, like); n != 0 {
		t.Errorf("%s: the secret body reached page_text.title or .headings", what)
	}
	if hits := h.ftsHits("page_fts", token); len(hits) != 0 {
		t.Errorf("%s: the secret body reached page_fts (%v)", what, hits)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE title LIKE ?`, like); n != 0 {
		t.Errorf("%s: the secret body reached pages.title", what)
	}
}

// assertAbsentFromSearchIndex fails if a secret body is in the secret search
// index, which is where only a `table` fence may put one.
func assertAbsentFromSearchIndex(t *testing.T, h *harness, what, token string) {
	t.Helper()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE body LIKE ?`, "%"+token+"%"); n != 0 {
		t.Errorf("%s: the secret body reached secret_text", what)
	}
	if hits := h.ftsHits("secret_fts", token); len(hits) != 0 {
		t.Errorf("%s: the secret body reached secret_fts (%v)", what, hits)
	}
}

// assertAuthorProblem fails unless the pass reported exactly one unknown-author
// problem for a secret.
func assertAuthorProblem(t *testing.T, res BatchResult, secretID string, want int) {
	t.Helper()
	var got int
	for _, r := range res.Indexed {
		for _, p := range r.Problems {
			if p.Code == ProblemAuthorUnknown && p.SecretID == secretID {
				got++
			}
		}
	}
	if got != want {
		t.Errorf("%d unknown-author problems for %s, want %d: %+v", got, secretID, want, res.Indexed)
	}
}

// TestASecretWhoseAuthorAppearsLaterBecomesReadable is the whole bug. A vault is
// indexed at boot, /setup then creates the administrator, and the administrator's
// own `dm` fences are visible to nobody until something re-reads the file. The
// test walks the whole arc and pins the two halves separately: the gap is real
// (re-running the ordinary pass does not close it) and the fix closes it without
// ever making the secret public.
func TestASecretWhoseAuthorAppearsLaterBecomesReadable(t *testing.T) {
	t.Parallel()
	const secretID = "a1a1a1a1a1a1"
	h := newHarness(t, map[string]string{
		"Cellar.md": "# Cellar\n\n" + secretFence(secretID, "dm", "wren", secretBody("the cellar")) + "\nA public tail.\n",
	})

	// The account does not exist yet.
	first := h.indexAll()
	h.settle()
	assertAuthorProblem(t, first, secretID, 1)
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets WHERE id = ?`, secretID); n != 0 {
		t.Fatalf("a secret naming an account that does not exist was indexed (%d rows)", n)
	}
	if pendingCount(h.ix) != 1 {
		t.Fatalf("%d paths pending, want 1", pendingCount(h.ix))
	}
	// Fail-closed, and provably so: no row, and the body nowhere public.
	assertAbsentFromPublic(t, h, "while the author is unknown", leakToken)
	assertAbsentFromSearchIndex(t, h, "while the author is unknown", leakToken)

	// The trap. Re-running the ordinary pass over an unchanged file does
	// nothing at all, which is why this gap survived the original report.
	h.indexAll()
	h.reconcile()
	h.settle()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets WHERE id = ?`, secretID); n != 0 {
		t.Fatalf("an ordinary pass indexed the secret (%d rows); the fixture no longer reproduces the bug", n)
	}

	// The account arrives. This is the moment the boot sequence has to react to.
	h.seedUser("wren", "dm")
	wren := h.userID("wren")
	res, err := h.ix.RetryUnresolvedAuthors(context.Background())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	h.settle()
	if len(res.Indexed) != 1 || res.Indexed[0].Path != "Cellar.md" {
		t.Fatalf("the retry indexed %+v, want just Cellar.md", res.Indexed)
	}
	if !res.Changed() {
		t.Error("the retry reported no change, so it did not write what it was asked to write")
	}
	// The problem is gone with it, and the path has left the pending set.
	assertAuthorProblem(t, res, secretID, 0)
	if pendingCount(h.ix) != 0 {
		t.Errorf("%d paths still pending after a successful retry", pendingCount(h.ix))
	}

	// The row exists, with the right owner and the visibility the fence claimed.
	row, err := store.GetSecretByID(context.Background(), h.db.Reader(), secretID)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if row.AuthorID != wren {
		t.Errorf("author_id = %d, want the account that was created (%d)", row.AuthorID, wren)
	}
	if row.Visibility != "dm" {
		t.Errorf("visibility = %q, want dm", row.Visibility)
	}
	if !strings.Contains(row.Body, leakToken) {
		t.Error("the indexed body is not the fence's body")
	}
	// And it is readable by exactly who §8.2 says, which is the point of the
	// whole exercise: it is not in the index and invisible, it is in the index
	// and governed.
	if _, err := store.GetVisibleSecret(context.Background(), h.db.Reader(), h.principal("dorn"), secretID); err != nil {
		t.Errorf("a DM cannot read the secret it authored: %v", err)
	}
	if _, err := store.GetVisibleSecret(context.Background(), h.db.Reader(), h.principal("wren"), secretID); err != nil {
		t.Errorf("the author cannot read their own secret: %v", err)
	}
	if _, err := store.GetVisibleSecret(context.Background(), h.db.Reader(), h.principal("pia"), secretID); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("a player can read a dm secret: %v", err)
	}
	// Indexed, not published: a dm secret is still out of the search index.
	assertAbsentFromPublic(t, h, "after the retry", leakToken)
	assertAbsentFromSearchIndex(t, h, "after the retry", leakToken)
	if n, err := store.CheckSecretIndexInvariant(context.Background(), h.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d, want 0 (%v)", n, err)
	}
	// And a second retry has nothing left to do.
	if again, err := h.ix.RetryUnresolvedAuthors(context.Background()); err != nil || len(again.Indexed) != 0 {
		t.Errorf("a second retry = %+v (%v), want nothing to do", again.Indexed, err)
	}
}

// TestRetryDoesNothingWhenNothingIsPending asserts the cheap case, which is the
// one a boot sequence calls unconditionally on every start.
//
// The assertion is a whole-index snapshot rather than a row count, because a
// retry that rewrote identical values would pass a count and still be wrong: the
// point of the call is that it does not touch the index at all.
func TestRetryDoesNothingWhenNothingIsPending(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Clean.md":    "# Clean\n\n" + secretFence("b2b2b2b2b2b2", "dm", "dorn", secretBody("the vault")) + "\n",
		"Ordinary.md": "# Ordinary\n\nJust a note.\n",
	})
	h.indexAll()
	h.settle()
	before := h.snapshot()
	h.drainEvents()

	res, err := h.ix.RetryUnresolvedAuthors(context.Background())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(res.Indexed) != 0 || res.Changed() {
		t.Errorf("a retry with nothing pending did work: %+v", res)
	}
	if got := h.drainEvents(); len(got) != 0 {
		t.Errorf("a retry with nothing pending announced %d invalidations", len(got))
	}
	if after := h.snapshot(); after != before {
		t.Errorf("a retry with nothing pending changed the index:\n%s\nwant:\n%s", after, before)
	}
}

// TestRetryWithNoAccountsIsANoOp asserts the case the pending set exists through:
// the vault is indexed before anybody has signed up, so every fence in it names
// an account that does not exist, and the retry has nothing to look up.
//
// The fixture is built without the harness's three accounts on purpose — the
// first thing a real vault does is get indexed with an empty users table — and
// the assertion is that the pending set survives the call untouched, because a
// retry that dropped it would be a retry that forgot a secret for ever.
func TestRetryWithNoAccountsIsANoOp(t *testing.T) {
	t.Parallel()
	const secretID = "c3c3c3c3c3c3"
	v := testutil.WithVault(t, map[string]string{
		"Cellar.md": "# Cellar\n\n" + secretFence(secretID, "dm", "wren", secretBody("the cellar")) + "\n",
	})
	ctx := context.Background()
	db, err := store.Open(v.Root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	})
	if migrateErr := store.Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); migrateErr != nil {
		t.Fatalf("migrate: %v", migrateErr)
	}
	if n, countUsersErr := store.CountUsers(ctx, db.Reader()); countUsersErr != nil || n != 0 {
		t.Fatalf("the fixture has %d accounts, want none (%v)", n, countUsersErr)
	}
	ix, err := New(Options{DB: db, Root: v.Root, Log: obs.Discard()})
	if err != nil {
		t.Fatalf("new indexer: %v", err)
	}
	if _, indexBatchErr := ix.IndexBatch(ctx, []string{"Cellar.md"}); indexBatchErr != nil {
		t.Fatalf("index: %v", indexBatchErr)
	}
	if pendingCount(ix) != 1 {
		t.Fatalf("%d paths pending, want 1", pendingCount(ix))
	}

	res, err := ix.RetryUnresolvedAuthors(ctx)
	if err != nil {
		t.Fatalf("retry with no accounts: %v", err)
	}
	if len(res.Indexed) != 0 || res.Changed() {
		t.Errorf("a retry with no accounts did work: %+v", res)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM secrets WHERE id = ?`, secretID); n != 0 {
		t.Errorf("a retry with no accounts indexed a secret (%d rows)", n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM secret_text`); n != 0 {
		t.Errorf("a retry with no accounts put a body in the search index (%d rows)", n)
	}
	// Still pending, which is the safe outcome: the next call, once the account
	// exists, is the one that fixes it.
	if !pendingHas(ix, "Cellar.md") {
		t.Error("the retry forgot a pending path that is still unattributable")
	}
	// And with the account finally created, the same call now does the work.
	if _, insertUserErr := store.InsertUser(ctx, db.Writer(), store.User{
		Username: "wren", DisplayName: "wren", Role: "dm",
		PWSalt: []byte("salt"), CreatedAt: clockNow,
	}); insertUserErr != nil {
		t.Fatalf("insert user: %v", insertUserErr)
	}
	res, err = ix.RetryUnresolvedAuthors(ctx)
	if err != nil {
		t.Fatalf("retry after the account exists: %v", err)
	}
	if len(res.Indexed) != 1 {
		t.Fatalf("the retry after the account exists indexed %+v, want Cellar.md", res.Indexed)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM secrets WHERE id = ?`, secretID); n != 1 {
		t.Errorf("%d secret rows, want 1", n)
	}
}

// TestThePendingSetIsBounded asserts the bound, and that exceeding it forgets the
// oldest path rather than growing without limit.
//
// The cost of forgetting is asserted too, because a bound that is only safe is
// not a bound: a forgotten path is not retried, and it must not be a page with a
// half-written index row instead.
func TestThePendingSetIsBounded(t *testing.T) {
	t.Parallel()
	const capacity = 4
	h := newHarness(t, nil)
	small, err := New(Options{
		DB: h.db, Root: h.vault.Root, Log: h.log, Clock: h.now,
		UnresolvedAuthorCapacity: capacity,
	})
	if err != nil {
		t.Fatalf("indexer: %v", err)
	}
	// Six pages, each naming a different account that does not exist. Written in
	// name order so which two are forgotten is not a property of a map.
	paths := make([]string, 0, 6)
	for i := 1; i <= 6; i++ {
		rel := fmt.Sprintf("P%d.md", i)
		paths = append(paths, rel)
		h.vault.WriteFile(t, rel, "# P\n\n"+
			secretFence(fmt.Sprintf("%012x", i), "dm", fmt.Sprintf("ghost%d", i), secretBody(rel))+"\n")
	}
	if _, indexBatchErr := small.IndexBatch(context.Background(), paths); indexBatchErr != nil {
		t.Fatalf("index: %v", indexBatchErr)
	}
	if got := pendingCount(small); got != capacity {
		t.Errorf("the pending set holds %d paths, want the capacity of %d", got, capacity)
	}
	for _, rel := range []string{"P1.md", "P2.md"} {
		if pendingHas(small, rel) {
			t.Errorf("%s was kept; the oldest paths are the ones forgotten", rel)
		}
	}
	for _, rel := range []string{"P5.md", "P6.md"} {
		if !pendingHas(small, rel) {
			t.Errorf("%s was evicted; the newest paths are the ones kept", rel)
		}
	}
	// Every account now exists, so every path that is still pending resolves.
	// The two that were forgotten do not, and must not be half-indexed.
	for i := 1; i <= 6; i++ {
		h.seedUser(fmt.Sprintf("ghost%d", i), "dm")
	}
	res, err := small.RetryUnresolvedAuthors(context.Background())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(res.Indexed) != capacity {
		t.Errorf("the retry indexed %d pages, want the %d still pending", len(res.Indexed), capacity)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != capacity {
		t.Errorf("%d secret rows, want %d", n, capacity)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets WHERE author_id = 0`); n != 0 {
		t.Errorf("%d secrets were indexed against a zero author", n)
	}
	for _, rel := range []string{"P1.md", "P2.md"} {
		if n := h.mustQueryInt(
			`SELECT COUNT(*) FROM secrets s JOIN pages p ON p.id = s.page_id WHERE p.path = ?`, rel); n != 0 {
			t.Errorf("%s was indexed even though it was forgotten: the bound changed an answer", rel)
		}
	}
	if pendingCount(small) != 0 {
		t.Errorf("%d paths are still pending after every account existed", pendingCount(small))
	}
}

// TestAPathLeavesPendingWhenItsFenceIsFixed asserts the other way out: a vault
// edit fixes the fence, and the ordinary pass — the one the watcher runs —
// clears the path without anybody calling the retry.
func TestAPathLeavesPendingWhenItsFenceIsFixed(t *testing.T) {
	t.Parallel()
	const (
		secretID = "d4d4d4d4d4d4"
		otherID  = "e5e5e5e5e5e5"
	)
	h := newHarness(t, map[string]string{
		"Cellar.md": "# Cellar\n\n" + secretFence(secretID, "dm", "wren", secretBody("the cellar")) + "\n",
		"Keep.md":   "# Keep\n\n" + secretFence(otherID, "dm", "vance", secretBody("the keep")) + "\n",
	})
	h.indexAll()
	h.settle()
	if pendingCount(h.ix) != 2 {
		t.Fatalf("%d paths pending, want 2", pendingCount(h.ix))
	}

	// The DM fixes the author by hand. Nothing else about the file changes, so
	// this is the ordinary idempotence path — which sees a changed hash and so
	// does the work.
	h.vault.WriteFile(t, "Cellar.md",
		"# Cellar\n\n"+secretFence(secretID, "dm", "dorn", secretBody("the cellar"))+"\n")
	h.reconcile()
	h.settle()

	if pendingHas(h.ix, "Cellar.md") {
		t.Error("a corrected fence is still pending after the ordinary pass indexed it")
	}
	if !pendingHas(h.ix, "Keep.md") {
		t.Error("correcting one page's fence dropped another page's entry")
	}
	row, err := store.GetSecretByID(context.Background(), h.db.Reader(), secretID)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if row.AuthorID != h.userID("dorn") {
		t.Errorf("author_id = %d, want dorn (%d)", row.AuthorID, h.userID("dorn"))
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 1 {
		t.Errorf("%d secret rows, want only the corrected one", n)
	}

	// Deleting the fence is the other way a page stops being pending.
	h.vault.WriteFile(t, "Keep.md", "# Keep\n\nThe keep has no secrets left.\n")
	h.reconcile()
	h.settle()
	if pendingCount(h.ix) != 0 {
		t.Errorf("%d paths are still pending after both fences stopped being a problem", pendingCount(h.ix))
	}
	// Only the corrected one is left: the row the removed fence produced went
	// with it, which is the ordinary replace-wholesale rule and not this fix.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 1 {
		t.Errorf("%d secret rows, want only the corrected one", n)
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM secrets s JOIN pages p ON p.id = s.page_id WHERE p.path = ?`,
		"Keep.md"); n != 0 {
		t.Error("a row survived removing the fence that made it")
	}
}

// TestPendingNeverBecomesATableSecret asserts the fail-closed property from both
// ends: a pending fence is absent from the index, so nothing about it is
// searchable, and when it finally resolves it reaches the search index if and
// only if the fence actually says `table`.
//
// A retry that indexed a pending secret as table-visible would be the worst
// outcome available here: a secret nobody could read, published to everybody by
// the code that was supposed to be fixing it.
func TestPendingNeverBecomesATableSecret(t *testing.T) {
	t.Parallel()
	const (
		hiddenID = "0a0a0a0a0a0a"
		sharedID = "0b0b0b0b0b0b"
		knownID  = "0c0c0c0c0c0c"
		// Three bodies, three tokens: a test that cannot tell one secret from
		// another cannot tell one leak from another, and would pass against a
		// retry that published the wrong fence.
		hiddenWord = "briar"
		sharedWord = "thistle"
		knownWord  = "nettle"
	)
	h := newHarness(t, map[string]string{
		"Page.md": "# Page\n\n" +
			secretFence(hiddenID, "dm", "wren", taggedSecretBody(hiddenWord, hiddenWord)) + "\n" +
			secretFence(sharedID, "table", "wren", taggedSecretBody(sharedWord, sharedWord)) + "\n" +
			secretFence(knownID, "table", "dorn", taggedSecretBody(knownWord, knownWord)) + "\n",
	})
	h.indexAll()
	h.settle()

	// The two fences whose author does not exist are indexed as nothing at all,
	// whatever visibility they claim, so only the known one is searchable.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 1 {
		t.Fatalf("%d secret rows, want only the one whose author exists", n)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE body LIKE ?`, "%"+knownWord+"%"); n != 1 {
		t.Errorf("%d bodies in the search index, want only the known table secret", n)
	}
	for word, which := range map[string]string{hiddenWord: "the pending dm fence", sharedWord: "the pending table fence"} {
		assertAbsentFromPublic(t, h, which, word)
		assertAbsentFromSearchIndex(t, h, which, word)
	}

	h.seedUser("wren", "dm")
	if _, err := h.ix.RetryUnresolvedAuthors(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	h.settle()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 3 {
		t.Fatalf("%d secret rows after the retry, want 3", n)
	}
	// The dm one is indexed and still unsearchable; the table one is indexed and
	// searchable. Both are now governed by the visibility their fence claimed,
	// which is the whole contract of the retry.
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, hiddenID); n != 0 {
		t.Error("a dm secret reached the search index")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, sharedID); n != 1 {
		t.Error("a table secret did not reach the search index once its author existed")
	}
	// A body never enters page_text, whatever the retry did, however open the
	// fence is: that is the difference between revealed and written on the page.
	for _, word := range []string{hiddenWord, sharedWord, knownWord} {
		if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE body LIKE ?`, "%"+word+"%"); n != 0 {
			t.Errorf("%d rows of page_text carry the %s body", n, word)
		}
		if hits := h.ftsHits("page_fts", word); len(hits) != 0 {
			t.Errorf("the %s body reached page_fts (%v)", word, hits)
		}
	}
	if hits := h.ftsHits("secret_fts", hiddenWord); len(hits) != 0 {
		t.Errorf("the dm body is searchable after the retry (%v)", hits)
	}
	if hits := h.ftsHits("secret_fts", sharedWord); len(hits) != 1 {
		t.Errorf("the table body is searchable in %d rows, want 1", len(hits))
	}
	if n, err := store.CheckSecretIndexInvariant(context.Background(), h.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d, want 0 (%v)", n, err)
	}
}

// mustCount is the one assertion the bare-database fixtures need and the harness
// helpers cannot give them.
func mustCount(t *testing.T, db *store.DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}
