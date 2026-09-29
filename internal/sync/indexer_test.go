package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// TestIndexIsIdempotent asserts that a second pass over unchanged files changes
// nothing at all.
//
// The assertion is a full snapshot of every derived table rather than a row
// count, because a row count cannot tell a pass that rewrote identical values
// from a pass that left the index alone — and the second is the property, not
// the first. A revision appended per pass is the specific churn this catches:
// it would keep the row count moving while every other table stayed still.
func TestIndexIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Campaign.md":        "---\ntitle: The Campaign\ntags: [alpha]\n---\n# The Campaign\n\n[[Gundren]] and #beta.\n\n![the map](assets/map.png)\n",
		"NPCs/Gundren.md":    "# Gundren\n\nA dwarf. See [[Campaign]] and [[Missing One]].\n",
		"NPCs/Secret One.md": "---\ntype: npc\n---\n# Secret One\n\n```secret id=a1b2c3d4e5f6 visibility=dm author=dorn\nHidden.\n```\n\n## Public part\n\n[[Campaign]]\n",
		// An attachment in the corpus is what makes the attachment rows part of
		// what idempotence is asserted about: without a file, the snapshot's
		// attachment section is empty and a pass that duplicated a row on every
		// reindex would pass it.
		"assets/map.png": "not a real map, and short enough to count",
	})
	first := h.indexAll()
	if !first.Changed() {
		t.Fatal("the first pass changed nothing, so the fixture is empty")
	}
	before := h.snapshot()
	revisions := h.mustQueryInt(`SELECT COUNT(*) FROM revisions`)
	if revisions == 0 {
		t.Fatal("no revision was recorded for the first sighting of a page")
	}

	second := h.indexAll()
	if second.Changed() {
		t.Fatalf("the second pass reported a change: %+v", second.Indexed)
	}
	if second.Unchanged != len(second.Indexed) {
		t.Fatalf("every file should have been unchanged: %+v", second.Indexed)
	}
	if after := h.snapshot(); after != before {
		t.Fatalf("the second pass churned the index\n--- first ---\n%s\n--- second ---\n%s", before, after)
	}
	if got := h.mustQueryInt(`SELECT COUNT(*) FROM revisions`); got != revisions {
		t.Fatalf("revision rows moved from %d to %d on an unchanged pass", revisions, got)
	}
	if n := h.bus.Published(); n == 0 {
		t.Fatal("the first pass published nothing at all")
	}
	if got := h.mustQueryInt(`SELECT COUNT(*) FROM attachments`); got != 1 {
		t.Fatalf("attachments = %d, want 1: the idempotence snapshot would not have covered them", got)
	}
}

// TestIndexIsIdempotentAfterAReconcile asserts the same property for the
// reconciliation path, which is the one that runs for ever.
func TestIndexIsIdempotentAfterAReconcile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"A.md": "# A\n\n[[B]]\n",
		"B.md": "# B\n\nback to [[A]]\n",
	})
	h.indexAll()
	before := h.snapshot()
	if res := h.reconcile(); res.Changed() {
		t.Fatalf("a scan of an unchanged vault reported a change: %+v", res.Indexed)
	}
	if after := h.snapshot(); after != before {
		t.Fatalf("a scan of an unchanged vault churned the index\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

// TestIndexMatchesTheScan asserts that the boot path and the reconciliation path
// land on byte-identical index state.
//
// The two indexers are separate on purpose: the second one has an empty scanner
// record, so its first scan reports every file as changed and re-reads the whole
// vault. If the two paths can disagree, that is where it shows up — and because
// the fast path is hash-based, a correct implementation writes nothing at all,
// so the comparison is between one state and itself rather than between two
// states that merely look the same.
func TestIndexMatchesTheScan(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"Campaign.md":     "---\ntitle: The Campaign\n---\n# The Campaign\n\n[[Gundren]] [[Tavern]] #hub\n",
		"NPCs/Gundren.md": "---\naliases: [The Dwarf]\n---\n# Gundren\n\nA dwarf.\n",
		"Tavern.md":       "# The Tavern\n\n[[Gundren]] sits in the corner.\n",
		"Loose/Note.md":   "```secret id=0123456789ab visibility=table author=dorn\nA revealed secret.\n```\n",
	}
	h := newHarness(t, files)
	h.indexAll()
	viaWalk := h.snapshot()

	// A second pass, and a change, then the scan-only indexer.
	h.vault.WriteFile(t, "Campaign.md", files["Campaign.md"]+"\nAn extra line.\n")
	h.reconcile()
	beforeSecond := h.snapshot()
	if beforeSecond == viaWalk {
		t.Fatal("editing a page did not move the index")
	}

	second := h.newIndexer()
	changed, err := second.scanFiles(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(changed) != len(files) {
		t.Fatalf("a fresh scanner should report every file, got %d of %d", len(changed), len(files))
	}
	if res, err := second.IndexBatch(context.Background(), changed); err != nil {
		t.Fatalf("index batch: %v", err)
	} else if res.Changed() {
		t.Fatalf("re-indexing unchanged files wrote something: %+v", res.Indexed)
	}
	if after := h.snapshot(); after != beforeSecond {
		t.Fatalf("the scan path and the walk path disagree\n--- walk ---\n%s\n--- scan ---\n%s",
			beforeSecond, after)
	}
}

// TestWatchAndReconcileAgree asserts that a vault indexed through the watcher's
// debounced batches ends up in the same state as one indexed by a scan.
//
// The watcher is the fast path and the scan is the guarantee, so the two must
// not be allowed to diverge; this is the test that says so with a real fsnotify
// watcher in the loop rather than a simulated event.
func TestWatchAndReconcileAgree(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newHarness(t, map[string]string{
		"Campaign.md": "# Campaign\n\n[[Gundren]]\n",
	})
	// The seed file's own event is drained so the wait below is for the two
	// files written after the watcher started, and not for one that was already
	// in the channel when the watcher came up.
	h.indexAll()
	h.settle()
	w, err := h.ix.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer w.Close()

	// Written after the watcher is running, so the events are real.
	h.vault.WriteFile(t, "NPCs/Gundren.md", "# Gundren\n\nA dwarf, in [[Campaign]].\n")
	h.vault.WriteFile(t, "Tavern.md", "# Tavern\n\n[[Gundren]] waits here.\n")
	// Two batches may or may not be delivered, and a pass that created pages may
	// publish a second event for one of them, so the wait is for silence rather
	// than for a count.
	h.awaitQuiet(500*time.Millisecond, 20*time.Second)
	viaWatch := h.snapshot()

	// A fresh indexer over the same vault, indexed by scan alone.
	other := newHarness(t, map[string]string{
		"Campaign.md":     "# Campaign\n\n[[Gundren]]\n",
		"NPCs/Gundren.md": "# Gundren\n\nA dwarf, in [[Campaign]].\n",
		"Tavern.md":       "# Tavern\n\n[[Gundren]] waits here.\n",
	})
	other.indexAll()
	if other.snapshot() != viaWatch {
		t.Fatalf("the watcher and the scan disagree\n--- watch ---\n%s\n--- scan ---\n%s",
			viaWatch, other.snapshot())
	}
}

// TestReconcileScanFindsMissedEvent asserts that a change the watcher never
// delivered is still found by the scan.
//
// The watcher here is real and running; its batch callback throws the batch away,
// which is exactly what a dropped fsnotify event looks like to the rest of the
// process. Nothing is retried, because fsnotify cannot tell you which events it
// lost: the scan is the only mechanism that can close the hole, so the test
// exists to prove the index converges without one.
func TestReconcileScanFindsMissedEvent(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newHarness(t, map[string]string{"Seed.md": "# Seed\n"})
	suppressed := make(chan string, 8)
	w, err := vault.NewWatcher(vault.WatchOptions{
		Root:  h.vault.Root,
		Store: NewSelfwrites(h.db, h.log),
		Log:   h.log,
		Clock: func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	// The event arrives and is thrown on the floor.
	w.OnBatch(func(_ context.Context, paths []string) {
		for _, p := range paths {
			select {
			case suppressed <- p:
			default:
			}
		}
	})
	if err := w.Start(ctx); err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	defer w.Close()
	h.indexAll()
	h.settle()

	h.vault.WriteFile(t, "Missed.md", "# Missed\n\nWritten while the watcher was lying.\n")
	select {
	case p := <-suppressed:
		t.Logf("the watcher did deliver %s; the batch was dropped on purpose", p)
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher never delivered the event, so the test is not exercising anything")
	}

	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = ?`, "Missed.md"); n != 0 {
		t.Fatalf("the dropped event was indexed anyway, so nothing was missed")
	}
	res := h.reconcile()
	if len(res.Indexed) == 0 {
		t.Fatal("the reconciliation scan found nothing")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = ?`, "Missed.md"); n != 1 {
		t.Fatalf("the reconciliation scan did not find the missed file; indexed=%+v", res.Indexed)
	}
	// A second scan must be quiet, or the scan is not tracking what it indexed.
	if again := h.reconcile(); again.Changed() {
		t.Fatalf("a second scan changed something: %+v", again.Indexed)
	}
}

// TestWatcherSuppressesSelfWritesButNotExternalEdits asserts that the app's own
// write produces no event while a hand edit to the same path inside the window
// does.
//
// The suppression is by content hash, which is the only version of it that is
// safe: a time window alone would swallow the DM's edit, because it lands in the
// same ten seconds.
func TestWatcherSuppressesSelfWritesButNotExternalEdits(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newHarness(t, map[string]string{"Page.md": "# Page\n\nfirst version\n"})
	h.indexAll()
	h.settle()

	w, err := h.ix.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer w.Close()

	wr := h.writer()
	onDisk := h.vault.ReadFile(t, "Page.md")
	if err := wr.Save(ctx, vault.SaveRequest{
		Path:            "Page.md",
		NewContent:      []byte("# Page\n\nsaved by the app\n"),
		BaseContentHash: vault.Hash(onDisk),
		ActorID:         h.userID("pia"),
		ExpectPerm:      authz.PermWritePage,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	h.expectNoEvent(1500 * time.Millisecond)

	// The DM edits the same file behind the app's back, inside the window. The
	// bytes differ, so the hash differs, so the event is real.
	h.vault.WriteFile(t, "Page.md", "# Page\n\nedited in Obsidian\n")
	ev := h.awaitEvent(10 * time.Second)
	if ev.Path != "Page.md" {
		t.Fatalf("the event was for %s, not Page.md", ev.Path)
	}
	if got := h.mustQueryString(`SELECT body FROM page_text WHERE page_id = ?`,
		h.pageID("Page.md")); !strings.Contains(got, "edited in Obsidian") {
		t.Fatalf("the external edit was not indexed, body=%q", got)
	}
}

// TestReconcileDeletesAPageWhoseFileWentAway asserts that a deletion observed by
// the scan removes the page, its text, its search rows and its orphaned tag.
func TestReconcileDeletesAPageWhoseFileWentAway(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Keep.md": "# Keep\n\n[[Gone]] #keep\n",
		"Gone.md": "# Gone\n\n#onlygone\n\n```secret id=111122223333 visibility=table author=dorn\nA revealed body.\n```\n",
	})
	h.indexAll()
	goneID := h.pageID("Gone.md")
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, "111122223333"); n != 1 {
		t.Fatal("the revealed secret was not indexed")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM tags WHERE name = ?`, "onlygone"); n != 1 {
		t.Fatal("the inline tag was not registered")
	}

	h.vault.Remove(t, "Gone.md")
	res := h.reconcile()
	if len(res.Indexed) == 0 {
		t.Fatal("the scan did not report the deletion")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE id = ?`, goneID); n != 0 {
		t.Fatal("the page row survived the deletion")
	}
	for _, table := range []string{"page_text", "headings", "secrets", "revisions"} {
		if n := h.mustQueryInt(`SELECT COUNT(*) FROM `+table+` WHERE page_id = ?`, goneID); n != 0 {
			t.Errorf("%s still has %d rows for the deleted page", table, n)
		}
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE source_page_id = ?`, goneID); n != 0 {
		t.Errorf("links still has %d rows for the deleted page", n)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, "111122223333"); n != 0 {
		t.Error("the deleted page's secret text survived")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, "onlygone"); n != 0 {
		t.Error("the deleted page's FTS row survived")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM tags WHERE name = ?`, "onlygone"); n != 0 {
		t.Error("an orphaned tag survived the deletion")
	}
}

// TestRemoveMissingDropsPagesTheWalkDidNotSee is the boot case: a page whose file
// was deleted while the app was closed.
func TestRemoveMissingDropsPagesTheWalkDidNotSee(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Keep.md": "# Keep\n",
		"Gone.md": "# Gone\n",
	})
	h.indexAll()
	if n, err := store.CountPages(context.Background(), h.db.Reader()); err != nil || n != 2 {
		t.Fatalf("expected two pages, got %d (%v)", n, err)
	}
	removed, err := h.ix.RemoveMissing(context.Background(), []string{"Keep.md"})
	if err != nil {
		t.Fatalf("remove missing: %v", err)
	}
	if len(removed) != 1 || removed[0].Path != "Gone.md" || removed[0].Kind != ChangeDeleted {
		t.Fatalf("unexpected removals: %+v", removed)
	}
	if n, err := store.CountPages(context.Background(), h.db.Reader()); err != nil || n != 1 {
		t.Fatalf("expected one page, got %d (%v)", n, err)
	}
}

// TestOversizeFileIsReportedAndNotIndexed asserts that a file over the read cap
// produces a problem instead of a truncated page.
func TestOversizeFileIsReportedAndNotIndexed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Small.md": "# Small\n"})
	big := strings.Repeat("a", int(vault.MaxFileBytes)+1)
	h.vault.WriteFile(t, "Big.md", big)

	// The walk refuses it, so the boot pass never sees it.
	walk, err := h.ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if contains(walk.Files, "Big.md") {
		t.Error("the walk offered an oversize file for indexing")
	}
	if len(walk.Unreadable) == 0 {
		t.Error("the walk did not report the oversize file as unreadable")
	}

	// A direct pass, which is what a watcher batch amounts to, reports a problem.
	res, err := h.ix.Index(context.Background(), "Big.md")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = ?`, "Big.md"); n != 0 {
		t.Fatal("an oversize file was indexed")
	}
	if len(res.Problems) != 1 || res.Problems[0].Code != ProblemOversize {
		t.Fatalf("the oversize file produced no problem: %+v", res.Problems)
	}
	// The rest of the vault is unaffected.
	h.indexAll()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages`); n != 1 {
		t.Fatalf("expected only the small page, got %d", n)
	}
}

// TestDirectoryPathIsNotAPage asserts that a directory delivered as a change does
// not become a page row.
func TestDirectoryPathIsNotAPage(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Real.md": "# Real\n"})
	h.vault.MkdirAll(t, "Sub/Dir")
	res, err := h.ix.IndexBatch(context.Background(), []string{"Sub/Dir"})
	if err != nil {
		t.Fatalf("index batch: %v", err)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = ?`, "Sub/Dir"); n != 0 {
		t.Fatal("a directory became a page")
	}
	if len(res.Indexed) != 1 || len(res.Indexed[0].Problems) != 1 {
		t.Fatalf("the directory produced no problem: %+v", res.Indexed)
	}
}

// TestIndexPublishesOneEventPerChangedFile asserts the announcement contract: a
// changed file publishes, an unchanged one does not, and a delete publishes as a
// delete.
func TestIndexPublishesOneEventPerChangedFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"One.md": "# One\n"})
	h.indexAll()
	h.settle()

	if _, err := h.ix.Index(context.Background(), "One.md"); err != nil {
		t.Fatalf("index: %v", err)
	}
	h.expectNoEvent(300 * time.Millisecond)

	h.vault.WriteFile(t, "One.md", "# One\n\nchanged\n")
	if _, err := h.ix.Index(context.Background(), "One.md"); err != nil {
		t.Fatalf("index: %v", err)
	}
	ev := h.awaitEvent(3 * time.Second)
	if ev.Kind != ChangeUpdated || ev.Path != "One.md" || ev.PageID == 0 || len(ev.Hash) != 32 {
		t.Fatalf("unexpected event %+v", ev)
	}
	h.drainEvents()

	h.vault.Remove(t, "One.md")
	if _, err := h.ix.Index(context.Background(), "One.md"); err != nil {
		t.Fatalf("index: %v", err)
	}
	if ev := h.awaitEvent(3 * time.Second); ev.Kind != ChangeDeleted {
		t.Fatalf("unexpected event %+v", ev)
	}
}

// TestConcurrentIndexOfOneFileHasOneWriter asserts that two passes racing over
// the same file leave one consistent state, because the write pool is a single
// connection and each file's rows are one transaction.
func TestConcurrentIndexOfOneFileHasOneWriter(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Race.md":  "# Race\n\n[[Other]] and #tagged\n",
		"Other.md": "# Other\n",
	})
	h.indexAll()
	before := h.snapshot()
	revisions := h.mustQueryInt(`SELECT COUNT(*) FROM revisions`)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			_, err := h.ix.Index(context.Background(), "Race.md")
			errs <- err
		}()
	}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent index: %v", err)
		}
	}
	after := h.snapshot()
	if after != before {
		t.Fatalf("four concurrent passes over one unchanged file churned the index\n--- before ---\n%s\n--- after ---\n%s",
			before, after)
	}
	if got := h.mustQueryInt(`SELECT COUNT(*) FROM revisions`); got != revisions {
		t.Fatalf("revision rows moved from %d to %d under concurrent passes", revisions, got)
	}
}

// TestWalkFindsWhatReconcileIndexes asserts the boot pass and the scan pass
// enumerate the same files.
func TestWalkFindsWhatReconcileIndexes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"a.md":           "# a\n",
		"dir/b.md":       "# b\n",
		"dir/sub/c.md":   "# c\n",
		".obsidian/x.md": "ignored\n",
		".git/y.md":      "ignored\n",
		"notes.txt":      "not a page? still indexed as a page\n",
	})
	walk, err := h.ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if walk.Ignored == 0 {
		t.Error("the walk ignored nothing, so the ignore rules did not run")
	}
	for _, ignored := range []string{".obsidian/x.md", ".git/y.md"} {
		if contains(walk.Files, ignored) {
			t.Errorf("the walk returned the ignored path %s", ignored)
		}
	}
	changed, err := h.ix.scanFiles(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !equalSets(walk.Files, changed) {
		t.Fatalf("walk and scan disagree\nwalk=%v\nscan=%v", walk.Files, changed)
	}
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
