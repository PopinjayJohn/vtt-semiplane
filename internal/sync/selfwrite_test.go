package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// TestSelfwriteSuppressionIsByHashNotByTime is the property that makes the
// suppression table safe to exist at all.
//
// A time window alone would swallow the DM's edit, because it lands in the same
// ten seconds the app's own write registered. Hash-based suppression means the
// app only ever ignores the bytes it wrote.
func TestSelfwriteSuppressionIsByHashNotByTime(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": "# Page\n"})
	sw := NewSelfwrites(h.db, h.log)
	sw.SetClock(h.now)
	ctx := context.Background()
	mine := vault.Hash([]byte("the bytes the app wrote"))
	theirs := vault.Hash([]byte("the bytes a human wrote"))

	if err := sw.PutSelfwrite(ctx, "Page.md", mine, h.now().Add(10*time.Second)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if ok, err := sw.IsSelfwrite(ctx, "Page.md", mine); err != nil || !ok {
		t.Errorf("the app's own write is not recognised (ok=%v err=%v)", ok, err)
	}
	if ok, err := sw.IsSelfwrite(ctx, "Page.md", theirs); err != nil || ok {
		t.Errorf("a human's write inside the window is being suppressed (ok=%v err=%v)", ok, err)
	}
	// A different path is not covered by this registration.
	if ok, err := sw.IsSelfwrite(ctx, "Other.md", mine); err != nil || ok {
		t.Errorf("the registration leaked to another path (ok=%v err=%v)", ok, err)
	}
	// A second write replaces the first: the newest hash is the one that counts.
	newer := vault.Hash([]byte("a second write"))
	if err := sw.PutSelfwrite(ctx, "Page.md", newer, h.now().Add(10*time.Second)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if ok, _ := sw.IsSelfwrite(ctx, "Page.md", mine); ok {
		t.Error("the first write is still suppressed after a second")
	}
	if ok, _ := sw.IsSelfwrite(ctx, "Page.md", newer); !ok {
		t.Error("the second write is not suppressed")
	}
	// The window expires.
	h.advance(11 * time.Second)
	if ok, err := sw.IsSelfwrite(ctx, "Page.md", newer); err != nil || ok {
		t.Errorf("an expired registration is still suppressing (ok=%v err=%v)", ok, err)
	}
}

// TestSelfwritePruneSweepsExpiredRegistrations asserts the table does not grow
// for ever, and that the explicit sweep is the one the boot sequence calls.
func TestSelfwritePruneSweepsExpiredRegistrations(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": "# Page\n"})
	sw := NewSelfwrites(h.db, h.log)
	sw.SetClock(h.now)
	ctx := context.Background()
	for i := range 5 {
		if err := sw.PutSelfwrite(ctx, string(rune('a'+i))+".md",
			vault.Hash([]byte{byte(i)}), h.now().Add(10*time.Second)); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM selfwrites`); n != 5 {
		t.Fatalf("expected five registrations, got %d", n)
	}
	if n, err := sw.Prune(ctx); err != nil || n != 0 {
		t.Fatalf("pruning live registrations removed %d (%v)", n, err)
	}
	h.advance(11 * time.Second)
	n, err := sw.Prune(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n == 0 {
		t.Fatal("pruning after the window removed nothing")
	}
	if left := h.mustQueryInt(`SELECT COUNT(*) FROM selfwrites`); left != 0 {
		t.Errorf("%d registrations survived the sweep", left)
	}
}

// TestAWatcherSaveIsSuppressedEndToEnd is the pair of the hash test above seen
// from the watcher's side: one save through vault.Writer produces no event, and
// one hand edit does.
//
// The save is the app's own, so the index is deliberately left stale by it. A
// watcher that reported the app's own write would index every page twice, once
// from the save handler's explicit pass and once from the event; the app is
// therefore responsible for re-indexing what it wrote, and the test does exactly
// that here to show the two halves meet.
func TestAWatcherSaveIsSuppressedEndToEnd(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newHarness(t, map[string]string{"Page.md": "# Page\n\noriginal\n"})
	h.indexAll()
	h.settle()
	w, err := h.ix.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer w.Close()

	wr := h.writer()
	onDisk := h.vault.ReadFile(t, "Page.md")
	saved := "# Page\n\nsaved by the app\n"
	if err := wr.Save(ctx, vault.SaveRequest{
		Path:            "Page.md",
		NewContent:      []byte(saved),
		BaseContentHash: vault.Hash(onDisk),
		ActorID:         h.userID("pia"),
		ExpectPerm:      "writePage",
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	h.expectNoEvent(1500 * time.Millisecond)
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE body LIKE '%saved by the app%'`); n != 0 {
		t.Error("the watcher's own pass indexed the app's write, which is the double pass this suppresses")
	}

	// The save handler's own pass, which is what the suppression is deferring to.
	if _, err := h.ix.Index(ctx, "Page.md"); err != nil {
		t.Fatalf("index: %v", err)
	}
	// Settled, because that pass publishes too and the await below must not
	// collect its event instead of the hand edit's.
	h.settle()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE body LIKE '%saved by the app%'`); n != 1 {
		t.Error("the app's own pass did not index the save")
	}

	// And a hand edit is not suppressed: the bytes differ, so the hash differs.
	h.vault.WriteFile(t, "Page.md", "# Page\n\nan edit the app did not make\n")
	ev := h.awaitEvent(10 * time.Second)
	if ev.Path != "Page.md" || ev.Kind != ChangeUpdated {
		t.Fatalf("unexpected event %+v", ev)
	}
	if got := h.mustQueryString(
		`SELECT body FROM page_text WHERE page_id = ?`, h.pageID("Page.md")); !strings.Contains(got, "an edit") {
		t.Fatalf("the external edit was not indexed, body=%q", got)
	}
}

// TestSelfwriteIsAskedThroughTheReadPool asserts the property that keeps the
// watcher's check off the write connection: with the single write connection held
// by an in-flight index, the question must still be answered promptly.
func TestSelfwriteIsAskedThroughTheReadPool(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": "# Page\n"})
	sw := NewSelfwrites(h.db, h.log)
	sw.SetClock(h.now)
	ctx := context.Background()
	if err := sw.PutSelfwrite(ctx, "Page.md", vault.Hash([]byte("x")), h.now().Add(time.Minute)); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Hold the write connection for the duration of the check.
	tx, err := h.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	done := make(chan bool, 1)
	go func() {
		ok, err := sw.IsSelfwrite(ctx, "Page.md", vault.Hash([]byte("x")))
		if err != nil {
			t.Errorf("is: %v", err)
		}
		done <- ok
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("the answer was wrong")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the suppression check queued behind the write connection")
	}
}
