package sync

import (
	"context"
	"strings"
	"testing"
)

// TestAReferenceResolvesWhenItsTargetArrives asserts the property that makes a
// vault of forward references work: a link written before the page it names
// starts working the moment that page appears, without the DM touching the file
// again.
//
// This is a product rule rather than an optimisation. A DM who writes "See
// [[The Mayor]]" before writing The Mayor would otherwise never see the
// backlink, and never know the link was broken.
func TestAReferenceResolvesWhenItsTargetArrives(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Note.md":    "# Note\n\nSee [[The Mayor]] and [[The Tavern]].\n",
		"Watched.md": "# Watched\n\n```secret id=abcabcabcabc visibility=dm author=dorn\nSee [[The Mayor]] too.\n```\n",
	})
	h.indexAll()
	h.settle()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id IS NULL`); n != 3 {
		t.Fatalf("expected three dangling references, got %d", n)
	}

	// The mayor arrives. Her link resolves; the tavern's does not, because the
	// tavern is still a name and not a page.
	h.vault.WriteFile(t, "The Mayor.md", "# The Mayor\n")
	h.reconcile()
	mayor := h.pageID("The Mayor.md")
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id = ?`, mayor); n != 2 {
		t.Fatalf("the mayor's page has %d backlinks, want 2", n)
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE target_page_id IS NULL AND target_raw = ?`, "The Tavern"); n != 1 {
		t.Error("a link to a page that does not exist was resolved")
	}

	// And the tavern arriving resolves the last one, in a later pass.
	h.vault.WriteFile(t, "The Tavern.md", "# The Tavern\n")
	h.reconcile()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id IS NULL`); n != 0 {
		t.Fatalf("%d references are still dangling", n)
	}
	// Every resolution is announced, so a panel showing backlinks updates.
	kinds := 0
	for _, ev := range h.settle() {
		if ev.Kind == ChangeUpdated {
			kinds++
		}
	}
	if kinds == 0 {
		t.Error("re-pointing a reference announced nothing")
	}
}

// TestTheUnresolvedReferenceIndexIsBounded asserts the bound, and that exceeding
// it forgets the oldest name rather than growing without limit.
//
// Forgetting costs a re-link the next time that name is written; it never costs a
// wrong answer, because a forgotten reference is simply left unresolved. The bound
// is what stops a vault full of typos from accumulating a promise for ever.
func TestTheUnresolvedReferenceIndexIsBounded(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	small, err := New(Options{
		DB: h.db, Root: h.vault.Root, Log: h.log, Clock: h.now,
		DanglingCapacity: 4,
	})
	if err != nil {
		t.Fatalf("indexer: %v", err)
	}
	var body strings.Builder
	body.WriteString("# Ref\n\n")
	for _, name := range []string{"Aaa", "Bbb", "Ccc", "Ddd", "Eee", "Fff"} {
		body.WriteString("See [[" + name + "]].\n\n")
	}
	h.vault.WriteFile(t, "Ref.md", body.String())
	if _, err := small.IndexBatch(context.Background(), []string{"Ref.md"}); err != nil {
		t.Fatalf("index: %v", err)
	}
	small.mu.Lock()
	size := len(small.dangling)
	_, keptAaa := small.dangling["aaa"]
	_, keptFff := small.dangling["fff"]
	small.mu.Unlock()
	if size != 4 {
		t.Errorf("the unresolved index holds %d names, want the capacity of 4", size)
	}
	if keptAaa {
		t.Error("the oldest name was kept")
	}
	if !keptFff {
		t.Error("the newest name was evicted")
	}
	// The cost of forgetting, which is only observable on its own: a name the
	// index has forgotten is not re-pointed when it arrives.
	h.vault.WriteFile(t, "Aaa.md", "# Aaa\n")
	if _, err := small.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE target_page_id IS NOT NULL AND target_raw = ?`, "Aaa"); n != 0 {
		t.Error("a forgotten reference was re-pointed, so the bound was not a bound")
	}
	// And the cost is one reference, not a broken page: the next re-link of the
	// referring page resolves everything, forgotten or not, because it rewrites
	// all of that page's links against the index as it now stands.
	h.vault.WriteFile(t, "Fff.md", "# Fff\n")
	if _, err := small.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, name := range []string{"Aaa", "Fff"} {
		if n := h.mustQueryInt(
			`SELECT COUNT(*) FROM links WHERE target_page_id IS NOT NULL AND target_raw = ?`, name); n != 1 {
			t.Errorf("the reference to %s is still dangling after a re-link", name)
		}
	}
}

// TestAFenceThatCannotBeIndexedIsReportedAndSkipped asserts the last fail-safe
// in the chain: a fence whose metadata could not be read produces a problem and
// no row, rather than a row with an empty id that every other fence collides
// with.
func TestAFenceThatCannotBeIndexedIsReportedAndSkipped(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Page.md": "# Page\n\n```secret visibility=dm author=dorn\nNo id at all.\n```\n",
	})
	res := h.indexAll()
	// md substitutes a placeholder id, so the fence is still redacted and the page
	// still indexes; the point is that nothing invalid reaches the secrets table.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 0 {
		t.Errorf("a fence with no id was indexed: %+v", allProblems(res))
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text`); n != 0 {
		t.Error("a dm secret reached the search index")
	}
	var found bool
	for _, p := range allProblems(res) {
		if p.Code == ProblemUnusableFence {
			found = true
		}
	}
	if !found {
		t.Errorf("no unusable-fence problem was reported: %+v", allProblems(res))
	}
}
