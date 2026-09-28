package sync

import (
	"context"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// TestRenameDetectionRequiresContentMatch is the boundary of §5.6: a rename is
// two events that were one event, and the only evidence strong enough to act on
// is that the bytes did not change.
//
// The three cases are the three ways a page can stop being at a path and start
// being at another: a move, a copy, and a move that happened long enough ago
// that it is a different event.
func TestRenameDetectionRequiresContentMatch(t *testing.T) {
	t.Parallel()
	const body = "# The Page\n\nThe same bytes, whichever name they answer to.\n"

	t.Run("a move with identical content is a rename", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, map[string]string{"Old Name.md": body})
		h.indexAll()
		h.drainEvents()

		h.vault.Rename(t, "Old Name.md", "New Name.md")
		res := h.reconcile()
		if len(res.Renames) != 1 {
			t.Fatalf("expected one rename, got %+v", res.Renames)
		}
		got := res.Renames[0]
		if got.From != "Old Name" || got.To != "New Name.md" || got.PageID != h.pageID("New Name.md") {
			t.Fatalf("unexpected rename %+v", got)
		}
		// The pass announces the deletion and then the fact that the new path is
		// the same page. The create and the rename share a key — one page — so a
		// subscriber that is already behind sees the last state rather than both.
		kinds := map[ChangeKind]bool{}
		for _, ev := range h.awaitQuiet(300*time.Millisecond, 10*time.Second) {
			kinds[ev.Kind] = true
		}
		if !kinds[ChangeDeleted] || !kinds[ChangeRenamed] {
			t.Fatalf("the pass announced %v, want a delete and a rename", kinds)
		}
	})

	t.Run("a copy is not a rename", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, map[string]string{"Original.md": body})
		h.indexAll()

		// The original stays and a copy appears. Nothing disappeared, so there is
		// nothing to pair.
		h.vault.WriteFile(t, "Copy.md", body)
		res := h.reconcile()
		if len(res.Renames) != 0 {
			t.Fatalf("a copy was treated as a rename: %+v", res.Renames)
		}
		if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = 'Copy.md'`); n != 1 {
			t.Fatal("the copy was not indexed as a page of its own")
		}
		if n := h.mustQueryInt(
			`SELECT COUNT(*) FROM page_aliases a JOIN pages p ON p.id = a.page_id
			 WHERE p.path = 'Copy.md' AND a.alias = 'Original'`); n != 0 {
			t.Error("a copy was given the original's name as an alias")
		}
	})

	t.Run("a delete and a different new page is not a rename", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, map[string]string{"Old Name.md": body})
		h.indexAll()

		// The file is replaced by a page with the same name and different
		// content: an edit that a sync client happened to express as delete plus
		// create. Nothing pairs, because the bytes are not the same.
		h.vault.Remove(t, "Old Name.md")
		h.vault.WriteFile(t, "Old Name.md", "# Different\n\nOther bytes entirely.\n")
		res := h.reconcile()
		if len(res.Renames) != 0 {
			t.Fatalf("different content was paired as a rename: %+v", res.Renames)
		}
	})

	t.Run("a move outside the window is not a rename", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, map[string]string{"Old Name.md": body})
		h.indexAll()
		h.drainEvents()

		// The file goes away and the deletion is seen.
		h.vault.Remove(t, "Old Name.md")
		if res := h.reconcile(); len(res.Renames) != 0 {
			t.Fatalf("a deletion was paired with nothing: %+v", res.Renames)
		}
		// The same bytes turn up under a new name an hour later: two events, not
		// one. Pairing them would mean acting on a coincidence.
		h.advance(DefaultRenameWindow + time.Second)
		h.vault.WriteFile(t, "New Name.md", body)
		res := h.reconcile()
		if len(res.Renames) != 0 {
			t.Fatalf("a move outside the window was paired: %+v", res.Renames)
		}
		if n := h.mustQueryInt(
			`SELECT COUNT(*) FROM page_aliases a JOIN pages p ON p.id = a.page_id
			 WHERE p.path = 'New Name.md'`); n != 0 {
			t.Error("an alias was recorded for a move outside the window")
		}
	})

	t.Run("both halves in one batch are a rename", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, map[string]string{"Old Name.md": body})
		h.indexAll()

		// A watcher batch carrying the deletion and the creation together, which
		// is the ordinary shape of a `mv` on a sync client.
		h.vault.Rename(t, "Old Name.md", "New Name.md")
		res, err := h.ix.IndexBatch(context.Background(), []string{"Old Name.md", "New Name.md"})
		if err != nil {
			t.Fatalf("index batch: %v", err)
		}
		if len(res.Renames) != 1 || res.Renames[0].From != "Old Name" {
			t.Fatalf("the batch did not detect the rename: %+v", res.Renames)
		}
	})
}

// TestAliasResolutionSurvivesARename asserts the reason a rename is recorded at
// all: every [[the old name]] in the vault keeps resolving to the page it always
// pointed at.
func TestAliasResolutionSurvivesARename(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Old Name.md":    "# Old Name\n\nThe body.\n",
		"Referrer.md":    "# Referrer\n\nSee [[Old Name]] and [[Old Name|the old page]].\n",
		"Third Party.md": "# Third\n\nNothing to see.\n",
	})
	h.indexAll()
	h.drainEvents()

	// Two renames of the same page, so the alias has to accumulate rather than
	// replace.
	h.vault.Rename(t, "Old Name.md", "Middle Name.md")
	h.reconcile()
	h.vault.Rename(t, "Middle Name.md", "New Name.md")
	h.reconcile()

	pageID := h.pageID("New Name.md")
	for _, alias := range []string{"Old Name", "Middle Name"} {
		pages, err := store.ListPagesByAlias(context.Background(), h.db.Reader(), alias)
		if err != nil {
			t.Fatalf("list pages by alias %s: %v", alias, err)
		}
		if len(pages) != 1 || pages[0].ID != pageID {
			t.Errorf("[[%s]] resolves to %+v, want the renamed page %d", alias, pages, pageID)
		}
	}
	// The referrer's own links are still pointing at the old name, which is
	// exactly the situation the alias exists for.
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT target_raw, COALESCE(alias, '') FROM links WHERE source_page_id = ? ORDER BY target_raw`,
		h.pageID("Referrer.md"))
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var raw, alias string
		if err := rows.Scan(&raw, &alias); err != nil {
			t.Fatalf("scan: %v", err)
		}
		targets = append(targets, raw+"|"+alias)
	}
	if len(targets) != 2 || targets[0] != "Old Name|" || targets[1] != "Old Name|the old page" {
		t.Fatalf("the referrer's links changed: %v", targets)
	}
	// And a frontmatter alias still works, because it is the same table.
	h.vault.WriteFile(t, "New Name.md", "---\naliases: [The New Name]\n---\n# Old Name\n\nThe body.\n")
	h.reconcile()
	pages, err := store.ListPagesByAlias(context.Background(), h.db.Reader(), "The New Name")
	if err != nil || len(pages) != 1 || pages[0].ID != pageID {
		t.Fatalf("a frontmatter alias did not resolve: %+v (%v)", pages, err)
	}
	// A reference written under the old name now points at the new row, so the
	// backlink panel does not go blank at the moment the file moved.
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.target_page_id
		 JOIN pages s ON s.id = l.source_page_id
		 WHERE s.path = 'Referrer.md' AND l.target_raw = 'Old Name' AND p.path = 'New Name.md'`); n != 2 {
		t.Errorf("the referrer's links under the old name point at %d pages, want 2", n)
	}
	// A frontmatter alias never removes the rename aliases, because the file
	// does not know about them. This is the documented cost of an add-only
	// alias set, and it is asserted so that changing it is a deliberate act.
	for _, alias := range []string{"Old Name", "Middle Name"} {
		pages, err := store.ListPagesByAlias(context.Background(), h.db.Reader(), alias)
		if err != nil || len(pages) != 1 {
			t.Errorf("re-indexing dropped the rename alias %s: %+v (%v)", alias, pages, err)
		}
	}
}

// TestADeletedPagesBacklinksDoNotSilentlyBlank asserts the other half: deleting a
// page sets its referrers' link targets to NULL, because the foreign key is ON
// DELETE SET NULL, and the pass re-links them so a link that can resolve again
// does.
func TestADeletedPagesBacklinksDoNotSilentlyBlank(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Hub.md":   "# Hub\n\nSee [[Spoke]] and [[Other]] and [[Ghost]].\n",
		"Spoke.md": "# Spoke\n\nA page.\n",
		"Other.md": "# Other\n\nAnother.\n",
		"Ghost.md": "# Ghost\n\nNot written yet.\n",
	})
	h.indexAll()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id IS NOT NULL`); n != 3 {
		t.Fatalf("all three links should resolve, %d do", n)
	}

	// The spoke is deleted, and nothing replaces it. The ghost is not part of this
	// test: a page that is deleted and stays deleted has to leave a dangling
	// link, and a re-link must not invent one.
	h.vault.Remove(t, "Spoke.md")
	h.reconcile()

	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages s ON s.id = l.source_page_id
		 WHERE s.path = 'Hub.md' AND l.target_raw = 'Spoke' AND l.target_page_id IS NULL`); n != 1 {
		t.Error("a link to a deleted page was re-pointed at something")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.target_page_id
		 JOIN pages s ON s.id = l.source_page_id
		 WHERE s.path = 'Hub.md' AND l.target_raw = 'Spoke'`); n != 0 {
		t.Error("a deleted page still has a backlink")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = 'Spoke.md'`); n != 0 {
		t.Error("the deleted page is still indexed")
	}
	// And a page re-created with the same name picks the reference up again,
	// because the deletion left the referrer on the list of pages to re-link.
	h.vault.WriteFile(t, "Spoke.md", "# Spoke\n\nWritten again.\n")
	h.reconcile()
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.target_page_id
		 JOIN pages s ON s.id = l.source_page_id
		 WHERE s.path = 'Hub.md' AND l.target_raw = 'Spoke' AND p.path = 'Spoke.md'`); n != 1 {
		t.Error("the reference to a page written again is still dangling")
	}
}

// TestRenameAcrossARestart asserts the boot case: the app was not running when
// the file moved, so the deletion was never observed as an event and the pair is
// reconstructed from the index.
//
// The window is what makes it possible at all — both rows are younger than it at
// boot — and a rename that happened while the app was down for a week is
// deliberately not detected, because the alternative is pairing two unrelated
// pages that happen to hold the same bytes.
func TestRenameAcrossARestart(t *testing.T) {
	t.Parallel()
	const body = "# The Page\n\nSome bytes.\n"
	h := newHarness(t, map[string]string{"Old Name.md": body})
	h.indexAll()

	h.vault.Rename(t, "Old Name.md", "New Name.md")
	// A restart: a new indexer over the same database, so the vanished side is
	// only a row and not an in-memory record.
	fresh := h.newIndexer()
	walk, err := fresh.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if _, err := fresh.IndexBatch(context.Background(), walk.Files); err != nil {
		t.Fatalf("index batch: %v", err)
	}
	if _, err := fresh.RemoveMissing(context.Background(), walk.Files); err != nil {
		t.Fatalf("remove missing: %v", err)
	}
	pages, err := store.ListPagesByAlias(context.Background(), h.db.Reader(), "Old Name")
	if err != nil {
		t.Fatalf("list by alias: %v", err)
	}
	if len(pages) != 1 || pages[0].Path != "New Name.md" {
		t.Fatalf("a rename across a restart left no alias: %+v", pages)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages`); n != 1 {
		t.Fatalf("the old page row survived, or the new one is missing: %d rows", n)
	}
}

// TestAMatchingNameResolvesTheLinkAndAddsNoAlias asserts the rule behind §5.6's
// warning: a new basename that matches a dangling reference resolves it, and
// nothing is auto-aliased.
//
// The two halves matter in opposite directions. Resolution is the correct answer
// for an exact name match, so the link works. Auto-aliasing would be the wrong
// answer for a name match alone, because a page called Notes.md would capture
// every broken [[Notes]] in the vault and a DM who mistyped one link would
// silently retarget another player's page. The only thing in this package that
// writes an alias is a content-hash match inside the rename window, and this test
// asserts that a new page with a dangling name in its history still gets none.
func TestAMatchingNameResolvesTheLinkAndAddsNoAlias(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Referrer.md": "# Referrer\n\nSee [[Later]] for the details.\n",
	})
	h.indexAll()
	h.drainEvents()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id IS NULL`); n != 1 {
		t.Fatalf("the link should be dangling before the page exists, %d are not", n)
	}

	h.vault.WriteFile(t, "Later.md", "# Later\n\nCompletely unrelated to the link.\n")
	res := h.reconcile()
	if len(res.Renames) != 0 {
		t.Fatalf("a name match was treated as a rename: %+v", res.Renames)
	}
	pageID := h.pageID("Later.md")
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.source_page_id
		 WHERE p.path = 'Referrer.md' AND l.target_page_id = ?`, pageID); n != 1 {
		t.Error("the link to a page that has since appeared is still dangling")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM page_aliases WHERE page_id = ?`, pageID); n != 0 {
		t.Error("a name match wrote an alias, which is the auto-alias the rule forbids")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages`); n != 2 {
		t.Errorf("expected two pages, got %d", n)
	}
}

// TestADanglingLinkInsideASecretIsRePointedWithoutBecomingVisible asserts the
// security consequence of re-pointing references.
//
// Re-pointing is not authorization: a reference inside a secret is resolved the
// same way as any other, because resolution is about names. What must not change
// is that the reference stays attached to its secret, so the canonical predicate
// still hides the fact that it exists from everyone who may not read the secret.
func TestADanglingLinkInsideASecretIsRePointedWithoutBecomingVisible(t *testing.T) {
	t.Parallel()
	const id = "abcabcabcabc"
	h := newHarness(t, map[string]string{
		"Public.md": "# Public\n\nSee [[Later]] openly.\n",
		"Veiled.md": "# Veiled\n\n```secret id=" + id + " visibility=dm author=dorn\nSee [[Later]] in here.\n```\n",
	})
	h.indexAll()
	h.drainEvents()

	h.vault.WriteFile(t, "Later.md", "# Later\n")
	h.reconcile()
	later := h.pageID("Later.md")
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE target_page_id = ? AND secret_id = ?`, later, id); n != 1 {
		t.Fatal("the link inside the secret was not re-pointed")
	}
	// A player may not see it, and the count agrees with the list.
	player := h.principal("pia")
	links, err := store.ListBacklinks(context.Background(), h.db.Reader(), player, later)
	if err != nil {
		t.Fatalf("backlinks: %v", err)
	}
	count, err := store.BacklinkCount(context.Background(), h.db.Reader(), player, later)
	if err != nil {
		t.Fatalf("backlink count: %v", err)
	}
	if len(links) != count {
		t.Fatalf("a panel would list %d backlinks and count %d", len(links), count)
	}
	for _, l := range links {
		if l.Page.Path == "Veiled.md" {
			t.Errorf("a backlink from inside a secret is visible to a player: %+v", l)
		}
	}
}

// TestRenameIsDetectedOnlyOnce asserts that a confirmed rename is not re-applied
// on the next pass, which would otherwise accumulate aliases for a page that has
// not moved since.
func TestRenameIsDetectedOnlyOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Old Name.md": "# Old Name\n\nBody.\n"})
	h.indexAll()
	h.vault.Rename(t, "Old Name.md", "New Name.md")
	first := h.reconcile()
	if len(first.Renames) != 1 {
		t.Fatalf("expected one rename, got %+v", first.Renames)
	}
	if again := h.reconcile(); len(again.Renames) != 0 {
		t.Fatalf("the rename was detected twice: %+v", again.Renames)
	}
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT alias, COUNT(*) FROM page_aliases GROUP BY alias`)
	if err != nil {
		t.Fatalf("aliases: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var alias string
		var n int
		if err := rows.Scan(&alias, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if n != 1 {
			t.Errorf("alias %s is stored %d times", alias, n)
		}
	}
}
