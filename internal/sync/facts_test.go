package sync

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// TestEveryFactCarriesTheSecretItCameFrom is the attribution test.
//
// §5.4 requires every extracted fact to carry the md.Span it came from, and the
// reason is not tidiness: a link, a heading or a tag written inside a secret is
// a fact about that secret, and a consumer that cannot tell the difference shows
// a player the existence of a chapter they may not read. The rows exist with the
// right secret_id here, and store's canonical predicate drops them for everyone
// who may not see the secret.
func TestEveryFactCarriesTheSecretItCameFrom(t *testing.T) {
	t.Parallel()
	const id = "123456789abc"
	h := newHarness(t, map[string]string{
		"Facts.md": "# Facts\n\nPublic #pub with [[Target]].\n\n" +
			secretFence(id, "dm", "dorn",
				"## Inside\n\nA link to [[Other Page]], a #hidetag and a [[Target]] too.") +
			"\n## Outside\n\nA #pub again.\n",
		"Target.md":     "# Target\n",
		"Other Page.md": "# Other Page\n",
	})
	h.indexAll()
	pageID := h.pageID("Facts.md")

	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT COALESCE(secret_id, ''), target_raw, kind FROM links WHERE source_page_id = ? ORDER BY id`,
		pageID)
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	defer rows.Close()
	type linkRow struct{ secret, raw, kind string }
	var links []linkRow
	for rows.Next() {
		var l linkRow
		if err := rows.Scan(&l.secret, &l.raw, &l.kind); err != nil {
			t.Fatalf("scan link: %v", err)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("links: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("expected three links, got %+v", links)
	}
	wantSecrets := map[string]int{"": 1, id: 2}
	for _, l := range links {
		wantSecrets[l.secret]--
		if l.kind != "wikilink" {
			t.Errorf("link %q has kind %q", l.raw, l.kind)
		}
	}
	for secret, missing := range wantSecrets {
		if missing != 0 {
			t.Errorf("%d links are missing secret id %q", missing, secret)
		}
	}

	// Headings.
	hrows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT text, COALESCE(secret_id, '') FROM headings WHERE page_id = ? ORDER BY ordinal`, pageID)
	if err != nil {
		t.Fatalf("headings: %v", err)
	}
	defer hrows.Close()
	headings := map[string]string{}
	for hrows.Next() {
		var text, secret string
		if err := hrows.Scan(&text, &secret); err != nil {
			t.Fatalf("scan heading: %v", err)
		}
		headings[text] = secret
	}
	if err := hrows.Err(); err != nil {
		t.Fatalf("headings: %v", err)
	}
	if headings["Inside"] != id {
		t.Errorf("the heading inside the fence is attributed to %q", headings["Inside"])
	}
	if headings["Outside"] != "" || headings["Facts"] != "" {
		t.Errorf("a public heading was attributed to a secret: %v", headings)
	}

	// Tags, by source.
	trows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT tag, source, secret_id FROM page_tags WHERE page_id = ? ORDER BY tag`, pageID)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	defer trows.Close()
	type tagRow struct{ tag, source, secret string }
	var tags []tagRow
	for trows.Next() {
		var tr tagRow
		if err := trows.Scan(&tr.tag, &tr.source, &tr.secret); err != nil {
			t.Fatalf("scan tag: %v", err)
		}
		tags = append(tags, tr)
	}
	if err := trows.Err(); err != nil {
		t.Fatalf("tags: %v", err)
	}
	// The same tag used publicly and inside a secret is two rows, because a
	// predicate needs a secret row to evaluate and one row cannot say both.
	var pub, hid int
	for _, tr := range tags {
		if tr.tag != "pub" {
			continue
		}
		if tr.source != "inline" {
			t.Errorf("an inline tag has source %q", tr.source)
		}
		if tr.secret == "" {
			pub++
		}
	}
	for _, tr := range tags {
		if tr.tag == "hidetag" && tr.secret == id {
			hid++
		}
	}
	if pub != 1 || hid != 1 {
		t.Errorf("the public use of a tag is stored %d times and the hidden one %d times", pub, hid)
	}
}

// TestFrontmatterTagsAreDistinguishedFromInlineOnes asserts the source
// discriminator, since page_tags.source is a CHECK column and a wrong value is a
// silent misattribution rather than an error.
func TestFrontmatterTagsAreDistinguishedFromInlineOnes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Tagged.md": "---\ntags: [fromfm, also-fm]\ntag: single\n---\n# Tagged\n\nAn #inline one.\n",
	})
	h.indexAll()
	pageID := h.pageID("Tagged.md")
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT tag, source FROM page_tags WHERE page_id = ? ORDER BY tag`, pageID)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var tag, source string
		if err := rows.Scan(&tag, &source); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[tag] = source
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("tags: %v", err)
	}
	for _, tag := range []string{"fromfm", "also-fm", "single"} {
		if got[tag] != "frontmatter" {
			t.Errorf("tag %q has source %q, want frontmatter", tag, got[tag])
		}
	}
	if got["inline"] != "inline" {
		t.Errorf("tag inline has source %q, want inline", got["inline"])
	}
	// And every tag exists in the tags table, or the foreign key would have
	// rejected the row and the tag would be invisible rather than wrong.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM tags`); n != int64(len(got)) {
		t.Errorf("the tags table holds %d rows for %d page_tags rows", n, len(got))
	}
}

// TestAPageTitleIsNeverAHeadingInsideASecret asserts the one place md's
// convenience would have leaked: page_text.title is indexed with weight 10, so a
// secret's first heading there would be the highest-weighted term in the whole
// search index.
func TestAPageTitleIsNeverAHeadingInsideASecret(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Sealed.md": "```secret id=abcabcabcabc visibility=table author=dorn\n# The Underpaid Guard\n\nA name nobody may search for.\n```\n",
	})
	h.indexAll()
	pageID := h.pageID("Sealed.md")
	if got := h.mustQueryString(`SELECT title FROM page_text WHERE page_id = ?`, pageID); got != "Sealed" {
		t.Errorf("the page title is %q, want the basename", got)
	}
	if got := h.mustQueryString(`SELECT title FROM pages WHERE id = ?`, pageID); got != "Sealed" {
		t.Errorf("the page row's title is %q, want the basename", got)
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM page_text WHERE page_id = ? AND (title || headings || body) LIKE ?`,
		pageID, "%underpaid%"); n != 0 {
		t.Error("the secret's heading is in the public text")
	}
	// With a public H1 the title is the heading, which is the whole point of
	// the convention.
	h.vault.WriteFile(t, "Sealed.md", "# A Public Title\n\n```secret id=abcabcabcabc visibility=table author=dorn\n# The Underpaid Guard\n\nA name nobody may search for.\n```\n")
	h.reconcile()
	if got := h.mustQueryString(`SELECT title FROM page_text WHERE page_id = ?`, pageID); got != "A Public Title" {
		t.Errorf("the page title is %q, want the first public heading", got)
	}
}

// TestFrontmatterTitleWinsOverTheBasename asserts the fallback order.
func TestFrontmatterTitleWinsOverTheBasename(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"file-name.md": "---\ntitle: A Better Name\n---\nNo headings here.\n",
		"plain.md":     "Just text.\n",
	})
	h.indexAll()
	if got := h.mustQueryString(`SELECT title FROM pages WHERE path = 'file-name.md'`); got != "A Better Name" {
		t.Errorf("the frontmatter title was not used: %q", got)
	}
	if got := h.mustQueryString(`SELECT title FROM pages WHERE path = 'plain.md'`); got != "plain" {
		t.Errorf("the basename was not the fallback: %q", got)
	}
}

// TestASelfLinkResolvesToItsOwnPage asserts that [[#heading]] is not left
// dangling, which is what a section link is.
func TestASelfLinkResolvesToItsOwnPage(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Sections.md": "# Sections\n\nJump to [[#Later]].\n\n## Later\n\nText.\n",
	})
	h.indexAll()
	pageID := h.pageID("Sections.md")
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND target_page_id = ? AND heading = ?`,
		pageID, pageID, "Later"); n != 1 {
		t.Errorf("the self-link does not resolve to its own page")
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND target_page_id IS NULL`,
		pageID); n != 0 {
		t.Error("a self-link was left dangling")
	}
}

// TestLinksResolveByBasenameThenByAlias asserts §5.6's resolution order, and that
// a path-shaped target resolves to the page it names.
func TestLinksResolveByBasenameThenByAlias(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Campaign.md":       "---\n---\n# Campaign\n\n[[Gundren]] [[folder/Gundren]] [[folder/Gundren.md]]\n",
		"folder/Gundren.md": "---\naliases: [The Dwarf]\n---\n# Gundren\n\nBody.\n",
		"NPCs/The Dwarf.md": "# The Dwarf\n\nA different page.\n",
		"Ref.md":            "# Ref\n\n[[The Dwarf]]\n",
	})
	h.indexAll()
	campaign := h.pageID("Campaign.md")
	gundren := h.pageID("folder/Gundren.md")
	dwarfPage := h.pageID("NPCs/The Dwarf.md")
	for _, raw := range []string{"Gundren", "folder/Gundren", "folder/Gundren.md"} {
		var target int64
		if err := h.db.Reader().QueryRowContext(context.Background(),
			`SELECT COALESCE(target_page_id, 0) FROM links WHERE source_page_id = ? AND target_raw = ?`,
			campaign, raw).Scan(&target); err != nil {
			t.Fatalf("link %s: %v", raw, err)
		}
		if target != gundren {
			t.Errorf("[[%s]] resolved to %d, want %d", raw, target, gundren)
		}
	}
	// An alias resolves, but a page that still calls itself that wins over it.
	ref := h.pageID("Ref.md")
	var target int64
	if err := h.db.Reader().QueryRowContext(context.Background(),
		`SELECT COALESCE(target_page_id, 0) FROM links WHERE source_page_id = ?`, ref).Scan(&target); err != nil {
		t.Fatalf("ref link: %v", err)
	}
	if target != dwarfPage {
		t.Errorf("[[The Dwarf]] resolved to %d, want the page that is named that (%d)", target, dwarfPage)
	}
	// A dangling link is listed as unresolved rather than guessed at.
	unresolved, err := store.ListUnresolvedLinks(context.Background(), h.db.Reader())
	if err != nil {
		t.Fatalf("unresolved: %v", err)
	}
	for _, l := range unresolved {
		if l.TargetRaw == "Gundren" {
			t.Errorf("a resolved link is listed as unresolved: %+v", l)
		}
	}
}

// TestAmbiguousBasenamePrefersTheShortestPath asserts the tie-break, which is
// what makes resolution deterministic rather than dependent on insertion order.
func TestAmbiguousBasenamePrefersTheShortestPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Ref.md":               "# Ref\n\n[[Notes]]\n",
		"a/very/deep/Notes.md": "# Notes\n\nDeep.\n",
		"Notes.md":             "# Notes\n\nShallow.\n",
	})
	h.indexAll()
	ref := h.pageID("Ref.md")
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.target_page_id
		 WHERE l.source_page_id = ? AND p.path = 'Notes.md'`, ref); n != 1 {
		t.Error("the shortest path did not win the tie")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.target_page_id
		 WHERE l.source_page_id = ? AND p.path = 'a/very/deep/Notes.md'`, ref); n != 0 {
		t.Error("the longer path won the tie")
	}
}

// TestRevisionsAreAppendedForEveryChangeAndPruned asserts the history: one row
// per change, with the source that says who made it, and the retention buckets
// applied.
func TestRevisionsAreAppendedForEveryChangeAndPruned(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Hist.md": "# Hist\n\nv1\n"})
	h.indexAll()
	if n, err := store.ListRevisionsByPage(context.Background(), h.db.Reader(), h.pageID("Hist.md"), 100); err != nil {
		t.Fatalf("revisions: %v", err)
	} else if len(n) != 1 || n[0].Source != store.RevisionCreate {
		t.Fatalf("the first sighting is %+v, want one create revision", n)
	}
	for i := range 3 {
		h.vault.WriteFile(t, "Hist.md", "# Hist\n\nv"+string(rune('2'+i))+"\n")
		h.reconcile()
	}
	revs, err := store.ListRevisionsByPage(context.Background(), h.db.Reader(), h.pageID("Hist.md"), 100)
	if err != nil {
		t.Fatalf("revisions: %v", err)
	}
	if len(revs) != 4 {
		t.Fatalf("expected four revisions, got %d", len(revs))
	}
	// The newest first, so the last entry is the first sighting of the page and
	// is the one the app is responsible for.
	for _, r := range revs[:len(revs)-1] {
		if r.Source != store.RevisionExternal {
			t.Errorf("a change the app did not make is recorded as %q", r.Source)
		}
		if !strings.Contains(r.Content, "v") {
			t.Errorf("a revision has no content: %q", r.Content)
		}
	}
	if revs[len(revs)-1].Source != store.RevisionCreate {
		t.Errorf("the first sighting is recorded as %q", revs[len(revs)-1].Source)
	}
	// The newest revision is the current bytes.
	if !strings.Contains(revs[0].Content, "v4") {
		t.Errorf("the newest revision is %q", revs[0].Content)
	}
	// Retention: fifty app revisions and five external ones per page.
	for i := range 60 {
		h.vault.WriteFile(t, "Hist.md", "# Hist\n\nbulk "+strings.Repeat("x", i)+"\n")
		h.reconcile()
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM revisions`); n > 55 {
		t.Fatalf("retention kept %d revisions, want at most 55", n)
	}
}

// TestLastChangeAtIsAdvanced asserts the timestamp the backup policy reads.
//
// It is read with MetaGet and ParseTime rather than MetaGetInt, because the value
// is an RFC 3339 timestamp even though meta.go lists the key among the integers.
func TestLastChangeAtIsAdvanced(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"A.md": "# A\n"})
	read := func() time.Time {
		t.Helper()
		raw, err := store.MetaGet(context.Background(), h.db.Reader(), store.KeyLastChangeAt)
		if err != nil {
			t.Fatalf("last_change_at: %v", err)
		}
		at, err := store.ParseTime(raw)
		if err != nil {
			t.Fatalf("last_change_at %q: %v", raw, err)
		}
		return at
	}
	if _, err := store.MetaGet(context.Background(), h.db.Reader(), store.KeyLastChangeAt); !isNoRows(err) {
		t.Fatalf("last_change_at exists before anything was indexed: %v", err)
	}
	h.indexAll()
	first := read()
	if time.Since(first) > time.Hour {
		t.Fatalf("last_change_at is %s, which is not a recent file", first)
	}
	// A file with an older mtime — a vault restored from a backup — must not
	// rewind it.
	h.vault.WriteFile(t, "Old.md", "# Old\n")
	past := time.Now().Add(-72 * time.Hour)
	old := vault.New(h.vault.Root, "Old.md")
	if err := os.Chtimes(old.Abs(), past, past); err != nil {
		t.Skipf("cannot set an mtime on this filesystem: %v", err)
	}
	h.reconcile()
	if second := read(); second.Before(first) {
		t.Errorf("last_change_at moved backwards: %s then %s", first, second)
	}
}

func isNoRows(err error) bool { return errors.Is(err, store.ErrNoRows) }

// TestPageTypeComesFromFrontmatterAndSystemFromTheResolver asserts the two
// columns that belong to a plugin boundary.
func TestPageTypeComesFromFrontmatterAndSystemFromTheResolver(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Character.md": "---\ntype: character\n---\n# Character\n",
		"Plain.md":     "# Plain\n",
	})
	// A resolver that claims one page type, which is the shape the plugin
	// registry will take at boot.
	ix, err := New(Options{
		DB: h.db, Root: h.vault.Root, Log: h.log, Clock: h.now,
		ResolveSystem: func(pageType string) (string, bool) {
			if pageType == "character" {
				return "dnd5e", true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatalf("new indexer: %v", err)
	}
	if _, err := ix.IndexBatch(context.Background(), []string{"Character.md", "Plain.md"}); err != nil {
		t.Fatalf("index: %v", err)
	}
	if got := h.mustQueryString(`SELECT page_type FROM pages WHERE path = 'Character.md'`); got != "character" {
		t.Errorf("page_type is %q", got)
	}
	if got := h.mustQueryString(`SELECT COALESCE(system_id, '') FROM pages WHERE path = 'Character.md'`); got != "dnd5e" {
		t.Errorf("system_id is %q, want dnd5e", got)
	}
	if got := h.mustQueryString(`SELECT page_type FROM pages WHERE path = 'Plain.md'`); got != "note" {
		t.Errorf("a page with no type is %q, want note", got)
	}
	if got := h.mustQueryString(`SELECT COALESCE(system_id, '') FROM pages WHERE path = 'Plain.md'`); got != "" {
		t.Errorf("a core page has system_id %q", got)
	}
}

// TestFrontmatterIsStoredVerbatim asserts the raw YAML is kept byte for byte,
// because the file is canonical and a normalised copy is a second source of
// truth.
func TestFrontmatterIsStoredVerbatim(t *testing.T) {
	t.Parallel()
	const front = "title: Spacing Matters   \ntags:\n  - one\n  - two\n# a comment\nnested:\n  key: value\n"
	h := newHarness(t, map[string]string{
		"Raw.md": "---\n" + front + "---\n# Raw\n",
	})
	h.indexAll()
	if got := h.mustQueryString(`SELECT frontmatter FROM pages WHERE path = 'Raw.md'`); got != front {
		t.Errorf("the stored frontmatter is %q, want %q", got, front)
	}
}

// TestFrontmatterAliasesAreIndexedAndResolve asserts the alias table's normal
// use, separate from the rename case.
func TestFrontmatterAliasesAreIndexedAndResolve(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"NPC.md": "---\naliases: [Gundren the Bold, The Dwarf]\n---\n# NPC\n",
		"Ref.md": "# Ref\n\nSee [[Gundren the Bold]].\n",
	})
	h.indexAll()
	pageID := h.pageID("NPC.md")
	for _, alias := range []string{"Gundren the Bold", "The Dwarf"} {
		pages, err := store.ListPagesByAlias(context.Background(), h.db.Reader(), alias)
		if err != nil || len(pages) != 1 || pages[0].ID != pageID {
			t.Errorf("alias %q resolves to %+v (%v)", alias, pages, err)
		}
	}
	// A link written before its target was indexed is re-pointed at the end of
	// the pass that created the target, which is the paste-twenty-notes case.
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.source_page_id
		 WHERE p.path = 'Ref.md' AND l.target_page_id IS NULL`); n != 0 {
		t.Error("the link to a page created in the same pass stayed dangling")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages s ON s.id = l.target_page_id
		 JOIN pages p ON p.id = l.source_page_id
		 WHERE p.path = 'Ref.md' AND s.path = 'NPC.md'`); n != 1 {
		t.Error("the link to an alias did not resolve to the aliased page")
	}
	// A page created in a *later* pass does not re-point a link in a page that
	// is already indexed, because nothing changes for that page and its hash
	// still matches. Closing that needs a store-side updater for
	// links.target_page_id, which does not exist; the test names the gap rather
	// than pretending it is handled.
	h.vault.WriteFile(t, "Later.md", "---\naliases: [The Late One]\n---\n# Later\n")
	h.reconcile()
	before := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.source_page_id
		 WHERE p.path = 'Ref.md' AND l.target_raw = 'The Late One' AND l.target_page_id IS NOT NULL`)
	if before != 0 {
		t.Skip("a bulk link updater exists, so the late-arrival gap is closed; update this test")
	}
	// Editing the referrer resolves it, because the referrer is re-indexed.
	h.vault.WriteFile(t, "Ref.md", "# Ref\n\nSee [[Gundren the Bold]] and [[The Late One]].\n")
	h.reconcile()
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM links l JOIN pages p ON p.id = l.source_page_id
		 WHERE p.path = 'Ref.md' AND l.target_page_id IS NULL`); n != 0 {
		t.Error("re-indexing the referrer did not resolve the late alias link")
	}
}

// TestReindexIsTheSeamSecretsCalls asserts the one method the secret write path
// depends on, from this side.
//
// internal/secrets cannot import this package — sync sits above it — so it
// declares a Reindexer interface that the indexer satisfies structurally. If this
// method's signature drifts, internal/secrets stops compiling, which is the point
// of declaring the seam there rather than here.
func TestReindexIsTheSeamSecretsCalls(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{"Page.md": "# Page\n\n[[Later]]\n"})
	h.indexAll()
	h.vault.WriteFile(t, "Later.md", "# Later\n")
	// The file is on disk and the index does not know, which is the state a
	// reveal leaves the page in before the service re-derives it.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM links WHERE target_page_id IS NOT NULL`); n != 0 {
		t.Fatal("the index already knows about a file the pass never saw")
	}
	if err := h.ix.Reindex(context.Background(), "Page.md"); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	// Reindex reads the file it is given, not the one that changed, so the link
	// is still unresolved — but the page's own bytes are current, which is what
	// the secret write path needs.
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM page_text WHERE page_id = ? AND body LIKE '%Later%'`, h.pageID("Page.md")); n != 1 {
		t.Error("reindex did not re-derive the page it was given")
	}
	var seam interface {
		Reindex(ctx context.Context, path string) error
	} = h.ix
	if err := seam.Reindex(context.Background(), "Page.md"); err != nil {
		t.Fatalf("reindex through the seam shape: %v", err)
	}
}

// TestEveryLinkKindIsClassified asserts the five kinds md can report all reach
// the index under store's name, because the column is a CHECK-constrained enum
// and a translation table that silently drops one kind loses the fact entirely.
func TestEveryLinkKindIsClassified(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Kinds.md": "# Kinds\n\n" +
			"A [[Page]] wikilink, an ![[Page]] embed, a [text](Page.md) markdown link, " +
			"an ![alt](picture.png) image and a #topic tag.\n",
		"Page.md":     "# Page\n",
		"picture.png": "not really an image\n",
	})
	h.indexAll()
	pageID := h.pageID("Kinds.md")
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT kind, target_raw FROM links WHERE source_page_id = ?`, pageID)
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	defer rows.Close()
	kinds := map[string]int{}
	for rows.Next() {
		var kind, raw string
		if err := rows.Scan(&kind, &raw); err != nil {
			t.Fatalf("scan: %v", err)
		}
		kinds[kind]++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("links: %v", err)
	}
	for kind, want := range map[string]int{
		"wikilink":   1,
		"embed":      1,
		"markdown":   1,
		"attachment": 1,
	} {
		if kinds[kind] != want {
			t.Errorf("%d links of kind %s, want %d (%v)", kinds[kind], kind, want, kinds)
		}
	}
	// A tag is a tag, not a link: it lives in page_tags with its source, and the
	// count above is of the links table.
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM page_tags WHERE page_id = ? AND tag = ? AND source = ?`,
		pageID, "topic", "inline"); n != 1 {
		t.Errorf("the inline tag is not in page_tags: %v", kinds)
	}
}
