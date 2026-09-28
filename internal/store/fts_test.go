package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// ftsFixture indexes one page of public text and three secrets, one per
// visibility, so that both FTS tables and the invariant between them are
// exercised together.
type ftsFixture struct {
	db        *DB
	alice     int64
	dm        int64
	pageID    int64
	secretIDs map[authz.Visibility]string
}

func newFTSFixture(t *testing.T) *ftsFixture {
	t.Helper()
	ctx := context.Background()
	db := newMigratedDB(t)
	f := &ftsFixture{db: db, secretIDs: map[authz.Visibility]string{}}

	f.dm = seedUser(t, db.Writer(), "dm", "dm")
	f.alice = seedUser(t, db.Writer(), "alice", "player")
	f.pageID = seedPage(t, db.Writer(), "Vault.md", "The Sunken Vault")

	if err := ReplacePageText(ctx, db.Writer(), PageText{
		PageID:   f.pageID,
		Title:    "The Sunken Vault",
		Headings: "Traps",
		Body:     "The vault door is warded. Opening it deals 3d6 necrotic damage.",
	}); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1750000000, 0).UTC()
	for i, vis := range []authz.Visibility{authz.VisibilityDM, authz.VisibilityPrivate, authz.VisibilityTable} {
		id := "s" + itoa(i)
		f.secretIDs[vis] = id
		if err := InsertSecret(ctx, db.Writer(), Secret{
			ID: id, PageID: f.pageID, Ordinal: i, Visibility: vis, AuthorID: f.alice,
			Body: "warded by a " + string(vis) + " sentinel", BodyHash: []byte(id),
			CreatedAt: at, UpdatedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// matchCount runs a raw MATCH against page_fts. The tests below use it instead
// of the search package so that store's FTS maintenance is verified on its own,
// without search's normalisation standing between the test and the index.
func matchCount(t *testing.T, db *DB, match string) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, match).Scan(&n); err != nil {
		t.Fatalf("page_fts MATCH %q: %v", match, err)
	}
	return n
}

func matchSecretCount(t *testing.T, db *DB, match string) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, match).Scan(&n); err != nil {
		t.Fatalf("secret_fts MATCH %q: %v", match, err)
	}
	return n
}

func TestReplacePageTextKeepsTheIndexHonest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	if got := matchCount(t, db, `"warded"`); got != 1 {
		t.Fatalf("after the first write, %d rows match, want 1", got)
	}
	// Replace the text and check the old terms are gone. A 'delete' skipped here
	// leaves stale terms that surface as hits on a page that no longer contains
	// the word.
	if err := ReplacePageText(ctx, db.Writer(), PageText{
		PageID: f.pageID, Title: "The Sunken Vault", Headings: "Consequences",
		Body: "The vault collapses without trace.",
	}); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"warded"`); got != 0 {
		t.Errorf("%d rows still match the replaced-away term, want 0", got)
	}
	if got := matchCount(t, db, `"collapses"`); got != 1 {
		t.Errorf("%d rows match the new term, want 1", got)
	}
	assertFTSIntegrity(t, db)

	// Writing the same content twice must not double-index or fail.
	if err := ReplacePageText(ctx, db.Writer(), PageText{
		PageID: f.pageID, Title: "The Sunken Vault", Headings: "Consequences",
		Body: "The vault collapses without trace.",
	}); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"collapses"`); got != 1 {
		t.Errorf("%d rows match after an identical rewrite, want 1", got)
	}
	assertFTSIntegrity(t, db)
}

func TestDeletePageTextRemovesTheRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	if err := DeletePageText(ctx, db.Writer(), f.pageID); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"warded"`); got != 0 {
		t.Errorf("%d index rows survive deleting the text, want 0", got)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM page_text`); got != 0 {
		t.Errorf("page_text rows = %d, want 0", got)
	}
	// Deleting again is a no-op, not an error: the indexer may not know whether
	// a page ever had text.
	if err := DeletePageText(ctx, db.Writer(), f.pageID); err != nil {
		t.Errorf("second delete: %v", err)
	}
	assertFTSIntegrity(t, db)

	// A cascade on the page does not reach the index, which is why DeletePage
	// removes the text first.
	if err := ReplacePageText(ctx, db.Writer(), PageText{
		PageID: f.pageID, Title: "T", Headings: "H", Body: "cascade probe token",
	}); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"cascade"`); got != 1 {
		t.Fatalf("setup failed: %d rows match", got)
	}
	if err := DeletePage(ctx, db.Writer(), f.pageID); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"cascade"`); got != 0 {
		t.Errorf("%d index rows survive DeletePage, want 0", got)
	}
	assertFTSIntegrity(t, db)
}

func TestSecretIndexHoldsOnlyTableSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	// Every attempt to index a hidden secret is refused.
	for _, vis := range []authz.Visibility{authz.VisibilityDM, authz.VisibilityPrivate} {
		err := IndexSecretText(ctx, db.Writer(), f.secretIDs[vis], vis, "warded by a sentinel")
		if !errors.Is(err, ErrSecretNotIndexable) {
			t.Errorf("indexing a %s secret returned %v, want ErrSecretNotIndexable", vis, err)
		}
	}
	if got := matchSecretCount(t, db, `"sentinel"`); got != 0 {
		t.Errorf("secret_fts holds %d rows after two refused inserts, want 0", got)
	}

	// The revealed one indexes, and only its text is findable.
	if err := IndexSecretText(ctx, db.Writer(), f.secretIDs[authz.VisibilityTable],
		authz.VisibilityTable, "warded by a table sentinel"); err != nil {
		t.Fatal(err)
	}
	if got := matchSecretCount(t, db, `"sentinel"`); got != 1 {
		t.Errorf("secret_fts rows = %d after indexing a table secret, want 1", got)
	}
	if n, err := CheckSecretIndexInvariant(ctx, db.Writer()); err != nil || n != 0 {
		t.Errorf("invariant reports %d violations (err %v), want 0", n, err)
	}
	assertFTSIntegrity(t, db)

	// Replacing the body must not leave the old terms behind.
	if err := IndexSecretText(ctx, db.Writer(), f.secretIDs[authz.VisibilityTable],
		authz.VisibilityTable, "bound by brass wards"); err != nil {
		t.Fatal(err)
	}
	if got := matchSecretCount(t, db, `"sentinel"`); got != 0 {
		t.Errorf("%d rows still match the replaced-away term, want 0", got)
	}
	if got := matchSecretCount(t, db, `"bound"`); got != 1 {
		t.Errorf("%d rows match the new term, want 1", got)
	}
	assertFTSIntegrity(t, db)

	// A revoke makes it unsearchable immediately.
	if err := DeleteSecretText(ctx, db.Writer(), f.secretIDs[authz.VisibilityTable]); err != nil {
		t.Fatal(err)
	}
	if got := matchSecretCount(t, db, `"bound"`); got != 0 {
		t.Errorf("%d rows survive a revoke, want 0", got)
	}
	if n := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM secret_text`); n != 0 {
		t.Errorf("secret_text rows = %d after a revoke, want 0", n)
	}
}

func TestRebuildSecretFTSOnlyIndexesTableSecrets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	// Index everything by hand so that the rebuild has a wrong index to fix.
	for _, vis := range []authz.Visibility{authz.VisibilityTable} {
		if err := IndexSecretText(ctx, db.Writer(), f.secretIDs[vis], vis, "warded by a sentinel"); err != nil {
			t.Fatal(err)
		}
	}
	if err := RebuildSecretFTS(ctx, db.Writer()); err != nil {
		t.Fatal(err)
	}
	if got := matchSecretCount(t, db, `"sentinel"`); got != 1 {
		t.Errorf("after a rebuild, %d rows match, want only the table secret", got)
	}
	if n, err := CheckSecretIndexInvariant(ctx, db.Writer()); err != nil || n != 0 {
		t.Errorf("invariant reports %d violations after a rebuild (err %v), want 0", n, err)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM secret_text`); got != 1 {
		t.Errorf("secret_text rows = %d after a rebuild, want 1", got)
	}
	assertFTSIntegrity(t, db)
}

// TestCheckSecretIndexInvariantCatchesALeak proves the assertion has teeth: a
// body forced into the index behind IndexSecretText's back is detected.
func TestCheckSecretIndexInvariantCatchesALeak(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	// Write the FTS shadow entry directly, the way a bug in a future writer
	// would. IndexSecretText's own check is bypassed on purpose here.
	mustExec(t, db.Writer(),
		`INSERT INTO secret_text (secret_id, body)
		 SELECT id, 'leaked warding phrase' FROM secrets WHERE visibility = ?
		 ON CONFLICT(secret_id) DO UPDATE SET body = excluded.body`,
		string(authz.VisibilityDM))
	mustExec(t, db.Writer(), `INSERT INTO secret_fts (secret_fts) VALUES('rebuild')`)

	n, err := CheckSecretIndexInvariant(ctx, db.Writer())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("invariant reports %d violations, want 1: the check does not detect a leak", n)
	}
}

func TestRebuildPageFTS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	// Corrupt the index behind the API's back, then rebuild.
	mustExec(t, db.Writer(), `DELETE FROM page_text`)
	if err := RebuildPageFTS(ctx, db.Writer()); err != nil {
		t.Fatal(err)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM page_text`); got != 0 {
		t.Errorf("rebuild resurrected content-table rows (%d); it must not invent data", got)
	}
	if got := matchCount(t, db, `"warded"`); got != 0 {
		t.Errorf("rebuilt index has %d rows, want 0", got)
	}

	// With content present, a rebuild restores the index from it.
	if err := ReplacePageText(ctx, db.Writer(), PageText{
		PageID: f.pageID, Title: "T", Headings: "H", Body: "rebuild probe",
	}); err != nil {
		t.Fatal(err)
	}
	if err := RebuildPageFTS(ctx, db.Writer()); err != nil {
		t.Fatal(err)
	}
	if got := matchCount(t, db, `"rebuild"`); got != 1 {
		t.Errorf("rebuilt index has %d rows, want 1", got)
	}
	assertFTSIntegrity(t, db)
}

// assertFTSIntegrity runs FTS5's own consistency check, which is the only thing
// that knows whether the index agrees with the content table row for row.
func assertFTSIntegrity(t *testing.T, db *DB) {
	t.Helper()
	for _, table := range []string{"page_fts", "secret_fts"} {
		if _, err := db.Writer().ExecContext(context.Background(),
			`INSERT INTO `+table+` (`+table+`) VALUES ('integrity-check')`); err != nil {
			t.Errorf("%s integrity-check failed: %v", table, err)
		}
	}
}

// TestFTSUsesTheSchemasTokenizer proves the schema's tokenizer is the one in
// force, by exercising the tokenchars and prefix settings §6.3 chose.
func TestFTSUsesTheSchemasTokenizer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	for _, tc := range []struct {
		text  string
		match string
		want  int
	}{
		{"Red-Dragon and goblin_scouts patrol", `"red-dragon"`, 1},
		{"Red-Dragon and goblin_scouts patrol", `"goblin_scouts"`, 1},
		{"Red-Dragon and goblin_scouts patrol", `"dragon"`, 0},
		// remove_diacritics: the query is folded exactly as the index was, so
		// an unaccented query finds accented text.
		{"Grüße aus Köln", `"koln"`, 1},
		{"Grüße aus Köln", `"grusse"`, 0},
		// prefix 2 3 4 is declared, so an explicit prefix match works. Note
		// that search.BuildMatchQuery never emits one: a quoted term is exact,
		// and * is an operator the query builder refuses to pass through. The
		// option is here for the autocomplete path, which builds its own
		// validated prefix.
		{"obsidian", `"obs"*`, 1},
		{"obsidian", `"obs"`, 0},
	} {
		if err := ReplacePageText(ctx, db.Writer(), PageText{
			PageID: f.pageID, Title: "T", Headings: "H", Body: tc.text,
		}); err != nil {
			t.Fatal(err)
		}
		if got := matchCount(t, db, tc.match); got != tc.want {
			t.Errorf("MATCH %q against %q = %d, want %d", tc.match, tc.text, got, tc.want)
		}
	}
}

func TestSecretTextSurvivesAPageReindex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFTSFixture(t)
	db := f.db

	if err := IndexSecretText(ctx, db.Writer(), f.secretIDs[authz.VisibilityTable],
		authz.VisibilityTable, "warded by a table sentinel"); err != nil {
		t.Fatal(err)
	}
	// The indexer deletes and reinserts a page's secrets on every re-index; the
	// index copy has to go with them, or a revoked secret stays searchable.
	if err := DeleteSecretByPage(ctx, db.Writer(), f.pageID); err != nil {
		t.Fatal(err)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM secret_text`); got != 0 {
		t.Errorf("secret_text rows = %d after deleting the page's secrets, want 0", got)
	}
	if got := matchSecretCount(t, db, `"sentinel"`); got != 0 {
		t.Errorf("%d index rows survive, want 0", got)
	}
	assertFTSIntegrity(t, db)
}
