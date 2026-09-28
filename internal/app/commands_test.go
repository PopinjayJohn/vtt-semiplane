package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// pageTitleToken is a page's title, which is vault content and must never reach
// a command's output: `vault info` output gets pasted into a bug report.
const pageTitleToken = "A courier with a letter"

// TestReindexSubcommandRebuildsFromTheVault covers the claim the whole design
// rests on: the index is derived and disposable, so deleting all of it and
// reindexing gets the same answers back.
//
// The secret is the part that matters. Its body must come back into the secrets
// table and must not come back into page_text, because that is the difference
// between "the reindex works" and "the reindex works and leaks".
func TestReindexSubcommandRebuildsFromTheVault(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	// Empty the index through the store's own deletion path, so the FTS rows go
	// with the pages.
	withDB(t, f.vault.Root, func(db *store.DB) {
		pages, err := store.ListRecentPages(context.Background(), db.Reader(), 100)
		if err != nil {
			t.Fatalf("list pages: %v", err)
		}
		for _, p := range pages {
			if err := store.DeletePage(context.Background(), db.Writer(), p.ID); err != nil {
				t.Fatalf("delete %s: %v", p.Path, err)
			}
		}
	})

	var out bytes.Buffer
	if err := Reindex(context.Background(), f.opts, &out, false); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	if !strings.Contains(out.String(), strconv.Itoa(len(campaignFiles()))+" pages") {
		t.Errorf("the command did not report the page count:\n%s", out.String())
	}

	withDB(t, f.vault.Root, func(db *store.DB) {
		ctx := context.Background()
		pages, err := store.CountPages(ctx, db.Reader())
		if err != nil {
			t.Fatalf("count pages: %v", err)
		}
		if want := int64(len(campaignFiles())); pages != want {
			t.Errorf("the index holds %d pages after the reindex, want %d", pages, want)
		}
		var body string
		err = db.Reader().QueryRowContext(ctx,
			`SELECT body FROM secrets WHERE id = ?`, "abcdef012345").Scan(&body)
		if err != nil {
			t.Fatalf("the secret is not in the index: %v", err)
		}
		if !strings.Contains(body, leakToken) {
			t.Errorf("the secret body was not restored: %q", body)
		}
		var public string
		err = db.Reader().QueryRowContext(ctx,
			`SELECT COALESCE(MAX(body), '') FROM page_text`).Scan(&public)
		if err != nil {
			t.Fatalf("read page_text: %v", err)
		}
		if strings.Contains(public, leakToken) {
			t.Error("a secret body reached page_text after the reindex")
		}
	})
}

// TestReindexFullRebuildsTheSearchTables covers the --full flag: the walk
// maintains the FTS rows incrementally, so only an explicit rebuild can bring
// them back in line with the schema.
func TestReindexFullRebuildsTheSearchTables(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	var out bytes.Buffer
	if err := Reindex(context.Background(), f.opts, &out, true); err != nil {
		t.Fatalf("reindex --full: %v", err)
	}
	withDB(t, f.vault.Root, func(db *store.DB) {
		generation, err := store.MetaGetInt(context.Background(), db.Reader(), store.KeyFTSGeneration)
		if err != nil {
			t.Fatalf("read the fts generation: %v", err)
		}
		schema, err := store.MetaGetInt(context.Background(), db.Reader(), store.KeySchemaVersion)
		if err != nil {
			t.Fatalf("read the schema version: %v", err)
		}
		if generation != schema {
			t.Errorf("the fts generation is %d and the schema is %d", generation, schema)
		}
		// A table-visible secret is the one kind of body that may be searched.
		var hits int
		err = db.Reader().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken).Scan(&hits)
		if err != nil {
			t.Fatalf("match the secret fts: %v", err)
		}
		if hits != 1 {
			t.Errorf("the table-visible secret is searchable in %d rows, want 1", hits)
		}
	})
}

// TestReindexOnBootRebuildsWhatTheDeltaWalkWouldSkip is the fix for a flag that
// parsed and was then discarded: `semiplane serve --reindex` booted, reported a
// healthy index and had not reindexed anything.
//
// The state it sets up is the one the delta walk cannot see: a page row whose
// content hash still matches the file, with a derived row that is not there.
// Nothing about the vault changed, so indexOne returns the file as unchanged
// and the missing row is never rewritten — which is exactly the failure the
// reindex subcommand answers by dropping the derived rows first.
func TestReindexOnBootRebuildsWhatTheDeltaWalkWouldSkip(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.opts)
	if got := countHeadings(t, f.vault.Root, "Campaign.md"); got == 0 {
		t.Fatal("the fixture did not index the page's headings, so the test proves nothing")
	}

	// Behind the indexer's back, the way a bug or a half-applied upgrade
	// would: the derived row is gone, the file and its recorded hash are not.
	withDB(t, f.vault.Root, func(db *store.DB) {
		if _, err := db.Writer().ExecContext(context.Background(),
			`DELETE FROM headings WHERE page_id = (SELECT id FROM pages WHERE path = ?)`, "Campaign.md"); err != nil {
			t.Fatalf("remove the derived row: %v", err)
		}
	})

	// The ordinary boot walks the vault and finds nothing changed.
	f.boot(t, f.opts)
	if got := countHeadings(t, f.vault.Root, "Campaign.md"); got != 0 {
		t.Fatalf("the ordinary boot rewrote %d headings, so this test does not isolate --reindex", got)
	}

	opts := f.opts
	opts.Reindex = true
	a := f.boot(t, opts)
	if got := countHeadings(t, f.vault.Root, "Campaign.md"); got == 0 {
		t.Error("--reindex on boot did not rebuild the row the delta walk skipped")
	}
	// The rest of the index survived the rebuild, and the report is the boot's
	// own: a rebuild that emptied the vault would pass the assertion above.
	if got := a.Status().PageCount; got != len(campaignFiles()) {
		t.Errorf("the rebuilt index holds %d pages, want %d", got, len(campaignFiles()))
	}
}

// TestTheReindexSubcommandStillReportsThePassThatDidTheWork is the other half
// of the same fix: the full rebuild moved into the boot, and reporting has to
// follow it. A reindex command that reported the walk *after* the rebuild would
// print "0 indexed" for a vault it had just re-read in full.
func TestTheReindexSubcommandStillReportsThePassThatDidTheWork(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	var out bytes.Buffer
	if err := Reindex(context.Background(), f.opts, &out, true); err != nil {
		t.Fatalf("reindex --full: %v", err)
	}
	want := strconv.Itoa(len(campaignFiles())) + " indexed, 0 already current"
	if !strings.Contains(out.String(), want) {
		t.Errorf("the command did not report the pass that rebuilt the index:\n%s", out.String())
	}
}

// countHeadings is how many heading rows the index holds for one path. It
// reads through the store rather than through the app, because a booted app
// holds the vault and the assertion is about what was persisted.
func countHeadings(t *testing.T, root, path string) int {
	t.Helper()
	var n int
	withDB(t, root, func(db *store.DB) {
		err := db.Reader().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM headings WHERE page_id = (SELECT id FROM pages WHERE path = ?)`, path).Scan(&n)
		if err != nil {
			t.Fatalf("count the headings of %s: %v", path, err)
		}
	})
	return n
}

// TestBackupThenMigrateTakesABackup covers the hook store.Migrate requires: a
// migration is the one moment a backup is not optional, because the file it is
// about to rewrite is the only copy of the state the new schema cannot read.
func TestBackupThenMigrateTakesABackup(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.opts)

	first, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("a first boot took no backup before its migration")
	}

	// Roll the schema back so the next boot has a migration to run.
	head := store.SchemaVersion()
	withDB(t, f.vault.Root, func(db *store.DB) {
		if _, err := db.Writer().ExecContext(context.Background(),
			"PRAGMA user_version = 1"); err != nil {
			t.Fatalf("roll the schema back: %v", err)
		}
	})
	f.boot(t, f.opts)

	second, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(second) <= len(first) {
		t.Errorf("the migration took no backup: %d backups before, %d after", len(first), len(second))
	}
	withDB(t, f.vault.Root, func(db *store.DB) {
		version, err := store.UserVersion(context.Background(), db.Reader())
		if err != nil {
			t.Fatalf("read user_version: %v", err)
		}
		if version != head {
			t.Errorf("user_version is %d after the migration, want %d", version, head)
		}
	})
}

// TestAnUnchangedVaultIsNotBackedUpOnEveryBoot covers the other half of the
// policy. Copying every page of a vault on every `semiplane vault info` would
// fill the disk with backups nobody asked for, and the retention is ten.
func TestAnUnchangedVaultIsNotBackedUpOnEveryBoot(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.opts)

	// The vault's last change is stated as older than the backup the first boot
	// took, which is what an unchanged vault looks like.
	withDB(t, f.vault.Root, func(db *store.DB) {
		err := store.MetaSet(context.Background(), db.Writer(), store.KeyLastChangeAt,
			store.FormatTime(bootNow.Add(-time.Hour)))
		if err != nil {
			t.Fatalf("set last_change_at: %v", err)
		}
	})
	before, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}

	f.boot(t, f.opts)
	after, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("an unchanged vault was backed up again: %d backups before, %d after",
			len(before), len(after))
	}
}

// TestTheBackupCommandWritesAndPlacesABackup covers `backup` and its --out
// directory: the copy is written under the vault, where it is private, retained
// and restorable, and is also copied to where the operator asked for it.
func TestTheBackupCommandWritesAndPlacesABackup(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	outDir := filepath.Join(t.TempDir(), "nightly")

	var out bytes.Buffer
	if err := Backup(context.Background(), f.opts, &out, outDir); err != nil {
		t.Fatalf("backup: %v", err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read the --out directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("the --out directory holds %d entries, want one backup", len(entries))
	}
	placed := filepath.Join(outDir, entries[0].Name())
	for _, want := range []string{vault.ManifestName, vault.MetaName, vault.DBName, vault.FilesDir} {
		if _, err := os.Stat(filepath.Join(placed, want)); err != nil {
			t.Errorf("the copy has no %s: %v", want, err)
		}
	}
	// The original stays where vault.Restore can reach it: a --out copy must not
	// take the vault's own restore point with it.
	canonical, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(canonical) == 0 {
		t.Error("--out moved the backup out of the vault, so it can no longer be restored")
	}
	// A backup that holds every DM secret in plaintext inherits the vault's
	// sensitivity, and the command says so where the operator will read it.
	if !strings.Contains(out.String(), "plaintext") {
		t.Errorf("the command did not warn about the backup's contents:\n%s", out.String())
	}
	if !strings.Contains(out.String(), placed) {
		t.Errorf("the command did not report the placed copy:\n%s", out.String())
	}
}

// TestVaultInfoReportsPathsAndCounts covers the command's output contract:
// paths, counts and versions, and not one byte of vault content.
func TestVaultInfoReportsPathsAndCounts(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	var out bytes.Buffer
	if err := VaultInfo(context.Background(), f.opts, &out); err != nil {
		t.Fatalf("vault info: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		f.vault.Root,                // the resolved path
		"flag:--vault",              // and how it was chosen
		filepath.Base(f.vault.Root), // the campaign name
		f.dbFile(),                  // the database
		"schema v",                  // the schema version
		strconv.Itoa(len(campaignFiles())) + " pages",
		"backups:", // the retention state
		"ready",    // the boot state
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the output does not mention %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{
		leakToken,        // a secret body
		pageTitleToken,   // a page's text
		"The Safe",       // a page's title
		"The Vault Door", // a secret's title
		"abcdef012345",   // a secret id
		"Campaign.md",    // a page's path
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the output printed vault content %q:\n%s", forbidden, got)
		}
	}
}

// TestRestoreBringsBackDeletedPages covers the other half of a backup: the
// operator deleted a page, and the restore puts the bytes and the index back.
func TestRestoreBringsBackDeletedPages(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	var backupOut bytes.Buffer
	if err := Backup(context.Background(), f.opts, &backupOut, ""); err != nil {
		t.Fatalf("backup: %v", err)
	}
	backups, err := vault.Backups(f.vault.Root)
	if err != nil {
		t.Fatalf("list backups: %v", err)
	}
	if len(backups) == 0 {
		t.Fatal("the backup command wrote no backup")
	}

	victim := filepath.Join(f.vault.Root, "Campaigns", "Ash.md")
	if err := os.Remove(victim); err != nil {
		t.Fatalf("delete the page: %v", err)
	}

	// Without --force the restore refuses to overwrite, which is the whole
	// reason the flag exists.
	refusal := Restore(context.Background(), f.opts, &bytes.Buffer{}, backups[0], false)
	if refusal == nil {
		t.Fatal("a restore overwrote an existing file without --force")
	}
	if !strings.Contains(refusal.Error(), "force") {
		t.Errorf("the refusal does not say how to proceed: %v", refusal)
	}

	var out bytes.Buffer
	if err := Restore(context.Background(), f.opts, &out, backups[0], true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the file was not restored: %v", err)
	}
	withDB(t, f.vault.Root, func(db *store.DB) {
		if _, err := store.GetPageByPath(context.Background(), db.Reader(), "Campaigns/Ash.md"); err != nil {
			t.Errorf("the restored page is not in the index: %v", err)
		}
	})
	if !strings.Contains(out.String(), "reindexed") {
		t.Errorf("the command did not report the reindex:\n%s", out.String())
	}
}

// TestASecretInTheSearchIndexIsReportedAndRebuiltAway covers the invariant that
// store.IndexSecretText enforces structurally, checked here because a boot is
// the one moment a leak in the index is worth stopping for.
//
// The boot does not refuse to start: a poisoned cache that made the app
// unbootable would be a denial of service created by a bug, so the finding is
// repaired, logged, audited and reported instead.
func TestASecretInTheSearchIndexIsReportedAndRebuiltAway(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	seedAuthor(t, f, "mara")

	// A table-visible secret is legitimately in secret_text. Flipping its
	// visibility afterwards is the closest a test can get to the bug this
	// invariant exists for: a hidden body sitting in the search index.
	withDB(t, f.vault.Root, func(db *store.DB) {
		_, err := db.Writer().ExecContext(context.Background(),
			`UPDATE secrets SET visibility = 'dm' WHERE id = ?`, "abcdef012345")
		if err != nil {
			t.Fatalf("flip the visibility: %v", err)
		}
	})
	withDB(t, f.vault.Root, func(db *store.DB) {
		leaked, err := store.CheckSecretIndexInvariant(context.Background(), db.Reader())
		if err != nil {
			t.Fatalf("check the invariant: %v", err)
		}
		if leaked == 0 {
			t.Skip("the fixture did not create a leak")
		}
	})

	a, err := Boot(context.Background(), f.opts)
	if err != nil {
		t.Fatalf("boot with a poisoned index: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown(context.Background()) })

	if !anyWarningContains(a, "search index") {
		t.Errorf("the boot report does not mention the leak: %v", a.Status().Warnings)
	}
	// The searchable table is clean even though the residue in secret_text is
	// not something a rebuild can remove.
	withDB(t, f.vault.Root, func(db *store.DB) {
		var hits int
		err := db.Reader().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken).Scan(&hits)
		if err != nil {
			t.Fatalf("match the secret fts: %v", err)
		}
		if hits != 0 {
			t.Errorf("a hidden secret body is searchable in %d rows after the rebuild", hits)
		}
	})
}

// seedAuthor adds the account the secret fences name and reindexes, so a secret
// is genuinely in the index.
//
// secrets.author_id is a real foreign key, so a fence whose author is unknown is
// recorded as a problem and not indexed. P3 does not invent an ownership
// convention, and P6 assigns owners when a page is created, so the tests that
// need an indexed secret create the account themselves.
func seedAuthor(t *testing.T, f *fixture, username string) {
	t.Helper()
	// The first boot is what creates the schema the account is inserted into.
	f.boot(t, f.opts)
	withDB(t, f.vault.Root, func(db *store.DB) {
		_, err := store.InsertUser(context.Background(), db.Writer(), store.User{
			Username:    username,
			DisplayName: username,
			Role:        "admin",
			PWSalt:      []byte("salt"),
			CreatedAt:   bootNow,
		})
		if err != nil {
			t.Fatalf("seed the author %q: %v", username, err)
		}
	})
	if err := shutdownAnd(f.app); err != nil {
		t.Fatalf("release the vault: %v", err)
	}
	f.app = nil
	// A full reindex, because the pages are already in the index with the same
	// hashes: an account that appears after a page was first read does not make
	// the file change, so nothing would be re-read without dropping the rows
	// first.
	if err := Reindex(context.Background(), f.opts, &bytes.Buffer{}, true); err != nil {
		t.Fatalf("reindex after seeding the author: %v", err)
	}
}

// withDB opens the vault's index, hands it to fn and closes it, so a test can
// seed or inspect between boots without holding the app open.
func withDB(t *testing.T, root string, fn func(*store.DB)) {
	t.Helper()
	db, err := store.Open(root)
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close the index: %v", err)
		}
	}()
	fn(db)
}
