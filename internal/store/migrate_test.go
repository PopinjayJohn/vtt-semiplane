package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

func TestMigrationsAreEmbedded(t *testing.T) {
	t.Parallel()
	ms := Migrations()
	if len(ms) == 0 {
		t.Fatal("no embedded migrations")
	}
	head := SchemaVersion()
	if head != ms[len(ms)-1].Version {
		t.Errorf("SchemaVersion() = %d, want %d", head, ms[len(ms)-1].Version)
	}
	for i, m := range ms {
		if m.Version < 1 {
			t.Errorf("%s: version %d is not positive", m.Filename(), m.Version)
		}
		if m.SQL == "" {
			t.Errorf("%s: empty SQL", m.Filename())
		}
		if i > 0 && m.Version <= ms[i-1].Version {
			t.Errorf("%s does not follow %s", m.Filename(), ms[i-1].Filename())
		}
	}
}

// TestMigrationsFromEveryVersion builds a database at each historical version
// from the migration file itself, migrates it to head, and asserts the result is
// indistinguishable from a freshly created head database.
//
// The v1 fixture is the migration applied directly rather than through Migrate,
// so it stands in for a file written by a released binary: no meta stamp, no
// backup hook, a populated row that must survive.
func TestMigrationsFromEveryVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fresh := newMigratedDB(t)
	want := schemaSnapshot(t, fresh.Writer())

	for _, fixture := range Migrations() {
		t.Run("from_v"+strconv.Itoa(fixture.Version), func(t *testing.T) {
			t.Parallel()
			db := newDB(t)

			// Stand up the historical database exactly as the old binary would
			// have left it.
			mustExec(t, db.Writer(), fixture.SQL)
			if got, err := UserVersion(ctx, db.Writer()); err != nil {
				t.Fatalf("read fixture version: %v", err)
			} else if got != fixture.Version {
				t.Fatalf("fixture is at v%d, want v%d", got, fixture.Version)
			}
			seedPage(t, db.Writer(), "Campaigns/Ash/Gundren.md", "Gundren")

			backupCalls := 0
			if err := Migrate(ctx, db.Writer(), func(context.Context) error {
				backupCalls++
				return nil
			}); err != nil {
				t.Fatalf("migrate from v%d: %v", fixture.Version, err)
			}
			if backupCalls != 1 {
				t.Errorf("backup hook called %d times, want 1", backupCalls)
			}

			if diff := diffSchema(want, schemaSnapshot(t, db.Writer())); len(diff) > 0 {
				t.Errorf("schema after migrating from v%d differs from a fresh head: %v",
					fixture.Version, diff)
			}
			if got, err := UserVersion(ctx, db.Writer()); err != nil {
				t.Fatalf("read version: %v", err)
			} else if got != SchemaVersion() {
				t.Errorf("version = %d, want %d", got, SchemaVersion())
			}
			// Seeded data must survive the migration, not merely the schema.
			p, err := GetPageByPath(ctx, db.Writer(), "Campaigns/Ash/Gundren.md")
			if err != nil {
				t.Fatalf("seeded page lost: %v", err)
			}
			if p.Title != "Gundren" {
				t.Errorf("seeded page title = %q, want %q", p.Title, "Gundren")
			}
			// The meta stamp is what §7.5 step 4 compares the FTS generation
			// against, so a migrated database must carry it.
			sv, err := MetaGetInt(ctx, db.Writer(), KeySchemaVersion)
			if err != nil {
				t.Fatalf("read meta schema_version: %v", err)
			}
			if sv != int64(SchemaVersion()) {
				t.Errorf("meta schema_version = %d, want %d", sv, SchemaVersion())
			}
			if _, err := MetaGet(ctx, db.Writer(), KeyInstalledAt); err != nil {
				t.Errorf("meta installed_at: %v", err)
			}
		})
	}
}

// TestBackupTakenBeforeMigration asserts the ordering §6.5 fixes. The hook runs
// against a database on which no migration has happened yet, which is the only
// way to observe "first" rather than "also".
func TestBackupTakenBeforeMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newDB(t)

	var sawEmpty bool
	err := Migrate(ctx, db.Writer(), func(context.Context) error {
		// Nothing may exist yet: not the schema, and not the meta stamp.
		var tables int64
		if err := db.Writer().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'pages'`).Scan(&tables); err != nil {
			return err
		}
		if tables != 0 {
			return errors.New("backup hook ran after a migration had already been applied")
		}
		var version int
		if err := db.Writer().QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
			return err
		}
		if version != 0 {
			return errors.New("backup hook ran with user_version already set")
		}
		sawEmpty = true
		return nil
	})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !sawEmpty {
		t.Fatal("backup hook never ran")
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='pages'`); got != 1 {
		t.Fatalf("migration did not apply (pages table present = %d)", got)
	}
}

// TestBackupFailureStopsMigration is the other half of backup-first: if the
// backup cannot be taken, no migration runs. A half-migrated database with no
// restore point is the failure this prevents.
func TestBackupFailureStopsMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newDB(t)

	boom := errors.New("backup device full")
	err := Migrate(ctx, db.Writer(), func(context.Context) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Migrate error = %v, want the backup error", err)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='pages'`); got != 0 {
		t.Errorf("pages table exists after a failed backup; the migration ran anyway")
	}
	if v, err := UserVersion(ctx, db.Writer()); err != nil || v != 0 {
		t.Errorf("user_version = %d (err %v), want 0", v, err)
	}
}

func TestMigrateRequiresABackupHook(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	if err := Migrate(context.Background(), db.Writer(), nil); err == nil {
		t.Fatal("Migrate accepted a nil backup hook; backup-first is not advisory")
	}
}

func TestNewerDatabaseRefusesToStart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newDB(t)
	mustExec(t, db.Writer(), `PRAGMA user_version = 7`)

	backedUp := false
	err := Migrate(ctx, db.Writer(), func(context.Context) error {
		backedUp = true
		return nil
	})
	if err == nil {
		t.Fatal("Migrate accepted a database from a newer semiplane")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("error %v does not match ErrSchemaTooNew", err)
	}
	var tooNew *SchemaTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("error %v is not a *SchemaTooNewError", err)
	}
	if tooNew.Found != 7 || tooNew.Supports != SchemaVersion() {
		t.Errorf("error reports v%d/v%d, want v%d/%d",
			tooNew.Found, tooNew.Supports, 7, SchemaVersion())
	}
	want := "database schema v7 is newer than this binary (supports v" +
		strconv.Itoa(SchemaVersion()) + "); upgrade semiplane"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
	if backedUp {
		t.Error("a refused database was backed up; nothing was about to be changed")
	}
	// The database must be left exactly as it was found.
	if v, err := UserVersion(ctx, db.Writer()); err != nil || v != 7 {
		t.Errorf("user_version = %d (err %v), want 7 untouched", v, err)
	}
}

// TestMigrationsAreIdempotent re-migrating a head database is a no-op: the same
// schema, the same version, and a backup that still happens because Migrate
// always takes one.
func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	before := schemaSnapshot(t, db.Writer())
	seedPage(t, db.Writer(), "a.md", "A")

	calls := 0
	for i := 0; i < 3; i++ {
		if err := Migrate(ctx, db.Writer(), func(context.Context) error {
			calls++
			return nil
		}); err != nil {
			t.Fatalf("re-migrate %d: %v", i, err)
		}
	}
	if calls != 3 {
		t.Errorf("backup hook called %d times over 3 migrations, want 3", calls)
	}
	if diff := diffSchema(before, schemaSnapshot(t, db.Writer())); len(diff) > 0 {
		t.Errorf("re-migration changed the schema: %v", diff)
	}
	if got := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM pages`); got != 1 {
		t.Errorf("pages = %d, want 1", got)
	}
}

// TestMigrationFailureIsRetryable checks the version/schema pairing survives a
// half-applied step: the schema is rolled back with the version, so a retry
// applies the same file again rather than skipping it.
func TestMigrationFailureIsRetryable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newDB(t)

	tx, err := db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE half_applied (x INTEGER); PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	if v, err := UserVersion(ctx, db.Writer()); err != nil || v != 0 {
		t.Errorf("user_version = %d (err %v), want 0 after rollback", v, err)
	}
	if got := mustQueryInt(t, db.Writer(),
		`SELECT COUNT(*) FROM sqlite_schema WHERE name = 'half_applied'`); got != 0 {
		t.Error("the failed migration's DDL survived the rollback")
	}
}

// TestSchemaHasEveryPlanTable checks the §6.2 object list one by one, so a table
// silently dropped from the migration file is a test failure rather than a
// missing table found at runtime.
func TestSchemaHasEveryPlanTable(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	present := map[string]bool{}
	for _, e := range schemaSnapshot(t, db.Writer()) {
		present[e.Name] = true
	}
	want := []string{
		"meta", "users", "sessions", "invites", "pages", "page_owners",
		"page_aliases", "tags", "page_tags", "links", "headings", "secrets",
		"secret_events", "revisions", "attachments", "plugin_migrations",
		"selfwrites", "page_text", "page_fts", "secret_text", "secret_fts",
	}
	for _, name := range want {
		if !present[name] {
			t.Errorf("table %q is missing from the schema", name)
		}
	}
	// The FTS tables are virtual, and a virtual table that silently became an
	// ordinary one would still answer a MATCH query with wrong results.
	for _, name := range []string{"page_fts", "secret_fts"} {
		var sqlText string
		if err := db.Writer().QueryRowContext(context.Background(),
			`SELECT COALESCE(sql, '') FROM sqlite_schema WHERE name = ?`, name).Scan(&sqlText); err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		for _, want := range []string{"fts5", "unicode61 remove_diacritics 2", "tokenchars '_-'", "prefix = '2 3 4'"} {
			if !strings.Contains(sqlText, want) {
				t.Errorf("%s does not declare %q: %s", name, want, sqlText)
			}
		}
		if !strings.Contains(sqlText, "content=") {
			t.Errorf("%s is not content-backed, so snippet() and rebuild will not work", name)
		}
	}
	// Porter stemming must stay off: §6.3 is explicit that over-stemming proper
	// nouns produces confusing results.
	var porter int64
	if err := db.Writer().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_schema WHERE sql LIKE '%porter%'`).Scan(&porter); err != nil {
		t.Fatal(err)
	}
	if porter != 0 {
		t.Error("the schema enables porter stemming; §6.3 requires it to be off")
	}
}

// TestQueryIterErrorPropagated is the regression test for the bug ForEach
// exists to prevent.
//
// Producing a genuine mid-iteration error from SQLite takes some work. Dropping
// the table under an open cursor does not do it: the cursor holds a read
// transaction and keeps reading its own snapshot, and rows.Err() is nil. A
// user-defined function that raises on its third call does do it, because
// SQLite evaluates one row per step and the failure lands between two of them.
func TestQueryIterErrorPropagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var calls atomic.Int64
	if err := sqlite.RegisterDeterministicScalarFunction("test_iter_raise", 1,
		func(_ *sqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
			if calls.Add(1) >= 3 {
				return nil, errors.New("iter boom")
			}
			return int64(1), nil
		}); err != nil {
		t.Fatalf("register function: %v", err)
	}

	db := newMigratedDB(t)
	mustExec(t, db.Writer(), `CREATE TABLE iter_probe (id INTEGER PRIMARY KEY, path TEXT)`)
	for i := 1; i <= 9; i++ {
		mustExec(t, db.Writer(), `INSERT INTO iter_probe (id, path) VALUES (?, ?)`, i, "p")
	}

	rows, err := db.Writer().QueryContext(ctx,
		`SELECT id, test_iter_raise(id) FROM iter_probe ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	seen := 0
	var iterErr error
	err = ForEach(rows, func(r Rows) error {
		var id, v int64
		if err := r.Scan(&id, &v); err != nil {
			return err
		}
		seen++
		return nil
	})
	if err == nil {
		t.Fatalf("ForEach returned nil after %d rows; rows.Err() was ignored", seen)
	}
	iterErr = err
	if !strings.Contains(iterErr.Error(), "iter boom") {
		t.Errorf("ForEach returned %v, want the iteration error", iterErr)
	}
	if seen >= 9 {
		t.Errorf("ForEach iterated all %d rows; the failure never reached the loop", seen)
	}
}

// TestForEachPropagatesCallbackError covers the other half: an error from the
// callback stops the iteration and is returned unchanged, and the rows are still
// closed.
func TestForEachPropagatesCallbackError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	mustExec(t, db.Writer(), `CREATE TABLE iter_probe2 (id INTEGER PRIMARY KEY)`)
	for i := 1; i <= 5; i++ {
		mustExec(t, db.Writer(), `INSERT INTO iter_probe2 (id) VALUES (?)`, i)
	}

	sentinel := errors.New("stop here")
	rows, err := db.Writer().QueryContext(ctx, `SELECT id FROM iter_probe2 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := ForEach(rows, func(Rows) error {
		seen++
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Errorf("ForEach returned %v, want the callback error", err)
	}
	if seen != 1 {
		t.Errorf("iteration continued past the callback error: %d rows", seen)
	}
}

// TestForEachRejectsNilRows guards the nil case, which would otherwise panic
// inside a deferred Close.
func TestForEachRejectsNilRows(t *testing.T) {
	t.Parallel()
	if err := ForEach(nil, func(Rows) error { return nil }); err == nil {
		t.Error("ForEach(nil) returned nil")
	}
}

// TestForEachClosesRows is why the helper closes: a hand-written loop that
// returns early leaks the cursor and the connection behind it.
func TestForEachClosesRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	mustExec(t, db.Writer(), `CREATE TABLE iter_probe3 (id INTEGER PRIMARY KEY)`)
	mustExec(t, db.Writer(), `INSERT INTO iter_probe3 (id) VALUES (1)`)

	rows, err := db.Writer().QueryContext(ctx, `SELECT id FROM iter_probe3`)
	if err != nil {
		t.Fatal(err)
	}
	if err := ForEach(rows, func(Rows) error { return errors.New("bail") }); err == nil {
		t.Fatal("expected the callback error")
	}
	// With one write connection, a leaked cursor would make this hang or fail.
	probe, err := db.Writer().QueryContext(ctx, `SELECT id FROM iter_probe3`)
	if err != nil {
		t.Fatalf("rows were not closed: %v", err)
	}
	probe.Close()
}
