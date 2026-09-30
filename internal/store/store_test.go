package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newDB opens a store over a fresh temp vault without migrating it.
func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return db
}

// newMigratedDB opens a store and brings it to head, failing the test if either
// step does not work. Every store test starts here so that a migration failure
// is never mistaken for a query failure.
func newMigratedDB(t *testing.T) *DB {
	t.Helper()
	db := newDB(t)
	if err := Migrate(context.Background(), db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newDBAtVersion opens a store and leaves it at a historical schema version, by
// applying the migration files up to that version raw — the way an older binary
// would have left the file, with no meta stamp and no backup hook, because
// Migrate is not what wrote it.
//
// The files are applied cumulatively, and that is a correction rather than a
// convenience. A migration is a delta from the version before it, not a whole
// schema: 0002 is an ALTER TABLE over a table 0001 creates, so running it alone
// against an empty database fails on a table that does not exist. A fixture that
// applied each file in isolation would only work while every migration happens
// to be a complete CREATE script, which is a property of the current series
// rather than of the mechanism — and the first ALTER was the first thing to
// expose it. The only honest fixture for version V is 1..V, and it is strictly
// more coverage than one file, because a V fixture carries every earlier object
// as well as the V delta.
//
// The version is stamped by the test rather than read out of a file's own
// PRAGMA, because applyMigration is what writes it in production: a fixture that
// took the version from a file would be testing the file instead of the
// migration.
func newDBAtVersion(t *testing.T, version int) *DB {
	t.Helper()
	db := newDB(t)
	for _, m := range Migrations() {
		if m.Version > version {
			break
		}
		mustExec(t, db.Writer(), m.SQL)
	}
	mustExec(t, db.Writer(), setUserVersionSQL(version))
	return db
}

// seedUser creates a user the other fixtures can reference.
func seedUser(t *testing.T, e Execer, name, role string) int64 {
	t.Helper()
	id, err := InsertUser(context.Background(), e, User{
		Username:    name,
		DisplayName: name,
		Role:        role,
		PWSalt:      []byte("salt"),
		CreatedAt:   time.Unix(1750000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("insert user %s: %v", name, err)
	}
	return id
}

// seedPage creates a page and returns its id.
func seedPage(t *testing.T, e Execer, path, title string) int64 {
	t.Helper()
	id, err := UpsertPage(context.Background(), e, Page{
		Path:        path,
		Basename:    trimExt(filepath.Base(path)),
		Title:       title,
		ContentHash: []byte("hash-" + path),
		MTimeUnix:   1750000000,
		SizeBytes:   42,
		PageType:    "note",
		CreatedAt:   time.Unix(1750000000, 0).UTC(),
		UpdatedAt:   time.Unix(1750000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("upsert page %s: %v", path, err)
	}
	return id
}

func trimExt(s string) string {
	if i := len(s) - len(".md"); i > 0 {
		return s[:i]
	}
	return s
}

func mustExec(t *testing.T, e Execer, query string, args ...any) {
	t.Helper()
	if _, err := e.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func mustQueryInt(t *testing.T, q Queryer, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := q.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// schemaSnapshot is the shape of a database: every object it declares, with the
// exact SQL that declares it. Two databases with equal snapshots are equal
// databases for every purpose this codebase has.
type schemaEntry struct {
	Type     string
	Name     string
	TblName  string
	SQL      string
	HasIndex int
}

func schemaSnapshot(t *testing.T, q Queryer) []schemaEntry {
	t.Helper()
	rows, err := q.QueryContext(context.Background(),
		`SELECT type, name, tbl_name, COALESCE(sql, ''), (sql IS NULL)
		 FROM sqlite_schema
		 WHERE name NOT LIKE 'sqlite_%'
		 ORDER BY type, name`)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []schemaEntry
	for rows.Next() {
		var e schemaEntry
		if err := rows.Scan(&e.Type, &e.Name, &e.TblName, &e.SQL, &e.HasIndex); err != nil {
			t.Fatalf("scan schema: %v", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema: %v", err)
	}
	return out
}

func diffSchema(a, b []schemaEntry) []string {
	if len(a) != len(b) {
		return []string{"object count differs"}
	}
	var out []string
	for i := range a {
		if a[i] != b[i] {
			out = append(out, a[i].Type+" "+a[i].Name+" differs")
		}
	}
	return out
}

// TestStateDirPermissions pins the two modes that are part of the threat model
// under D4: the database holds every secret body in plaintext, so neither the
// directory nor the file may be group- or world-readable.
//
// The modes are the only evidence there is of what was asked for, so the
// assertion needs a volume that keeps them. Windows has no mode bits: os.Stat
// synthesises 0777 for a directory and 0666 for a file out of the read-only
// attribute, so both assertions below report 0777/0666 whatever the migration
// requested. That is measured rather than assumed, because the same answer comes
// from a volume mounted without mode support and from a CIFS share, and
// runtime.GOOS would skip on all three for the same unexamined reason.
func TestStateDirPermissions(t *testing.T) {
	t.Parallel()
	file, dir := keepModeBits(t)
	if file != 0o600 || dir != 0o700 {
		t.Skipf("this volume does not keep POSIX mode bits: a file created 0600 reads back %04o and a directory created 0700 reads back %04o, "+
			"so the mode the migration asked for is not observable here", file, dir)
	}

	db := newDB(t)

	d := filepath.Join(db.Vault(), StateDirName)
	di, err := os.Stat(d)
	if err != nil {
		t.Fatalf("stat %s: %v", d, err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("state dir mode = %04o, want 0700", got)
	}

	fi, err := os.Stat(db.Path())
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("database mode = %04o, want 0600", got)
	}
}

// keepModeBits reports the mode this volume gave a file created 0600 and a
// directory created 0700, read back through the same os.Stat the assertions
// under test use. It lives in a directory of its own so it cannot be confused
// with the state directory it is about.
func keepModeBits(t *testing.T) (file, dir os.FileMode) {
	t.Helper()
	probe := t.TempDir()
	p := filepath.Join(probe, "file")
	d := filepath.Join(probe, "dir")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("create the mode probe file: %v", err)
	}
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatalf("create the mode probe directory: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat the mode probe file: %v", err)
	}
	di, err := os.Stat(d)
	if err != nil {
		t.Fatalf("stat the mode probe directory: %v", err)
	}
	return st.Mode().Perm(), di.Mode().Perm()
}

// TestWriterPoolIsSerialised proves the write pool is a queue, not a crowd. A
// second concurrent write must block rather than open a second connection, which
// is what turns lock contention into SQLITE_BUSY.
func TestWriterPoolIsSerialised(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	if got := db.Writer().Stats().MaxOpenConnections; got != 1 {
		t.Errorf("write pool max connections = %d, want 1", got)
	}
	if db.Writer().Stats().MaxOpenConnections == db.Reader().Stats().MaxOpenConnections {
		t.Errorf("read pool and write pool have the same size (%d); they are meant to be separate",
			db.Writer().Stats().MaxOpenConnections)
	}
}

// TestReaderPoolIsReadOnly proves the read pool cannot write, which is what makes
// it safe to hand to query traffic while a reindex runs.
func TestReaderPoolIsReadOnly(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	seedUser(t, db.Writer(), "dm", "dm")

	if _, err := db.Reader().ExecContext(context.Background(),
		`INSERT INTO meta (key, value) VALUES ('x', 'y')`); err == nil {
		t.Fatal("read pool accepted an insert; the mode=ro parameter is not in effect")
	}
}

// TestPragmasAreInEffect asserts the §6.1 settings are actually applied rather
// than merely written in a DSN. foreign_keys especially: without it every
// ON DELETE CASCADE in the schema is decorative.
func TestPragmasAreInEffect(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	ctx := context.Background()

	for _, c := range []struct {
		pool  *sql.DB
		name  string
		query string
		want  string
	}{
		{db.Writer(), "journal_mode", `PRAGMA journal_mode`, "wal"},
		{db.Writer(), "foreign_keys", `PRAGMA foreign_keys`, "1"},
		{db.Writer(), "trusted_schema", `PRAGMA trusted_schema`, "0"},
		{db.Reader(), "foreign_keys", `PRAGMA foreign_keys`, "1"},
		{db.Reader(), "trusted_schema", `PRAGMA trusted_schema`, "0"},
	} {
		var got string
		if err := c.pool.QueryRowContext(ctx, c.query).Scan(&got); err != nil {
			t.Errorf("%s: %s: %v", c.name, c.query, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
	var busy int
	if err := db.Writer().QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Errorf("busy_timeout: %v", err)
	} else if busy != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busy)
	}
}

// TestTimeLayoutIsFixedWidth guards the reason the format is not
// time.RFC3339Nano. A trimmed fraction makes "…:11Z" sort after "…:11.5Z", and
// several indexes order these TEXT columns lexicographically.
func TestTimeLayoutIsFixedWidth(t *testing.T) {
	t.Parallel()
	early := FormatTime(time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC))
	late := FormatTime(time.Date(2026, 9, 28, 10, 4, 11, 500000000, time.UTC))
	if len(early) != len(late) {
		t.Fatalf("timestamp widths differ: %q vs %q", early, late)
	}
	if !(early < late) {
		t.Errorf("text order is wrong: %q must sort before %q", early, late)
	}
	parsed, err := ParseTime(late)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Nanosecond() != 500000000 {
		t.Errorf("nanosecond = %d, want 500000000", parsed.Nanosecond())
	}
	// The variable-width RFC 3339 forms must still load.
	if _, err := ParseTime("2026-09-28T10:04:11Z"); err != nil {
		t.Errorf("parse RFC3339: %v", err)
	}
	if _, err := ParseTime("not a time"); err == nil {
		t.Error("ParseTime accepted junk")
	}
}

// TestFileDSNEscapesPath covers a vault whose name would otherwise terminate
// the DSN: the driver hands it to SQLite as a URI, so an unencoded '#' or '?'
// would silently address a different file.
func TestFileDSNEscapesPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"/v/plain", "file:/v/plain?p=1"},
		{"/v/has space", "file:/v/has%20space?p=1"},
		{"/v/hash#tag", "file:/v/hash%23tag?p=1"},
		{"/v/q?mark", "file:/v/q%3Fmark?p=1"},
		{"/v/100%", "file:/v/100%25?p=1"},
	} {
		if got := fileDSN(tc.in, "p=1"); got != tc.want {
			t.Errorf("fileDSN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
