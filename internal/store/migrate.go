package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is one embedded, forward-only schema step.
type Migration struct {
	// Version is the schema version the file takes the database to. It is the
	// numeric prefix of the filename and is also written to PRAGMA user_version.
	Version int
	// Name is the rest of the filename, for the boot report and errors.
	Name string
	// SQL is the file's contents, executed verbatim inside one transaction.
	SQL string
}

// Filename is the embedded path of the migration.
func (m Migration) Filename() string { return MigrationDir + "/" + m.versionsName() }

func (m Migration) versionsName() string {
	return fmt.Sprintf("%04d_%s.sql", m.Version, m.Name)
}

// MigrationDir is the directory the migration series is embedded from.
const MigrationDir = "migrations"

// Migrations returns the embedded series in version order. It reads the
// embedded filesystem on every call rather than caching, so a test that adds a
// fixture migration sees it; the series is short and the cost is irrelevant
// next to the migration it guards.
func Migrations() []Migration {
	entries, err := migrationFS.ReadDir(MigrationDir)
	if err != nil {
		// The embed directive above guarantees the directory exists; a failure
		// here is a build problem, not a runtime condition.
		panic("store: embedded migrations unreadable: " + err.Error())
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, err := parseMigrationName(e.Name())
		if err != nil {
			panic("store: embedded migration filename: " + err.Error())
		}
		b, err := migrationFS.ReadFile(path.Join(MigrationDir, e.Name()))
		if err != nil {
			panic("store: embedded migration unreadable: " + err.Error())
		}
		out = append(out, Migration{Version: version, Name: name, SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			panic(fmt.Sprintf("store: two migrations claim version %d", out[i].Version))
		}
	}
	return out
}

func parseMigrationName(name string) (version int, label string, err error) {
	base, ok := strings.CutSuffix(name, ".sql")
	if !ok {
		return 0, "", fmt.Errorf("%q has no .sql suffix", name)
	}
	num, label, ok := strings.Cut(base, "_")
	if !ok || label == "" {
		return 0, "", fmt.Errorf("%q is not NNN_name.sql", name)
	}
	version, err = strconv.Atoi(num)
	if err != nil || version < 1 {
		return 0, "", fmt.Errorf("%q does not start with a positive version", name)
	}
	return version, label, nil
}

// SchemaVersion is the highest version the embedded series reaches, which is
// the version this binary supports.
func SchemaVersion() int {
	ms := Migrations()
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].Version
}

// ErrSchemaTooNew is the sentinel a SchemaTooNewError matches with errors.Is.
// The situation is not recoverable by retrying or by passing a flag: the file on
// disk was written by a newer semiplane, and running the old binary against it
// would mean writing a schema the newer binary cannot read.
var ErrSchemaTooNew = errors.New("database schema is newer than this binary")

// SchemaTooNewError reports a database written by a newer semiplane.
type SchemaTooNewError struct {
	// Found is the database's user_version.
	Found int
	// Supports is the highest version this binary's embedded series reaches.
	Supports int
}

func (e *SchemaTooNewError) Error() string {
	return fmt.Sprintf("database schema v%d is newer than this binary (supports v%d); upgrade semiplane", e.Found, e.Supports)
}

// Is reports ErrSchemaTooNew for any SchemaTooNewError.
func (e *SchemaTooNewError) Is(target error) bool { return target == ErrSchemaTooNew }

// Migrate brings db to the highest embedded version.
//
// The order is fixed by §6.5 and is not negotiable: take a backup first, always
// (a nil hook is an error, not an implicit "skip"), then apply each pending file
// in its own transaction, then record the version. A migration that fails leaves
// user_version where it was, so the next boot retries exactly that file.
//
// There are no down migrations. A user_version above this binary's series is
// refused before the backup hook runs, because refusing to start is the only
// safe answer and taking a backup first would be misleading.
func Migrate(ctx context.Context, db *sql.DB, backup func(context.Context) error) error {
	if backup == nil {
		return errors.New("store: migrate requires a backup hook")
	}
	current, err := UserVersion(ctx, db)
	if err != nil {
		return err
	}
	head := SchemaVersion()
	if current > head {
		return &SchemaTooNewError{Found: current, Supports: head}
	}
	if err := backup(ctx); err != nil {
		return fmt.Errorf("store: backup before migration: %w", err)
	}

	for _, m := range Migrations() {
		if m.Version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	// Re-read rather than trusting the writes: a version that did not land is a
	// boot that will silently skip a migration next time.
	after, err := UserVersion(ctx, db)
	if err != nil {
		return err
	}
	if after != head {
		return fmt.Errorf("store: migration reached v%d but database reports v%d", head, after)
	}
	return stampMeta(ctx, db, head)
}

// stampMeta mirrors the schema version into the meta table and records the
// install time once.
//
// The mirror is what §7.5 step 4 compares against meta.fts_generation to decide
// whether the FTS tables were built by a different generation. Without it, a
// tokenizer change would never trigger a rebuild, because user_version is not
// readable from a backup's meta.json without opening SQLite.
func stampMeta(ctx context.Context, db *sql.DB, version int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin meta stamp: %w", err)
	}
	defer tx.Rollback()

	if err := MetaSet(ctx, tx, KeySchemaVersion, strconv.Itoa(version)); err != nil {
		return err
	}
	var n int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM meta WHERE key = ?`, KeyInstalledAt).Scan(&n); err != nil {
		return fmt.Errorf("store: read meta %s: %w", KeyInstalledAt, err)
	}
	if n == 0 {
		if err := MetaSet(ctx, tx, KeyInstalledAt, FormatTime(time.Now())); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit meta stamp: %w", err)
	}
	return nil
}

// applyMigration runs one migration file in its own transaction.
//
// PRAGMA user_version is written inside that transaction on purpose. It lives in
// the database header, so a failure rolls the version back with the schema and
// the step is retried from a clean state rather than being marked applied over
// a half-built schema.
func applyMigration(ctx context.Context, db *sql.DB, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %04d_%s: %w", m.Version, m.Name, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: apply migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, setUserVersionSQL(m.Version)); err != nil {
		return fmt.Errorf("store: record schema version %d: %w", m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration %04d_%s: %w", m.Version, m.Name, err)
	}
	return nil
}

// setUserVersionSQL renders the one statement in this package that cannot be
// parameterised.
//
// SQLite pragmas accept no bind parameters, so the version has to be written
// into the statement. That is safe here and only here: the value is an int
// parsed from an embedded migration's own filename, never anything a request,
// a file, or a plugin supplied.
func setUserVersionSQL(version int) string {
	return "PRAGMA user_version = " + strconv.Itoa(version)
}

// UserVersion is the database's current PRAGMA user_version.
func UserVersion(ctx context.Context, q Queryer) (int, error) {
	var v int
	if err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}
