package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	// The driver is registered here, in the one package that opens a database.
	// Every other package reaches SQLite through this one, so there is exactly
	// one place where the pure-Go driver is pulled in and no caller has to
	// remember a blank import.
	_ "modernc.org/sqlite"
)

// Driver is the database/sql driver name this package opens. It is a const so
// that a test can assert the DSN against the one production uses.
const Driver = "sqlite"

const (
	// StateDirName is the per-vault directory holding the database, the
	// single-instance lock, and the backups. The leading dot keeps the walker
	// in §7.4 from ever seeing its contents as vault content.
	StateDirName = ".semiplane"
	// DBName is the SQLite file inside StateDirName.
	DBName = "semiplane.db"
)

// The write DSN is §6.1 verbatim. journal_mode is persistent and is therefore
// set once, here, and deliberately omitted from the read DSN: re-asserting it
// on a read-only connection is an error, not a no-op.
const writePragmas = "_pragma=busy_timeout(5000)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=trusted_schema(0)"

const readPragmas = "_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=trusted_schema(0)"

// DB is the database handle. It owns two pools over one file: a single-connection
// write pool and a many-connection read-only pool. The split is the whole
// reason a reindex does not block a page view (§6.1).
type DB struct {
	write *sql.DB
	read  *sql.DB
	vault string
	path  string
}

// Open opens (creating if absent) the index for a vault.
//
// It creates .semiplane/ 0700 and the database file 0600 if absent. Those modes
// are not hygiene: under D4 the database holds every secret body in plaintext,
// so its permissions are part of the threat model.
func Open(vault string) (*DB, error) {
	if vault == "" {
		return nil, errors.New("store: vault path is empty")
	}
	abs, err := filepath.Abs(vault)
	if err != nil {
		return nil, fmt.Errorf("store: resolve vault path: %w", err)
	}
	dir := filepath.Join(abs, StateDirName)
	if mkdirAllErr := os.MkdirAll(dir, 0o700); mkdirAllErr != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, mkdirAllErr)
	}
	path := filepath.Join(dir, DBName)
	if ensureDBFileErr := ensureDBFile(path); ensureDBFileErr != nil {
		return nil, ensureDBFileErr
	}

	write, err := sql.Open(Driver, fileDSN(path, writePragmas))
	if err != nil {
		return nil, fmt.Errorf("store: open write pool: %w", err)
	}
	// One writer. SQLite serialises writers anyway, and an unbounded pool
	// turns lock contention into SQLITE_BUSY rather than into a queue.
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(0)

	// Ping before the read pool exists: a WAL reader cannot create the -shm
	// file it needs, so the writer must have created it first.
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if pingContextErr := write.PingContext(ctx); pingContextErr != nil {
		_ = write.Close()
		return nil, fmt.Errorf("store: open write pool for %s: %w", path, pingContextErr)
	}

	read, err := sql.Open(Driver, fileDSN(path, readPragmas+"&mode=ro"))
	if err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("store: open read pool: %w", err)
	}
	read.SetMaxOpenConns(runtime.NumCPU())
	read.SetMaxIdleConns(runtime.NumCPU())
	read.SetConnMaxLifetime(0)
	if err := read.PingContext(ctx); err != nil {
		_ = read.Close()
		_ = write.Close()
		return nil, fmt.Errorf("store: open read pool for %s: %w", path, err)
	}

	return &DB{write: write, read: read, vault: abs, path: path}, nil
}

// openTimeout bounds the two pings in Open. A vault on a stalled network mount
// must fail at boot with a clear error rather than hang the process.
const openTimeout = 10 * time.Second

// Writer is the single-connection pool. Every mutation goes through it, and
// every multi-statement mutation must run inside a transaction on it, because
// the pool serialises rather than queues: two concurrent writers would
// otherwise deadlock instead of waiting.
func (db *DB) Writer() *sql.DB { return db.write }

// Reader is the read-only pool, sized at NumCPU. Query traffic goes here so it
// never contends with the indexer.
func (db *DB) Reader() *sql.DB { return db.read }

// Path is the absolute path of the database file.
func (db *DB) Path() string { return db.path }

// Vault is the absolute path of the vault this database indexes.
func (db *DB) Vault() string { return db.vault }

// Close releases both pools. Both errors are reported.
func (db *DB) Close() error {
	var errs []error
	if db.read != nil {
		errs = append(errs, db.read.Close())
	}
	if db.write != nil {
		errs = append(errs, db.write.Close())
	}
	return errors.Join(errs...)
}

// ensureDBFile creates the database file with mode 0600 if it is absent, and
// tightens the mode of a file that already exists. A file restored from a
// backup may have arrived with the umask of whatever created it.
func ensureDBFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("store: create database file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: create database file %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("store: secure permissions on %s: %w", path, err)
	}
	return nil
}

// uriPathEscaper percent-encodes only the characters that would change how
// SQLite reads the DSN. The driver hands the string to sqlite3_open_v2 with
// SQLITE_OPEN_URI, so an unencoded '?' or '#' in a vault path would silently
// truncate it into a different file.
var uriPathEscaper = strings.NewReplacer(
	"%", "%25",
	"?", "%3F",
	"#", "%23",
	" ", "%20",
	"[", "%5B",
	"]", "%5D",
)

func fileDSN(path, query string) string {
	return "file:" + uriPathEscaper.Replace(filepath.ToSlash(path)) + "?" + query
}

// timeLayout is fixed-width on purpose. Several indexes order TEXT timestamps
// lexicographically (revisions_page, pages_updated, secret_events_secret), and
// time.RFC3339Nano trims trailing zeros from the fraction, which makes
// "…:11Z" sort after "…:11.5Z". A zero-padded 9-digit fraction is still valid
// RFC 3339 and compares correctly as text.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// FormatTime renders t for a TEXT timestamp column.
func FormatTime(t time.Time) string { return t.Format(timeLayout) }

// ParseTime reads a timestamp written by FormatTime. It also accepts the
// variable-width RFC 3339 forms, so a value that reached the database another
// way still loads.
func ParseTime(s string) (time.Time, error) {
	if t, err := time.Parse(timeLayout, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: parse time %q: %w", s, err)
	}
	return t, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return FormatTime(*t)
}

// nullIfEmpty maps the Go zero value for a nullable TEXT column to SQL NULL. A
// page with no owning plugin is NULL in the schema and "" in Go, and writing
// "" instead would make "is this a core page" two different queries.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
