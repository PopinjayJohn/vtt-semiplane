package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// The meta keys, named here once so that a typo is a compile error rather than
// a row that is written and never read.
const (
	// KeySchemaVersion mirrors PRAGMA user_version inside the table, so a
	// backup's meta.json and the live database can be compared without opening
	// SQLite.
	KeySchemaVersion = "schema_version"
	// KeyBootState is 'indexing' or 'ready'. The sync indicator reads it, and
	// pages that are not indexed yet return 503 rather than a wrong answer.
	KeyBootState = "boot_state"
	// KeyFTSGeneration is the schema generation the FTS tables were built with.
	// A tokenizer or column change bumps it, and a mismatch at boot triggers a
	// rebuild (§6.3).
	KeyFTSGeneration = "fts_generation"
	// KeyInstalledAt is when this vault was first opened.
	KeyInstalledAt = "installed_at"
	// KeyLastBackup is when a backup was last completed.
	KeyLastBackup = "last_backup"
	// KeyLastChangeAt is the newest mtime the indexer has seen, used to decide
	// whether a daily backup is warranted (§7.6). It is an RFC 3339 timestamp
	// via FormatTime, NOT an integer: MetaGetInt on it is a caller bug and
	// returns a parse error rather than a silent zero.
	KeyLastChangeAt = "last_change_at"
	// KeyAuthzGeneration increments on every authorization change. It exists
	// to terminate stale live-push streams and to key a future cache
	// (§8.11), and is maintained from day one because retrofitting it would
	// mean replaying history.
	KeyAuthzGeneration = "authz_generation"
)

// The boot states, in the order the boot sequence visits them.
const (
	// BootStateIndexing means the vault walk is in progress.
	BootStateIndexing = "indexing"
	// BootStateReady means the index is complete and the server is serving.
	BootStateReady = "ready"
)

const metaGetSQL = `SELECT value FROM meta WHERE key = ?`
const metaSetSQL = `INSERT INTO meta (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`

// metaBumpSQL increments in the database rather than read-modify-write in Go.
// The read and the write have to be one statement, because a bump is called
// from paths that already hold a transaction and a plain get-then-set would
// lose an increment whenever two of them overlap.
const metaBumpSQL = `INSERT INTO meta (key, value) VALUES (?, '1')
ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(meta.value AS INTEGER) + 1 AS TEXT)
RETURNING CAST(value AS INTEGER)`

// MetaGet reads one meta value.
func MetaGet(ctx context.Context, q Queryer, key string) (string, error) {
	var v string
	if err := q.QueryRowContext(ctx, metaGetSQL, key).Scan(&v); err != nil {
		return "", fmt.Errorf("store: read meta %s: %w", key, wrapNoRows(err, "meta "+key))
	}
	return v, nil
}

// MetaSet writes one meta value.
func MetaSet(ctx context.Context, e Execer, key, value string) error {
	if _, err := e.ExecContext(ctx, metaSetSQL, key, value); err != nil {
		return fmt.Errorf("store: write meta %s: %w", key, err)
	}
	return nil
}

// MetaGetInt reads one meta value as an integer. A missing key reads as zero: a
// counter that has never been touched is zero, and at boot the FTS generation
// must read as 0 so that a never-indexed vault is rebuilt rather than trusted.
func MetaGetInt(ctx context.Context, q Queryer, key string) (int64, error) {
	var v string
	err := q.QueryRowContext(ctx, metaGetSQL, key).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("store: read meta %s: %w", key, err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: meta %s is %q, not an integer: %w", key, v, err)
	}
	return n, nil
}

// MetaBump increments one meta counter and returns its new value. It creates the
// row at 1 if the key is absent.
func MetaBump(ctx context.Context, q Queryer, key string) (int64, error) {
	var v int64
	if err := q.QueryRowContext(ctx, metaBumpSQL, key).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: bump meta %s: %w", key, err)
	}
	return v, nil
}

// AuthzGeneration is the current authorization generation.
func AuthzGeneration(ctx context.Context, q Queryer) (int64, error) {
	return MetaGetInt(ctx, q, KeyAuthzGeneration)
}

// BumpAuthzGeneration increments the authorization generation and returns the
// new value. Call it on every reveal, revoke, role change, page-owner change,
// user disable or delete, and case-collision skip (§8.11).
func BumpAuthzGeneration(ctx context.Context, q Queryer) (int64, error) {
	return MetaBump(ctx, q, KeyAuthzGeneration)
}
