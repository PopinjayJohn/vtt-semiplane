package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Queryer is the read surface store's queries need. *sql.DB, *sql.Tx and
// *sql.Conn all satisfy it, which is how a caller runs a read inside the same
// transaction as the write that made it visible — the indexer's whole contract
// is that a reader never sees a half-indexed page (§7.2 step 8).
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Execer is Queryer plus writes. Every mutating function in this package takes
// an Execer rather than a *sql.DB, so the caller chooses the transaction and
// the package never opens one implicitly.
type Execer interface {
	Queryer
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// RowScanner is the single-row scan surface, satisfied by both *sql.Row and
// *sql.Rows.
type RowScanner interface {
	Scan(dest ...any) error
}

// Rows is what ForEach hands to its callback: the three methods a row loop
// needs and nothing else. Handing out the interface rather than *sql.Rows means
// a test can drive ForEach without a database, and a caller cannot reach past
// the iteration it was given.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// ForEach runs fn once per row and returns the first error from either side.
//
// This helper exists because of the classic Go database bug: a loop over
// sql.Rows that checks the callback's error but not rows.Err() reports success
// when iteration failed part way through, silently truncating the result set.
// ForEach also closes rows, which the manual pattern usually forgets on the
// error paths.
func ForEach(rows *sql.Rows, fn func(Rows) error) error {
	if rows == nil {
		return errors.New("store: ForEach called with no rows")
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Exec runs a statement that returns no rows and reports how many rows it
// touched.
func Exec(ctx context.Context, e Execer, query string, args ...any) (int64, error) {
	res, err := e.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ErrNoRows reports a missing row. Every single-row getter in this package
// returns it, so a caller can tell "not found" from "the query failed" without
// inspecting driver-specific error text.
var ErrNoRows = errors.New("store: no such row")

func wrapNoRows(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", what, ErrNoRows)
	}
	return fmt.Errorf("%s: %w", what, err)
}
