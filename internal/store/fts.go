package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// PageText is the public content of one page, and the content table page_fts
// is built over. Secret spans never reach it: a body that appears only inside a
// ```secret fence is not public content and is not searchable by anyone.
type PageText struct {
	// PageID is the page.
	PageID int64
	// Title is the page title, indexed with weight 10.
	Title string
	// Headings is the page's heading text, indexed with weight 5.
	Headings string
	// Body is the public body text, indexed with weight 1.
	Body string
}

// ErrSecretNotIndexable is returned by IndexSecretText for anything that is not
// a table-visible secret. It is a hard error rather than a silent skip: a
// caller that indexes a hidden secret has a bug, and hiding that bug behind a
// no-op would leave the leak in place and the symptom invisible.
var ErrSecretNotIndexable = errors.New("store: only a table-visible secret may be indexed for search")

const pageTextColumns = `page_id, title, headings, body`

func readPageText(ctx context.Context, q Queryer, pageID int64) (PageText, bool, error) {
	var t PageText
	err := q.QueryRowContext(ctx, `SELECT `+pageTextColumns+` FROM page_text WHERE page_id = ?`, pageID).
		Scan(&t.PageID, &t.Title, &t.Headings, &t.Body)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return PageText{}, false, nil
	case err != nil:
		return PageText{}, false, fmt.Errorf("store: read page_text of page %d: %w", pageID, err)
	}
	return t, true, nil
}

// ReplacePageText writes a page's public text and updates its FTS row, inside
// the caller's transaction.
//
// The four statements are in the order FTS5 requires for a content-backed
// table, and the order is the whole difficulty:
//
//  1. replay the OLD values through the 'delete' command, so the terms the row
//     used to contribute are removed from the index;
//  2. update the content table;
//  3. insert the NEW values into the index.
//
// Sending 'delete' for a rowid that is not indexed corrupts the index, which is
// why step 1 is conditional on the row existing. Skipping step 1 instead leaves
// stale terms behind, which is why it is not optional. A caller that bypasses
// this function and writes page_text directly has broken search in a way that
// only a rebuild will fix.
func ReplacePageText(ctx context.Context, e Execer, t PageText) error {
	old, existed, err := readPageText(ctx, e, t.PageID)
	if err != nil {
		return err
	}
	if existed {
		if _, err := e.ExecContext(ctx,
			`INSERT INTO page_fts (page_fts, rowid, title, headings, body) VALUES ('delete', ?, ?, ?, ?)`,
			old.PageID, old.Title, old.Headings, old.Body); err != nil {
			return fmt.Errorf("store: deindex page %d text: %w", t.PageID, err)
		}
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO page_text (page_id, title, headings, body) VALUES (?, ?, ?, ?)
		 ON CONFLICT(page_id) DO UPDATE SET
		   title = excluded.title, headings = excluded.headings, body = excluded.body`,
		t.PageID, t.Title, t.Headings, t.Body); err != nil {
		return fmt.Errorf("store: write page_text of page %d: %w", t.PageID, err)
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO page_fts (rowid, title, headings, body) VALUES (?, ?, ?, ?)`,
		t.PageID, t.Title, t.Headings, t.Body); err != nil {
		return fmt.Errorf("store: index page %d text: %w", t.PageID, err)
	}
	return nil
}

// DeletePageText removes a page's public text and its FTS row.
//
// A cascade from `DELETE FROM pages` removes the page_text row but leaves the
// FTS row behind, because a content-backed fts5 table has no triggers. The
// indexer must call this before deleting a page; DeletePage does it for you.
func DeletePageText(ctx context.Context, e Execer, pageID int64) error {
	old, existed, err := readPageText(ctx, e, pageID)
	if err != nil {
		return err
	}
	if existed {
		if _, err := e.ExecContext(ctx,
			`INSERT INTO page_fts (page_fts, rowid, title, headings, body) VALUES ('delete', ?, ?, ?, ?)`,
			old.PageID, old.Title, old.Headings, old.Body); err != nil {
			return fmt.Errorf("store: deindex page %d text: %w", pageID, err)
		}
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM page_text WHERE page_id = ?`, pageID); err != nil {
		return fmt.Errorf("store: delete page_text of page %d: %w", pageID, err)
	}
	return nil
}

func readSecretText(ctx context.Context, q Queryer, secretID string) (string, int64, bool, error) {
	var (
		body string
		row  int64
	)
	err := q.QueryRowContext(ctx,
		`SELECT body, fts_rowid FROM secret_text WHERE secret_id = ?`, secretID).Scan(&body, &row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", 0, false, nil
	case err != nil:
		return "", 0, false, fmt.Errorf("store: read secret_text of %s: %w", secretID, err)
	}
	return body, row, true, nil
}

// IndexSecretText puts a revealed secret's body into the search index, and only
// a table-visible secret may be indexed. A hidden secret is not filtered out of
// a search result; it is never in the index to begin with, which is a structural
// property rather than a predicate that could be forgotten (§6.3).
//
// The visibility argument is checked here rather than in SQL so that this
// package contains no SQL comparison against a visibility value at all.
func IndexSecretText(ctx context.Context, e Execer, secretID string, visibility authz.Visibility, body string) error {
	if visibility != authz.VisibilityTable {
		return fmt.Errorf("%w: secret %s is %q", ErrSecretNotIndexable, secretID, visibility)
	}
	old, row, existed, err := readSecretText(ctx, e, secretID)
	if err != nil {
		return err
	}
	if existed {
		if _, err := e.ExecContext(ctx,
			`INSERT INTO secret_fts (secret_fts, rowid, body) VALUES ('delete', ?, ?)`,
			row, old); err != nil {
			return fmt.Errorf("store: deindex secret %s: %w", secretID, err)
		}
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO secret_text (secret_id, body) VALUES (?, ?)
		 ON CONFLICT(secret_id) DO UPDATE SET body = excluded.body`,
		secretID, body); err != nil {
		return fmt.Errorf("store: write secret_text of %s: %w", secretID, err)
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO secret_fts (rowid, body)
		 SELECT fts_rowid, body FROM secret_text WHERE secret_id = ?`, secretID); err != nil {
		return fmt.Errorf("store: index secret %s: %w", secretID, err)
	}
	return nil
}

// DeleteSecretText removes a secret's body from the search index and from the
// content table. A revoke calls it, so the terms in a revoked secret become
// unsearchable immediately rather than at the next restart.
func DeleteSecretText(ctx context.Context, e Execer, secretID string) error {
	old, row, existed, err := readSecretText(ctx, e, secretID)
	if err != nil {
		return err
	}
	if existed {
		if _, err := e.ExecContext(ctx,
			`INSERT INTO secret_fts (secret_fts, rowid, body) VALUES ('delete', ?, ?)`,
			row, old); err != nil {
			return fmt.Errorf("store: deindex secret %s: %w", secretID, err)
		}
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM secret_text WHERE secret_id = ?`, secretID); err != nil {
		return fmt.Errorf("store: delete secret_text of %s: %w", secretID, err)
	}
	return nil
}

// DeleteSecretTextsOfPage removes the search-index copies of every secret on a
// page, which is what a cascade on `DELETE FROM secrets` would otherwise leave
// behind. The indexer calls it before reinserting a page's fences; the reason is
// the same as for DeletePageText.
func DeleteSecretTextsOfPage(ctx context.Context, e Execer, pageID int64) error {
	rows, err := e.QueryContext(ctx, `SELECT secret_id FROM secret_text WHERE secret_id IN
		(SELECT id FROM secrets WHERE page_id = ?)`, pageID)
	if err != nil {
		return fmt.Errorf("store: list indexed secrets of page %d: %w", pageID, err)
	}
	var ids []string
	err = ForEach(rows, func(r Rows) error {
		var id string
		if scanErr := r.Scan(&id); scanErr != nil {
			return fmt.Errorf("store: scan secret id: %w", scanErr)
		}
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := DeleteSecretText(ctx, e, id); err != nil {
			return err
		}
	}
	return nil
}

// RebuildPageFTS rebuilds page_fts from page_text. It is the recovery path after
// a tokenizer or column change, not something a normal write does.
func RebuildPageFTS(ctx context.Context, e Execer) error {
	if _, err := e.ExecContext(ctx, `INSERT INTO page_fts (page_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("store: rebuild page fts: %w", err)
	}
	return nil
}

// RebuildSecretFTS repopulates secret_text from secrets and rebuilds
// secret_fts, which is §6.3's regeneration step for the secret index.
//
// The two statements below select on visibility with the canonical constant as
// a bind parameter. That is not a hand-rolled read predicate: nothing here is
// returned to a principal, there is no principal in a boot-time rebuild, and
// the value is authz.VisibilityTable rather than a literal, so it cannot drift
// from the constant the read path uses. The rule this package does obey without
// exception is that no query returning a secret-derived row to a principal
// filters on anything but authz.SecretVisibleSQL.
func RebuildSecretFTS(ctx context.Context, e Execer) error {
	table := string(authz.VisibilityTable)
	if _, err := e.ExecContext(ctx,
		`DELETE FROM secret_text WHERE secret_id IN
		 (SELECT id FROM secrets WHERE visibility <> ?)`, table); err != nil {
		return fmt.Errorf("store: drop hidden secrets from the search index: %w", err)
	}
	if _, err := e.ExecContext(ctx,
		`INSERT INTO secret_text (secret_id, body)
		 SELECT id, body FROM secrets WHERE visibility = ?
		 ON CONFLICT(secret_id) DO UPDATE SET body = excluded.body`, table); err != nil {
		return fmt.Errorf("store: repopulate secret search index: %w", err)
	}
	if _, err := e.ExecContext(ctx, `INSERT INTO secret_fts (secret_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("store: rebuild secret fts: %w", err)
	}
	return nil
}

// CheckSecretIndexInvariant returns the number of rows in secret_text whose
// secret is not table-visible. It must always be zero.
//
// It exists so the invariant is checked rather than assumed: a bug that indexes
// a hidden secret is a leak, and the difference between finding it in a test and
// finding it in a vault is one assertion.
func CheckSecretIndexInvariant(ctx context.Context, q Queryer) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM secret_text st
		 JOIN secrets s ON s.id = st.secret_id
		 WHERE NOT (s.visibility = ?)`,
		string(authz.VisibilityTable)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: check secret index invariant: %w", err)
	}
	return n, nil
}

// NeedsFTSRebuild reports whether the FTS tables were built by a different
// generation than the current schema, which is the boot check in §7.5 step 4.
func NeedsFTSRebuild(ctx context.Context, q Queryer) (bool, error) {
	fts, err := MetaGetInt(ctx, q, KeyFTSGeneration)
	if err != nil {
		return false, err
	}
	schema, err := MetaGetInt(ctx, q, KeySchemaVersion)
	if err != nil {
		return false, err
	}
	return fts != schema, nil
}

// MarkFTSGeneration records that the FTS tables now match a schema generation.
// The indexer calls it after a successful rebuild, so a vault that has been
// rebuilt once does not rebuild on every boot.
func MarkFTSGeneration(ctx context.Context, e Execer, generation int64) error {
	return MetaSet(ctx, e, KeyFTSGeneration, fmt.Sprintf("%d", generation))
}
