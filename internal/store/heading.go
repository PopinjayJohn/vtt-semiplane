package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

const headingColumns = `page_id, ordinal, level, slug, text, COALESCE(secret_id, '')`

func scanHeading(s RowScanner) (Heading, error) {
	var (
		h    Heading
		page int64
		ord  int64
		lvl  int64
	)
	if err := s.Scan(&page, &ord, &lvl, &h.Slug, &h.Text, &h.SecretID); err != nil {
		return Heading{}, err
	}
	h.PageID = page
	h.Ordinal = int(ord)
	h.Level = int(lvl)
	return h, nil
}

// InsertHeading records one heading, with the secret it lives in if any. A
// heading inside a secret is a fact about a hidden secret, so the secret id is
// mandatory here even though the column allows NULL.
func InsertHeading(ctx context.Context, e Execer, h Heading) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO headings (page_id, ordinal, level, slug, text, secret_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		h.PageID, h.Ordinal, h.Level, h.Slug, h.Text, nullIfEmpty(h.SecretID)); err != nil {
		return fmt.Errorf("store: insert heading on page %d: %w", h.PageID, err)
	}
	return nil
}

// DeleteHeadingsByPage removes every heading of a page.
func DeleteHeadingsByPage(ctx context.Context, e Execer, pageID int64) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM headings WHERE page_id = ?`, pageID); err != nil {
		return fmt.Errorf("store: delete headings of page %d: %w", pageID, err)
	}
	return nil
}

// ListHeadings returns every heading of a page, unfiltered. The indexer and the
// bulk link updater need the file's real structure.
func ListHeadings(ctx context.Context, q Queryer, pageID int64) ([]Heading, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+headingColumns+` FROM headings WHERE page_id = ? ORDER BY ordinal`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list headings of page %d: %w", pageID, err)
	}
	var out []Heading
	err = ForEach(rows, func(r Rows) error {
		h, err := scanHeading(r)
		if err != nil {
			return fmt.Errorf("store: scan heading: %w", err)
		}
		out = append(out, h)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// tocSQL carries the predicate because §8.5 names the table of contents: a
// heading's existence is itself a leak, so the filter happens before the row
// leaves the database, not in the renderer.
const tocSQL = `SELECT ` + headingColumns + `
FROM headings h
JOIN pages p ON p.id = h.page_id
WHERE h.page_id = ?
  AND (h.secret_id IS NULL
       OR EXISTS (SELECT 1 FROM secrets s WHERE s.id = h.secret_id AND ` + authz.SecretVisibleSQL + `))`

// TOC returns the table of contents a principal may see.
func TOC(ctx context.Context, q Queryer, p authz.Principal, pageID int64) ([]Heading, error) {
	uid, isDM := p.Bind()
	rows, err := q.QueryContext(ctx, tocSQL+publicOnlySQL(p, `h.secret_id IS NULL`)+` ORDER BY h.ordinal`,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if err != nil {
		return nil, fmt.Errorf("store: read toc of page %d: %w", pageID, err)
	}
	var out []Heading
	err = ForEach(rows, func(r Rows) error {
		h, err := scanHeading(r)
		if err != nil {
			return fmt.Errorf("store: scan heading: %w", err)
		}
		out = append(out, h)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HeadingCount is the number of rows TOC would return, computed from the
// identical statement.
func HeadingCount(ctx context.Context, q Queryer, p authz.Principal, pageID int64) (int, error) {
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+tocSQL+publicOnlySQL(p, `h.secret_id IS NULL`)+`)`,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count toc of page %d: %w", pageID, err)
	}
	return n, nil
}
