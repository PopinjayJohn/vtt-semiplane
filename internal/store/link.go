package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

const linkColumns = `id, source_page_id, target_page_id, target_raw, kind,
	alias, heading, block_ref, COALESCE(secret_id, ''), line`

func scanLink(s RowScanner) (Link, error) {
	var (
		l          Link
		targetPage sql.NullInt64
		alias      sql.NullString
		heading    sql.NullString
		blockRef   sql.NullString
		kind       string
	)
	if err := s.Scan(&l.ID, &l.SourcePageID, &targetPage, &l.TargetRaw, &kind,
		&alias, &heading, &blockRef, &l.SecretID, &l.Line); err != nil {
		return Link{}, err
	}
	if targetPage.Valid {
		id := targetPage.Int64
		l.TargetPageID = &id
	}
	l.Kind = LinkKind(kind)
	l.Alias = alias.String
	l.Heading = heading.String
	l.BlockRef = blockRef.String
	return l, nil
}

// InsertLink records one outgoing reference. An unresolved target is a row with
// a nil target_page_id, not a missing row: the broken-links panel needs it, and
// resolution is re-run on every index.
func InsertLink(ctx context.Context, e Execer, l Link) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx,
		`INSERT INTO links
		 (source_page_id, target_page_id, target_raw, kind, alias, heading, block_ref, secret_id, line)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		l.SourcePageID, l.TargetPageID, l.TargetRaw, string(l.Kind),
		nullIfEmpty(l.Alias), nullIfEmpty(l.Heading), nullIfEmpty(l.BlockRef),
		nullIfEmpty(l.SecretID), l.Line).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: insert link on page %d: %w", l.SourcePageID, err)
	}
	return id, nil
}

// DeleteLinksByPage removes every outgoing reference of a page. The indexer
// calls it before reinserting, inside the same transaction.
func DeleteLinksByPage(ctx context.Context, e Execer, pageID int64) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM links WHERE source_page_id = ?`, pageID); err != nil {
		return fmt.Errorf("store: delete links of page %d: %w", pageID, err)
	}
	return nil
}

// SetLinkTargets points a set of links at pages, or un-points them.
//
// Resolution runs on every index pass, and a page that did not exist when a
// link was first written resolves only when it later appears. Doing that with
// the indexer's fallback — re-inserting the referring page's entire links
// table — costs a full re-extract per affected page and, in an in-memory
// implementation, does not survive a restart for a reference that was already
// dangling at boot. Updating the target column is the whole operation: a link's
// text lives in the file, which is canonical, and only the resolved pointer is
// derived.
//
// A target of 0 leaves the link unresolved, so a rename can un-point before it
// re-points without deleting the row the broken-links panel needs.
func SetLinkTargets(ctx context.Context, e Execer, ids []int64, targetPageID int64) error {
	if len(ids) == 0 {
		return nil
	}
	var target any
	if targetPageID != 0 {
		target = targetPageID
	}
	// One statement per id keeps every value a bind parameter; the id list is
	// built from placeholders, never from interpolated values.
	for _, id := range ids {
		if _, err := e.ExecContext(ctx,
			`UPDATE links SET target_page_id = ? WHERE id = ?`, target, id); err != nil {
			return fmt.Errorf("store: set link %d target: %w", id, err)
		}
	}
	return nil
}

// ListLinksByPage returns a page's outgoing references in file order. It is
// unfiltered: this is the indexer's and the bulk link updater's view of what is
// actually written in the file, not a user's view of it.
func ListLinksByPage(ctx context.Context, q Queryer, pageID int64) ([]Link, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+linkColumns+` FROM links WHERE source_page_id = ? ORDER BY line, id`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list links of page %d: %w", pageID, err)
	}
	return collectLinks(rows)
}

// ListUnresolvedLinks returns every link that does not resolve to a page, for
// the broken-links panel.
func ListUnresolvedLinks(ctx context.Context, q Queryer) ([]Link, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+linkColumns+` FROM links
		 WHERE target_page_id IS NULL
		 ORDER BY target_raw COLLATE NOCASE, source_page_id, line`)
	if err != nil {
		return nil, fmt.Errorf("store: list unresolved links: %w", err)
	}
	return collectLinks(rows)
}

// ListLinksToPage returns every recorded reference to a page, unfiltered, with
// the line each was written on. The bulk link updater uses it, and it applies
// its own authorization per affected page before touching anything (§5.6).
func ListLinksToPage(ctx context.Context, q Queryer, targetPageID int64) ([]Link, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+linkColumns+` FROM links
		 WHERE target_page_id = ? ORDER BY source_page_id, line, id`, targetPageID)
	if err != nil {
		return nil, fmt.Errorf("store: list links to page %d: %w", targetPageID, err)
	}
	return collectLinks(rows)
}

func collectLinks(rows *sql.Rows) ([]Link, error) {
	var out []Link
	err := ForEach(rows, func(r Rows) error {
		l, err := scanLink(r)
		if err != nil {
			return fmt.Errorf("store: scan link: %w", err)
		}
		out = append(out, l)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Backlink is one referring occurrence: the page that mentions the target, and
// the line it mentions it on.
type Backlink struct {
	// Page is the referring page.
	Page PageRef
	// Line is the line in that page the reference is written on.
	Line int
}

// backlinksSQL is §6.4's fragment, verbatim in shape, with the canonical
// predicate in the position the plan puts it. `s` and `p` are the aliases
// SecretVisibleSQL is written against, which is why this cannot be
// re-indented or factored: the fragment is text, not a macro.
const backlinksSQL = `SELECT DISTINCT p.id, p.title, p.path, l.line
FROM links l
JOIN pages p ON p.id = l.source_page_id
WHERE l.target_page_id = ?
  AND (l.secret_id IS NULL
       OR EXISTS (SELECT 1 FROM secrets s WHERE s.id = l.secret_id AND ` + authz.SecretVisibleSQL + `))`

// ListBacklinks returns the visible references to a page. A link written inside
// a secret the viewer may not read is filtered out in SQL, before the row
// exists, so neither the list nor its length can reveal it.
func ListBacklinks(ctx context.Context, q Queryer, p authz.Principal, targetPageID int64) ([]Backlink, error) {
	uid, isDM := p.Bind()
	rows, err := q.QueryContext(ctx, backlinksSQL+publicOnlySQL(p, `l.secret_id IS NULL`)+` ORDER BY p.title`,
		targetPageID, sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if err != nil {
		return nil, fmt.Errorf("store: list backlinks of page %d: %w", targetPageID, err)
	}
	var out []Backlink
	err = ForEach(rows, func(r Rows) error {
		var (
			b    Backlink
			line int64
		)
		if err := r.Scan(&b.Page.ID, &b.Page.Title, &b.Page.Path, &line); err != nil {
			return fmt.Errorf("store: scan backlink: %w", err)
		}
		b.Line = int(line)
		out = append(out, b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BacklinkCount is the number of rows ListBacklinks would return.
//
// It is a COUNT over the identical statement, not a paraphrase of it: the
// predicate, the join, the DISTINCT and the filter conditions are literally the
// same constant. A panel that shows "3" while listing 1 is an existence leak,
// and the only defence is that there is nothing to paraphrase.
func BacklinkCount(ctx context.Context, q Queryer, p authz.Principal, targetPageID int64) (int, error) {
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+backlinksSQL+publicOnlySQL(p, `l.secret_id IS NULL`)+`)`,
		targetPageID, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count backlinks of page %d: %w", targetPageID, err)
	}
	return n, nil
}

// CountOutgoingLinks returns how many references a page makes, for the
// unresolved-links counter.
func CountOutgoingLinks(ctx context.Context, q Queryer, pageID int64) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND target_page_id IS NULL`,
		pageID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count outgoing links of page %d: %w", pageID, err)
	}
	return n, nil
}
