package store

import (
	"context"
	"fmt"
	"time"
)

// RevisionSource is where a revision came from. The values are the four the
// schema's CHECK constraint allows.
type RevisionSource string

const (
	// RevisionApp is a write that came through vault.Writer.Save.
	RevisionApp RevisionSource = "app"
	// RevisionExternal is a change the app did not make: an editor, a sync
	// client, or the DM on another machine.
	RevisionExternal RevisionSource = "external"
	// RevisionCreate is the first sighting of a new file.
	RevisionCreate RevisionSource = "create"
	// RevisionDelete records that a file went away.
	RevisionDelete RevisionSource = "delete"
)

// Retention from §8.10. Unbounded revision storage is not acceptable because
// Obsidian autosaves often, so each external change would otherwise add a copy
// of a whole file forever.
const (
	// AppRevisionRetention is how many app-made revisions survive per page. It
	// covers 'app', 'create' and 'delete', all of which are app-made.
	AppRevisionRetention = 50
	// ExternalRevisionRetention is how many external revisions survive per page.
	ExternalRevisionRetention = 5
)

// Revision is a time-frozen copy of a whole file.
//
// content therefore contains whatever secret text the file held at the time.
// That is why a revision is re-segmented and re-authorised at read time and
// never filtered at write time (§8.10), and why revision reading is a P8 concern
// with its own tests rather than something this package can enforce.
type Revision struct {
	// ID is the surrogate key.
	ID int64
	// PageID is the page the file belonged to.
	PageID int64
	// ContentHash is the sha256 of the content.
	ContentHash []byte
	// Content is the whole file as it was.
	Content string
	// AuthorID is the account responsible, or nil for an external change.
	AuthorID *int64
	// At is when the revision was recorded.
	At time.Time
	// Source is one of the four RevisionSource values.
	Source RevisionSource
}

const revisionColumns = `id, page_id, content_hash, content, author_id, at, source`

func scanRevision(s RowScanner) (Revision, error) {
	var (
		r   Revision
		at  string
		src string
	)
	if err := s.Scan(&r.ID, &r.PageID, &r.ContentHash, &r.Content, &r.AuthorID, &at, &src); err != nil {
		return Revision{}, err
	}
	var err error
	if r.At, err = ParseTime(at); err != nil {
		return Revision{}, err
	}
	r.Source = RevisionSource(src)
	return r, nil
}

// AppendRevision records a revision and returns its id. Call it inside the
// indexer's transaction: a revision that is written outside one can be orphaned
// from the page write that justified it.
func AppendRevision(ctx context.Context, e Execer, r Revision) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx,
		`INSERT INTO revisions (page_id, content_hash, content, author_id, at, source)
		 VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		r.PageID, r.ContentHash, r.Content, r.AuthorID, FormatTime(r.At), string(r.Source)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: append revision for page %d: %w", r.PageID, err)
	}
	return id, nil
}

// ListRevisionsByPage returns a page's revisions, newest first, without their
// content. The history panel needs ids and timestamps; only the single-revision
// view needs the bytes.
func ListRevisionsByPage(ctx context.Context, q Queryer, pageID int64, limit int) ([]Revision, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+revisionColumns+` FROM revisions
		 WHERE page_id = ? ORDER BY at DESC, id DESC LIMIT ?`, pageID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list revisions of page %d: %w", pageID, err)
	}
	var out []Revision
	err = ForEach(rows, func(r Rows) error {
		rev, err := scanRevision(r)
		if err != nil {
			return fmt.Errorf("store: scan revision: %w", err)
		}
		out = append(out, rev)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetRevision returns one revision including its content. The bytes are a
// time-frozen copy of a file that may contain secrets the caller cannot read
// now, so this is deliberately not filtered; the caller must re-segment and
// re-authorise before rendering anything (§8.10).
func GetRevision(ctx context.Context, q Queryer, id int64) (Revision, error) {
	rev, err := scanRevision(q.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM revisions WHERE id = ?`, id))
	if err != nil {
		return Revision{}, wrapNoRows(err, fmt.Sprintf("revision %d", id))
	}
	return rev, nil
}

// PruneRevisions applies the §8.10 retention policy for one page: the newest 50
// app-made revisions and the newest 5 external ones survive, everything older
// goes. Call it after appending, inside the same transaction, so a page can
// never transiently exceed its budget.
func PruneRevisions(ctx context.Context, e Execer, pageID int64) (int64, error) {
	// 'create' and 'delete' are app-made too: they are writes this app
	// performed, and treating them as a third bucket would let a page retain
	// unbounded rows if an external tool churned the file.
	n, err := Exec(ctx, e, `DELETE FROM revisions
		 WHERE page_id = ? AND source <> ?
		   AND id NOT IN (
		     SELECT id FROM revisions WHERE page_id = ? AND source <> ?
		     ORDER BY at DESC, id DESC LIMIT ?)`,
		pageID, string(RevisionExternal), pageID, string(RevisionExternal), AppRevisionRetention)
	if err != nil {
		return 0, fmt.Errorf("store: prune app revisions of page %d: %w", pageID, err)
	}
	m, err := Exec(ctx, e, `DELETE FROM revisions
		 WHERE page_id = ? AND source = ?
		   AND id NOT IN (
		     SELECT id FROM revisions WHERE page_id = ? AND source = ?
		     ORDER BY at DESC, id DESC LIMIT ?)`,
		pageID, string(RevisionExternal), pageID, string(RevisionExternal), ExternalRevisionRetention)
	if err != nil {
		return 0, fmt.Errorf("store: prune external revisions of page %d: %w", pageID, err)
	}
	return n + m, nil
}
