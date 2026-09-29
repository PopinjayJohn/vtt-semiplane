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

// RevisionMeta is a revision without its bytes.
//
// It is a separate type rather than a Revision with an empty Content, because
// those are not the same thing: a zero Content is indistinguishable from a
// revision whose file was empty, so a history panel that took []Revision would
// have to know which of its rows it is allowed to read. A type with no Content
// field makes the question unaskable, which is the same reason PageRow and
// SecretRow exist.
type RevisionMeta struct {
	// ID is the surrogate key, and what the single-revision read takes.
	ID int64
	// PageID is the page the file belonged to.
	PageID int64
	// ContentHash is the sha256 of the content, which identifies a revision
	// without carrying it.
	ContentHash []byte
	// AuthorID is the account responsible, or nil for an external change.
	AuthorID *int64
	// At is when the revision was recorded.
	At time.Time
	// Source is one of the four RevisionSource values.
	Source RevisionSource
}

// revisionMetaColumns deliberately does not name content. The statement it is
// spliced into must be readable as a fact about that absence: a history panel
// asking for fifty rows would otherwise pull fifty whole files, each of which
// may contain secret plaintext that no read-time authorization has touched yet.
const revisionMetaColumns = `id, page_id, content_hash, author_id, at, source`

// The page's revisions, as a FROM and a WHERE, in one constant. The count below
// the list is the same question asked twice, and a paraphrase is how a badge
// ends up disagreeing with the list beside it.
const revisionMetaFromSQL = `FROM revisions
	WHERE page_id = ?`

const (
	revisionMetaListSQL  = `SELECT ` + revisionMetaColumns + ` ` + revisionMetaFromSQL + ` ORDER BY at DESC, id DESC`
	revisionMetaCountSQL = `SELECT COUNT(*) ` + revisionMetaFromSQL
)

const revisionColumns = `id, page_id, content_hash, content, author_id, at, source`

func scanRevisionMeta(s RowScanner) (RevisionMeta, error) {
	var (
		m   RevisionMeta
		at  string
		src string
	)
	if err := s.Scan(&m.ID, &m.PageID, &m.ContentHash, &m.AuthorID, &at, &src); err != nil {
		return RevisionMeta{}, err
	}
	var err error
	if m.At, err = ParseTime(at); err != nil {
		return RevisionMeta{}, err
	}
	m.Source = RevisionSource(src)
	return m, nil
}

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

// ListRevisionMetaByPage returns a page's revisions, newest first, without their
// content. This is the history panel's read.
//
// The content is not selected and cannot be reached from the result, which is
// the whole point: fifty rows of this are fifty ids and timestamps, and fifty
// rows of ListRevisionsByPage are fifty whole files, each of which may hold
// secret plaintext that has not been re-authorised at read time.
func ListRevisionMetaByPage(ctx context.Context, q Queryer, pageID int64, limit int) ([]RevisionMeta, error) {
	rows, err := q.QueryContext(ctx, revisionMetaListSQL+` LIMIT ?`, pageID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list revision metadata of page %d: %w", pageID, err)
	}
	var out []RevisionMeta
	err = ForEach(rows, func(r Rows) error {
		rev, err := scanRevisionMeta(r)
		if err != nil {
			return fmt.Errorf("store: scan revision metadata: %w", err)
		}
		out = append(out, rev)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountRevisionsByPage returns how many revisions a page has, for the history
// panel's total beside a windowed list.
func CountRevisionsByPage(ctx context.Context, q Queryer, pageID int64) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, revisionMetaCountSQL, pageID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count revisions of page %d: %w", pageID, err)
	}
	return n, nil
}

// ListRevisionsByPage returns a page's revisions, newest first, WITH their
// content. The metadata-only read is ListRevisionMetaByPage, and that is the one
// a panel wants: this one exists for the callers that need the bytes to compare
// or to diff, and it will hand out every secret body a revision ever held.
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
