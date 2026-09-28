package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// pageColumns is the one projection of the pages table. Every getter and lister
// selects exactly these, in this order, so a change to the row struct is a
// change to one list rather than to twenty queries.
// PageRef is a lightweight reference to a page, used where only identity and a
// display string are needed (breadcrumb, backlink chip, related list).
type PageRef struct {
	ID    int64
	Path  string
	Title string
}

// Page is a row of the pages table. It is the canonical description of a
// markdown file in the vault.
//
// A Page is derived state. The file is canonical; this row may be rebuilt at
// any time from the vault.
type Page struct {
	// ID is the surrogate key. The vault-relative path is the natural key and
	// is what users, links and URLs use.
	ID int64
	// Path is vault-relative, forward slashes, no leading slash.
	Path string
	// Basename is the file name without the .md extension.
	Basename string
	// Title is the first H1, else the frontmatter title, else the basename.
	Title string
	// Frontmatter is the raw YAML between the --- fences, verbatim. It is
	// stored and re-emitted byte for byte; it is never re-serialised.
	Frontmatter string
	// ContentHash is the sha256 of the whole file.
	ContentHash []byte
	// MTimeUnix is the file's modification time in whole seconds.
	MTimeUnix int64
	// SizeBytes is the file size in bytes.
	SizeBytes int64
	// PageType is the frontmatter `type:` value, or "note".
	PageType string
	// SystemID is the id of the plugin that owns the page type, or "" for core.
	SystemID string
	// OwnerID is the primary owner, mirrored as a page_owners row. It is nil
	// when the page has no owner. page_owners remains the single source of
	// truth for ownership.
	OwnerID *int64
	// CreatedAt is when the page was first indexed.
	CreatedAt time.Time
	// UpdatedAt is when the page was last indexed.
	UpdatedAt time.Time
}

// Href is the canonical URL path of the page. Every internal link in rendered
// output uses it, so the core link-preview interaction has one shape to bind
// to.
func (p Page) Href() string { return "/p/" + p.Path }

// TitleOr returns the title, or a fallback when the title is empty.
func (p Page) TitleOr(fallback string) string {
	if p.Title != "" {
		return p.Title
	}
	return fallback
}

// PageRow is a page as it appears in a list: the identifying fields plus
// whatever the caller needs. It exists so that backlink and search results
// carry no more than they need — a list query must not select
// page_text.body, which would pull whole documents into memory.
type PageRow struct {
	ID    int64
	Path  string
	Title string
}

// SecretRow is the projection of a secret that is safe to hold in memory in a
// context that is not yet authorized. Note that it deliberately has no Body
// field: reading a body requires authz.CanReadSecret to have been consulted
// first, and the only API that returns one is GetSecretByID or
// GetVisibleSecret, both of which are documented as such.
type SecretRow struct {
	ID         string
	PageID     int64
	Ordinal    int
	Visibility string
	AuthorID   int64
	BodyHash   []byte
	Title      string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Link is a row of the links table: an outgoing reference from one page to
// another page, to an attachment, or to a tag.
//
// SecretID is the whole point of the table: it is the secret the reference
// appears in, or "" for a public reference. Every consumer filters on it.
type Link struct {
	ID           int64
	SourcePageID int64
	TargetPageID *int64
	TargetRaw    string
	Kind         LinkKind
	Alias        string
	Heading      string
	BlockRef     string
	SecretID     string
	Line         int
}

// LinkKind is the kind of reference a Link row represents.
type LinkKind string

const (
	LinkWikilink   LinkKind = "wikilink"
	LinkEmbed      LinkKind = "embed"
	LinkMarkdown   LinkKind = "markdown"
	LinkAttachment LinkKind = "attachment"
	LinkTag        LinkKind = "tag"
)

// Heading is a row of the headings table: one heading, at one ordinal, with
// the secret it lives in if any. A heading inside a secret is filtered out of
// the table of contents by the same predicate, because a heading's existence
// is itself a leak.
type Heading struct {
	PageID   int64
	Ordinal  int
	Level    int
	Slug     string
	Text     string
	SecretID string
}

// Tag is a normalised tag name: lowercased, no leading #.
type Tag struct {
	Name string
}

const pageColumns = `p.id, p.path, p.basename, p.title, p.frontmatter, p.content_hash,
	p.mtime_unix, p.size_bytes, p.page_type, p.system_id, p.owner_id,
	p.created_at, p.updated_at`

func scanPage(s RowScanner) (Page, error) {
	var (
		p         Page
		systemID  sql.NullString
		ownerID   sql.NullInt64
		createdAt string
		updatedAt string
	)
	if err := s.Scan(
		&p.ID, &p.Path, &p.Basename, &p.Title, &p.Frontmatter, &p.ContentHash,
		&p.MTimeUnix, &p.SizeBytes, &p.PageType, &systemID, &ownerID,
		&createdAt, &updatedAt,
	); err != nil {
		return Page{}, err
	}
	p.SystemID = systemID.String
	if ownerID.Valid {
		id := ownerID.Int64
		p.OwnerID = &id
	}
	var err error
	if p.CreatedAt, err = ParseTime(createdAt); err != nil {
		return Page{}, err
	}
	if p.UpdatedAt, err = ParseTime(updatedAt); err != nil {
		return Page{}, err
	}
	return p, nil
}

func scanPageRow(s RowScanner) (PageRow, error) {
	var r PageRow
	if err := s.Scan(&r.ID, &r.Path, &r.Title); err != nil {
		return PageRow{}, err
	}
	return r, nil
}

// upsertPageSQL keys on path, which is the natural key, and deliberately leaves
// created_at alone on conflict: a page that is re-indexed a thousand times has
// been created once.
const upsertPageSQL = `INSERT INTO pages
	(path, basename, title, frontmatter, content_hash, mtime_unix, size_bytes,
	 page_type, system_id, owner_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(path) DO UPDATE SET
	basename = excluded.basename,
	title = excluded.title,
	frontmatter = excluded.frontmatter,
	content_hash = excluded.content_hash,
	mtime_unix = excluded.mtime_unix,
	size_bytes = excluded.size_bytes,
	page_type = excluded.page_type,
	system_id = excluded.system_id,
	owner_id = excluded.owner_id,
	updated_at = excluded.updated_at
RETURNING id`

// UpsertPage writes a page row and returns its id. Pass the caller's *sql.Tx:
// the indexer upserts a page and its owners, links, headings and text in one
// transaction, and a reader must not see the page before its derived rows
// exist.
func UpsertPage(ctx context.Context, e Execer, p Page) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx, upsertPageSQL,
		p.Path, p.Basename, p.Title, p.Frontmatter, p.ContentHash,
		p.MTimeUnix, p.SizeBytes, p.PageType, nullIfEmpty(p.SystemID), p.OwnerID,
		FormatTime(p.CreatedAt), FormatTime(p.UpdatedAt),
	).Scan(&id)
	if err != nil {
		return 0, wrapNoRows(err, "page "+p.Path)
	}
	return id, nil
}

// GetPageByPath returns the page at a vault-relative path.
func GetPageByPath(ctx context.Context, q Queryer, path string) (Page, error) {
	p, err := scanPage(q.QueryRowContext(ctx, `SELECT `+pageColumns+` FROM pages p WHERE p.path = ?`, path))
	if err != nil {
		return Page{}, wrapNoRows(err, "page "+path)
	}
	return p, nil
}

// GetPageByID returns a page by id.
func GetPageByID(ctx context.Context, q Queryer, id int64) (Page, error) {
	p, err := scanPage(q.QueryRowContext(ctx, `SELECT `+pageColumns+` FROM pages p WHERE p.id = ?`, id))
	if err != nil {
		return Page{}, wrapNoRows(err, fmt.Sprintf("page %d", id))
	}
	return p, nil
}

// ListPagesByOwner returns the pages a user owns, newest first.
func ListPagesByOwner(ctx context.Context, q Queryer, userID int64) ([]Page, error) {
	return queryPages(ctx, q,
		`SELECT `+pageColumns+` FROM pages p
		 JOIN page_owners po ON po.page_id = p.id
		 WHERE po.user_id = ?
		 ORDER BY p.updated_at DESC, p.id`, userID)
}

// ListPagesByTag returns the pages carrying a tag.
func ListPagesByTag(ctx context.Context, q Queryer, tag string) ([]Page, error) {
	return queryPages(ctx, q,
		`SELECT DISTINCT `+pageColumns+` FROM pages p
		 JOIN page_tags pt ON pt.page_id = p.id
		 WHERE pt.tag = ?
		 ORDER BY p.title COLLATE NOCASE, p.id`, tag)
}

// ListPagesByBasename returns every page whose basename matches, for link
// resolution step 2 (§5.6). There is more than one on a case-insensitive
// filesystem, which is exactly why the caller breaks the tie rather than
// trusting a single row.
func ListPagesByBasename(ctx context.Context, q Queryer, basename string) ([]Page, error) {
	return queryPages(ctx, q,
		`SELECT `+pageColumns+` FROM pages p
		 WHERE p.basename = ? COLLATE NOCASE
		 ORDER BY LENGTH(p.path), p.path`, basename)
}

// ListPagesByAlias returns the pages an alias points at, for link resolution
// step 3 (§5.6).
func ListPagesByAlias(ctx context.Context, q Queryer, alias string) ([]Page, error) {
	return queryPages(ctx, q,
		`SELECT DISTINCT `+pageColumns+` FROM pages p
		 JOIN page_aliases a ON a.page_id = p.id
		 WHERE a.alias = ? COLLATE NOCASE
		 ORDER BY LENGTH(p.path), p.path`, alias)
}

// ListRecentPages returns the most recently updated pages, for the dashboard.
func ListRecentPages(ctx context.Context, q Queryer, limit int) ([]Page, error) {
	return queryPages(ctx, q,
		`SELECT `+pageColumns+` FROM pages p
		 ORDER BY p.updated_at DESC LIMIT ?`, limit)
}

// CountPages returns the number of indexed pages.
func CountPages(ctx context.Context, q Queryer) (int64, error) {
	var n int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM pages`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count pages: %w", err)
	}
	return n, nil
}

// DeletePage removes a page and, by cascade, its owners, aliases, tags, links,
// headings, secrets, revisions and text row.
//
// The FTS row is not covered by the cascade — a content-backed fts5 table has no
// triggers — so it is removed here first, inside the caller's transaction.
// Skipping that would leave unresolvable index rows behind until a rebuild.
func DeletePage(ctx context.Context, e Execer, id int64) error {
	if err := DeletePageText(ctx, e, id); err != nil {
		return err
	}
	if err := DeleteSecretTextsOfPage(ctx, e, id); err != nil {
		return err
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM pages WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete page %d: %w", id, err)
	}
	return nil
}

func queryPages(ctx context.Context, q Queryer, query string, args ...any) ([]Page, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list pages: %w", err)
	}
	var out []Page
	err = ForEach(rows, func(r Rows) error {
		p, err := scanPage(r)
		if err != nil {
			return fmt.Errorf("store: scan page: %w", err)
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PageOwner is one row of page_owners. page_owners is the single source of truth
// for ownership; pages.owner_id records only the primary owner and is always
// mirrored here.
type PageOwner struct {
	// PageID is the owned page.
	PageID int64
	// UserID is the owner.
	UserID int64
	// IsOwner marks the primary owner, the one pages.owner_id points at.
	IsOwner bool
	// AddedAt is when the ownership was granted.
	AddedAt time.Time
}

const addPageOwnerSQL = `INSERT INTO page_owners (page_id, user_id, is_owner, added_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(page_id, user_id) DO UPDATE SET is_owner = excluded.is_owner`

// AddPageOwner grants a user ownership of a page.
//
// It bumps the authorization generation, because ownership is an authorization
// input and not only a display one: a page owner may read that page's `private`
// secrets, so a grant changes who may read a body, and any live-push stream
// captured under the old ownership would keep serving it. The bump and the
// insert are the caller's transaction, so a caller that rolls back for any reason
// leaves the counter alone too.
func AddPageOwner(ctx context.Context, e Execer, po PageOwner) error {
	if _, err := e.ExecContext(ctx, addPageOwnerSQL,
		po.PageID, po.UserID, boolToInt(po.IsOwner), FormatTime(po.AddedAt)); err != nil {
		return fmt.Errorf("store: add owner %d of page %d: %w", po.UserID, po.PageID, err)
	}
	if _, err := BumpAuthzGeneration(ctx, e); err != nil {
		return err
	}
	return nil
}

// RemovePageOwner revokes a user's ownership of a page. It does not touch
// pages.owner_id; the caller that manages the primary owner keeps the two in
// step, and only within the caller's transaction.
//
// It bumps the authorization generation for the reason AddPageOwner does, and the
// direction matters more here: a revoke is the one that must take effect, since
// a stream captured while the user owned the page is serving them a body they may
// no longer fetch.
func RemovePageOwner(ctx context.Context, e Execer, pageID, userID int64) error {
	if _, err := e.ExecContext(ctx,
		`DELETE FROM page_owners WHERE page_id = ? AND user_id = ?`, pageID, userID); err != nil {
		return fmt.Errorf("store: remove owner %d of page %d: %w", userID, pageID, err)
	}
	if _, err := BumpAuthzGeneration(ctx, e); err != nil {
		return err
	}
	return nil
}

// IsPageOwner reports whether a user owns a page.
func IsPageOwner(ctx context.Context, q Queryer, pageID, userID int64) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx,
		`SELECT 1 FROM page_owners WHERE page_id = ? AND user_id = ?`, pageID, userID).Scan(&one)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: check ownership of page %d: %w", pageID, err)
	}
	return true, nil
}

// ListPageOwners returns every owner of a page.
func ListPageOwners(ctx context.Context, q Queryer, pageID int64) ([]PageOwner, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT page_id, user_id, is_owner, added_at FROM page_owners
		 WHERE page_id = ? ORDER BY is_owner DESC, user_id`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list owners of page %d: %w", pageID, err)
	}
	var out []PageOwner
	err = ForEach(rows, func(r Rows) error {
		var (
			po      PageOwner
			isOwner int64
			addedAt string
		)
		if err := r.Scan(&po.PageID, &po.UserID, &isOwner, &addedAt); err != nil {
			return fmt.Errorf("store: scan page owner: %w", err)
		}
		po.IsOwner = isOwner != 0
		var err error
		if po.AddedAt, err = ParseTime(addedAt); err != nil {
			return err
		}
		out = append(out, po)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListPagesForUser returns the ids of the pages a user owns, for the ownership
// filter of a list query that must not select whole page rows.
func ListPagesForUser(ctx context.Context, q Queryer, userID int64) ([]int64, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT page_id FROM page_owners WHERE user_id = ? ORDER BY page_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list pages of user %d: %w", userID, err)
	}
	var out []int64
	err = ForEach(rows, func(r Rows) error {
		var id int64
		if err := r.Scan(&id); err != nil {
			return fmt.Errorf("store: scan page id: %w", err)
		}
		out = append(out, id)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AddPageAlias records an alias for a page, so that [[the-old-name]] keeps
// resolving after a rename (§5.6).
func AddPageAlias(ctx context.Context, e Execer, pageID int64, alias string) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO page_aliases (page_id, alias) VALUES (?, ?)
		 ON CONFLICT(page_id, alias) DO NOTHING`, pageID, alias); err != nil {
		return fmt.Errorf("store: add alias for page %d: %w", pageID, err)
	}
	return nil
}

// RemovePageAlias drops one alias from a page.
func RemovePageAlias(ctx context.Context, e Execer, pageID int64, alias string) error {
	if _, err := e.ExecContext(ctx,
		`DELETE FROM page_aliases WHERE page_id = ? AND alias = ?`, pageID, alias); err != nil {
		return fmt.Errorf("store: remove alias from page %d: %w", pageID, err)
	}
	return nil
}

// ListPageAliases returns a page's aliases, sorted.
func ListPageAliases(ctx context.Context, q Queryer, pageID int64) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT alias FROM page_aliases WHERE page_id = ? ORDER BY alias`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list aliases of page %d: %w", pageID, err)
	}
	var out []string
	err = ForEach(rows, func(r Rows) error {
		var alias string
		if err := r.Scan(&alias); err != nil {
			return fmt.Errorf("store: scan alias: %w", err)
		}
		out = append(out, alias)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
