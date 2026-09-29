package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Attachment is a non-Markdown file recorded from the index.
//
// There is deliberately no secret id here: visibility is a property of the
// reference, not of the file. A DM embedding a portrait inside a secret must not
// hand the player the image via a guessable URL, and a file referenced both
// inside and outside a secret has no single secret to belong to. The serve path
// therefore evaluates authorization per referencing links row (§8.8).
type Attachment struct {
	// ID is the surrogate key.
	ID int64
	// PageID is the page the file was found beside, or nil for a vault-level
	// file.
	PageID *int64
	// Path is the vault-relative path, forward slashes.
	Path string
	// Mime is the detected content type.
	Mime string
	// SizeBytes is the file size.
	SizeBytes int64
}

const attachmentColumns = `id, page_id, path, mime, size_bytes`

func scanAttachment(s RowScanner) (Attachment, error) {
	var (
		a      Attachment
		pageID sql.NullInt64
	)
	if err := s.Scan(&a.ID, &pageID, &a.Path, &a.Mime, &a.SizeBytes); err != nil {
		return Attachment{}, err
	}
	if pageID.Valid {
		id := pageID.Int64
		a.PageID = &id
	}
	return a, nil
}

// InsertAttachment records a non-Markdown file.
func InsertAttachment(ctx context.Context, e Execer, a Attachment) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx,
		`INSERT INTO attachments (page_id, path, mime, size_bytes) VALUES (?, ?, ?, ?) RETURNING id`,
		a.PageID, a.Path, a.Mime, a.SizeBytes).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: insert attachment %s: %w", a.Path, err)
	}
	return id, nil
}

// GetAttachmentByPath returns an attachment by its vault-relative path.
func GetAttachmentByPath(ctx context.Context, q Queryer, path string) (Attachment, error) {
	a, err := scanAttachment(q.QueryRowContext(ctx,
		`SELECT `+attachmentColumns+` FROM attachments WHERE path = ?`, path))
	if err != nil {
		return Attachment{}, wrapNoRows(err, "attachment "+path)
	}
	return a, nil
}

// ListAttachmentsByPage returns a page's recorded files. The §8.8 serve path
// resolves a requested name against exactly this set, never against the
// filesystem directly, so a name that is not here cannot be served.
func ListAttachmentsByPage(ctx context.Context, q Queryer, pageID int64) ([]Attachment, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+attachmentColumns+` FROM attachments WHERE page_id = ? ORDER BY path`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list attachments of page %d: %w", pageID, err)
	}
	return collectAttachments(rows)
}

// attachmentVisibleSQL is §8.8's rule as one statement: an attachment is served
// if at least one referencing links row for its page is public, or lives inside
// a secret this principal may read.
//
// The join to the attachment row is not a formality. The rule is about a
// *reference*, so a query that counted references without asking whether the
// file is one of the page's recorded attachments would report a DM's secret-only
// image as servable for any name the page happens to mention — and the serve
// path resolves names against the attachments rows precisely so that a file the
// index never recorded cannot be served at all. The `pages p` join is not
// decorative either: the predicate's private branch names it to test ownership.
//
// name is the string both sides carry, and the two are the same string by
// construction: the indexer writes target_raw and attachments.path from one
// extraction of the same token. A caller that resolved a name to some other
// vault-relative path is asking a different question here and gets the safe
// answer, because this package matches exactly and never by basename.
const attachmentVisibleSQL = `SELECT 1
	FROM attachments a
	JOIN links l ON l.source_page_id = a.page_id
	JOIN pages p ON p.id = a.page_id
	WHERE a.page_id = ? AND a.path = ? AND l.kind = ? AND l.target_raw = ?
	  AND (l.secret_id IS NULL
	       OR EXISTS (SELECT 1 FROM secrets s WHERE s.id = l.secret_id AND ` + authz.SecretVisibleSQL + `))`

// AttachmentVisibleTo reports whether one of a page's recorded attachments may
// be served to a principal.
//
// The answer is a bool and never ErrNoRows, so "you may not have it" and "there
// is no such file" are one answer: a route that could tell them apart would be a
// route that confirms the existence of a DM's portrait. A principal who may not
// read public content at all is answered without a query, which is §8.2's bottom
// row rather than a special case of the SQL.
func AttachmentVisibleTo(ctx context.Context, q Queryer, p authz.Principal, pageID int64, name string) (bool, error) {
	if !p.CanReadPublic() {
		return false, nil
	}
	uid, isDM := p.Bind()
	var one int
	err := q.QueryRowContext(ctx, attachmentVisibleSQL+publicOnlySQL(p, `l.secret_id IS NULL`),
		pageID, name, string(LinkAttachment), name,
		sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&one)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: check attachment on page %d: %w", pageID, err)
	}
	return true, nil
}

func collectAttachments(rows *sql.Rows) ([]Attachment, error) {
	var out []Attachment
	err := ForEach(rows, func(r Rows) error {
		a, err := scanAttachment(r)
		if err != nil {
			return fmt.Errorf("store: scan attachment: %w", err)
		}
		out = append(out, a)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteAttachment removes one attachment record.
func DeleteAttachment(ctx context.Context, e Execer, id int64) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM attachments WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete attachment %d: %w", id, err)
	}
	return nil
}

// PluginMigration is one applied plugin schema step. Plugin migrations ride the
// same forward-only mechanism as the core series, keyed by (plugin_id, version),
// so a plugin cannot run DDL at register time.
type PluginMigration struct {
	// PluginID is the plugin that owns the step.
	PluginID string
	// Version is the monotonic step number, from 1.
	Version int
	// AppliedAt is when it was applied.
	AppliedAt time.Time
}

// RecordPluginMigration marks a plugin step as applied. It is idempotent, so a
// plugin that re-registers after a restart does not fail.
func RecordPluginMigration(ctx context.Context, e Execer, m PluginMigration) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO plugin_migrations (plugin_id, version, applied_at) VALUES (?, ?, ?)
		 ON CONFLICT(plugin_id, version) DO NOTHING`,
		m.PluginID, m.Version, FormatTime(m.AppliedAt)); err != nil {
		return fmt.Errorf("store: record migration %d of %s: %w", m.Version, m.PluginID, err)
	}
	return nil
}

// HasPluginMigration reports whether a plugin step has been applied.
func HasPluginMigration(ctx context.Context, q Queryer, pluginID string, version int) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx,
		`SELECT 1 FROM plugin_migrations WHERE plugin_id = ? AND version = ?`,
		pluginID, version).Scan(&one)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: check migration %d of %s: %w", version, pluginID, err)
	}
	return true, nil
}

// AppliedPluginVersion returns the highest applied version of a plugin, or 0.
func AppliedPluginVersion(ctx context.Context, q Queryer, pluginID string) (int, error) {
	var v sql.NullInt64
	err := q.QueryRowContext(ctx,
		`SELECT MAX(version) FROM plugin_migrations WHERE plugin_id = ?`, pluginID).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read applied version of %s: %w", pluginID, err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// ListPluginMigrations returns a plugin's applied steps in order.
func ListPluginMigrations(ctx context.Context, q Queryer, pluginID string) ([]PluginMigration, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT plugin_id, version, applied_at FROM plugin_migrations
		 WHERE plugin_id = ? ORDER BY version`, pluginID)
	if err != nil {
		return nil, fmt.Errorf("store: list migrations of %s: %w", pluginID, err)
	}
	var out []PluginMigration
	err = ForEach(rows, func(r Rows) error {
		var (
			m  PluginMigration
			at string
		)
		if err := r.Scan(&m.PluginID, &m.Version, &at); err != nil {
			return fmt.Errorf("store: scan plugin migration: %w", err)
		}
		var err error
		if m.AppliedAt, err = ParseTime(at); err != nil {
			return err
		}
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Selfwrite is a row of the selfwrites table: proof that this process wrote
// this path, so the watcher can suppress its own echo.
//
// The match is by hash, not by time. A genuine external edit to the same path
// inside the window still differs in hash and still lands, which is the only
// reason a time-based suppression would be dangerous.
type Selfwrite struct {
	// Path is the vault-relative path written.
	Path string
	// Hash is the sha256 of the bytes written.
	Hash []byte
	// ExpiresAt is when the entry stops counting.
	ExpiresAt time.Time
}

const selfwriteWindow = 10 * time.Second

// UpsertSelfwrite records that this process wrote a path. Re-recording a path
// replaces the row, so a path written twice inside the window keeps only the
// newest hash.
func UpsertSelfwrite(ctx context.Context, e Execer, s Selfwrite) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO selfwrites (path, hash, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT(path) DO UPDATE SET hash = excluded.hash, expires_at = excluded.expires_at`,
		s.Path, s.Hash, FormatTime(s.ExpiresAt)); err != nil {
		return fmt.Errorf("store: record selfwrite for %s: %w", s.Path, err)
	}
	return nil
}

// RecordSelfwrite records a selfwrite for path with the standard 10 s window.
func RecordSelfwrite(ctx context.Context, e Execer, path string, hash []byte, now time.Time) error {
	return UpsertSelfwrite(ctx, e, Selfwrite{
		Path:      path,
		Hash:      hash,
		ExpiresAt: now.Add(selfwriteWindow),
	})
}

// SelfwriteMatches reports whether a path's latest recorded selfwrite matches
// the given hash and is still inside its window. The watcher consults this
// before treating a filesystem event as external.
func SelfwriteMatches(ctx context.Context, q Queryer, path string, hash []byte, now time.Time) (bool, error) {
	var (
		stored    []byte
		expiresAt string
	)
	err := q.QueryRowContext(ctx, `SELECT hash, expires_at FROM selfwrites WHERE path = ?`, path).
		Scan(&stored, &expiresAt)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("store: read selfwrite for %s: %w", path, err)
	}
	exp, err := ParseTime(expiresAt)
	if err != nil {
		return false, err
	}
	if now.After(exp) {
		return false, nil
	}
	return bytesEqual(stored, hash), nil
}

// PruneSelfwrites removes entries that expired before a cutoff. It is the boot
// step in §7.5.
func PruneSelfwrites(ctx context.Context, e Execer, before time.Time) (int64, error) {
	n, err := Exec(ctx, e, `DELETE FROM selfwrites WHERE expires_at < ?`, FormatTime(before))
	if err != nil {
		return 0, fmt.Errorf("store: prune selfwrites: %w", err)
	}
	return n, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
