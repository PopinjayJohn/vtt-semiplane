package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// TagSource records where a tag came from. The column is a CHECK constraint, so
// these three values are the whole set.
type TagSource string

const (
	// TagFromFrontmatter is a tag written in the YAML frontmatter.
	TagFromFrontmatter TagSource = "frontmatter"
	// TagFromInline is a #tag found in the body.
	TagFromInline TagSource = "inline"
)

// PageTag is one page_tags row: a tag on a page, from one source, inside one
// secret or in public text.
type PageTag struct {
	// PageID is the tagged page.
	PageID int64
	// Tag is the normalised name, lowercased, without the '#'.
	Tag string
	// Source is frontmatter or inline.
	Source TagSource
	// SecretID is the secret the tag appears in, or "" when it is public. A tag
	// that exists only inside a secret must not appear in a player's tag cloud,
	// and this column is the only thing that can say so.
	SecretID string
}

// TagCount is a tag and how many pages carry it, for the tag cloud.
type TagCount struct {
	// Name is the normalised tag.
	Name string
	// PageCount is the number of pages a principal may see carrying the tag. It
	// is computed with the canonical visibility predicate, so a tag that only
	// appears inside a secret the principal may not read counts as zero rather
	// than leaking its existence through the number.
	PageCount int
}

// listTagsSQL carries the predicate because §6.4 names tag counts as one of the
// queries that must use it. page_tags.secret_id is the empty string for a public
// tag, so the EXISTS is only evaluated for the tags that appear inside a secret.
// It stops after the WHERE clause so the anonymous public-only filter can be
// inserted before GROUP BY, where it belongs; assembling it anywhere else would
// put a stray AND after the ORDER BY.
const listTagsSQL = `SELECT t.name, COUNT(DISTINCT pt.page_id)
	FROM tags t
	JOIN page_tags pt ON pt.tag = t.name
	JOIN pages p ON p.id = pt.page_id
	WHERE pt.secret_id = ''
	   OR EXISTS (SELECT 1 FROM secrets s
	              WHERE s.id = pt.secret_id AND ` + authz.SecretVisibleSQL + `)`

const listTagsOrderSQL = ` GROUP BY t.name ORDER BY t.name COLLATE NOCASE`

// ListTags returns every tag with the number of pages a principal may see
// carrying it.
func ListTags(ctx context.Context, q Queryer, p authz.Principal) ([]TagCount, error) {
	uid, isDM := p.Bind()
	rows, err := q.QueryContext(ctx, listTagsSQL+publicOnlySQL(p, `pt.secret_id = ''`)+listTagsOrderSQL,
		sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if err != nil {
		return nil, fmt.Errorf("store: list tags: %w", err)
	}
	var out []TagCount
	err = ForEach(rows, func(r Rows) error {
		var t TagCount
		if scanErr := r.Scan(&t.Name, &t.PageCount); scanErr != nil {
			return fmt.Errorf("store: scan tag: %w", scanErr)
		}
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TagCountFor returns the number of pages a principal may see carrying a tag.
func TagCountFor(ctx context.Context, q Queryer, p authz.Principal, tag string) (int, error) {
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT pt.page_id)
		 FROM page_tags pt
		 JOIN pages p ON p.id = pt.page_id
		 WHERE pt.tag = ?
		   AND (pt.secret_id = ''
		        OR EXISTS (SELECT 1 FROM secrets s
		                    WHERE s.id = pt.secret_id AND `+authz.SecretVisibleSQL+`))`+publicOnlySQL(p, `pt.secret_id = ''`),
		tag, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count pages for tag %s: %w", tag, err)
	}
	return n, nil
}

// ListTagsForPage returns a page's tags, without the filter: the indexer and
// the editor need what is actually on the page.
func ListTagsForPage(ctx context.Context, q Queryer, pageID int64) ([]PageTag, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT page_id, tag, source, secret_id FROM page_tags
		 WHERE page_id = ? ORDER BY tag, source`, pageID)
	if err != nil {
		return nil, fmt.Errorf("store: list tags of page %d: %w", pageID, err)
	}
	var out []PageTag
	err = ForEach(rows, func(r Rows) error {
		var pt PageTag
		if scanErr := r.Scan(&pt.PageID, &pt.Tag, &pt.Source, &pt.SecretID); scanErr != nil {
			return fmt.Errorf("store: scan page tag: %w", scanErr)
		}
		out = append(out, pt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReplacePageTags sets a page's tags to exactly those supplied, inside the
// caller's transaction. A tag name absent from the list is removed, so a
// re-index that drops a tag actually drops the row.
func ReplacePageTags(ctx context.Context, e Execer, pageID int64, tags []PageTag) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM page_tags WHERE page_id = ?`, pageID); err != nil {
		return fmt.Errorf("store: clear tags of page %d: %w", pageID, err)
	}
	for _, pt := range tags {
		pt.PageID = pageID
		if _, err := e.ExecContext(ctx,
			`INSERT INTO tags (name) VALUES (?) ON CONFLICT(name) DO NOTHING`, pt.Tag); err != nil {
			return fmt.Errorf("store: register tag %s: %w", pt.Tag, err)
		}
		if _, err := e.ExecContext(ctx,
			`INSERT INTO page_tags (page_id, tag, source, secret_id) VALUES (?, ?, ?, ?)`,
			pageID, pt.Tag, string(pt.Source), pt.SecretID); err != nil {
			return fmt.Errorf("store: tag %s on page %d: %w", pt.Tag, pageID, err)
		}
	}
	return nil
}

// PruneOrphanTags removes tag names no page carries any more, so the tag list
// does not grow forever as files are renamed and retagged.
func PruneOrphanTags(ctx context.Context, e Execer) (int64, error) {
	n, err := Exec(ctx, e,
		`DELETE FROM tags WHERE name NOT IN (SELECT tag FROM page_tags)`)
	if err != nil {
		return 0, fmt.Errorf("store: prune orphan tags: %w", err)
	}
	return n, nil
}
