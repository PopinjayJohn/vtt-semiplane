package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// The page reads a plugin's host hands out, and the narrowness of them.
//
// A plugin is first-party Go code, so nothing here stops one from reaching for a
// database another way; what the surface does is make the wrong thing
// inexpressible in the ordinary case. Every function below takes the principal
// as a parameter and applies authz.SecretVisibleSQL itself, so a plugin that
// forgets the check gets the right answer rather than every row — the opposite of
// the failure mode of a raw Queryer, where forgetting is silent and total.
//
// The three rules that make this safe, and that a reader should check any future
// addition against:
//
//   - No function here returns secret-derived text. PageSummary.Excerpt comes
//     from page_text.body, which the indexer writes from md.Doc.PublicBody() and
//     nothing else, so a secret body is not in the table to be selected. This is
//     a property of what is stored, not of a filter somebody has to remember.
//   - Every list has a matching count that reads the identical FROM and WHERE
//     out of the same constant, so a badge cannot disagree with the list beside
//     it.
//   - Every function takes authz.Principal. A list-of-titles query that cannot
//     filter is a query whose filtering gets added later by someone in a hurry,
//     in a handler, in a post-filter, where the count and the list stop
//     agreeing.

// SummaryExcerptMaxChars is the longest public excerpt a summary carries.
//
// It is a length cap and not a truncation of the source: a page of two hundred
// hidden secrets and a page of none both answer with at most this many bytes, so
// response size cannot be used to infer what a reader may not see. The value
// itself is a reading-length budget, chosen so that a link-preview card is a
// card.
const SummaryExcerptMaxChars = 200

// PageSummary is the public card of one page: what a link preview shows.
//
// It carries no secret-derived field and no visibility decision, because both
// were made before the row existed. Excerpt is public text by construction,
// and a summary of a page the principal may not read is ErrNoRows rather than a
// summary with something removed from it.
type PageSummary struct {
	// ID is the page id, which is what an internal link carries in its
	// data-wikilink attribute.
	ID int64
	// Path is vault-relative, and it is the same value the page's own URL is
	// built from.
	Path string
	// Title is the page's title, or its basename when it has none.
	Title string
	// Excerpt is the leading public text, capped at SummaryExcerptMaxChars. It
	// is never secret-derived and never carries a redaction placeholder: the
	// spans a secret occupied are not in the source, so there is nothing to
	// replace and no marker whose shape could leak the size of what it hid.
	Excerpt string
	// Tags are the page's public tags, sorted. A tag written inside a secret the
	// principal may not read is absent rather than greyed out, for the reason the
	// excerpt has no placeholder.
	Tags []string
	// UpdatedAt is the page's last indexed modification time.
	UpdatedAt time.Time
}

// Href is the page's canonical URL, the same one Page.Href builds and the one
// a link preview's reader is sent to when they follow the card.
func (s PageSummary) Href() string { return "/p/" + s.Path }

// pageSummaryFromSQL is the FROM and WHERE of the summary read.
//
// The join to page_text is an INNER join on purpose: a page with no public text
// row has no excerpt, and a preview card whose body is empty and whose title is
// the basename is a worse answer than declining the preview altogether. The
// caller reads ErrNoRows as "no preview for this page", which is the same
// answer a page that does not exist gets.
const pageSummaryFromSQL = `FROM pages p
	JOIN page_text pt ON pt.page_id = p.id
	WHERE p.id = ?`

// The excerpt is bounded by the query rather than by Go.
//
// substr is applied in SQL so that a 400 KiB page hands back 200 characters
// rather than being read whole and then cut, which is the difference between a
// summary endpoint's cost being independent of page size and being a way to make
// the server allocate whatever the vault's largest file is. It counts
// characters, so the cap means the same thing in every encoding, and a
// multi-byte rune is never cut in half by the database leaving a replacement
// character in the card.
//
// The bound is one character wider than the budget so that Go can tell "exactly
// at the limit" from "there was more", and only append the ellipsis in the
// second case. An ellipsis on an excerpt that was never truncated tells the
// reader the page ended there.
const pageSummarySQL = `SELECT p.id, p.path, p.title, p.updated_at,
	substr(pt.body, 1, ?) AS excerpt, LENGTH(pt.body) > ? AS clipped ` +
	pageSummaryFromSQL

// GetPageSummary returns the public card for one page.
//
// ErrNoRows means one of three things that a reader must not be able to tell
// apart: the page does not exist, the principal may not read it, or it has no
// public text. The first two are the property that matters and the third is
// folded in because a preview that declines is the documented degradation; all
// three answer the same way so that a summary endpoint cannot become a way to
// probe for pages.
func GetPageSummary(ctx context.Context, q Queryer, p authz.Principal, pageID int64) (PageSummary, error) {
	// A principal who may not read public content at all gets nothing, and the
	// statement is not sent. §8.2's bottom row: an unauthenticated request sees
	// no secret, and an unauthenticated request with anonymous read off sees no
	// page either, so the check belongs on the principal rather than in SQL.
	if !p.CanReadPublic() {
		return PageSummary{}, wrapNoRows(ErrNoRows, "page summary")
	}
	var (
		out       PageSummary
		updatedAt string
		clipped   int
	)
	err := q.QueryRowContext(ctx, pageSummarySQL,
		SummaryExcerptMaxChars+1, SummaryExcerptMaxChars, pageID).
		Scan(&out.ID, &out.Path, &out.Title, &updatedAt, &out.Excerpt, &clipped)
	// errors.Is, not ==. Every other read in this package wraps with %w, and a
	// Queryer that does the same would hand back a wrapped sql.ErrNoRows that a
	// == comparison silently fails to recognise — which is not a wrong answer
	// here so much as a wrong *shape*: a real error would be reported as a
	// missing page, and a missing page is the answer the preview route maps to
	// 404. A wrapped error must not be able to become a 404 by losing a compare.
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PageSummary{}, wrapNoRows(ErrNoRows, "page summary")
		}
		return PageSummary{}, fmt.Errorf("store: get page summary: %w", err)
	}
	// The ellipsis is a claim about the source, not about the card, so it is
	// added only when the database says there was more to say. A card whose text
	// ended at the budget with no marker is a page that ended there, and one that
	// was cut should not pretend otherwise.
	if clipped != 0 {
		out.Excerpt = strings.TrimSpace(out.Excerpt) + "…"
	}
	tags, err := publicTagsFor(ctx, q, p, pageID)
	if err != nil {
		return PageSummary{}, err
	}
	out.Tags = tags
	if out.UpdatedAt, err = ParseTime(updatedAt); err != nil {
		return PageSummary{}, err
	}
	return out, nil
}

// publicTagsFor returns a page's tags as this principal may see them.
//
// A page_tags row whose secret_id is set was written inside a secret, and it is
// filtered by the same predicate every other tag query uses. The tag cloud and
// the tag page already apply it, so a preview that did not would make a hidden
// tag visible on a surface the reader can reach without typing the tag.
//
// The join to pages is not decorative. authz.SecretVisibleSQL names aliases `s`
// and `p` — the secret and the page that owns it, which the private branch needs
// in order to test ownership — and tagVisibleSQL is written against the same
// names. A query that filters a page's tags without introducing both aliases is
// a query that does not compile, and the compile error is the good outcome; the
// bad one is a query that renames one and silently counts the wrong ownership.
func publicTagsFor(ctx context.Context, q Queryer, p authz.Principal, pageID int64) ([]string, error) {
	uid, isDM := p.Bind()
	rows, err := q.QueryContext(ctx,
		`SELECT pt.tag FROM page_tags pt
		 JOIN pages p ON p.id = pt.page_id
		 WHERE pt.page_id = ? AND `+tagVisibleSQL+publicOnlySQL(p, `pt.secret_id = ''`)+`
		 ORDER BY pt.tag COLLATE NOCASE`,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if err != nil {
		return nil, fmt.Errorf("store: list page tags: %w", err)
	}
	var out []string
	err = ForEach(rows, func(r Rows) error {
		var name string
		if err = r.Scan(&name); err != nil {
			return fmt.Errorf("store: scan page tag: %w", err)
		}
		out = append(out, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// typedPagesFromSQL is the FROM and WHERE of the by-type page query, held as one
// constant for the reason every other pair in this package is: a count and its
// list are the same question asked twice, and two WHERE clauses that look alike
// are two clauses that will diverge.
//
// There is no secret predicate here and that is a deliberate, load-bearing
// absence rather than an oversight. pages has no secret_id column: a page is a
// file, and a file is not a secret. What can be hidden on a page is text inside
// it, and that text is filtered when it is read — the excerpt above, the page
// render, the tags just above — rather than by withholding the page row. A
// predicate here would filter rows that carry no secret data and would make the
// count and the list agree on a number that is not about visibility at all.
//
// The list this builds is titles and paths, and those are public text: they are
// in the file tree, in the tag cloud, in the command palette and in every
// backlink, all under the same rules. A filter that hid them here would hide
// them in one place and not the others, which is worse than showing them.
const typedPagesFromSQL = `FROM pages p
	WHERE p.page_type = ?`

// The three pieces of the by-type page pair, so the SELECT list differs and the
// predicate cannot.
const (
	typedPagesListSQL  = `SELECT ` + pageColumns + ` `
	typedPagesCountSQL = `SELECT COUNT(*) `
	typedPagesOrderSQL = ` ORDER BY p.title COLLATE NOCASE, p.id`
)

// ListPagesByType returns the pages carrying one frontmatter type, title order.
//
// This is the query behind a frontmatter convention rather than a registered page
// type: `type: houserule` is a convention precisely because the pages are
// ordinary and need no plugin to be read. An empty pageType returns nothing
// rather than everything, for the reason ListCommandPages gives.
func ListPagesByType(ctx context.Context, q Queryer, p authz.Principal, pageType string) ([]Page, error) {
	if pageType == "" {
		return nil, nil
	}
	if !p.CanReadPublic() {
		return nil, nil
	}
	return queryPages(ctx, q,
		typedPagesListSQL+typedPagesFromSQL+typedPagesOrderSQL, pageType)
}

// CountPagesByType returns the number of pages ListPagesByType would return,
// from the identical statement. See BacklinkCount for why the paraphrase is the
// dangerous version.
func CountPagesByType(ctx context.Context, q Queryer, p authz.Principal, pageType string) (int, error) {
	if pageType == "" {
		return 0, nil
	}
	if !p.CanReadPublic() {
		return 0, nil
	}
	var n int
	err := q.QueryRowContext(ctx, typedPagesCountSQL+typedPagesFromSQL, pageType).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count pages of type %s: %w", pageType, err)
	}
	return n, nil
}
