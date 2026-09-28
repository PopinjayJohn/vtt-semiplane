package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// The tree's own ceilings. Every list in this file renders a sidebar or a
// palette, so a limit here is a page size and an unbounded one is an unbounded
// allocation — the same reasoning as search.MaxLimit, for the same reason.
const (
	// defaultListLimit is what a non-positive limit becomes. SQLite reads
	// `LIMIT -1` as *no limit at all*, so a negative value is not a small
	// window, it is the entire vault, and it must never reach the driver.
	defaultListLimit = 20
	// maxListLimit is the hard ceiling, whatever the caller asked for. A panel
	// is a panel; past this it is a download.
	maxListLimit = 200
)

// clampLimit turns a caller's window into one SQLite will accept. A non-positive
// limit means "the caller did not choose", which is not the same thing as the
// whole table and must not be passed on as though it were.
func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return defaultListLimit
	case limit > maxListLimit:
		return maxListLimit
	default:
		return limit
	}
}

// ListAllPages returns every indexed page in path order, so the caller can
// assemble a file tree in a single forward pass without sorting.
//
// Nothing is filtered in v1: there is no hidden page and no page-level
// permission. The principal is a parameter anyway, because a list-of-titles
// query that cannot filter is a query whose filtering gets added later by
// someone in a hurry — in a handler, in a post-filter, where the count and the
// list stop agreeing. The place for it is here.
func ListAllPages(ctx context.Context, q Queryer, p authz.Principal) ([]Page, error) {
	return queryPages(ctx, q, `SELECT `+pageColumns+` FROM pages p ORDER BY p.path`)
}

// tagVisibleSQL is the visibility half of every tag-keyed page query: a page_tags
// row counts only when the tag is public, or when the secret it was written
// inside passes the canonical predicate.
//
// It is written against the `s` and `p` aliases authz.SecretVisibleSQL names,
// which is why it is text and not a macro. An alias renamed here and not there
// does not fail to compile; it changes whose page ownership the private branch
// counts, quietly.
const tagVisibleSQL = `(pt.secret_id = ''
	  OR EXISTS (SELECT 1 FROM secrets s
	              WHERE s.id = pt.secret_id AND ` + authz.SecretVisibleSQL + `))`

// taggedPagesFromSQL is the FROM and WHERE of the tag page query, held as one
// constant for the reason AGENTS.md §2.4 gives: a count and its list are the
// same question asked twice, and two WHERE clauses that look alike are two
// clauses that will diverge. There is nothing here to paraphrase.
const taggedPagesFromSQL = `FROM pages p
	JOIN page_tags pt ON pt.page_id = p.id
	WHERE pt.tag = ? AND ` + tagVisibleSQL

// The three pieces of the tag page pair, so the SELECT list differs and the
// predicate cannot. taggedPagesCountSQL is COUNT(DISTINCT pt.page_id) because
// the list is SELECT DISTINCT: a page carrying the tag both publicly and inside
// a secret is one page, and a badge that says two would be a leak of its own.
const (
	taggedPagesListSQL  = `SELECT DISTINCT ` + pageColumns + ` `
	taggedPagesCountSQL = `SELECT COUNT(DISTINCT pt.page_id) `
	taggedPagesOrderSQL = ` ORDER BY p.title COLLATE NOCASE, p.id`
)

// ListTaggedPages returns the pages carrying a tag, title order.
//
// A page may carry a tag both in public text and inside a secret, and the two
// are different page_tags rows with different visibility. The row from a secret
// the viewer may not read is filtered in SQL, before the page row exists, so
// neither this list nor its length can reveal that the page is tagged at all.
func ListTaggedPages(ctx context.Context, q Queryer, p authz.Principal, tag string) ([]Page, error) {
	uid, isDM := p.Bind()
	return queryPages(ctx, q,
		taggedPagesListSQL+taggedPagesFromSQL+
			publicOnlySQL(p, `pt.secret_id = ''`)+taggedPagesOrderSQL,
		tag, sql.Named("uid", uid), sql.Named("is_dm", isDM))
}

// CountTaggedPages returns the number of pages ListTaggedPages would return,
// from the identical statement. See BacklinkCount for why the paraphrase is the
// dangerous version.
func CountTaggedPages(ctx context.Context, q Queryer, p authz.Principal, tag string) (int, error) {
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx,
		taggedPagesCountSQL+taggedPagesFromSQL+publicOnlySQL(p, `pt.secret_id = ''`),
		tag, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count pages tagged %s: %w", tag, err)
	}
	return n, nil
}

// commandPagesSQL matches a prefix on either the title or the path, and
// nothing else.
//
// A prefix is the only match the command palette is allowed to make. A
// substring match over a path list is a way to learn that a page exists whose
// name the reader has guessed most of, one character at a time; a prefix at
// least says "you must start with this".
//
// Nothing here is secret-derived — a title and a path are public text — so no
// visibility predicate applies. The two branches are still parenthesised
// together, so that a filter appended to this statement later is ANDed onto
// both of them rather than onto whichever one the author was looking at.
// The match is case-insensitive. SQLite's LIKE already folds ASCII case, but
// saying COLLATE NOCASE states the intent rather than leaning on a driver
// default, and likePrefixPattern escapes the reader's own metacharacters so a
// `%` in a page name is reachable rather than catastrophic.
const commandPagesSQL = `SELECT ` + pageColumns + ` FROM pages p
	 WHERE (p.title COLLATE NOCASE LIKE ? ESCAPE '\'
	    OR p.path COLLATE NOCASE LIKE ? ESCAPE '\')`

// commandPagesOrderSQL closes the palette query. The id is the tie-break, so
// two pages whose titles differ only in case do not swap places between two
// keystrokes' worth of typing.
const commandPagesOrderSQL = ` ORDER BY p.title COLLATE NOCASE, p.id LIMIT ?`

// ListCommandPages returns the pages whose title or path starts with prefix.
//
// An empty prefix returns nothing, not everything. The palette shows its own
// actions and a hint to type until the reader has committed to a name; a
// palette that lists the whole vault on focus is a page browser with an extra
// keystroke in front of it, and it is where "guess most of the name" becomes
// practical.
func ListCommandPages(ctx context.Context, q Queryer, p authz.Principal, prefix string, limit int) ([]Page, error) {
	if prefix == "" {
		return nil, nil
	}
	pattern := likePrefixPattern(prefix)
	return queryPages(ctx, q,
		commandPagesSQL+commandPagesOrderSQL,
		pattern, pattern, clampLimit(limit))
}

// likePrefixPattern turns a typed prefix into a LIKE pattern that matches
// exactly the strings starting with it.
//
// The three characters below are the whole of LIKE's metacharacter set, and the
// replacer runs in one pass, so the backslashes it writes are not rescanned and
// double-escaped. A reader who typed `%` meant a per-cent sign; a pattern that
// treated it as a wildcard would answer "does any page start with this" for a
// prefix that matches no page at all.
func likePrefixPattern(prefix string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
}
