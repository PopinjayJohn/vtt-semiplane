package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// The campaign rollups. Two of the five are the tag page query with a different
// tag, and they reuse taggedPagesFromSQL rather than restating it, because a
// restatement is how CountOpenThreads and CountTaggedPages end up disagreeing
// about the same campaign.

// openThreadsOrderSQL closes the thread list before the window: newest first,
// with p.id as the tie-break, because a panel of threads that reshuffles every
// render is unreadable.
const openThreadsOrderSQL = ` ORDER BY p.updated_at DESC, p.id`

// ListOpenThreads returns the pages still carrying the open-thread tag, most
// recently touched first, windowed to limit.
//
// A thread is closed by removing the tag, so this tag is the whole closure
// queue — there is no state column for it to disagree with, and no second way
// to ask.
func ListOpenThreads(ctx context.Context, q Queryer, p authz.Principal, limit int) ([]Page, error) {
	uid, isDM := p.Bind()
	return queryPages(ctx, q,
		taggedPagesListSQL+taggedPagesFromSQL+
			publicOnlySQL(p, `pt.secret_id = ''`)+openThreadsOrderSQL+` LIMIT ?`,
		TagOpenThread, sql.Named("uid", uid), sql.Named("is_dm", isDM), clampLimit(limit))
}

// CountOpenThreads returns how many threads are open, over the whole set and
// not the window ListOpenThreads shows.
//
// That is the reason the two are separate functions. The panel shows a count
// beside a short list; a count taken as len() of the list would be a count of
// the window, and a thread that fell off the end would silently stop existing.
// Both halves read the identical WHERE, from taggedPagesFromSQL.
func CountOpenThreads(ctx context.Context, q Queryer, p authz.Principal) (int, error) {
	uid, isDM := p.Bind()
	var n int
	err := q.QueryRowContext(ctx,
		taggedPagesCountSQL+taggedPagesFromSQL+publicOnlySQL(p, `pt.secret_id = ''`),
		TagOpenThread, sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count open threads: %w", err)
	}
	return n, nil
}

// recentPagesSQL is the dashboard's recent list, less the page being looked at.
//
// The exclusion is a WHERE clause rather than a post-filter, so the window the
// caller sees is filled with the pages *after* the excluded one. Filtering
// afterwards would take the top `limit` and then drop the one, leaving a panel
// with a hole in it. excludeID of 0 excludes nothing, which is how the same
// statement doubles as the unfiltered recent list.
const recentPagesSQL = `SELECT ` + pageColumns + ` FROM pages p
	 WHERE ? = 0 OR p.id <> ?
	 ORDER BY p.updated_at DESC, p.id LIMIT ?`

// ListRecentPagesExcluding returns the most recently updated pages other than
// excludeID, newest first.
func ListRecentPagesExcluding(ctx context.Context, q Queryer, p authz.Principal, excludeID int64, limit int) ([]Page, error) {
	return queryPages(ctx, q, recentPagesSQL, excludeID, excludeID, clampLimit(limit))
}

// partyOwnerSQL is the correlated subquery that picks a party member's account:
// the primary owner where there is one, and otherwise the lowest numbered
// remaining owner row.
//
// pages.owner_id is always also a row in page_owners, so the fallback is what
// runs on a page whose page_owners rows were written without a primary being
// flagged. It answers "somebody owns this" rather than "nobody does", which is
// the only failure direction that is safe, and ordering by user_id last keeps
// the choice deterministic when no row is flagged.
const partyOwnerSQL = `(SELECT po.user_id FROM page_owners po
	 WHERE po.page_id = p.id
	 ORDER BY po.is_owner DESC, po.user_id LIMIT 1)`

// partySQL selects the display name and never the username. A username is an
// account identifier as well as a display string, and a sidebar printing one
// next to a character sheet hands every reader the login of every player in the
// campaign.
const partySQL = `SELECT ` + pageColumns + `, u.display_name
	FROM pages p
	JOIN users u ON u.id = ` + partyOwnerSQL + `
	WHERE p.page_type = ?
	ORDER BY p.title COLLATE NOCASE, p.id LIMIT ?`

// ListParty returns the character sheets that have an owner, with the owner's
// display name.
//
// The join to page_owners is what "has an owner" means; a character sheet with
// no owner row is an unowned NPC, not a party member. Nothing here is
// secret-derived, so no visibility predicate applies — the principal is still a
// parameter, because a party list is the first thing a per-campaign rule would
// filter and there is nowhere else for that filter to go.
func ListParty(ctx context.Context, q Queryer, p authz.Principal, limit int) ([]PartyMember, error) {
	rows, err := q.QueryContext(ctx, partySQL, TypeCharacter, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("store: list party: %w", err)
	}
	var out []PartyMember
	err = ForEach(rows, func(r Rows) error {
		var displayName string
		page, scanErr := scanPage(trailingScanner{inner: r, extra: []any{&displayName}})
		if scanErr != nil {
			return fmt.Errorf("store: scan party member: %w", scanErr)
		}
		out = append(out, PartyMember{Page: page, OwnerDisplayName: displayName})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// trailingScanner reads a row whose leading columns are pageColumns' projection
// and whose trailing columns are the caller's, and hands scanPage only the
// leading ones.
//
// It exists so ListParty can reuse scanPage's thirteen destinations instead of
// copying them. A copied destination list is a list that still compiles after a
// column is added to pageColumns and stops matching it.
type trailingScanner struct {
	inner RowScanner
	extra []any
}

func (t trailingScanner) Scan(dest ...any) error {
	return t.inner.Scan(append(dest, t.extra...)...)
}

// The related-pages statement, in pieces rather than one constant because the
// anonymous public-only term has to be injected where a tag is evaluated and
// not once at the end: appended to the outermost WHERE it would name a `pt`
// that is out of scope there, and injected only once it would be missing from
// one of the two halves that have to agree.
const (
	// relatedPagesHeadSQL opens the CTE: the tags the *viewed* page carries, as
	// this principal may see them. It needs a `pages p` of its own, because
	// authz.SecretVisibleSQL names `p` literally for the ownership term; a
	// subquery that aliased the viewed page `p2` would resolve that name
	// outwards to the candidate page and answer "does the viewer own the other
	// one". Two scopes, one name, no shadowing — hence a CTE rather than a
	// correlated subquery.
	relatedPagesHeadSQL = `WITH mine AS (
	SELECT DISTINCT pt.tag
	FROM page_tags pt
	JOIN pages p ON p.id = pt.page_id
	WHERE pt.page_id = ? AND ` + tagVisibleSQL

	relatedPagesBodySQL = `)
	SELECT ` + pageColumns + `, COUNT(DISTINCT pt.tag) AS shared
	FROM pages p
	JOIN page_tags pt ON pt.page_id = p.id
	WHERE ` + tagVisibleSQL

	// relatedPagesTailSQL intersects the candidate's visible tags with the
	// viewed page's and groups the result per page. GROUP BY p.id is what makes
	// the shared count a count rather than a page, and HAVING on it is what
	// keeps a page with nothing in common out of the list instead of leaving it
	// there with a count of zero — a filter on `mine` alone would not, because
	// `mine` is the same for every candidate.
	relatedPagesTailSQL = ` AND p.id <> ? AND pt.tag IN (SELECT tag FROM mine)
	GROUP BY p.id HAVING shared > 0`

	// relatedPagesOrderSQL orders and caps inside the derived table, because
	// `shared` is one of its output columns and the outer projection does not
	// carry it. Wrapping rather than selecting a fourteenth column is what
	// keeps ListRelatedPages on queryPages, the one path every page lister here
	// uses — a second scan of pageColumns' destinations would be a second list
	// to forget.
	relatedPagesOrderSQL = ` ORDER BY shared DESC, p.title COLLATE NOCASE, p.id LIMIT ?`
)

// ListRelatedPages returns the pages sharing the most tags with pageID, capped
// at limit.
//
// Shared tags are the whole of "related" in v1: no embedding similarity, no
// plugin contribution. A query whose result set a plugin can widen without
// owning the filter is a query whose authorization the plugin can widen too,
// and this one runs on every page render for every reader.
//
// A tag both pages carry only inside secrets the viewer may not read makes no
// relationship at all, which is why both halves of the intersection carry
// tagVisibleSQL and the anonymous public-only term. The ordering is total —
// shared count, then case-insensitive title, then id — so two pages sharing one
// tag do not swap places between two renders of the same state. A page with no
// visible tag in common returns an empty slice and no error; "nothing is
// related to this" is an answer, not a failure.
func ListRelatedPages(ctx context.Context, q Queryer, p authz.Principal, pageID int64, limit int) ([]Page, error) {
	uid, isDM := p.Bind()
	only := publicOnlySQL(p, `pt.secret_id = ''`)
	return queryPages(ctx, q,
		`SELECT `+pageColumns+` FROM (`+
			relatedPagesHeadSQL+only+relatedPagesBodySQL+only+relatedPagesTailSQL+
			relatedPagesOrderSQL+`) p`,
		pageID, sql.Named("uid", uid), sql.Named("is_dm", isDM), pageID, clampLimit(limit))
}
