package httpapi

import (
	"context"
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The broken-links panel: every reference in the campaign that does not resolve
// to a page.
//
// The whole difficulty of this surface is one SQL fact, and this file exists to
// record it. `links.target_page_id IS NULL` does not mean "this link is
// broken": an attachment reference and an inline tag point at a file and at a
// tag, never at a page, so that column is NULL for every image embed and every
// #tag in the vault as well as for every dangling wikilink. A panel built on
// the column alone lists the campaign's picture library and calls it a list of
// mistakes, and its badge is the number of attachments.
//
// So the panel asks store.ListVisibleUnresolvedLinks, whose statement excludes
// those two kinds and applies the canonical secret predicate, and asks
// store.CountVisibleUnresolvedLinks for the badge, which is a COUNT over the
// identical statement. Neither is re-spelled here, because a WHERE clause
// written twice is two clauses that will diverge, and a panel whose badge
// disagrees with its own list is the existence leak AGENTS.md §2.4 is about.

// brokenLinksPage answers GET /broken.
//
// It is PermAnonRead in the plan's table and PermReadPage in the one that was
// mounted, and for this handler the two are the same question: the policy's
// PermReadPage takes no resource, so it asks only whether the principal may read
// public content, and every row on this panel is a page such a principal can
// already open. The panel is navigation over content the reader can read, and it
// needs no gate of its own beyond that.
//
// An anonymous reader with anonymous read off is sent to the login form, and an
// authenticated reader with no read access at all gets nothing from either store
// query — which is a statement about the panel's public rows and not about its
// secret ones.
func (s *Server) brokenLinksPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	links, err := store.ListVisibleUnresolvedLinks(ctx, s.db.Reader(), who)
	if err != nil {
		s.fail(w, r, "list the dangling references", err)
		return
	}
	// The count comes from the count query rather than from len(links), so that a
	// future limit on the list cannot turn the badge into a number the rows below
	// it do not add up to. Today the two are equal; carrying both is what keeps
	// them equal.
	count, err := store.CountVisibleUnresolvedLinks(ctx, s.db.Reader(), who)
	if err != nil {
		s.fail(w, r, "count the dangling references", err)
		return
	}

	view := BrokenLinksView{
		Shell:      s.liveShell(r, "Broken links"),
		Rows:       s.brokenLinkRows(ctx, links),
		Total:      count,
		ShownLimit: ShownLimit,
		Truncated:  count > len(links),
	}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the broken-links page", err)
	}
}

// brokenLinkRows projects the store's rows onto the view model, resolving each
// referring page once and stopping at ShownLimit.
//
// The cap is applied here rather than in the query so that the count beside it
// is a count of everything the principal may see rather than of the page that
// fits: a badge that counts the first two hundred rows is a badge that under-
// counts, and a badge that says 4 when the panel shows 3 says the fourth is
// being hidden from this reader for a reason.
//
// A referring page that has gone from the index contributes a row carrying the
// recorded id and no title, rather than being dropped: the reference is still in
// a file on disk, and a panel that hid it would be claiming the campaign has
// fewer dangling links than it does.
//
// No content crosses here. A row is a target, a line and a path, and the target
// is the short token an author typed between brackets — the one thing §2.6
// requires the canonical predicate to have already cleared, because a reference
// inside a secret the reader may not read was removed in SQL before the row
// existed.
func (s *Server) brokenLinkRows(ctx context.Context, links []store.Link) []BrokenLinkRow {
	if len(links) > ShownLimit {
		links = links[:ShownLimit]
	}
	out := make([]BrokenLinkRow, 0, len(links))
	pages := make(map[int64]store.Page, len(links))
	for _, l := range links {
		row, ok := pages[l.SourcePageID]
		if !ok {
			// A page the index does not have is a page the reconciling scan has
			// not caught, not an error: the reference is still real.
			if found, err := store.GetPageByID(ctx, s.db.Reader(), l.SourcePageID); err == nil {
				row = found
			}
			pages[l.SourcePageID] = row
		}
		out = append(out, BrokenLinkRow{
			Card:   cardOf(row),
			Target: l.TargetRaw,
			Line:   l.Line,
			Kind:   string(l.Kind),
		})
	}
	return out
}
