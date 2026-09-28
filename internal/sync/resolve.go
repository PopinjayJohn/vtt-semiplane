package sync

import (
	"context"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// linkResolver answers "which page does this target name" for the duration of
// one index pass.
//
// It exists because the naive implementation is a full-table scan per link, and
// a campaign page routinely holds a hundred of them: a hundred scans is a
// hundred times the work to answer a question the answer to which changes only
// when a page is added. One pass therefore loads the basename index once and
// consults aliases only for the targets that miss, memoised, so a page with the
// same wikilink written a thousand times costs one lookup rather than a
// thousand.
//
// The tie-break is §5.6's: shortest path first, then lexicographic. It is
// applied in Go over the rows the pass loaded rather than by asking SQLite to
// order them, because the two have to agree and one implementation of the rule
// is one rule that cannot drift.
type linkResolver struct {
	db store.Queryer
	// byBasename maps a lowercased basename to every page carrying it, shortest
	// path first.
	byBasename map[string][]store.PageRef
	// memo caches a resolved target. A zero id means "resolved to nothing",
	// which is a different answer from "not looked at yet".
	memo map[string]int64
}

func newLinkResolver(ctx context.Context, db store.Queryer) (*linkResolver, error) {
	// ListRecentPages is the only lister in store that returns every page, so
	// the pass-wide index is built from it with a limit no vault will reach.
	// The columns it projects are the page's identity, not its text, so the cost
	// of the scan is rows rather than bytes.
	pages, err := store.ListRecentPages(ctx, db, allPagesLimit)
	if err != nil {
		return nil, err
	}
	r := &linkResolver{db: db, byBasename: map[string][]store.PageRef{}, memo: map[string]int64{}}
	for _, p := range pages {
		key := strings.ToLower(p.Basename)
		if key == "" {
			continue
		}
		r.byBasename[key] = append(r.byBasename[key], store.PageRef{ID: p.ID, Path: p.Path, Title: p.Title})
	}
	for _, refs := range r.byBasename {
		sortPageRefs(refs)
	}
	return r, nil
}

// sortPageRefs orders candidates shortest path first, then lexicographically.
func sortPageRefs(refs []store.PageRef) {
	// Insertion sort: the candidate list for one basename is one entry in
	// almost every case, and a sort that allocates for a one-element slice on
	// every page of a ten-thousand page vault is a worse trade than a linear
	// scan of a two-element slice.
	for i := 1; i < len(refs); i++ {
		for j := i; j > 0 && refLess(refs[j], refs[j-1]); j-- {
			refs[j], refs[j-1] = refs[j-1], refs[j]
		}
	}
}

func refLess(a, b store.PageRef) bool {
	if len(a.Path) != len(b.Path) {
		return len(a.Path) < len(b.Path)
	}
	return a.Path < b.Path
}

// note registers a page this pass has just written, so a later file in the same
// batch can link to it.
//
// The memo entries that resolved to nothing are dropped for the new name: a
// target that was unresolvable when an earlier file in this batch was written
// may be this page, and keeping the cached miss would leave it dangling for
// ever, because the page that would fix it never changes again and so never
// gets re-indexed.
//
// A link written *before* the page it names is not fixed by this, and cannot be
// without a way to re-point an existing links row. store has no setter for
// links.target_page_id, so link re-resolution is a store-side change this
// package must not make; what it can do is never cache a miss across a page
// creation, which is the part of the problem that is ours.
func (r *linkResolver) note(pageID int64, path string) {
	name := strings.ToLower(md.Basename(path))
	if name == "" {
		return
	}
	refs := r.byBasename[name]
	for _, ref := range refs {
		if ref.ID == pageID {
			return
		}
	}
	r.byBasename[name] = append([]store.PageRef{{ID: pageID, Path: path}}, refs...)
	sortPageRefs(r.byBasename[name])
	for target, id := range r.memo {
		if id == 0 && strings.ToLower(md.Basename(target)) == name {
			delete(r.memo, target)
		}
	}
}

// resolve returns the id of the page a link target names, if any.
func (r *linkResolver) resolve(ctx context.Context, target string) (int64, bool) {
	if target == "" {
		return 0, false
	}
	if id, seen := r.memo[target]; seen {
		return id, id != 0
	}
	id := r.lookup(ctx, target)
	r.memo[target] = id
	return id, id != 0
}

func (r *linkResolver) lookup(ctx context.Context, target string) int64 {
	// A target may be written as a bare basename, as a path relative to the
	// vault root, or with the extension. Obsidian accepts all three, so all
	// three are tried before the target is called unresolved.
	names := []string{target}
	if base := md.Basename(target); base != target && base != "" {
		names = append(names, base)
	}
	for _, name := range names {
		if refs := r.byBasename[strings.ToLower(name)]; len(refs) > 0 {
			return refs[0].ID
		}
	}
	// A rename leaves the old name in page_aliases, so an alias is a page as
	// far as a link is concerned — but only after every page that still calls
	// itself that has been ruled out, which is what the loop order means.
	for _, name := range names {
		if id := r.byAlias(ctx, name); id != 0 {
			return id
		}
	}
	return 0
}

func (r *linkResolver) byAlias(ctx context.Context, alias string) int64 {
	pages, err := store.ListPagesByAlias(ctx, r.db, alias)
	if err != nil || len(pages) == 0 {
		return 0
	}
	// ListPagesByAlias already orders by LENGTH(path), path, so the first row
	// is the §5.6 winner.
	return pages[0].ID
}

// mapLinkKind converts md's link classification to store's. The two packages
// spell the same five values independently — md sits where importing store
// would have been a convenience nobody wanted in a leaf parser — so the
// translation is one switch rather than a cast, and an unrecognised value is
// refused rather than written through as whatever the string happened to be.
func mapLinkKind(k md.LinkKind) (store.LinkKind, bool) {
	switch k {
	case md.LinkWikilink:
		return store.LinkWikilink, true
	case md.LinkEmbed:
		return store.LinkEmbed, true
	case md.LinkMarkdown:
		return store.LinkMarkdown, true
	case md.LinkAttachment:
		return store.LinkAttachment, true
	case md.LinkTag:
		return store.LinkTag, true
	default:
		return "", false
	}
}
