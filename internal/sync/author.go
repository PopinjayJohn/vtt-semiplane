package sync

import (
	"context"
	"sort"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// indexMode is whether a pass may take an unchanged content hash as proof that
// the page is already indexed.
type indexMode int

const (
	// indexIfChanged is the ordinary pass. A file whose hash already matches its
	// indexed row costs one read and writes nothing, which is what makes a scan
	// over an unchanged vault free.
	indexIfChanged indexMode = iota
	// indexForced re-reads the file and rewrites its derived rows even when the
	// bytes are the bytes already indexed.
	//
	// It exists for exactly one caller. The hash comparison is a statement about
	// the file, and it is true: the file did not change. What it cannot see is
	// that the index was built against a different set of accounts, so the same
	// bytes ask — by name — for a foreign key that did not exist when they were
	// first read. Re-running the ordinary pass over an unchanged vault therefore
	// does nothing at all, which is why the unresolved-author case was invisible
	// until a full reindex.
	indexForced
)

// unresolvedPage is one pending path and the lower-cased usernames its fences
// named that no account answered.
type unresolvedPage struct {
	path  string
	names []string
}

// RetryUnresolvedAuthors re-indexes the pages whose secret fences named an
// account that did not exist when they were first indexed.
//
// The gap it closes is the first thing a new user meets: a vault is indexed at
// boot, /setup then creates the administrator, and the administrator's own `dm`
// fences are visible to nobody until somebody remembers to reindex. A fence
// names its author by username and secrets.author_id is a foreign key, so the
// indexer reports the problem and writes no row — fail-closed, and therefore not
// a leak, but a miss nobody can see from inside the app.
//
// It is safe to call at any time and it is a no-op when nothing is pending,
// which is the common case and the one a boot sequence may rely on. The pending
// set is read, never written: the re-index it triggers re-derives the set from
// the file, so a fence that still names nobody stays pending and a fence the DM
// has since corrected leaves the set on the next ordinary pass.
//
// The call belongs immediately after an account is created — the /setup
// bootstrap and any later invite redemption — and nowhere on a timer: the cost
// is one query and, for the paths that resolve, one re-read each.
func (ix *Indexer) RetryUnresolvedAuthors(ctx context.Context) (BatchResult, error) {
	var out BatchResult
	waiting := ix.unresolvedAuthorPages()
	if len(waiting) == 0 {
		return out, nil
	}

	// One query for every name, because the alternative is one per path and a
	// fresh vault can be full of them. The names are values and they go in as
	// bind parameters; only the placeholder run is generated, and that is a
	// count.
	names := make([]string, 0, len(waiting))
	for _, p := range waiting {
		names = append(names, p.names...)
	}
	resolved, err := store.GetUserIDsByUsernames(ctx, ix.db.Reader(), names)
	if err != nil {
		return out, err
	}
	if len(resolved) == 0 {
		return out, nil
	}

	resolver, err := newLinkResolver(ctx, ix.db.Reader())
	if err != nil {
		return out, err
	}
	// Not IndexBatch, deliberately: a forced pass rewrites a page that is
	// already indexed, so it creates no page, names nothing new and needs no
	// rename window — and IndexBatch is the ordinary mode, which is the one call
	// here that must not happen.
	for _, p := range waiting {
		if !anyAuthorResolved(p.names, resolved) {
			continue
		}
		res, err := ix.indexOne(ctx, p.path, resolver, indexForced)
		if err != nil {
			return out, err
		}
		out.Indexed = append(out.Indexed, res)
		if res.Unchanged {
			out.Unchanged++
		}
	}
	return out, nil
}

// anyAuthorResolved reports whether at least one of a page's pending names now
// names an account.
//
// One is enough, because the page is re-read in full and every fence on it is
// reconsidered: a page with two pending authors gets a second chance for each of
// them, on this call and on the next one. It is not enough to re-index a page
// whose every name is still unknown, because the re-read would produce exactly
// the rows the index already has.
func anyAuthorResolved(names []string, resolved map[string]int64) bool {
	for _, n := range names {
		if _, ok := resolved[n]; ok {
			return true
		}
	}
	return false
}

// unresolvedAuthorPages snapshots the pending set in path order.
//
// The order is the reason a retry is reproducible: a map's iteration order would
// decide which page's re-read ran first, and the set is otherwise unordered.
func (ix *Indexer) unresolvedAuthorPages() []unresolvedPage {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	out := make([]unresolvedPage, 0, len(ix.unresolved))
	for path, names := range ix.unresolved {
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		out = append(out, unresolvedPage{path: path, names: list})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// setUnresolvedAuthors records, for one path, every username a fence on it named
// that no account answered.
//
// It is called from a committed write and nowhere else, which is what makes the
// set exact rather than hopeful: it always says what the file on disk currently
// asks for, so a corrected fence clears its path and a fence that has just been
// indexed never leaves a stale entry behind. An empty list removes the path.
//
// The empty username is not remembered. No account can be created for the empty
// name, so an entry for it could only ever be a promise nothing could keep.
func (ix *Indexer) setUnresolvedAuthors(rel string, names []string) {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		// Folded here, once, so the retry can look a name up with a plain map
		// index whether the fence wrote `Alice` or `alice` and the account is
		// `alice`. The comparison in the query is NOCASE for the same reason.
		set[strings.ToLower(n)] = true
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	if len(set) == 0 {
		ix.deleteUnresolvedLocked(rel)
		return
	}
	if _, known := ix.unresolved[rel]; !known {
		if len(ix.unresolved) >= ix.unresolvedCapacity {
			ix.evictUnresolvedLocked()
		}
		ix.unresolvedOrder = append(ix.unresolvedOrder, rel)
	}
	ix.unresolved[rel] = set
}

// forgetUnresolvedAuthors drops a path from the pending set because there is
// nothing left at that path to wait for.
func (ix *Indexer) forgetUnresolvedAuthors(rel string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.deleteUnresolvedLocked(rel)
}

func (ix *Indexer) deleteUnresolvedLocked(rel string) {
	if _, live := ix.unresolved[rel]; !live {
		return
	}
	delete(ix.unresolved, rel)
	for i, path := range ix.unresolvedOrder {
		if path != rel {
			continue
		}
		ix.unresolvedOrder = append(ix.unresolvedOrder[:i], ix.unresolvedOrder[i+1:]...)
		return
	}
}

// evictUnresolvedLocked forgets the oldest pending path so a new one can be
// remembered.
//
// Forgetting costs that page the automatic retry and nothing else: its fence is
// still a problem reported on the page, and a full reindex still indexes it
// once the account exists. What it must never cost is a wrong index row, so
// eviction drops the path and touches no state the retry would have written.
func (ix *Indexer) evictUnresolvedLocked() {
	for len(ix.unresolvedOrder) > 0 {
		oldest := ix.unresolvedOrder[0]
		before := len(ix.unresolvedOrder)
		ix.unresolvedOrder = ix.unresolvedOrder[1:]
		// The queue must shrink, or this loop forgets the same path for ever.
		// It cannot, because it was non-empty — asserted rather than trusted,
		// since two parsers in this repository shipped a loop that recognised
		// something and never advanced past it.
		if len(ix.unresolvedOrder) >= before {
			return
		}
		if _, live := ix.unresolved[oldest]; !live {
			continue
		}
		delete(ix.unresolved, oldest)
		// The path is logged and the username is not: the name is a value out of
		// the file's own directive, and the problem on the page deliberately does
		// not carry it either.
		ix.log.Warn("too many pages with an unattributable secret fence, forgetting the oldest",
			"action", "index.unresolved_author_evict", "path", oldest,
			"limit", ix.unresolvedCapacity)
		return
	}
}
