package md

import (
	"sort"
	"strings"
)

// PageID is the index's surrogate key for a page. It is an alias rather than a
// distinct type so that a store row's ID needs no conversion at the boundary.
type PageID = int64

// PageKey is everything the resolver needs to know about one page. It is a
// description handed to the resolver, not a database row: the resolver holds no
// connection and never queries anything.
type PageKey struct {
	// ID is the page's surrogate key.
	ID PageID
	// Path is the vault-relative path, forward slashes, `.md` included.
	Path string
	// Basename is the file name without the extension. It is derived from
	// Path when empty, because carrying both is a chance to disagree.
	Basename string
	// Aliases are the frontmatter aliases, in the order they were written.
	Aliases []string
}

// Resolver maps a wikilink target to a page id.
//
// The order is fixed and the winner for each key is decided once, at
// construction, so Resolve is a map lookup and two runs over the same pages
// always produce the same answer. Renames and the bulk link updater are a
// later phase; this resolves §5.6's order and nothing else.
type Resolver struct {
	byPath  map[string]PageKey
	byBase  map[string]PageKey
	byAlias map[string]PageKey
	count   int
}

// NewResolver indexes pages for resolution.
//
// Three ambiguity rules are applied while indexing, in this order, so that the
// answer does not depend on the order the pages arrived in:
//
//   - a key claimed by more than one page is won by the shortest path, and a
//     tie on length by the lexicographically smallest path;
//   - a page claims its path both with and without the `.md` suffix, because
//     Obsidian writes `[[Party/Tavern]]` for `Party/Tavern.md`;
//   - an alias is matched case-insensitively, because a player who typed
//     `[[the tavern]]` meant it.
func NewResolver(pages []PageKey) *Resolver {
	r := &Resolver{
		byPath:  make(map[string]PageKey, len(pages)*2),
		byBase:  make(map[string]PageKey, len(pages)),
		byAlias: make(map[string]PageKey, len(pages)*2),
		count:   len(pages),
	}
	for _, p := range pages {
		if p.Path != "" {
			path := normalizePath(p.Path)
			name := p.Basename
			if name == "" {
				name = Basename(path)
			}
			p.Path, p.Basename = path, name
			r.claim(r.byPath, path, p)
			r.claim(r.byPath, strings.TrimSuffix(path, ".md"), p)
			r.claim(r.byBase, name, p)
		}
		for _, a := range p.Aliases {
			if a = strings.TrimSpace(a); a != "" {
				r.claim(r.byAlias, strings.ToLower(a), p)
			}
		}
	}
	return r
}

// Len returns the number of pages the resolver was built from.
func (r *Resolver) Len() int { return r.count }

// claim records a key, keeping the better of any existing holder and the
// candidate. It is called once per key per page, so it stays linear.
func (r *Resolver) claim(index map[string]PageKey, key string, p PageKey) {
	if key == "" {
		return
	}
	if cur, ok := index[key]; !ok || betterMatch(p, cur) {
		index[key] = p
	}
}

// betterMatch reports whether a is a better match for a key than b. Shortest
// path wins first, because a link that names a file's directory is naming the
// most specific page available; the lexicographic order then makes the
// remaining ties deterministic rather than dependent on insertion order.
func betterMatch(a, b PageKey) bool {
	if len(a.Path) != len(b.Path) {
		return len(a.Path) < len(b.Path)
	}
	return a.Path < b.Path
}

// Resolve returns the page a target names, or false when nothing does.
//
// The order is: an exact vault-relative path, then the same path with `.md`
// appended, then an exact basename, then a case-insensitive alias, then
// unresolved. A fragment is not part of a target; the extractor splits it off
// and records it as a heading or a block reference, because a page is what a
// link points at and an anchor is where inside it.
func (r *Resolver) Resolve(target string) (PageID, bool) {
	target = strings.TrimSpace(strings.ReplaceAll(target, "\\", "/"))
	target = strings.TrimPrefix(target, "./")
	if target == "" {
		return 0, false
	}
	if p, ok := r.byPath[target]; ok {
		return p.ID, true
	}
	if p, ok := r.byPath[strings.TrimSuffix(target, ".md")]; ok {
		return p.ID, true
	}
	name := target
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name = strings.TrimSuffix(name, ".md"); name != "" {
		if p, ok := r.byBase[name]; ok {
			return p.ID, true
		}
	}
	if p, ok := r.byAlias[strings.ToLower(target)]; ok {
		return p.ID, true
	}
	return 0, false
}

// Paths returns the resolver's index keys, sorted. It exists for the boot
// self-check and for a failing test's message, not for the request path.
func (r *Resolver) Paths() []string {
	out := make([]string, 0, len(r.byPath))
	for k := range r.byPath {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
