package httpapi

import (
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// filesPage is the whole vault as a tree: the directories the reader's files
// live in, and the files themselves.
//
// It is PermAnonRead because it is a page list by another shape, and a page
// list is public content by the same measure as any other page — a viewer who
// could not read a page must not learn from this that it was written last
// Tuesday under a directory name. The pages come from ListAllPages, which
// applies the viewer's principal to the query even though v1 filters no page
// out, so the day a page filter arrives it arrives in the store rather than
// here.
func (s *Server) filesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pages, err := store.ListAllPages(ctx, s.db.Reader(), PrincipalFrom(ctx))
	if err != nil {
		s.fail(w, r, "list every page", err)
		return
	}
	view := FilesView{
		Shell:     s.liveShell(r, "Files"),
		Tree:      buildFileTree(s.campaign, pages),
		PageCount: len(pages),
	}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the file tree", err)
	}
}

// treeNode is the mutable form of a FileNode, used only while the tree is being
// assembled.
//
// FileNode holds its children by value, and a stack of pointers into such a
// slice is a trap: append reallocates, the values are copied, and the pointer
// the builder is still holding names a node the live tree no longer contains.
// Building in pointers and flattening once, when nothing is being appended
// any more, is what keeps the walk's cursor pointing at the node it means.
type treeNode struct {
	// node is the view model being filled in. Its Dir and Children are decided
	// at flattening time, when the node's children are known.
	node FileNode
	// dirs are the subdirectories, in the order the sorted list produced them.
	dirs []*treeNode
	// pages are the files in this node, in the order the sorted list produced
	// them.
	pages []PageCard
}

// buildFileTree assembles a path-ordered page list into the file tree.
//
// A stack is enough because the list arrives ordered by path, and that is a
// property of ListAllPages' contract rather than an assumption here: every file
// under a given directory prefix is contiguous in path order, so a directory
// that has been closed can never be reopened. The two loops below are therefore
// bounded — the first shortens the stack, the second lengthens it by one and
// stops at the directory the file belongs to — and the outer cursor is a slice
// index that advances on every iteration. That is the whole reason this is
// written as three explicit loops over one visible cursor rather than as a
// `for _, page := range` with an index walk inside it: §11 records two
// production hangs that were both a branch which recognised a token and did not
// move its read position, and the shape of that bug is exactly the shape of the
// obvious version of this function.
//
// A node is a directory when it has children and a leaf when it does not, and
// a directory carries no count and no timestamp. That is not an omission: a
// number in a sidebar is one whose derivation a reader cannot check, and this
// codebase has already shipped a panel whose badge and whose list were
// computed from two different queries. There is nothing derived here that
// could disagree with anything.
func buildFileTree(campaign string, pages []store.Page) FileNode {
	root := &treeNode{node: FileNode{Name: campaign, Path: "", Dir: true}}
	// open[d] is the directory at depth d that the previous file lived in and
	// openPath[d] is its vault-relative path. The root is depth zero, and its
	// path is empty by definition.
	open := []*treeNode{root}
	openPath := []string{""}

	for i := 0; i < len(pages); i++ {
		row := pages[i]
		segments := splitVaultPath(row.Path)
		n := len(segments)
		if n == 0 {
			// An indexed page always has a name. Skipping an empty one keeps the
			// cursor honest rather than manufacturing a node with no name.
			continue
		}
		dirPath := path.Join(segments[:n-1]...)

		// Close every open directory that is neither this file's own directory
		// nor an ancestor of it. The equality is the half that matters: a file
		// directly inside an open directory shares that directory's path exactly,
		// and a test for "is an ancestor" alone would read that as "not related",
		// pop the directory and then open a second node with the same name. The
		// result is a tree that shows Guild twice, once holding its cellar and
		// once holding the rest. Each iteration drops one entry, so it cannot
		// spin.
		for len(open) > 1 {
			top := openPath[len(open)-1]
			if dirPath == top || strings.HasPrefix(dirPath, top+"/") {
				break
			}
			open = open[:len(open)-1]
			openPath = openPath[:len(openPath)-1]
		}
		// Open the directories this file needs and does not have yet. Each
		// iteration adds one, and after len(segments)-1 of them the open path
		// equals dirPath, so it terminates on the files' own shape.
		for openPath[len(openPath)-1] != dirPath {
			parent := open[len(open)-1]
			child := &treeNode{node: FileNode{Name: segments[len(open)-1]}}
			child.node.Path = path.Join(openPath[len(openPath)-1], child.node.Name)
			parent.dirs = append(parent.dirs, child)
			open = append(open, child)
			openPath = append(openPath, child.node.Path)
		}
		leaf := open[len(open)-1]
		leaf.pages = append(leaf.pages, cardOf(row))
	}
	return flattenFileTree(root)
}

// splitVaultPath is a vault-relative path as its segments.
//
// Empty segments are dropped rather than turned into directories, so a path
// with a doubled or trailing slash cannot produce a node with no name in it.
func splitVaultPath(p string) []string {
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// flattenFileTree copies the builder's tree into the view model.
//
// It is a second pass because the builder holds pointers and the view model
// holds values, and because "is this node a directory" is only answerable once
// the node's children are all known. The root is always a directory: it is the
// vault itself, and a flat vault still has its files hanging off the root.
func flattenFileTree(root *treeNode) FileNode {
	out := root.node
	out.Dir = true
	out.Pages = sortedPageCards(root.pages)
	out.Children = nil
	for _, child := range root.dirs {
		out.Children = append(out.Children, flattenFileChild(child))
	}
	sortFileNodes(out.Children)
	return out
}

// flattenFileChild is flattenFileTree for everything below the root.
//
// A node can hold pages and children at once, and it does when a vault contains
// both Guild.md and a Guild directory. It is reported as a directory — the
// contract is that a node with children is one — and it keeps its pages, so the
// only cost of that collision is that the template shows both, and no file is
// ever dropped from the tree.
func flattenFileChild(node *treeNode) FileNode {
	out := node.node
	out.Dir = len(node.dirs) > 0
	out.Pages = sortedPageCards(node.pages)
	out.Children = nil
	for _, child := range node.dirs {
		out.Children = append(out.Children, flattenFileChild(child))
	}
	sortFileNodes(out.Children)
	return out
}

// sortedPageCards orders a node's files by title, then by path.
func sortedPageCards(cards []PageCard) []PageCard {
	sort.SliceStable(cards, func(i, j int) bool {
		if c := compareNoCase(cards[i].Title, cards[j].Title); c != 0 {
			return c < 0
		}
		return compareNoCase(cards[i].Path, cards[j].Path) < 0
	})
	return cards
}

// sortFileNodes orders directories before leaves, and each group by name.
//
// The comparison is SQLite's NOCASE rather than Go's strings.Compare, because
// the store's own listings order with NOCASE and a sidebar that sorted its
// directories by a different collation than the list it was built from would
// show a reader two different orders of the same campaign.
func sortFileNodes(nodes []FileNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Dir != nodes[j].Dir {
			return nodes[i].Dir
		}
		return compareNoCase(nodes[i].Name, nodes[j].Name) < 0
	})
}

// compareNoCase compares two names the way SQLite's NOCASE collation does:
// ASCII letters fold, every other byte compares by value, and a string that
// folds equal is byte-equal, so the order is total and the same list always
// produces the same tree.
//
// It is deliberately not strings.ToLower. That folds Unicode, and a Unicode
// fold would sort "Éclair" somewhere NOCASE does not, which is precisely the
// disagreement this function exists to prevent.
func compareNoCase(a, b string) int {
	ar, br := []byte(a), []byte(b)
	for i := 0; i < min(len(ar), len(br)); i++ {
		x, y := foldASCII(ar[i]), foldASCII(br[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ar) < len(br):
		return -1
	case len(ar) > len(br):
		return 1
	default:
		return 0
	}
}

// foldASCII lowercases one ASCII letter and leaves every other byte alone.
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
