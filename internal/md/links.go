package md

import (
	"bytes"
	"sort"
	"strings"
)

// The bulk link updater's byte rewriter: §5.6 steps 3 and 4, the part of the
// rename that touches bytes.
//
// The rule the whole file follows is that nothing is ever re-rendered. A rename
// replaces the token that names the old page and copies every other byte of
// every other page, so a DM's prose, their line endings, their trailing spaces
// and their Obsidian quirks come out of a rename exactly as they went in. The
// cost is that this cannot be written on top of a Markdown parser, because a
// parser hands back a tree and throws the offsets away — so the ranges are
// located here, once, and every replacement is checked against the bytes it is
// about to overwrite.

// Problem codes reported by the rewriter. A rewrite that finds the wrong bytes
// is not an error to retry: it is a stale index, and the answer is to report it
// and write nothing on that page.
const (
	// ProblemLinkOutOfRange is an edit whose range is not inside the file, which
	// means the record was made against a different document.
	ProblemLinkOutOfRange = "link.out_of_range"
	// ProblemLinkStale is an edit whose range holds something other than the
	// target that was recorded. The file was edited after the link was indexed,
	// so the preview no longer describes it. Skipping is the whole point: §5.6
	// step 3 exists so that a stale preview is harmless.
	ProblemLinkStale = "link.stale"
	// ProblemLinkOverlap is an edit that covers bytes another edit already
	// covers. Two edits over one byte range have no correct answer, so neither
	// is applied and the caller is told.
	ProblemLinkOverlap = "link.overlap"
)

// LinkEdit is one token to replace: the bytes at [Offset, Offset+Length) are
// expected to be Want and become With.
type LinkEdit struct {
	// Offset is an absolute offset into Doc.Bytes — a file offset, which is what
	// Link.Offset holds once Extract has walked a document, and not an offset
	// into Doc.Body. Doc.FileOffset converts the other kind.
	Offset int
	// Length is how many bytes the token occupies.
	Length int
	// Want is the text the index recorded. It is compared against the bytes at
	// the offset before anything is written, so an edit computed from a
	// document that has since changed is skipped rather than trusted.
	Want string
	// With is the replacement text.
	With string
}

// RewriteLinks returns the document with every edit applied, or the document's
// own bytes when there is nothing to apply.
//
// An edit is applied only when the bytes it names are the bytes it expects.
// That check is what makes a preview safe to act on: a file edited between the
// preview and the apply is reported under conflicts and left alone, which is
// §5.6's reason for having the check at all. Every other byte of the file —
// including the bytes inside a secret, which are never an edit's target because
// LinkEdits will not produce one — is copied.
//
// Out-of-range, mismatched and overlapping edits are problems, not panics: the
// ranges come from an index that another process may be rewriting, and a crash
// on a stale record would be a denial of service over a rename preview.
func RewriteLinks(d *Doc, edits []LinkEdit) ([]byte, []Problem) {
	if d == nil || len(edits) == 0 {
		return docBytes(d), nil
	}
	lines := newLineIndex(d.Bytes)
	var problems []Problem
	ordered := make([]LinkEdit, 0, len(edits))
	for _, e := range edits {
		switch {
		case e.Offset < 0 || e.Length < 0 || e.Offset > len(d.Bytes) ||
			e.Length > len(d.Bytes)-e.Offset:
			problems = append(problems, Problem{
				Code:      ProblemLinkOutOfRange,
				StartByte: e.Offset,
				Path:      d.Path,
				Line:      lines.line(e.Offset),
				Message:   "the recorded link range is not inside this file",
			})
			continue
		case !bytes.Equal(d.Bytes[e.Offset:e.Offset+e.Length], []byte(e.Want)):
			problems = append(problems, Problem{
				Code:      ProblemLinkStale,
				StartByte: e.Offset,
				Path:      d.Path,
				Line:      lines.line(e.Offset),
				Message:   "the bytes at the recorded link offset are not the recorded target",
			})
			continue
		}
		ordered = append(ordered, e)
	}
	// Ascending, so that an overlap is a comparison with the edit before it and
	// so that applying back to front needs no index arithmetic.
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	kept := make([]LinkEdit, 0, len(ordered))
	covered := 0
	for i, e := range ordered {
		if i > 0 && e.Offset < covered {
			problems = append(problems, Problem{
				Code:      ProblemLinkOverlap,
				StartByte: e.Offset,
				Path:      d.Path,
				Line:      lines.line(e.Offset),
				Message:   "two edits cover the same bytes in this file",
			})
			continue
		}
		kept = append(kept, e)
		if end := e.Offset + e.Length; end > covered {
			covered = end
		}
	}

	out := d.Bytes
	for i := len(kept) - 1; i >= 0; i-- {
		out = splice(out, kept[i].Offset, kept[i].Offset+kept[i].Length, []byte(kept[i].With))
	}
	return out, problems
}

// LinkEdits builds the edit list that repoints a page's links from one target to
// another, in the order the links appear in the file.
//
// Only a page reference is rewritten: a wikilink, an embed of a page, and a
// markdown link whose destination is a page. An attachment, a tag and a
// self-reference are left alone — a self-reference is `[[#Heading]]`, which names
// no page at all, and rewriting one would be rewriting the anchor.
//
// A link with a fragment keeps it. `[[Old Name#The Cellar]]` becomes
// `[[New Name#The Cellar]]` and the token that moves is the path alone, because
// the fragment is a position inside the target and the rename did not move it.
// For a markdown link the whole destination is the token, and a `.md` extension
// on it is carried over to the new name, because a relative link that loses its
// extension stops being the same link as soon as the two pages sit in different
// directories.
//
// from is matched case-insensitively against a link's target after dropping a
// `.md` suffix from both, and nothing else. It is a path, with no fragment and
// no alias: a caller that resolved a page from a link has the fragment on the
// link's own row and does not want it in the name it searches for.
//
// That rule is narrower than the Resolver's basename fallback on purpose: a
// fallback would rewrite `[[Other/Tavern]]` when the page being renamed is
// `Party/Tavern`, and repointing a DM's prose at a page they did not mean is the
// one thing the updater must never do. A caller that wants the other spellings
// as well asks for them by name, once per spelling it resolved.
//
// A link inside a secret is never rewritten. The exclusion is by byte range
// against the document's own spans, not by the recorded secret id, because the
// range is what the edit would touch: a caller that could talk this function
// into rewriting a secret's bytes could use one to disclose a page's redaction,
// whatever the caller's permission on the page itself.
func LinkEdits(d *Doc, facts Extracted, from, to string) []LinkEdit {
	if d == nil || from == "" || to == "" {
		return nil
	}
	want := linkTargetKey(from)
	if want == "" || want == linkTargetKey(to) {
		// A rename to the name the page already has is not a rename, however
		// the two names are spelled: `[[Gundren]]` and `[[Gundren.md]]` are one
		// page, and offering to rewrite the first into the second is a diff the
		// author has to read for nothing.
		return nil
	}
	var out []LinkEdit
	for _, l := range facts.Links {
		switch l.Kind {
		case LinkWikilink, LinkEmbed, LinkMarkdown:
		default:
			continue
		}
		if l.SelfLink || l.Target == "" {
			continue
		}
		if linkTargetKey(l.Target) != want {
			continue
		}
		start, end := l.TargetStart, l.TargetEnd
		if end <= start || end > len(d.Bytes) {
			continue
		}
		if l.Span.SecretID != "" || spanCovers(d, start, end) {
			continue
		}
		token := string(d.Bytes[start:end])
		replacement := to
		if hasMDExtension(token) && !hasMDExtension(replacement) {
			replacement += ".md"
		}
		if replacement == token {
			continue
		}
		out = append(out, LinkEdit{Offset: start, Length: end - start, Want: token, With: replacement})
	}
	return out
}

// linkTargetKey reduces a target to the form two spellings of the same page
// share: no `.md` suffix, and lower case. Obsidian writes `[[Tavern]]` and
// `[x](Tavern.md)` for one file, and a rename that matched only one of them
// would leave the other dangling.
func linkTargetKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	return strings.ToLower(trimMDExtension(target))
}

// hasMDExtension reports whether a token is written with the extension a
// relative markdown link needs to keep resolving once the page it names moves
// directory. The case is not normalised away: a file is `.md` and not `.MD`, so
// a target spelled in capitals is not the same spelling.
func hasMDExtension(token string) bool {
	return len(token) > 3 && strings.EqualFold(token[len(token)-3:], ".md")
}

func trimMDExtension(target string) string {
	if hasMDExtension(target) {
		return target[:len(target)-3]
	}
	return target
}

// spanCovers reports whether any secret span of the document covers any part of
// [start, end). A byte range that only partly overlaps a secret is as much a
// disclosure as one wholly inside it, so the test is on the intersection rather
// than on the start offset alone.
func spanCovers(d *Doc, start, end int) bool {
	for _, s := range d.SecretSpans() {
		if s.SecretID != "" && s.StartByte < end && start < s.EndByte {
			return true
		}
	}
	return false
}

// wikilinkTargetRange locates the target token of a wikilink or an embed.
//
// goldmark's wikilink node does not carry offsets, and the first text child is
// the target, the fragment or the alias depending on which of them is present —
// so the node's own offset is not where the target is. What is always true is
// that the target is the text immediately after the `[[` that opens the link, so
// the nearest `[[` at or before the node is located and the bytes after it are
// compared with the target the parser read. The comparison is what makes this
// safe to guess with: a range that does not hold the expected bytes is not
// returned, so the worst case is a link that is not rewritten.
func wikilinkTargetRange(src []byte, off int, target string) (start, end int, ok bool) {
	if target == "" || off < 0 || off > len(src) {
		return 0, 0, false
	}
	open := bytes.LastIndex(src[:off], []byte("[["))
	if open < 0 {
		return 0, 0, false
	}
	start = open + 2
	end = start + len(target)
	if end > len(src) || !bytes.Equal(src[start:end], []byte(target)) {
		return 0, 0, false
	}
	// What follows the target is the fragment, the alias, or the closing
	// brackets. Anything else means this is not the range the parser read, and
	// a token in the middle of a longer word is not a link target.
	if end < len(src) {
		switch src[end] {
		case '#', '|', ']':
		default:
			return 0, 0, false
		}
	}
	return start, end, true
}

// markdownTargetRange locates the destination of a markdown link or image.
//
// The AST holds the destination as a value with no offset, and the node's first
// text child is the link's *label*, so the destination has to be found from the
// label's closing bracket. CommonMark's own rules for a link destination are
// followed here — optional whitespace, a `<…>` form or a run of characters that
// are not whitespace or an unbalanced parenthesis, with a backslash escaping
// whatever follows — and the bytes found are then compared with the destination
// the parser read. A destination written with escapes or in angle brackets does
// not compare equal, so it is left alone: rewriting it byte-surgically would
// mean deciding what the author meant by the escaping, and this package does not
// rewrite what it cannot reproduce exactly.
func markdownTargetRange(src []byte, off int, dest string) (start, end int, ok bool) {
	if dest == "" || off < 0 || off > len(src) {
		return 0, 0, false
	}
	// A link may not span a blank line, and the closing bracket of its label is
	// the first one that is followed by an opening parenthesis. Searching for
	// the pair rather than for the bracket alone is what keeps a label
	// containing a nested link from ending the search early.
	rest := src[off:]
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] != ']' || rest[i+1] != '(' {
			continue
		}
		j := i + 2
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
			j++
		}
		if j >= len(rest) {
			return 0, 0, false
		}
		if rest[j] == '<' {
			for k := j + 1; k < len(rest); k++ {
				if rest[k] == '>' {
					if string(rest[j:k+1]) == dest {
						return off + j, off + k + 1, true
					}
					return 0, 0, false
				}
			}
			return 0, 0, false
		}
		k := j
		for k < len(rest) {
			c := rest[k]
			if c == '\\' && k+1 < len(rest) {
				k += 2
				continue
			}
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ')' {
				break
			}
			k++
		}
		if string(rest[j:k]) == dest {
			return off + j, off + k, true
		}
		return 0, 0, false
	}
	return 0, 0, false
}
