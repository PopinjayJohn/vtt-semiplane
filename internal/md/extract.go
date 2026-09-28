package md

import (
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/yuin/goldmark/ast"
	"go.abhg.dev/goldmark/hashtag"
	"go.abhg.dev/goldmark/wikilink"
)

// DefaultPageType is the page type of a document whose frontmatter does not
// name one. It is what store.Page.PageType holds for an ordinary note.
const DefaultPageType = "note"

// LinkKind classifies an outgoing reference. The values are the ones
// store.LinkKind uses, spelled here so that md does not have to import store
// to describe what it found; the indexer converts.
type LinkKind string

const (
	// LinkWikilink is `[[target]]`.
	LinkWikilink LinkKind = "wikilink"
	// LinkEmbed is `![[target]]` where the target is a page.
	LinkEmbed LinkKind = "embed"
	// LinkMarkdown is a `[text](url)` whose target is a page.
	LinkMarkdown LinkKind = "markdown"
	// LinkAttachment is any reference whose target is a file that is not a
	// page: an image, a PDF, an Excalidraw drawing.
	LinkAttachment LinkKind = "attachment"
	// LinkTag is an inline `#tag`.
	LinkTag LinkKind = "tag"
)

// Tag is a normalised tag name with the span it was written in. The span is
// what makes a tag found inside a secret distinguishable from one found in
// public text: the consumer filters on Span.SecretID.
type Tag struct {
	// Name is the tag lowercased, with the leading # removed and any nested
	// `#` kept, so `#Area/Port` is one tag.
	Name string
	// Span is where the tag was written. A tag in a secret span carries that
	// secret's id.
	Span Span
}

// Link is one outgoing reference with the span it was written in.
type Link struct {
	// Kind is the kind of reference.
	Kind LinkKind
	// TargetRaw is the target exactly as the author wrote it, minus the alias
	// half of a `[[a|b]]` and including the `#fragment`.
	TargetRaw string
	// Target is the page part of TargetRaw, with any extension removed.
	Target string
	// Alias is the display text of a `[[a|b]]`, empty when there was none.
	Alias string
	// Heading is the `#heading` fragment, empty when there was none.
	Heading string
	// BlockRef is the `#^block` fragment, empty when there was none.
	BlockRef string
	// SelfLink reports a `[[#heading]]` with no target, which points at the
	// page it is written in.
	SelfLink bool
	// Line is the 1-based line the reference starts on.
	Line int
	// Span is where the reference was written.
	Span Span
	// Offset is the byte offset of the reference in Doc.Body, which is what
	// the AST carries. Doc.FileOffset turns it into a file offset; the line and
	// the span are already resolved, and the bulk link updater in a later phase
	// needs the offset to rewrite the target in place.
	Offset int
}

// Heading is one heading with the span it was written in.
type Heading struct {
	// Level is 1 to 6.
	Level int
	// Text is the heading's text with the `#` markers and the closing `###`
	// sequence removed, but otherwise unnormalised.
	Text string
	// Slug is the GitHub-style anchor: lowercase, punctuation dropped, spaces
	// to hyphens, deduplicated per document with -1, -2 suffixes.
	Slug string
	// Ordinal is the heading's 1-based position among the document's
	// headings, counting the ones inside secrets.
	Ordinal int
	// Span is where the heading was written. A heading inside a secret carries
	// that secret's id, because a heading's existence is itself a leak.
	Span Span
	// Offset is the byte offset of the heading in Doc.Bytes, kept for the same
	// reason Link.Offset is: a later phase rewrites anchors in place.
	Offset int
}

// Attachment is a reference to a file that is not a page.
type Attachment struct {
	// Name is the target as written, with any size or fragment suffix kept:
	// the vault is the only thing that can turn it into a real path.
	Name string
	// Line is the 1-based line the reference starts on.
	Line int
	// Span is where the reference was written.
	Span Span
}

// Extracted is everything one document contributes to the index. Every field
// that can come from inside a secret carries the Span it came from, so the
// indexer can attribute it and every reader of the index can filter on it.
type Extracted struct {
	// Title is the first H1, else the frontmatter title, else the basename.
	Title string
	// Aliases are the frontmatter aliases, in the order they were written.
	Aliases []string
	// Tags are the frontmatter and inline tags, deduplicated by name.
	Tags []Tag
	// Links are the outgoing references, in document order.
	Links []Link
	// Headings are the headings, in document order.
	Headings []Heading
	// Attachments are the non-page file references, in document order.
	Attachments []Attachment
	// PageType is the frontmatter `type` or DefaultPageType.
	PageType string
	// CodeLanguages are the info-string languages of the document's fenced
	// code blocks, deduplicated and in first-appearance order.
	CodeLanguages []string
}

// Extract walks a document's whole body — secrets included, so that a heading
// inside a secret can be attributed to it — and returns everything the index
// needs.
//
// The walk reads structure, not bytes: goldmark has already decided what a
// link is and where a heading begins, and re-deriving either from the raw text
// would be a second Markdown parser with a second set of bugs.
//
// r may be nil, in which case a Renderer with no extenders is used. That
// keeps the call sites in the indexer free of a nil check for a function whose
// only non-nil use is the plugin extenders.
func Extract(d *Doc, r *Renderer) (Extracted, []Problem) {
	var out Extracted
	if r == nil {
		r = New(Options{})
	}
	fields := d.Fields
	out.PageType = FieldString(fields, "type")
	if out.PageType == "" {
		out.PageType = DefaultPageType
	}
	out.Aliases = trimmedStrings(FieldStrings(fields, "aliases", "alias"))
	frontmatterSpan, _ := d.SpanAt(d.FrontmatterYAMLRange.Start)
	// The line index is built over the whole file, because a line number is a
	// line in the file: an editor showing "line 42" is not talking about the
	// body.
	lines := newLineIndex(d.Bytes)
	collect := &facts{seenTags: map[string]bool{}, seenLang: map[string]bool{}}
	for _, raw := range FieldStrings(fields, "tags", "tag") {
		collect.addTag(&out, raw, frontmatterSpan)
	}

	// The body is walked whole, so a secret fence parses as the fenced code
	// block it is and its interior contributes nothing.
	collect.walk(r, d.Body, d.BodyRange.Start, docAttributor(d), lines, &out)

	// Each secret's body is then walked on its own. Inside the whole-body parse
	// it is code, so a heading written in a secret would otherwise be invisible
	// to the table of contents, the backlinks and the search index — and a fact
	// that is missing from the index is a fact no feature can find. What comes
	// out carries the secret's span, and every consumer of these rows filters
	// on it.
	for _, s := range d.SecretSpans() {
		start, stop := secretBody(d.Bytes, s)
		if start >= stop || start < 0 || stop > len(d.Bytes) {
			continue
		}
		collect.walk(r, d.Bytes[start:stop], start, fixedAttributor(s), lines, &out)
	}

	// Facts are collected in the order they were walked, which is body order
	// followed by secret order, and re-sorted into the order they appear in the
	// file so that an ordinal or a link list reads top to bottom.
	sort.SliceStable(out.Headings, func(i, j int) bool {
		return out.Headings[i].Offset < out.Headings[j].Offset
	})
	sort.SliceStable(out.Links, func(i, j int) bool {
		return out.Links[i].Offset < out.Links[j].Offset
	})
	slugs := map[string]int{}
	for i := range out.Headings {
		h := &out.Headings[i]
		h.Ordinal = i + 1
		slug := h.Slug
		if seen := slugs[slug]; seen > 0 {
			slug = slug + "-" + itoa(seen)
		}
		slugs[h.Slug]++
		h.Slug = slug
	}
	// The title is the first H1 in the file, wherever it was found.
	if out.Title == "" {
		for _, h := range out.Headings {
			if h.Level == 1 {
				out.Title = h.Text
				break
			}
		}
	}
	if out.Title == "" {
		out.Title = FieldString(fields, "title")
	}
	if out.Title == "" {
		out.Title = Basename(d.Path)
	}
	return out, d.Problems
}

// facts accumulates what one walk over one region found. The seen sets live
// here rather than on Extracted because a document's tags and code languages are
// deduplicated across every region it has.
type facts struct {
	seenTags map[string]bool
	seenLang map[string]bool
}

// attributor says which span a fact found at a file offset belongs to.
type attributor func(off int) Span

// docAttributor resolves a fact's span from the document. It is what the whole
// body is walked with, because a body is not all public: a fact in the middle
// of a secret's fence has to come out attributed to that secret even though the
// body walk never saw inside it.
func docAttributor(d *Doc) attributor {
	return func(off int) Span {
		s, _ := d.SpanAt(off)
		return s
	}
}

// fixedAttributor attributes every fact of a region to one span, which is what
// a secret's own body is walked with: everything found inside a secret belongs
// to that secret.
func fixedAttributor(s Span) attributor {
	return func(int) Span { return s }
}

// walk extracts the facts from one region of the document. src is the region's
// bytes, base is its offset in the file, and attribute says which span each
// fact it finds belongs to.
func (f *facts) walk(r *Renderer, src []byte, base int, attribute attributor, lines *lineIndex, out *Extracted) {
	root := r.Parse(src)
	_ = ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch node := n.(type) {
		case *ast.Heading:
			off, text := headingText(src, node)
			abs := base + off
			out.Headings = append(out.Headings, Heading{
				Level:  node.Level,
				Text:   text,
				Slug:   Slug(text),
				Offset: abs,
				Span:   attribute(abs),
			})
		case *wikilink.Node:
			if l := linkFromWikilink(src, node); l != nil {
				l.Offset += base
				f.addLink(lines, out, l, attribute(l.Offset))
			}
		case *ast.Link:
			if l := linkFromMarkdown(src, node, false); l != nil {
				l.Offset += base
				f.addLink(lines, out, l, attribute(l.Offset))
			}
		case *ast.Image:
			if l := linkFromMarkdown(src, node, true); l != nil {
				l.Offset += base
				f.addLink(lines, out, l, attribute(l.Offset))
			}
		case *hashtag.Node:
			off := nodeOffset(src, node)
			if off > 0 && isWordByte(src[off-1]) {
				break
			}
			f.addTag(out, string(node.Tag), attribute(base+off))
		case *ast.FencedCodeBlock:
			if node.Info == nil {
				break
			}
			seg := node.Info.Segment
			if seg.Start < 0 || seg.Stop > len(src) {
				break
			}
			word, _ := splitFirstWord(string(src[seg.Start:seg.Stop]))
			// `secret` is this package's own fence syntax, not a language a
			// reader chose, so it is not a code language.
			if word != "" && !strings.EqualFold(word, SecretFenceWord) && !f.seenLang[word] {
				f.seenLang[word] = true
				out.CodeLanguages = append(out.CodeLanguages, word)
			}
		}
		return ast.WalkContinue, nil
	})
}

// addLink attributes a link to the span and line it was written in, then files
// it. The attribution is why the secret regions are walked at all: a reference
// inside a secret has to come out carrying that secret's id, or the index would
// hold a link no reader is allowed to follow.
func (f *facts) addLink(lines *lineIndex, out *Extracted, l *Link, span Span) {
	l.Line = lines.line(l.Offset)
	l.Span = span
	out.Links = append(out.Links, *l)
	if l.Kind == LinkAttachment {
		out.Attachments = append(out.Attachments, Attachment{
			Name: l.TargetRaw, Line: l.Line, Span: span,
		})
	}
}

func (f *facts) addTag(out *Extracted, raw string, span Span) {
	name := NormalizeTag(raw)
	if name == "" || f.seenTags[name] {
		return
	}
	f.seenTags[name] = true
	out.Tags = append(out.Tags, Tag{Name: name, Span: span})
}

func linkFromWikilink(src []byte, n *wikilink.Node) *Link {
	target := string(n.Target)
	fragment := string(n.Fragment)
	raw := target
	if fragment != "" {
		raw += "#" + fragment
	}
	label := inlineLabel(src, n)
	alias := ""
	if label != "" && label != raw {
		alias = label
	}
	l := &Link{
		Kind:      LinkWikilink,
		TargetRaw: raw,
		Target:    target,
		Alias:     alias,
		SelfLink:  target == "" && fragment != "",
		Offset:    nodeOffset(src, n),
	}
	if n.Embed {
		l.Kind = LinkEmbed
	}
	if strings.HasPrefix(fragment, "^") {
		l.BlockRef = strings.TrimPrefix(fragment, "^")
	} else {
		l.Heading = fragment
	}
	// An embed of a page is a page link; an embed of anything with a file
	// extension is an attachment, and the only difference between the two is
	// the extension.
	if n.Embed && hasExtension([]byte(target)) && !isMarkdownExt(target) {
		l.Kind = LinkAttachment
	}
	return l
}

func linkFromMarkdown(src []byte, n ast.Node, image bool) *Link {
	dest := markdownDestination(src, n)
	if dest == "" {
		return nil
	}
	kind := LinkMarkdown
	if image {
		kind = LinkAttachment
	}
	if hasExtension([]byte(dest)) && !isMarkdownExt(dest) {
		kind = LinkAttachment
	}
	return &Link{
		Kind:      kind,
		TargetRaw: dest,
		Target:    strings.TrimSuffix(dest, ".md"),
		Alias:     inlineLabel(src, n),
		Offset:    nodeOffset(src, n),
	}
}

func markdownDestination(src []byte, n ast.Node) string {
	switch node := n.(type) {
	case *ast.Link:
		return string(node.Destination)
	case *ast.Image:
		return string(node.Destination)
	}
	return ""
}

// inlineLabel returns the text of an inline node's first text child, which for
// a link and for a wikilink is the display text. Inline nodes have no offsets
// of their own, so the child's segment is the only place the text exists.
func inlineLabel(src []byte, n ast.Node) string {
	if t, ok := n.FirstChild().(*ast.Text); ok &&
		t.Segment.Start >= 0 && t.Segment.Stop <= len(src) && t.Segment.Start <= t.Segment.Stop {
		return string(src[t.Segment.Start:t.Segment.Stop])
	}
	return ""
}

// nodeOffset returns the byte offset an inline node starts at, for attributing
// it to a span.
func nodeOffset(src []byte, n ast.Node) int {
	if t, ok := n.FirstChild().(*ast.Text); ok && t.Segment.Start >= 0 {
		return t.Segment.Start
	}
	return 0
}

// headingText returns the byte offset the heading starts at and its text. The
// `#` markers are not in the node's lines, so they are skipped by the offset
// and the closing `###` of an ATX heading is trimmed from the text.
func headingText(src []byte, n *ast.Heading) (offset int, text string) {
	lines := n.Lines()
	if lines == nil || lines.Len() == 0 {
		return 0, ""
	}
	first, last := lines.At(0), lines.At(lines.Len()-1)
	if first.Start < 0 || last.Stop > len(src) || first.Start > last.Stop {
		return 0, ""
	}
	text = string(src[first.Start:last.Stop])
	if n.Level > 0 && n.Parent() != nil {
		// An ATX heading may be closed with a trailing run of hashes, which
		// is not part of its text.
		text = strings.TrimRight(strings.TrimRight(text, "#"), " \t")
	}
	return first.Start, text
}

// isWordByte reports whether a byte can be part of a word, which is what
// decides whether a `#` starts a tag or sits inside one. goldmark-obsidian's
// hashtag parser takes `not#atag` for a tag, and a tag panel that fills up with
// the middle of words is worse than a tag the author forgot to space.
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// NormalizeTag lowercases a tag and strips the leading `#`, keeping any
// further `#` so that `#Area#Port` stays one tag. Obsidian tags are
// case-insensitive, so a lookup that did not normalise would find only the
// spelling the first author happened to use.
func NormalizeTag(name string) string {
	name = strings.TrimSpace(name)
	for strings.HasPrefix(name, "#") {
		name = name[1:]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// Slug produces the GitHub-style anchor for a heading: lowercased, with
// punctuation dropped, whitespace to hyphens, and existing hyphens and
// underscores kept. Deduplication is the caller's job because the counter is
// per document.
func Slug(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	pendingSpace := false
	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			if pendingSpace && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingSpace = false
			b.WriteRune(unicode.ToLower(r))
		case r == '-' || r == '_':
			if pendingSpace && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingSpace = false
			b.WriteRune(r)
		case unicode.IsSpace(r):
			pendingSpace = true
		}
	}
	// github-slugger drops a leading or trailing hyphen, so "A - B" and
	// "- A - B -" do not produce slugs that differ only in their ends.
	return strings.Trim(b.String(), "-")
}

func trimmedStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func isMarkdownExt(name string) bool {
	return strings.EqualFold(path.Ext(name), ".md")
}

// lineIndex answers "which line is this byte offset on" without rescanning the
// body for every node.
type lineIndex struct {
	starts []int
}

func newLineIndex(body []byte) *lineIndex {
	idx := &lineIndex{starts: make([]int, 1, 1+strings.Count(string(body), "\n"))}
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			idx.starts = append(idx.starts, i+1)
		}
	}
	return idx
}

func (l *lineIndex) line(off int) int {
	if off < 0 {
		return 1
	}
	i := sort.SearchInts(l.starts, off+1) - 1
	if i < 0 {
		return 1
	}
	return i + 1
}
