package md

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	"go.abhg.dev/goldmark/wikilink"
)

// Renderer and parser priorities. The html renderer registers at 1000, so
// anything below that can take a node kind away from it.
const (
	passthroughPriority = 100
	calloutPriority     = 120
	highlightPriority   = 140
)

// Node kinds for the constructs this package renders itself. They are goldmark
// node kinds, so the ordinary renderer dispatch finds them.
var (
	// PassthroughKind is a block whose source is shown escaped.
	PassthroughKind = ast.NewNodeKind("SemiplanePassthrough")
	// PassthroughInlineKind is an inline construct shown escaped.
	PassthroughInlineKind = ast.NewNodeKind("SemiplanePassthroughInline")
	// CalloutTitleKind is a callout's parsed `[!type]` marker line.
	CalloutTitleKind = ast.NewNodeKind("SemiplaneCalloutTitle")
	// HighlightKind is an `==highlighted==` run.
	HighlightKind = ast.NewNodeKind("SemiplaneHighlight")
	// CommentKind is a `%%comment%%` run, which renders as nothing.
	CommentKind = ast.NewNodeKind("SemiplaneComment")
)

// Passthrough is a block this package will not interpret, carrying the exact
// source bytes of the construct. Nothing inside the range is ever parsed, so
// nothing inside it can become an attribute value, a URL or a script.
type Passthrough struct {
	ast.BaseBlock
	// Start and End are byte offsets into the source passed to Render.
	Start, End int
	// Name identifies the construct in the data-passthrough attribute, for a
	// stylesheet rule and for a failing assertion.
	Name string
}

// Kind implements ast.Node.
func (*Passthrough) Kind() ast.NodeKind { return PassthroughKind }

// Dump implements ast.Node.
func (n *Passthrough) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{
		"Name":  n.Name,
		"Range": fmt.Sprintf("[%d,%d)", n.Start, n.End),
	}, nil)
}

// PassthroughInline is the inline form of Passthrough.
type PassthroughInline struct {
	ast.BaseInline
	// Start and End are byte offsets into the source passed to Render.
	Start, End int
	// Name identifies the construct in the data-passthrough attribute.
	Name string
}

// Kind implements ast.Node.
func (*PassthroughInline) Kind() ast.NodeKind { return PassthroughInlineKind }

// Dump implements ast.Node.
func (n *PassthroughInline) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{
		"Name":  n.Name,
		"Range": fmt.Sprintf("[%d,%d)", n.Start, n.End),
	}, nil)
}

// unsupportedFences are the fenced-block languages whose contents are plugin
// query or embed syntax rather than code. A code fence in an unknown language
// is already safe: goldmark escapes it into <pre><code class="language-x">.
// These are the ones a reader would otherwise mistake for rendered output.
var unsupportedFences = map[string]string{
	"dataview":          "dataview",
	"dataviewjs":        "dataview",
	"dataview-view":     "dataview",
	"dataviewjs-view":   "dataview",
	"dataview-inline":   "dataview",
	"tasks":             "tasks-query",
	"taskquery":         "tasks-query",
	"taskqueries":       "tasks-query",
	"excalidraw":        "excalidraw",
	"excalidraw-plugin": "excalidraw",
	"canvas":            "canvas-embed",
}

// unsupportedEmbeds are the embed targets whose payload is a plugin's own
// document format, mapped to the name of the construct. An embed of a `.md`
// file is a page link and an embed of an image is an image; these are neither.
// `.excalidraw.md` is matched before `.excalidraw` would be, so the order of a
// map lookup does not depend on this slice.
var unsupportedEmbeds = []struct {
	ext  string
	name string
}{
	{".excalidraw.md", "excalidraw-embed"},
	{".excalidraw", "excalidraw-embed"},
	{".canvas", "canvas-embed"},
}

// passthroughRenderer writes every passthrough node as escaped source.
type passthroughRenderer struct{}

// RegisterFuncs implements renderer.NodeRendererFuncRegisterer.
func (passthroughRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(PassthroughKind, renderPassthrough)
	reg.Register(PassthroughInlineKind, renderPassthrough)
}

func renderPassthrough(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	start, end, name := passthroughOf(n)
	if start < 0 || end > len(source) || start > end {
		start, end, name = 0, 0, "malformed"
	}
	// An inline passthrough is a <code>, not a <pre>: it lands inside the
	// paragraph it was written in, and a block element there would produce
	// markup the browser silently relocates.
	tag, class := "pre", "passthrough"
	if n.Kind() == PassthroughInlineKind {
		tag, class = "code", "passthrough-inline"
	}
	_, _ = w.WriteString("<" + tag + ` class="` + class + `" data-passthrough="`)
	_, _ = w.Write(util.EscapeHTML([]byte(name)))
	_, _ = w.WriteString(`">` + PassthroughLabel + "\n")
	// The trailing line terminator is dropped so the closing tag does not sit
	// on a line of its own inside the pre.
	if end > start && source[end-1] == '\n' {
		end--
	}
	_, _ = w.Write(util.EscapeHTML(source[start:end]))
	_, _ = w.WriteString("\n</" + tag + ">\n")
	return ast.WalkContinue, nil
}

func passthroughOf(n ast.Node) (start, end int, name string) {
	switch p := n.(type) {
	case *Passthrough:
		return p.Start, p.End, p.Name
	case *PassthroughInline:
		return p.Start, p.End, p.Name
	}
	return 0, 0, ""
}

// passthroughBytes wraps a whole body in a passthrough block, for a file that
// is not Markdown at all.
func passthroughBytes(src []byte, name string) []byte {
	p := &Passthrough{Start: 0, End: len(src), Name: name}
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	_, _ = renderPassthrough(w, src, p, true)
	_ = w.Flush()
	return buf.Bytes()
}

// sanitize rewrites the tree so that every construct this package does not
// implement is replaced by a passthrough node carrying its source bytes. It
// runs between parsing and rendering, so the renderer's own walk only ever
// sees nodes it has a renderer for.
//
// It is a rewrite rather than a check on the output because an HTML block
// nested three levels deep inside a list inside a block quote has to be caught
// too, and only the tree knows where it is.
func sanitize(root ast.Node, src []byte) { sanitizeNode(root, src) }

func sanitizeNode(n ast.Node, src []byte) {
	for c := n.FirstChild(); c != nil; {
		// The sibling is captured before the rewrite, because replacing a node
		// unlinks it and an unlinked node has no next sibling.
		next := c.NextSibling()
		if repl, ok := passthroughFor(c, src); ok {
			c.Parent().ReplaceChild(c.Parent(), c, repl)
		} else {
			sanitizeNode(c, src)
		}
		c = next
	}
}

// passthroughFor returns the node that should replace n, if any.
//
// A callout is the one case that is not a replacement: a callout of a type
// this package knows keeps its block quote and only has its marker paragraph
// rewritten, so calloutFor reports false after having done that. The rewrite
// happens on the way in, before the tree is walked, so the block quote's own
// children are still sanitised on the way down.
func passthroughFor(n ast.Node, src []byte) (ast.Node, bool) {
	switch node := n.(type) {
	case *ast.HTMLBlock:
		if start, end, ok := blockRange(node); ok {
			return &Passthrough{Start: start, End: end, Name: "html-block"}, true
		}
	case *ast.RawHTML:
		if start, end, ok := segmentsRange(node.Segments); ok {
			return &PassthroughInline{Start: start, End: end, Name: "inline-html"}, true
		}
	case *ast.FencedCodeBlock:
		name, bad := unsupportedFence(src, node)
		if !bad {
			break
		}
		if _, end, ok := blockRange(node); ok {
			return &Passthrough{
				Start: fenceLineStart(src, node.Lines().At(0)),
				End:   end,
				Name:  name,
			}, true
		}
	case *ast.Blockquote:
		return calloutFor(node, src)
	case *wikilink.Node:
		name, unsupported := unsupportedTargetName(node.Target)
		if !node.Embed || !unsupported {
			break
		}
		if start, end, ok := wikilinkRange(node, src); ok {
			return &PassthroughInline{Start: start, End: end, Name: name}, true
		}
	}
	return nil, false
}

func unsupportedFence(src []byte, node *ast.FencedCodeBlock) (string, bool) {
	// Info is nil for a fence with no info string, which is the common case
	// and cannot be one of the unsupported languages.
	if node.Info == nil {
		return "", false
	}
	seg := node.Info.Segment
	if seg.Start < 0 || seg.Stop > len(src) || seg.Start > seg.Stop {
		return "", false
	}
	word, _ := splitFirstWord(string(src[seg.Start:seg.Stop]))
	name, ok := unsupportedFences[strings.ToLower(word)]
	return name, ok
}

// unsupportedTargetName reports whether an embed target holds a plugin's own
// document format, and names it. An embed of a `.md` file is a page link and an
// embed of an image is an image; these are neither.
func unsupportedTargetName(target []byte) (string, bool) {
	t := strings.ToLower(string(target))
	for _, e := range unsupportedEmbeds {
		if strings.HasSuffix(t, e.ext) {
			return e.name, true
		}
	}
	return "", false
}

// blockRange returns the byte range of a block node's own source lines.
func blockRange(n ast.Node) (start, end int, ok bool) {
	if n.Type() != ast.TypeBlock {
		return 0, 0, false
	}
	lines := n.Lines()
	if lines == nil || lines.Len() == 0 {
		return 0, 0, false
	}
	return lines.At(0).Start, lines.At(lines.Len() - 1).Stop, true
}

// segmentsRange returns the byte range covering every segment. The range is
// widened to include any gap, because a raw HTML run broken across lines must
// still be shown as one contiguous run of source.
func segmentsRange(segs *text.Segments) (start, end int, ok bool) {
	if segs == nil || segs.Len() == 0 {
		return 0, 0, false
	}
	start, end = segs.At(0).Start, segs.At(0).Stop
	for i := 1; i < segs.Len(); i++ {
		s := segs.At(i)
		if s.Start < start {
			start = s.Start
		}
		if s.Stop > end {
			end = s.Stop
		}
	}
	return start, end, start >= 0 && start <= end
}

// wikilinkRange recovers the byte range of a `![[...]]` embed. goldmark gives
// an inline node no offsets, so the delimiters are found by scanning around
// the label's own segment. The nearest `[[` before the label is always this
// link's, because a link's label can only be preceded by its own opening
// delimiter.
func wikilinkRange(n ast.Node, src []byte) (start, end int, ok bool) {
	text := n.FirstChild()
	t, isText := text.(*ast.Text)
	if !isText || t.Segment.Start <= 0 || t.Segment.Stop > len(src) {
		return 0, 0, false
	}
	open := bytes.LastIndex(src[:t.Segment.Start], []byte("[["))
	if open < 0 {
		return 0, 0, false
	}
	if open >= 1 && src[open-1] == '!' {
		open--
	}
	close := bytes.Index(src[t.Segment.Stop:], []byte("]]"))
	if close < 0 {
		return 0, 0, false
	}
	end = t.Segment.Stop + close + 2
	if open >= end {
		return 0, 0, false
	}
	return open, end, true
}

// fenceLineStart walks back from the first line of a fenced code block to the
// start of the fence's opening line, so a passthrough shows the construct the
// author wrote rather than a reconstruction of it. It falls back to the code
// line itself when the bytes do not look like a fence, which is the only way
// it can be wrong and the fallback is still a safe, escaped range.
// fenceLineStart returns the start of the fence's opening line, which is the
// line before the block's first content line. It falls back to the content
// line when the bytes before it are not a fence, which is the only way it can
// be wrong and the fallback is still a safe, escaped range.
func fenceLineStart(src []byte, first text.Segment) int {
	fallback := clamp(first.Start, 0, len(src))
	if first.Start <= 0 || first.Start > len(src) {
		return fallback
	}
	contentLine := first.Start
	for contentLine > 0 && src[contentLine-1] != '\n' {
		contentLine--
	}
	if contentLine == 0 {
		return fallback
	}
	openLine := contentLine - 1
	for openLine > 0 && src[openLine-1] != '\n' {
		openLine--
	}
	indent := openLine
	for indent < contentLine-1 && (src[indent] == ' ' || src[indent] == '\t') {
		indent++
	}
	run := indent
	for run < contentLine-1 && (src[run] == '`' || src[run] == '~') {
		run++
	}
	if run == indent {
		return fallback
	}
	return openLine
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
