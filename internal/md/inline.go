package md

import (
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// Highlight is an `==highlighted==` run. It carries the source range of the
// run's content and renders it escaped, without re-parsing the inside.
//
// goldmark-obsidian does not implement highlights, and without a parser the
// source reaches the page as the literal characters `==`. Not parsing the
// inside means markup nested in a highlight stays literal; a highlight is
// almost always plain text, and the alternative is a parser that would have to
// be right about every nested construct to be worth having.
type Highlight struct {
	ast.BaseInline
	// Start and End are byte offsets of the content, excluding the `==`.
	Start, End int
}

// Kind implements ast.Node.
func (*Highlight) Kind() ast.NodeKind { return HighlightKind }

// Dump implements ast.Node.
func (n *Highlight) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{
		"Range": rangeString(n.Start, n.End),
	}, nil)
}

// Comment is a `%%comment%%` run, which renders as nothing. An Obsidian
// comment may span lines, so the closing delimiter is looked for on the
// following lines too.
type Comment struct {
	ast.BaseInline
	// Start and End are byte offsets of the content, excluding the `%%`.
	Start, End int
}

// Kind implements ast.Node.
func (*Comment) Kind() ast.NodeKind { return CommentKind }

// Dump implements ast.Node.
func (n *Comment) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{
		"Range": rangeString(n.Start, n.End),
	}, nil)
}

func rangeString(start, end int) string {
	return "[" + itoa(start) + "," + itoa(end) + ")"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// delimiterRun returns the offset of a two-character delimiter at or after i,
// and 2 when one is there, 0 when there is not.
//
// It is capped at three characters on purpose. goldmark invokes an inline
// parser once per trigger byte, so counting a whole run of `=` on a line that
// is a megabyte of `=` would make parsing quadratic, and a comment or
// highlight is always written as exactly two characters.
func delimiterRun(line []byte, i int, c byte) (int, int) {
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i+2 >= len(line)+1 || line[i] != c || line[i+1] != c {
		return -1, 0
	}
	if i+2 < len(line) && line[i+2] == c {
		return -1, 0
	}
	return i, 2
}

// isDelimiterAt reports whether a closing delimiter starts at i.
func isDelimiterAt(line []byte, i int, c byte) bool {
	return i+1 < len(line) && line[i] == c && line[i+1] == c &&
		(i+2 >= len(line) || line[i+2] != c)
}

func leftFlanking(line []byte, i int) bool {
	return i < len(line) && !isInlineSpace(line[i])
}

func rightFlanking(line []byte, i int) bool {
	return i > 0 && !isInlineSpace(line[i-1])
}

func isInlineSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// highlightParser recognises `==...==`.
type highlightParser struct{}

// Trigger implements parser.InlineParser.
func (highlightParser) Trigger() []byte { return []byte{'='} }

// Parse implements parser.InlineParser. A nil node with a nil error means "this
// `=` is not a highlight, carry on", so `a == b` stays a comparison.
func (highlightParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	line, seg := block.PeekLine()
	start, consumed := delimiterRun(line, 0, '=')
	if start < 0 || !leftFlanking(line, start+consumed) {
		return nil
	}
	for i := start + consumed; i < len(line); i++ {
		if !isDelimiterAt(line, i, '=') || !rightFlanking(line, i) {
			continue
		}
		block.Advance(consumed + i - start)
		return &Highlight{Start: seg.Start + start + consumed, End: seg.Start + i}
	}
	return nil
}

// commentParser recognises `%%...%%`.
type commentParser struct{}

// Trigger implements parser.InlineParser.
func (commentParser) Trigger() []byte { return []byte{'%'} }

// Parse implements parser.InlineParser. A nil node with a nil error means "this
// `%%` is not a comment, carry on". The reader must be left advanced: goldmark
// re-invokes a parser that consumed nothing on the same bytes, and a parser
// that never makes progress is an unbounded loop rather than a wrong answer.
func (commentParser) Parse(parent ast.Node, block text.Reader, pc parser.Context) ast.Node {
	src := block.Source()
	line, seg := block.PeekLine()
	start, consumed := delimiterRun(line, 0, '%')
	if start < 0 {
		return nil
	}
	openStart := seg.Start + start
	contentStart := start + consumed
	contentSeg := seg
	for {
		for i := contentStart; i < len(line); i++ {
			if !isDelimiterAt(line, i, '%') {
				continue
			}
			// The advance is relative to where the reader is *now*, not to
			// where it was on entry. The loop below walks the reader forward a
			// line at a time and every AdvanceLine has already moved it, so a
			// delta from the entry position is counted once too often and eats
			// the rest of the paragraph. That is how `%%a\nb%% after` lost
			// `after`.
			_, here := block.Position()
			block.Advance(contentSeg.Start + i + 2 - here.Start)
			return &Comment{Start: openStart, End: contentSeg.Start + i}
		}
		// An unterminated comment runs to the end of the source. It has to
		// consume that much, not merely refuse: returning with the reader where
		// it started makes no progress, and goldmark's block loop re-enters this
		// parser on the same bytes and appends to the block buffer forever. A
		// 24-byte fixture that way exhausts 8 GiB, which is a denial of service
		// reachable by any player who can save a note.
		//
		// Consuming and returning no node leaves the rest of the file to be
		// rendered as ordinary Markdown, which is the recoverable reading of a
		// comment that was never closed. Swallowing the remainder instead would
		// silently delete a page's content over a stray `%%`.
		if len(line) == 0 {
			at, _ := block.Position()
			block.SetPosition(at, text.NewSegment(len(src), len(src)))
			return nil
		}
		block.AdvanceLine()
		line, seg = block.PeekLine()
		contentSeg, contentStart = seg, 0
	}
}

// highlightRenderer writes the nodes this file owns.
type highlightRenderer struct{}

// RegisterFuncs implements renderer.NodeRendererFuncRegisterer.
func (highlightRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(HighlightKind, renderHighlight)
	reg.Register(CommentKind, renderComment)
}

func renderHighlight(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	h, isHighlight := n.(*Highlight)
	if !isHighlight || h.Start < 0 || h.End > len(source) || h.Start > h.End {
		return ast.WalkContinue, nil
	}
	_, _ = w.WriteString("<mark>")
	_, _ = w.Write(util.EscapeHTML(source[h.Start:h.End]))
	_, _ = w.WriteString("</mark>")
	return ast.WalkContinue, nil
}

func renderComment(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	return ast.WalkContinue, nil
}
