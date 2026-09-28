package md

import (
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// calloutKinds are the callout types this package knows how to title. A
// `[!type]` outside this set is a passthrough rather than a broken callout:
// the type is a plugin's namespace, and rendering a note from a plugin nobody
// installed as though it were core would be worse than showing its source.
var calloutKinds = map[string]bool{
	"abstract": true, "summary": true, "tldr": true,
	"info": true, "todo": true, "tip": true, "hint": true, "important": true,
	"success": true, "check": true, "done": true,
	"question": true, "help": true, "faq": true,
	"warning": true, "caution": true, "attention": true,
	"failure": true, "fail": true, "missing": true, "danger": true, "error": true,
	"bug": true, "example": true, "quote": true, "cite": true,
	"note": true,
}

// CalloutTitle is a callout's `> [!note] Title` marker line after the marker
// has been parsed off it. It stands in for the block quote's first paragraph,
// which is where the marker was, and carries the parsed type, fold state and
// title so the renderer reads them from the tree rather than re-parsing text.
type CalloutTitle struct {
	ast.BaseBlock
	// Name is the lowercased callout type, without the brackets.
	Name string
	// Fold is "+" for expanded, "-" for collapsed and "" for the default,
	// which is expanded.
	Fold string
	// Title is the text after the marker on the marker line, unescaped.
	Title string
}

// Kind implements ast.Node.
func (*CalloutTitle) Kind() ast.NodeKind { return CalloutTitleKind }

// Dump implements ast.Node.
func (n *CalloutTitle) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{
		"Name": n.Name, "Fold": n.Fold, "Title": n.Title,
	}, nil)
}

// Expanded reports whether the callout should be open. No marker means the
// default, which is expanded, matching Obsidian.
func (n *CalloutTitle) Expanded() bool { return n.Fold != "-" }

// calloutFor recognises a callout and returns the node that should replace the
// block quote's marker paragraph: a CalloutTitle for a type this package
// knows, or a Passthrough for one it does not.
func calloutFor(bq *ast.Blockquote, src []byte) (ast.Node, bool) {
	p, isParagraph := bq.FirstChild().(*ast.Paragraph)
	if !isParagraph {
		return nil, false
	}
	lines := p.Lines()
	if lines == nil || lines.Len() == 0 {
		return nil, false
	}
	seg := lines.At(0)
	if seg.Start < 0 || seg.Stop > len(src) {
		return nil, false
	}
	name, fold, title, ok := parseCalloutMarker(string(src[seg.Start:seg.Stop]))
	if !ok {
		return nil, false
	}
	if !calloutKinds[name] {
		start, stop, hasRange := subtreeRange(bq)
		if !hasRange {
			return nil, false
		}
		return &Passthrough{Start: start, End: stop, Name: "callout"}, true
	}
	// The marker line is very nearly always the whole of the block quote's
	// first paragraph, but when the author ran the title into the next line
	// goldmark keeps both in one paragraph separated by a soft line break. The
	// split is made there: everything up to the break belongs to the marker
	// and is dropped, everything after it becomes the callout's body. A
	// paragraph with more than one line and no line break to split on is left
	// alone, because rewriting it would mean dropping text to make the frame
	// look right.
	rest, split := splitAtLineBreak(p, lines)
	if lines.Len() > 1 && !split {
		return nil, false
	}
	titleNode := &CalloutTitle{Name: name, Fold: fold, Title: title}
	bq.ReplaceChild(bq, p, titleNode)
	if rest.Len() > 0 {
		body := ast.NewParagraph()
		body.SetLines(rest)
		for _, c := range childrenAfter(p, split) {
			body.AppendChild(body, c)
		}
		bq.InsertAfter(bq, titleNode, body)
	}
	return nil, false
}

// splitAtLineBreak returns the paragraph's lines after the first, and whether
// the paragraph's inline children could be split at the line break that
// separates them. In goldmark v1 a line break inside a paragraph is a flag on
// the Text node that ends the line, not a node of its own.
func splitAtLineBreak(p *ast.Paragraph, lines *text.Segments) (rest *text.Segments, split bool) {
	rest = &text.Segments{}
	for i := 1; i < lines.Len(); i++ {
		rest.Append(lines.At(i))
	}
	if lines.Len() == 1 {
		return rest, true
	}
	for c := p.FirstChild(); c != nil; c = c.NextSibling() {
		if isLineBreakText(c) {
			return rest, true
		}
	}
	return rest, false
}

// childrenAfter collects the paragraph's inline children that follow the line
// break, detaching them from the paragraph as it goes.
func childrenAfter(p *ast.Paragraph, split bool) []ast.Node {
	var out []ast.Node
	seen := !split
	for c := p.FirstChild(); c != nil; {
		next := c.NextSibling()
		if !seen {
			seen = isLineBreakText(c)
			c = next
			continue
		}
		p.RemoveChild(p, c)
		out = append(out, c)
		c = next
	}
	return out
}

func isLineBreakText(n ast.Node) bool {
	t, ok := n.(*ast.Text)
	return ok && (t.SoftLineBreak() || t.HardLineBreak())
}

// parseCalloutMarker parses `[!type]`, `[!type]+` and `[!type]-` followed by an
// optional title. The marker must start the line: a `[!note]` in the middle of
// a paragraph is ordinary text.
func parseCalloutMarker(line string) (name, fold, title string, ok bool) {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i+1 >= len(line) || line[i] != '[' || line[i+1] != '!' {
		return "", "", "", false
	}
	j := i + 2
	for j < len(line) && line[j] != ']' && line[j] != '\n' && line[j] != '\r' {
		j++
	}
	if j >= len(line) || line[j] != ']' {
		return "", "", "", false
	}
	name = strings.ToLower(strings.TrimSpace(line[i+2 : j]))
	if name == "" {
		return "", "", "", false
	}
	rest := line[j+1:]
	// The fold marker is only a fold marker when it is not glued to the title,
	// so that a callout titled `+1` is a title and not a fold. The end of the
	// line counts as a separator: `> [!note]+` is the commonest fold spelling
	// there is, and reading its `+` as a title is not a corner case.
	if rest != "" && (rest[0] == '+' || rest[0] == '-') &&
		(len(rest) == 1 || isInlineSpace(rest[1])) {
		fold, rest = rest[:1], rest[1:]
	}
	return name, fold, strings.TrimSpace(rest), true
}

// subtreeRange returns the byte range covering every line in a node's subtree,
// which is how a block whose extent is not its own first line — a block quote,
// a list item — is turned back into source.
func subtreeRange(n ast.Node) (start, stop int, ok bool) {
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering || c.Type() != ast.TypeBlock {
			return ast.WalkContinue, nil
		}
		lines := c.Lines()
		if lines == nil || lines.Len() == 0 {
			return ast.WalkContinue, nil
		}
		s, e := lines.At(0).Start, lines.At(lines.Len()-1).Stop
		if !ok {
			start, stop, ok = s, e, true
		} else {
			if s < start {
				start = s
			}
			if e > stop {
				stop = e
			}
		}
		return ast.WalkContinue, nil
	})
	return start, stop, ok
}

// calloutRenderer takes over ast.KindBlockquote so a block quote whose first
// child is a CalloutTitle renders as a <details>, and every other block quote
// renders as a plain <blockquote>.
type calloutRenderer struct{}

// RegisterFuncs implements renderer.NodeRendererFuncRegisterer.
func (calloutRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindBlockquote, renderBlockquote)
	reg.Register(CalloutTitleKind, renderCalloutTitle)
}

func renderBlockquote(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	title, isCallout := calloutTitleOf(n)
	if !isCallout {
		if entering {
			_, _ = w.WriteString("<blockquote>\n")
		} else {
			_, _ = w.WriteString("</blockquote>\n")
		}
		return ast.WalkContinue, nil
	}
	if !entering {
		_, _ = w.WriteString("</details>\n")
		return ast.WalkContinue, nil
	}
	_, _ = w.WriteString(`<details class="callout" data-callout="`)
	_, _ = w.Write(util.EscapeHTML([]byte(title.Name)))
	_, _ = w.WriteString(`"`)
	if title.Expanded() {
		_, _ = w.WriteString(" open")
	}
	if title.Fold != "" {
		_, _ = w.WriteString(` data-callout-fold="` + title.Fold + `"`)
	}
	_, _ = w.WriteString(">\n<summary class=\"callout-title\">")
	label := title.Title
	if label == "" {
		label = title.Name
	}
	_, _ = w.Write(util.EscapeHTML([]byte(label)))
	_, _ = w.WriteString("</summary>\n")
	return ast.WalkContinue, nil
}

func renderCalloutTitle(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	return ast.WalkContinue, nil
}

func calloutTitleOf(n ast.Node) (*CalloutTitle, bool) {
	if n.Kind() != ast.KindBlockquote {
		return nil, false
	}
	title, ok := n.FirstChild().(*CalloutTitle)
	return title, ok
}
