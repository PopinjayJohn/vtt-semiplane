package md

import (
	"fmt"
	"path"
	"strings"
)

// Segment classifies a vault file into public and secret spans.
//
// The scan runs on raw bytes and shares no state with goldmark, because a
// misparse that reaches the renderer becomes a rendered secret and a misparse
// that does not is a redacted paragraph. Nothing here can be recovered from
// goldmark's AST, which by then has thrown the byte offsets away.
//
// Segment is a no-op constructor over Parse. The error result is always nil:
// every recoverable failure is recorded as a Doc.Problem and the document is
// still returned, because an unparseable page is a page the DM needs to see.
// The result is reserved for a failure that would make the span list
// untrustworthy.
func Segment(src []byte) (*Doc, error) { return Parse("", src), nil }

// Parse is Segment with the page's vault-relative path attached, which the
// extractor needs for the title fallback and the renderer needs to decide
// whether the file is a canvas.
func Parse(pagePath string, src []byte) *Doc {
	body, bodyRange, fm, fmRange, err := SplitFrontmatter(src)
	d := &Doc{
		Path:             normalizePath(pagePath),
		Bytes:            src,
		Frontmatter:      fm,
		FrontmatterRange: fmRange,
		Body:             body,
		BodyRange:        bodyRange,
	}
	if fmRange.Valid() {
		d.FrontmatterYAMLRange = yamlRange(src, fmRange, bodyRange)
	}
	if n := bomLen(src); n > 0 {
		d.BOM = src[:n]
	}
	if err != nil {
		if p, ok := err.(Problem); ok {
			d.Problems = append(d.Problems, p)
		} else {
			d.Problems = append(d.Problems, Problem{
				Code:      ProblemFrontmatterUnterminated,
				StartByte: fmRange.Start,
				Message:   "frontmatter could not be located"})
		}
	}
	fields, ferr := ParseFields(fm)
	if ferr != nil {
		d.Problems = append(d.Problems, Problem{
			Code:      ProblemFrontmatterInvalid,
			StartByte: d.FrontmatterYAMLRange.Start,
			Message:   "frontmatter is not valid yaml"})
	}
	d.Fields = fields
	segmentBody(d)
	return d
}

// yamlRange locates the YAML text inside the frontmatter block: the bytes
// between the opening fence line and the closing fence line. SplitFrontmatter's
// fixed result tuple cannot carry it, and a structured edit needs to splice
// the block without disturbing the fences.
func yamlRange(src []byte, fmRange, bodyRange Range) Range {
	_, openNext, ok := lineBounds(src, fmRange.Start)
	if !ok {
		return Range{Start: bodyRange.Start, End: bodyRange.Start}
	}
	// The closing fence is the last line of the block, and the block ends
	// where the body begins. The scan starts at that line's end, which is the
	// newline just before the body when there is one, and walks back to the
	// line's start. Starting the scan at the body's own first byte instead
	// would stop on the newline and include the closing fence in the YAML.
	closeEnd := bodyRange.Start
	if closeEnd > 0 && src[closeEnd-1] == '\n' {
		closeEnd--
	}
	closeStart := closeEnd
	for closeStart > openNext && src[closeStart-1] != '\n' {
		closeStart--
	}
	if closeStart < openNext {
		closeStart = openNext
	}
	return Range{Start: openNext, End: closeStart}
}

func segmentBody(d *Doc) {
	src, start, end := d.Bytes, d.BodyRange.Start, d.BodyRange.End
	cursor := start
	for pos := start; pos < end; {
		lineEnd, next, more := lineBounds(src, pos)
		if !more {
			break
		}
		// Every iteration must move the cursor forward. A branch that records a
		// problem and leaves `pos` alone re-reads the same fence forever and
		// appends the same Problem on every pass, which is an unbounded loop
		// that looks like a hang and reads as a memory leak. It cost a day of
		// bisection once already; the guard is the assertion, not the fix.
		if next <= pos {
			break
		}
		f, ok := fenceAt(src[pos:lineEnd])
		if !ok || !IsSecret(f.Info) {
			pos = next
			continue
		}
		dir, derr := ParseFenceDirective(f.Info)
		// A fence that claims to be a secret is one, whatever its directive
		// says. The old response to a directive we could not understand was
		// public passthrough, and that was a leak: AGENTS.md documents
		// `title=<optional>` with no quoting requirement, so `title=The cellar
		// key` scanned as one known key plus two unknown ones and the body was
		// served in plaintext to a player who was not a DM.
		//
		// Failing closed costs a DM nothing they can see — the file is on their
		// disk, and the problem is reported — and it is the only answer that
		// cannot turn a documentation ambiguity into a disclosed secret.
		unreadable := false
		if derr != nil {
			unreadable = true
			d.Problems = append(d.Problems, Problem{
				Code:      ProblemSecretBadDirective,
				StartByte: pos,
				Message:   "secret fence directive could not be parsed"})
		}
		if dir.HasUnknown {
			unreadable = true
			d.Problems = append(d.Problems, Problem{
				Code:      ProblemSecretUnknownKey,
				StartByte: pos,
				Message:   "secret fence directive has an unknown key"})
		}
		{
			d.emitPublic(cursor, pos)
			stop, closed, inner := findSecretEnd(src, next, end, f)
			if inner >= 0 {
				d.Problems = append(d.Problems, Problem{
					Code:      ProblemSecretNested,
					StartByte: inner,
					Message:   "secret fence nested inside a secret fence"})
			}
			if !closed {
				d.Problems = append(d.Problems, Problem{
					Code:      ProblemSecretUnterminated,
					StartByte: pos,
					SecretID:  dir.ID,
					Message:   "secret fence is not closed"})
			}
			id := dir.ID
			switch {
			case unreadable && id == "":
				// The directive named an id we cannot trust, and either none or
				// one we did not accept. A synthetic id that cannot collide with
				// a real 12-hex-character id: the index keys on it, so a
				// corrected file produces a different span and the stale
				// placeholder is replaced rather than accumulated.
				id = fmt.Sprintf("%s%08x", ProblemUnparsableIDPrefix, pos)
				d.Problems = append(d.Problems, Problem{
					Code:      ProblemSecretMissingID,
					StartByte: pos, SecretID: id,
					Message: "secret fence has no usable id"})
			case id == "":
				id = fmt.Sprintf("anon-%08x", pos)
				d.Problems = append(d.Problems, Problem{
					Code:      ProblemSecretMissingID,
					StartByte: pos, SecretID: id,
					Message: "secret fence has no id"})
			}
			if dir.BadVisibility {
				d.Problems = append(d.Problems, Problem{
					Code:      ProblemSecretBadVisibility,
					StartByte: pos, SecretID: id,
					Message: "secret fence visibility is not a known value"})
			}
			d.Spans = append(d.Spans, Span{
				Kind: SpanSecret, SecretID: id, StartByte: pos, EndByte: stop})
			if stop <= pos {
				stop = next
			}
			cursor, pos = stop, stop
		}
	}
	d.emitPublic(cursor, end)
}

// emitPublic appends the public span [from, to), skipping an empty one. A
// zero-length span carries no information for a consumer indexing by byte
// offset, and every one of them is a chance to be off by one.
func (d *Doc) emitPublic(from, to int) {
	if to > from {
		d.Spans = append(d.Spans, Span{Kind: SpanPublic, StartByte: from, EndByte: to})
	}
}

// Fence is a fenced-code delimiter found on one line.
type Fence struct {
	// Offset is the byte offset of the fence's first character within the
	// line it was found in.
	Offset int
	// QuoteDepth is the number of block-quote markers the line opened with.
	// A fence inside a block quote is still a fence, and its closing fence has
	// to sit at the same depth or the quote would have ended.
	QuoteDepth int
	// Indent is the column of the fence's first character, counted after the
	// quote markers are removed.
	Indent int
	// Char is the run character, ` or ~.
	Char byte
	// Run is the length of the character run, at least three.
	Run int
	// Info is the info string, trailing whitespace removed.
	Info string
}

// fenceAt parses one line as a fence delimiter. It reports false for an
// indented code block, a thematic break, a backtick run whose info string
// contains a backtick, and every ordinary line.
//
// The backtick rule is CommonMark's, and it is why a directive with a stray
// backtick in it is not a secret fence: such a line is a paragraph. The
// directive parser would reject the stray backtick as an unknown key in any
// case, so both readings land on the same answer and there is nothing to gain
// from a second, more permissive path.
func fenceAt(line []byte) (Fence, bool) {
	offset, depth, indent, rest := stripQuotePrefix(line)
	if len(rest) < 3 {
		return Fence{}, false
	}
	c := rest[0]
	if c != '`' && c != '~' {
		return Fence{}, false
	}
	run := 0
	for run < len(rest) && rest[run] == c {
		run++
	}
	if run < 3 {
		return Fence{}, false
	}
	info := strings.TrimRight(string(rest[run:]), " \t\r")
	// A backtick run may not carry a backtick in its info string; a tilde run
	// may, which is what lets a ``` fence wrap a ~~~ example.
	if c == '`' && strings.ContainsRune(info, '`') {
		return Fence{}, false
	}
	return Fence{Offset: offset, QuoteDepth: depth, Indent: indent, Char: c, Run: run, Info: info}, true
}

// stripQuotePrefix removes any leading `>` markers and the indentation that
// follows them, reporting how deep the quote is, where the content starts and
// what column that is. CommonMark gives a block quote's content an optional
// single space of padding, which is why one space is consumed per marker.
//
// The whitespace before a `>` does not count toward the content's indent: a
// block quote's body is dedented, so a fence inside one is compared against
// other fences at the same depth on their own terms.
func stripQuotePrefix(line []byte) (offset, depth, indent int, rest []byte) {
	i := 0
	for i < len(line) {
		j := i
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		if j < len(line) && line[j] == '>' {
			depth++
			i = j + 1
			if i < len(line) && (line[i] == ' ' || line[i] == '\t') {
				i++
			}
			continue
		}
		return j, depth, j, line[j:]
	}
	return i, depth, i, nil
}

// findSecretEnd returns the offset just past the closing fence of a secret
// opened by f. inner is the offset of a secret fence found inside the body, or
// -1; a nested fence cannot itself be secret, so it is literal text and the
// outer span runs past it. closed is false when the body ends first.
func findSecretEnd(src []byte, from, end int, f Fence) (stop int, closed bool, inner int) {
	inner = -1
	for pos := from; pos < end; {
		lineEnd, next, more := lineBounds(src, pos)
		if !more {
			break
		}
		if g, ok := fenceAt(src[pos:lineEnd]); ok {
			switch {
			case g.QuoteDepth == f.QuoteDepth && g.Char == f.Char &&
				g.Run >= f.Run && g.Info == "" && g.Indent <= f.Indent+3:
				return next, true, inner
			case inner < 0 && IsSecret(g.Info):
				inner = pos
			}
		}
		pos = next
	}
	return end, false, inner
}

// normalizePath puts a vault-relative path into the canonical form the rest of
// the app compares: forward slashes, no leading slash, no `.` segments.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}
