package md

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Problem codes reported by this file. They are part of the package's contract
// with the indexer and the UI, so they are constants rather than literals at
// the call sites.
const (
	// ProblemFrontmatterUnterminated is a file that opens a frontmatter fence
	// and never closes it. The whole file is then treated as body, because
	// guessing where the YAML was meant to end would corrupt a re-save.
	ProblemFrontmatterUnterminated = "frontmatter.unterminated"
	// ProblemFrontmatterInvalid is frontmatter that is not parseable YAML. The
	// bytes are still preserved verbatim; only Fields is empty.
	ProblemFrontmatterInvalid = "frontmatter.invalid"
)

// ErrNoFrontmatter reports a file with no frontmatter block.
var ErrNoFrontmatter = errors.New("md: no frontmatter")

// SplitFrontmatter separates a leading YAML frontmatter block from the body
// without ever re-serialising either part.
//
// The block is located by scanning for a leading `---` line and the next `---`
// line; a UTF-8 BOM before the opening fence and a CRLF line ending on the
// closing fence are both tolerated, because a vault written on Windows must
// survive a round trip unchanged. The returned frontmatter bytes are the raw
// text between the two fence lines, copied verbatim out of src — a YAML
// round-trip library would reorder keys, drop comments and reflow block
// scalars, which is exactly what §5.3 forbids.
//
// fmRange locates the whole fenced block, opening fence line through the
// closing fence's newline, because that is the range a structured edit
// replaces. fm is therefore a sub-range of fmRange, not the whole of it; a
// Doc exposes the two offsets separately as FrontmatterYAMLRange.
//
// A file with no frontmatter returns the whole file as body, an invalid
// fmRange, and a nil error. A file that opens a fence and never closes one
// also returns the whole file as body and a ProblemFrontmatterUnterminated
// problem: the first line could be a thematic break, and guessing would be
// worse than not parsing.
func SplitFrontmatter(src []byte) (body []byte, bodyRange Range, fm []byte, fmRange Range, err error) {
	start := bomLen(src)

	openEnd, openNext, ok := lineBounds(src, start)
	if !ok || !isFenceLine(src, start, openEnd) {
		return src[start:], Range{Start: start, End: len(src)}, nil, Range{}, nil
	}

	for pos := openNext; pos <= len(src); {
		lineEnd, next, more := lineBounds(src, pos)
		if !more {
			break
		}
		if isFenceLine(src, pos, lineEnd) {
			fmRange = Range{Start: start, End: next}
			bodyRange = Range{Start: next, End: len(src)}
			return src[bodyRange.Start:bodyRange.End], bodyRange,
				src[openNext:pos], fmRange, nil
		}
		pos = next
	}
	return src[start:], Range{Start: start, End: len(src)}, nil, Range{},
		Problem{Code: ProblemFrontmatterUnterminated, StartByte: start,
			Message: "frontmatter fence is not closed"}
}

// bomLen returns the length of a leading UTF-8 byte order mark, or 0. The
// mark is neither frontmatter nor body: it belongs to neither range, and it
// is preserved because Doc.Bytes is the file verbatim.
func bomLen(src []byte) int {
	if len(src) >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		return 3
	}
	return 0
}

// lineBounds returns the end of the line starting at pos, excluding its line
// terminator, and the offset of the next line. ok is false at end of file.
func lineBounds(src []byte, pos int) (end, next int, ok bool) {
	if pos >= len(src) {
		return 0, 0, false
	}
	for end = pos; end < len(src) && src[end] != '\n'; end++ {
	}
	if end == len(src) {
		return end, end, true
	}
	return end, end + 1, true
}

// isFenceLine reports whether src[start:end] is a `---` delimiter line. At
// least three dashes are required and trailing whitespace is tolerated, so a
// CRLF file and an editor that trimmed the line both still parse.
func isFenceLine(src []byte, start, end int) bool {
	if end > len(src) {
		return false
	}
	for end > start && (src[end-1] == ' ' || src[end-1] == '\t' || src[end-1] == '\r') {
		end--
	}
	dashes := end - start
	if dashes < 3 {
		return false
	}
	for i := start; i < end; i++ {
		if src[i] != '-' {
			return false
		}
	}
	return true
}

// ParseFields decodes frontmatter into a read-only map. It is a convenience
// wrapper over the same decode Segment performs, exposed for callers that hold
// only the raw block.
//
// The decode is deliberately non-strict about shapes: Obsidian properties may
// be a scalar or a list, may nest, and may carry a `cssclasses` list, none of
// which may fail the parse. Only genuinely invalid YAML is an error.
func ParseFields(fm []byte) (map[string]any, error) {
	if len(trimSpace(fm)) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := yaml.Unmarshal(fm, &out); err != nil {
		return map[string]any{}, fmt.Errorf("md: frontmatter: %w", err)
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return out, nil
}

// FieldString returns a frontmatter value as a string. A list or map yields
// the empty string, because a caller that wanted a list must say so: guessing
// here would silently turn a list property into its first element.
func FieldString(fields map[string]any, key string) string {
	switch v := fields[key].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return ""
	}
}

// FieldStrings returns a frontmatter value as a list of strings, accepting
// both the scalar and the list spellings. Obsidian writes `tags: a` and
// `tags: [a, b]` interchangeably and a vault contains both.
func FieldStrings(fields map[string]any, keys ...string) []string {
	var out []string
	for _, key := range keys {
		switch v := fields[key].(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		case nil:
		default:
			// A number or a bool is still a nameable value; formatting it
			// keeps a typo'd `tags: 2024` from vanishing silently.
			out = append(out, fmt.Sprintf("%v", v))
		}
	}
	return out
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpaceByte(b[start]) {
		start++
	}
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
