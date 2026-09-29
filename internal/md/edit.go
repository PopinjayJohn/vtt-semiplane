package md

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Problem codes reported by the structured edits.
const (
	// ProblemEditUnsupportedValue is a structured edit asked to write a value
	// shape this package does not know how to write into a YAML block without
	// reformatting the rest of it.
	ProblemEditUnsupportedValue = "edit.unsupported_value"
	// ProblemEditNoFrontmatter is a structured edit asked to patch a document
	// that has no frontmatter block to patch.
	ProblemEditNoFrontmatter = "edit.no_frontmatter"
)

// Resave returns a document's bytes unchanged.
//
// A save writes what was read. The file is canonical and this package never
// re-serialises it, so the only correct answer to "write this page back
// unchanged" is the bytes themselves — including the BOM, the CRLF line
// endings and the trailing spaces that a YAML round trip would have thrown
// away on the way past.
func Resave(d *Doc) []byte { return d.Bytes }

// PatchFrontmatter returns the document with key/value pairs set in its
// frontmatter, or the document's bytes unchanged when every value is already
// what the document says.
//
// Only string, list-of-string and bool values are writable, because those are
// the only shapes the app edits. Anything else is a problem and leaves the
// document alone: a general YAML writer would have to reformat the whole block
// to be correct, and §5.3 forbids that. The patch is applied to the bytes in
// place — an existing key's value is replaced between its delimiters, a new
// key is appended before the closing fence — so comments, key order, quoting
// style and indentation outside the edited line all survive.
func PatchFrontmatter(d *Doc, patch map[string]any) ([]byte, []Problem) {
	if len(patch) == 0 {
		return d.Bytes, nil
	}
	lines, problems := renderPatch(patch)
	if len(problems) > 0 {
		return d.Bytes, problems
	}
	if !d.FrontmatterRange.Valid() {
		block := []byte("---\n")
		for _, line := range lines {
			block = append(block, line...)
		}
		block = append(block, "---\n"...)
		return splice(d.Bytes, 0, 0, block), nil
	}
	return spliceFrontmatter(d, lines)
}

// AddTags returns the document with tags added, or its bytes unchanged when
// every tag is already present. Tags already written are left where they are
// rather than being moved, so a hand-ordered frontmatter keeps its order.
func AddTags(d *Doc, tags ...string) ([]byte, []Problem) {
	existing := FieldStrings(d.Fields, "tags", "tag")
	seen := map[string]bool{}
	for _, t := range existing {
		seen[NormalizeTag(t)] = true
	}
	var missing []string
	for _, t := range tags {
		if n := NormalizeTag(t); n != "" && !seen[n] {
			seen[n] = true
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return d.Bytes, nil
	}
	key := "tags"
	if len(existing) > 0 && FieldString(d.Fields, "tags") == "" && FieldString(d.Fields, "tag") != "" {
		key = "tag"
	}
	return PatchFrontmatter(d, map[string]any{key: append(existing, missing...)})
}

// AddAliases returns the document with aliases added, or its bytes unchanged
// when every alias is already present.
func AddAliases(d *Doc, aliases ...string) ([]byte, []Problem) {
	existing := FieldStrings(d.Fields, "aliases", "alias")
	seen := map[string]bool{}
	for _, a := range existing {
		seen[strings.ToLower(strings.TrimSpace(a))] = true
	}
	var missing []string
	for _, a := range aliases {
		a = strings.TrimSpace(a)
		if a == "" || seen[strings.ToLower(a)] {
			continue
		}
		seen[strings.ToLower(a)] = true
		missing = append(missing, a)
	}
	if len(missing) == 0 {
		return d.Bytes, nil
	}
	key := "aliases"
	if len(existing) > 0 && FieldString(d.Fields, "aliases") == "" && FieldString(d.Fields, "alias") != "" {
		key = "alias"
	}
	return PatchFrontmatter(d, map[string]any{key: append(existing, missing...)})
}

// Reveal returns the document with every named secret's visibility set to
// VisibilityTable, which is what a reveal means: readable by every
// authenticated user.
//
// No names means no secrets and no change. A call that names nothing must not
// be a wildcard, because a wildcard here would rewrite every fence on the page
// when the caller meant one — and the difference between "reveal this" and
// "reveal everything" is exactly the difference the audit log exists to
// record.
func Reveal(d *Doc, ids ...string) ([]byte, []Problem) {
	return SetVisibility(d, authz.VisibilityTable, ids...)
}

// Revoke returns the document with every named secret's visibility set to
// VisibilityPrivate.
//
// The caller is also responsible for deleting the secret_text and secret_fts
// rows for each id: the file is authoritative, and the index mirrors it, so a
// revoke that only rewrote the fence would leave the body readable through
// search. This package owns no database and cannot do that part.
func Revoke(d *Doc, ids ...string) ([]byte, []Problem) {
	return SetVisibility(d, authz.VisibilityPrivate, ids...)
}

// SetVisibility returns the document with the visibility of every named secret
// rewritten to v, or the document's bytes unchanged when every named fence
// already says v. A no-op returns the input bytes, not a re-encoding of them,
// so a caller can compare the two and skip the write entirely.
//
// Only the visibility= token changes. The fence, its id, its author, its
// created timestamp, its title, the secret's body and every other byte of the
// file are untouched, which is the whole point of §8.3: reveal is a file
// mutation of one token, and the fence has to survive it because the fence is
// what carries the id, the audit trail and the revocability. Removing the
// fence would leave plaintext that can never again be hidden, never audited
// and never revoked.
//
// A fence with no visibility= token has visibility private by definition, so
// naming it is an insertion into its directive line rather than a replacement,
// and nothing else on the line moves.
func SetVisibility(d *Doc, v authz.Visibility, ids ...string) ([]byte, []Problem) {
	if len(ids) == 0 {
		return d.Bytes, nil
	}
	if !v.Valid() {
		return d.Bytes, []Problem{{
			Code:    ProblemSecretBadVisibility,
			Message: "visibility is not one of the three known values",
		}}
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			wanted[id] = true
		}
	}
	if len(wanted) == 0 {
		return d.Bytes, nil
	}

	edits, problems := visibilityEdits(d, wanted, v)
	if len(edits) == 0 {
		return d.Bytes, problems
	}
	// The document is not mutated: the caller writes these bytes to the vault,
	// the watcher re-reads the file, and the index is rebuilt from it. Patching
	// the parsed document in place would leave its spans pointing into bytes
	// that have moved.
	out := d.Bytes
	// Back to front, so that the offsets of the edits not yet applied stay
	// valid.
	for i := len(edits) - 1; i >= 0; i-- {
		out = splice(out, edits[i].Start, edits[i].End, edits[i].With)
	}
	return out, problems
}

// visibilityEdits locates the byte range each named secret's visibility token
// occupies, in the order the spans appear.
func visibilityEdits(d *Doc, wanted map[string]bool, v authz.Visibility) ([]spliceEdit, []Problem) {
	var edits []spliceEdit
	found := map[string]bool{}
	var problems []Problem
	for _, s := range d.SecretSpans() {
		if !wanted[s.SecretID] {
			continue
		}
		found[s.SecretID] = true
		// A secret that already says v contributes no edit, so the output is
		// the input and the caller can skip the write.
		if edit, ok := visibilityEdit(d.Bytes, s, v); ok {
			edits = append(edits, edit)
		}
	}
	for _, id := range sortedKeys(wanted) {
		if !found[id] {
			problems = append(problems, Problem{
				Code:     ProblemSecretUnknownID,
				SecretID: id,
				Message:  "no secret with this id is in the document",
			})
		}
	}
	return edits, problems
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// spliceEdit is a byte range to replace. An insertion has Start == End.
type spliceEdit struct {
	Start, End int
	With       []byte
}

// visibilityEdit computes the single byte range to replace to give one secret
// the visibility v. It reports false when the fence already says v, in which
// case the caller must not write anything.
func visibilityEdit(src []byte, s Span, v authz.Visibility) (spliceEdit, bool) {
	lineEnd, _, ok := lineBounds(src, s.StartByte)
	if !ok || lineEnd > s.EndByte {
		return spliceEdit{}, false
	}
	line := src[s.StartByte:lineEnd]
	f, isFence := fenceAt(line)
	if !isFence {
		return spliceEdit{}, false
	}
	// The info string is everything after the fence run, minus the trailing
	// whitespace, which belongs to the line rather than to the directive.
	infoStart := f.Offset + f.Run
	info := trimRightSpace(line[infoStart:])
	base := s.StartByte + infoStart
	for _, field := range scanDirectiveFields(info, base) {
		if !strings.EqualFold(string(field.key), KeyVisibility) {
			continue
		}
		if string(unquoteBytes(field.value)) == string(v) {
			return spliceEdit{}, false
		}
		// Only the value moves, so a quoted value keeps its quotes and a bare
		// one stays bare: the author's style is not ours to normalise.
		return spliceEdit{
			Start: field.valueStart,
			End:   field.valueEnd,
			With:  []byte(v),
		}, true
	}
	// No visibility= token. An absent token means private, so naming the
	// secret private is a no-op in meaning as well as in bytes: inserting
	// `visibility=private` would rewrite every fence that never mentioned a
	// visibility, which is most of them, for a change nothing can observe.
	if v == authz.VisibilityPrivate {
		return spliceEdit{}, false
	}
	// Any other visibility is an insertion at the end of the directive,
	// before any trailing whitespace, so nothing else on the line moves.
	return spliceEdit{
		Start: base + len(info),
		End:   base + len(info),
		With:  []byte(" " + KeyVisibility + "=" + string(v)),
	}, true
}

// SecretBody returns the bytes of a secret span's body: everything between the
// opening fence's line terminator and the closing fence line, or the end of
// the span when the fence is unterminated.
func SecretBody(src []byte, s Span) []byte {
	start, end := secretBody(src, s)
	if start < 0 || end > len(src) || start > end {
		return nil
	}
	return src[start:end]
}

func secretBody(src []byte, s Span) (start, end int) {
	// A Span is a byte range into src, and not every caller got it from Parse: a
	// test, a re-sliced document or a corrupted index row can all produce one
	// that points outside the buffer. Clamp before indexing rather than after,
	// because the caller-visible bounds check in SecretBody runs only once this
	// has returned. A panic in the secret path is a denial of service, not a
	// wrong answer.
	if s.StartByte < 0 {
		s.StartByte = 0
	}
	if s.StartByte > len(src) {
		return len(src), len(src)
	}
	if s.EndByte > len(src) {
		s.EndByte = len(src)
	}
	if s.EndByte < s.StartByte {
		s.EndByte = s.StartByte
	}
	_, next, ok := lineBounds(src, s.StartByte)
	if !ok || next > s.EndByte {
		return s.EndByte, s.EndByte
	}
	start = next
	end = s.EndByte
	// The closing fence is the span's last line, so the body is everything
	// before that line starts. Its terminator is stepped over first: scanning
	// back from the span's end stops on the newline immediately, and a body
	// that then includes the closing fence is a body nobody asked for.
	lineEnd := end
	if lineEnd > start && src[lineEnd-1] == '\n' {
		lineEnd--
	}
	if lineEnd > start && src[lineEnd-1] == '\r' {
		lineEnd--
	}
	lineStart := lineEnd
	for lineStart > start && src[lineStart-1] != '\n' {
		lineStart--
	}
	if lineStart > start || closesFence(src, s, lineStart) {
		// lineStart == start means the span's last line begins where the body
		// would: the block has no body at all and that line is the closing
		// fence, so the body is the empty range. Treating it as a body would
		// hand the closing fence to a caller as the secret's text — a body of
		// "```" whose hash is a hash of three backticks, and a redaction that
		// replaces it destroys the fence it was supposed to leave alone.
		end = lineStart
	}
	return start, end
}

// closesFence reports whether the line at off closes the secret span s. It is
// the same test findSecretEnd applies, factored out so that the body of a fence
// and the extent of a fence are one rule rather than two.
func closesFence(src []byte, s Span, off int) bool {
	if off < 0 || off >= len(src) {
		return false
	}
	lineEnd, _, ok := lineBounds(src, off)
	if !ok {
		return false
	}
	g, isFence := fenceAt(src[off:lineEnd])
	if !isFence {
		return false
	}
	openEnd, _, ok := lineBounds(src, s.StartByte)
	if !ok {
		return false
	}
	f, isFence := fenceAt(src[s.StartByte:openEnd])
	if !isFence {
		return false
	}
	return g.QuoteDepth == f.QuoteDepth && g.Char == f.Char &&
		g.Run >= f.Run && g.Info == "" && g.Indent <= f.Indent+3
}

// renderPatch turns a patch into YAML lines, sorted by key so that two runs of
// the same patch produce the same bytes.
func renderPatch(patch map[string]any) ([][]byte, []Problem) {
	keys := make([]string, 0, len(patch))
	for k := range patch {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var out [][]byte
	var problems []Problem
	for _, k := range keys {
		line, ok := renderValue(k, patch[k])
		if !ok {
			problems = append(problems, Problem{
				Code:    ProblemEditUnsupportedValue,
				Message: "frontmatter value shape cannot be written without reformatting the block",
			})
			continue
		}
		out = append(out, line)
	}
	return out, problems
}

func renderValue(key string, v any) ([]byte, bool) {
	switch value := v.(type) {
	case string:
		if strings.ContainsAny(value, "\n") {
			return nil, false
		}
		return []byte(key + ": " + yamlScalar(value) + "\n"), true
	case bool:
		return []byte(key + ": " + strconv.FormatBool(value) + "\n"), true
	case []string:
		if len(value) == 0 {
			return []byte(key + ": []\n"), true
		}
		out := []byte(key + ":\n")
		for _, item := range value {
			if strings.ContainsAny(item, "\n") {
				return nil, false
			}
			out = append(out, []byte("  - "+yamlScalar(item)+"\n")...)
		}
		return out, true
	default:
		return nil, false
	}
}

// yamlScalar quotes a value only when it would otherwise change meaning: an
// empty string, a leading indicator, a value that looks like a number or a
// boolean, or anything with YAML-significant trailing space. Everything else
// is written bare, which is how a hand-written frontmatter usually looks.
func yamlScalar(s string) string {
	if s == "" || strings.TrimSpace(s) != s {
		return strconv.Quote(s)
	}
	switch s {
	case "true", "false", "null", "yes", "no", "on", "off", "~":
		return strconv.Quote(s)
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return strconv.Quote(s)
	}
	if strings.ContainsAny(s[:1], "-?:,[]{}#&*!|>'\"%@`") {
		return strconv.Quote(s)
	}
	if strings.Contains(s, ": ") || strings.Contains(s, " #") {
		return strconv.Quote(s)
	}
	return s
}

func splice(src []byte, from, to int, with []byte) []byte {
	if from < 0 || to > len(src) || from > to {
		return src
	}
	out := make([]byte, 0, len(src)-(to-from)+len(with))
	out = append(out, src[:from]...)
	out = append(out, with...)
	return append(out, src[to:]...)
}

// spliceFrontmatter applies a rendered patch to a document's frontmatter block,
// replacing the value of a key that is already there and appending the rest
// before the closing fence.
func spliceFrontmatter(d *Doc, lines [][]byte) ([]byte, []Problem) {
	yaml := d.FrontmatterYAMLRange.Slice(d.Bytes)
	updated := patchYAML(yaml, lines)
	if bytes.Equal(updated, yaml) {
		return d.Bytes, nil
	}
	// The block is rewritten inside its own delimiters, so the closing fence
	// and the body that follows it are untouched.
	return splice(d.Bytes, d.FrontmatterYAMLRange.Start, d.FrontmatterYAMLRange.End, updated), nil
}

// patchYAML applies a rendered patch to a YAML block by replacing an existing
// key's value or appending the key before the end of the block.
func patchYAML(yaml []byte, lines [][]byte) []byte {
	out := append([]byte(nil), yaml...)
	ensureTrailingNewline(&out)
	keep := make([][]byte, 0, len(lines))
	for _, line := range lines {
		raw, _, _ := bytes.Cut(line, []byte(":"))
		key := string(bytes.TrimRight(raw, " \t"))
		at, end, found := findYAMLKey(out, key)
		if !found {
			keep = append(keep, line)
			continue
		}
		out = splice(out, at, end, line)
	}
	for _, line := range keep {
		out = append(out, line...)
	}
	return out
}

func ensureTrailingNewline(b *[]byte) {
	if len(*b) > 0 && (*b)[len(*b)-1] != '\n' {
		*b = append(*b, '\n')
	}
}

// findYAMLKey locates a top-level key's line in a YAML block and returns the
// range its line occupies, so the whole line can be replaced. Only a key at
// column zero counts: a nested key of the same name is not the value.
func findYAMLKey(yaml []byte, key string) (start, end int, ok bool) {
	pos := 0
	for pos < len(yaml) {
		lineEnd := pos
		for lineEnd < len(yaml) && yaml[lineEnd] != '\n' {
			lineEnd++
		}
		line := yaml[pos:lineEnd]
		trimmed := bytes.TrimLeft(line, " \t")
		if !bytes.HasPrefix(trimmed, []byte(key)) {
			pos = lineEnd + 1
			continue
		}
		rest := trimmed[len(key):]
		if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' || rest[0] == ':' {
			// Consume the following more-indented lines, which are this
			// key's block sequence or mapping.
			stop := lineEnd + 1
			for stop < len(yaml) {
				next := stop
				for next < len(yaml) && yaml[next] != '\n' {
					next++
				}
				if next == stop || isYAMLLine(yaml[stop:next]) {
					stop = next + 1
					continue
				}
				break
			}
			if stop > len(yaml) {
				stop = len(yaml)
			}
			return pos, stop, true
		}
		pos = lineEnd + 1
	}
	return 0, 0, false
}

func isYAMLLine(line []byte) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t' || line[0] == '-')
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
