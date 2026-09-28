package md

// SpanKind classifies a byte range of a source file.
type SpanKind int

const (
	// SpanPublic is content every reader of the page may see.
	SpanPublic SpanKind = iota
	// SpanSecret is the interior of a ```secret fence, including the fence
	// lines themselves. SecretID is always non-empty for a SpanSecret.
	SpanSecret
)

func (k SpanKind) String() string {
	if k == SpanSecret {
		return "secret"
	}
	return "public"
}

// Span is a half-open byte range [StartByte, EndByte) of the original file
// together with its classification. Offsets are absolute into Doc.Bytes, never
// relative to the span list, so a span can be re-located in a file that has
// been re-read.
type Span struct {
	Kind      SpanKind
	SecretID  string // "" when Kind == SpanPublic
	StartByte int
	EndByte   int
}

// Secret reports whether the span is secret.
func (s Span) Secret() bool { return s.Kind == SpanSecret }

// Len is the span's length in bytes.
func (s Span) Len() int { return s.EndByte - s.StartByte }

// Contains reports whether off is inside the span.
func (s Span) Contains(off int) bool { return off >= s.StartByte && off < s.EndByte }

// Range is a half-open byte range, used for the frontmatter block.
type Range struct {
	Start int
	End   int
}

// Valid reports whether the range is non-empty.
func (r Range) Valid() bool { return r.End > r.Start }

// Slice returns the bytes of the range from src.
func (r Range) Slice(src []byte) []byte {
	if !r.Valid() || r.End > len(src) {
		return nil
	}
	return src[r.Start:r.End]
}

// Doc is a parsed vault file. Bytes is the verbatim file content; nothing here
// is ever re-serialised back to disk, because the app must not normalise,
// reflow or reformat user Markdown (§5.3).
type Doc struct {
	// Path is the vault-relative path with forward slashes.
	Path string
	// Bytes is the whole file verbatim.
	Bytes []byte

	// Frontmatter is the raw YAML between the leading --- fences, verbatim.
	Frontmatter []byte
	// FrontmatterRange locates the fenced block inside Bytes: from the first
	// byte of the opening --- line through the closing line's newline. It is
	// the range a structured edit replaces, and it is deliberately wider than
	// Frontmatter, because a re-splice has to be able to rewrite the fences
	// themselves without disturbing the body that follows.
	FrontmatterRange Range
	// FrontmatterYAMLRange locates the YAML text inside the block: from just
	// after the opening fence's line terminator to the first byte of the
	// closing fence line. It is invalid when there is no frontmatter.
	FrontmatterYAMLRange Range
	// BOM is the file's leading UTF-8 byte order mark, empty when it has
	// none. The mark belongs to neither FrontmatterRange nor BodyRange, and it
	// survives only because Bytes is the file verbatim.
	BOM []byte
	// Body is everything after the frontmatter block.
	Body []byte
	// BodyRange locates Body inside Bytes.
	BodyRange Range

	// Spans covers Body exactly once, in ascending, non-overlapping order.
	// Every byte of a document belongs to exactly one span, so the union of
	// the spans is the body and they never overlap.
	Spans []Span

	// Fields holds the parsed frontmatter. It is read-only to everything
	// downstream: a structured edit patches the frontmatter byte range, it
	// never re-emits these values.
	Fields map[string]any

	// Problems records recoverable parse problems (an unterminated secret
	// fence, an unknown directive key, invalid frontmatter). A document with
	// problems is still indexed and still rendered; problems are surfaced, not
	// swallowed.
	Problems []Problem
}

// Problem is a recoverable parse or validation problem in a document.
type Problem struct {
	// Code is a stable machine-readable identifier, e.g. "secret.unterminated".
	Code string
	// StartByte locates the problem in Doc.Bytes, when it has a location.
	StartByte int
	// SecretID is set when the problem concerns a specific secret.
	SecretID string
	// Message is a human-readable, lowercase, no-punctuation description. It
	// must never contain document content.
	Message string
}

func (p Problem) Error() string {
	if p.SecretID != "" {
		return p.Code + ": " + p.SecretID + ": " + p.Message
	}
	return p.Code + ": " + p.Message
}

// PublicSpans returns the spans that every reader of the page may see, in
// order. This is the only input the FTS writer and the renderer consume.
func (d *Doc) PublicSpans() []Span {
	out := make([]Span, 0, len(d.Spans))
	for _, s := range d.Spans {
		if !s.Secret() {
			out = append(out, s)
		}
	}
	return out
}

// SecretSpans returns the secret spans, in order.
func (d *Doc) SecretSpans() []Span {
	out := make([]Span, 0, 2)
	for _, s := range d.Spans {
		if s.Secret() {
			out = append(out, s)
		}
	}
	return out
}

// SpanAt returns the span containing off, or false when off is outside the
// body (for example inside frontmatter, which is always public).
func (d *Doc) SpanAt(off int) (Span, bool) {
	for _, s := range d.Spans {
		if s.Contains(off) {
			return s, true
		}
	}
	return Span{}, false
}

// PublicBody concatenates the public spans. It is the text that may enter
// page_text/page_fts, and the text the renderer parses.
//
// The result is a copy: the vault file's bytes are never aliased into a string
// that might be retained past the request that produced it.
func (d *Doc) PublicBody() []byte {
	spans := d.PublicSpans()
	out := make([]byte, 0, len(d.Body))
	for _, s := range spans {
		out = append(out, d.Bytes[s.StartByte:s.EndByte]...)
	}
	return out
}

// PublicBodyOffsets is PublicBody with the absolute offsets translated into
// offsets within the returned slice, so a caller can record where a fact came
// from and map it back to the file.
func (d *Doc) PublicBodyOffsets() (text []byte, out []Span) {
	for _, s := range d.Spans {
		if s.Secret() {
			continue
		}
		start := len(text)
		text = append(text, d.Bytes[s.StartByte:s.EndByte]...)
		s.StartByte, s.EndByte = start, len(text)
		out = append(out, s)
	}
	return text, out
}

// SpanOffset translates an absolute file offset into an offset within Body.
// Offsets that fall inside frontmatter are reported with ok=false, because
// frontmatter is public but is not part of the body.
func (d *Doc) SpanOffset(abs int) (int, bool) {
	if abs < d.BodyRange.Start || abs >= d.BodyRange.End {
		return 0, false
	}
	return abs - d.BodyRange.Start, true
}

// FileOffset translates a body offset back to an absolute file offset.
func (d *Doc) FileOffset(bodyOff int) int { return d.BodyRange.Start + bodyOff }
