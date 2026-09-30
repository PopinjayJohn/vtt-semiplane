package md

import "testing"

// doc builds a document whose body is exactly the concatenated spans, so that
// the invariant tests below are about the span bookkeeping and nothing else.
func doc(spans ...Span) *Doc {
	d := &Doc{
		BodyRange:   Range{Start: 0, End: 100},
		Body:        make([]byte, 100),
		Bytes:       make([]byte, 100),
		Frontmatter: []byte("---\ntitle: x\n---\n"),
	}
	d.Spans = append(d.Spans, spans...)
	return d
}

func TestSpanAccessors(t *testing.T) {
	t.Parallel()
	s := Span{Kind: SpanSecret, SecretID: "7f3a91c40d2e", StartByte: 10, EndByte: 40}
	if !s.Secret() {
		t.Error("a secret span does not report itself as secret")
	}
	if s.Len() != 30 {
		t.Errorf("Len = %d, want 30", s.Len())
	}
	if !s.Contains(10) || !s.Contains(39) {
		t.Error("Contains is wrong at the edges")
	}
	if s.Contains(40) || s.Contains(9) {
		t.Error("the range is half-open and must exclude the end offset")
	}
	if (Span{Kind: SpanPublic}).Secret() {
		t.Error("a public span reports itself as secret")
	}
}

func TestRange(t *testing.T) {
	t.Parallel()
	src := []byte("0123456789")
	r := Range{Start: 2, End: 5}
	if !r.Valid() {
		t.Error("a non-empty range is invalid")
	}
	if got := string(r.Slice(src)); got != "234" {
		t.Errorf("Slice = %q", got)
	}
	if (Range{}).Valid() {
		t.Error("an empty range is valid")
	}
	if (Range{Start: 5, End: 50}).Slice(src) != nil {
		t.Error("an out-of-range slice must return nil, not panic")
	}
}

func TestPublicBodyExcludesSecretsAndCopies(t *testing.T) {
	t.Parallel()

	d := doc(
		Span{Kind: SpanPublic, StartByte: 0, EndByte: 10},
		Span{Kind: SpanSecret, SecretID: "a", StartByte: 10, EndByte: 20},
		Span{Kind: SpanPublic, StartByte: 20, EndByte: 30},
	)
	for i := range d.Bytes {
		d.Bytes[i] = byte('a' + i%26)
	}

	got := string(d.PublicBody())
	if len(got) != 20 {
		t.Fatalf("public body length = %d, want 20", len(got))
	}
	if want := string(d.Bytes[0:10]) + string(d.Bytes[20:30]); got != want {
		t.Errorf("public body = %q, want %q", got, want)
	}

	// The result must be a copy: mutating it cannot corrupt the file bytes.
	pub := d.PublicBody()
	pub[0] = 'Z'
	if d.PublicBody()[0] == 'Z' {
		t.Error("PublicBody returned an alias of the file bytes")
	}
	if len(d.SecretSpans()) != 1 {
		t.Errorf("secret spans = %d, want 1", len(d.SecretSpans()))
	}
	if len(d.PublicSpans()) != 2 {
		t.Errorf("public spans = %d, want 2", len(d.PublicSpans()))
	}
}

func TestPublicBodyOffsetsAreRelativeToTheResult(t *testing.T) {
	t.Parallel()

	d := doc(
		Span{Kind: SpanPublic, StartByte: 5, EndByte: 15},
		Span{Kind: SpanSecret, SecretID: "a", StartByte: 15, EndByte: 25},
		Span{Kind: SpanPublic, StartByte: 25, EndByte: 40},
	)
	d.Bytes = make([]byte, 100)

	text, spans := d.PublicBodyOffsets()
	if len(text) != 25 {
		t.Fatalf("text length = %d, want 25", len(text))
	}
	if spans[0].StartByte != 0 || spans[0].EndByte != 10 {
		t.Errorf("first span = %+v, want [0,10)", spans[0])
	}
	if spans[1].StartByte != 10 || spans[1].EndByte != 25 {
		t.Errorf("second span = %+v, want [10,25)", spans[1])
	}
	// The public span keeps its identity: no secret id leaked into it, and no
	// secret span came back at all.
	for _, s := range spans {
		if s.Secret() {
			t.Errorf("a secret span was returned: %+v", s)
		}
	}
}

func TestSpanAt(t *testing.T) {
	t.Parallel()
	d := doc(
		Span{Kind: SpanPublic, StartByte: 0, EndByte: 10},
		Span{Kind: SpanSecret, SecretID: "7f3a91c40d2e", StartByte: 10, EndByte: 20},
	)
	if s, ok := d.SpanAt(15); !ok || !s.Secret() || s.SecretID != "7f3a91c40d2e" {
		t.Errorf("SpanAt(15) = %+v, %v", s, ok)
	}
	if s, ok := d.SpanAt(5); !ok || s.Secret() {
		t.Errorf("SpanAt(5) = %+v, %v", s, ok)
	}
	if _, ok := d.SpanAt(50); ok {
		t.Error("an offset outside every span should not resolve")
	}
}

func TestOffsetTranslation(t *testing.T) {
	t.Parallel()
	d := &Doc{BodyRange: Range{Start: 20, End: 100}}

	if off, ok := d.SpanOffset(30); !ok || off != 10 {
		t.Errorf("SpanOffset(30) = %d, %v", off, ok)
	}
	// Frontmatter is public but is not part of the body.
	if _, ok := d.SpanOffset(5); ok {
		t.Error("an offset inside frontmatter should not map into the body")
	}
	if got := d.FileOffset(10); got != 30 {
		t.Errorf("FileOffset(10) = %d, want 30", got)
	}
}

func TestProblemErrorCarriesTheIdNotTheContent(t *testing.T) {
	t.Parallel()
	p := Problem{Code: "secret.unterminated", SecretID: "7f3a91c40d2e", Message: "fence never closed"}
	got := p.Error()
	if got == "" {
		t.Fatal("Error is empty")
	}
	if want := "secret.unterminated: 7f3a91c40d2e: fence never closed"; got != want {
		t.Errorf("Error = %q, want %q", got, want)
	}
	if got := (Problem{Code: "x", Message: "y"}).Error(); got != "x: y" {
		t.Errorf("Error without an id = %q", got)
	}
}

func TestSpanKindString(t *testing.T) {
	t.Parallel()
	if (SpanPublic).String() != "public" || (SpanSecret).String() != "secret" {
		t.Error("SpanKind.String is wrong")
	}
}
