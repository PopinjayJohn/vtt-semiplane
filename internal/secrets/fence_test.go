package secrets

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// TestParseReadsEveryFenceInFileOrder is the unit test for the bridge between
// md's byte-level segmentation and everything that wants a fence as a value.
func TestParseReadsEveryFenceInFileOrder(t *testing.T) {
	t.Parallel()
	src := []byte("# Page\n\nBefore.\n\n" +
		"```secret id=aaaaaaaaaaaa visibility=private author=dorn created=2026-09-28T10:04:11Z title=\"The First\"\n" +
		"First body.\n```\n\n" +
		"Middle.\n\n" +
		"~~~secret id=bbbbbbbbbbbb visibility=table author=mara\nSecond body.\n~~~\n\n" +
		"> ```secret id=cccccccccccc visibility=dm author=pia\n> A quoted fence.\n> ```\n\n" +
		"After.\n")
	doc := md.Parse("Page.md", src)
	fences, problems := Parse(doc)

	var ids []string
	for _, f := range fences {
		ids = append(ids, f.ID)
	}
	want := []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"}
	if len(ids) != len(want) {
		t.Fatalf("read %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("read %v, want %v", ids, want)
		}
	}
	for i, f := range fences {
		if f.Ordinal != i {
			t.Errorf("fence %d has ordinal %d", i, f.Ordinal)
		}
		if !f.Valid() {
			t.Errorf("fence %d is not valid: %s", i, f)
		}
	}
	// Field by field, because a mis-split directive shows up as a title that is
	// a fragment of the real one.
	first := fences[0]
	if first.Visibility != VisibilityPrivate || first.Author != "dorn" || first.Title != "The First" {
		t.Errorf("the first fence is %+v", first)
	}
	if want := time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC); !first.CreatedAt.Equal(want) {
		t.Errorf("created is %s, want %s", first.CreatedAt, want)
	}
	if first.Body != "First body.\n" {
		t.Errorf("the first body is %q", first.Body)
	}
	if !bytes.Equal(first.BodyHash, vault.Hash([]byte("First body.\n"))) {
		t.Error("the body hash does not match the body")
	}
	if fences[1].Visibility != VisibilityTable || fences[1].Author != "mara" {
		t.Errorf("the second fence is %+v", fences[1])
	}
	if fences[2].Visibility != VisibilityDM {
		t.Errorf("the quoted fence is %+v", fences[2])
	}
	if !strings.Contains(fences[2].Body, "A quoted fence.") {
		t.Errorf("the quoted fence's body is %q", fences[2].Body)
	}
	// The problems are md's, passed through rather than swallowed.
	for _, p := range problems {
		if p.Code == md.ProblemSecretUnknownKey || p.Code == md.ProblemSecretBadDirective {
			t.Errorf("a clean document produced %s", p.Code)
		}
	}
}

// TestParseOffsetsPointAtTheFence asserts the byte offsets, because they are what
// a caller uses to splice a fence and an off-by-one rewrites the wrong line.
func TestParseOffsetsPointAtTheFence(t *testing.T) {
	t.Parallel()
	head := "# Page\n\nBefore.\n\n"
	fence := "```secret id=abcdef012345 visibility=dm author=dorn\nThe body.\n```\n"
	tail := "\nAfter.\n"
	src := []byte(head + fence + tail)
	fences, _ := Parse(md.Parse("Page.md", src))
	if len(fences) != 1 {
		t.Fatalf("read %d fences", len(fences))
	}
	f := fences[0]
	if got := string(src[f.StartByte:f.EndByte]); got != fence {
		t.Errorf("the span covers %q, want the whole fence", got)
	}
	if got := string(src[f.BodyStartByte:f.BodyEndByte]); got != "The body.\n" {
		t.Errorf("the body covers %q", got)
	}
	if !bytes.Equal(src[f.BodyStartByte:f.BodyEndByte], []byte(f.Body)) {
		t.Error("the offsets and the body disagree")
	}
	if f.Directive != "```secret id=abcdef012345 visibility=dm author=dorn" {
		t.Errorf("the directive is %q", f.Directive)
	}
}

// TestParseOfAnUnterminatedFence asserts the fail-safe: a fence with no closing
// line is still a secret, still redacted, and still carries its body, because the
// bytes are on the page and the app has to show the DM what they wrote.
func TestParseOfAnUnterminatedFence(t *testing.T) {
	t.Parallel()
	src := []byte("# Page\n\n```secret id=abcdef012345 visibility=dm author=dorn\nNever closed.\n")
	fences, problems := Parse(md.Parse("Page.md", src))
	if len(fences) != 1 {
		t.Fatalf("read %d fences", len(fences))
	}
	if !strings.Contains(fences[0].Body, "Never closed.") {
		t.Errorf("the body is %q", fences[0].Body)
	}
	if fences[0].EndByte != len(src) {
		t.Errorf("the span ends at %d, want the end of the file (%d)", fences[0].EndByte, len(src))
	}
	var unterminated bool
	for _, p := range problems {
		if p.Code == md.ProblemSecretUnterminated {
			unterminated = true
		}
	}
	if !unterminated {
		t.Error("an unterminated fence produced no problem")
	}
}

// TestParseTerminates asserts the property this file's byte loops have to have:
// every fixture ends, including the ones with a run of fence characters, a
// carriage return, and no newline at all.
func TestParseTerminates(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no trailing newline":     "```secret id=abcdef012345 visibility=dm author=dorn\nbody",
		"crlf line endings":       "# Page\r\n\r\n```secret id=abcdef012345 visibility=dm author=dorn\r\nbody\r\n```\r\n",
		"a run of backticks":      "```````secret id=abcdef012345 visibility=dm author=dorn\nbody\n```````\n",
		"a run of tildes":         "~~~~~~~~secret id=abcdef012345 visibility=dm author=dorn\nbody\n~~~~~~~~\n",
		"only a fence opener":     "```secret id=abcdef012345 visibility=dm author=dorn\n",
		"a byte order mark":       "\ufeff# Page\n\n```secret id=abcdef012345 visibility=dm author=dorn\nbody\n```\n",
		"an indented fence":       "# Page\n\n    ```secret id=abcdef012345 visibility=dm author=dorn\n    body\n    ```\n",
		"many fences":             strings.Repeat("```secret id=abcdef012345 visibility=dm author=dorn\nb\n```\n", 200),
		"nesting two deep":        "```secret id=abcdef012345 visibility=dm author=dorn\n```secret id=bbbbbbbbbbbb visibility=dm author=dorn\nx\n```\n```\n",
		"a fence with no id":      "```secret visibility=dm author=dorn\nbody\n```\n",
		"a fence with no info":    "```\nbody\n```\n",
		"an empty document":       "",
		"a fence at the very end": "```secret id=abcdef012345 visibility=dm author=dorn\nb\n```",
	}
	for name, body := range cases {
		body := body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fences, _ := Parse(md.Parse("Page.md", []byte(body)))
			for i, f := range fences {
				// md substitutes a placeholder for a fence with no id, so the id
				// is never empty; it may be the placeholder, which is why this
				// asserts the shape of a *present* id rather than validity.
				if f.ID == "" {
					t.Errorf("fence %d has no id at all", i)
				}
				if !f.Visibility.Valid() {
					t.Errorf("fence %d has visibility %q", i, f.Visibility)
				}
				if len(f.BodyHash) != 32 {
					t.Errorf("fence %d has no body hash", i)
				}
				if f.StartByte < 0 || f.EndByte > len(body) || f.StartByte > f.EndByte {
					t.Errorf("fence %d has span %d..%d of %d bytes", i, f.StartByte, f.EndByte, len(body))
				}
			}
		})
	}
}

// TestParseFailsSafeOnADocumentItCannotReadBack asserts the guard between the
// two readers of a fence.
//
// md's segmenter decides what a fence is; this file reads the directive off the
// line md pointed at. The two agree, so the guard is unreachable through Parse's
// normal input — which is exactly why it is worth a test: a document whose span
// points at something that is not a secret fence must produce a problem and a
// fence with the fail-safe visibility, never a fence whose visibility was read
// from the wrong bytes.
func TestParseFailsSafeOnADocumentItCannotReadBack(t *testing.T) {
	t.Parallel()
	src := []byte("secret id=abcdef012345 visibility=table author=dorn\nA body.\n")
	doc := &md.Doc{
		Path:  "Hand.md",
		Bytes: src,
		Spans: []md.Span{{Kind: md.SpanSecret, SecretID: "abcdef012345", StartByte: 0, EndByte: len(src)}},
	}
	fences, problems := Parse(doc)
	if len(fences) != 1 {
		t.Fatalf("read %d fences", len(fences))
	}
	// private, not table: the failure mode of guessing wrong in the other
	// direction is a secret rendered to the table.
	if fences[0].Visibility != VisibilityPrivate {
		t.Errorf("the visibility is %q, want the private fail-safe", fences[0].Visibility)
	}
	var reported int
	for _, p := range problems {
		if p.Code == ProblemDirectiveUnreadable {
			reported++
		}
	}
	if reported != 1 {
		t.Errorf("reported %d unreadable problems, want 1: %+v", reported, problems)
	}
}

// TestParseSurvivesASpanThatPointsNowhere asserts the offset guards, because a
// span is a range into a byte slice and every consumer of one eventually assumes
// the two agree.
func TestParseSurvivesASpanThatPointsNowhere(t *testing.T) {
	t.Parallel()
	for name, span := range map[string]md.Span{
		"before the buffer": {Kind: md.SpanSecret, SecretID: "abcdef012345", StartByte: -4, EndByte: 8},
		"at the end":        {Kind: md.SpanSecret, SecretID: "abcdef012345", StartByte: 16, EndByte: 16},
		"past the end":      {Kind: md.SpanSecret, SecretID: "abcdef012345", StartByte: 8, EndByte: 4096},
		"inverted":          {Kind: md.SpanSecret, SecretID: "abcdef012345", StartByte: 12, EndByte: 4},
	} {
		span := span
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := []byte("secret id=abcdef012345 visibility=dm\nA body.\n")
			doc := &md.Doc{Path: "Hand.md", Bytes: src, Spans: []md.Span{span}}
			fences, _ := Parse(doc)
			for i, f := range fences {
				if f.ID == "" {
					t.Errorf("fence %d has no id", i)
				}
				// Clamped into the buffer, which is the whole point: md's own
				// accessors index the buffer with these offsets unchecked.
				if f.StartByte < 0 || f.StartByte > len(src) {
					t.Errorf("fence %d starts at %d of %d bytes", i, f.StartByte, len(src))
				}
				if f.EndByte < f.StartByte || f.EndByte > len(src) {
					t.Errorf("fence %d ends at %d of %d bytes", i, f.EndByte, len(src))
				}
				if f.BodyStartByte < f.StartByte || f.BodyEndByte > f.EndByte {
					t.Errorf("fence %d has body %d..%d outside its span", i, f.BodyStartByte, f.BodyEndByte)
				}
				if !f.Visibility.Valid() {
					t.Errorf("fence %d has visibility %q", i, f.Visibility)
				}
			}
		})
	}
}

// TestSecretStringCarriesNoBody asserts the string form is safe to put in an
// error, which is the only reason it exists.
func TestSecretStringCarriesNoBody(t *testing.T) {
	t.Parallel()
	s := Secret{
		ID: "abcdef012345", Ordinal: 2, Visibility: VisibilityDM,
		Body: "The vault door is oak and the key is with the mayor.",
	}
	got := s.String()
	if strings.Contains(got, "oak") || strings.Contains(got, "mayor") {
		t.Fatalf("the string form carries the body: %q", got)
	}
	for _, want := range []string{"abcdef012345", "dm", "52 body bytes"} {
		if !strings.Contains(got, want) {
			t.Errorf("the string form %q does not mention %q", got, want)
		}
	}
	if redacted := s.Redacted(); redacted.Body != "" || !strings.Contains(redacted.String(), "abcdef012345") {
		t.Error("a redacted secret lost its identity")
	}
}

// TestValidRejectsWhatCannotBeIndexed asserts the fail-safe predicate: anything
// the index could not use makes the fence invalid, and an invalid fence is
// redacted and absent rather than half-written.
func TestValidRejectsWhatCannotBeIndexed(t *testing.T) {
	t.Parallel()
	good := Secret{ID: "abcdef012345", Visibility: VisibilityTable, BodyHash: vault.Hash([]byte("b"))}
	if !good.Valid() {
		t.Fatal("a complete fence is invalid")
	}
	for name, s := range map[string]Secret{
		"no id":            {Visibility: VisibilityTable, BodyHash: vault.Hash([]byte("b"))},
		"no visibility":    {ID: "abcdef012345", BodyHash: vault.Hash([]byte("b"))},
		"a bad visibility": {ID: "abcdef012345", Visibility: "everyone", BodyHash: vault.Hash([]byte("b"))},
		"no hash":          {ID: "abcdef012345", Visibility: VisibilityTable},
	} {
		if s.Valid() {
			t.Errorf("a fence with %s is valid", name)
		}
	}
}

// TestParseIsDeterministic asserts that parsing the same bytes twice gives the
// same answer, which is what lets the indexer compare a hash and skip.
func TestParseIsDeterministic(t *testing.T) {
	t.Parallel()
	src := []byte(pageWithOneFence)
	first, _ := Parse(md.Parse("Page.md", src))
	second, _ := Parse(md.Parse("Page.md", src))
	if len(first) != len(second) || len(first) != 1 {
		t.Fatalf("read %d and %d fences", len(first), len(second))
	}
	a, b := first[0], second[0]
	if a.ID != b.ID || a.Visibility != b.Visibility || a.Author != b.Author ||
		a.Title != b.Title || a.Body != b.Body || !a.CreatedAt.Equal(b.CreatedAt) ||
		!bytes.Equal(a.BodyHash, b.BodyHash) || a.StartByte != b.StartByte || a.EndByte != b.EndByte {
		t.Error("two parses of the same bytes disagree")
	}
	if a.Ordinal != 0 {
		t.Errorf("the ordinal is %d", a.Ordinal)
	}
}

const pageWithOneFence = "# The Page\n\n" +
	"```secret id=abcdef012345 visibility=dm author=dorn created=2026-09-28T10:04:11Z\n" +
	"The body.\n```\n"
