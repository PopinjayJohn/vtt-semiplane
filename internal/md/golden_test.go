package md

import (
	"bytes"
	"strings"
	"testing"
)

// The golden round trip is the whole of §5.3 in one test: for every fixture,
// for every structured operation, a no-op must produce the input's bytes back.
// Anything that reformats, reflows or reorders a byte fails here, and the
// failure names the fixture and the operation.

type roundTripOp struct {
	name string
	// run returns the document's bytes after the operation. A nil error with
	// the input's bytes means the operation was a no-op for this fixture.
	run func(t *testing.T, d *Doc) []byte
}

func roundTripOps() []roundTripOp {
	return []roundTripOp{
		{
			name: "full re-save",
			run:  func(_ *testing.T, d *Doc) []byte { return Resave(d) },
		},
		{
			// An empty patch is the cheapest way to ask "what would you write
			// if you wrote the frontmatter again?", and the answer must be
			// what you read.
			name: "frontmatter patch",
			run: func(t *testing.T, d *Doc) []byte {
				out, problems := PatchFrontmatter(d, nil)
				assertNoProblems(t, problems)
				return out
			},
		},
		{
			// Re-adding the tags the document already carries is the shape of
			// the real call: the UI sends the whole tag list every time.
			name: "tag add",
			run: func(t *testing.T, d *Doc) []byte {
				out, problems := AddTags(d, FieldStrings(d.Fields, "tags", "tag")...)
				assertNoProblems(t, problems)
				return out
			},
		},
		{
			name: "alias add",
			run: func(t *testing.T, d *Doc) []byte {
				out, problems := AddAliases(d, FieldStrings(d.Fields, "aliases", "alias")...)
				assertNoProblems(t, problems)
				return out
			},
		},
		{
			// Revealing nothing is a no-op on every fixture, including the ones
			// with secrets in them. A call that names no secret must not be a
			// wildcard: it must not touch a single fence, or the golden sweep
			// would be asserting that the wrong thing is byte-identical.
			name: "secret reveal",
			run: func(t *testing.T, d *Doc) []byte {
				out, problems := Reveal(d)
				assertNoProblems(t, problems)
				return out
			},
		},
		{
			// Revoking nothing is the same no-op, and has to be one for the
			// same reason: the caller that forgot to collect the ids must not
			// silently lock every secret on the page.
			name: "secret revoke",
			run: func(t *testing.T, d *Doc) []byte {
				out, problems := Revoke(d)
				assertNoProblems(t, problems)
				return out
			},
		},
		{
			// Naming a secret that is not there changes nothing and says so,
			// rather than guessing which fence was meant.
			name: "secret reveal of an absent id",
			run: func(t *testing.T, d *Doc) []byte {
				out, _ := Reveal(d, "000000000000")
				return out
			},
		},
	}
}

func assertNoProblems(t *testing.T, problems []Problem) {
	t.Helper()
	for _, p := range problems {
		t.Errorf("unexpected problem: %v", p)
	}
}

func TestRoundTripGolden(t *testing.T) {
	t.Parallel()
	corpus := loadCorpus(t)
	ops := roundTripOps()

	for name, src := range corpus {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, op := range ops {
				d := Parse("golden/"+name, src)
				got := op.run(t, d)
				if !bytes.Equal(got, src) {
					t.Errorf("%s: %d bytes in, %d bytes out; first difference at %s",
						op.name, len(src), len(got), firstDifference(src, got))
				}
			}
		})
	}
}

// TestRoundTripGoldenIsNotVacuous is the guard against a golden test that
// asserts nothing: it re-runs one fixture through an operation that must
// change it and asserts the bytes really do differ. If a future refactor makes
// every operation a no-op, this fails and so does the meaning of the corpus.
func TestRoundTripGoldenIsNotVacuous(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "frontmatter-simple.md")
	d := Parse("frontmatter-simple.md", src)

	if !bytes.Equal(Resave(d), src) {
		t.Fatal("Resave is not returning the document's bytes")
	}
	patched, problems := PatchFrontmatter(d, map[string]any{"status": "active"})
	assertNoProblems(t, problems)
	if bytes.Equal(patched, src) {
		t.Error("a frontmatter patch that adds a key changed nothing")
	}
	if !bytes.Contains(patched, []byte("status: active")) {
		t.Errorf("the patch is not in the output: %q", patched)
	}

	withSecret := loadFixture(t, "secret-basic.md")
	sd := Parse("secret-basic.md", withSecret)
	revealed, problems := Reveal(sd, "a1b2c3d4e5f6")
	assertNoProblems(t, problems)
	if bytes.Equal(revealed, withSecret) {
		t.Error("revealing a secret changed nothing")
	}
	// The fence survives. It is what carries the id, the author and the audit
	// trail, and a secret that is once revealed has to be revocable.
	if !bytes.Contains(revealed, []byte("```secret id=a1b2c3d4e5f6 visibility=table")) {
		t.Errorf("reveal did not rewrite the visibility token: %q", revealed)
	}
	if !bytes.Contains(revealed, []byte("under the third stone")) {
		t.Errorf("the body did not survive the reveal: %q", revealed)
	}
	if !bytes.HasPrefix(revealed, []byte("# Secrets\n\nPublic before.\n\n")) {
		t.Errorf("reveal disturbed the bytes before the fence: %q", revealed)
	}
}

// TestRenderIsDeterministic renders each fixture twice and requires the same
// bytes both times. A renderer that carried state between calls would break
// this before it broke anything a user would notice.
func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		if len(src) > renderSizeLimit {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first, err := r.Render(src)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			second, err := r.Render(src)
			if err != nil {
				t.Fatalf("re-render: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("two renders of the same input differ: %d then %d bytes",
					len(first), len(second))
			}
		})
	}
}

// TestRenderedPublicBodyExcludesSecrets is the security assertion of the whole
// package: a document's secrets never reach the renderer, so no fragment of a
// secret body and no secret id may appear in the HTML a reader receives.
func TestRenderedPublicBodyExcludesSecrets(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		d := Parse(name, src)
		secrets := d.SecretSpans()
		if len(secrets) == 0 {
			continue
		}
		if len(src) > renderSizeLimit {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := r.RenderDoc(d)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for _, s := range secrets {
				if s.SecretID != "" && bytes.Contains(out, []byte(s.SecretID)) {
					t.Errorf("secret id %s reached the output", s.SecretID)
				}
				for _, line := range secretBodyLines(d, s) {
					if bytes.Contains(out, line) {
						t.Errorf("a line of secret %s reached the output: %q", s.SecretID, line)
					}
				}
			}
		})
	}
}

// secretBodyLines returns the non-trivial lines of a secret's body. A one-word
// line is skipped: the word "Body" or "a" appears in plenty of public prose,
// and a test that failed on it would be a test nobody would keep.
func secretBodyLines(d *Doc, s Span) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(SecretBody(d.Bytes, s), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) < 8 {
			continue
		}
		out = append(out, line)
	}
	return out
}

// TestExtractIsStable re-runs the extractor over its own output's document and
// requires the same facts, which catches an extractor whose result depends on
// something other than the file.
func TestExtractIsStable(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		if len(src) > renderSizeLimit {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first, _ := Extract(Parse("x/"+name, src), r)
			second, _ := Extract(Parse("x/"+name, src), r)
			if !sameExtracted(first, second) {
				t.Error("two extractions of the same document disagree")
			}
		})
	}
}

func sameExtracted(a, b Extracted) bool {
	if a.Title != b.Title || a.PageType != b.PageType {
		return false
	}
	if len(a.Aliases) != len(b.Aliases) || len(a.Tags) != len(b.Tags) ||
		len(a.Links) != len(b.Links) || len(a.Headings) != len(b.Headings) ||
		len(a.Attachments) != len(b.Attachments) ||
		len(a.CodeLanguages) != len(b.CodeLanguages) {
		return false
	}
	for i := range a.Aliases {
		if a.Aliases[i] != b.Aliases[i] {
			return false
		}
	}
	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	for i := range a.Links {
		if a.Links[i] != b.Links[i] {
			return false
		}
	}
	for i := range a.Headings {
		if a.Headings[i] != b.Headings[i] {
			return false
		}
	}
	for i := range a.Attachments {
		if a.Attachments[i] != b.Attachments[i] {
			return false
		}
	}
	for i := range a.CodeLanguages {
		if a.CodeLanguages[i] != b.CodeLanguages[i] {
			return false
		}
	}
	return true
}

func firstDifference(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return offset(i) + " (want " + quoteByte(a[i]) + ", got " + quoteByte(b[i]) + ")"
		}
	}
	return offset(n) + " (length only)"
}

func offset(i int) string { return "offset " + itoa(i) }

func quoteByte(b byte) string {
	if b == '\n' {
		return `\n`
	}
	if b == '\r' {
		return `\r`
	}
	if b == 0 {
		return `\0`
	}
	if b < 0x20 {
		return "\\x" + strings.ToLower(hex(b>>4)) + strings.ToLower(hex(b&0xf))
	}
	return string(rune(b))
}

func hex(v byte) string { return string("0123456789abcdef"[v&0xf]) }
