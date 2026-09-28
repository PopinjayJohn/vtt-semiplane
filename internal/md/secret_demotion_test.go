package md

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// A directive value containing a space used to be split on whitespace, so
// title="The Vault Door" parsed as a key named `Door"`. The fence then looked
// like it carried an unknown key, and the documented rule for an unknown key is
// public passthrough — which rendered the secret body in plaintext. A bug in a
// title took a DM secret off the table.
//
// These tests are written against the *property* rather than the parser's
// internals, so a future refactor that reintroduces it fails here.

const demotedBody = "The vault door is warded and deals 3d6 necrotic damage."

func TestQuotedDirectiveValueDoesNotDemoteASecretToPublic(t *testing.T) {
	t.Parallel()

	r := New(Options{})
	cases := []struct {
		name      string
		directive string
	}{
		{"quoted title with a space", "id=a1b2c3d4e5f6 visibility=dm author=johan created=2026-09-28T10:04:11Z title=\"The Vault Door\""},
		{"single-quoted title with a space", "id=a1b2c3d4e5f6 visibility=table author=johan title='The Warded Door'"},
		{"quoted author", "id=a1b2c3d4e5f6 visibility=private author=\"johan smith\" title=door"},
		{"quoted id", "id=\"a1b2c3d4e5f6\" visibility=dm author=johan"},
		{"keys in a different order", "title=\"The Vault Door\" author=johan visibility=dm id=a1b2c3d4e5f6"},
		{"quoted title containing an equals sign", "id=a1b2c3d4e5f6 visibility=dm author=johan title=\"a = b\""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := []byte("Public line.\n\n```secret " + tc.directive + "\n" + demotedBody + "\n```\n")

			d := Parse("ash.md", src)

			// Classified as a secret, with the right id, and not reported as
			// carrying an unknown key.
			secrets := d.SecretSpans()
			if len(secrets) != 1 {
				t.Fatalf("got %d secret spans, want 1; problems=%v", len(secrets), d.Problems)
			}
			if secrets[0].SecretID != "a1b2c3d4e5f6" {
				t.Errorf("secret id = %q", secrets[0].SecretID)
			}
			for _, p := range d.Problems {
				if p.Code == ProblemSecretUnknownKey {
					t.Errorf("a quoted value was read as an unknown key: %v", p)
				}
				if p.Code == ProblemSecretBadDirective {
					t.Errorf("a quoted value broke directive parsing: %v", p)
				}
			}

			// The decisive assertion: the body must not be in what a reader
			// receives, either as the public body or as rendered HTML.
			if bytes.Contains(d.PublicBody(), []byte(demotedBody)) {
				t.Error("the secret body is inside the public body")
			}
			out, err := r.RenderDoc(d)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if bytes.Contains(out, []byte(demotedBody)) {
				t.Errorf("the secret body reached the rendered HTML: %s", out)
			}
			if bytes.Contains(out, []byte("3d6")) || bytes.Contains(out, []byte("necrotic")) {
				t.Errorf("a fragment of the secret body reached the HTML: %s", out)
			}
			if !bytes.Contains(out, []byte("Public line.")) {
				t.Errorf("the public line was lost: %s", out)
			}
		})
	}
}

// TestRevealTouchesNothingButTheVisibilityToken is the §8.3 guarantee, asserted
// structurally: the output must equal the input with exactly one contiguous
// range replaced, and the only range that may change is the value of
// visibility=.
func TestRevealTouchesNothingButTheVisibilityToken(t *testing.T) {
	t.Parallel()

	src := []byte("Before.\n\n```secret id=a1b2c3d4e5f6 visibility=dm author=johan created=2026-09-28T10:04:11Z title=\"The Vault Door\"\n" +
		demotedBody + "\n```\n\nAfter.\n")
	d := Parse("ash.md", src)

	out, problems := Reveal(d, "a1b2c3d4e5f6")
	if len(problems) != 0 {
		t.Fatalf("reveal reported problems: %v", problems)
	}

	// The only difference is `dm` becoming `table`.
	want := bytes.Replace(src, []byte("visibility=dm"), []byte("visibility=table"), 1)
	if !bytes.Equal(out, want) {
		t.Errorf("reveal changed more than the visibility token:\n got %q\nwant %q", out, want)
	}

	// Structurally: everything before the change and everything after it is
	// byte-identical, so the edit is a single contiguous splice. Comparing byte
	// by byte would not show this: `dm` and `table` differ in length, so every
	// later offset shifts even though no other byte changed.
	prefix := commonPrefixLen(src, out)
	suffix := commonSuffixLen(src[prefix:], out[prefix:])
	tail := len(src) - suffix
	if !bytes.Equal(src[:prefix], out[:prefix]) {
		t.Errorf("bytes before the token changed")
	}
	if !bytes.Equal(src[tail:], out[len(out)-suffix:]) {
		t.Errorf("bytes after the token changed: %q", src[tail:])
	}
	if strings.Contains(string(src[prefix:tail]), "\n") {
		t.Errorf("the changed region spans a line break: %q", src[prefix:tail])
	}
	if !strings.Contains(string(src[:prefix]), "```secret") {
		t.Errorf("the change is not on the fence's opening line: %q", src[:prefix])
	}
	// The body, the id, the author, the created timestamp and the title all
	// survive verbatim.
	for _, want := range []string{
		"id=a1b2c3d4e5f6", "author=johan", "created=2026-09-28T10:04:11Z",
		`title="The Vault Door"`, demotedBody, "```", "Before.", "After.",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("reveal lost %q", want)
		}
	}
}

func TestRevokeIsRevealToPrivate(t *testing.T) {
	t.Parallel()

	src := []byte("```secret id=a1b2c3d4e5f6 visibility=table author=johan\nbody\n```\n")
	d := Parse("ash.md", src)

	out, problems := Revoke(d, "a1b2c3d4e5f6")
	if len(problems) != 0 {
		t.Fatalf("revoke reported problems: %v", problems)
	}
	want := bytes.Replace(src, []byte("visibility=table"), []byte("visibility=private"), 1)
	if !bytes.Equal(out, want) {
		t.Errorf("revoke: got %q, want %q", out, want)
	}

	// Revoking a revealed secret and revealing it again is a byte-for-byte
	// round trip. This is the property that lets a DM toggle a secret in the UI
	// without ever dirtying the file more than the toggle itself.
	again, _ := Reveal(Parse("ash.md", out), "a1b2c3d4e5f6")
	if !bytes.Equal(again, src) {
		t.Errorf("revoke then reveal is not byte-identical:\n got %q\nwant %q", again, src)
	}
}

// TestRevealWithNoIdsIsANoOp is the case that a "no filter means everything"
// reading gets wrong, and it is the one the golden corpus runs on every
// fixture.
func TestRevealWithNoIdsIsANoOp(t *testing.T) {
	t.Parallel()

	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		d := Parse(name, src)
		out, _ := Reveal(d)
		if !bytes.Equal(out, src) {
			t.Fatalf("%s: Reveal with no ids changed the file", name)
		}
		out, _ = Revoke(d)
		if !bytes.Equal(out, src) {
			t.Fatalf("%s: Revoke with no ids changed the file", name)
		}
	}
}

func TestRevealUnknownIDChangesNothing(t *testing.T) {
	t.Parallel()

	src := []byte("```secret id=a1b2c3d4e5f6 visibility=dm author=johan\nbody\n```\n")
	d := Parse("ash.md", src)

	out, problems := Reveal(d, "deadbeefcafe")
	if !bytes.Equal(out, src) {
		t.Errorf("an unknown id changed the file: %q", out)
	}
	if len(problems) == 0 {
		t.Error("an unknown id must be reported, not silently ignored")
	}
}

func TestRevealAlreadyAtTargetIsUnchanged(t *testing.T) {
	t.Parallel()

	src := []byte("```secret id=a1b2c3d4e5f6 visibility=table author=johan\nbody\n```\n")
	d := Parse("ash.md", src)

	out, _ := SetVisibility(d, authz.VisibilityTable, "a1b2c3d4e5f6")
	if !bytes.Equal(out, src) {
		t.Errorf("revealing an already-revealed secret rewrote the file: %q", out)
	}
	// private is the default, so a fence with no visibility token needs no
	// write to be private — adding one would touch every fence in a vault for
	// no observable difference.
	bare := []byte("```secret id=a1b2c3d4e5f6 author=johan\nbody\n```\n")
	out, _ = SetVisibility(Parse("ash.md", bare), authz.VisibilityPrivate, "a1b2c3d4e5f6")
	if !bytes.Equal(out, bare) {
		t.Errorf("a bare fence was rewritten to carry the default visibility: %q", out)
	}
	// But dm and table are not the default, so they must be written.
	out, _ = SetVisibility(Parse("ash.md", bare), authz.VisibilityTable, "a1b2c3d4e5f6")
	if bytes.Equal(out, bare) {
		t.Error("revealing a bare fence to table changed nothing")
	}
	if !bytes.Contains(out, []byte("visibility=table")) {
		t.Errorf("the visibility token was not inserted: %q", out)
	}
	// The token is appended to the end of the directive line, which is the
	// only place a key can be added without disturbing the other keys, the body
	// or the closing fence.
	if !bytes.Contains(out, []byte("id=a1b2c3d4e5f6 author=johan visibility=table\nbody\n```\n")) {
		t.Errorf("inserting the token disturbed the fence: %q", out)
	}
}

// TestRevealPreservesSecretId proves the id survives a reveal, which is what
// makes a revoke possible afterwards. An implementation that unwraps the fence
// passes a naive "did the body become public" test and fails this one.
func TestRevealPreservesSecretID(t *testing.T) {
	t.Parallel()

	src := []byte("```secret id=a1b2c3d4e5f6 visibility=dm author=johan\n" + demotedBody + "\n```\n")
	out, _ := Reveal(Parse("ash.md", src), "a1b2c3d4e5f6")

	// Still a fence, still an id, still the same secret — not unwrapped into
	// plain Markdown.
	if !bytes.Contains(out, []byte("```secret")) {
		t.Fatalf("the fence was removed by a reveal: %q", out)
	}
	d := Parse("ash.md", out)
	spans := d.SecretSpans()
	if len(spans) != 1 || spans[0].SecretID != "a1b2c3d4e5f6" {
		t.Fatalf("the secret did not survive the reveal as a secret: %+v (%v)", spans, d.Problems)
	}
	if bytes.Contains(d.PublicBody(), []byte(demotedBody)) {
		t.Error("the revealed body is public: visibility=table is the app's job, not the file's")
	}
}

// commonPrefixLen is the length of the longest common prefix of a and b.
func commonPrefixLen(a, b []byte) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// commonSuffixLen is the length of the longest common suffix of a and b.
func commonSuffixLen(a, b []byte) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return i
}
