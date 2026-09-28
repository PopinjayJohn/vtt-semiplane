package md

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// visibilityToken matches a visibility= token and the space that separates it
// from its neighbours. It is written independently of the production scanner
// on purpose: a test that verified the writer with the writer's own parser
// would agree with a bug.
var visibilityToken = regexp.MustCompile(`[ ]*visibility=(?:"[^"]*"|'[^']*'|\S+)[ ]*`)

// TestVaultRoundTripPreservesSecretBytes is §8.3's own assertion: a reveal or a
// revoke rewrites one token, and every other byte of the file is the file.
//
// It is a property test over the whole fixture corpus rather than a table of
// cases, because the failure it guards against is asymmetric: a reveal that
// reflows a directive, drops a quoted title or clips a body produces a file
// that still parses and still renders, so nothing else would notice.
func TestVaultRoundTripPreservesSecretBytes(t *testing.T) {
	t.Parallel()
	visibilities := []authz.Visibility{authz.VisibilityPrivate, authz.VisibilityDM, authz.VisibilityTable}
	corpus := loadCorpus(t)

	for name, src := range corpus {
		d := Parse("secrets/"+name, src)
		spans := d.SecretSpans()
		if len(spans) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, s := range spans {
				for _, from := range visibilities {
					for _, to := range visibilities {
						seed := mustSetVisibility(t, src, s.SecretID, from)
						got, problems := SetVisibility(Parse("secrets/"+name, seed), to, s.SecretID)
						for _, p := range problems {
							if p.Code == ProblemSecretUnknownID {
								t.Fatalf("secret %s went missing between reads", s.SecretID)
							}
						}
						assertOnlyVisibilityChanged(t, seed, got, s.SecretID, to)
						assertBodyUnchanged(t, seed, got, s.SecretID)
					}
				}
				// A full cycle returns the file to the bytes it started as.
				cyclic := mustSetVisibility(t, src, s.SecretID, authz.VisibilityTable)
				revoked, _ := Revoke(Parse("secrets/"+name, cyclic), s.SecretID)
				back, _ := Reveal(Parse("secrets/"+name, revoked), s.SecretID)
				if !bytes.Equal(back, cyclic) {
					t.Errorf("a table revoke and reveal cycle changed the file: %s",
						firstDifference(cyclic, back))
				}
			}
		})
	}
}

// TestRevealAndRevokeAreNoOpsWhenAlreadyThere pins the other half: a fence that
// already says what it is being told to say must produce the input's bytes, so
// the caller can compare and skip the write. A re-save of the identical bytes
// would be a spurious modification for every file watcher to report.
func TestRevealAndRevokeAreNoOpsWhenAlreadyThere(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "secret-visibilities.md")
	for id, want := range map[string]authz.Visibility{
		"111111111111": authz.VisibilityPrivate,
		"222222222222": authz.VisibilityDM,
		"333333333333": authz.VisibilityTable,
	} {
		got, problems := SetVisibility(Parse("visibilities.md", src), want, id)
		assertNoProblems(t, problems)
		if !bytes.Equal(got, src) {
			t.Errorf("setting %s to its current visibility %s rewrote the file", id, want)
		}
	}
	// The same holds for a fence with no visibility= token at all, whose
	// visibility is private by definition.
	implicit := loadFixture(t, "secret-default-visibility.md")
	got, problems := Revoke(Parse("default.md", implicit), "444444444444")
	assertNoProblems(t, problems)
	if !bytes.Equal(got, implicit) {
		t.Errorf("revoking an already-private secret rewrote the file: %q", got)
	}
}

// TestRevealInsertsAnAbsentVisibilityToken covers the other direction: a fence
// with no visibility= token has to gain one, and must gain nothing else.
func TestRevealInsertsAnAbsentVisibilityToken(t *testing.T) {
	t.Parallel()
	src := []byte("```secret id=abcd1234abcd\nBody.\n```\n")
	got, problems := Reveal(Parse("x.md", src), "abcd1234abcd")
	assertNoProblems(t, problems)
	want := "```secret id=abcd1234abcd visibility=table\nBody.\n```\n"
	if string(got) != want {
		t.Errorf("Reveal = %q, want %q", got, want)
	}
}

// TestRevealRejectsAnUnknownVisibility checks the one value that would be a
// data-loss bug: writing a visibility nothing can read back would leave the
// secret unreachable rather than merely unreadable.
func TestRevealRejectsAnUnknownVisibility(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "secret-basic.md")
	got, problems := SetVisibility(Parse("x.md", src), authz.Visibility("everyone"), "a1b2c3d4e5f6")
	if !bytes.Equal(got, src) {
		t.Error("an invalid visibility was written to the file")
	}
	if len(problems) != 1 || problems[0].Code != ProblemSecretBadVisibility {
		t.Errorf("problems = %v, want one secret.bad_visibility", problems)
	}
}

// TestRevealOfAnAbsentIDChangesNothingAndSays so: a stale id from an index that
// has drifted from the file is a bug to surface, not a fence to guess at.
func TestRevealOfAnAbsentIDChangesNothingAndSays(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "secret-basic.md")
	got, problems := Reveal(Parse("x.md", src), "000000000000")
	if !bytes.Equal(got, src) {
		t.Error("revealing an absent id changed the file")
	}
	if len(problems) != 1 || problems[0].Code != ProblemSecretUnknownID {
		t.Errorf("problems = %v, want one secret.unknown_id", problems)
	}
	if problems[0].SecretID != "000000000000" {
		t.Errorf("the problem does not name the id: %v", problems[0])
	}
}

// TestDirectiveFieldScanningIsQuoteAware is the regression test for the quoted
// title. A whitespace split reads `Door"` as a key name, which makes a reveal
// append a second visibility token and corrupt the directive.
func TestDirectiveFieldScanningIsQuoteAware(t *testing.T) {
	t.Parallel()
	info := []byte(`secret id=555555555555 visibility=dm author=gundren created=2024-03-04T05:06:07Z title="The Vault Door"`)
	fields := scanDirectiveFields(info, 0)
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		keys = append(keys, string(f.key))
	}
	want := []string{"secret", "id", "visibility", "author", "created", "title"}
	if len(keys) != len(want) {
		t.Fatalf("fields = %q, want %q", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("fields = %q, want %q", keys, want)
		}
	}
	for _, f := range fields {
		if string(f.key) == "title" {
			if string(unquoteBytes(f.value)) != "The Vault Door" {
				t.Errorf("title value = %q", unquoteBytes(f.value))
			}
			continue
		}
		if string(f.key) == "visibility" && string(unquoteBytes(f.value)) != "dm" {
			t.Errorf("visibility value = %q", unquoteBytes(f.value))
		}
	}
}

// mustSetVisibility returns src with the named secret's visibility set, and
// fails the test if that could not be done. It builds the starting state of
// each case of the round-trip property test.
func mustSetVisibility(t *testing.T, src []byte, id string, v authz.Visibility) []byte {
	t.Helper()
	got, problems := SetVisibility(Parse("seed.md", src), v, id)
	for _, p := range problems {
		if p.Code == ProblemSecretUnknownID {
			t.Fatalf("secret %s is not in the fixture", id)
		}
	}
	return got
}

// assertOnlyVisibilityChanged requires that out differs from src only inside
// the named secret's directive line, and that within that line only the
// visibility token differs.
func assertOnlyVisibilityChanged(t *testing.T, src, out []byte, id string, v authz.Visibility) {
	t.Helper()
	before := Parse("before.md", src)
	after := Parse("after.md", out)
	s, ok := spanOf(before, id)
	if !ok {
		t.Fatalf("secret %s is not in the input", id)
	}
	s2, ok := spanOf(after, id)
	if !ok {
		t.Fatalf("secret %s is not in the output", id)
	}
	// Everything before the fence and everything after its directive line is
	// the file.
	if !bytes.HasPrefix(out, src[:s.StartByte]) {
		t.Errorf("reveal rewrote bytes before the fence of %s", id)
	}
	dirEnd := directiveLineEnd(before, s)
	if !bytes.HasSuffix(out, src[dirEnd:]) {
		t.Errorf("reveal rewrote bytes after the directive line of %s", id)
	}
	// Within the directive line, only the token moves.
	got := visibilityToken.ReplaceAll(after.Bytes[s2.StartByte:directiveLineEnd(after, s2)], nil)
	want := visibilityToken.ReplaceAll(before.Bytes[s.StartByte:dirEnd], nil)
	if !bytes.Equal(got, want) {
		t.Errorf("reveal rewrote more than the visibility token of %s:\n got %q\nwant %q", id, got, want)
	}
	if got := effectiveVisibility(t, after, s2); got != v {
		t.Errorf("the effective visibility of %s is %s, want %s", id, got, v)
	}
}

// effectiveVisibility is the visibility a fence's directive names, applying the
// private default. It is the semantic counterpart of the byte comparison: a
// fence with no token and one with `visibility=private` are the same secret.
func effectiveVisibility(t *testing.T, d *Doc, s Span) authz.Visibility {
	t.Helper()
	end, _, ok := lineBounds(d.Bytes, s.StartByte)
	if !ok {
		t.Fatalf("secret span at %d has no line", s.StartByte)
	}
	f, isFence := fenceAt(d.Bytes[s.StartByte:end])
	if !isFence {
		t.Fatalf("secret span at %d is not a fence", s.StartByte)
	}
	info := string(trimRightSpace(d.Bytes[s.StartByte+f.Offset+f.Run : end]))
	dir, err := ParseFenceDirective(info)
	if err != nil {
		t.Fatalf("directive %q: %v", info, err)
	}
	return dir.Visibility
}

// assertBodyUnchanged requires that the secret's own text is byte-identical
// after a rewrite. This is the invariant that an unwrap-style reveal violates
// most visibly.
func assertBodyUnchanged(t *testing.T, src, out []byte, id string) {
	t.Helper()
	before := SecretBody(src, spanMustFind(t, src, id))
	after := SecretBody(out, spanMustFind(t, out, id))
	if !bytes.Equal(after, before) {
		t.Errorf("the body of %s changed: %q became %q", id, before, after)
	}
}

func spanOf(d *Doc, id string) (Span, bool) {
	for _, s := range d.SecretSpans() {
		if s.SecretID == id {
			return s, true
		}
	}
	return Span{}, false
}

func spanMustFind(t *testing.T, src []byte, id string) Span {
	t.Helper()
	s, ok := spanOf(Parse("x.md", src), id)
	if !ok {
		t.Fatalf("secret %s is not in the document", id)
	}
	return s
}

// directiveLineEnd returns the offset just past a span's fence line, excluding
// its line terminator.
func directiveLineEnd(d *Doc, s Span) int {
	end, _, ok := lineBounds(d.Bytes, s.StartByte)
	if !ok {
		return s.StartByte
	}
	for end > s.StartByte && isSpaceByte(d.Bytes[end-1]) {
		end--
	}
	return end
}
