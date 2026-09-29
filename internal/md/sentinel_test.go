package md

import (
	"bytes"
	"crypto/sha256"
	hexenc "encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The redacted editor's own tests. Every one of them is a property of bytes:
// a body that is not restored exactly, or a byte that moves when nothing asked
// it to, is a corrupted vault file, and nothing downstream would notice.

func TestSentinelRendersAndParsesBack(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ id, body string }{
		"an ordinary body":   {"a1b2c3d4e5f6", "The key is under the stone.\n"},
		"an empty body":      {"000000000000", ""},
		"a body of newlines": {"deadbeef1234", "\n\n"},
		"a crlf body":        {"deadbeef1234", "line one\r\nline two\r\n"},
		"a body of braces":   {"deadbeef1234", "‹s:deadbeef1234:0:00000000›\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := Sentinel(tc.id, []byte(tc.body))
			if got == "" {
				t.Fatalf("Sentinel(%q) refused a valid id", tc.id)
			}
			parsed, ok := ParseSentinel([]byte(got))
			if !ok {
				t.Fatalf("ParseSentinel did not recognise %q", got)
			}
			if !parsed.Matches([]byte(tc.body)) {
				t.Errorf("the sentinel does not match the body it was rendered from: %+v", parsed)
			}
			if parsed.ID != tc.id || parsed.Len != len(tc.body) {
				t.Errorf("parsed = %+v, want id %q and length %d", parsed, tc.id, len(tc.body))
			}
		})
	}
}

func TestSentinelRefusesAnIDThatIsNotAddressable(t *testing.T) {
	t.Parallel()
	for name, id := range map[string]string{
		"empty":                    "",
		"too short":                "abc",
		"too long":                 "a1b2c3d4e5f6a",
		"upper case":               "A1B2C3D4E5F6",
		"not hex":                  "a1b2c3d4e5zz",
		"a segmenter placeholder":  ProblemUnparsableIDPrefix + "0000001a",
		"an anonymous placeholder": "anon-0000001a",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := Sentinel(id, []byte("body\n")); got != "" {
				t.Errorf("Sentinel rendered %q for id %q", got, id)
			}
		})
	}
}

// TestSentinelDigestIsSHA256OfTheBody pins the agreement with
// internal/secrets, which fingerprints a body as vault.Hash(md.SecretBody(...))
// and this package cannot import. The digest is computed here with
// crypto/sha256 over the same bytes SecretBody returns. If the two ever
// disagreed, every redacted save of every page on a vault would be refused as a
// modified sentinel, and the reason — a fingerprint computed differently on two
// sides of a package boundary — would be invisible in every message the user is
// shown.
func TestSentinelDigestIsSHA256OfTheBody(t *testing.T) {
	t.Parallel()
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		if len(src) > renderSizeLimit {
			continue
		}
		d := Parse("digest/"+name, src)
		spans := d.SecretSpans()
		if len(spans) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, s := range spans {
				body := SecretBody(d.Bytes, s)
				want := hexenc.EncodeToString(hashPrefix(body))
				got := Sentinel(s.SecretID, body)
				if got == "" {
					continue
				}
				parsed, ok := ParseSentinel([]byte(got))
				if !ok {
					t.Fatalf("secret %s did not render a parsable sentinel: %q", s.SecretID, got)
				}
				if parsed.Hash != want {
					t.Errorf("secret %s: sentinel digest %s, sha256 says %s",
						s.SecretID, parsed.Hash, want)
				}
				if parsed.Len != len(body) {
					t.Errorf("secret %s: sentinel length %d, the body is %d",
						s.SecretID, parsed.Len, len(body))
				}
			}
		})
	}
}

func TestParseSentinelRefusesAnythingButExactlyOneSentinel(t *testing.T) {
	t.Parallel()
	body := []byte("The key.\n")
	good := Sentinel("a1b2c3d4e5f6", body)
	for name, in := range map[string]string{
		"empty":                 "",
		"a trailing newline":    good + "\n",
		"a leading newline":     "\n" + good,
		"a trailing space":      good + " ",
		"two sentinels":         good + good,
		"a sentinel in prose":   "see " + good + " for details",
		"an uppercase digest":   strings.ToUpper(good),
		"a leading zero length": strings.Replace(good, ":9:", ":09:", 1),
		"a negative length":     strings.Replace(good, ":9:", ":-9:", 1),
		"a short digest":        strings.Replace(good, ":", ":0000", 1),
		"a truncated digest":    "‹s:a1b2c3d4e5f6:9:b2e943e›",
		"a non-hex digest":      strings.Replace(good, ":", ":zzzzzzzz", 1),
		"a missing close":       strings.TrimSuffix(good, "›"),
		"a missing open":        strings.TrimPrefix(good, "‹"),
		"a placeholder id":      "‹s:anon-0000001a:9:00000000›",
		"an unknown tag":        strings.Replace(good, sentinelOpen+"s:", sentinelOpen+"x:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, ok := ParseSentinel([]byte(in)); ok {
				t.Errorf("ParseSentinel accepted %q", in)
			}
		})
	}
}

// TestSentinelRoundTripIsByteIdentical is §8.9's central claim over the whole
// corpus: redacting every readable-to-nobody secret and splicing the buffer
// back returns the file, byte for byte, for every shape a vault has. The BOM,
// the CRLF, the file with no frontmatter, the unterminated fence and the body
// that is nothing but blank lines are all in here, and all of them fail loudly
// if a sentinel is rendered without its terminator or spliced back without one.
func TestSentinelRoundTripIsByteIdentical(t *testing.T) {
	t.Parallel()
	corpus := loadCorpus(t)
	for name, src := range corpus {
		d := Parse("redacted/"+name, src)
		hidden := sentinelledSecretIDs(d)
		if len(hidden) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			buffer := Redact(d, hidden)
			if bytes.Equal(buffer, src) {
				t.Fatal("Redact left the buffer identical on a page with hidden secrets")
			}
			assertNoSecretBodyIn(t, buffer, d, hidden)

			out, problems, err := Splice(d, buffer, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			assertNoProblems(t, problems)
			if !bytes.Equal(out, src) {
				t.Errorf("the redacted round trip changed the file: %s", firstDifference(src, out))
			}
		})
	}
}

// TestSentinelRoundTripInBothDirections is the same round trip as the editor
// actually performs it: a body the reader may not see is redacted, and a body
// they may see is not. Getting that backwards would hand a DM's secret to a
// player, and the golden sweep cannot see it because the golden sweep only ever
// hides everything.
func TestSentinelRoundTripInBothDirections(t *testing.T) {
	t.Parallel()
	corpus := loadCorpus(t)
	for name, src := range corpus {
		d := Parse("redacted/"+name, src)
		all := d.SecretSpans()
		if len(all) < 2 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first := all[0]
			hidden := map[string]bool{first.SecretID: true}
			buffer := Redact(d, hidden)
			assertNoSecretBodyIn(t, buffer, d, hidden)

			out, problems, err := Splice(d, buffer, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			assertNoProblems(t, problems)
			if !bytes.Equal(out, src) {
				t.Errorf("the redacted round trip changed the file: %s", firstDifference(src, out))
			}
		})
	}
}

// TestEditingAboveASecretSavesCorrectly is the case the design exists for: a
// player who may not read a DM's secret can still edit the public text above
// it, and the secret's own bytes come back untouched.
func TestEditingAboveASecretSavesCorrectly(t *testing.T) {
	t.Parallel()
	src := []byte("# Page\n\nOld opening line.\n\n" +
		"```secret id=a1b2c3d4e5f6\nThe key is under the third stone.\n```\n\nClosing.\n")
	d := Parse("page.md", src)
	hidden := map[string]bool{"a1b2c3d4e5f6": true}

	submitted := bytes.Replace(Redact(d, hidden), []byte("Old opening line."),
		[]byte("A new opening line, and a second one."), 1)
	if bytes.Equal(submitted, Redact(d, hidden)) {
		t.Fatal("the test did not change anything above the secret")
	}

	out, problems, err := Splice(d, submitted, hidden)
	if err != nil {
		t.Fatalf("Splice: %v", err)
	}
	assertNoProblems(t, problems)
	want := bytes.Replace(src, []byte("Old opening line."), []byte("A new opening line, and a second one."), 1)
	if !bytes.Equal(out, want) {
		t.Errorf("the save is not the file with the edit applied: %s", firstDifference(want, out))
	}
	if !bytes.Contains(out, []byte("The key is under the third stone.\n")) {
		t.Error("the secret body did not survive the save")
	}
}

// TestSentinelRejectsAModifiedBody is the refusal the whole sentinel scheme
// exists for. A user who may not read a secret cannot change what is inside it,
// and a save that changed one writes nothing at all: not the public edits, not
// the secret, nothing.
func TestSentinelRejectsAModifiedBody(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(sentinel string) string{
		"a changed digest": func(s string) string {
			return strings.Replace(s, s[len(s)-9:], "deadbeef›", 1)
		},
		"a changed length": func(s string) string {
			return Sentinel("a1b2c3d4e5f6", []byte("a different body entirely\n"))
		},
		"a text body":        func(string) string { return "I know what the key is.\n" },
		"an empty body":      func(string) string { return "" },
		"sentinel plus text": func(s string) string { return s + " and a guess\n" },
		"a stray space":      func(s string) string { return s[:len(s)-1] + " ›" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := []byte("Public.\n\n```secret id=a1b2c3d4e5f6\nThe key is under the third stone.\n```\n\nMore public.\n")
			d := Parse("page.md", src)
			hidden := map[string]bool{"a1b2c3d4e5f6": true}

			token, ok := ParseSentinel(secretBodyContent(t, Redact(d, hidden)))
			if !ok {
				t.Fatal("Redact did not render a sentinel")
			}
			_ = token
			submitted := replaceSecretBody(t, Redact(d, hidden), mutate(string(secretBodyContent(t, Redact(d, hidden)))))

			out, problems, err := Splice(d, submitted, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			if len(problems) == 0 {
				t.Fatal("a modified secret body was accepted")
			}
			if problems[0].SecretID != "a1b2c3d4e5f6" {
				t.Errorf("the problem does not name the secret: %v", problems[0])
			}
			if !bytes.Equal(out, src) {
				t.Error("a refused save still wrote something")
			}
		})
	}
}

// TestASubmittedSentinelForAnUnknownSecretIsRefused covers the forgery and the
// stale editor at once. A sentinel is a request to restore a body by id, and an
// id the file does not hold names no body: there is nothing to check the digest
// against and nothing that could safely be written.
func TestASubmittedSentinelForAnUnknownSecretIsRefused(t *testing.T) {
	t.Parallel()
	for name, submitted := range map[string][]byte{
		"a fabricated id": []byte("Public.\n\n```secret id=000000000000\n" +
			Sentinel("111111111111", []byte("anything\n")) + "\n```\n"),
		"a sentinel pasted into a page with no secrets": []byte(
			"Just prose with " + Sentinel("111111111111", []byte("anything\n")) + " in it.\n"),
		"a sentinel in a fence that names another secret": []byte(
			"```secret id=222222222222\n" + Sentinel("a1b2c3d4e5f6", []byte("x\n")) + "\n```\n"),
		"a second copy of a real secret": []byte(
			"```secret id=a1b2c3d4e5f6\n" + Sentinel("a1b2c3d4e5f6", []byte("The key.\n")) + "\n```\n" +
				"```secret id=a1b2c3d4e5f6\n" + Sentinel("a1b2c3d4e5f6", []byte("The key.\n")) + "\n```\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := []byte("Public.\n\n```secret id=a1b2c3d4e5f6\nThe key is under the third stone.\n```\n")
			d := Parse("page.md", src)
			hidden := map[string]bool{"a1b2c3d4e5f6": true}

			out, problems, err := Splice(d, submitted, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			if len(problems) == 0 {
				t.Fatal("the submission was accepted")
			}
			if !bytes.Equal(out, src) {
				t.Error("a refused save still wrote something")
			}
		})
	}
}

// TestSentinelShapedTextInAPublicRegionIsLiteral is the rule the save path is
// built on: sentinels are found by walking the submitted document's own secret
// spans, never by scanning the buffer. Public text that happens to look like a
// sentinel is text, and a secret body that contains one is restored as bytes.
func TestSentinelShapedTextInAPublicRegionIsLiteral(t *testing.T) {
	t.Parallel()
	shaped := Sentinel("a1b2c3d4e5f6", []byte("The key is under the third stone.\n"))
	src := []byte("Public prose holding " + shaped + " as an example.\n\n" +
		"```secret id=a1b2c3d4e5f6\n" + shaped + "\n```\n\n" +
		"And a line that is only a fragment: " + shaped[:len(shaped)-4] + "\n")
	d := Parse("page.md", src)
	hidden := map[string]bool{"a1b2c3d4e5f6": true}

	buffer := Redact(d, hidden)
	// The public occurrences survive untouched; only the secret's own body is
	// replaced. The truncated one is neither a sentinel nor a body, so it is
	// still there too — which is the point: nothing in a public region is
	// parsed, so nothing in one can be consumed.
	if got := strings.Count(string(buffer), shaped); got != 1 {
		t.Errorf("the buffer holds %d copies of the sentinel-shaped text, want the 1 public one", got)
	}
	if !bytes.Contains(buffer, []byte(shaped[:len(shaped)-4])) {
		t.Error("a truncated sentinel-shaped fragment was rewritten")
	}

	out, problems, err := Splice(d, buffer, hidden)
	if err != nil {
		t.Fatalf("Splice: %v", err)
	}
	assertNoProblems(t, problems)
	if !bytes.Equal(out, src) {
		t.Errorf("sentinel-shaped text was not treated as literal: %s", firstDifference(src, out))
	}

	// And a submission that keeps the secret's body as its own sentinel-shaped
	// text is a modification, not a restore: the body inside the fence is
	// compared as a whole against the on-disk body, so the copy the author
	// pasted into the secret is refused rather than believed.
	pasted := replaceSecretBody(t, buffer, shaped+"\n")
	if _, problems, _ := Splice(d, pasted, hidden); len(problems) == 0 {
		t.Error("sentinel-shaped text inside a secret was accepted as a restore token")
	}
}

// TestRedactLeavesEverythingElseByteIdentical is the narrow form of the golden
// sweep: for one page with several secrets, hiding one of them must move bytes
// inside that one body and nowhere else. A rewriter that rebuilt the document,
// or that re-emitted the fence, would pass the round trip only if it also
// reproduced the fence exactly — which is not a thing to rely on.
func TestRedactLeavesEverythingElseByteIdentical(t *testing.T) {
	t.Parallel()
	src := []byte("---\ntitle: Two secrets\n---\n\nBefore.\n\n" +
		"```secret id=111111111111 visibility=dm\nfirst body\n```\n\n" +
		"Middle with  trailing spaces.   \n\n" +
		"```secret id=222222222222\nsecond body\n```\n\nAfter.\n")
	d := Parse("two.md", src)
	hidden := map[string]bool{"222222222222": true}
	got := Redact(d, hidden)

	// Everything before the hidden fence and everything after it is the file.
	s := spanMustFind(t, src, "222222222222")
	if !bytes.HasPrefix(got, src[:s.StartByte]) {
		t.Errorf("bytes before the hidden secret changed: %s", firstDifference(src[:s.StartByte], got))
	}
	if !bytes.HasSuffix(got, src[s.EndByte:]) {
		t.Error("bytes after the hidden secret changed")
	}
	// The visible secret is untouched, fence and body.
	before := spanMustFind(t, src, "111111111111")
	visible := spanMustFind(t, got, "111111111111")
	if !bytes.Equal(got[visible.StartByte:visible.EndByte], src[before.StartByte:before.EndByte]) {
		t.Error("the readable secret was rewritten")
	}
	// The hidden one is the fence, then a sentinel, then the fence.
	hiddenSpan := spanMustFind(t, got, "222222222222")
	if !bytes.HasPrefix(got[hiddenSpan.StartByte:hiddenSpan.EndByte],
		[]byte("```secret id=222222222222\n"+sentinelOpen)) {
		t.Errorf("the hidden secret is not a fence around a sentinel: %q",
			got[hiddenSpan.StartByte:hiddenSpan.EndByte])
	}
	if !bytes.HasSuffix(got[hiddenSpan.StartByte:hiddenSpan.EndByte], []byte("›\n```\n")) {
		t.Errorf("the closing fence moved: %q", got[hiddenSpan.StartByte:hiddenSpan.EndByte])
	}
	// Trailing whitespace outside a secret is the author's, not ours.
	if !bytes.Contains(got, []byte("Middle with  trailing spaces.   \n")) {
		t.Error("redaction reflowed a line")
	}
}

// TestRedactReplacesAnUnaddressableBodyRatherThanLeakingIt is the fail-closed
// case. A fence whose directive could not be read has a placeholder id, which no
// sentinel can carry, and the body must still not reach the buffer.
func TestRedactReplacesAnUnaddressableBodyRatherThanLeakingIt(t *testing.T) {
	t.Parallel()
	src := []byte("```secret id=NotHexAtAll\nA body the reader may not see.\n```\n")
	d := Parse("broken.md", src)
	spans := d.SecretSpans()
	if len(spans) != 1 || validSecretID(spans[0].SecretID) {
		t.Fatalf("the fixture did not produce an unaddressable id: %+v", spans)
	}
	got := Redact(d, map[string]bool{spans[0].SecretID: true})
	if bytes.Contains(got, []byte("A body the reader may not see.")) {
		t.Fatal("an unaddressable secret's body reached the buffer")
	}
	// And a save of that page is refused rather than silently losing the body.
	out, problems, err := Splice(d, got, map[string]bool{spans[0].SecretID: true})
	if err != nil {
		t.Fatalf("Splice: %v", err)
	}
	if len(problems) == 0 {
		t.Error("a save of an unredactable secret was accepted")
	}
	if !bytes.Equal(out, src) {
		t.Error("a refused save still wrote something")
	}
}

// TestRemovingAWholeSecretBlockIsReported covers the operation the plan makes
// separately authorisable. Redacted mode cannot splice a block that is not
// there, so its absence is a problem naming the id, not a deletion.
func TestRemovingAWholeSecretBlockIsReported(t *testing.T) {
	t.Parallel()
	src := []byte("Public.\n\n```secret id=a1b2c3d4e5f6\nThe key.\n```\n\nMore.\n")
	d := Parse("page.md", src)
	hidden := map[string]bool{"a1b2c3d4e5f6": true}
	submitted := []byte("Public.\n\nMore.\n")

	out, problems, err := Splice(d, submitted, hidden)
	if err != nil {
		t.Fatalf("Splice: %v", err)
	}
	if len(problems) != 1 || problems[0].Code != ProblemSecretBlockRemoved {
		t.Fatalf("problems = %v, want one %s", problems, ProblemSecretBlockRemoved)
	}
	if !bytes.Equal(out, src) {
		t.Error("a refused save still wrote something")
	}
}

// TestCrlfRedactedRoundTrip covers the line ending around a sentinel. A
// browser textarea rewrites CRLF as LF on submit, so the buffer that comes back
// from a redacted editor of a CRLF page has a different terminator around each
// sentinel than the file did. The bytes inside the secret come from disk
// whatever the buffer says, so the file keeps the endings it had instead of the
// save being refused over a byte the reader cannot see.
func TestCrlfRedactedRoundTrip(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		file string
		crlf bool
	}{
		"a crlf file":                     {"secret-crlf-fence.md", true},
		"a crlf file with a bom":          {"secret-bom-crlf.md", true},
		"an lf file with a bom":           {"secret-bom.md", false},
		"a crlf file with no frontmatter": {"secret-crlf-no-frontmatter.md", true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			src := loadFixture(t, tc.file)
			d := Parse("crlf/"+tc.file, src)
			hidden := sentinelledSecretIDs(d)
			if len(hidden) == 0 {
				t.Skip("the fixture holds no secret")
			}
			submitted := Redact(d, hidden)
			if tc.crlf {
				submitted = crlfToLFAroundSentinels(submitted)
			}

			out, problems, err := Splice(d, submitted, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			assertNoProblems(t, problems)
			if !bytes.Equal(out, src) {
				t.Errorf("the round trip changed the file: %s", firstDifference(src, out))
			}
		})
	}
}

// TestRedactedRoundTripOnDegenerateFences is the pair of shapes the fuzz target
// found, both of which a redaction can get wrong in a way that only shows up as
// a wrong save:
//
//   - a block with no body at all. The span's last line is the closing fence and
//     it begins where the body would, so a body calculation that does not check
//     whether that line is a fence reports "```" as the secret's text — and
//     replacing it deletes the fence.
//   - a file whose last line is a secret fence with nothing after it. A sentinel
//     written there joins the fence's own line, and the unquoted `id=` value
//     runs to the end of the line, so the buffer re-parses as a page holding a
//     secret named after the sentinel. There is no body to hide, so the honest
//     answer is to leave the bytes alone and to have nothing to complain about
//     on the way back.
func TestRedactedRoundTripOnDegenerateFences(t *testing.T) {
	t.Parallel()
	for name, src := range map[string][]byte{
		"a block with no body":             []byte("```secret id=000000000000\n```\n"),
		"a block with no body, no newline": []byte("```secret id=000000000000\n```"),
		"a fence that is the last line":    []byte("```secret id=000000000000"),
		"a fence with no id":               []byte("```secret\n```\n"),
		"a body that is one blank line":    []byte("```secret id=000000000000\n\n```\n"),
		"a body of nothing but newlines":   []byte("```secret id=000000000000\n\n\n```\n"),
		"two empty blocks": []byte("```secret id=000000000000\n```\n\n" +
			"```secret id=111111111111\n```\n"),
		"an empty block then a real one": []byte("```secret id=000000000000\n```\n\n" +
			"```secret id=111111111111\nThe body.\n```\n"),
		"a nested fence in an empty one": []byte("```secret id=000000000000\n```\n\n" +
			"```secret id=111111111111\n```secret id=222222222222\ninner\n```\n```\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("degenerate.md", src)
			hidden := sentinelledSecretIDs(d)
			if len(hidden) == 0 {
				t.Skip("no secret on this page can carry a sentinel")
			}
			buffer := Redact(d, hidden)
			assertNoSecretBodyIn(t, buffer, d, hidden)
			out, problems, err := Splice(d, buffer, hidden)
			if err != nil {
				t.Fatalf("Splice: %v", err)
			}
			assertNoProblems(t, problems)
			if !bytes.Equal(out, src) {
				t.Errorf("the round trip changed the file: %s", firstDifference(src, out))
			}
		})
	}
}

// TestSecretBodyOfAnEmptyBlockIsEmpty pins the first half of the above on its
// own, because the consequence is not only a redaction: the body is what
// internal/secrets hashes and what the renderer would be handed, and a body of
// "```" is neither.
func TestSecretBodyOfAnEmptyBlockIsEmpty(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		src  string
		want string
	}{
		"an empty block":              {"```secret id=000000000000\n```\n", ""},
		"a block with one blank line": {"```secret id=000000000000\n\n```\n", "\n"},
		"a block with a body":         {"```secret id=000000000000\nbody\n```\n", "body\n"},
		"an unterminated fence with a last line that is not a fence": {
			"```secret id=000000000000\nbody", "body",
		},
		"an unterminated fence whose last line looks like a fence of another kind": {
			// The span's last line is excluded whatever it is, so a `~~~~` under
			// a ` ``` ` fence is treated as a closing fence it is not. That is
			// the rule the body has always had and the one both halves of the
			// redacted round trip use, so the round trip stays exact; a heading
			// or a link on that last line is not extracted, which is a gap in
			// extraction rather than in the round trip.
			"```secret id=000000000000\nbody\n~~~~", "body\n",
		},
		"an unterminated fence with a deeper closing fence": {
			"```secret id=000000000000\nbody\n    ```", "body\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("body.md", []byte(tc.src))
			spans := d.SecretSpans()
			if len(spans) != 1 {
				t.Fatalf("spans = %d, want one", len(spans))
			}
			if got := string(SecretBody(d.Bytes, spans[0])); got != tc.want {
				t.Errorf("SecretBody = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSpliceRefusesADocumentItCannotReasonAbout(t *testing.T) {
	if _, _, err := Splice(nil, []byte("x"), map[string]bool{"a1b2c3d4e5f6": true}); !errors.Is(err, ErrNoDocument) {
		t.Errorf("Splice(nil) = %v, want ErrNoDocument", err)
	}
	dup := Parse("dup.md", []byte(
		"```secret id=a1b2c3d4e5f6\none\n```\n\n```secret id=a1b2c3d4e5f6\ntwo\n```\n"))
	out, _, err := Splice(dup, Redact(dup, map[string]bool{"a1b2c3d4e5f6": true}),
		map[string]bool{"a1b2c3d4e5f6": true})
	if !errors.Is(err, ErrDuplicateSecretID) {
		t.Errorf("Splice on a file with two fences for one id = %v, want ErrDuplicateSecretID", err)
	}
	if !bytes.Equal(out, dup.Bytes) {
		t.Error("a refused save still wrote something")
	}
}

// assertNoSecretBodyIn requires that no byte of any hidden body is in the
// buffer. The check is on the body, not on the sentinel, because the sentinel is
// supposed to be there and a redaction that leaked would leak a fragment of it.
func assertNoSecretBodyIn(t *testing.T, buffer []byte, d *Doc, hidden map[string]bool) {
	t.Helper()
	for _, s := range d.SecretSpans() {
		if !hidden[s.SecretID] {
			continue
		}
		for _, line := range secretBodyLines(d, s) {
			if bytes.Contains(buffer, line) {
				t.Errorf("a line of secret %s reached the editor buffer: %q", s.SecretID, line)
			}
		}
	}
}

// secretBodyContent is the part of a redacted buffer's only secret body that
// ParseSentinel is given: the sentinel, with the line terminator the body keeps
// around it removed.
func secretBodyContent(t *testing.T, buffer []byte) []byte {
	t.Helper()
	d := Parse("buffer.md", buffer)
	spans := d.SecretSpans()
	if len(spans) != 1 {
		t.Fatalf("the buffer has %d secret spans, want 1", len(spans))
	}
	content, _ := splitTerminator(SecretBody(d.Bytes, spans[0]))
	return content
}

// replaceSecretBody rewrites the one secret body in a buffer, which is how a
// test simulates a user typing inside a fence.
func replaceSecretBody(t *testing.T, buffer []byte, body string) []byte {
	t.Helper()
	d := Parse("buffer.md", buffer)
	spans := d.SecretSpans()
	if len(spans) != 1 {
		t.Fatalf("the buffer has %d secret spans, want 1", len(spans))
	}
	start, end := secretBody(d.Bytes, spans[0])
	return splice(buffer, start, end, []byte(body))
}

// hashPrefix is the first four bytes of a sha256, as the tests compute it
// independently of the package under test.
func hashPrefix(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:4]
}

// crlfToLFAroundSentinels rewrites the line ending that follows every sentinel
// in a buffer, and only those. It is what a textarea does to a CRLF page on
// submit, restricted to the region the reader is not allowed to edit: the public
// line endings are the author's own bytes and a change to them is a change they
// made.
func crlfToLFAroundSentinels(buffer []byte) []byte {
	out := append([]byte(nil), buffer...)
	for pos := 0; pos < len(out); {
		i := bytes.Index(out[pos:], []byte(sentinelClose))
		if i < 0 {
			break
		}
		at := pos + i + len(sentinelClose)
		if bytes.HasPrefix(out[at:], []byte("\r\n")) {
			out = append(out[:at], append([]byte("\n"), out[at+2:]...)...)
		}
		// Every iteration moves the cursor past the terminator it may have
		// rewritten, or past the closing bracket that was not one.
		pos = at + 1
	}
	return out
}
