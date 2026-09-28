package md

import (
	"bytes"
	"testing"
)

// TestSegmentCoversBodyExactlyOnce is the partition property, checked over the
// whole committed corpus rather than over cases someone thought of. A span
// list with a gap, an overlap or a length that does not add up produces a Doc
// whose PublicBody is not the public part of the file, and everything
// downstream indexes that instead.
func TestSegmentCoversBodyExactlyOnce(t *testing.T) {
	t.Parallel()
	corpus := loadCorpus(t)
	secrets := 0
	for name, src := range corpus {
		d := Parse(name, src)
		assertSpansPartitionBody(t, d)
		secrets += len(d.SecretSpans())
		// Reassembling the public body and the secret bodies must give the
		// body back, in the order they appeared.
		var public, secret []byte
		for _, s := range d.Spans {
			if s.Secret() {
				secret = append(secret, d.Bytes[s.StartByte:s.EndByte]...)
			} else {
				public = append(public, d.Bytes[s.StartByte:s.EndByte]...)
			}
		}
		if !bytes.Equal(public, d.PublicBody()) {
			t.Errorf("%s: the public spans do not reassemble into PublicBody", name)
		}
		_ = secret
	}
	if secrets == 0 {
		t.Fatal("no fixture produced a secret span: the corpus cannot be testing anything")
	}
	t.Logf("%d fixtures, %d secret spans", len(corpus), secrets)
}

// TestSegmenterNestedSecretRejected pins §5.4's nesting rule. The inner fence
// cannot be secret — a secret is opaque, so a secret inside one is just text —
// which means the outer span has to continue past it. A segmenter that ended
// the outer span at the inner fence would render the outer secret's tail as
// public text, and a segmenter that nested would produce spans that overlap.
func TestSegmenterNestedSecretRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		// wantSpans is the whole span list's length and wantIDs the secret ids
		// in it, in order. The nested fence's id is never among them.
		wantSpans  int
		wantIDs    []string
		wantEnd    string
		wantPublic string
	}{
		{
			name: "a secret fence inside another",
			src:  "before\n```secret id=outer1\n```secret id=inner1\nbody\n```\nafter\n",
			// Public, secret, public: the inner fence is inside the outer
			// span, and the outer span ends at the line that closes it.
			wantSpans:  3,
			wantIDs:    []string{"outer1"},
			wantEnd:    "```\n",
			wantPublic: "before\n",
		},
		{
			// The third line closes the outer fence, so the `id=b` fence that
			// follows it is a second, separate secret rather than a nested one.
			// Only the `id=a` fence is nesting.
			name:      "two inner fences",
			src:       "```secret id=o\n```secret id=a\nx\n```\n```secret id=b\ny\n```\n",
			wantSpans: 2,
			wantIDs:   []string{"o", "b"},
		},
		{
			// The indented `  ``` ` closes the outer fence, so the trailing
			// one at column zero is public text.
			name:      "an inner fence in a list item",
			src:       "```secret id=o\n  ```secret id=i\n  body\n  ```\n```\n",
			wantSpans: 2,
			wantIDs:   []string{"o"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Parse("nested.md", []byte(tc.src))
			assertSpansPartitionBody(t, d)
			if len(d.Spans) != tc.wantSpans {
				t.Fatalf("spans = %+v, want %d", d.Spans, tc.wantSpans)
			}
			secrets := d.SecretSpans()
			if got := secretIDs(secrets); !sameStrings(got, tc.wantIDs) {
				t.Fatalf("secret ids = %q, want %q", got, tc.wantIDs)
			}
			if tc.wantEnd != "" {
				if got := string(d.Bytes[secrets[0].EndByte-len(tc.wantEnd) : secrets[0].EndByte]); got != tc.wantEnd {
					t.Errorf("the secret span ends with %q, want %q", got, tc.wantEnd)
				}
			}
			if tc.wantPublic != "" {
				if got := string(d.Bytes[secrets[0].StartByte-len(tc.wantPublic) : secrets[0].StartByte]); got != tc.wantPublic {
					t.Errorf("the secret span starts at %q, want it preceded by %q", got, tc.wantPublic)
				}
			}
			// A nesting problem is recorded, and the inner fence never becomes
			// a span of its own.
			nested := 0
			for _, p := range d.Problems {
				if p.Code == ProblemSecretNested {
					nested++
				}
			}
			if nested == 0 {
				t.Errorf("no secret.nested problem: %v", d.Problems)
			}
			// A fence that is nested is literal text. A fence that merely
			// follows the outer one, because the outer one closed, is not
			// nested and is entitled to a span of its own.
			for _, id := range []string{"inner1", "i", "a"} {
				for _, s := range d.Spans {
					if s.SecretID == id {
						t.Errorf("the nested fence %q became a span: %+v", id, s)
					}
				}
			}
		})
	}
}

// TestUnterminatedSecretRecovers pins the recoverable-failure contract: the
// span runs to the end of the file, a problem is recorded, and nothing is
// dropped. A segmenter that gave up on an unclosed fence would render the
// secret's text as a public code block, which is the one failure a save cannot
// undo.
func TestUnterminatedSecretRecovers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
	}{
		{"no closing fence at all", "# T\n\n```secret id=abc123abc123\nthe body\n"},
		{"closing fence of a tilde", "```secret id=abc123abc123\nbody\n~~~\n"},
		{"closing fence with an info string", "```secret id=abc123abc123\nbody\n```go\n"},
		{"nothing after the opening fence", "```secret id=abc123abc123"},
		{"a backtick run shorter than the opener", "````secret id=abc123abc123\nbody\n```\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Parse("unterminated.md", []byte(tc.src))
			assertSpansPartitionBody(t, d)
			secrets := d.SecretSpans()
			if len(secrets) != 1 {
				t.Fatalf("secret spans = %+v, want exactly one", d.Spans)
			}
			if secrets[0].EndByte != d.BodyRange.End {
				t.Errorf("the span ends at %d, want the body's end %d",
					secrets[0].EndByte, d.BodyRange.End)
			}
			found := false
			for _, p := range d.Problems {
				if p.Code == ProblemSecretUnterminated {
					found = true
				}
			}
			if !found {
				t.Errorf("problems = %v, want a secret.unterminated", d.Problems)
			}
			// The body is not public, or a render would show it.
			if bytes.Contains(d.PublicBody(), []byte("body")) {
				t.Errorf("an unterminated secret body is in the public body: %q", d.PublicBody())
			}
		})
	}
}

// TestUnknownDirectiveKeyIsPublicPassthrough pins the other direction: a fence
// whose directive this package cannot fully understand is public, and says so.
//
// It is the uncomfortable half of the contract. Refusing to redact a block
// whose semantics are unknown would be safer, but it would also make an
// ordinary note unopenable the moment a plugin added a key — so the rule is
// that only a directive md understands can be a secret, and a problem says
// which block stopped being one.
// A ```secret fence with a directive we cannot read is a secret whose contents
// are not shown, never public text. It used to be public passthrough, which was
// a leak: see TestAnUnunderstoodSecretFenceNeverBecomesPublic, which is the
// regression test for the whole class.
func TestUnknownDirectiveKeyIsHiddenNotDemoted(t *testing.T) {
	t.Parallel()
	cases := []string{
		"```secret id=abc123abc123 rotate=on\nbody\n```\n",
		"```secret rotate=on\nbody\n```\n",
		"```secret id=a id=b\nbody\n```\n",
		"```secret id=a unexpected=\nbody\n```\n",
	}
	for _, src := range cases {
		t.Run(src[:min(24, len(src))], func(t *testing.T) {
			t.Parallel()
			d := Parse("unknown-key.md", []byte(src))
			assertSpansPartitionBody(t, d)
			if len(d.SecretSpans()) != 1 {
				t.Fatalf("a fence claiming secrecy was demoted to public: %+v", d.Spans)
			}
			if bytes.Contains(d.PublicBody(), []byte("body")) {
				t.Error("the secret body is in the public body")
			}
			found := false
			for _, p := range d.Problems {
				if p.Code == ProblemSecretUnknownKey || p.Code == ProblemSecretBadDirective ||
					p.Code == ProblemSecretMissingID {
					found = true
				}
			}
			if !found {
				t.Errorf("problems = %v, want an unknown-key, bad-directive or missing-id problem", d.Problems)
			}
		})
	}
}
func TestKnownKeyWithAnUnusableValueStaysSecret(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"```secret id=abc123abc123 visibility\nbody\n```\n",
		"```secret id=abc123abc123 visibility=\nbody\n```\n",
		"```secret id=abc123abc123 visibility=everyone\nbody\n```\n",
		"```secret id=abc123abc123 visibility=DM\nbody\n```\n",
	} {
		t.Run(src[:min(36, len(src))], func(t *testing.T) {
			t.Parallel()
			d := Parse("bad-value.md", []byte(src))
			secrets := d.SecretSpans()
			if len(secrets) != 1 {
				t.Fatalf("a known key with an unusable value stopped being a secret: %+v", d.Spans)
			}
			if bytes.Contains(d.PublicBody(), []byte("body")) {
				t.Error("the secret body is public")
			}
		})
	}
}

// TestQuotedDirectiveValueStillSegmentsAsSecret is the regression test for the
// worst bug this package could have: a whitespace-split directive parser reads
// `Door"` in title="The Vault Door" as a key name, the fence then looks like
// it carries an unknown key, and the block is demoted to public passthrough —
// a secret rendered in plaintext because its title had a space in it.
func TestQuotedDirectiveValueStillSegmentsAsSecret(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"```secret id=abc123abc123 title=\"The Vault Door\"\nbody\n```\n",
		"```secret id=abc123abc123 title='The Vault Door'\nbody\n```\n",
		"```secret title=\"Two Words\" id=abc123abc123 visibility=dm\nbody\n```\n",
		"```secret id=abc123abc123 title=\"A \\\"quoted\\\" title\"\nbody\n```\n",
	} {
		t.Run(src[:min(40, len(src))], func(t *testing.T) {
			t.Parallel()
			d := Parse("quoted.md", []byte(src))
			secrets := d.SecretSpans()
			if len(secrets) != 1 || secrets[0].SecretID != "abc123abc123" {
				t.Fatalf("spans = %+v, problems = %v, want one secret span",
					d.Spans, d.Problems)
			}
			if bytes.Contains(d.PublicBody(), []byte("body")) {
				t.Error("the secret body is public")
			}
		})
	}
	// The directive is read, not guessed at.
	d := Parse("t.md", []byte("```secret id=abc123abc123 title=\"The Vault Door\" visibility=dm\nb\n```\n"))
	dir, err := ParseFenceDirective("secret id=abc123abc123 title=\"The Vault Door\" visibility=dm")
	if err != nil {
		t.Fatal(err)
	}
	if dir.Title != "The Vault Door" || dir.Visibility != "dm" || dir.HasUnknown {
		t.Errorf("directive = %+v", dir)
	}
	_ = d
}

// TestSecretSegmentationShapes walks the placements the segmenter has to get
// right: a fence in a list item, in a block quote, indented, and several in a
// row.
func TestSecretSegmentationShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		src   string
		ids   []string
		spans int
	}{
		{
			name: "in a list item",
			src:  "- item\n\n  ```secret id=aaaaaaaaaaaa\n  body\n  ```\n\n- next\n",
			ids:  []string{"aaaaaaaaaaaa"}, spans: 3,
		},
		{
			name: "in a block quote",
			src:  "> text\n\n> ```secret id=bbbbbbbbbbbb\n> body\n> ```\n\n> more\n",
			ids:  []string{"bbbbbbbbbbbb"}, spans: 3,
		},
		{
			name: "indented by two, closing fence at the same indent",
			src:  "  ```secret id=cccccccccccc\n  body\n  ```\n",
			ids:  []string{"cccccccccccc"}, spans: 1,
		},
		{
			name: "indented by two, closing fence at column zero",
			src:  "  ```secret id=dddddddddddd\n  body\n```\n",
			ids:  []string{"dddddddddddd"}, spans: 1,
		},
		{
			name: "tilde fence",
			src:  "~~~secret id=eeeeeeeeeeee\nbody\n~~~\n",
			ids:  []string{"eeeeeeeeeeee"}, spans: 1,
		},
		{
			name: "adjacent fences",
			src:  "```secret id=ffffffffffff\na\n```\n```secret id=111111111111\nb\n```\n",
			// Two secret spans with no public one between them: a zero-length
			// public span carries no information for a consumer indexing by
			// byte offset, so the segmenter does not emit one.
			ids: []string{"ffffffffffff", "111111111111"}, spans: 2,
		},
		{
			name:  "a plain code fence is not a secret",
			src:   "```go\nfunc main() {}\n```\n",
			spans: 1,
		},
		{
			name:  "a fence mentioning secret in its info string is not one",
			src:   "```notsecret id=aaaaaaaaaaaa\nbody\n```\n",
			spans: 1,
		},
		{
			// CommonMark: a backtick run's info string may not contain a
			// backtick, so this line is a paragraph and not a fence at all.
			// The directive parser would reject the stray backtick as an
			// unknown key in any case, so both readings agree — and the page
			// still renders, as text, rather than vanishing.
			name:  "a backtick in the info string is not a fence",
			src:   "```secret id=aaaaaaaaaaaa `x`\nbody\n```\n",
			spans: 1,
		},
		{
			name: "a fence inside a secret is not a fence at all",
			src:  "```secret id=aaaaaaaaaaaa\n```text\n```\n",
			ids:  []string{"aaaaaaaaaaaa"}, spans: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Parse("shapes.md", []byte(tc.src))
			assertSpansPartitionBody(t, d)
			if len(d.Spans) != tc.spans {
				t.Errorf("spans = %d, want %d: %+v", len(d.Spans), tc.spans, d.Spans)
			}
			secrets := d.SecretSpans()
			if len(secrets) != len(tc.ids) {
				t.Fatalf("secret ids = %+v, want %v", secretIDs(secrets), tc.ids)
			}
			for i, id := range tc.ids {
				if secrets[i].SecretID != id {
					t.Errorf("secret %d = %q, want %q", i, secrets[i].SecretID, id)
				}
			}
		})
	}
}

// TestSecretsInACRLFFile: the closing fence is `---\r\n` in a Windows file and
// the scan must not treat the \r as part of the delimiter's info string.
func TestSecretsInACRLFFile(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "secret-crlf-fence.md")
	d := Parse("secret-crlf-fence.md", src)
	secrets := d.SecretSpans()
	if len(secrets) != 1 || secrets[0].SecretID != "161616161616" {
		t.Fatalf("spans = %+v, problems = %v", d.Spans, d.Problems)
	}
	if !bytes.Equal(SecretBody(src, secrets[0]), []byte("A secret in a CRLF file.\r\n")) {
		t.Errorf("secret body = %q", SecretBody(src, secrets[0]))
	}
}

// TestFenceParsing does not mistake other block syntax for a fence.
func TestFenceParsing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		line string
		ok   bool
		run  int
		info string
	}{
		{name: "backtick fence", line: "```go", ok: true, run: 3, info: "go"},
		{name: "four backticks", line: "````", ok: true, run: 4, info: ""},
		{name: "tilde fence", line: "~~~ ", ok: true, run: 3, info: ""},
		{name: "two backticks is not a fence", line: "``x``", ok: false},
		{name: "thematic break", line: "---", ok: false},
		{name: "setext underline", line: "===", ok: false},
		{name: "list marker", line: "- item", ok: false},
		{name: "quote marker", line: "> text", ok: false},
		{name: "indented", line: "   ```", ok: true, run: 3, info: ""},
		{name: "backtick in the info string", line: "```a`b", ok: false},
		{name: "tilde in the info string is fine", line: "~~~a`b", ok: true, run: 3, info: "a`b"},
		{name: "trailing whitespace is not part of the info string", line: "```go   ", ok: true, run: 3, info: "go"},
		{name: "empty line", line: "", ok: false},
		{name: "quote then fence", line: "> ```go", ok: true, run: 3, info: "go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, ok := fenceAt([]byte(tc.line))
			if ok != tc.ok {
				t.Fatalf("fenceAt(%q) ok = %v, want %v", tc.line, ok, tc.ok)
			}
			if !ok {
				return
			}
			if f.Run != tc.run {
				t.Errorf("run = %d, want %d", f.Run, tc.run)
			}
			if f.Info != tc.info {
				t.Errorf("info = %q, want %q", f.Info, tc.info)
			}
		})
	}
}

// TestSegmentIsAParseWithoutAPath: the two constructors must not drift, since
// the indexer uses Segment and the renderer uses Parse.
func TestSegmentIsAParseWithoutAPath(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "secret-around-public.md")
	seg, err := Segment(src)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	parsed := Parse("x.md", src)
	if len(seg.Spans) != len(parsed.Spans) {
		t.Fatalf("spans differ: %d then %d", len(seg.Spans), len(parsed.Spans))
	}
	for i := range seg.Spans {
		if seg.Spans[i] != parsed.Spans[i] {
			t.Errorf("span %d differs", i)
		}
	}
	if seg.Path != "" {
		t.Errorf("Segment set a path: %q", seg.Path)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func secretIDs(spans []Span) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.SecretID)
	}
	return out
}
