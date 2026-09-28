package md

import (
	"bytes"
	"strings"
	"testing"
)

// A ```secret fence is a claim of secrecy. If its directive cannot be
// understood, honouring the claim is the only safe answer.
//
// This is a regression test for a leak, not a style rule. AGENTS.md documents
// the on-disk syntax as `title=<optional>` with no quoting requirement, so an
// author who writes
//
//	```secret id=abc123abc123 visibility=dm author=johan title=The cellar key
//
// has their info string scanned as `title=The` plus two unknown keys, `cellar`
// and `key`. The old response to an unknown key was public passthrough — so the
// fence was demoted and its body was served in plaintext to a player. A
// documentation ambiguity became a secret leak.
//
// The body is not public here, and it is not in the public body either, so it
// cannot reach page_text, page_fts, a snippet, or any rendered HTML.
const leakyBody = "The cellar key is a brass tooth, and the trap kills on turn."

func TestAnUnunderstoodSecretFenceNeverBecomesPublic(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		directive string
	}{
		// The exact shape the documentation invites.
		{"unquoted title with a space", "id=abc123abc123 visibility=dm author=johan title=The cellar key"},
		{"unquoted title with several words", "id=abc123abc123 visibility=private author=johan title=Where the boats come from"},
		{"unknown flag", "id=abc123abc123 rotate=on"},
		{"no id at all plus a flag", "rotate=on"},
		{"duplicate keys", "id=a id=b"},
		{"valueless key", "id=abc123abc123 unexpected="},
		{"unknown visibility value", "id=abc123abc123 visibility=everyone"},
		{"not even key=value", "secret sauce"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := []byte("Public prose.\n\n```secret " + tc.directive + "\n" + leakyBody + "\n```\n\nMore prose.\n")

			d := Parse("leak.md", src)

			// The decisive assertion. A secret span covers the fence, so the
			// body is not in the public body.
			if bytes.Contains(d.PublicBody(), []byte(leakyBody)) {
				t.Fatalf("an unparseable secret fence was demoted to public: public body = %q", d.PublicBody())
			}
			if len(d.SecretSpans()) == 0 {
				t.Fatalf("no secret span: the fence was demoted, spans = %+v problems = %v", d.Spans, d.Problems)
			}
			// The public prose either side survives, so the page is not simply
			// blanked.
			if !bytes.Contains(d.PublicBody(), []byte("Public prose.")) ||
				!bytes.Contains(d.PublicBody(), []byte("More prose.")) {
				t.Errorf("the surrounding public text was lost: %q", d.PublicBody())
			}
			// The problem is still reported, so the sync panel and the DM can
			// see that a fence needs fixing.
			var reported bool
			for _, p := range d.Problems {
				if p.Code == ProblemSecretUnknownKey || p.Code == ProblemSecretBadDirective ||
					p.Code == ProblemSecretBadVisibility || p.Code == ProblemSecretMissingID {
					reported = true
				}
			}
			if !reported {
				t.Errorf("an unparseable directive was reported no problem: %v", d.Problems)
			}
			// The body never reaches the renderer.
			out, err := New(Options{}).RenderDoc(d)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			for _, fragment := range []string{leakyBody, "brass tooth", "trap kills", "cellar key"} {
				if bytes.Contains(out, []byte(fragment)) {
					t.Errorf("fragment %q reached the rendered HTML: %s", fragment, out)
				}
			}
		})
	}
}

// The unparseable fence's span must still carry a usable id, because the index
// and the tripwire key off it. A synthetic, obviously-not-real id is right: it
// cannot collide with a real 12-hex-char secret id, so a re-parse of a corrected
// file produces a different span and the stale one is replaced.
func TestAnUnparseableSecretFenceGetsAnID(t *testing.T) {
	t.Parallel()

	// A fence whose directive is unreadable but which still names a valid id
	// keeps it: the fence is hidden either way, and when the author fixes the
	// directive the same id addresses the same secret, so the recovered secret
	// is the one they wrote.
	t.Run("a stated id is kept", func(t *testing.T) {
		t.Parallel()
		d := Parse("leak.md", []byte("```secret id=abc123abc123 rotate=on\nbody\n```\n"))
		spans := d.SecretSpans()
		if len(spans) != 1 {
			t.Fatalf("spans = %+v, want one secret span", spans)
		}
		if spans[0].SecretID != "abc123abc123" {
			t.Errorf("id = %q, want the id the file stated", spans[0].SecretID)
		}
		if bytes.Contains(d.PublicBody(), []byte("body")) {
			t.Error("the body became public")
		}
	})

	// With no usable id there is nothing to address the fence by, and the index
	// and the tripwire both key on it, so it gets a synthetic one that cannot
	// collide with a real 12-hex-character id.
	t.Run("a missing id is synthesised", func(t *testing.T) {
		t.Parallel()
		d := Parse("leak.md", []byte("```secret rotate=on\nbody\n```\n"))
		spans := d.SecretSpans()
		if len(spans) != 1 {
			t.Fatalf("spans = %+v, want one secret span", spans)
		}
		id := spans[0].SecretID
		if !strings.HasPrefix(id, ProblemUnparsableIDPrefix) {
			t.Errorf("id = %q, want a %s prefix so it cannot be mistaken for a real secret",
				id, ProblemUnparsableIDPrefix)
		}
		if len(id) == 12 {
			t.Errorf("the synthetic id %q is 12 characters, the shape of a real secret id", id)
		}
	})
}

// The whole point, restated: a fence that cannot be understood is hidden, and a
// fence that CAN be understood is shown to whoever may read it. Neither
// direction is allowed to depend on the other.
func TestAWellFormedFenceIsStillASecret(t *testing.T) {
	t.Parallel()
	src := []byte("```secret id=abc123abc123 visibility=dm author=johan title=\"The cellar key\"\n" +
		leakyBody + "\n```\n")
	d := Parse("ok.md", src)

	if len(d.SecretSpans()) != 1 {
		t.Fatalf("a well-formed fence is not a secret: %+v %v", d.Spans, d.Problems)
	}
	if d.SecretSpans()[0].SecretID != "abc123abc123" {
		t.Errorf("id = %q", d.SecretSpans()[0].SecretID)
	}
	if len(d.Problems) != 0 {
		t.Errorf("a well-formed fence reported problems: %v", d.Problems)
	}
}
