package md

import (
	"bytes"
	"strings"
	"testing"
)

// The page an attachment URL is scoped to. It is deliberately nested: a relative
// address that works for a page at the vault root is exactly what is wrong for
// one three directories down, so a test that only used a root path could not
// tell the two apart.
const scopePage = "notes/Deep/Wardens.md"

func scopeSrc(t *testing.T, body string) string {
	t.Helper()
	d := Parse(scopePage, []byte(body))
	out, err := New(Options{}).RenderDoc(d)
	if err != nil {
		t.Fatalf("render %q: %v", body, err)
	}
	return string(out)
}

func TestAnAttachmentIsAddressedAtThePageThatReferencesIt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{"a wikilink embed", "![[assets/harbour.png]]\n", "assets/harbour.png"},
		{"a wikilink", "[[assets/harbour.png]]\n", "assets/harbour.png"},
		// The markdown-native forms never reach the wikilink resolver at all, so
		// a fix that lived in the resolver would leave these two broken. They are
		// here because the bug this pins shipped with all three forms broken and
		// the first two are the ones a reader notices.
		{"a markdown image", "![the map](assets/harbour.png)\n", "assets/harbour.png"},
		{"a markdown link", "[the map](assets/harbour.png)\n", "assets/harbour.png"},
		{"a name at the vault root", "![[portrait.png]]\n", "portrait.png"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := scopeSrc(t, tc.body)
			want := "/p/" + scopePage + "/attachment/" + tc.want
			if !strings.Contains(out, `src="`+want+`"`) && !strings.Contains(out, `href="`+want+`"`) {
				t.Errorf("the rendered page does not address the attachment at %q:\n%s", want, out)
			}
			// The relative form is the bug, and a page whose body is scoped
			// correctly while something else in the output kept the relative
			// reference would still be a broken image in a browser.
			if strings.Contains(out, `src="`+tc.want+`"`) || strings.Contains(out, `href="`+tc.want+`"`) {
				t.Errorf("the rendered page still carries a relative reference to %q:\n%s", tc.want, out)
			}
		})
	}
}

func TestScopingLeavesEverythingThatIsNotAnAttachmentAlone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		// A page keeps /p/ and gains no attachment segment.
		{"a page wikilink", "[[Wardens]]\n", `href="/p/Wardens"`},
		// The fragment is space-encoded on the way into the attribute. That is
		// correct and is not this file's decision to make either way.
		{"a page wikilink with a fragment", "[[Wardens#The door]]\n", `href="/p/Wardens#The%20door"`},
		// A destination carrying a URI scheme is not ours and is left exactly as
		// the author wrote it. These three used to expect an /p/ prefix, which was
		// the wrong answer twice over: an external link was addressed inside the
		// vault, and `javascript:` stopped being recognisable as a scheme, so
		// goldmark's stripping of a dangerous href stopped happening and a link
		// that had been inert became one the page carried. Leaving them alone
		// hands the decision to the only component that knows which schemes are
		// dangerous.
		{"an https url", "[[https://example.invalid/a.png]]\n", `href="https://example.invalid/a.png"`},
		{"a mailto", "[[mailto:x@y.invalid]]\n", `href="mailto:x@y.invalid"`},
		// An image data URI is inert and passes through. The dangerous sibling —
		// data:text/html — is goldmark's to strip, and is not this file's to
		// assert: TestXSSFixturesAreEscaped in internal/httpapi pins it, and a
		// second expectation of it here would be a second place to be wrong about
		// which schemes are dangerous.
		{"a data uri", "[[data:image/png;base64,AAAA]]\n", `href="data:image/png;base64,AAAA"`},
		// An author who wrote a rooted path has answered the question themselves.
		{"an already rooted name", "![[/vault/root/map.png]]\n", `src="/vault/root/map.png"`},
		// A reference that climbs out of the directory it is written in has no
		// address here, and inventing one would be a link the author never wrote.
		{"a climbing reference", "[up](../outside.md)\n", `href="../outside.md"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := scopeSrc(t, tc.body)
			if !strings.Contains(out, tc.want) {
				t.Errorf("the rendered page does not carry %s:\n%s", tc.want, out)
			}
			if strings.Contains(out, attachmentURLPrefix) {
				t.Errorf("a non-file reference was sent to an attachment route:\n%s", out)
			}
		})
	}
}

// TestAnAttachmentNameIsEncodedOnce pins the encoding against the most likely
// way to break it. The name is left raw on purpose because goldmark escapes the
// attribute it writes; a "helpful" pre-encoding in the rewriter would produce
// Caf%25C3%25A9.png, which is a 404 with no error anywhere.
func TestAnAttachmentNameIsEncodedOnce(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string
	}{
		{"a space", "![[a b.png]]\n", "a%20b.png"},
		{"a non-ascii name", "![[Café.png]]\n", "Caf%C3%A9.png"},
		{"a percent", "![[50%.png]]\n", "50%25.png"},
		{"a quote", "![[o\"brien.png]]\n", "o%22brien.png"},
		// A single quote is left literal, and that is right rather than a missed
		// case: the attribute is double-quoted, so it cannot be escaped by one.
		// The case is here so that a future "encode everything" change is visible
		// as a diff rather than as a surprise.
		{"a single quote", "![[o'brien.png]]\n", "o'brien.png"},
		{"an angle bracket", "![[a<b.png]]\n", "a%3Cb.png"},
		// A traversal is scoped rather than dropped: the decision that it is not
		// servable belongs to the route, which proves it there, and a rewriter
		// that silently swallowed a name would hide a file the author can see in
		// Obsidian.
		{"a traversal", "![[../escape.png]]\n", "/attachment/../escape.png"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := scopeSrc(t, tc.body)
			if !strings.Contains(out, tc.want) {
				t.Errorf("the rendered page does not carry %q:\n%s", tc.want, out)
			}
			// A name that broke out of the attribute would end the tag early,
			// so the rendered element is checked as well as the fragment.
			if i := strings.Index(out, "<img"); i >= 0 {
				if j := strings.IndexByte(out[i:], '>'); j > 0 && !strings.Contains(out[i:i+j], "src=") {
					t.Errorf("the img tag lost its src, so the name escaped the attribute:\n%s", out)
				}
			}
		})
	}
}

// TestAFenceBodyIsNeverScoped is the half of the rule that is a security
// property rather than a convenience. A secret's body never reaches the
// renderer as Markdown — PublicBody excludes it, and the page view shows it as
// source — so nothing inside a fence is an attachment reference to scope. If a
// future change ever renders a secret body, this is the assertion that says the
// scoping did not turn a hidden name into a served one.
func TestAFenceBodyIsNeverScoped(t *testing.T) {
	t.Parallel()
	src := "![[visible.png]]\n\n```secret id=a1a1a1a1a1a1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"x\"\n![[hidden.png]]\n```\n"
	d := Parse("Page.md", []byte(src))
	body := d.PublicBody()
	if bytes.Contains(body, []byte("hidden.png")) {
		t.Fatal("the public body carries a secret's body, so this test would prove nothing")
	}
	out, err := New(Options{}).RenderDoc(d)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// The visible reference is scoped, and the hidden name appears nowhere at
	// all — not scoped, not raw, not as a lock, because a secret's body is not
	// rendered and there is nothing here to redraw.
	if !strings.Contains(string(out), "/attachment/visible.png") {
		t.Errorf("the public reference was not scoped:\n%s", out)
	}
	if strings.Contains(string(out), "hidden.png") {
		t.Errorf("a name referenced only inside a secret reached the page:\n%s", out)
	}
}

// TestASchemeBearingDestinationIsNeverRewritten is the property the
// implementation almost broke, and it is here because the test that caught it
// lives two packages away in an HTTP-level XSS walk.
//
// A destination that already looks like a URI must come out of the renderer
// byte-identical. Rewriting one — even by prefixing the /p/ root — destroys the
// thing goldmark looks at: it decides whether a scheme is dangerous by the shape
// of the destination, so `/p/javascript:alert(1)` is no longer a scheme at all
// and the href is emitted intact. The link goes from inert to carried.
//
// Every scheme is in scope and none is listed here, because a list is what made
// this wrong: an earlier version enumerated mailto, tel and data, and
// javascript: was the one that was missing.
func TestASchemeBearingDestinationIsNeverRewritten(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{
		"https://example.invalid/a.png",
		"mailto:x@y.invalid",
		"data:image/png;base64,AAAA",
		"javascript:alert(1)",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"JAVASCRIPT:alert(1)",
	} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			for _, body := range []string{
				"[[" + scheme + "]]\n",
				"[" + scheme + "](" + scheme + ")\n",
				"![" + scheme + "](" + scheme + ")\n",
			} {
				out := scopeSrc(t, body)
				if !strings.Contains(out, scheme) {
					t.Errorf("%q was rewritten rather than passed through:\n%s", body, out)
				}
				if strings.Contains(out, pageURLPrefix+scheme) {
					t.Errorf("%q was given the /p/ root, so a scheme-shaped destination stopped being one:\n%s", body, out)
				}
			}
		})
	}
}

// TestARenderWithNoPageKeepsItsReferences is the guard on the rewriter's
// blast radius. Render has no page to scope to, so it must behave exactly as it
// did before scoping existed; a rewriter that guessed a page would put a
// broken URL on every caller that has none.
func TestARenderWithNoPageKeepsItsReferences(t *testing.T) {
	t.Parallel()
	out, err := New(Options{}).Render([]byte("![[assets/harbour.png]]\n"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(out), `src="assets/harbour.png"`) {
		t.Errorf("Render changed a relative reference with no page to scope it to:\n%s", out)
	}
}
