package md

import (
	"bytes"
	"strings"
	"testing"
)

// The bulk updater's tests. Every one is about which bytes move: a rename that
// reflows a line, swallows a fragment or reaches into a secret is a DM's prose
// changed by something they never asked for.

func TestRewriteLinksIsBytePreserving(t *testing.T) {
	t.Parallel()
	// The golden case. Every shape the rewriter has to leave alone is in this
	// one file: a self-reference, a link whose basename matches but whose path
	// does not, a link inside a secret, a link wrapped across a line, trailing
	// whitespace, and four ways of spelling a fragment.
	src := loadFixture(t, "link-rename.md")
	d := Parse("links/link-rename.md", src)
	facts, _ := Extract(d, nil)

	edits := LinkEdits(d, facts, "Gundren", "Gundren Redrake")
	if len(edits) != 5 {
		t.Fatalf("edits = %d, want the five public references to Gundren: %+v", len(edits), edits)
	}
	got, problems := RewriteLinks(d, edits)
	assertNoProblems(t, problems)

	want := "# Links around a secret\n" +
		"\n" +
		"A [[Gundren Redrake]] and a [[Gundren Redrake#Flaws|flaws]] and a ![[Gundren Redrake#^d8f1a2]] and a\n" +
		"[markdown](Gundren Redrake.md) and a [[#Local heading]] and a [[Other/Gundren]].\n" +
		"\n" +
		"```secret id=abcdef012345\n" +
		"A [[Gundren]] that only the DM may read.\n" +
		"```\n" +
		"\n" +
		"And a [[Gundren Redrake]] after the secret.   " + "\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("the rewrite is not byte-exact:\n%s", firstDifference([]byte(want), got))
	}
	// The self-reference and the same-basename link are not touched, and
	// neither is anything inside the secret.
	if !bytes.Contains(got, []byte("[[#Local heading]]")) {
		t.Error("a self-reference was rewritten")
	}
	if !bytes.Contains(got, []byte("[[Other/Gundren]]")) {
		t.Error("a link with a matching basename and a different path was rewritten")
	}
	if !bytes.Contains(got, []byte("A [[Gundren]] that only the DM may read.")) {
		t.Error("a link inside a secret was rewritten")
	}
}

func TestRewriteLinksRefusesAStaleOffset(t *testing.T) {
	t.Parallel()
	src := []byte("A [[Gundren]] here.\n")
	for name, tc := range map[string]struct {
		edits []LinkEdit
		want  string
		// out is the file the rewriter should produce; empty means unchanged.
		out string
	}{
		"bytes that are not the recorded target": {
			edits: []LinkEdit{{Offset: 4, Length: 7, Want: "Gundres", With: "Gundren Redrake"}},
			want:  ProblemLinkStale,
		},
		"a range one byte off": {
			edits: []LinkEdit{{Offset: 3, Length: 7, Want: "Gundren", With: "Gundren Redrake"}},
			want:  ProblemLinkStale,
		},
		"a range past the end of the file": {
			edits: []LinkEdit{{Offset: 40, Length: 7, Want: "Gundren", With: "Gundren Redrake"}},
			want:  ProblemLinkOutOfRange,
		},
		"a negative offset": {
			edits: []LinkEdit{{Offset: -1, Length: 7, Want: "Gundren", With: "Gundren Redrake"}},
			want:  ProblemLinkOutOfRange,
		},
		"a length that runs off the end": {
			edits: []LinkEdit{{Offset: 4, Length: 400, Want: "Gundren", With: "Gundren Redrake"}},
			want:  ProblemLinkOutOfRange,
		},
		"a negative length": {
			edits: []LinkEdit{{Offset: 4, Length: -7, Want: "Gundren", With: "Gundren Redrake"}},
			want:  ProblemLinkOutOfRange,
		},
		"two edits over the same bytes": {
			edits: []LinkEdit{
				{Offset: 4, Length: 7, Want: "Gundren", With: "Gundren Redrake"},
				{Offset: 4, Length: 7, Want: "Gundren", With: "Something Else"},
			},
			want: ProblemLinkOverlap,
			// The first of two identical edits is not itself a conflict; the
			// second is, and the one that survives is the one that was written
			// first.
			out: "A [[Gundren Redrake]] here.\n",
		},
		"an edit inside another one": {
			edits: []LinkEdit{
				{Offset: 4, Length: 9, Want: "Gundren]]", With: "Gundren Redrake]"},
				{Offset: 6, Length: 3, Want: "ndr", With: "XYZ"},
			},
			want: ProblemLinkOverlap,
			out:  "A [[Gundren Redrake] here.\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("page.md", src)
			got, problems := RewriteLinks(d, tc.edits)
			if len(problems) != 1 || problems[0].Code != tc.want {
				t.Fatalf("problems = %v, want one %s", problems, tc.want)
			}
			want := src
			if tc.out != "" {
				want = []byte(tc.out)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("rewrite = %q, want %q", got, want)
			}
		})
	}
}

// TestRewriteLinksAppliesTheNonOverlappingEditsAroundAConflict: one bad
// occurrence is reported and the rest of the page is still updated. §5.6 step 6
// is explicit that a failure on one occurrence does not abort the others, and a
// rewriter that gave up on the whole file would report a conflict as a failed
// rename.
func TestRewriteLinksAppliesTheNonOverlappingEditsAroundAConflict(t *testing.T) {
	t.Parallel()
	src := []byte("[[Gundren]] and [[Gundren]] and [[Gundren]]\n")
	d := Parse("page.md", src)
	got, problems := RewriteLinks(d, []LinkEdit{
		{Offset: 2, Length: 7, Want: "Gundren", With: "Gundren Redrake"},
		{Offset: 19, Length: 7, Want: "Gundren", With: "Gundren Redrake"},
		{Offset: 34, Length: 7, Want: "Gundren", With: "Gundren Redrake"},
	})
	if len(problems) != 1 || problems[0].Code != ProblemLinkStale {
		t.Fatalf("problems = %v, want one %s", problems, ProblemLinkStale)
	}
	want := "[[Gundren Redrake]] and [[Gundren]] and [[Gundren Redrake]]\n"
	if string(got) != want {
		t.Errorf("rewrite = %q, want %q", got, want)
	}
}

// TestRewriteLinksNamesThePageAndTheLine: §5.6's response reports every page
// with a reason, and a reason a user cannot locate is a reason they cannot act
// on.
func TestRewriteLinksNamesThePageAndTheLine(t *testing.T) {
	t.Parallel()
	src := []byte("one\ntwo\nthree [[Gundren]]\n")
	d := Parse("Party/Tavern.md", src)
	// One byte off the target, so the edit is a conflict rather than a change:
	// the name has to be attached to a refusal as much as to a write.
	got, problems := RewriteLinks(d, []LinkEdit{{Offset: 15, Length: 7, Want: "Gundren", With: "X"}})
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want one", problems)
	}
	p := problems[0]
	if p.Path != "Party/Tavern.md" {
		t.Errorf("Path = %q, want the page it is about", p.Path)
	}
	if p.Line != 3 {
		t.Errorf("Line = %d, want 3", p.Line)
	}
	if p.StartByte != 15 {
		t.Errorf("StartByte = %d, want 15", p.StartByte)
	}
	if !strings.Contains(p.Error(), "Party/Tavern.md") || !strings.Contains(p.Error(), "line 3") {
		t.Errorf("the error does not locate the problem: %q", p.Error())
	}
	// A message is lowercase and carries no document content: the target is not
	// repeated in it, because the target is the very text a rename is moving.
	if p.Message != strings.ToLower(p.Message) || strings.Contains(p.Message, "Gundren") {
		t.Errorf("the message is %q", p.Message)
	}
	if !bytes.Equal(got, src) {
		t.Error("a refused edit still changed the file")
	}
}

func TestRewriteLinksKeepsHeadingAndBlockFragments(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ in, from, to, want string }{
		"a heading": {
			in: "See [[Old Name#The Cellar]] today.\n", from: "Old Name", to: "New Name",
			want: "See [[New Name#The Cellar]] today.\n",
		},
		"a block reference": {
			in: "See ![[Old Name#^d8f1a2]] today.\n", from: "Old Name", to: "New Name",
			want: "See ![[New Name#^d8f1a2]] today.\n",
		},
		"a heading and an alias": {
			in: "See [[Old Name#The Cellar|the cellar]] today.\n", from: "Old Name", to: "New Name",
			want: "See [[New Name#The Cellar|the cellar]] today.\n",
		},
		"a block reference and an alias": {
			in: "See [[Old Name#^d8f1a2|a note]] today.\n", from: "Old Name", to: "New Name",
			want: "See [[New Name#^d8f1a2|a note]] today.\n",
		},
		"a heading with spaces": {
			in: "See [[Old Name#Two Words In It]] today.\n", from: "Old Name", to: "New Name",
			want: "See [[New Name#Two Words In It]] today.\n",
		},
		"a markdown link with a title": {
			in: "See [the cellar](Old-Name.md \"A door\") today.\n", from: "Old-Name.md", to: "New-Name",
			want: "See [the cellar](New-Name.md \"A door\") today.\n",
		},
		"a wikilink written with its extension": {
			in: "See [[Old Name.md]] today.\n", from: "Old Name.md", to: "New Name",
			want: "See [[New Name.md]] today.\n",
		},
		"a lowercase reference to a capitalised page": {
			in: "See [[old name]] today.\n", from: "old name", to: "New Name",
			want: "See [[New Name]] today.\n",
		},
		"a path-qualified reference": {
			in: "See [[Party/Old Name#Cellar]] today.\n", from: "Party/Old Name", to: "Party/New Name",
			want: "See [[Party/New Name#Cellar]] today.\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("page.md", []byte(tc.in))
			facts, _ := Extract(d, nil)
			edits := LinkEdits(d, facts, tc.from, tc.to)
			if len(edits) != 1 {
				t.Fatalf("edits = %+v, want exactly one", edits)
			}
			got, problems := RewriteLinks(d, edits)
			assertNoProblems(t, problems)
			if string(got) != tc.want {
				t.Errorf("rewrite = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLinkEditsSkipsSecrets is the security property of the whole rewriter: a
// link inside a secret is never a rewrite target, so no caller can use a rename
// to touch bytes it may not read, and no page's redaction can be moved by a
// bulk operation. The exclusion is by byte range, not by a permission the
// caller passed in, because a caller that could name the range could name any.
func TestLinkEditsSkipsSecrets(t *testing.T) {
	t.Parallel()
	src := []byte("Public [[Gundren]] here.\n\n" +
		"```secret id=abcdef012345\nDM [[Gundren]] and a [[Other#Section]] too.\n```\n\n" +
		"More [[Gundren]].\n")
	d := Parse("page.md", src)
	secret := spanMustFind(t, src, "abcdef012345")
	facts, _ := Extract(d, nil)

	edits := LinkEdits(d, facts, "Gundren", "Gundren Redrake")
	if len(edits) != 2 {
		t.Fatalf("edits = %+v, want the two public references only", edits)
	}
	for _, e := range edits {
		if secret.StartByte <= e.Offset && e.Offset < secret.EndByte {
			t.Errorf("edit at %d falls inside the secret span [%d, %d)", e.Offset, secret.StartByte, secret.EndByte)
		}
	}
	// And the file says so, not just the edit list.
	got, problems := RewriteLinks(d, edits)
	assertNoProblems(t, problems)
	if !bytes.Contains(got, []byte("DM [[Gundren]] and a [[Other#Section]] too.")) {
		t.Errorf("the secret's bytes were rewritten: %s", firstDifference(src, got))
	}
	if strings.Count(string(got), "Gundren Redrake") != 2 {
		t.Errorf("the public references were not rewritten: %q", got)
	}
	// The guarantee is on the builder, because the builder is the only place
	// that knows what the document is. RewriteLinks is a byte tool: it will
	// apply any range whose bytes match, which is what makes a stale record
	// harmless and also what makes an unexcluded secret writable. So the
	// property to assert is that no range it produces touches one.
	for _, e := range edits {
		for _, s := range d.SecretSpans() {
			if s.SecretID != "" && s.StartByte < e.Offset+e.Length && e.Offset < s.EndByte {
				t.Errorf("edit [%d, %d) intersects secret %s", e.Offset, e.Offset+e.Length, s.SecretID)
			}
		}
	}
	// And the same for a link found inside a secret: the range is recorded, and
	// the builder skips it anyway. That is the shape the property has to hold
	// in — the exclusion is a decision LinkEdits makes with the span list in
	// hand, not an accident of the extractor having nothing to rewrite.
	for _, l := range facts.Links {
		if l.Span.SecretID == "" {
			continue
		}
		if l.TargetEnd <= l.TargetStart {
			t.Errorf("a link inside secret %s has no recorded target range", l.Span.SecretID)
			continue
		}
		if !(secret.StartByte <= l.TargetStart && l.TargetStart < secret.EndByte) {
			t.Errorf("a link attributed to secret %s points at [%d, %d), which is not inside it",
				l.Span.SecretID, l.TargetStart, l.TargetEnd)
		}
	}
}

func TestLinkEditsMatchingRule(t *testing.T) {
	t.Parallel()
	src := []byte("[[Tavern]] [[tavern]] [[Party/Tavern]] [[Tavern.md]] [[#Anchor]] " +
		"![[drawing.png]] [x](https://example.invalid/) [y](Tavern.md) #Tavern\n")
	d := Parse("page.md", src)
	facts, _ := Extract(d, nil)

	for name, tc := range map[string]struct {
		from string
		want int
	}{
		"the exact spelling":                 {"Tavern", 4},
		"a different case":                   {"TAVERN", 4},
		"with the extension":                 {"Tavern.md", 4},
		"a path, which matches nothing here": {"Other/Tavern", 0},
		"an empty name":                      {"", 0},
		"a name nothing uses":                {"Cellar", 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := LinkEdits(d, facts, tc.from, "The Inn")
			if len(got) != tc.want {
				t.Errorf("edits = %d, want %d: %+v", len(got), tc.want, got)
			}
		})
	}

	// An embed of an image and an external link are not page references, so no
	// rename moves them however they are spelled.
	for _, e := range LinkEdits(d, facts, "Tavern", "The Inn") {
		if bytes.Contains([]byte(e.With), []byte(".png")) {
			t.Errorf("an attachment was rewritten: %+v", e)
		}
	}
}

func TestLinkEditsAreVerifiableAgainstTheFile(t *testing.T) {
	t.Parallel()
	// Every edit the builder produces must name bytes that are actually there.
	// A wrong offset produces an edit that RewriteLinks reports as a conflict
	// and refuses, so a rename over a page with a bad offset would silently
	// update nothing — which is the safe failure, and also a bug worth failing
	// a test over.
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		if len(src) > renderSizeLimit {
			continue
		}
		d := Parse("links/"+name, src)
		facts, _ := Extract(d, nil)
		if len(facts.Links) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, l := range facts.Links {
				switch l.Kind {
				case LinkWikilink, LinkEmbed, LinkMarkdown:
				default:
					// An attachment or a tag names a file, not a page, and a
					// rename of a page is not a rename of a file.
					continue
				}
				if l.Target == "" || l.SelfLink {
					continue
				}
				edits := LinkEdits(d, facts, l.Target, "zz-renamed-target-zz")
				if len(edits) == 0 {
					t.Errorf("link %q at %d produced no edit for its own target", l.TargetRaw, l.Offset)
					continue
				}
				for _, e := range edits {
					if e.Offset+e.Length > len(d.Bytes) {
						t.Fatalf("edit [%d, %d) is outside a %d byte file", e.Offset, e.Offset+e.Length, len(d.Bytes))
					}
					if got := string(d.Bytes[e.Offset : e.Offset+e.Length]); got != e.Want {
						t.Errorf("edit wants %q but the file holds %q at %d", e.Want, got, e.Offset)
					}
					if e.With == e.Want {
						t.Errorf("edit at %d replaces a token with itself", e.Offset)
					}
				}
				if _, problems := RewriteLinks(d, edits); len(problems) > 0 {
					t.Errorf("the rewriter rejected the builder's own edits: %v", problems)
				}
			}
		})
	}
}

// TestLinkTargetRangeIsTheTokenNotTheNode: the range a rename moves is the
// target alone. goldmark hands back the node's first text child, which is the
// alias for a link that has one and the fragment for a link that has one, so a
// range derived from the node's offset would replace the wrong bytes.
func TestLinkTargetRangeIsTheTokenNotTheNode(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ in, target string }{
		"a plain wikilink":          {"See [[Old Name]] here.\n", "Old Name"},
		"a heading fragment":        {"See [[Old Name#Cellar]].\n", "Old Name"},
		"an alias":                  {"See [[Old Name|cellar]].\n", "Old Name"},
		"a fragment and an alias":   {"See [[Old Name#Cellar|cellar]].\n", "Old Name"},
		"an embed":                  {"See ![[Old Name#^abc]].\n", "Old Name"},
		"a markdown link":           {"See [cellar](Old-Name.md).\n", "Old-Name.md"},
		"a label with brackets":     {"See [a [b] c](Old-Name.md).\n", "Old-Name.md"},
		"a second link on one line": {"See [[One]] and [two](Three.md).\n", "Three.md"},
		"an embed of an attachment": {"See ![[portrait.png]].\n", "portrait.png"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("page.md", []byte(tc.in))
			facts, _ := Extract(d, nil)
			// The last link is the one this case is about, so a case with more
			// than one reference in it does not need a separate shape.
			if len(facts.Links) == 0 {
				t.Fatalf("no link was found in %q", tc.in)
			}
			l := facts.Links[len(facts.Links)-1]
			if l.TargetEnd <= l.TargetStart {
				t.Fatalf("no target range was located for %q", l.TargetRaw)
			}
			if got := string(d.Bytes[l.TargetStart:l.TargetEnd]); got != tc.target {
				t.Errorf("target range = %q, want %q", got, tc.target)
			}
		})
	}
}

// TestLinkTargetRangeIsLeftUnlocatedWhenItCannotBeVerified: a destination
// written with escapes or in angle brackets is not the same string as the one
// the parser read, so the range is not recorded and the link is not rewritten.
// Guessing which of the two the author meant is not a decision this package
// makes.
func TestLinkTargetRangeIsLeftUnlocatedWhenItCannotBeVerified(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"an escaped destination": "See [cellar](Old\\ Name.md).\n",
		"an angled destination":  "See [cellar](<Old Name.md>).\n",
		"a percent-encoded one":  "See [cellar](Old%20Name.md).\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse("page.md", []byte(in))
			facts, _ := Extract(d, nil)
			if len(facts.Links) == 0 {
				t.Skip("the destination did not parse as a link at all")
			}
			if got := LinkEdits(d, facts, "Old Name", "New Name"); len(got) != 0 {
				t.Errorf("edits = %+v, want none", got)
			}
		})
	}
}

func TestLinkEditsWithNothingToDo(t *testing.T) {
	t.Parallel()
	d := Parse("page.md", []byte("A [[Gundren]].\n"))
	facts, _ := Extract(d, nil)
	for name, got := range map[string][]LinkEdit{
		"a nil document":        LinkEdits(nil, facts, "Gundren", "X"),
		"an empty from":         LinkEdits(d, facts, "", "X"),
		"an empty to":           LinkEdits(d, facts, "Gundren", ""),
		"no facts":              LinkEdits(d, Extracted{}, "Gundren", "X"),
		"the same name":         LinkEdits(d, facts, "Gundren", "Gundren"),
		"only a bare extension": LinkEdits(d, facts, "Gundren", "Gundren.md"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(got) != 0 {
				t.Errorf("edits = %+v, want none", got)
			}
		})
	}
}
