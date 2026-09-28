package md

import (
	"strings"
	"testing"

	"github.com/yuin/goldmark/ast"
	"go.abhg.dev/goldmark/hashtag"
	"go.abhg.dev/goldmark/wikilink"
)

// TestExtractFacts is the table for the extractor. Every case states what the
// index is supposed to contain, because the index is what search, backlinks
// and the table of contents all read, and a fact that is missing from it is a
// fact no feature can find.
func TestExtractFacts(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	cases := []struct {
		name      string
		path      string
		src       string
		title     string
		pageType  string
		aliases   []string
		tags      []string
		links     []Link
		headings  []Heading
		attach    []string
		languages []string
	}{
		{
			name: "title from the first H1",
			src:  "# The Title\n\nBody.\n\n## Section\n",
			// The first H1 wins, and a later H1 does not replace it.
			title:    "The Title",
			pageType: DefaultPageType,
			headings: []Heading{{Level: 1, Text: "The Title", Slug: "the-title", Ordinal: 1}, {Level: 2, Text: "Section", Slug: "section", Ordinal: 2}},
		},
		{
			name:     "title from frontmatter when there is no H1",
			path:     "notes/x.md",
			src:      "---\ntitle: From Frontmatter\n---\n\nBody.\n",
			title:    "From Frontmatter",
			pageType: DefaultPageType,
		},
		{
			name:     "title from the basename as a last resort",
			path:     "Party/Night at the Tavern.md",
			src:      "No heading and no title.\n",
			title:    "Night at the Tavern",
			pageType: DefaultPageType,
		},
		{
			name:     "the H1 wins over the frontmatter title",
			src:      "---\ntitle: Ignored\n---\n\n# The Heading\n",
			title:    "The Heading",
			pageType: DefaultPageType,
			headings: []Heading{{Level: 1, Text: "The Heading", Slug: "the-heading", Ordinal: 1}},
		},
		{
			name:     "page type from frontmatter",
			src:      "---\ntype: npc\n---\n\n# N\n",
			title:    "N",
			pageType: "npc",
			headings: []Heading{{Level: 1, Text: "N", Slug: "n", Ordinal: 1}},
		},
		{
			name:     "aliases from either spelling",
			src:      "---\naliases:\n  - One\n  - Two\nalias: Three\n---\n\n# A\n",
			title:    "A",
			pageType: DefaultPageType,
			aliases:  []string{"One", "Two", "Three"},
			headings: []Heading{{Level: 1, Text: "A", Slug: "a", Ordinal: 1}},
		},
		{
			name: "tags from frontmatter and inline, normalised and deduplicated",
			// `#Both` is a tag, not a heading: there is no space after the #.
			src:      "---\ntags:\n  - FromFrontmatter\n  - shared\n---\n\n#Both #only-inline #shared\n",
			title:    "",
			pageType: DefaultPageType,
			tags:     []string{"fromfrontmatter", "shared", "both", "only-inline"},
		},
		{
			name: "every link form",
			src: "[[Gundren]] [[Party/Tavern|their table]] [[Gundren#Flaws]] " +
				"![[Gundren]] ![[portrait.png]] [[Gundren#^d8f1a2]] [[#Here]]\n",
			title:    "",
			pageType: DefaultPageType,
			links: []Link{
				{Kind: LinkWikilink, TargetRaw: "Gundren", Target: "Gundren", Line: 1},
				{Kind: LinkWikilink, TargetRaw: "Party/Tavern", Target: "Party/Tavern", Alias: "their table", Line: 1},
				{Kind: LinkWikilink, TargetRaw: "Gundren#Flaws", Target: "Gundren", Heading: "Flaws", Line: 1},
				{Kind: LinkEmbed, TargetRaw: "Gundren", Target: "Gundren", Line: 1},
				{Kind: LinkAttachment, TargetRaw: "portrait.png", Target: "portrait.png", Line: 1},
				{Kind: LinkWikilink, TargetRaw: "Gundren#^d8f1a2", Target: "Gundren", BlockRef: "d8f1a2", Line: 1},
				{Kind: LinkWikilink, TargetRaw: "#Here", Target: "", Heading: "Here", SelfLink: true, Line: 1},
			},
			attach: []string{"portrait.png"},
		},
		{
			name:     "markdown links",
			src:      "[Gundren](Gundren.md) [the map](media/vault.png) [x](https://example.invalid)\n",
			title:    "",
			pageType: DefaultPageType,
			links: []Link{
				{Kind: LinkMarkdown, TargetRaw: "Gundren.md", Target: "Gundren", Alias: "Gundren", Line: 1},
				{Kind: LinkAttachment, TargetRaw: "media/vault.png", Target: "media/vault.png", Alias: "the map", Line: 1},
				{Kind: LinkMarkdown, TargetRaw: "https://example.invalid", Target: "https://example.invalid", Alias: "x", Line: 1},
			},
			attach: []string{"media/vault.png"},
		},
		{
			name:     "a heading with punctuation, spaces and a duplicate",
			src:      "# What's In A Name?!\n\n## What's In A Name?!\n\n### what's in a name?\n",
			title:    "What's In A Name?!",
			pageType: DefaultPageType,
			headings: []Heading{
				{Level: 1, Text: "What's In A Name?!", Slug: "whats-in-a-name", Ordinal: 1},
				{Level: 2, Text: "What's In A Name?!", Slug: "whats-in-a-name-1", Ordinal: 2},
				{Level: 3, Text: "what's in a name?", Slug: "whats-in-a-name-2", Ordinal: 3},
			},
		},
		{
			name:     "an ATX heading's closing hashes are not its text",
			src:      "# The Title #\n\n## Also ##\n",
			title:    "The Title",
			pageType: DefaultPageType,
			headings: []Heading{
				{Level: 1, Text: "The Title", Slug: "the-title", Ordinal: 1},
				{Level: 2, Text: "Also", Slug: "also", Ordinal: 2},
			},
		},
		{
			name:     "a setext heading",
			src:      "Setext Title\n==============\n",
			title:    "Setext Title",
			pageType: DefaultPageType,
			headings: []Heading{{Level: 1, Text: "Setext Title", Slug: "setext-title", Ordinal: 1}},
		},
		{
			name:      "code fence languages, deduplicated in first-appearance order",
			src:       "```go\na\n```\n\n```python\nb\n```\n\n```go\nc\n```\n\n```\nd\n```\n",
			title:     "",
			pageType:  DefaultPageType,
			languages: []string{"go", "python"},
		},
		{
			name:     "links inside a code fence are not links",
			src:      "```\n[[NotALink]] #notag\n```\n",
			title:    "",
			pageType: DefaultPageType,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := Extract(Parse(tc.path, []byte(tc.src)), r)

			if got.Title != tc.title {
				t.Errorf("title = %q, want %q", got.Title, tc.title)
			}
			if got.PageType != tc.pageType {
				t.Errorf("page type = %q, want %q", got.PageType, tc.pageType)
			}
			if !sameStrings(got.Aliases, nonNil(tc.aliases)) {
				t.Errorf("aliases = %q, want %q", got.Aliases, tc.aliases)
			}
			var tagNames []string
			for _, tag := range got.Tags {
				tagNames = append(tagNames, tag.Name)
				if strings.Contains(tag.Name, "#") {
					t.Errorf("tag %q still has a #", tag.Name)
				}
			}
			if !sameStrings(tagNames, nonNil(tc.tags)) {
				t.Errorf("tags = %q, want %q", tagNames, tc.tags)
			}
			if len(got.Links) != len(tc.links) {
				t.Fatalf("links = %+v, want %d of them", got.Links, len(tc.links))
			}
			for i, want := range tc.links {
				have := got.Links[i]
				if have.Kind != want.Kind || have.TargetRaw != want.TargetRaw ||
					have.Target != want.Target || have.Alias != want.Alias ||
					have.Heading != want.Heading || have.BlockRef != want.BlockRef ||
					have.SelfLink != want.SelfLink || have.Line != want.Line {
					t.Errorf("link %d =\n %+v\nwant\n %+v", i, have, want)
				}
			}
			if len(got.Headings) != len(tc.headings) {
				t.Fatalf("headings = %+v, want %d of them", got.Headings, len(tc.headings))
			}
			for i, want := range tc.headings {
				have := got.Headings[i]
				if have.Level != want.Level || have.Text != want.Text ||
					have.Slug != want.Slug || have.Ordinal != want.Ordinal {
					t.Errorf("heading %d =\n %+v\nwant\n %+v", i, have, want)
				}
			}
			var attachNames []string
			for _, a := range got.Attachments {
				attachNames = append(attachNames, a.Name)
			}
			if !sameStrings(attachNames, nonNil(tc.attach)) {
				t.Errorf("attachments = %q, want %q", attachNames, tc.attach)
			}
			if !sameStrings(got.CodeLanguages, nonNil(tc.languages)) {
				t.Errorf("code languages = %q, want %q", got.CodeLanguages, tc.languages)
			}
		})
	}
}

// TestExtractAttributesFactsToTheirSecret is the reason the extractor walks the
// whole body rather than the public one. A heading or a link found inside a
// secret has to come out carrying that secret's id, because the alternative is
// an index that either hides a fact nobody can see or shows a fact everybody
// should not.
func TestExtractAttributesFactsToTheirSecret(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	src := "# Public\n\n[[PublicLink]]\n\n" +
		"```secret id=abc123abc123\n# Secret Heading\n\n[[SecretLink]]\n```\n\n" +
		"## After\n"
	got, _ := Extract(Parse("x.md", []byte(src)), r)

	if len(got.Headings) != 3 {
		t.Fatalf("headings = %+v, want three", got.Headings)
	}
	wantSecret := map[string]string{"Public": "", "Secret Heading": "abc123abc123", "After": ""}
	for _, h := range got.Headings {
		if h.Span.SecretID != wantSecret[h.Text] {
			t.Errorf("heading %q has secret id %q, want %q", h.Text, h.Span.SecretID, wantSecret[h.Text])
		}
	}
	if len(got.Links) != 2 {
		t.Fatalf("links = %+v, want two", got.Links)
	}
	for _, l := range got.Links {
		want := map[string]string{"PublicLink": "", "SecretLink": "abc123abc123"}[l.TargetRaw]
		if l.Span.SecretID != want {
			t.Errorf("link %q has secret id %q, want %q", l.TargetRaw, l.Span.SecretID, want)
		}
	}
	// An ordinal counts every heading, including the ones a reader may not see,
	// so the numbering matches the file rather than the filtered view.
	for i, h := range got.Headings {
		if h.Ordinal != i+1 {
			t.Errorf("heading %d has ordinal %d", i, h.Ordinal)
		}
	}
}

// TestExtractLineNumbers locates a fact in the file, which is what an error
// message quoting "line 42" needs.
func TestExtractLineNumbers(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	src := "---\ntitle: T\n---\n\n# One\n\nline three\nline four\n\n[[Link]]\n"
	got, _ := Extract(Parse("x.md", []byte(src)), r)
	if len(got.Links) != 1 {
		t.Fatalf("links = %+v", got.Links)
	}
	// The body starts after the frontmatter, but the line number is the line
	// in the file, which is what an editor shows.
	if got.Links[0].Line != 10 {
		t.Errorf("link line = %d, want 10", got.Links[0].Line)
	}
}

// TestSlug is a unit test of the anchor rule, which the table of contents and
// every `#fragment` link depend on.
func TestSlug(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"The Cellar":                   "the-cellar",
		"A  Double  Space":             "a-double-space",
		"What's In A Name?!":           "whats-in-a-name",
		"Level 3: The Catacombs":       "level-3-the-catacombs",
		"already-hyphenated_and_kept":  "already-hyphenated_and_kept",
		"Ünïcödé Heading":              "ünïcödé-heading",
		"日本語の見出し":                      "日本語の見出し",
		"100% of the Time":             "100-of-the-time",
		"  leading and trailing  ":     "leading-and-trailing",
		"":                             "",
		"!!!":                          "",
		"tabs\tand\nnewlines":          "tabs-and-newlines",
		"[brackets] (parens) {braces}": "brackets-parens-braces",
		"a/b\\c":                       "abc",
		"multiple   inner    spaces":   "multiple-inner-spaces",
		"trailing hyphen-":             "trailing-hyphen",
		"colon: and comma,":            "colon-and-comma",
	}
	for in, want := range cases {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNormalizeTag covers the shapes Obsidian writes, including a tag with a
// `/` and a tag whose name is a prefix of another's.
func TestNormalizeTag(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"#alpha":      "alpha",
		"##alpha":     "alpha",
		"#Beta":       "beta",
		"#area/port":  "area/port",
		"#not#a#tag":  "not#a#tag",
		"  #spaced  ": "spaced",
		"#":           "",
		"":            "",
		"no hash":     "no hash",
		"#UPPER":      "upper",
	}
	for in, want := range cases {
		if got := NormalizeTag(in); got != want {
			t.Errorf("NormalizeTag(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHashtagScoping pins the tags the inline parser accepts. A tag that
// matches inside a word is a tag nobody wrote, and the tag panel fills up with
// them.
func TestHashtagScoping(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	got, _ := Extract(Parse("x.md", []byte("a #word b not#atag c # real #one\n")), r)
	var names []string
	for _, tag := range got.Tags {
		names = append(names, tag.Name)
	}
	// `not#atag` is the middle of a word and `# real` has a space after the
	// marker. goldmark-obsidian takes the first of those and the second comes
	// from Obsidian's own rule; neither is a tag anybody wrote.
	if !sameStrings(names, []string{"word", "one"}) {
		t.Errorf("tags = %q, want [word one]", names)
	}
}

// TestExtractProblemsAreTheDocuments checks that Extract surfaces the parse
// problems rather than swallowing them: a page with a problem is a page the
// DM needs to see.
func TestExtractProblemsAreTheDocuments(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	src := "```secret id=abc123abc123\nnever closed\n"
	got, problems := Extract(Parse("x.md", []byte(src)), r)
	if len(problems) == 0 {
		t.Error("Extract reported no problems for an unterminated fence")
	}
	if len(got.Headings) != 0 {
		t.Errorf("headings = %+v, want none", got.Headings)
	}
}

// TestExtractWithNoRenderer: the nil path exists so the indexer's call sites do
// not have to carry a nil check for a parameter whose only non-nil use is the
// plugin extenders.
func TestExtractWithNoRenderer(t *testing.T) {
	t.Parallel()
	got, _ := Extract(Parse("x.md", []byte("# T\n\n[[L]]\n")), nil)
	if got.Title != "T" || len(got.Links) != 1 {
		t.Errorf("extraction with a nil renderer = %+v", got)
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// extractWalk is a small helper for the tests that need to look at the AST the
// extractor sees, rather than at its output.
func extractWalk(t *testing.T, d *Doc, r *Renderer, fn func(ast.Node)) {
	t.Helper()
	_ = ast.Walk(r.ParseDoc(d), func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			fn(n)
		}
		return ast.WalkContinue, nil
	})
}

var (
	_ = wikilink.Kind
	_ = hashtag.Kind
)
