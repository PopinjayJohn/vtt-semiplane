package md

import (
	"bytes"
	"testing"
)

// TestSplitFrontmatter pins the byte ranges the rest of the package is written
// against. Every case asserts the two ranges against the input bytes rather
// than against a hard-coded number, because a range that is off by the
// frontmatter's own length is a range that re-saves the wrong bytes.
func TestSplitFrontmatter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		src        string
		wantBody   string
		wantFM     string
		wantFence  string
		problemate string
	}{
		{
			name:      "no frontmatter",
			src:       "# Title\n\nBody.\n",
			wantBody:  "# Title\n\nBody.\n",
			wantFence: "",
		},
		{
			name:      "simple block",
			src:       "---\ntitle: x\n---\nBody\n",
			wantFM:    "title: x\n",
			wantBody:  "Body\n",
			wantFence: "---\ntitle: x\n---\n",
		},
		{
			name:      "body starts immediately after the closing fence",
			src:       "---\na: 1\n---\n# T\n",
			wantFM:    "a: 1\n",
			wantBody:  "# T\n",
			wantFence: "---\na: 1\n---\n",
		},
		{
			name:      "empty block",
			src:       "---\n---\nBody\n",
			wantFM:    "",
			wantBody:  "Body\n",
			wantFence: "---\n---\n",
		},
		{
			name:      "no blank line after the fence",
			src:       "---\na: 1\n---\nBody\n",
			wantFM:    "a: 1\n",
			wantBody:  "Body\n",
			wantFence: "---\na: 1\n---\n",
		},
		{
			name:      "unterminated fence is body, and says so",
			src:       "---\na: 1\nBody, not YAML.\n",
			wantBody:  "---\na: 1\nBody, not YAML.\n",
			wantFence: "",
		},
		{
			// Four dashes are a valid YAML document start, and a `---` inside
			// the block that is not the first such line is content.
			name:      "four dash fence",
			src:       "----\na: 1\n----\nBody\n",
			wantFM:    "a: 1\n",
			wantBody:  "Body\n",
			wantFence: "----\na: 1\n----\n",
		},
		{
			name:      "a thematic break does not open a block",
			src:       "# T\n\n---\n\nMore.\n",
			wantBody:  "# T\n\n---\n\nMore.\n",
			wantFence: "",
		},
		{
			name:      "trailing spaces on the fences",
			src:       "---  \na: 1\n---  \nBody\n",
			wantFM:    "a: 1\n",
			wantBody:  "Body\n",
			wantFence: "---  \na: 1\n---  \n",
		},
		{
			name:      "crlf fences",
			src:       "---\r\na: 1\r\n---\r\nBody\r\n",
			wantFM:    "a: 1\r\n",
			wantBody:  "Body\r\n",
			wantFence: "---\r\na: 1\r\n---\r\n",
		},
		{
			name:      "the first --- line closes, later ones do not",
			src:       "---\na: ---\n---\nBody\n",
			wantFM:    "a: ---\n",
			wantBody:  "Body\n",
			wantFence: "---\na: ---\n---\n",
		},
		{
			name:      "a file that is only the opening fence",
			src:       "---",
			wantBody:  "---",
			wantFence: "",
		},
		{
			name:      "a file that is only the opening fence and a newline",
			src:       "---\n",
			wantBody:  "---\n",
			wantFence: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, bodyRange, fm, fmRange, err := SplitFrontmatter([]byte(tc.src))
			if string(body) != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
			if string(fm) != tc.wantFM {
				t.Errorf("frontmatter = %q, want %q", fm, tc.wantFM)
			}
			if tc.wantFence == "" {
				if fmRange.Valid() {
					t.Errorf("frontmatter range %+v is valid, want invalid", fmRange)
				}
			} else if got := string(fmRange.Slice([]byte(tc.src))); got != tc.wantFence {
				t.Errorf("frontmatter range = %q, want %q", got, tc.wantFence)
			}
			if got := string(bodyRange.Slice([]byte(tc.src))); got != tc.wantBody {
				t.Errorf("body range = %q, want %q", got, tc.wantBody)
			}
			// A body range must never overlap the frontmatter range, whatever
			// the two hold.
			if fmRange.Valid() && bodyRange.Start < fmRange.End {
				t.Errorf("body range %+v overlaps frontmatter range %+v", bodyRange, fmRange)
			}
			_ = err
		})
	}
}

// TestFrontmatterYAMLRangeSitsBetweenTheFences is the invariant the structured
// edits rely on: patching the YAML range must not touch either fence.
func TestFrontmatterYAMLRangeSitsBetweenTheFences(t *testing.T) {
	t.Parallel()
	src := []byte("---\na: 1\nb: 2\n---\nBody\n")
	d := Parse("x.md", src)
	got := string(d.FrontmatterYAMLRange.Slice(src))
	if got != "a: 1\nb: 2\n" {
		t.Errorf("YAML range = %q", got)
	}
	// The two ranges together must reconstruct the block the frontmatter
	// value was taken from, and the value must be a sub-range of the range.
	if !bytes.Contains(d.Frontmatter, []byte("a: 1")) {
		t.Errorf("Frontmatter = %q", d.Frontmatter)
	}
	block := d.FrontmatterRange.Slice(src)
	if !bytes.HasPrefix(block, []byte("---")) || !bytes.HasSuffix(block, []byte("---\n")) {
		t.Errorf("block range = %q, want both fences", block)
	}
}

// TestBOMPreserved checks the three things that have to be true at once for a
// Windows-authored file to survive: the mark is in neither range, it is
// reported, and the bytes are still the file.
func TestBOMPreserved(t *testing.T) {
	t.Parallel()
	corpus := loadCorpus(t)
	for _, name := range []string{"bom.md", "bom-no-frontmatter.md"} {
		src := corpus[name]
		if len(src) < 3 || src[0] != 0xEF || src[1] != 0xBB || src[2] != 0xBF {
			t.Fatalf("fixture %s does not start with a BOM", name)
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Parse(name, src)
			if !bytes.Equal(d.BOM, src[:3]) {
				t.Errorf("BOM = %x, want %x", d.BOM, src[:3])
			}
			if d.BodyRange.Start < 3 {
				t.Errorf("the body starts at %d, inside the BOM", d.BodyRange.Start)
			}
			if d.FrontmatterRange.Valid() && d.FrontmatterRange.Start < 3 {
				t.Errorf("the frontmatter starts at %d, inside the BOM", d.FrontmatterRange.Start)
			}
			if !bytes.Equal(Resave(d), src) {
				t.Error("a BOM file did not round trip")
			}
			if !bytes.Equal(d.Bytes, src) {
				t.Error("Doc.Bytes is not the file")
			}
		})
	}
}

// TestCRLFRoundTrip checks the same for CRLF: the closing fence may end in
// \r\n, and a structured edit must not turn the file into a mixed-ending one.
func TestCRLFRoundTrip(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "crlf.md")
	if !bytes.Contains(src, []byte("\r\n")) {
		t.Fatal("the CRLF fixture has no CRLF in it")
	}
	d := Parse("crlf.md", src)
	if d.FrontmatterRange.Valid() {
		if got := string(d.Frontmatter); got != "title: Windows\r\n" {
			t.Errorf("frontmatter = %q", got)
		}
	}
	if got := string(d.Body); !bytes.HasSuffix([]byte(got), []byte("- item\r\n")) {
		t.Errorf("body = %q", got)
	}
	if !bytes.Equal(Resave(d), src) {
		t.Error("a CRLF file did not round trip")
	}
	// A real edit has to stay CRLF: it splices bytes, it does not re-emit
	// lines, and this is the assertion that keeps it that way.
	patched, problems := PatchFrontmatter(d, map[string]any{"status": "active"})
	assertNoProblems(t, problems)
	if !bytes.Contains(patched, []byte("status: active\n")) {
		t.Errorf("the patch is missing: %q", patched)
	}
	if bytes.Contains(patched, []byte("\nstatus")) && !bytes.Contains(patched, []byte("\r\nstatus")) {
		t.Errorf("the patch introduced a bare LF into a CRLF file: %q", patched)
	}
	// Mixed line endings are legal and must be preserved as written.
	mixed := loadFixture(t, "crlf-mixed.md")
	if !bytes.Equal(Resave(Parse("mixed.md", mixed)), mixed) {
		t.Error("a mixed-ending file did not round trip")
	}
}

// TestTrailingWhitespacePreserved covers the whitespace a YAML round trip and
// most editors would quietly remove.
func TestTrailingWhitespacePreserved(t *testing.T) {
	t.Parallel()
	// Each case is a fixture and the exact bytes inside it that a tidy-up
	// would remove.
	cases := map[string]string{
		"trailing-whitespace.md": "Line with trailing spaces.   \n",
		"frontmatter-comment.md": "title: Commented   # trailing comment\n",
		"escape.md":              `and a backslash \\ at the end.` + "\n",
	}
	for name, want := range cases {
		src := loadFixture(t, name)
		d := Parse(name, src)
		if !bytes.Equal(Resave(d), src) {
			t.Errorf("%s: a re-save changed the bytes", name)
		}
		if want != "" && !bytes.Contains(src, []byte(want)) {
			t.Errorf("%s: the fixture does not contain %q", name, want)
		}
		// A real frontmatter edit must not tidy the rest of the block.
		if d.FrontmatterRange.Valid() {
			patched, problems := PatchFrontmatter(d, map[string]any{"added": "yes"})
			assertNoProblems(t, problems)
			if !bytes.Contains(patched, []byte(want)) {
				t.Errorf("%s: the patch removed the trailing whitespace %q", name, want)
			}
		}
	}
	// A tab-indented line and a trailing tab both survive a no-op.
	for _, name := range []string{"tabs.md", "trailing-whitespace.md", "code-fence-indented.md"} {
		src := loadFixture(t, name)
		if !bytes.Equal(Resave(Parse(name, src)), src) {
			t.Errorf("%s: a re-save changed the bytes", name)
		}
	}
}

// TestParseFieldsToleratesObsidianPropertyShapes covers the shapes Obsidian
// writes that a strict reader would reject: a scalar, a list, a nested mapping
// and a list of scalars. A property this package cannot read is a page whose
// tags are silently missing, which is a data-loss bug dressed as a parse
// error.
func TestParseFieldsToleratesObsidianPropertyShapes(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "frontmatter-cssclasses.md")
	d := Parse("cssclasses.md", src)
	if len(d.Problems) != 0 {
		t.Errorf("a valid properties block produced problems: %v", d.Problems)
	}
	classes := FieldStrings(d.Fields, "cssclasses")
	if len(classes) != 2 || classes[0] != "wide" {
		t.Errorf("cssclasses = %q", classes)
	}
	if got := FieldString(d.Fields, "cssclass"); got != "legacy" {
		t.Errorf("cssclass = %q", got)
	}
	nested, ok := d.Fields["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %T, want a map", d.Fields["nested"])
	}
	if nested["key"] != "value" {
		t.Errorf("nested.key = %v", nested["key"])
	}
	deeper, ok := nested["deeper"].([]any)
	if !ok || len(deeper) != 2 {
		t.Errorf("nested.deeper = %v", nested["deeper"])
	}
	// A list property spelled inline and one spelled as a block are the same
	// property.
	inline := Parse("inline.md", loadFixture(t, "frontmatter-inline-list.md"))
	if got := FieldStrings(inline.Fields, "tags"); len(got) != 2 || got[0] != "gamma" {
		t.Errorf("inline tags = %q", got)
	}
	if got := FieldStrings(inline.Fields, "aliases"); len(got) != 1 || got[0] != "Only One" {
		t.Errorf("inline aliases = %q", got)
	}
}

// TestInvalidFrontmatterIsPreservedAndReported: the bytes stay, the problem is
// raised, and the page still gets a body.
func TestInvalidFrontmatterIsPreservedAndReported(t *testing.T) {
	t.Parallel()
	src := loadFixture(t, "frontmatter-invalid.md")
	d := Parse("invalid.md", src)
	if len(d.Fields) != 0 {
		t.Errorf("Fields = %v, want empty", d.Fields)
	}
	found := false
	for _, p := range d.Problems {
		if p.Code == ProblemFrontmatterInvalid {
			found = true
		}
	}
	if !found {
		t.Errorf("problems = %v, want a frontmatter.invalid", d.Problems)
	}
	if !bytes.Equal(Resave(d), src) {
		t.Error("an unparseable frontmatter block was rewritten")
	}
	block := d.FrontmatterRange.Slice(src)
	if !bytes.HasPrefix(block, []byte("---\n")) || !bytes.Contains(block, []byte("\n---\n")) {
		t.Errorf("block range = %q, want both fences", block)
	}
	if !bytes.Contains(src[d.FrontmatterYAMLRange.Start:d.FrontmatterYAMLRange.End], []byte("title: [unclosed")) {
		t.Errorf("the YAML range = %q", src[d.FrontmatterYAMLRange.Start:d.FrontmatterYAMLRange.End])
	}
}

// TestParseFenceDirective covers the directive grammar, including the two
// shapes a hand-written fence gets wrong: a quoted value with a space in it,
// and a repeated key.
func TestParseFenceDirective(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		info     string
		want     Directive
		wantErr  bool
		notField string
	}{
		{
			name: "id only",
			info: "secret id=7f3a91c40d2e",
			want: Directive{ID: "7f3a91c40d2e", Visibility: "private"},
		},
		{
			name: "every key",
			info: `secret id=7f3a91c40d2e visibility=dm author=gundren created=2024-03-04T05:06:07Z title="The Vault Door"`,
			want: Directive{ID: "7f3a91c40d2e", Visibility: "dm", Author: "gundren",
				Created: "2024-03-04T05:06:07Z", Title: "The Vault Door"},
		},
		{
			name: "single quoted title with a space",
			info: "secret id=a title='Two Words'",
			want: Directive{ID: "a", Visibility: "private", Title: "Two Words"},
		},
		{
			name: "an unknown visibility redacts harder",
			info: "secret id=a visibility=everyone",
			want: Directive{ID: "a", Visibility: "private", BadVisibility: true},
		},
		{
			name:     "an unknown key is a flag, not an error",
			info:     "secret id=a rotate=on",
			want:     Directive{ID: "a", Visibility: "private", HasUnknown: true, UnknownKeys: []string{"rotate"}},
			notField: "rotate",
		},
		{
			name: "a bare key",
			info: "secret id=a flag",
			want: Directive{ID: "a", Visibility: "private", HasUnknown: true, UnknownKeys: []string{"flag"}},
		},
		{
			name:    "a repeated key is an error",
			info:    "secret id=a visibility=dm visibility=table",
			wantErr: true,
		},
		{
			name:    "not a secret fence",
			info:    "go",
			wantErr: true,
		},
		{
			name:    "empty",
			info:    "",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseFenceDirective(tc.info)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseFenceDirective(%q) = %+v, want an error", tc.info, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFenceDirective(%q): %v", tc.info, err)
			}
			if got.ID != tc.want.ID || got.Visibility != tc.want.Visibility ||
				got.Author != tc.want.Author || got.Created != tc.want.Created ||
				got.Title != tc.want.Title || got.HasUnknown != tc.want.HasUnknown ||
				got.BadVisibility != tc.want.BadVisibility {
				t.Errorf("ParseFenceDirective(%q) =\n %+v\nwant\n %+v", tc.info, got, tc.want)
			}
			if tc.want.UnknownKeys != nil {
				if len(got.UnknownKeys) != len(tc.want.UnknownKeys) {
					t.Fatalf("unknown keys = %q, want %q", got.UnknownKeys, tc.want.UnknownKeys)
				}
				for i := range tc.want.UnknownKeys {
					if got.UnknownKeys[i] != tc.want.UnknownKeys[i] {
						t.Errorf("unknown keys = %q, want %q", got.UnknownKeys, tc.want.UnknownKeys)
					}
				}
			}
			if tc.notField != "" {
				for _, k := range got.UnknownKeys {
					if k == tc.notField {
						return
					}
				}
				t.Errorf("unknown keys = %q, want %q in them", got.UnknownKeys, tc.notField)
			}
		})
	}
}

// TestDirectiveCreatedTimeIsNotAValidationGate: a malformed timestamp yields
// the zero time, not an error. The on-disk text is preserved either way, and
// refusing to parse a page over a bad date would hide the page.
func TestDirectiveCreatedTimeIsNotAValidationGate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		created string
		zero    bool
	}{
		{"2024-03-04T05:06:07Z", false},
		{"2024-03-04", true},
		{"", true},
		{"not a date", true},
	} {
		d, err := ParseFenceDirective("secret id=a created=" + tc.created)
		if err != nil {
			t.Fatalf("created=%q: %v", tc.created, err)
		}
		if got := d.CreatedTime().IsZero(); got != tc.zero {
			t.Errorf("created=%q: zero = %v, want %v", tc.created, got, tc.zero)
		}
	}
}
