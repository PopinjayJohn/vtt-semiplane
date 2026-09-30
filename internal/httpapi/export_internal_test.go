package httpapi

import (
	"net/url"
	"strings"
	"testing"
)

// The Content-Disposition a page name is written into, tested against names no
// filesystem can be asked to hold.
//
// The end-to-end version of this is
// TestSecretFixturesNeverLeak/the_content-disposition_filename_cannot_split_a_header,
// and it has to go through a real page on a real volume — which is what makes it
// a weak place to cover the sharpest characters. A quote is the one that
// matters, because it ends the quoted string the name is written into and
// everything after it parses as a new parameter, and it is legal in a POSIX file
// name and illegal in a Windows one. So on a Windows runner the end-to-end case
// cannot be built at all, and the character would go untested there unless the
// function itself is reachable.
//
// exportDisposition and headerFilename are unexported, so this is an in-package
// test. It has no filesystem in it, so it runs identically on every platform and
// the hostile names cost nothing but a table.
func TestTheExportHeaderCannotBeSplitByAPageName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		page string
	}{
		{"a quote", `Quote "only".md`},
		{"a quote on both sides", `"Quoted".md`},
		{"a backslash", `Back\slash.md`},
		{"a quote then a parameter", `x".md; filename="evil`},
		{"a carriage return", "Carriage\rReturn.md"},
		{"a line feed", "Line\nFeed.md"},
		{"a CRLF pair", "Both\r\nFence.md"},
		{"a NUL", "Nul\x00Name.md"},
		{"a delete", "Del\x7fName.md"},
		{"a name outside ASCII", "Owes €5.md"},
		{"a name outside BMP", "Night\U0001F426.md"},
		{"a name that reduces to nothing", "\r\n\x00.md"},
		{"a very long name", strings.Repeat("a", 400) + ".md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := exportDisposition(tc.page)
			const prefix = `attachment; filename="`
			if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, `"`) {
				t.Fatalf("the disposition is not a quoted attachment filename: %q", got)
			}
			if strings.ContainsAny(got[:len(got)-1], "\r\n") {
				t.Errorf("the disposition carries a line break, which is a split response header: %q", got)
			}
			value := got[len(prefix) : len(got)-1]
			if strings.ContainsAny(value, "\"\\\r\n\x00") {
				t.Errorf("the filename %q still carries a quote, a backslash, a line break or a NUL", value)
			}
			for _, r := range value {
				if r < 0x20 || r == 0x7f || r > 0x7e {
					t.Errorf("the filename carries %q, which is outside printable ASCII: %q", r, value)
				}
			}
			if value == "" {
				t.Error("the filename is empty, so a browser is told to save the file under no name at all")
			}
			// The value is still a usable header parameter, not merely a safe
			// one: escaping it the way a browser would have to yields a string
			// that parses back to the same bytes the function was handed.
			if escaped := url.PathEscape(value); strings.ContainsAny(escaped, "\r\n") {
				t.Errorf("the escaped filename %q carries a line break", escaped)
			}
		})
	}
}

// TestExportFilenameIsTheBaseNameAndNothingElse pins the other half of the
// header: which name is chosen. A page called Café.md exports as Café.md, a page
// called docs/notes/adventuring.md exports as adventuring.md, and a path that
// reduces to a directory produces something a browser can save.
//
// exportFilename deliberately does not sanitise — it takes a base name and
// nothing else, and the reduction is headerFilename's job, one layer up. A name
// carrying a line break therefore comes out of here unchanged, which is why the
// composition is asserted as well: the two are separate steps and the header is
// only safe because both are called.
func TestExportFilenameIsTheBaseNameAndNothingElse(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Tavern.md":                 "Tavern.md",
		"docs/notes/adventuring.md": "adventuring.md",
		"a name with a space.md":    "a name with a space.md",
		"/etc/passwd":               "passwd",
		".":                         "page.md",
		"/":                         "page.md",
		"nested/dir/":               "dir",
		"weird\r\nname.md":          "weird\r\nname.md",
		"trailing.dot. ":            "trailing.dot. ",
		"UPPER.MD":                  "UPPER.MD",
		"no-extension":              "no-extension",
		"a.dot.in.the.middle":       "a.dot.in.the.middle",
		"dots.only...":              "dots.only...",
	}
	for page, want := range cases {
		if got := exportFilename(page); got != want {
			t.Errorf("exportFilename(%q) = %q, want %q", page, got, want)
		}
	}
	if got := exportDisposition(exportFilename("weird\r\nname.md")); strings.ContainsAny(got, "\r\n") {
		t.Errorf("the composed disposition is %q, so a base name carrying a line break reaches the header unreduced", got)
	}
}
