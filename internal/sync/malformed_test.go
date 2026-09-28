package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// TestIndexerHandlesMalformedInput asserts that every way a file can be wrong
// ends in a page row or a recorded problem, and never in a hang, a panic or a
// truncated page.
//
// The hang is the failure this file is really about. Two of them have shipped in
// this repository already, both from a parser that recognised a token and did not
// advance its cursor, each spinning *while appending* so it looked like a hang
// and read as a memory leak. Every fixture here is a shape that has a plausible
// story for doing that, and the test's value is that it terminates.
func TestIndexerHandlesMalformedInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		// wantProblem is a problem code the pass must report. Empty means the
		// fixture is expected to index cleanly.
		wantProblem string
		// wantTitle is the title the fence's directive carried, if the fixture has
		// one. It is asserted because a quoted value is the one place the
		// directive grammar can mis-split, and a mis-split shows up as a title
		// that is a fragment of the real one.
		wantTitle string
		// wantPages is how many page rows the file may produce.
		wantPages int
	}{
		{
			name:        "an empty file",
			body:        "",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a fence that is never closed",
			body:        "# Page\n\n```secret id=abcabcabcabc visibility=dm author=dorn\nThe body, and no closing fence.\n",
			wantPages:   1,
			wantProblem: "secret.unterminated",
		},
		{
			name: "a directive that cannot be parsed",
			// A duplicated key: the second value is ambiguous, and a fence whose
			// meaning is ambiguous is not a fence this build will act on.
			body:        "# Page\n\n```secret id=abcabcabcabc visibility=dm visibility=table author=dorn\nBody.\n```\n",
			wantPages:   1,
			wantProblem: "secret.bad_directive",
		},
		{
			name: "a directive with a key nobody knows",
			body: "# Page\n\n```secret id=abcabcabcabc visibility=dm author=dorn colour=red\nBody.\n```\n",
			// md demotes this to public passthrough, so the bytes are ordinary
			// text on the page and are indexed as such. The problem is reported
			// because the author needs to know the fence is not doing anything.
			wantPages:   1,
			wantProblem: "secret.unknown_key",
		},
		{
			name: "a visibility nobody knows",
			body: "# Page\n\n```secret id=abcabcabcabc visibility=everyone author=dorn\nBody.\n```\n",
			// The fence is still secret — the body is not in page_text — and the
			// bad value is reported. An unknown visibility is never treated as
			// open.
			wantPages:   1,
			wantProblem: "secret.bad_visibility",
		},
		{
			name: "a fence with no id",
			body: "# Page\n\n```secret visibility=dm author=dorn\nBody.\n```\n",
			// md gives the span a deterministic placeholder id, so the fence is
			// still a fence and the file is still indexable.
			wantPages:   1,
			wantProblem: "secret.missing_id",
		},
		{
			name:        "an id that is not the format's twelve hex characters",
			body:        "# Page\n\n```secret id=short visibility=dm author=dorn\nBody.\n```\n",
			wantPages:   1,
			wantProblem: ProblemUnusableFence,
		},
		{
			name:        "an upper-case id",
			body:        "# Page\n\n```secret id=ABCDEF012345 visibility=table author=dorn\nBody.\n```\n",
			wantPages:   1,
			wantProblem: ProblemUnusableFence,
		},
		{
			name:        "a quoted title with punctuation and escaped quotes",
			body:        "# Page\n\n```secret id=abcabcabcabc visibility=private author=dorn title=\"Has a = sign and \\\"quotes\\\"\"\nBody.\n```\n",
			wantPages:   1,
			wantProblem: "",
			wantTitle:   `Has a = sign and "quotes"`,
		},
		{
			name: "a title written with doubled quotes instead of escapes",
			// The directive grammar is quote-aware but not YAML's: a doubled
			// quote inside a quoted value is an unknown key, and an unknown key
			// means the fence is not a fence. Recorded here so that changing the
			// grammar is a deliberate act rather than a surprise.
			body:        "# Page\n\n```secret id=abcabcabcabc visibility=dm author=dorn title=\"The \"\"real\"\" name\"\nBody.\n```\n",
			wantPages:   1,
			wantProblem: "secret.unknown_key",
		},
		{
			name: "a nested secret fence",
			body: "# Page\n\n```secret id=abcabcabcabc visibility=dm author=dorn\nOuter.\n\n```secret id=defdefdefdef visibility=dm author=dorn\nInner.\n```\n```\n",
			// The inner fence is literal text inside the outer one, which is what
			// makes the outer span run past it.
			wantPages:   1,
			wantProblem: "secret.nested",
		},
		{
			name:        "an unterminated frontmatter block",
			body:        "---\ntitle: Page\n# Page\n\nBody.\n",
			wantPages:   1,
			wantProblem: "frontmatter.unterminated",
		},
		{
			name:        "frontmatter that is not yaml",
			body:        "---\ntitle: [unclosed\n---\n# Page\n\nBody.\n",
			wantPages:   1,
			wantProblem: "frontmatter.invalid",
		},
		{
			name:        "a file that is not valid utf-8",
			body:        "# Page \xff\xfe\n\nBody with a stray byte: \x80\x81.\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a page that is only a fence",
			body:        "```secret id=abcabcabcabc visibility=table author=dorn\nOnly this.\n```\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a self-closing fence",
			body:        "# Page\n\n```\n```\n\nText.\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a fence with a stray backtick in its directive",
			body:        "# Page\n\n```secret id=abc`abc visibility=dm\nBody.\n```\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a megabyte of wikilinks",
			body:        wikilinkFlood(1 << 20),
			wantPages:   1,
			wantProblem: "",
		},
		{
			// Half a mebibyte on a single line. goldmark's inline parser rescans a
			// line for a closing delimiter at every opening one, so this is
			// quadratic in the line's length and costs seconds rather than
			// milliseconds. The size is chosen to keep the race run quick while
			// keeping the property: it terminates.
			name:        "a large run of brackets on one line",
			body:        strings.Repeat("[", 1<<17) + "\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a page of nothing but newlines",
			body:        strings.Repeat("\n", 4096),
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "two fences with the same body",
			body:        "# Page\n\n" + secretFence("abcabcabcabc", "table", "dorn", "x") + "\n" + secretFence("defdefdefdef", "table", "dorn", "x") + "\n",
			wantPages:   1,
			wantProblem: "",
		},
		{
			name:        "a secret fence that repeats a body byte for byte",
			body:        "# Page\n\n" + secretFence("abcabcabcabc", "table", "dorn", "x") + "\n" + secretFence("defdefdefdef", "table", "dorn", "x") + "\n",
			wantPages:   1,
			wantProblem: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			// Written explicitly rather than seeded through WithVault, because a
			// fixture whose body is the empty string would otherwise be a
			// directory.
			h.vault.WriteFile(t, "Fixture.md", tc.body)
			start := time.Now()
			res := h.indexAll()
			t.Logf("%s: %d bytes indexed in %s with %d problems",
				tc.name, len(tc.body), time.Since(start).Round(time.Millisecond), countProblems(res))
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages`); n != int64(tc.wantPages) {
				t.Fatalf("expected %d pages, got %d", tc.wantPages, n)
			}
			if tc.wantTitle != "" {
				if got := h.mustQueryString(
					`SELECT COALESCE(MAX(title), '') FROM secrets`); got != tc.wantTitle {
					t.Errorf("the fence title is %q, want %q", got, tc.wantTitle)
				}
			}
			if tc.wantProblem == "" {
				return
			}
			if !hasProblem(res, tc.wantProblem) {
				t.Errorf("no %s problem was reported: %+v", tc.wantProblem, allProblems(res))
			}
		})
	}
}

// TestAWholeVaultOfBrokenFilesStillIndexes is the bulk case: many broken files
// in one pass, so the transaction-per-file property is exercised under a batch
// that is mostly errors.
func TestAWholeVaultOfBrokenFilesStillIndexes(t *testing.T) {
	t.Parallel()
	files := map[string]string{}
	for i := range 40 {
		files[string(rune('a'+i%26))+string(rune('a'+i/26))+".md"] = strings.Repeat(
			"# Page\n\n```secret id=abc visibility=oops author=nobody\nbody\n", 1+i%5)
	}
	h := newHarness(t, files)
	res := h.indexAll()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages`); n != 40 {
		t.Fatalf("expected 40 pages, got %d", n)
	}
	// Every one of them has an unparseable visibility, so none of them has a
	// searchable secret, and none of them has a body in the public index.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text`); n != 0 {
		t.Errorf("%d secrets with an unknown visibility reached the search index", n)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 0 {
		t.Errorf("%d secrets with an unusable author were indexed", n)
	}
	for _, r := range res.Indexed {
		if !hasProblem(BatchResult{Indexed: []Result{r}}, "secret.bad_visibility") {
			t.Errorf("%s reported no bad-visibility problem", r.Path)
		}
	}
}

// TestAFenceMayNotBeReadAsPublicBecauseItsDirectiveIsOdd asserts the direction
// of every malformed-directive fallback: the body stays out of the public index.
//
// A fence with a duplicated key or a nonsense visibility is not a fence this
// build can act on, and md's own answer is to treat the bytes as ordinary text.
// That is a real leak by design — an unparseable directive is public by
// definition, and the author is told — so the test asserts the opposite for the
// cases md *does* keep secret: an unknown visibility is reported and still
// redacted.
func TestAFenceMayNotBeReadAsPublicBecauseItsDirectiveIsOdd(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Bad.md": "# Page\n\n```secret id=abcabcabcabc visibility=everyone author=dorn\nThe underpaid guard.\n```\n",
	})
	res := h.indexAll()
	if !hasProblem(res, "secret.bad_visibility") {
		t.Fatal("the bad visibility was not reported")
	}
	if n := h.mustQueryInt(
		`SELECT COUNT(*) FROM page_text WHERE body LIKE '%underpaid%'`); n != 0 {
		t.Fatal("a secret with an unknown visibility leaked into the public text")
	}
	// Its facts are still attributed to it, so the canonical predicate treats
	// the secret as a secret even though the visibility is nonsense: the
	// predicate's answer to an unknown visibility is deny.
	player := h.principal("pia")
	rows, err := store.ListVisibleSecretRowsByPage(context.Background(), h.db.Reader(), player, h.pageID("Bad.md"))
	if err != nil {
		t.Fatalf("visible secrets: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("a player can see %d secrets with an unknown visibility", len(rows))
	}
	count, err := store.CountVisibleSecrets(context.Background(), h.db.Reader(), player, h.pageID("Bad.md"))
	if err != nil {
		t.Fatalf("visible secret count: %v", err)
	}
	if count != 0 {
		t.Fatalf("a panel would count %d secrets with an unknown visibility", count)
	}
}

// wikilinkFlood builds a document of the given size out of wikilinks, one per
// line.
//
// One per line is deliberate. goldmark's inline parser rescans a line for a
// closing delimiter at every opening one, so a single line of a mebibyte of
// brackets is quadratic in the length of that line and takes minutes; a real
// campaign page with a thousand links has a thousand lines. The single-line case
// is its own fixture so that the cost is attributed rather than guessed at.
func wikilinkFlood(size int) string {
	const line = "[[Quest Log|the log]] and [[Npc- Gundren]] plus #flooded\n"
	var b strings.Builder
	b.Grow(size)
	for b.Len() < size {
		b.WriteString(line)
	}
	return b.String()
}

func countProblems(res BatchResult) int {
	n := 0
	for _, r := range res.Indexed {
		n += len(r.Problems)
	}
	return n
}

func allProblems(res BatchResult) []Problem {
	var out []Problem
	for _, r := range res.Indexed {
		out = append(out, r.Problems...)
	}
	return out
}

func hasProblem(res BatchResult, code string) bool {
	for _, p := range allProblems(res) {
		if p.Code == code {
			return true
		}
	}
	return false
}
