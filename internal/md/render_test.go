package md

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestRawHTMLIsNotRendered is the package's stored-XSS gate. A vault file is
// user content, and every user in the game reads every page, so a rendered
// <script> is a script one player runs in another player's session.
//
// html.WithUnsafe is not set anywhere in this package and must not be: the
// assertion below is the reason, so a future "just this once" edit fails here
// rather than in someone's browser.
func TestRawHTMLIsNotRendered(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	attacks := []string{
		`<script>alert(1)</script>`,
		`<script src="https://example.invalid/x.js"></script>`,
		`<SCRIPT>alert(1)</SCRIPT>`,
		`<img src=x onerror="alert(1)">`,
		`<img src=x onerror=alert(1)//>`,
		`<svg/onload=alert(1)>`,
		`<iframe src="javascript:alert(1)"></iframe>`,
		`<body onload=alert(1)>`,
		`<a href="javascript:alert(1)">click</a>`,
		`<style>body{display:none}</style>`,
		`<div onmouseover="steal()">hover</div>`,
		`<form action="https://example.invalid"><input name=pw></form>`,
		`<math><mtext><script>alert(1)</script></mtext></math>`,
		"<![CDATA[<script>alert(1)</script>]]>",
	}
	for _, attack := range attacks {
		t.Run(attack[:min(28, len(attack))], func(t *testing.T) {
			t.Parallel()
			for _, src := range []string{
				attack,
				"before\n\n" + attack + "\n\nafter\n",
				"- list item\n\n  " + attack + "\n",
				"> quote\n>\n> " + attack + "\n",
				"| a |\n| --- |\n| " + attack + " |\n",
				attack + " and a [[link]] and a `code span`\n",
			} {
				out, err := r.Render([]byte(src))
				if err != nil {
					t.Fatalf("render: %v", err)
				}
				assertNoLiveHTML(t, out)
			}
		})
	}
	// The whole committed corpus, in case a construct nobody thought of
	// produces an attribute value out of source.
	for _, name := range fixtureNames(t) {
		src := loadFixture(t, name)
		if len(src) > renderSizeLimit {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := r.Render(src)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			assertNoLiveHTML(t, out)
		})
	}
}

// assertNoLiveHTML checks the output for HTML that this package did not write.
//
// Passthrough bodies are removed first, and that is not a loophole: their
// contents are escaped by construction, so a `<script` inside one appears as
// `&lt;script` and can never match. What is left is only the markup the
// renderers emitted, and every tag and every attribute in it is ours to have
// written.
func assertNoLiveHTML(t *testing.T, out []byte) {
	t.Helper()
	live := stripPassthroughBodies(out)
	lower := strings.ToLower(string(live))
	for _, forbidden := range []string{
		"<script", "<iframe", "<object", "<embed", "<applet",
		"<style", "<link", "<meta", "<base", "<form",
		"<svg", "<math", "<foreignobject",
		"javascript:", "data:text/html", "data:application",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("the output contains %q, which is HTML this package does not write:\n%s",
				forbidden, truncate(out))
		}
	}
	// Every event-handler and URL-bearing attribute, found inside a real tag
	// rather than anywhere in the document.
	for i := 0; i < len(live); i++ {
		if live[i] != '<' || i+1 >= len(live) || !isTagNameByte(live[i+1]) {
			continue
		}
		j := i + 1
		for j < len(live) && live[j] != '>' {
			j++
		}
		tag := strings.ToLower(string(live[i:min(j, len(live))]))
		for _, forbidden := range []string{
			" on", "javascript:", "data:text", "formaction", "srcdoc", "xlink:href",
		} {
			if strings.Contains(tag, forbidden) {
				t.Errorf("the tag %q contains %q:\n%s", tag, forbidden, truncate(out))
			}
		}
		i = j
	}
}

func isTagNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '!'
}

// stripPassthroughBodies removes everything a passthrough node wrote between
// its opening and closing tags, leaving the tags themselves.
func stripPassthroughBodies(out []byte) []byte {
	keep := make([]byte, 0, len(out))
	for i := 0; i < len(out); {
		rel := bytes.Index(out[i:], []byte(` class="passthrough`))
		if rel < 0 {
			keep = append(keep, out[i:]...)
			break
		}
		start := i + rel
		open := bytes.IndexByte(out[start:], '>')
		if open < 0 {
			keep = append(keep, out[i:]...)
			break
		}
		end := start + open + 1
		closing := "</pre>"
		if bytes.HasPrefix(out[start:], []byte(` class="passthrough-inline`)) {
			closing = "</code>"
		}
		stop := bytes.Index(out[end:], []byte(closing))
		if stop < 0 {
			keep = append(keep, out[i:end]...)
			break
		}
		keep = append(keep, out[i:end]...)
		keep = append(keep, out[end+stop:]...)
		i = end + stop
	}
	return keep
}

func truncate(b []byte) string {
	if len(b) > 600 {
		return string(b[:600]) + "..."
	}
	return string(b)
}

// TestUnsupportedSyntaxIsEscapedPassthrough pins the escape hatch: a construct
// this package does not implement is shown as source, escaped, inside a
// labelled block. The reader is told what happened rather than shown a broken
// control, and the source is inert.
func TestUnsupportedSyntaxIsEscapedPassthrough(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"dataview query", "```dataview\nTABLE file\n```\n", "dataview"},
		{"dataviewjs", "```dataviewjs\nawait dv.pages()\n```\n", "dataview"},
		{"tasks query", "```tasks\nnot done\n```\n", "tasks-query"},
		{"excalidraw embed", "![[sketch.excalidraw]]\n", "excalidraw-embed"},
		{"excalidraw file embed", "![[battle.excalidraw.md]]\n", "excalidraw-embed"},
		{"canvas embed", "![[plan.canvas]]\n", "canvas-embed"},
		{"unknown callout", "> [!wombat] Not a known type\n> body\n", "callout"},
		{"html block", "<div class=\"x\">body</div>\n", "html-block"},
		{"inline html", "text with <b onerror=x>b</b> in it\n", "inline-html"},
		{"html comment", "<!-- a comment -->\n", "html-block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := r.Render([]byte(tc.src))
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !bytes.Contains(out, []byte(`class="passthrough"`)) &&
				!bytes.Contains(out, []byte(`class="passthrough-inline"`)) {
				t.Errorf("no passthrough block in the output:\n%s", out)
			}
			if !bytes.Contains(out, []byte(`data-passthrough="`+tc.want+`"`)) {
				t.Errorf("data-passthrough is not %q:\n%s", tc.want, out)
			}
			if !bytes.Contains(out, []byte(PassthroughLabel)) {
				t.Errorf("the passthrough is not labelled:\n%s", out)
			}
			assertNoLiveHTML(t, out)
		})
	}
}

// TestPassthroughShowsTheSourceEscaped is the other half: the label is present
// and the construct is legible, which is the whole point of showing it at all.
func TestPassthroughShowsTheSourceEscaped(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	out, err := r.Render([]byte("```dataview\n<script>alert(1)</script> & more\n```\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("&lt;script&gt;alert(1)&lt;/script&gt;")) {
		t.Errorf("the source is not escaped in the passthrough:\n%s", out)
	}
	if !bytes.Contains(out, []byte("```dataview")) {
		t.Errorf("the fence is not shown:\n%s", out)
	}
	if !bytes.Contains(out, []byte("&amp; more")) {
		t.Errorf("an ampersand in the source was not escaped:\n%s", out)
	}
}

// TestCanvasFileIsNotRenderedAsMarkdown: a canvas is JSON, and rendering JSON
// as Markdown produces a page of mangled punctuation.
func TestCanvasFileIsNotRenderedAsMarkdown(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	src := loadFixture(t, "canvas.md")
	d := Parse("plan.canvas", src)
	if !IsCanvas(d.Path) {
		t.Fatal("IsCanvas did not recognise the path")
	}
	out, err := r.RenderDoc(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`data-passthrough="canvas"`)) {
		t.Errorf("a canvas was not shown as source:\n%s", out)
	}
	if !bytes.Contains(out, []byte("&quot;nodes&quot;")) {
		t.Errorf("the canvas JSON is not escaped in the passthrough:\n%s", out)
	}
	if IsCanvas("notes/plan.md") {
		t.Error("a markdown file was taken for a canvas")
	}
}

// TestKnownCalloutsRenderAsCallouts is the positive half of the callout rule:
// a type this package knows gets a frame, a title, and a fold state; a type it
// does not know gets a passthrough.
func TestKnownCalloutsRenderAsCallouts(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	cases := []struct {
		src   string
		kind  string
		fold  string
		title string
		open  bool
	}{
		{"> [!note] Hello\n> body\n", "note", "", "Hello", true},
		{"> [!note]+\n> body\n", "note", ` data-callout-fold="+"`, "note", true},
		{"> [!note]-\n> body\n", "note", ` data-callout-fold="-"`, "note", false},
		{"> [!warning] Read this\n> body\n", "warning", "", "Read this", true},
		{"> [!tip]\n> body\n", "tip", "", "tip", true},
		// A callout whose title line runs into its body keeps the body and
		// loses the marker.
		{"> [!note] Title\n> body on the next line\n", "note", "", "Title", true},
		// +1 is a title, not a fold.
		{"> [!note]+1 wins\n> body\n", "note", "", "+1 wins", true},
		// A marker that is not at the start of the line is ordinary text.
		{"> this is only [!note] here\n> body\n", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.src[:min(24, len(tc.src))], func(t *testing.T) {
			t.Parallel()
			out, err := r.Render([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == "" {
				if !bytes.Contains(out, []byte("<blockquote>")) {
					t.Errorf("a non-callout block quote did not render as one:\n%s", out)
				}
				if !bytes.Contains(out, []byte("[!note]")) {
					t.Errorf("the marker text was dropped from a non-callout:\n%s", out)
				}
				return
			}
			if !bytes.Contains(out, []byte(`<details class="callout" data-callout="`+tc.kind+`"`)) {
				t.Errorf("no callout frame of type %s:\n%s", tc.kind, out)
			}
			if !bytes.Contains(out, []byte("<summary class=\"callout-title\">"+tc.title+"</summary>")) {
				t.Errorf("the title is wrong:\n%s", out)
			}
			if tc.fold == "" && bytes.Contains(out, []byte("data-callout-fold")) {
				t.Errorf("a fold marker was invented:\n%s", out)
			}
			if tc.fold != "" && !bytes.Contains(out, []byte(tc.fold)) {
				t.Errorf("the fold state is missing:\n%s", out)
			}
			// The open state is an attribute of the <details> tag, not the
			// presence of the tag.
			tag := out[:bytes.IndexByte(out, '>')+1]
			if got := bytes.Contains(tag, []byte(" open")); tc.open != got {
				t.Errorf("open = %v, want %v, in %s:\n%s", got, tc.open, tag, out)
			}
			if bytes.Contains(out, []byte("[!"+tc.kind+"]")) {
				t.Errorf("the marker survived into the output:\n%s", out)
			}
		})
	}
}

// TestCalloutsNestAndSitInLists covers the two placements that change the
// block's own extent, which is what the passthrough range depends on.
func TestCalloutsNestAndSitInLists(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	nested, err := r.Render([]byte("> [!info] Outer\n> > [!tip] Inner\n> > body\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(nested, []byte(`class="callout"`)) != 2 {
		t.Errorf("the nested callouts did not both render:\n%s", nested)
	}
	inList, err := r.Render([]byte("- item\n  > [!note] in a list\n  > body\n- second\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(inList, []byte(`data-callout="note"`)) {
		t.Errorf("a callout in a list item did not render:\n%s", inList)
	}
}

// TestHighlightsAndComments covers the two inline constructs goldmark-obsidian
// does not implement. Rendered as literal text they would look broken; a
// comment that renders at all is a spoiler.
func TestHighlightsAndComments(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	cases := []struct {
		src    string
		want   string
		absent []string
	}{
		{src: "a ==marked== word\n", want: "<mark>marked</mark>"},
		{src: "no highlight here\n", absent: []string{"<mark>"}},
		{src: "a == b is a comparison\n", absent: []string{"<mark>"}},
		{src: "=== is not a highlight\n", absent: []string{"<mark>"}},
		{src: "visible %%hidden%% visible\n", absent: []string{"hidden", "%%"}},
		{src: "%%multi\nline\ncomment%% after\n", absent: []string{"comment", "%%"}},
		// An unterminated comment is not a comment: the rest of the file is
		// ordinary Markdown, markers and all. Swallowing it instead would
		// delete a page's content over a stray `%%`.
		{src: "%% never closed\n\nafter\n", absent: nil},
	}
	for _, tc := range cases {
		t.Run(tc.src[:min(24, len(tc.src))], func(t *testing.T) {
			t.Parallel()
			out, err := r.Render([]byte(tc.src))
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if tc.want != "" && !bytes.Contains(out, []byte(tc.want)) {
				t.Errorf("the output does not contain %q:\n%s", tc.want, out)
			}
			for _, absent := range tc.absent {
				if bytes.Contains(out, []byte(absent)) {
					t.Errorf("the output contains %q:\n%s", absent, out)
				}
			}
			// Whatever the comment did, the text after it has to survive.
			if bytes.Contains([]byte(tc.src), []byte("after")) &&
				!bytes.Contains(out, []byte("after")) {
				t.Errorf("the text after the comment was lost:\n%s", out)
			}
		})
	}
}

// TestWikilinksResolveToVaultURLs pins the href shape. The renderer deliberately
// does not consult the index: a link to a page that does not exist yet still
// has to render as a link, or the editor loses the text.
func TestWikilinksResolveToVaultURLs(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	cases := []struct {
		src  string
		want string
	}{
		{"[[Gundren]]", `href="/p/Gundren"`},
		{"[[Party/Tavern]]", `href="/p/Party/Tavern"`},
		{"[[Gundren|alias]]", `href="/p/Gundren"`},
		{"[[Gundren#Flaws]]", `href="/p/Gundren#Flaws"`},
		// goldmark percent-escapes the destination, so a `^` and a space
		// arrive as %5E and %20. That is what the browser decodes before
		// looking an element up, so the fragment still reaches the id.
		{"[[Gundren#^blk]]", `href="/p/Gundren#%5Eblk"`},
		{"[[#Same page]]", `href="#Same%20page"`},
		{"![[portrait.png]]", `src="portrait.png"`},
		{"[md](Gundren.md)", `href="Gundren.md"`},
	}
	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			t.Parallel()
			out, err := r.Render([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(out, []byte(tc.want)) {
				t.Errorf("the output does not contain %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestRenderIsSafeUnderConcurrency: one Renderer is built at boot and shared by
// every request, so it must carry no state. A sanitizer map on the renderer
// would be a data race, not a slow path.
func TestRenderIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()
	r := New(Options{})
	corpus := loadCorpus(t)
	done := make(chan string, 8)
	for range 8 {
		go func() {
			for name, src := range corpus {
				if len(src) > renderSizeLimit {
					continue
				}
				if _, err := r.RenderDoc(Parse(name, src)); err != nil {
					done <- name + ": " + err.Error()
					return
				}
			}
			done <- ""
		}()
	}
	for range 8 {
		if msg := <-done; msg != "" {
			t.Fatal(msg)
		}
	}
}

// TestRenderStaysLinearOnAnAdversarialBody pins a number rather than a shape.
//
// The composite parser's inline loop is quadratic in the length of a single
// line: goldmark retries every inline parser at every trigger byte, and the
// wikilink parser rescans the line for its closing delimiter each time. This
// package's own scanners are linear, which is why the guard is on the render
// and not on the parse.
//
// The bound is thirty times the measured cost, so it fails on a regression
// rather than on a slow machine. It is here because the exposure is a denial
// of service any player can reach by pasting a long run of `[` into a note,
// and a test that measures it is the only thing that will notice the day
// somebody swaps the composite parser for one that is worse.
func TestRenderStaysLinearOnAnAdversarialBody(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("timing bound")
	}
	r := New(Options{})
	src := []byte(strings.Repeat("[", 64<<10))
	doc := Parse("flood.md", src)

	// The byte-level pipeline is linear, so this is the tight bound.
	start := time.Now()
	Parse("flood.md", src)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("parsing 64 KiB of '[' took %v; the scanner is not linear", elapsed)
	}

	start = time.Now()
	if _, err := r.Render(doc.PublicBody()); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Errorf("rendering 64 KiB of '[' took %v; the composite parser is quadratic "+
			"and a page a player can save is enough to reach it", elapsed)
	}
	t.Logf("64 KiB of '[' renders in %v", elapsed.Round(time.Millisecond))
}
