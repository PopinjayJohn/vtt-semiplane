package web_test

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// templatesFS carries the .templ sources into the test binary, so the check runs
// against what is written rather than against what has been generated from it.
// The generated *_templ.go is not the source of the names — the templates are.
//
// The sprite and the templates drift.
//
// It happened once: the shell referenced six symbols the sprite did not have,
// and the cost of that is a row of invisible `<use>` elements — a missing glyph,
// a collapsed width, and nothing at all in the console. Every icon in this
// codebase is paired with a text label or an `sr-only` span precisely so a
// missing symbol costs a glyph rather than a message, which is a mitigation and
// not a fix: the fix is not being able to reference a symbol that is not there.
//
// So this is that check, and it reads both halves out of the repository rather
// than out of a hand-maintained list, because a hand-maintained list is the
// same list, one more place to forget.

var (
	// iconUseRe finds a symbol reference in a template or in app.js.
	iconUseRe = regexp.MustCompile(`\bi-[a-z][a-z0-9-]*\b`)
	// iconSymbolRe finds a defined symbol in the sprite.
	iconSymbolRe = regexp.MustCompile(`<symbol id="(i-[a-z0-9-]+)"`)
	// iconComponentRe finds the icons the Icon component is handed by name.
	iconComponentRe = regexp.MustCompile(`@Icon\("(i-[a-z0-9-]+)"`)
)

// TestEveryReferencedIconIsDefinedInTheSprite is the whole claim.
func TestEveryReferencedIconIsDefinedInTheSprite(t *testing.T) {
	t.Parallel()

	defined := map[string]bool{}
	for _, m := range iconSymbolRe.FindAllStringSubmatch(spriteSource(t), -1) {
		defined[m[1]] = true
	}
	if len(defined) == 0 {
		t.Fatal("the sprite defines no symbols at all: it is not being read where the test thinks it is")
	}

	for file, src := range templateSources(t) {
		// Only the names the template hands to a component, plus anything that
		// already looks like a reference. A bare word matching i-… in prose is
		// not a symbol, so the set is drawn from the two shapes that are.
		names := map[string]bool{}
		for _, m := range iconComponentRe.FindAllStringSubmatch(src, -1) {
			names[m[1]] = true
		}
		for _, m := range iconUseRe.FindAllString(src, -1) {
			names[m] = true
		}
		for name := range names {
			if strings.Contains(name, "-") && !defined[name] {
				t.Errorf("%s references %q, which web/static/icons.svg does not define", file, name)
			}
		}
	}
}

// TestTheIconsAreHandDrawnAndEmbeddable guards the two properties the sprite
// needs to have independently of what references it: nothing that makes the
// browser go and fetch something, and no script, because it is inlined into the
// binary and served same-origin.
//
// The check is on the attributes that fetch, not on the text. An SVG document
// carries `xmlns="http://www.w3.org/2000/svg"`, and a namespace identifier is a
// name the parser compares strings against — it is never resolved — so a grep for
// a scheme finds one and reports a violation that does not exist. What matters is
// an element that asks for a resource.
func TestTheIconsAreHandDrawnAndEmbeddable(t *testing.T) {
	t.Parallel()
	src := spriteSource(t)
	// Anything that makes the browser fetch: a url() in a paint, an image
	// reference, a style import, a script.
	for _, forbidden := range []string{"url(", "<image", "<script", "onload=", "@import", "xlink:href", "href=\"http", "href='http", "src="} {
		if strings.Contains(src, forbidden) {
			t.Errorf("the sprite contains %q: it is inlined into the binary and served from /_/assets/", forbidden)
		}
	}
	if !strings.Contains(src, `xmlns="http://www.w3.org/2000/svg"`) {
		t.Error("the sprite has no SVG namespace: it will not parse as SVG at all")
	}
}

// spriteSource is the shipped sprite, read out of the embedded assets.
//
// It is the embed rather than the file on disk because the embed is what is
// served, and a test that read the working tree would pass against a sprite the
// binary does not carry.
func spriteSource(t *testing.T) string {
	t.Helper()
	f, err := web.Assets().Open("icons.svg")
	if err != nil {
		t.Fatalf("the sprite is not in the embedded assets: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read the sprite: %v", err)
	}
	return string(b)
}

// templateSources is every template in the package, by file name.
func templateSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the template directory: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".templ") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("no templates were found: the test is not looking where it thinks it is")
	}
	return out
}
