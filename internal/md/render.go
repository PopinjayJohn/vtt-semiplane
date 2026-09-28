package md

import (
	"bytes"
	"strings"

	mathjax "github.com/litao91/goldmark-mathjax"
	obsidian "github.com/powerman/goldmark-obsidian"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
	"go.abhg.dev/goldmark/mermaid"
	"go.abhg.dev/goldmark/wikilink"
)

// PassthroughLabel is the visible caption carried by every passthrough block.
// It is one constant so the stylesheet, the tests and a screen reader all name
// the same thing, and so the phrase is greppable in an integration test.
const PassthroughLabel = "Unsupported Obsidian syntax — shown as source"

// Options configures a Renderer.
type Options struct {
	// Extend are extra goldmark extenders, applied after the core composite.
	// The plugin phase appends its extenders here; the constructor is
	// deliberately the only place the parser is assembled so there is exactly
	// one composite parser per Renderer.
	Extend []goldmark.Extender
	// WikilinkResolver turns a wikilink into a URL. Nil selects VaultResolver.
	WikilinkResolver wikilink.Resolver
	// Typographer enables goldmark's smart-quote and smart-dash extension. It
	// is off by default because it rewrites the user's punctuation on the way
	// out, and §5.3 requires the render to be a faithful view of the file.
	Typographer bool
}

// Renderer holds the composite goldmark parser. It is immutable after
// construction and safe for concurrent use, so one instance is built at boot
// and shared by every request.
//
// Raw HTML in vault content is never rendered. html.WithUnsafe is not set and
// must not be set: a vault file is user content, and rendering its HTML would
// make every saved note a stored-XSS vector for every other user in the game.
// TestRawHTMLIsNotRendered is the gate.
type Renderer struct {
	md       goldmark.Markdown
	resolver wikilink.Resolver
}

// New builds a Renderer from the core composite plus the caller's extenders.
//
// The core composite is goldmark's GFM (tables, strikethrough, linkify, task
// lists), footnotes, and goldmark-obsidian, which layers Obsidian's wikilinks,
// embeds, block references, tags, properties, mermaid and math on top. Math
// is switched to Obsidian's `$$` delimiters because the defaults are LaTeX's
// `\(...\)`, which a campaign page has never contained.
//
// The module set is built against goldmark v1, not goldmark/v2: every one of
// the three extensions implements goldmark.Extender, whose signature in v2 is
// `Extend(goldmark.Markdown)` and goldmark/v2 no longer exports a Markdown
// façade at all.
func New(opts Options) *Renderer {
	res := opts.WikilinkResolver
	if res == nil {
		res = VaultResolver{}
	}
	extenders := []goldmark.Extender{
		extension.GFM,
		extension.Footnote,
		obsidian.NewObsidian().
			WithWikilinkResolver(res).
			WithMathJaxOptions(
				mathjax.WithInlineDelim("$", "$"),
				mathjax.WithBlockDelim("$$", "$$"),
			).
			// NoScript keeps the mermaid extension from appending a <script>
			// tag that fetches mermaid from cdn.jsdelivr.net. §2.5 forbids a
			// request from a remote origin in the request path, and this is
			// the only place in the composite that would have added one. The
			// diagram is still emitted as a <pre class="mermaid"> holding its
			// source; whether anything renders it is the web phase's decision,
			// and it can only be made with an asset this repository serves.
			WithMermaid(mermaid.Extender{NoScript: true}),
		// obsidian installs wikilink itself; this one is registered with the
		// same resolver, so whichever wins registration the result is the
		// same and the composite does not silently depend on that order.
		&wikilink.Extender{Resolver: res},
	}
	if opts.Typographer {
		extenders = append(extenders, extension.Typographer)
	}
	extenders = append(extenders, opts.Extend...)

	md := goldmark.New(goldmark.WithExtensions(extenders...))
	// Registered after the html renderer, whose Register is a map keyed by
	// node kind, so these replace the defaults for HTMLBlock and RawHTML.
	md.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(passthroughRenderer{}, passthroughPriority),
		util.Prioritized(calloutRenderer{}, calloutPriority),
		util.Prioritized(highlightRenderer{}, highlightPriority),
	))
	md.Parser().AddOptions(parser.WithInlineParsers(
		util.Prioritized(highlightParser{}, highlightPriority),
		util.Prioritized(commentParser{}, highlightPriority-1),
	))
	return &Renderer{md: md, resolver: res}
}

// Markdown returns the underlying goldmark instance, for a caller that needs
// to install a further extender or renderer after construction. Prefer
// Options.Extend: building the composite in one place is the only reason the
// parser is auditable.
func (r *Renderer) Markdown() goldmark.Markdown { return r.md }

// Resolver returns the wikilink resolver in force.
func (r *Renderer) Resolver() wikilink.Resolver { return r.resolver }

// Render converts a public body to HTML.
//
// src must already be free of secret content: RenderDoc enforces that by
// feeding it Doc.PublicBody, and there is no path from a secret span to this
// function. The sanitize pass that runs between parsing and rendering replaces
// every construct this package does not implement with an escaped passthrough,
// so the only HTML in the output is HTML this package wrote.
func (r *Renderer) Render(src []byte) ([]byte, error) {
	return r.render(r.md.Parser().Parse(text.NewReader(src)), src)
}

// RenderDoc converts a document's public body to HTML. A secret span is never
// an input, and a canvas file is not Markdown at all, so its whole body is
// shown as source.
func (r *Renderer) RenderDoc(d *Doc) ([]byte, error) {
	body := d.PublicBody()
	if IsCanvas(d.Path) {
		return passthroughBytes(body, "canvas"), nil
	}
	return r.render(r.md.Parser().Parse(text.NewReader(body)), body)
}

// Parse builds the AST for a body without the passthrough rewrite, for callers
// that want structure rather than HTML. The extractor uses it: it needs the
// wikilink and hashtag nodes, which the rewrite would have swallowed.
func (r *Renderer) Parse(src []byte) ast.Node {
	return r.md.Parser().Parse(text.NewReader(src))
}

// ParseDoc builds the AST for a document's whole body, secrets included. The
// facts extracted from it carry the Span they came from, so a fact found
// inside a secret is attributed to that secret and every consumer filters on
// the secret id rather than on the text.
func (r *Renderer) ParseDoc(d *Doc) ast.Node {
	return r.Parse(d.Body)
}

func (r *Renderer) render(doc ast.Node, src []byte) ([]byte, error) {
	sanitize(doc, src)
	var buf bytes.Buffer
	if err := r.md.Renderer().Render(&buf, src, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// VaultResolver turns a wikilink into the app's canonical URL: a
// vault-relative path under /p/ for anything without an extension, and the
// path itself for a file that has one, which is how an attachment is named.
// The `#fragment` is appended verbatim so that a heading or block reference
// survives the hop.
//
// It deliberately does not consult the index. Resolution to a page id, with
// the shortest-path and lexicographic tie-breaks, is Resolver's job, and
// keeping that out of the renderer means an unresolvable link still renders as
// a link to where the page will be rather than silently disappearing.
type VaultResolver struct{}

// ResolveWikilink implements wikilink.Resolver.
func (VaultResolver) ResolveWikilink(n *wikilink.Node) ([]byte, error) {
	target := n.Target
	dest := make([]byte, 0, len(target)+len(pageURLPrefix)+2)
	if len(target) > 0 {
		if !hasExtension(target) {
			dest = append(dest, pageURLPrefix...)
		}
		dest = append(dest, target...)
	}
	if len(n.Fragment) > 0 {
		dest = append(dest, '#')
		dest = append(dest, n.Fragment...)
	}
	return dest, nil
}

// pageURLPrefix is the canonical page URL root, matching store.Page.Href.
const pageURLPrefix = "/p/"

// hasExtension reports whether a link target names a file rather than a page.
//
// A target with a URI scheme is never a file, whatever its last component
// looks like: `https://example.invalid` has a dot in its host, and calling that
// an attachment sends an outbound link to the vault's attachment handler.
func hasExtension(target []byte) bool {
	if bytes.Contains(target, []byte("://")) {
		return false
	}
	lower := bytes.ToLower(target)
	if bytes.HasPrefix(lower, []byte("mailto:")) ||
		bytes.HasPrefix(lower, []byte("tel:")) ||
		bytes.HasPrefix(lower, []byte("data:")) {
		return false
	}
	if i := bytes.LastIndexByte(target, '/'); i >= 0 {
		target = target[i+1:]
	}
	return bytes.IndexByte(target, '.') > 0
}

// IsCanvas reports whether a vault-relative path names an Obsidian canvas.
// A canvas is JSON, not Markdown: rendering it as Markdown would produce a
// page of mangled punctuation, so it is shown as source instead.
func IsCanvas(p string) bool {
	return strings.HasSuffix(strings.ToLower(normalizePath(p)), ".canvas")
}
