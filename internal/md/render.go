package md

import (
	"bytes"
	"regexp"
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
	return r.render(r.md.Parser().Parse(text.NewReader(src)), src, "")
}

// RenderDoc converts a document's public body to HTML. A secret span is never
// an input, and a canvas file is not Markdown at all, so its whole body is
// shown as source.
func (r *Renderer) RenderDoc(d *Doc) ([]byte, error) {
	body := d.PublicBody()
	if IsCanvas(d.Path) {
		return passthroughBytes(body, "canvas"), nil
	}
	return r.render(r.md.Parser().Parse(text.NewReader(body)), body, d.Path)
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

// render converts an AST to HTML. page is the vault-relative path the document
// is served at, or "" when the caller has no page to scope to — a fragment
// render, or a parse that is not going to be served as a page.
func (r *Renderer) render(doc ast.Node, src []byte, page string) ([]byte, error) {
	sanitize(doc, src)
	if page != "" {
		scopeReferences(doc, page)
	}
	var buf bytes.Buffer
	if err := r.md.Renderer().Render(&buf, src, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// attachmentURLPrefix is the one address a file is served on. There is
// deliberately no vault-wide attachment route (AGENTS.md §6): a file referenced
// only from inside a secret must not be reachable by a principal who may not
// read that secret, and a global route would be reachable by name rather than
// by decision.
const attachmentURLPrefix = "/attachment/"

// scopeReferences rewrites every reference in the document so it names an
// address this app serves: a page under /p/, or a file at the page's own
// attachment route.
//
// It is a walk and not a resolver change for three reasons, each of which is a
// constraint rather than a preference:
//
//   - The wikilink resolver is chosen once, in New, and Renderer is shared by
//     every request. A resolver that knew the page would have to read it from
//     mutable state on a shared object, which is a data race.
//   - The reference is not always a wikilink. `![alt](map.png)` is an
//     ast.Image and `[[map.png]]` is a wikilink.Node; only the second passes
//     through the resolver at all, so fixing the resolver would leave the
//     markdown-native forms broken. Both were shipped broken for exactly this
//     reason: a markdown link to a page rendered as a bare relative destination,
//     which resolves against /p/ and so names nothing.
//   - The rewrite happens before the resolver runs, and a target that already
//     names a file still reads as a file to the resolver, so it is passed
//     through unchanged rather than gaining a second /p/.
//
// The name is left raw. goldmark escapes the attribute it writes, and encoding
// here would encode twice.
func scopeReferences(doc ast.Node, page string) {
	prefix := []byte(pageURLPrefix + page + attachmentURLPrefix)
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *wikilink.Node:
			// A wikilink already reaches the resolver, which owns the page case.
			v.Target = scopeAttachment(prefix, v.Target)
		case *ast.Image:
			v.Destination = scopeDestination(prefix, v.Destination)
		case *ast.Link:
			v.Destination = scopeDestination(prefix, v.Destination)
		}
		return ast.WalkContinue, nil
	})
}

// scopeDestination addresses a markdown-native reference, which reaches neither
// the wikilink resolver nor scopeAttachment's file rule.
//
// A markdown link is vault-relative in Obsidian, so a bare name is a page and
// gains the /p/ root; a file is scoped to the page's attachment route, as a
// wikilink's would be. Four shapes are left alone, and each is left alone for a
// reason rather than by omission: a destination the author rooted, a destination
// with a URI scheme, a destination that climbs out of the vault with "..", and
// an empty one. A relative destination that survives this is one the vault's own
// router will answer or will refuse, and inventing an address for it here would
// be a link the author never wrote.
func scopeDestination(attachmentPrefix, dest []byte) []byte {
	if len(dest) == 0 || dest[0] == '/' || climbsOut(dest) || hasScheme(dest) {
		return dest
	}
	if isAttachment(dest) {
		return scopeAttachment(attachmentPrefix, dest)
	}
	out := make([]byte, 0, len(pageURLPrefix)+len(dest))
	out = append(out, pageURLPrefix...)
	return append(out, dest...)
}

// climbsOut reports whether a destination leaves the directory it is written in.
// Such a reference is not rewritten, because the address this app would give it
// does not exist and a plausible-looking one is worse than the relative form.
func climbsOut(dest []byte) bool {
	for _, seg := range bytes.Split(dest, []byte("/")) {
		if string(seg) == ".." {
			return true
		}
	}
	return false
}

// schemePrefix matches a URI scheme at the start of a destination.
//
// The rule is RFC 3986's and it is deliberately general rather than a list of
// the schemes this app happens to know: goldmark decides which schemes are
// dangerous, using the same shape, and a hand-written list is a list that can be
// one entry short. `javascript:alert(1)` with that entry missing is a rendered
// href containing javascript: — a link whose safety depended on a typo not
// being made.
var schemePrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)

// hasScheme reports whether a destination carries a URI scheme, and therefore
// is not something this app addresses.
func hasScheme(dest []byte) bool {
	return schemePrefix.Match(dest)
}

// scopeAttachment returns name addressed at the page, or unchanged when it does
// not name a file this page may serve.
//
// A name that is already rooted is left alone: an author who wrote an absolute
// path has answered the question themselves, and second-guessing it would
// rewrite a link that was never ours.
func scopeAttachment(prefix, name []byte) []byte {
	if len(name) == 0 || name[0] == '/' || !isAttachment(name) {
		return name
	}
	out := make([]byte, 0, len(prefix)+len(name))
	out = append(out, prefix...)
	return append(out, name...)
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
	// A target carrying a URI scheme is returned untouched, and that is a
	// security property rather than a courtesy. goldmark drops a dangerous
	// scheme from the href it writes — that is how a `javascript:` link becomes an
	// empty href — but it recognises the scheme by the shape of the destination.
	// Prefixing `/p/` here would turn `javascript:alert(1)` into
	// `/p/javascript:alert(1)`, which no longer looks like a scheme, so the
	// stripping would not happen and a link that was inert would become one the
	// page carried. Leaving it alone keeps the decision with the only component
	// that knows which schemes are dangerous.
	if hasScheme(target) {
		return target, nil
	}
	dest := make([]byte, 0, len(target)+len(pageURLPrefix)+2)
	if len(target) > 0 {
		if !isAttachment(target) {
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

// LinkHref is the URL a page link resolves to: /p/ for a target that names a
// page, and the page's own attachment route for one that names a file, with
// the fragment appended verbatim.
//
// It is exported so that there is exactly one place that knows the rule.
// ResolveWikilink cannot use it, because at render time an extension-bearing
// target is rewritten to the attachment route by scopeAttachment before the
// resolver runs, and the two have to agree about which one is which — but a
// caller that has a link row and wants the URL the renderer will emit has
// nothing else to consult. httpapi is that caller: it decorates the rendered
// anchors with the link-preview attribute by matching hrefs, and it once
// rebuilt this rule from the raw target and got the fragment encoding and the
// attachment route wrong, so the preview silently never appeared on a link with
// a heading or on a link that named a file.
//
// page is the vault-relative path of the page the link was written on, and is
// needed only for the file case. ok is false when the target names nothing this
// app can link: empty, or a URI with a scheme.
func LinkHref(target, page string) (string, bool) {
	target = strings.TrimSpace(target)
	name, fragment, hasFragment := strings.Cut(target, "#")
	if name == "" {
		return "", false
	}
	tb := []byte(name)
	if hasScheme(tb) {
		return "", false
	}
	var dest string
	switch {
	case !isAttachment(tb):
		dest = pageURLPrefix + name
	case page != "":
		dest = pageURLPrefix + page + attachmentURLPrefix + name
	default:
		// A file with no page to scope it to has no address here. Returning it
		// bare would hand the caller a string the router does not serve.
		return "", false
	}
	if hasFragment && fragment != "" {
		dest += "#" + fragment
	}
	return dest, true
}

// isAttachment reports whether a link target names a file this app serves from
// a page's attachment route, rather than a page.
//
// A Markdown target is a page even though it has an extension, so `[[Tavern.md]]`
// and `[the tavern](Tavern.md)` are links to the page and not to a file called
// Tavern.md sitting in Hub's attachments. This is the renderer's half of a rule
// the extractor already applied to itself — see the isMarkdownExt guards in
// extract.go — and the two halves had drifted, which is how a markdown link to a
// page came to be rendered at /p/Hub.md/attachment/Tavern.md: an address that
// resolves, so it looked plausible, and names nothing a reader can reach.
func isAttachment(target []byte) bool {
	return hasExtension(target) && !isMarkdownExt(string(target))
}

// pageURLPrefix is the canonical page URL root, matching store.Page.Href.
const pageURLPrefix = "/p/"

// hasExtension reports whether a link target names a file rather than a page.
//
// A target with a URI scheme is never a file, whatever its last component
// looks like: `https://example.invalid` has a dot in its host, and calling that
// an attachment sends an outbound link to the vault's attachment handler.
func hasExtension(target []byte) bool {
	if hasScheme(target) {
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
