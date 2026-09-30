// Package web holds the templ component library, the layouts, and the renderer.
//
// It sits at the top of the dependency graph: it may import httpapi for the
// view-model types, and nothing below it may import it. The one interface it
// implements is httpapi.Renderer, which has two methods — a whole document and a
// content region — and the region is the same component the document nests, so
// the two cannot drift.
//
// Rendered output is escaped by construction, and the only two places that mark a
// string unescaped are the named funnels in html.go: PreRendered for HTML the
// markdown renderer produced, and Escaped for a string another package in this
// codebase has already escaped. TestOnlyThisPackageMarksHTMLRaw in internal/httpapi
// walks the tree and fails on any other templ.Raw, which is what keeps the
// guarantee checkable rather than merely intended.
package web
