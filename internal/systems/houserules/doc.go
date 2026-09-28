// Package houserules is the reference feature plugin: a filterable index of the
// campaign's house rules, and a search resolver that contributes them to /search.
//
// It exists as the evidence for the other half of the plugin architecture.
// dnd5e proves what a KindSystem may claim — reserved page-type ids, an editor,
// a panel, a migration — and this proves what a KindFeature may claim, which is
// almost nothing and has to be enough: navigation, routes and a derived search
// row. Everything here is built out of the frontmatter convention `type:
// houserule`, so the plugin registers no page type, owns no table and runs no
// migration. A page carrying that convention renders with the core Markdown
// viewer and is read by the core FTS whether or not this plugin is installed;
// the whole contribution is a way to *find* those pages, and a way that is
// authz-filtered because it asks the store with a principal rather than reading
// the vault.
//
// The files are split by what they own. plugin.go is the Plugin implementation
// and the static declaration behind it — capabilities, navigation, the search
// resolver — plus the one place this package asks the store a question.
// hostcall.go is the two halves the host calls into, the HTTP handlers, and the
// view model. index.templ is markup over Go values this package owns. None of
// them contains a script, a style or a DOM handle, because the Host interface
// has no method that could install one.
//
// **The one section this package does not render, and why.** A house-rule index
// with a "rules the table can see" section and a "rules only the DM sees" section
// is the obvious design, and this package ships the first and not the second. The
// gate is not the obstacle — the principal is reachable, through
// authz.PrincipalFrom on the request context, and reader() in plugin.go is that
// one call site. The obstacle is the content model:
//
//   - A page is a file, and a file has no visibility. What can be hidden is text
//     *inside* a page, in a secret fence, and that is filtered when the page is
//     read. store.ListPagesByType carries no secret predicate and store.Page has
//     no visibility column, so there is no such thing as a DM-only house-rule
//     *page* for an index to hold back.
//   - The only per-page signal a plugin could invent is a frontmatter key, and
//     nothing else in the app would enforce it. A player who cannot see the
//     section can still open the page at /p/{path}, because the page is in the
//     file tree, the tag cloud, the command palette and every backlink under the
//     same rules. So a second section would advertise rules it does not protect,
//     under a heading that tells the reader which side of it they are standing on.
//   - A rule that genuinely has to stay private is a page whose *body* is a
//     `visibility=dm` fence. A fence is not something a page index can list, and
//     the page that holds it is listed for everyone, which is why the note on the
//     page tells an author that.
//
// The limits, stated rather than left for a reader to infer:
//
//   - It is a *convention*, not a page type. This plugin does not create,
//     validate, edit or render a house rule; it lists pages that already carry
//     `type: houserule`, and an author who deletes that line removes the page
//     from this index while changing nothing about the page itself. The fixture
//     under testdata/ is ten ordinary Markdown files carrying it, plus one page
//     of another type that the index must not list, and the tests are driven off
//     those files rather than off a hand-written row — so the convention is
//     exercised as Markdown and not as a Go literal.
//
//   - It reads no page text. The store hands a plugin titles, paths, frontmatter
//     and the page's own tags — `store.Page` has no body column at all — so the
//     search row's summary is assembled from the same named frontmatter keys the
//     filter uses. The core FTS already answers a body search under the canonical
//     predicate, and a second path to page text would only ever be a path around
//     that predicate.
//
//   - It never names a principal. reader() resolves the request's own; there is
//     no default, no fallback and no anonymous stand-in, so a context that lost
//     its principal yields the zero Principal, which cannot read public content,
//     and the page renders its empty state. Losing a request's identity fails
//     closed, and a source-level test holds the package to that: `authz.Anonymous`
//     and `authz.ForUser` are forbidden outright, and `authz.PrincipalFrom` is
//     allowed exactly once.
//
//   - It ships no interactivity. Every control on the page is a link or a form
//     that navigates, because the page is a standalone document that loads the
//     stylesheet and no script: a plugin may not reference app.js, and a
//     control wired to nothing is the affordance-with-nothing-behind-it §7 of
//     the working agreement calls a bug.
//
//   - It mounts no write route. The Markdown file stays canonical; a house rule
//     is edited by editing the file, and nothing on this page writes to it.
package houserules
