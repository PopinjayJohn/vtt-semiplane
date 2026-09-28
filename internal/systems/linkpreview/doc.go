// Package linkpreview is the link-preview feature plugin: the body of the card
// core shows when a reader hovers or focuses an internal link.
//
// It is the smallest interesting plugin in the tree, and the size is the point.
// Everything a reader does to a link preview — the hover intent delay, the
// transient role="tooltip" card, the pin toggle, the floating pane, Esc, the
// ARIA wiring, the rate limit, the 404 — belongs to core, in
// internal/httpapi/preview.go and web/static/app.js. What is left over for a
// plugin is one templ.Component: what the card says about a page. A plugin that
// contributed behaviour as well would be a second implementation of focus
// management, an arbitrary-script hole in the CSP, and a per-plugin
// accessibility bug.
//
// So this package declares one capability, registers no page type, no nav item,
// no table and no route, and answers exactly one question: given a page id,
// what does a card say?
//
// # The endpoint is core's
//
// GET /plugin/linkpreview/summary/{pageID} is mounted by core, not by this
// package, and RegisterRoutes here mounts nothing. A summary of a page the
// viewer may not read has to answer with the same bytes as navigating to that
// page, and those bytes come from httpapi's writeError, which renders a fixed
// table with nothing a caller can fill in. writeError is unexported and httpapi
// is on the plugin boundary's forbidden list, so a plugin-owned route could only
// approximate the requirement — and a preview with a distinguishable 404 is a
// way to probe for pages. Core owns the answer; the plugin owns the content.
//
// # The principal
//
// Summary is handed a context.Context and a page id, and plugin.PageStore — the
// only data surface a plugin is given — takes an authz.Principal on every one of
// its four methods. The bridge between them is authz.PrincipalFrom, which reads
// the principal the session middleware resolved and which lives in the package
// that owns Principal rather than in the one that happens to resolve it.
//
// That placement is the whole of it. httpapi's own context key is an unexported
// type behind an unexported variable, so a plugin could see a principal on a
// context and not be able to ask for it: ctx.Value needs a key, and there was no
// way to name that one. There is exactly one key and exactly one writer now, so
// no two layers can disagree about who is asking.
//
// The rules below are in order of how badly each would end. It never guesses an
// id-to-principal mapping. It never hands PageStore a fabricated DM, which would
// put DM-secret tags in a player's card. It never renders a page the store
// declined. And it does not check for a missing principal before asking: a
// context that never went through WithPrincipal yields the zero Principal, which
// is anonymous and cannot read public content, so the store declines every page
// and the answer is the 404 a missing page gets. Losing a request's identity
// fails closed here, which is the only direction a preview is allowed to fail.
package linkpreview
