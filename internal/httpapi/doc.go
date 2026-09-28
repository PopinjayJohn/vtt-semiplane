// Package httpapi is the route table, the middleware chain, and the handlers.
//
// Middleware order, outermost first: Recoverer, RequestID, requestLogger (which
// writes through obs), SecureHeaders, Session, RateLimit, per-route Perm,
// per-route CSRF, handler. The Perm middleware is the only place a role is
// compared; a handler receives a resolved principal and a view model and never
// inspects a role.
//
// Every handler negotiates its response shape from the request — a whole document
// or the content region on its own — and ends by handing one view model to
// Server.Render. That single choke point is what lets a later phase's live-push
// path call a handler verbatim: the bytes a subscriber receives are the bytes the
// ordinary handler would have produced under that subscriber's own principal, in
// whichever shape that subscriber asked for.
//
// The view models live here rather than in internal/web because web sits above
// this package in the dependency order. The renderer is an interface, and
// internal/web is its implementation: the router decides what a request may see
// and the template library decides what the response looks like, and neither can
// grow an authorization rule the other has to know about.

package httpapi
