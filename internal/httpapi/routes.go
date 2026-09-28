package httpapi

import (
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// PermNone is the route table's "no permission" column value.
//
// It is the zero Permission, and the Perm middleware skips its check for it.
// Every other value is a real permission that the policy answers, including the
// ones that exist to be refused: a route with a typo in its permission fails
// closed, because authz.Policy refuses a permission it does not know rather
// than defaulting to allow. The three routes that legitimately need no
// permission — /login, /invite/{token} and the two probes — are the ones whose
// entire purpose is to be reachable by somebody who is not yet known.
const PermNone authz.Permission = ""

// Route is one row of the route table.
//
// The table is the contract. A route that is not in it does not exist, and the
// two tests that walk it — the authorization matrix and the CSRF check — are
// therefore derived from the same list the router mounts, so neither can drift
// from what is actually served.
type Route struct {
	// Method is the HTTP method. Every method that is not GET or HEAD is
	// checked for a CSRF token, which is why the table is the source of that
	// list rather than a separate one.
	Method string
	// Pattern is the chi route pattern. A trailing /* is chi's catch-all and its
	// value is read with chi.URLParam(r, "*"); the named form, /p/{path...}, is
	// not what chi v5 implements and yields an empty value, which would make
	// every page 404 for a reason no test would name.
	Pattern string
	// Perm is the permission the policy is asked about, or PermNone.
	Perm authz.Permission
	// Handle is the handler. It receives a resolved principal and a view model
	// and never inspects a role.
	Handle http.HandlerFunc
}

// Name is the route's stable identity: the method and the pattern together. A
// log line and a test's subtest name both use it, so a failure names the route
// the way the table does.
func (rt Route) Name() string { return rt.Method + " " + rt.Pattern }

// Mutating reports whether the route changes something, which is exactly the
// condition the CSRF gate applies to: anything that is not a safe method.
func (rt Route) Mutating() bool {
	switch rt.Method {
	case http.MethodGet, http.MethodHead:
		return false
	default:
		return true
	}
}

// Routes returns the route table.
//
// It is a function rather than a package-level slice because the handlers are
// methods on a Server, and a global holding them would be global mutable state
// holding a whole application. The order is the order the router mounts them
// in, and chi matches on the pattern rather than the position, so the order
// exists for the reader and not for the dispatch.
func (s *Server) Routes() []Route {
	return []Route{
		{Method: http.MethodGet, Pattern: "/", Perm: authz.PermAnonRead, Handle: s.home},

		{Method: http.MethodGet, Pattern: "/p/*", Perm: authz.PermReadPage, Handle: s.page},

		{Method: http.MethodGet, Pattern: "/login", Perm: PermNone, Handle: s.loginForm},
		{Method: http.MethodPost, Pattern: "/login", Perm: PermNone, Handle: s.loginSubmit},
		{Method: http.MethodPost, Pattern: "/logout", Perm: authz.PermSession, Handle: s.logout},

		{Method: http.MethodGet, Pattern: "/setup", Perm: authz.PermSetupOpen, Handle: s.setupForm},
		{Method: http.MethodPost, Pattern: "/setup", Perm: authz.PermSetupOpen, Handle: s.setupSubmit},

		{Method: http.MethodGet, Pattern: "/invite/{token}", Perm: PermNone, Handle: s.inviteForm},
		{Method: http.MethodPost, Pattern: "/invite/{token}", Perm: PermNone, Handle: s.inviteAccept},

		{Method: http.MethodGet, Pattern: "/search", Perm: authz.PermAnonRead, Handle: s.searchPage},
		{Method: http.MethodGet, Pattern: "/api/search", Perm: authz.PermAnonRead, Handle: s.searchAPI},

		{Method: http.MethodGet, Pattern: "/tags", Perm: authz.PermAnonRead, Handle: s.tagsPage},
		{Method: http.MethodGet, Pattern: "/tag/{name}", Perm: authz.PermAnonRead, Handle: s.tagPage},

		// The boot report. It is the only surface that says *why* a panel is
		// missing, which is why it exists rather than a line in the log: a plugin
		// that fails silently fails permanently, and the one reader who can fix
		// it is an administrator. Admin-only because it names the host's granted
		// capabilities, which is a description of what this binary will do for
		// whom.
		{Method: http.MethodGet, Pattern: "/admin/plugins", Perm: authz.PermAdmin, Handle: s.adminPluginsPage},
		{Method: http.MethodGet, Pattern: "/files", Perm: authz.PermAnonRead, Handle: s.filesPage},

		// The one call a page view needs for its whole context column: the table
		// of contents, the backlinks, the related pages and the campaign status
		// in a single round trip. Four routes would have been four authorizations
		// and four chances for one of them to be answered under a different rule
		// than the other three.
		{Method: http.MethodGet, Pattern: "/api/pages/{id}/context", Perm: authz.PermReadPage, Handle: s.pageContextAPI},

		// The command palette's data source. It is PermSession rather than
		// PermAnonRead because every row it returns is a destination inside the
		// campaign, and an anonymous reader with anonymous read on has the
		// campaign already: the palette is an affordance, not a capability.
		{Method: http.MethodGet, Pattern: "/_/commands", Perm: authz.PermSession, Handle: s.commandsAPI},

		// The live-update stream. See events.go for why it carries a trigger and
		// never content.
		{Method: http.MethodGet, Pattern: "/_/events", Perm: authz.PermSession, Handle: s.events},

		// A link preview's content. It is core-owned rather than a route the
		// linkpreview plugin mounts, and the reason is the 404.
		//
		// AGENTS.md §7 requires a summary of a page the viewer may not read to be
		// byte-identical to navigating to that page, and that byte-identity is
		// enforced by httpapi.writeError rendering a fixed errorCopy table with
		// nothing in the model that could differ between two renderings. A route
		// mounted by a plugin cannot reach writeError — it is unexported, and
		// httpapi is on the plugin boundary's forbidden list — so a plugin-owned
		// summary route could only approximate the requirement, and a preview that
		// renders a distinguishable 404 is a way to probe for pages.
		//
		// So the route is here and the plugin supplies the card body. That is also
		// the division §2.8.2 asks for: the plugin supplies content, core owns
		// behaviour. It is PermReadPage rather than something weaker because the
		// decision it makes is exactly that one, and the policy is the only place
		// a role is compared.
		{Method: http.MethodGet, Pattern: "/plugin/{id}/summary/{pageID}", Perm: authz.PermReadPage, Handle: s.pageSummary},

		{Method: http.MethodGet, Pattern: "/healthz", Perm: PermNone, Handle: s.healthz},
		{Method: http.MethodGet, Pattern: "/readyz", Perm: PermNone, Handle: s.readyz},

		{Method: http.MethodGet, Pattern: "/_/assets/*", Perm: PermNone, Handle: s.asset},
	}
}

// router mounts the route table behind the per-route gates.
//
// The two gates are inside the chain and inside the route, and Perm is the outer
// of the two: a route that does not exist for this principal answers with the
// route's own answer, whatever the request carried. That is the more useful
// answer and the more honest one — a closed /setup is a 404 whether the request
// was authorised or not, and it must not become a 403 for an unauthorised one,
// because a permission-shaped answer is a fact about the router.
//
// CSRF is applied only to a mutation. A safe method has no state to forge, so
// gating one would mean every page load needed a token the browser had not
// fetched yet, and the failure would be a blank page rather than a refused
// write.
func (s *Server) router() http.Handler {
	r := chi.NewRouter()
	for _, rt := range s.Routes() {
		var h http.Handler = rt.Handle
		if rt.Mutating() {
			h = s.checkCSRF(h)
		}
		h = s.permit(rt)(h)
		// context.Set keeps the matched pattern reachable from the request
		// record without the log carrying a page path and a title in it.
		pattern := rt.Pattern
		inner := h
		r.Method(rt.Method, pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			inner.ServeHTTP(w, req.WithContext(withValue(req.Context(), routeKey, pattern)))
		}))
	}
	r.NotFound(s.notFound)
	r.MethodNotAllowed(s.methodNotAllowed)
	s.mountPluginRoutes(r)
	return r
}

// mountPluginRoutes mounts every registered plugin's sub-router under its own
// prefix, behind the same two gates the table applies.
//
// The gates are re-applied here rather than inherited, and that is the whole
// point of the function. `chain` wraps the router, so a mounted sub-router is
// already behind Session, RateLimit and the headers — but `checkCSRF` and
// `permit` are applied per row inside the table loop, and a mount is not a row.
// Without this, a plugin's POST would run with no CSRF check and no permission,
// which is a hole in a boundary whose entire claim is that a plugin cannot
// escape it.
//
// The permission is the plugin's *least* requirement rather than a per-plugin
// one, because the host has no vocabulary for "the permission this route needs"
// and inventing one would let a plugin name its own gate. PermSession is the
// ceiling: a plugin surface is for signed-in members of the campaign, and a
// plugin that needs less can already serve anonymous readers through the pages
// those readers may already read.
func (s *Server) mountPluginRoutes(r *chi.Mux) {
	if s.plugins == nil {
		return
	}
	for _, owned := range s.plugins.Routes() {
		if owned.Value == nil {
			continue
		}
		// The prefix is derived from the registry's own record of which plugin
		// owns the router, never from anything the plugin said, so a plugin
		// cannot mount at a prefix it does not own.
		prefix := plugin.PluginPrefix(owned.Plugin)
		rt := Route{Method: "*", Pattern: prefix + "/*", Perm: authz.PermSession}
		var h http.Handler = owned.Value
		h = s.checkCSRF(h)
		h = s.permit(rt)(h)
		pattern := rt.Pattern
		inner := h
		r.Mount(prefix, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			inner.ServeHTTP(w, req.WithContext(withValue(req.Context(), routeKey, pattern)))
		}))
	}
}

// Table returns the route patterns and permissions without a Server, for a
// caller that wants to assert the table's shape without booting one — a
// documentation generator, or the boot report.
func (s *Server) Table() []string {
	out := make([]string, 0, len(s.Routes()))
	for _, rt := range s.Routes() {
		out = append(out, rt.Name()+" → "+string(rt.Perm))
	}
	return out
}
