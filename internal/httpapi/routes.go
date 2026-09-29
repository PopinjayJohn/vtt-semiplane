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
	// Pattern is the row's address, and it is both what a reader types and what
	// a failing subtest prints: "/p/*/raw" is the URL the raw view lives at.
	//
	// It is not always the pattern handed to chi. A trailing /* is chi's
	// catch-all and its value is read with chi.URLParam(r, "*"); the named
	// form, /p/{path...}, is not what chi v5 implements and yields an empty
	// value, which would make every page 404 for a reason no test would name.
	// A /* in the *middle* cannot be mounted at all — see pagedispatch.go for
	// the measurement — so the segments after it are the template that tells
	// this row apart from its siblings on the one shared catch-all. That is
	// the whole of the difference, and it is derived from Pattern by
	// mountPattern and selectTemplate rather than stated again in a field, so
	// the table cannot hold two addresses for one route.
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

		// The page-scoped surfaces. Every one of them shares the /p/* catch-all
		// with the page row and with each other, and each is one row here with
		// its own permission, its own CSRF treatment and its own handler;
		// pagedispatch.go holds the measurement that forces the shape and the
		// tie-break that makes it unambiguous.
		//
		// They are in one block because they are one idea, and a row added
		// somewhere else in the table is a row a reader will not connect to the
		// catch-all it is hung off.
		//
		// raw is a text/plain response rather than a view, for the reason in
		// pageraw.go: the answer is a file, and a file rendered as HTML is
		// either escaped into uselessness or raw, and raw is not available.
		{Method: http.MethodGet, Pattern: "/p/*/raw", Perm: authz.PermReadPage, Handle: s.rawPage},
		// The editor and the revert are the two writes.
		//
		// The Perm column is PermSession, not PermWritePage, and that is a
		// deliberate reading of the table's own contract rather than a weaker
		// gate. permit() asks the policy with a zero Resource, so a PermWritePage
		// column is answered "is this a DM" and its ownership arm is unreachable;
		// the real, page-scoped decision — which carries this page's ownership —
		// is the one mayWritePage makes inside the handler, and it is the check
		// the secrets service makes before it writes. Gating on the coarse one
		// as well would make the redacted editor unreachable over HTTP: §8.9
		// exists so a player may edit the public parts of a page a DM has put a
		// secret on, and a DM-only column answers 403 to exactly that player
		// before the handler runs.
		//
		// The coarse gate therefore stays where it can do work, on the surfaces
		// that are genuinely campaign-wide, and the per-page decision is made
		// once, in one function, where the page row is already loaded.
		{Method: http.MethodGet, Pattern: "/p/*/edit", Perm: authz.PermSession, Handle: s.editForm},
		{Method: http.MethodPost, Pattern: "/p/*/edit", Perm: authz.PermSession, Handle: s.editSubmit},
		// History and one revision are reads, re-authorised at read time: a
		// revision recorded before a revoke is refused after it. The revert is
		// a write and is authorized as an edit, not as a read of the revision.
		{Method: http.MethodGet, Pattern: "/p/*/history", Perm: authz.PermReadPage, Handle: s.historyPage},
		{Method: http.MethodGet, Pattern: "/p/*/revisions/{revID}", Perm: authz.PermReadPage, Handle: s.revisionPage},
		{Method: http.MethodPost, Pattern: "/p/*/revert/{revID}", Perm: authz.PermSession, Handle: s.revertPage},
		// §8.8's serve path. The name is {name...} and not {name} because an
		// attachment's recorded path is vault-relative and may sit in a
		// subdirectory; {name} binds one segment and would refuse to serve
		// every file under assets/.
		{Method: http.MethodGet, Pattern: "/p/*/attachment/{name...}", Perm: authz.PermReadPage, Handle: s.attachment},

		// Reveal and revoke, §8.3. The Perm column is PermDM rather than
		// PermSession for a reason the editor's rows do not share: ownership buys
		// the right to author a secret, never the right to broadcast it, so
		// asking the page-scoped question here would be asking the wrong one. A
		// page owner reaches the page and the editor and not this.
		//
		// The service asks the same policy again before it looks anything up, so
		// the gate here is the coarse outer one and the refusal that matters is
		// the one that cannot enumerate a secret id.
		{Method: http.MethodPost, Pattern: "/p/*/secrets/{secretID}/reveal", Perm: authz.PermDM, Handle: s.revealSecret},
		{Method: http.MethodPost, Pattern: "/p/*/secrets/{secretID}/revoke", Perm: authz.PermDM, Handle: s.revokeSecret},

		// The export is a page-scoped read, redacted to what the reader may read,
		// for the reason the raw view is: it is the same file, and a second
		// spelling of it that did not redact would be a way around the redaction
		// the raw view already does.
		{Method: http.MethodGet, Pattern: "/p/*/export", Perm: authz.PermReadPage, Handle: s.exportPage},

		// The broken-links panel. PermReadPage rather than PermAnonRead, so an
		// unauthenticated reader with anonymous read off is sent to the login
		// form: a panel that lists where the campaign refers to itself is
		// content, and the list is filtered by the same predicate a page render
		// is.
		{Method: http.MethodGet, Pattern: "/broken", Perm: authz.PermReadPage, Handle: s.brokenLinksPage},

		// Renaming a page and the opt-in bulk link updater (§5.6), on the same
		// two-layer gate as the editor: PermSession here, the page-scoped
		// PermWritePage inside the handler by mayWritePage.
		//
		// The rename is the only one of the three that moves a file, and it does
		// not touch a single referring page: it returns a pointer to the updater
		// rather than running it, because rewriting twelve links in somebody
		// else's prose is the reader's decision and not the app's.
		{Method: http.MethodPost, Pattern: "/api/pages/{id}/rename", Perm: authz.PermSession, Handle: s.renamePage},
		// The preview is a read of the same decision, and it is where the
		// per-page permission is checked, so a reader is never told twelve links
		// will update when only four can.
		{Method: http.MethodGet, Pattern: "/api/pages/{id}/rename-preview", Perm: authz.PermSession, Handle: s.renamePreview},
		// The update is the confirmed write. confirmed=true is required: without
		// it the route answers 400 and touches nothing.
		{Method: http.MethodPost, Pattern: "/api/pages/{id}/update-links", Perm: authz.PermSession, Handle: s.updateLinks},

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

		// The secret audit trail, on PermAuditSecrets rather than PermAdmin and
		// deliberately not on PermDM: the constant's name is the only thing
		// standing between a future surface and a permission row that answers a
		// different question, and folding it into PermDM would have closed the
		// gap AGENTS.md §2.6a records by accident and left the name lying.
		{Method: http.MethodGet, Pattern: "/admin/secrets", Perm: authz.PermAuditSecrets, Handle: s.adminSecretsPage},
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
//
// The loop is over *groups* rather than over rows, because several rows mount
// on one chi pattern and chi silently overwrites a handler registered twice for
// the same method and pattern. A group of one row that owns its pattern is
// mounted as before; anything sharing a catch-all gets the dispatcher, which
// picks the row and then runs that row's own gates — so the table's per-row
// permissions and CSRF treatment still apply to the row that was actually
// selected, which is the property the matrix is derived from.
func (s *Server) router() http.Handler {
	r := chi.NewRouter()
	for _, g := range groupsOf(s.Routes()) {
		r.Method(g.method, g.pattern, s.groupHandler(g))
	}
	r.NotFound(s.notFound)
	r.MethodNotAllowed(s.methodNotAllowed)
	s.mountPluginRoutes(r)
	return r
}

// groupHandler is the mounted handler for one group of table rows.
func (s *Server) groupHandler(g mountGroup) http.Handler {
	if len(g.rows) == 1 && g.rows[0].Pattern == g.pattern {
		// A row that owns its pattern: nothing to tell apart, so the gates go
		// straight on it.
		return s.routeHandler(g.rows[0])
	}
	return s.catchAllHandler(g)
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
