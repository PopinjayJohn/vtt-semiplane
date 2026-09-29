package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// The page-scoped dispatch, and the routing fact that forces it.
//
// **chi v5 cannot route /p/{path}/raw.** Three things were measured on
// chi v5.3.2, and TestTheCatchAllAndItsSuffixesAreUnambiguous asserts all
// three so that a future upgrade re-measures them rather than assuming:
//
//  1. Registering the pattern "/p/*/raw" **panics at registration**:
//     "chi: wildcard '*' must be the last value in a route". It is not a
//     pattern that fails to match; it is a pattern the trie refuses to hold.
//  2. "/p/{path...}", the v4 named-catch-all spelling the route table's
//     comment already warns about, matches only a single-segment path and
//     returns an **empty** value when it does. It is worse than useless: it
//     looks like it works.
//  3. "/p/{raw}" and "/p/{raw...}" are param nodes, and a param node cannot
//     span a "/". "/p/Guild/Cellar/Wine.md/raw" does not match either, so a
//     flat param only ever serves a page at the vault's root — and it *does*
//     shadow the page named raw.md at the root, because chi prefers the param
//     node for a one-segment path whichever order the two were registered in.
//
// So a page-scoped suffix is a property of the catch-all's *value*, not of the
// route pattern. Every such row shares one mounted chi pattern, and the rows are
// told apart by the trailing segments of what chi hands the handler — which is
// the only place in chi where "everything up to the last segment" is
// expressible, because the handler is handed the whole path as one string.
//
// The consequence worth knowing: two patterns that would be distinct routes are
// one route with a dispatcher, so the table stays the contract by carrying one
// row per surface — its own Perm, its own CSRF treatment, its own handler — and
// the dispatcher runs *that row's* wrapped chain, not a merged one.

// pageWildcard is the catch-all chi's route table spells a page-scoped pattern
// with. It is a trailing "/*" for the page row itself and a mid-pattern "/*"
// for every surface hung off a page.
const pageWildcard = "/*"

// selectionKey carries what the dispatch resolved: the page path with the
// selecting segments removed, and any named parameters the template bound.
var selectionKey = contextKey{"selection"}

// selection is one resolved page-scoped route.
type selection struct {
	// path is the vault-relative page path, with the selecting segments removed.
	// For the page row itself it is the whole value.
	path string
	// named holds the template's parameters, by name. It is nil for a template
	// that binds none.
	named map[string]string
}

// selectedPath is the vault-relative page path a page-scoped route is about.
func selectedPath(r *http.Request) string {
	if sel, ok := r.Context().Value(selectionKey).(selection); ok {
		return sel.path
	}
	// A route that is not page-scoped, or a request that reached a handler
	// without the dispatcher: the catch-all's own value is the best answer
	// there is, and the page handler has always read it that way.
	return chi.URLParam(r, "*")
}

// selectedParam is a named parameter bound by the selecting segments, and falls
// back to chi's own for a route that declares one in its pattern.
func selectedParam(r *http.Request, name string) string {
	if sel, ok := r.Context().Value(selectionKey).(selection); ok {
		if v, ok := sel.named[name]; ok {
			return v
		}
	}
	return chi.URLParam(r, name)
}

// mountGroup is the set of table rows that share one mounted chi pattern.
type mountGroup struct {
	// method is the HTTP method the group answers.
	method string
	// pattern is the chi pattern handed to the mux.
	pattern string
	// rows are the table rows mounted on it, in table order.
	rows []Route
}

// groupsOf splits the table into the routes it mounts.
//
// A row's Pattern is its identity in the table and the shape of the URL it
// answers; the mounted chi pattern is the part of it up to and including the
// wildcard. Two rows that share a mounted pattern share a mux entry, and the
// dispatcher is what tells them apart.
func groupsOf(routes []Route) []mountGroup {
	var out []mountGroup
	index := make(map[string]int, len(routes))
	for _, rt := range routes {
		mount := mountPattern(rt.Pattern)
		key := rt.Method + " " + mount
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, mountGroup{method: rt.Method, pattern: mount, rows: []Route{rt}})
			continue
		}
		out[i].rows = append(out[i].rows, rt)
	}
	return out
}

// mountPattern is the chi pattern a row mounts on: everything up to and
// including the wildcard, or the whole pattern when the wildcard is at the end
// or there is none.
//
// It is the one place that knows chi's rule, and it is a function rather than a
// field on Route so that a row cannot declare a mounted pattern that disagrees
// with its own — the two would then be two answers to "what is this route's
// address" and the table would no longer be the contract.
func mountPattern(pattern string) string {
	if i := strings.Index(pattern, pageWildcard); i >= 0 {
		return pattern[:i+len(pageWildcard)]
	}
	return pattern
}

// selectTemplate is what is left of a row's pattern after the mounted part: the
// trailing segments that pick the row out of a shared catch-all. It is empty
// for a row that owns its pattern, and for the page row itself — which is what
// makes "no template" mean "the page" rather than "nothing".
func selectTemplate(pattern string) string {
	if i := strings.Index(pattern, pageWildcard); i >= 0 {
		return strings.Trim(pattern[i+len(pageWildcard):], "/")
	}
	return ""
}

// selector matches one row's template against a catch-all's value.
//
// The grammar is three things and no more, because it is a routing decision
// and an open grammar is a runtime error in the middle of a request:
//
//   - a literal segment, compared for equality;
//   - {name}, which binds exactly one segment;
//   - {name...}, which binds one or more and must be last.
//
// The multi-segment form exists for one reason: an attachment's recorded path
// is vault-relative and may live in a subdirectory, so {name} would silently
// refuse to serve every attachment under assets/. A refused attachment is an
// image the reader can see in the page and cannot open, which is a broken
// control rather than a conservative answer.
type selector struct {
	// segments are the template's own segments, in order.
	segments []string
	// params names the parameters, in the order the segments bind them. It is
	// parallel to segments and holds "" for a literal.
	params []string
	// greedy is the index of the {name...} segment, or -1.
	greedy int
}

// parseSelector reads a template. A malformed one panics rather than returning
// an error, because there is nowhere at request time to report one and a
// template that does not parse would otherwise become a route that answers 404
// to every request for ever — the exact failure this file exists to prevent.
// The panic happens while the router is being built, which is boot.
func parseSelector(template string) selector {
	sel := selector{greedy: -1}
	for i, seg := range strings.Split(template, "/") {
		if seg == "" {
			panic("httpapi: an empty segment in the route template " + template)
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			name := seg[1 : len(seg)-1]
			if strings.HasSuffix(name, "...") {
				sel.greedy = i
				name = strings.TrimSuffix(name, "...")
			}
			if name == "" {
				panic("httpapi: an unnamed parameter in the route template " + template)
			}
			if sel.greedy >= 0 && i > sel.greedy {
				panic("httpapi: {name...} is not last in the route template " + template)
			}
			sel.params = append(sel.params, name)
		} else {
			sel.params = append(sel.params, "")
		}
		sel.segments = append(sel.segments, seg)
	}
	return sel
}

// match reports whether value is this row, and if so what page it is about.
//
// A value is never this row's when it has no page part at all: "/p/edit" is
// this template with an empty page, and the page row answers it (as a 404,
// because no page is named edit) rather than the editor answering for a page
// that was never named.
func (sel selector) match(value string) (string, map[string]string, bool) {
	segs := strings.Split(value, "/")
	if sel.greedy < 0 {
		k := len(sel.segments)
		if len(segs) <= k {
			return "", nil, false
		}
		return sel.bind(segs[:len(segs)-k], segs[len(segs)-k:])
	}
	// The greedy form. The literal block is matched at its LAST occurrence, so
	// the captured name is the shortest and the page path the longest: a value
	// of "a/attachment/attachment" is the page "a" with an attachment called
	// "attachment", and not the page "a/attachment" with one called nothing.
	// Taking the first occurrence instead would make which page an attachment
	// belongs to depend on a name someone chose for a file.
	lits := sel.greedy
	lo, hi := 1, len(segs)-lits-1
	if hi < lo {
		return "", nil, false
	}
	for i := hi; i >= lo; i-- {
		if !slices.Equal(segs[i:i+lits], sel.segments[:lits]) {
			continue
		}
		return sel.bind(segs[:i], segs[i:])
	}
	return "", nil, false
}

// bind checks the tail against the template and returns the page path.
func (sel selector) bind(path, tail []string) (string, map[string]string, bool) {
	if len(tail) != len(sel.segments) {
		return "", nil, false
	}
	var named map[string]string
	for i, want := range sel.segments {
		if sel.params[i] == "" {
			if tail[i] != want {
				return "", nil, false
			}
			continue
		}
		if tail[i] == "" {
			return "", nil, false
		}
		if named == nil {
			named = make(map[string]string, 1)
		}
		named[sel.params[i]] = tail[i]
	}
	return strings.Join(path, "/"), named, true
}

// catchAllHandler is the mounted handler for a group of rows that share one
// chi pattern.
//
// The page row wins a collision, and that is the one judgement call here. For a
// GET, "Tavern.md/raw" is either a page at the path Tavern.md/raw or the raw
// view of Tavern.md, and both readings are things the reader could already
// read: pages have no visibility, and the raw view is redacted to what the
// reader may read. Resolving it with a store lookup — so that a vault holding
// Guild/edit.md keeps that page openable — costs one indexed query, and only on
// the ambiguous shape: a value whose trailing segments match a template is the
// only place the question is asked at all. The alternative, letting the action
// win, would make a page named for a suffix unopenable, which is a broken
// control.
//
// A group with no page row — POST /p/*, which carries only the editor and the
// revert — asks nothing, because a POST to a page is not a thing: there is no
// reading of that URL that is a page, and spending a query to establish it would
// be a query on every write.
func (s *Server) catchAllHandler(g mountGroup) http.Handler {
	rows := make([]bound, 0, len(g.rows))
	var plain *bound
	for _, rt := range g.rows {
		tmpl := selectTemplate(rt.Pattern)
		if tmpl == "" {
			cp := bound{route: rt, handle: s.routeHandler(rt)}
			plain = &cp
			continue
		}
		rows = append(rows, bound{
			sel:    parseSelector(tmpl),
			route:  rt,
			handle: s.routeHandler(rt),
		})
	}
	// Longest template first, so a two-segment template is tried before a
	// one-segment one. Every template in the table starts with a distinct
	// literal, so this is not load-bearing today; it is here so that adding a
	// surface whose template is a prefix of another's does not depend on the
	// order two rows happen to be written in.
	sort.SliceStable(rows, func(i, j int) bool {
		return len(rows[i].sel.segments) > len(rows[j].sel.segments)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := chi.URLParam(r, "*")
		for _, b := range rows {
			path, named, ok := b.sel.match(value)
			if !ok {
				continue
			}
			if plain != nil && s.isPagePath(r.Context(), value) {
				break
			}
			b.serve(w, r, path, named)
			return
		}
		if plain != nil {
			plain.serve(w, r, value, nil)
			return
		}
		// A method the table has no row for, on a URL whose shape it does. The
		// router's own answer, not a 405: the path exists, but nothing on it
		// answers to this kind of request, and "there is no POST here" is not a
		// fact about a page.
		s.writeError(w, r, http.StatusNotFound)
	})
}

// isPagePath reports whether value names a page in the index.
//
// A read error is answered "no", and the reason is that the alternative is a
// 500 on a URL that is not broken: the action the value selected is about to
// read the very same page row, so a failure here shows up there with a proper
// error page, and answering "no" here only means the dispatcher chose the
// action.
func (s *Server) isPagePath(ctx context.Context, value string) bool {
	_, err := s.lookupPage(ctx, value)
	if err == nil {
		return true
	}
	if !errors.Is(err, store.ErrNoRows) {
		s.log.WarnContext(ctx, "the page-scoped dispatch could not tell a page from a surface",
			"reason", err.Error())
	}
	return false
}

// routeHandler wraps one table row in its two gates and stamps the route name
// on the request.
//
// The route name is stamped per row rather than per mounted pattern because a
// shared pattern is mounted once for several rows: a log line that said
// "/p/*" for an editor save would be a record that could not say which surface
// was written.
func (s *Server) routeHandler(rt Route) http.Handler {
	var h http.Handler = rt.Handle
	if rt.Mutating() {
		h = s.checkCSRF(h)
	}
	h = s.permit(rt)(h)
	return &stamped{pattern: rt.Pattern, next: h}
}

// stamped attaches the matched table row's pattern to the request context.
type stamped struct {
	pattern string
	next    http.Handler
}

func (st *stamped) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st.next.ServeHTTP(w, r.WithContext(withValue(r.Context(), routeKey, st.pattern)))
}

// serve runs a bound row's chain with the dispatch's answer on the context.
func serveSelected(w http.ResponseWriter, r *http.Request, rt Route, h http.Handler, path string, named map[string]string) {
	ctx := withValue(r.Context(), routeKey, rt.Pattern)
	ctx = withValue(ctx, selectionKey, selection{path: path, named: named})
	h.ServeHTTP(w, r.WithContext(ctx))
}

// bound is one row of a catch-all group with its wrapped chain.
type bound struct {
	sel    selector
	route  Route
	handle http.Handler
}

// serve runs this row's chain with the dispatch's answer on the context.
func (b bound) serve(w http.ResponseWriter, r *http.Request, path string, named map[string]string) {
	serveSelected(w, r, b.route, b.handle, path, named)
}
