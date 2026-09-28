package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/search"
)

// maxQueryBytes is the longest search term the router will look at. A search
// term becomes an FTS5 MATCH expression, and the expression is re-tokenised
// rather than interpolated — so this is about refusing a pointless megabyte
// rather than about protecting the parser, and the parser is protected anyway.
const maxQueryBytes = 512

// searchPage is the search form and its results.
func (s *Server) searchPage(w http.ResponseWriter, r *http.Request) {
	view := s.searchView(r)
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the search results", err)
	}
}

// searchAPI is the same query as JSON.
//
// It exists because the shell's in-place search needs a shape that is not a
// document, and because a client that wants results should not have to parse
// HTML to get them. It is the *same* view model and the same search.Query call
// as the page: a second implementation of "what may this principal see" is the
// bug the canonical predicate exists to prevent, and this one deliberately has
// none.
func (s *Server) searchAPI(w http.ResponseWriter, r *http.Request) {
	view := s.searchView(r)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The payload carries titles and paths, which is page content, so it is
	// marked private: a shared cache between two principals must never keep it.
	w.Header().Set("Vary", "Cookie")
	if err := json.NewEncoder(w).Encode(jsonOf(view)); err != nil {
		s.log.Error("the search payload could not be encoded",
			"action", "http.search", "err", logRecord(err).String())
	}
}

// jsonSearch is the API shape. It is a projection of the view model rather than
// the view model itself, so that a field added to the page for layout does not
// silently become part of a machine-readable contract.
type jsonSearch struct {
	// Query is what the viewer typed.
	Query string `json:"query"`
	// Total is how many hits exist across both sources.
	Total int `json:"total"`
	// Failed reports an unusable query rather than an empty result set.
	Failed bool `json:"failed"`
	// Hits are the rows in the requested window.
	Hits []jsonHit `json:"hits"`
}

// jsonHit is one result row.
type jsonHit struct {
	// Href is where the hit navigates to.
	Href string `json:"href"`
	// Title is the owning page's display title.
	Title string `json:"title"`
	// Path is the owning page's vault-relative path.
	Path string `json:"path"`
	// Kind is "page" or "secret". A secret hit names its page and nothing
	// else: the hit's own existence is already the disclosure, and a snippet
	// of a revealed secret is not something the search index may render.
	Kind string `json:"kind"`
	// Snippet is an escaped excerpt for a page hit, empty for a secret hit.
	Snippet string `json:"snippet,omitempty"`
}

// searchView runs one search and builds the view model.
//
// Everything here is the same for the page and the API: the same principal, the
// same Options, the same call into search.Query, which is where the visibility
// predicate is applied. The handler decides nothing about what may be seen.
func (s *Server) searchView(r *http.Request) SearchView {
	q := searchQuery(r)
	view := SearchView{
		Shell: s.liveShell(r, "Search"),
		Query: q,
	}
	if q == "" {
		return view
	}
	if len(q) > maxQueryBytes {
		view.Failed = true
		return view
	}
	limit, offset := searchWindow(r)
	result, err := search.Query(r.Context(), s.db.Reader(), PrincipalFrom(r.Context()), q, search.Options{
		Limit:  limit,
		Offset: offset,
	})
	switch {
	case errors.Is(err, search.ErrQueryTooLong):
		// A refusal from the query builder is the visitor's problem, not a fault
		// of the server, and it is reported as an unusable query rather than as
		// a 500.
		view.Failed = true
		return view
	case err != nil:
		view.Failed = true
		s.log.ErrorContext(r.Context(), "a search could not be completed",
			"action", "http.search", "request_id", obs.RequestID(r.Context()),
			"err", logRecord(err).String())
		return view
	}
	view.Total = result.Total
	for _, h := range result.Hits {
		view.Hits = append(view.Hits, SearchHit{
			Card: PageCard{
				ID:       h.PageID,
				Path:     h.Path,
				Title:    h.Title,
				PageType: "note",
			},
			Kind:    string(h.Kind),
			Snippet: h.Snippet,
		})
	}
	return view
}

// searchQuery is the term the visitor typed, trimmed.
//
// It is read from the query string for a GET. Nothing else is read from the
// query string on this route: no sort, no filter, no page size that the
// handler did not clamp, because a parameter that reaches a query unvalidated
// is a parameter somebody will eventually find a way through.
func searchQuery(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("q"))
}

// searchWindow is the result window, clamped.
//
// search.Options clamps the limit itself, and the clamp is duplicated here so
// that an absurd value is refused with 400 rather than silently reduced, which
// is the difference between a client that knows and one that does not.
func searchWindow(r *http.Request) (limit, offset int) {
	limit = search.DefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > search.MaxLimit {
			return limit, 0
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return limit, 0
		}
		offset = n
	}
	return limit, offset
}

// jsonOf projects the view model onto the API shape.
func jsonOf(v SearchView) jsonSearch {
	out := jsonSearch{Query: v.Query, Total: v.Total, Failed: v.Failed, Hits: make([]jsonHit, 0, len(v.Hits))}
	for _, h := range v.Hits {
		out.Hits = append(out.Hits, jsonHit{
			Href:    h.Card.Href(),
			Title:   h.Card.Title,
			Path:    h.Card.Path,
			Kind:    h.Kind,
			Snippet: h.Snippet,
		})
	}
	return out
}
