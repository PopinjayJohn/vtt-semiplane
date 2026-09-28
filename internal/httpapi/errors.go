package httpapi

import (
	"net/http"
)

// errorCopy is the one shape every non-2xx response uses.
//
// Each status has a fixed heading and a fixed detail. There is no field a
// caller can fill in, and that is the whole point: the body shown to a viewer
// who may not read a page has to be byte-identical to the body shown for a
// page that does not exist, and the only way to guarantee two renderings are
// identical is for there to be nothing in the model that could differ.
//
// A request id would differ. A page title would differ. A path would differ, and
// it would also confirm that the path exists. So none of them is here: the
// request id is in a response header, which is where a person debugging a
// failure reads it, and nowhere else.
var errorCopy = map[int]struct{ heading, detail string }{
	http.StatusNotFound: {
		heading: "Not found",
		detail:  "There is no page at that address. It may have been renamed, or it may never have existed.",
	},
	http.StatusForbidden: {
		heading: "Not allowed",
		detail:  "Your account may not do that. If you think that is wrong, ask the campaign's administrator.",
	},
	http.StatusUnauthorized: {
		heading: "Sign in",
		detail:  "That action needs an account.",
	},
	http.StatusMethodNotAllowed: {
		heading: "Wrong method",
		detail:  "That address does not answer to this kind of request.",
	},
	http.StatusTooManyRequests: {
		heading: "Too many requests",
		detail:  "Wait a minute and try again.",
	},
	// 400 and 503 are here because a route that needs them arrived before this
	// table had them, and the fallback in writeError turns a missing entry into a
	// 500. A 500 is a claim that the server broke; a 400 is a claim that the
	// request was wrong. Confusing the two is how a client bug becomes an
	// on-call question.
	http.StatusBadRequest: {
		heading: "That request did not make sense",
		detail:  "The address asked for something this page cannot answer. Check it and try again.",
	},
	http.StatusServiceUnavailable: {
		heading: "Not ready",
		detail:  "The server is shutting down or not ready yet. Try again in a moment.",
	},
	http.StatusInternalServerError: {
		heading: "Something went wrong",
		detail:  "The server could not complete that request. Nothing was changed.",
	},
	http.StatusRequestHeaderFieldsTooLarge: {
		heading: "Request too large",
		detail:  "That request carried more than the server will read.",
	},
}

// writeError renders the error page for a status.
//
// It is the only writer of a non-2xx body in this package, which is what makes
// "every error page has the same shape" a property of the code rather than a
// convention. The error that caused it, if there was one, is never passed in:
// there is no parameter to pass it in, so there is no way for a caller to leak a
// vault path or a fragment of a secret into an error page by mistake.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int) {
	text, ok := errorCopy[status]
	if !ok {
		text = errorCopy[http.StatusInternalServerError]
		status = http.StatusInternalServerError
	}
	// An error response is never cached: a shared cache between two principals
	// is precisely the place a 403 and a 200 for the same URL would be confused.
	w.Header().Set("Cache-Control", "no-store")
	// The status goes out before the body. A template writes bytes, and the
	// first write is what commits a 200, so an error page rendered without this
	// line would be a successful response carrying an apology — which is the
	// one shape that would make the matrix's statuses meaningless.
	w.WriteHeader(status)
	v := ErrorView{
		Shell:   s.shell(r, http.StatusText(status)),
		Status:  status,
		Heading: text.heading,
		Detail:  text.detail,
	}
	if err := s.Render(w, r, v); err != nil {
		// The renderer itself failed. There is nothing left to say except the
		// status line, and a plain-text body is the honest fallback rather than
		// a second attempt at HTML that would fail the same way.
		s.log.Error("the error page could not be rendered",
			"action", "http.error", "status", status, "err", logRecord(err).String())
		_, _ = w.Write([]byte(text.heading + ".\n"))
	}
}

// shell is the part of a view model the layout needs, read once per response.
//
// The title is passed in rather than derived, because a page's title is vault
// content and an error page must not have one: the caller names a constant for
// every status and a page names its own title only when it has been authorized
// to show it.
func (s *Server) shell(r *http.Request, title string) Shell {
	return Shell{
		Title:     title,
		Principal: PrincipalFrom(r.Context()),
		CSRF:      CSRFFrom(r.Context()),
		Campaign:  s.campaign,
		Dev:       s.cfg.Dev,
		// The plugin nav group is chrome, so it belongs here rather than in the
		// handlers. It was set in four handlers, and the sidebar then gained and
		// lost a section as the reader moved between a page and the file tree — a
		// layout that reflows itself is a layout nobody can build a mental model
		// of, and the fix is one line in the function every shell goes through.
		//
		// It is nil-safe on a nil registry, which is the ordinary case for a build
		// with no plugins, and the sidebar renders no group at all rather than an
		// empty one.
		PluginNav: s.pluginNav(r),
		// Same reasoning, same place: whether previews exist is chrome too, and
		// setting it in the handlers that happened to have a plugin would make
		// the affordance depend on which surface the reader is looking at.
		PreviewsEnabled: s.hasSummaryProvider(),
	}
}
