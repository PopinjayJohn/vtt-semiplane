package httpapi

import (
	"net/http"
)

// Shape is the response shape one request asked for.
type Shape int

const (
	// ShapeDocument is a whole HTML page: what a browser gets when it follows a
	// link, and what a reader with JavaScript disabled always gets.
	ShapeDocument Shape = iota
	// ShapeFragment is the content region on its own: what an in-page
	// enhancement swaps in, and what the live-push path of a later phase will
	// ask a handler for when it re-renders under a subscriber's own principal.
	ShapeFragment
)

// String names the shape, for a log line and for a failing test.
func (s Shape) String() string {
	if s == ShapeFragment {
		return "fragment"
	}
	return "document"
}

// DataStarRequestHeader is the header DataStar 1.0 sets on a fetch it wants a
// fragment for. Its presence is the whole negotiation: there is no query
// parameter, no alternate URL and no second route, so a link in the rendered
// page and the same link followed by hand produce the same URL and the same
// permission check.
const DataStarRequestHeader = "Datastar-Request"

// Negotiate reports the response shape a request asked for.
//
// The rule is one header and nothing else. A handler called by a browser, a
// handler called by a test's httptest server, and a handler called by a later
// phase's live-push fan-out all go through this one function, so a fragment can
// never be produced by a code path that skipped the permission check, and a
// document can never be produced by one that forgot the shell.
//
// A missing or unrecognised header is ShapeDocument, which is the safe
// default: an unrecognised caller gets the whole page, and the whole page is
// exactly what a client that does not know about fragments needs.
func Negotiate(r *http.Request) Shape {
	if r != nil && r.Header.Get(DataStarRequestHeader) == "true" {
		return ShapeFragment
	}
	return ShapeDocument
}

// wantsFragment is Negotiate's predicate, for a caller that has the shape
// already and only wants the test.
func wantsFragment(r *http.Request) bool { return Negotiate(r) == ShapeFragment }
