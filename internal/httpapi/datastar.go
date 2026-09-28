package httpapi

import (
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// webRegionCommandGroups is the renderer's name for the palette's rows.
//
// It is spelled here rather than imported from internal/web, because the
// dependency arrow runs httpapi → web and not the other way round: web imports
// httpapi for the view models, so httpapi naming a region is how a region is
// requested without the import that would make a cycle. web maps it back to its
// own component, and a name it does not map is an error at render time rather
// than an empty panel.
const webRegionCommandGroups = "command-groups"

// Why the palette is not answered with a DataStar element patch.
//
// The obvious implementation of an in-place swap is the bundle's
// `datastar-patch-elements` event, and that was the first thing written here. It
// does not work, and the reason is worth recording so nobody tries it again.
//
// The vendored bundle (v1.0.4) reads a patch as an event stream. Its SSE
// accumulator joins every `data:` line into ONE message with a space — not a
// newline — and the consumer then splits that message on newlines and takes each
// line as a name, a space and a value. A frame of three `data:` lines therefore
// arrives as a single entry named `selector` whose value is the rest of the
// frame, and the element the client patches with is the string " mode inner
// elements <section…". Nothing throws. The palette simply stays empty.
//
// The other candidate is worse rather than better. The bundle branches on the
// response's content type before anything else: an `application/json` response is
// dispatched as `datastar-patch-signals` and merged into the reactive signal
// store. A palette answering with JSON does not render a palette — it writes
// every matched page's title into the document's signal state, where any signal
// expression can read it and the next fetch's request headers can carry it.
//
// So the palette asks for a fragment with an ordinary query parameter and the
// client puts it in the DOM. The bytes are still produced by the same templ
// component, through the same authorized handler, under the same principal; the
// only thing that changed is the envelope, and the envelope is the part that was
// guesswork. `TestThePaletteAnswersWithHTMLRatherThanAPatch` is the test that
// keeps a future edit from "fixing" this back into a guess.

// fragmentParam is the query parameter that asks for the bare region.
//
// It is a parameter rather than a header because a header would be negotiated
// against a bundle, and the one thing learned here is that the bundle's contract
// is not knowable from the outside with confidence. A parameter is ours.
const fragmentParam = "fragment"

// patchIntoParam is the query parameter naming which region to return.
//
// The name comes from the client and the element it is rendered into does not:
// the client asks for "the palette" and the server decides that means the
// dialog's rows. A client that could name the element could name any element on
// the page, and the server would write a fragment rendered for one purpose into
// it — so a name the server has not heard of is a 400 rather than a guess.
const patchIntoParam = "into"

// regionTarget is one named region a fragment request may ask for.
//
// The set is closed and it is a table rather than a value at a call site,
// because the client picks from this and the server owns what each name means.
var regionTargets = map[string]string{
	"palette": webRegionCommandGroups,
	"page":    webRegionCommandGroups,
}

// defaultRegionName is what a fragment request gets when it names nothing.
//
// It is the palette rather than the page because the palette's fetch is the one
// that can arrive without a name, and a blank palette is the failure a reader
// notices; the page's own results region is a fallback a reader can reach by
// scrolling.
const defaultRegionName = "palette"

// writeRegion answers a fragment request with the bare region, as HTML.
//
// It is not JSON and not an event stream, and those are the two shapes the
// client would misinterpret. `text/html` is the one content type the client
// treats as markup, and the body is the same component the full page renders, so
// a row in the fragment and a row on the page are the same bytes — which is what
// makes the two answers comparable at all.
func (s *Server) writeRegion(w http.ResponseWriter, r *http.Request, view View, param, fallback string) error {
	target := r.URL.Query().Get(param)
	if target == "" {
		target = fallback
	}
	region, ok := regionTargets[target]
	if !ok {
		// writeError, not a bare status: the page is what a reader sees when a
		// client asks for a region that does not exist, and a reader is what this
		// is for.
		s.writeError(w, r, http.StatusBadRequest)
		return nil
	}
	body, err := s.view.Region(view, region)
	if err != nil {
		s.log.ErrorContext(r.Context(), "a region could not be rendered",
			"action", "http.region", "request_id", obs.RequestID(r.Context()),
			"region", region, "err", logRecord(err).String())
		s.writeError(w, r, http.StatusInternalServerError)
		return nil
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// The body carries page titles, so it is marked private for the same reason
	// searchAPI is: a shared cache between two principals must not keep it.
	h.Set("Vary", "Cookie")
	_, err = w.Write(body)
	return err
}
