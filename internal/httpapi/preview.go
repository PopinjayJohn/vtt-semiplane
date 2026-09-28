package httpapi

import (
	"bytes"
	"net/http"
	"strconv"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// The link preview's content endpoint.
//
// The design decision this file exists to record: the route is core's and the
// card body is the plugin's. §2.8.2 of the plan describes the plugin mounting
// GET /plugin/{id}/summary/{pageID}, and the code does not do that, and the
// divergence is deliberate rather than an omission.
//
// The requirement a summary has to satisfy is that a page the viewer may not
// read answers byte-identically to navigating to it, because a preview must not
// become a way to probe for pages. That byte-identity is a property of
// writeError, which renders a fixed errorCopy table with nothing a caller can
// fill in — no request id in the body, no title, no path. A plugin cannot
// produce it: writeError is unexported, and httpapi is on the plugin boundary's
// forbidden list precisely so a plugin cannot bypass the redaction and the Perm
// gate. A plugin-owned summary route would therefore have had to render its own
// 404, and a distinguishable one is the leak the requirement exists to prevent.
//
// So the plugin supplies content and core owns behaviour, which is the same
// division §2.8.2 states for the interaction, applied one layer further in.

// summaryRateWindow and summaryRateBurst are the preview route's own budget.
//
// Hovering a paragraph of links is a request amplifier if nothing bounds it, and
// the page-load budget is the wrong one to charge it against: a preview that
// spent the reader's page budget would make a normal reading session look like
// a scrape. The numbers are tight enough that sweeping the mouse across a page
// cannot fan out into a burst, and loose enough that a reader who actually
// previews twenty pages in a session is not refused.
const (
	summaryRateWindow = time.Minute
	summaryRateBurst  = 30
)

// pageSummary answers GET /plugin/{id}/summary/{pageID}.
//
// The four ways this can decline are one answer. No such page, a page the
// principal may not read, a plugin that registered no summary provider, and a
// provider that declines the page are all a 404 with the same bytes, because the
// only one a reader could otherwise tell apart is "this page exists and you may
// not have it" — and telling that apart from "this page does not exist" is
// exactly the probe the requirement forbids.
func (s *Server) pageSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	pluginID := chi.URLParam(r, "id")
	pageID, err := strconv.ParseInt(chi.URLParam(r, "pageID"), 10, 64)
	if err != nil || pageID <= 0 {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	// A summary is never cached: a shared cache between two principals is
	// precisely where a 404 and a 200 for the same URL would be confused, and
	// the pinned preview pane refetches on every authz change anyway.
	w.Header().Set("Cache-Control", "private, max-age=0")

	if !s.summaries.allow(r) {
		s.writeError(w, r, http.StatusTooManyRequests)
		return
	}

	provider, ok := s.summaryProvider(pluginID)
	if !ok {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	// The policy is asked, and the answer it gives is the coarse one: whether
	// this principal may read the campaign at all. That is worth asking here
	// because it is the question an anonymous reader with anonymous read off
	// must not get a summary answered for, and the answer belongs to the policy
	// rather than to a handler.
	//
	// It is not the page-level decision, and it is not pretending to be.
	// PermReadPage is a resource-free permission, and v1 has no per-page ACL —
	// what decides whether this page may be previewed is store.GetPageSummary
	// finding public text for it, and what keeps a secret out of the card is that
	// the text it returns never contained one. The policy guards the campaign;
	// the store guards the page.
	// The scope is the handler, not the if-statement: a shadowed err here would
	// make the check's own name mean something else for the rest of the
	// function, and the next reader would have to know which of the two they
	// were looking at before they could tell whether the policy was checked.
	if err = s.policy.Check(who, authz.PermReadPage, authz.Resource{PageID: pageID}); err != nil {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	body, ok, err := provider.Value.Summary(ctx, pageID)
	if err != nil {
		// A provider that fails is a 404 rather than a 500, and the reason is
		// that a 500 says "this page exists" to anyone who can tell the two
		// apart. The failure is still logged with its type and a hash, so it is
		// not silent.
		s.log.ErrorContext(ctx, "a page summary could not be produced",
			"action", "http.summary", "request_id", obs.RequestID(ctx),
			"plugin", pluginID, "err", logRecord(err).String())
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	if !ok || body == nil {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	// Buffered rather than streamed, because a component that fails halfway
	// through has already written a 200 by then. A preview card is small and a
	// half-written one is worse than none.
	var buf bytes.Buffer
	if err := body.Render(ctx, &buf); err != nil {
		s.log.ErrorContext(ctx, "a page summary could not be rendered",
			"action", "http.summary", "request_id", obs.RequestID(ctx),
			"plugin", pluginID, "err", logRecord(err).String())
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// summaryProvider finds the summary provider a plugin contributed.
//
// The lookup is by plugin id and there is exactly one provider per plugin in
// v1: a second would be a second card format for the same hover, and which one
// won would be a decision the reader cannot see or override.
func (s *Server) summaryProvider(pluginID string) (plugin.Owned[plugin.SummaryProvider], bool) {
	if s.plugins == nil {
		return plugin.Owned[plugin.SummaryProvider]{}, false
	}
	for _, owned := range s.plugins.Summaries() {
		if owned.Plugin == pluginID {
			return owned, true
		}
	}
	return plugin.Owned[plugin.SummaryProvider]{}, false
}

// summaryLimiter is the preview route's rate budget.
//
// It is a field on the Server rather than a package-level map keyed by one,
// for the reason the event registry is: AGENTS.md §4 forbids global mutable
// state, and a map keyed by *Server is a global that happens to be tidy.
//
// It is a separate bucket rather than a lower class on the general one because
// the two budgets answer different questions. The general bucket bounds a client
// that is abusing the app; this one bounds hover, which is a normal reading
// action that happens to be an HTTP request, and charging it against the abuse
// budget would let a reader who previews a lot spend the budget their page loads
// draw on.
type summaryLimiter struct {
	bucket *bucket
}

// allow spends one token for the request's address.
func (s *summaryLimiter) allow(r *http.Request) bool {
	if s.bucket == nil {
		return true
	}
	return s.bucket.allow(clientIP(r))
}

// hasSummaryProvider reports whether any plugin registered a summary provider.
//
// It exists so the shell can tell the client that the preview interaction is
// worth binding, rather than having every link on every page attempt a request
// that a build with no preview plugin will answer with a 404. Without it the
// graceful degradation AGENTS.md §7 asks for is still correct but noisy: a
// reader would hover a link, wait 300 ms, and see nothing appear, on every link
// in a campaign that has no previews at all.
func (s *Server) hasSummaryProvider() bool {
	return s.plugins != nil && len(s.plugins.Summaries()) > 0
}
