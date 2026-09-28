package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// The campaign status panel's windows.
//
// They are the plan's, and they are constants rather than numbers read from a
// request because a sidebar is not a paginated list: there is no "next" to
// press, and a panel that silently grew with the vault would be the one part of
// the shell a reader cannot scan.
const (
	// threadLimit is how many open threads the panel lists. ThreadCount is
	// counted over the identical predicate and is not derived from this, so a
	// panel with more threads than rows still says how many there are.
	threadLimit = 5
	// activityLimit is how many recently updated pages the panel lists, other
	// than the one open.
	activityLimit = 5
	// partyLimit is how many character sheets the party list shows.
	partyLimit = 8
	// relatedLimit is how many related pages the right column offers.
	relatedLimit = 6
)

// noSystemNote is the panel's statement that no game system is registered.
//
// It is a constant rather than an empty string because a missing plugin has to
// look like a missing plugin: a panel with a blank section reads as a panel that
// failed to render, and a reader who sees a blank asks for a bug report rather
// than an account of what the app does not have yet.
const noSystemNote = "No game system is registered for this campaign."

// liveShell is s.shell with the live-push seed filled in.
//
// PushEnabled is a property of the principal rather than of the surface: a
// stream is only ever opened for an authenticated one, so a view that renders
// the shell says so here instead of each handler remembering to.
func (s *Server) liveShell(r *http.Request, title string) Shell {
	shell := s.shell(r, title)
	shell.PushEnabled = PrincipalFrom(r.Context()).Authenticated()
	return shell
}

// campaignStatus builds the right column's campaign-wide panel.
//
// It is field-level authorized rather than all-or-nothing, and the rule is
// uniform: every list here is asked of the store with the viewer's own
// principal, and a field the reader may not see is *omitted* rather than
// blanked or locked. A player sees a smaller panel, not the same panel with
// holes in it — a lock standing where a session log would be tells the reader
// that a session log exists, which is the disclosure the omission avoids.
//
// excludeID is the page currently open, so the last-activity list does not
// spend one of its five rows on the page the reader is already reading. It is 0
// for a view that is not about a page, and no page has that id.
func (s *Server) campaignStatus(ctx context.Context, who authz.Principal, excludeID int64) (CampaignStatus, error) {
	db := s.db.Reader()
	status := CampaignStatus{SystemNote: noSystemNote}

	logs, err := store.ListTaggedPages(ctx, db, who, store.TagSession)
	if err != nil {
		return CampaignStatus{}, fmt.Errorf("httpapi: list the session logs: %w", err)
	}
	// A nil Session and a blanked one are different answers, and only the first
	// is safe: the second is a row-shaped hole that says a session log is there.
	if ref, ok := currentSession(logs); ok {
		status.Session = &ref
	}

	threads, err := store.ListOpenThreads(ctx, db, who, threadLimit)
	if err != nil {
		return CampaignStatus{}, fmt.Errorf("httpapi: list the open threads: %w", err)
	}
	threadCount, err := store.CountOpenThreads(ctx, db, who)
	if err != nil {
		return CampaignStatus{}, fmt.Errorf("httpapi: count the open threads: %w", err)
	}
	// The badge comes from the count query rather than from len(threads): the
	// list is windowed and the count is not, and a badge computed from a
	// windowed list would read as "that is all of them" when it is not.
	status.Threads = pageCards(threads)
	status.ThreadCount = threadCount

	activity, err := store.ListRecentPagesExcluding(ctx, db, who, excludeID, activityLimit)
	if err != nil {
		return CampaignStatus{}, fmt.Errorf("httpapi: list the recent pages: %w", err)
	}
	status.LastActivity = pageCards(activity)

	party, err := store.ListParty(ctx, db, who, partyLimit)
	if err != nil {
		return CampaignStatus{}, fmt.Errorf("httpapi: list the party: %w", err)
	}
	for _, member := range party {
		// Note is left empty: the one-liner beside a character sheet is a
		// system-specific value that no core code can produce, and a field that
		// is always empty in v1 is omitted by the template rather than rendered
		// blank. Owner is the account's display name, never its username — a
		// sidebar that printed usernames would hand every reader the identifier
		// of every player in the campaign.
		status.Party = append(status.Party, PartyMember{
			Card:  cardOf(member.Page),
			Owner: member.OwnerDisplayName,
		})
	}
	return status, nil
}

// currentSession picks the session log the panel names.
//
// The newest `date:` frontmatter wins, because that is a value an author wrote
// down. A log with no date is not the newest — it has no claim to be — but it is
// still a session log, so when no log carries a date the first one is named
// with an empty Date rather than the panel showing nothing at all. Ties keep the
// first row the store returned, so the answer does not depend on a sort this
// function would have to invent.
func currentSession(logs []store.Page) (SessionRef, bool) {
	if len(logs) == 0 {
		return SessionRef{}, false
	}
	pick, newest := 0, time.Time{}
	for i := 0; i < len(logs); i++ {
		day, ok := sessionDay(logs[i])
		if !ok {
			continue
		}
		if i == 0 || day.After(newest) {
			pick, newest = i, day
		}
	}
	row := logs[pick]
	fields := frontmatterOf(row)
	ref := SessionRef{
		Card: cardOf(row),
		// The number is the file's own `session:` value, and 0 when it declares
		// none. It is never inferred from a position in a list: "the third log"
		// is a statement about this vault's directory, not about the third
		// session anybody played.
		Number: sessionNumber(fields),
	}
	if !newest.IsZero() {
		ref.Date = newest.Format(time.DateOnly)
	}
	return ref, true
}

// sessionDay reads a log's `date:` frontmatter.
//
// The value arrives as a time.Time when YAML resolved it as a timestamp, which
// is what an unquoted 2026-03-14 is, and as a string when the author quoted it
// or wrote something the timestamp resolver would not take. Both spellings are
// a date, so both are read, and neither is an error: a session log with an
// unreadable date is a log with no date, which the panel already knows how to
// say.
func sessionDay(row store.Page) (time.Time, bool) {
	value, ok := frontmatterOf(row)["date"]
	if !ok {
		return time.Time{}, false
	}
	switch v := value.(type) {
	case time.Time:
		return v, true
	case string:
		v = strings.TrimSpace(v)
		for _, layout := range []string{time.DateOnly, time.RFC3339} {
			if t, err := time.Parse(layout, v); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// sessionNumber reads a log's `session:` frontmatter as an integer, or 0 when
// there is none to read.
//
// A session number is a small integer an author typed, so the accepted shapes
// are the ones YAML produces for one and the one a hand-edited file is likely
// to hold. Anything else is 0 rather than an error, for the same reason an
// unreadable date is: the panel is not where a typo in a session log is
// reported.
func sessionNumber(fields map[string]any) int {
	switch n := fields["session"].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if v, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return v
		}
	}
	return 0
}

// frontmatterOf decodes a page's raw frontmatter into fields.
//
// The index stores the YAML verbatim and never re-serialises it, so this is
// the only copy of it and md.ParseFields is what turns it back into values. A
// block that does not parse yields no fields rather than an error: a
// `frontmatter.invalid` problem is reported on the page view, which is where an
// author is looking, and a sidebar that refused to render because one session
// log has a typo in its YAML would be a worse failure than a panel that omits
// that log's number.
func frontmatterOf(row store.Page) map[string]any {
	fields, err := md.ParseFields([]byte(row.Frontmatter))
	if err != nil {
		return nil
	}
	return fields
}

// pageAside is everything a page's right column carries, resolved once.
//
// It is one function rather than a handful of calls repeated at two call sites
// because a page's context has to be the same in the HTML view and in the JSON
// API. Two implementations of "what may this principal see about this page" is
// the bug the canonical predicate exists to prevent, and the two would drift.
type pageAside struct {
	// toc is the table of contents, filtered by the canonical predicate.
	toc []TocEntry
	// backlinks are the references to the page this viewer may see.
	backlinks []BacklinkChip
	// backlinkCount is what backlinks would have held in total.
	backlinkCount int
	// related are the pages sharing the most tags with this one.
	related []PageCard
	// status is the campaign-wide panel.
	status CampaignStatus
}

// pageAsideFor resolves one page's right column.
func (s *Server) pageAsideFor(ctx context.Context, who authz.Principal, pageID int64) (pageAside, error) {
	db := s.db.Reader()
	var out pageAside

	headings, err := store.TOC(ctx, db, who, pageID)
	if err != nil {
		return pageAside{}, fmt.Errorf("httpapi: read the table of contents: %w", err)
	}
	for _, h := range headings {
		out.toc = append(out.toc, TocEntry{Level: h.Level, Text: h.Text, Slug: h.Slug})
	}

	backlinks, err := store.ListBacklinks(ctx, db, who, pageID)
	if err != nil {
		return pageAside{}, fmt.Errorf("httpapi: read the backlinks: %w", err)
	}
	// The count comes from the identical query rather than from len(backlinks),
	// which is what AGENTS.md §2.4 demands: a panel whose number disagrees with
	// its own list is an existence leak, and there is nothing here that could
	// disagree.
	count, err := store.BacklinkCount(ctx, db, who, pageID)
	if err != nil {
		return pageAside{}, fmt.Errorf("httpapi: count the backlinks: %w", err)
	}
	for _, b := range backlinks {
		out.backlinks = append(out.backlinks, BacklinkChip{
			Card: PageCard{
				ID:       b.Page.ID,
				Path:     b.Page.Path,
				Title:    titleOr(b.Page.Title, b.Page.Path),
				PageType: md.DefaultPageType,
			},
			Line: b.Line,
		})
	}
	out.backlinkCount = count

	related, err := store.ListRelatedPages(ctx, db, who, pageID, relatedLimit)
	if err != nil {
		return pageAside{}, fmt.Errorf("httpapi: list the related pages: %w", err)
	}
	out.related = pageCards(related)

	status, err := s.campaignStatus(ctx, who, pageID)
	if err != nil {
		return pageAside{}, err
	}
	out.status = status
	return out, nil
}

// pageContextAPI is one page's whole right column, as JSON.
//
// It is one route rather than four because opening a page has to cost one
// request, and four routes would have been four authorizations and four
// chances for one of them to be answered under a different rule than the other
// three. Every value in the body is the same one the page view renders, from
// the same builders and the same queries, so the two cannot describe different
// campaigns.
//
// A refused id and an id that names nothing are the same response, byte for
// byte. There is nothing in the refusal that could differ, because nothing in
// the body of a refusal varies per request at all — no id, no path, no title,
// not even a reason that would distinguish "no such page" from "not yours".
func (s *Server) pageContextAPI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	// A parse failure, a zero and a negative are all the same answer, and none of
	// them is a 400: a 400 would confirm that the address is one this route
	// understands, which is itself a fact about the campaign's internals.
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusNotFound)
		return
	}
	row, err := store.GetPageByID(ctx, s.db.Reader(), id)
	if errors.Is(err, store.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, "load the page", err)
		return
	}
	// The file is canonical and the index is derived, so a row whose file has
	// gone is not a page any more: it is a row the reconciling scan has not yet
	// caught. The page view answers 404 for exactly this case, and this route
	// has to answer the same thing — otherwise "the file was deleted" and "the
	// page is not yours" would be two different answers, which is the whole
	// class of probe this route must not be.
	if _, err := s.readPage(ctx, row.Path); err != nil {
		s.log.WarnContext(ctx, "a page in the index could not be read from the vault",
			"action", "http.context", "request_id", obs.RequestID(ctx),
			"path", row.Path, "reason", err.Error())
		writeJSONError(w, http.StatusNotFound)
		return
	}

	aside, err := s.pageAsideFor(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "read the page's context", err)
		return
	}

	card := cardOf(row)
	view := ContextView{
		Shell:         s.liveShell(r, card.Title),
		Card:          card,
		Toc:           aside.toc,
		Backlinks:     aside.backlinks,
		BacklinkCount: aside.backlinkCount,
		Related:       aside.related,
		Status:        aside.status,
	}
	view.Shell.CurrentPageID = row.ID
	view.Shell.CurrentPageURL = card.Href()
	s.writeJSON(w, r, jsonContextOf(view))
}

// jsonContext is the API shape. It is a projection of the view model rather than
// the view model itself, for the reason jsonSearch is: a field added to the page
// for layout must not silently become part of a machine-readable contract.
type jsonContext struct {
	// Href is the page's own URL, so a client can navigate without having to
	// build one.
	Href string `json:"href"`
	// Title is the page's display title.
	Title string `json:"title"`
	// Path is the page's vault-relative path.
	Path string `json:"path"`
	// Toc is the table of contents.
	Toc []jsonTocEntry `json:"toc"`
	// Backlinks are the references to this page the viewer may see.
	Backlinks []jsonBacklink `json:"backlinks"`
	// BacklinkCount is what Backlinks would have held in total.
	BacklinkCount int `json:"backlink_count"`
	// Related are the pages this one shares the most tags with.
	Related []jsonRef `json:"related"`
	// Status is the campaign-wide panel.
	Status jsonStatus `json:"status"`
}

// jsonTocEntry is one table-of-contents row.
type jsonTocEntry struct {
	// Level is the heading level, 1 to 6.
	Level int `json:"level"`
	// Text is the heading's text.
	Text string `json:"text"`
	// Slug is the anchor the heading is reachable at.
	Slug string `json:"slug"`
	// Href is that anchor as a fragment of the page.
	Href string `json:"href"`
}

// jsonBacklink is one referring page.
type jsonBacklink struct {
	// Href is where the referring page is.
	Href string `json:"href"`
	// Title is the referring page's display title.
	Title string `json:"title"`
	// Path is the referring page's vault-relative path.
	Path string `json:"path"`
	// Line is the line in that page the reference is written on.
	Line int `json:"line"`
}

// jsonRef is a page named without its whole card.
type jsonRef struct {
	// Href is where the page is.
	Href string `json:"href"`
	// Title is the page's display title.
	Title string `json:"title"`
	// Path is the page's vault-relative path.
	Path string `json:"path"`
}

// jsonStatus is the campaign status panel on the wire.
type jsonStatus struct {
	// Session is the current session log, absent rather than null when the
	// viewer may not see one, so that a client cannot tell an omitted field from
	// a field it chose to render empty.
	Session *jsonSession `json:"session,omitempty"`
	// Threads are the open threads.
	Threads []jsonRef `json:"threads"`
	// ThreadCount is the total the badge shows.
	ThreadCount int `json:"thread_count"`
	// LastActivity are the recently updated pages other than this one.
	LastActivity []jsonRef `json:"last_activity"`
	// Party are the character sheets.
	Party []jsonPartyMember `json:"party"`
	// SystemNote is the plugin layer's contribution.
	SystemNote string `json:"system_note"`
}

// jsonSession is the current session log on the wire.
type jsonSession struct {
	// Href is where the log is.
	Href string `json:"href"`
	// Title is the log's display title.
	Title string `json:"title"`
	// Path is the log's vault-relative path.
	Path string `json:"path"`
	// Number is the session's own number, or 0 when the file declares none.
	Number int `json:"number"`
	// Date is the log's `date:` frontmatter as a day, or empty.
	Date string `json:"date"`
}

// jsonPartyMember is one character sheet on the wire.
type jsonPartyMember struct {
	// Href is where the sheet is.
	Href string `json:"href"`
	// Title is the sheet's display title.
	Title string `json:"title"`
	// Path is the sheet's vault-relative path.
	Path string `json:"path"`
	// Owner is the owning account's display name, or "" when the sheet is
	// unowned.
	Owner string `json:"owner"`
	// Note is the system plugin's one-liner, always empty in v1.
	Note string `json:"note"`
}

// jsonError is the one shape a non-2xx JSON response uses.
//
// Nothing in it varies per request, for the reason ErrorView's doc comment
// gives: the body a viewer is shown for a page they may not read has to be
// byte-identical to the body shown for a page that does not exist, and the only
// way to guarantee that is for there to be nothing in it that could differ. A
// request id, a page title or a path would each make the two differ, and the
// path would also confirm that the page exists.
type jsonError struct {
	// Status is the HTTP status code.
	Status int `json:"status"`
	// Error is the short title, one of a fixed set.
	Error string `json:"error"`
	// Detail is one sentence of explanation, a constant per status.
	Detail string `json:"detail"`
}

// jsonContextOf projects the view model onto the API shape.
func jsonContextOf(v ContextView) jsonContext {
	out := jsonContext{
		Href:          v.Card.Href(),
		Title:         v.Card.Title,
		Path:          v.Card.Path,
		Toc:           make([]jsonTocEntry, 0, len(v.Toc)),
		Backlinks:     make([]jsonBacklink, 0, len(v.Backlinks)),
		BacklinkCount: v.BacklinkCount,
		Related:       make([]jsonRef, 0, len(v.Related)),
		Status: jsonStatus{
			Threads:      make([]jsonRef, 0, len(v.Status.Threads)),
			ThreadCount:  v.Status.ThreadCount,
			LastActivity: make([]jsonRef, 0, len(v.Status.LastActivity)),
			Party:        make([]jsonPartyMember, 0, len(v.Status.Party)),
			SystemNote:   v.Status.SystemNote,
		},
	}
	for _, entry := range v.Toc {
		out.Toc = append(out.Toc, jsonTocEntry{
			Level: entry.Level,
			Text:  entry.Text,
			Slug:  entry.Slug,
			Href:  "#" + entry.Slug,
		})
	}
	for _, chip := range v.Backlinks {
		out.Backlinks = append(out.Backlinks, jsonBacklink{
			Href:  chip.Card.Href(),
			Title: chip.Card.Title,
			Path:  chip.Card.Path,
			Line:  chip.Line,
		})
	}
	for _, card := range v.Related {
		out.Related = append(out.Related, jsonRef{Href: card.Href(), Title: card.Title, Path: card.Path})
	}
	for _, card := range v.Status.Threads {
		out.Status.Threads = append(out.Status.Threads, jsonRef{Href: card.Href(), Title: card.Title, Path: card.Path})
	}
	for _, card := range v.Status.LastActivity {
		out.Status.LastActivity = append(out.Status.LastActivity, jsonRef{Href: card.Href(), Title: card.Title, Path: card.Path})
	}
	for _, member := range v.Status.Party {
		out.Status.Party = append(out.Status.Party, jsonPartyMember{
			Href:  member.Card.Href(),
			Title: member.Card.Title,
			Path:  member.Card.Path,
			Owner: member.Owner,
			Note:  member.Note,
		})
	}
	if v.Status.Session != nil {
		s := v.Status.Session
		out.Status.Session = &jsonSession{
			Href:   s.Card.Href(),
			Title:  s.Card.Title,
			Path:   s.Card.Path,
			Number: s.Number,
			Date:   s.Date,
		}
	}
	return out
}

// writeJSON writes a machine-readable body.
//
// The two cache headers are the search API's, for the same reason: the payload
// carries page titles and paths, so a shared cache holding it for one principal
// and serving it to another would be a leak with no HTTP header to explain it.
func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.ErrorContext(r.Context(), "a payload could not be encoded",
			"action", "http.json", "request_id", obs.RequestID(r.Context()),
			"err", logRecord(err).String())
	}
}

// writeJSONError answers a JSON route's refusal.
//
// It is separate from writeError because that one renders HTML through the
// template layer, and a client that receives an HTML apology for a JSON request
// cannot tell a refusal from a misconfigured route. The copy comes from the same
// constant table the HTML error page uses, so the two answers cannot drift apart
// in wording, and there is no parameter through which a caller could put
// anything request-specific into one.
func writeJSONError(w http.ResponseWriter, status int) {
	text, ok := errorCopy[status]
	if !ok {
		text = errorCopy[http.StatusInternalServerError]
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	// The status goes out before the body, for the reason writeError gives: a
	// first write is what commits a 200.
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonError{Status: status, Error: text.heading, Detail: text.detail})
}
