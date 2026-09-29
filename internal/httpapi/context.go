package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/a-h/templ"
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

// The plugin layer's contribution to the shell, and the three rules that keep it
// from being a broken control.
//
// They live here rather than in the view layer for the reason the canonical
// predicate does: a rule that sits next to the thing it decides cannot be
// forgotten by whoever adds the next surface.

// PluginPanelSlots is the order the right column renders plugin panels in, and
// the set of slots it renders at all.
//
// It is one list, exported, because two packages need the same answer: the
// handler that fills the view model and the template that lays it out. A slot
// order written twice is a column that disagrees with itself the first time a
// slot is added, and that disagreement would be invisible until a panel turned
// up in the wrong place.
//
// SlotLeftBottom is here because the left column has no panel region yet, and a
// panel a plugin contributed is shown rather than dropped — at the bottom of the
// context column, which is the only region this build has. SlotEditorToolbar
// and SlotPageActions are absent because the editor stage owns those
// placements, and a roll button in a sidebar is a control in the wrong place
// rather than a working one.
func PluginPanelSlots() []string {
	return []string{
		string(plugin.SlotRightTop),
		string(plugin.SlotRightMid),
		string(plugin.SlotRightBottom),
		string(plugin.SlotLeftBottom),
	}
}

// PluginNavFor projects a registry's sidebar entries onto one request's shell.
//
// Two entries never reach a template. One whose href is outside its own
// plugin's route prefix, because a link to nothing is a broken control: the host
// is supposed to have refused it at registration, and this is the cheap second
// check that turns a mistake there into a missing link here rather than a 404 in
// a reader's sidebar. And one this principal may not see, because MinimumRole
// is resolved here, through the policy — so the sidebar's answer to "may this
// reader open this" is the same answer the route table gives, and the role never
// reaches a template that might ask a second question about it.
//
// The order is the registry's. NavItems is already sorted by Order, then owning
// plugin id, then declaration index, and sorting it again here could only lose
// that order.
//
// The role-name-to-permission table is authz.PermissionForRole and not a switch
// here, so that this package asks the policy a question and never answers one:
// a second copy of that table would be a second answer to "what does `dm` mean",
// and TestNoRoleComparisonOutsidePerm refuses the copy.
func PluginNavFor(owned []plugin.Owned[plugin.NavItem], who authz.Principal, policy authz.Policy) []PluginNavItem {
	out := make([]PluginNavItem, 0, len(owned))
	for _, item := range owned {
		perm, known := authz.PermissionForRole(item.Value.MinimumRole)
		if !known || !policy.Allows(who, perm, authz.Resource{}) {
			continue
		}
		entry := PluginNavItem{
			ID:     item.Value.ID,
			Plugin: item.Plugin,
			Label:  item.Value.Label,
			Href:   item.Value.Href,
			Icon:   item.Value.Icon,
			Order:  item.Value.Order,
		}
		if !entry.WithinPrefix() {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		// nil rather than an empty slice, so that "no plugin group" is one
		// value in a JSON projection and one branch in a template rather than
		// two shapes of the same absence.
		return nil
	}
	return out
}

// pluginNav is the left sidebar's plugin group for one request.
//
// A nil registry is the ordinary case for a build with no plugins in it, so the
// check is here rather than in New: the group is chrome, and chrome that cannot
// be built at all is a page that cannot be rendered.
func (s *Server) pluginNav(r *http.Request) []PluginNavItem {
	if s.plugins == nil {
		return nil
	}
	return PluginNavFor(s.plugins.NavItems(), PrincipalFrom(r.Context()), s.policy)
}

// pluginPanels is the right column's plugin panels for a page of this type.
//
// pageType is the frontmatter `type:` and the empty string is not a special
// case: PanelsFor reads it as "the global panels only", which is what a page
// naming no type should get.
//
// A panel that does not render is dropped and logged rather than failed on. The
// column is chrome and it is on every page, so a component with a bug in it
// would otherwise be a 500 for every reader of every page. The log line names
// the plugin and the slot and carries no content, for the reason every log line
// in this package carries no content.
func (s *Server) pluginPanels(ctx context.Context, pageType string) []PluginPanel {
	if s.plugins == nil {
		return nil
	}
	var out []PluginPanel
	for _, owned := range s.plugins.PanelsFor(pageType) {
		slot := string(owned.Value.Slot)
		if owned.Value.Component == nil || !knownPanelSlot(slot) {
			continue
		}
		var body strings.Builder
		if err := owned.Value.Component.Render(ctx, &body); err != nil {
			s.log.WarnContext(ctx, "a plugin panel did not render",
				"action", "http.panel", "request_id", obs.RequestID(ctx),
				"plugin", owned.Plugin, "slot", slot, "err", logRecord(err).String())
			continue
		}
		out = append(out, PluginPanel{
			Slot:  slot,
			Title: panelSlotTitle(slot),
			Body:  strings.TrimSpace(body.String()),
		})
	}
	if len(out) == 0 {
		return nil
	}
	// The slot order is fixed and the order within a slot is the registry's, so
	// two panels competing for one slot cannot swap places between two requests.
	slices.SortStableFunc(out, func(a, b PluginPanel) int {
		return panelSlotRank(a.Slot) - panelSlotRank(b.Slot)
	})
	return out
}

// knownPanelSlot reports whether the context column renders this slot.
func knownPanelSlot(slot string) bool { return slices.Contains(PluginPanelSlots(), slot) }

// panelSlotRank is a slot's position in the column. An unknown slot sorts last
// rather than first, so a slot added to neither list cannot displace the ones
// that are.
func panelSlotRank(slot string) int {
	for i, known := range PluginPanelSlots() {
		if known == slot {
			return i
		}
	}
	return len(PluginPanelSlots())
}

// panelSlotTitle is the heading a panel is rendered under.
//
// plugin.Panel carries no title field, so every panel is given one of these and
// the alternative — output under no heading at all — is the unlabelled block
// AGENTS.md §7 is about. The wording names the slot rather than guessing what
// the panel is for, because the host cannot know that, and a heading that
// guesses is a heading that is sometimes wrong.
//
// SlotLeftBottom reads as the bottom of the context column because that is
// where it is rendered; nothing in this build puts a panel in the left column.
func panelSlotTitle(slot string) string {
	switch plugin.Slot(slot) {
	case plugin.SlotRightTop:
		return "Above the page context"
	case plugin.SlotRightMid:
		return "Page context"
	case plugin.SlotRightBottom, plugin.SlotLeftBottom:
		return "Below the page context"
	default:
		return "Plugin panel"
	}
}

// pageViewer is the custom viewer a plugin registered for this page type, or
// nil.
//
// Nil is the answer for every page of a campaign with no system plugin, and for
// every page type that exists only as a frontmatter convention: `type:
// houserule` names a type nobody registered, and it renders with the core
// Markdown view. A registered type that supplied no viewer is the same answer,
// so "there is nothing custom here" is one path rather than two, and the
// template's default branch is what every page takes unless a plugin said
// otherwise.
func (s *Server) pageViewer(pageType string) templ.Component {
	if s.plugins == nil || pageType == "" {
		return nil
	}
	registered, ok := s.plugins.PageType(pageType)
	if !ok {
		return nil
	}
	return registered.Viewer
}

// currentPageType is the `type:` a page's frontmatter names.
//
// It is read through md.ParseFields — the helper campaignStatus already uses —
// rather than with a second YAML reader, because a second reader is a second
// opinion about the same bytes and the indexer's own column is derived from the
// first one. A block that does not parse yields no fields at all, and the
// indexer's column is then the only surviving copy of the same fact. When
// neither has one the page is a note, which is what md.DefaultPageType is for.
func (s *Server) currentPageType(row store.Page) string {
	for _, value := range []string{frontmatterType(row), row.PageType} {
		if t := strings.TrimSpace(value); t != "" {
			return t
		}
	}
	return md.DefaultPageType
}

// frontmatterType reads the `type:` field as a string.
//
// A Stringer is accepted because YAML resolves an unquoted date-shaped value to
// a timestamp, and a page type written as one is a string an author meant. Every
// other shape is a number, a list or a map, and none of those is a page type
// this registry could have registered, so they read as absent.
func frontmatterType(row store.Page) string {
	switch value := frontmatterOf(row)["type"].(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		return ""
	}
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
	if _, readErr := s.readPage(ctx, row.Path); readErr != nil {
		s.log.WarnContext(ctx, "a page in the index could not be read from the vault",
			"action", "http.context", "request_id", obs.RequestID(ctx),
			"path", row.Path, "reason", readErr.Error())
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
		// The same panels the page view's column carries, from the same page
		// type. A client that swapped this region in and then rendered the
		// document would otherwise be looking at two different answers about
		// what is around the page.
		Panels: s.pluginPanels(ctx, s.currentPageType(row)),
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
