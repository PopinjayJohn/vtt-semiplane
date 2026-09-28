package houserules

import (
	"bytes"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/a-h/templ"
)

// CoreTypes returns the page types this plugin claims.
//
// It returns nil, and that is the whole of what a feature plugin may say here.
// The host refuses a feature plugin that registers a page type at all — this
// package's Register checks it before the host does, so the failure names a line
// of code rather than a boot report entry — and `type: houserule` needs no
// registration: a page carrying a type nobody registered renders with the core
// Markdown viewer, which is the whole reason a feature plugin can express
// content at all.
func (p *Plugin) CoreTypes() []plugin.PageType { return nil }

// MarkdownExtenders returns the goldmark extenders this plugin contributes.
//
// It contributes none, and that is an answer rather than a gap. A house rule is
// ordinary Markdown with ordinary frontmatter; the one convention this plugin
// reads is a `type:` value the core indexer already stores, so there is no block
// syntax to teach the parser. Returning an empty list keeps the composite
// goldmark from growing an extender that draws nothing on every page in the
// vault.
func (p *Plugin) MarkdownExtenders() []any { return nil }

// ConfigSchema returns the configuration this plugin declares.
//
// Nothing. A setting nothing reads is a promise to a future contributor that the
// value will be honoured, and a promise nobody keeps is how a campaign ends up
// with an option the operator can change and the app ignores.
func (p *Plugin) ConfigSchema() map[string]any { return nil }

// Panels returns the panels this plugin contributes.
//
// None, and not because there was nowhere to put one. A panel renders inside the
// shell on somebody else's page, and this plugin's only surface is its own
// index — a panel over the campaign status data would be a second, worse answer
// to a question the core panel already answers, on every page in the vault
// rather than on the one page that needs it.
func (p *Plugin) Panels() []plugin.Panel { return nil }

// NavItems returns the one sidebar link this plugin contributes.
func (p *Plugin) NavItems() []plugin.NavItem { return navItems() }

// Summaries returns the page-summary providers for link previews.
//
// None. The link-preview card is core's route and core's behaviour, and
// GetPageSummary already answers it from the same public excerpt every other
// page preview uses. A provider here would have to decline every page anyway —
// the one page-id-keyed surface a plugin could fill is a summary of a character
// sheet, which this plugin has no opinion about — and a provider that declines
// every page is a control with nothing behind it.
func (p *Plugin) Summaries() []plugin.SummaryProvider { return nil }

// RegisterRoutes mounts this plugin's routes on the router the host supplies.
//
// The router arrives already prefixed at /plugin/houserules and already wrapped
// in the host's session and role middleware, so there is nothing here to mount at
// and nothing here to unwrap: a pattern is a pattern, and a method is a method.
// It is the host that calls this, once, after Register has returned — so the page
// store this plugin captured is already in place by the time the handlers run.
//
// Both routes are GET, and that is not an accident of the current feature set.
// Every route under a plugin prefix is behind the host's CSRF check and behind
// PermSession, so a mutating route here would work — and would need a permission
// the host has no vocabulary for, since mountPluginRoutes applies the same least
// requirement to every plugin route. The Markdown file stays canonical: a house
// rule is edited by editing the file.
func (p *Plugin) RegisterRoutes(sub plugin.RouteMounter) {
	p.routes = sub
	sub.Get(indexRoute, p.index)
	sub.Get(rulesRoute, p.rulesFragment)
}

// index renders the plugin's own page: the house rules, the filter, and the one
// section it is able to gate.
func (p *Plugin) index(w http.ResponseWriter, r *http.Request) {
	view, err := p.indexView(r)
	if err != nil {
		view.Problem = storeUnreadable
		writeComponent(w, r, http.StatusInternalServerError, houseRulesDocument(view))
		return
	}
	writeComponent(w, r, http.StatusOK, houseRulesDocument(view))
}

// rulesFragment renders the same list without the document around it.
//
// The response is text/html and the body is the list, which is the shape the
// core typeahead parses and swaps into a region. Nothing on this page fetches
// it — the page loads no script, and its form navigates to the index instead —
// so it is here because it is the one piece of this plugin's surface a
// core-owned hook could use without the plugin shipping any behaviour of its
// own, and because a fragment is a thing a test can assert on without parsing a
// document.
func (p *Plugin) rulesFragment(w http.ResponseWriter, r *http.Request) {
	view, err := p.indexView(r)
	if err != nil {
		view.Problem = storeUnreadable
		writeComponent(w, r, http.StatusInternalServerError, houseRulesList(view))
		return
	}
	writeComponent(w, r, http.StatusOK, houseRulesList(view))
}

// storeUnreadable is what the page says when the store could not be read.
//
// It names the failure rather than showing an empty list, because an empty house
// rule list and a store that could not be read look identical otherwise, and the
// second of those is a page quietly lying to the table about the campaign's
// rules.
const storeUnreadable = "The rules could not be read, so the list below is not the whole set."

// writeComponent renders a component and then writes it.
//
// The render goes into a buffer first. A component that failed halfway through
// would otherwise have written half a page with a 200 already on the wire, and
// the reader would be looking at a plausible document that is missing its
// bottom.
func writeComponent(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	var buf bytes.Buffer
	if err := c.Render(r.Context(), &buf); err != nil {
		// The message names the plugin and never the content it was rendering.
		// A render error that quoted a page would be a way to get vault text into
		// a response body, which is the one thing §2.2 of the working agreement
		// rules out.
		http.Error(w, "houserules: the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The two cache headers are the search API's, for the same reason: the body
	// carries page titles and paths, so a shared cache holding it for one
	// principal and serving it to another would be a leak with no HTTP header to
	// explain it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Cookie")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// groupParam is the query value that turns grouping on.
//
// It is one named value rather than a boolean so that a future second grouping —
// by tag, by author — is a new value rather than a meaning stolen from an old
// one, and so that an unrecognised value is ignored rather than half-applied.
const groupParam = "system"

// indexView is what the index and the fragment render.
//
// It is a value and not a component, so a template never reaches back into this
// package, and it is a value rather than a live store handle so that one request
// reads the store once and every part of the page describes that one answer.
type indexView struct {
	// All is every house rule the store will show, before any reader-chosen
	// filter. The chips and the count are computed from this, so a filter can
	// never make a rule stop existing.
	All []Rule
	// Shown is All after the tag and term filters, and is what the list shows.
	Shown []Rule
	// Total is CountPagesByType over the identical statement All came from, so
	// the number and the list cannot disagree.
	Total int
	// Groups is Shown grouped by system, and is nil unless the reader asked for
	// it. Nil rather than empty so that "not grouped" and "grouped with nothing
	// in it" are two states a template can tell apart.
	Groups []ruleGroup
	// Chips is one entry per tag carried by at least one rule in All.
	Chips []tagChip
	// ActiveTag is the tag being filtered by, or the empty string. It is a value
	// that survived the normalisation in indexView, so a template never has to
	// decide whether a chip is on.
	ActiveTag string
	// Term is the text in the filter box, as the reader typed it.
	Term string
	// Grouped reports whether the reader asked for grouping.
	Grouped bool
	// Problem is set when the store could not be read, and is the only case in
	// which the list below is not the whole truth.
	Problem string
}

// ruleGroup is one system and the rules filed under it.
type ruleGroup struct {
	// ID is the element id for the group's heading, and is derived from the
	// group's position rather than from its name: a system named with a quote in
	// it would make a heading id out of its own markup, and two systems whose
	// names sanitised to the same string would make two elements with one id.
	ID string
	// Name is the system as the frontmatter spelled it.
	Name string
	// Rules are the group's rules, in the store's order.
	Rules []Rule
}

// tagChip is one filterable tag and how many of the readable rules carry it.
//
// The count is over All, not over Shown, so a chip's number does not change under
// the reader's finger as they type — and because All is already the store's
// answer for the reader, a chip's number can never count a rule that reader may
// not open. That is the property the whole of this package rests on, and it is
// why the count is computed here rather than read from the store's tag cloud:
// ListTags counts every page in the vault, so a chip built from it would show a
// number for a tag the list below never shows.
type tagChip struct {
	Name  string
	Count int
}

// indexView builds one request's view from the store.
//
// The order is the security-relevant part. The principal comes off the request
// context, the store answers for that principal, and only then is a
// reader-chosen filter applied. A filter applied before the query would be a
// filter the store's count never saw, and a tag a reader may not read would come
// back as a count of one with no row under it.
func (p *Plugin) indexView(r *http.Request) (indexView, error) {
	ctx := r.Context()
	who := reader(ctx)
	all, err := p.rules(ctx, who)
	if err != nil {
		return indexView{Problem: storeUnreadable}, err
	}
	total, err := p.count(ctx, who)
	if err != nil {
		return indexView{Problem: storeUnreadable}, err
	}

	query := r.URL.Query()
	view := indexView{
		All:     all,
		Total:   total,
		Term:    strings.TrimSpace(query.Get("q")),
		Grouped: query.Get("group") == groupParam,
		Chips:   chips(all),
	}
	// A tag nobody carries is not a filter, it is a typo. Dropping it here is
	// what keeps the page honest: a `?tag=nonsense` that rendered an active chip
	// over an empty list would be a filter with no row to remove it by.
	if chip, ok := findChip(view.Chips, query.Get("tag")); ok {
		view.ActiveTag = chip
	}
	view.Shown = filterRules(all, view.ActiveTag, strings.Fields(strings.ToLower(view.Term)))
	if view.Grouped {
		view.Groups = groupRules(view.Shown)
	}
	return view, nil
}

// chips is one chip per tag carried by at least one readable rule, sorted.
//
// Built from the readable rules rather than from the store's tag cloud, so a chip
// exists only where a row exists beside it.
func chips(rules []Rule) []tagChip {
	counts := map[string]int{}
	for _, rule := range rules {
		for _, tag := range rule.Tags {
			counts[tag]++
		}
	}
	out := make([]tagChip, 0, len(counts))
	for name, count := range counts {
		out = append(out, tagChip{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// findChip resolves a requested tag to the spelling the chips use.
//
// The comparison is case-insensitive, so `?tag=combat` finds the chip the author
// wrote as `Combat`, and the filter is the one the reader thinks they applied.
// A tag no chip carries is absent rather than an empty string, and that
// distinction is what indexView's caller uses to drop a typo.
func findChip(chips []tagChip, want string) (string, bool) {
	if want == "" {
		return "", false
	}
	for _, chip := range chips {
		if strings.EqualFold(chip.Name, want) {
			return chip.Name, true
		}
	}
	return "", false
}

// filterRules narrows the readable rules to a tag and a set of terms.
//
// Conjunctive in both. The tag match is case-insensitive and the term match is
// not: a reader who types `Combat` in the box means the tag `Combat`, while a
// reader who types `combat` means that tag and any rule whose own text contains
// the word.
func filterRules(rules []Rule, tag string, terms []string) []Rule {
	if tag == "" && len(terms) == 0 {
		return rules
	}
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if tag != "" && !rule.HasTag(tag) {
			continue
		}
		if !rule.matches(terms) {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// groupRules files rules under their system, unassigned last.
//
// Unassigned last rather than in alphabetical order because it is not a system:
// a rule whose author never wrote a `system:` is a rule that belongs to the
// table's house style generally, and filing it between `D&D 5e` and `Shadowrun`
// would read as a claim that somebody chose it.
func groupRules(rules []Rule) []ruleGroup {
	index := map[string]int{}
	var out []ruleGroup
	for _, rule := range rules {
		at, ok := index[rule.System]
		if !ok {
			at = len(out)
			index[rule.System] = at
			out = append(out, ruleGroup{Name: rule.System})
		}
		out[at].Rules = append(out[at].Rules, rule)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Name == UnassignedSystem) != (out[j].Name == UnassignedSystem) {
			return out[j].Name == UnassignedSystem
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	// The ids are numbered after the sort rather than before it, so the first
	// group on the page is group 0. Numbering at insertion would produce a
	// document whose heading ids run 2, 0, 1 — unique, and a nuisance to read a
	// bug report against.
	for i := range out {
		out[i].ID = groupID(i)
	}
	return out
}

// groupID is a heading id for the group at this position.
//
// The position, not the name: a system is a frontmatter value an author typed,
// and a heading id is a document-wide identifier. Deriving one from the other
// means a name with a space, a quote or a duplicate produces an id that is
// either invalid or shared with another heading.
func groupID(at int) string { return "houserules-group-" + itoa(at) }

// Filtered reports whether a reader-chosen filter is narrowing the list.
func (v indexView) Filtered() bool { return v.ActiveTag != "" || v.Term != "" }

// Action is where the filter form submits.
//
// The index route and not the fragment route: the form navigates, and a
// navigation to a fragment would replace the reader's page with a list and no way
// back. The form works with scripting disabled, which is the only situation it
// is written for — a plugin may not reference app.js, and the filter box is a
// GET form because the query string is the filter's state.
func (v indexView) Action() string { return IndexHref }

// ChipHref is where a chip goes: the filter with that tag on, or off when it is
// already on.
//
// That is the toggle. There is no script on this page to do it, so the toggle is
// a link to the other state of the same query — which is also a state a reader
// can bookmark, share and press Back out of, none of which a scripted toggle
// gives.
func (v indexView) ChipHref(tag string) string {
	if strings.EqualFold(tag, v.ActiveTag) {
		return v.href("", v.Term, v.Grouped)
	}
	return v.href(tag, v.Term, v.Grouped)
}

// GroupHref is where the "group by system" toggle goes.
//
// The other state of the same query, for the reason ChipHref gives. A control
// that is a link to a URL is a control a reader can open in a new tab; a control
// that is only a click is not.
func (v indexView) GroupHref() string { return v.href(v.ActiveTag, v.Term, !v.Grouped) }

// ClearHref drops every filter at once, and is the way back from a list that is
// empty because of a filter rather than because the campaign has no rules.
func (v indexView) ClearHref() string { return v.href("", "", false) }

// href builds the index URL for one state of the filter.
//
// Every value goes through url.Values, so a tag containing a space, a quote or
// anything else an author typed into frontmatter is percent-encoded rather than
// concatenated into an attribute. A reader's term is never pasted raw, which is
// the only reason this is not an injection surface.
func (v indexView) href(tag, term string, grouped bool) string {
	query := url.Values{}
	if tag != "" {
		query.Set("tag", tag)
	}
	if term != "" {
		query.Set("q", term)
	}
	if grouped {
		query.Set("group", groupParam)
	}
	if len(query) == 0 {
		return IndexHref
	}
	return IndexHref + "?" + query.Encode()
}

// IsActive reports whether a chip is the one currently filtering, so the
// template marks it with this package's answer rather than comparing strings.
func (v indexView) IsActive(name string) bool { return strings.EqualFold(name, v.ActiveTag) }

// Showing is how many rules the filter left, as the page says it beside the
// count of the whole set.
func (v indexView) Showing() int { return len(v.Shown) }

// countLabel is a number with the noun it counts, so the page's count reads as a
// count. A bare number in a sentence is the kind of thing a reader learns to
// stop reading.
func countLabel(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return itoa(n) + " " + noun + "s"
}

// boolAttr is an ARIA tri-state as the attribute value it needs.
//
// "false" rather than an absent attribute, because a false aria-current and a
// false aria-selected are both meaningful and both are what the ARIA spec says
// they are. Omitting it says something weaker and different — and here it would
// also say a chip is not a filter when it is, which is the one fact a reader
// navigating by keyboard needs from it.
func boolAttr(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
