package houserules

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	// ID is this plugin's registry name, kebab-case and stable forever. The same
	// string is the route prefix, so it is a constant rather than a literal
	// repeated at each use.
	ID = "houserules"

	// Name is what an operator reads in the boot report.
	Name = "House Rules"

	// Version is this plugin's own semver, and not the APILevel: the two move
	// independently, and a plugin bump is what tells a reader a behaviour changed
	// while the host contract stood still.
	Version = "0.1.0"

	// PageTypeHouseRule is the frontmatter `type:` this plugin lists.
	//
	// It is a *convention* and is deliberately not registered as a page type.
	// A feature plugin may not register one — the host refuses that at boot, and
	// this package's own Register refuses it first — and it does not need to: a
	// page carrying this type is an ordinary page, renders with the core
	// Markdown viewer, and is indexed by the core FTS with no plugin involved.
	// The whole point of the feature half of the architecture is that
	// `type: houserule` works with no game system and no page-type registration
	// anywhere in the binary.
	PageTypeHouseRule = "houserule"

	// NavID is the sidebar nav item's id. Nav ids are unique across the whole
	// registry rather than per plugin, so the id is namespaced.
	NavID = "houserules.index"

	// IndexHref is where the nav item points, and it is the plugin's own route
	// prefix and nothing else. A nav href outside the prefix is a registration
	// error rather than a working link, and a link to a route the plugin did not
	// mount is a control with nothing behind it.
	IndexHref = "/plugin/" + ID

	// navOrder is where the item sits in the sidebar's plugin group. 40 puts it
	// after dnd5e's 10, so the campaign's own content comes before the tool that
	// indexes it.
	navOrder = 40

	// NavIcon is the sprite token the nav item and the page's headings use.
	//
	// It is i-book and not a balance scale, because web/static/icons.svg has no
	// scale symbol and a token the sprite does not define is a silently empty
	// <use>: the affordance looks broken rather than absent, which is the harder
	// of the two to notice. Adding the symbol is a change to a core-owned asset
	// and not this package's to make.
	NavIcon = "i-book"

	// ResultKind is the badge a contributed search row carries.
	//
	// It is a display string and not the frontmatter type value, because the
	// badge is what a reader reads and "houserule" is what a machine reads. A
	// reader filtering search results to "House rule" is asking a question the
	// index has to answer the same way tomorrow, which is why it is a constant.
	ResultKind = "House rule"

	// ResolverID names the search resolver, so two plugins contributing one
	// cannot collide in the host's registry.
	ResolverID = "houserules.index"

	// indexRoute is the plugin's root route and the nav item's destination.
	//
	// RouteReservation trims the separator and finds no segment in it, so the
	// root claims no reserved name and needs no capability — the correct answer
	// for a route that carries the plugin's own name and links to nothing outside
	// its prefix.
	indexRoute = "/"

	// rulesRoute is the filtered list as an HTML fragment.
	//
	// It is the same component the index embeds, without the document around
	// it, so the page and the fragment cannot describe different rules: there is
	// one renderer and two wrappers. The response is text/html and the body is
	// the list, which is the shape app.js's typeahead parses and swaps into a
	// region; the index page itself does not use it, because the index loads no
	// script and the form that would fetch it navigates to the index instead.
	rulesRoute = "/api/rules"

	// maxSearchRows bounds what one resolver call contributes. The core clamps
	// its own limits; a plugin that did not would make a single keystroke walk a
	// whole vault. The index has no equivalent bound, and the reason is the one
	// that matters here: a windowed list beside an unwindowed count is the shape
	// AGENTS.md §2.4 calls an existence leak, and a campaign's house rules are a
	// human-curated list rather than a table of every note in the vault.
	maxSearchRows = 20

	// UnassignedSystem is the group a rule with no `system:` frontmatter falls
	// into. It is a visible group rather than a rule filed nowhere, because a
	// house rule the author never assigned is still a house rule and a list that
	// silently dropped it would be wrong in a way nobody could see.
	UnassignedSystem = "Unassigned"

	// pluginPageHref is the core route a page is served at, relative to the host
	// root. It is a constant so that a plugin link and the core's own page card
	// cannot disagree, and so that the one literal is the single thing to look
	// at when the two ever do.
	pluginPageHref = "/p/"

	// stylesheetHref is the committed stylesheet, served from the embedded asset
	// tree. A plugin page is a whole document and this is the only way it gets
	// the app's classes; the asset route's allow-list is what keeps it from
	// becoming a way to reference anything off-origin.
	stylesheetHref = "/_/assets/app.css"

	// spritePath is the icon sprite's asset path, with no fragment separator.
	spritePath = "/_/assets/icons.svg"

	// spriteHref is the sprite's asset path with the fragment separator, for a
	// <use> reference.
	//
	// It is a second copy of a string internal/web owns, and it has to be:
	// httpapi imports internal/app, internal/app imports the plugin registry, and
	// the registry imports this package, so a plugin cannot import internal/web
	// without closing a cycle. Two definitions of the sprite's path is the
	// smaller of the two problems; the larger one is the backwards edge, and it
	// belongs in core rather than in a plugin working around it quietly.
	spriteHref = "/_/assets/icons.svg#"
)

// capabilities is what this plugin declares: two names, and each one is the
// requirement for a contribution this package makes.
//
// CapSidebarNav is what keeps the sidebar from hiding the group, and CapSearchResolvers
// is what keeps the host from discarding the rows below. A feature plugin that
// declared a page type, a panel or a summary provider would be declaring a
// capability it has no contribution for, which §7 of the working agreement calls
// a control with nothing behind it — and a panel is the one that actually hurts,
// because a panel is rendered on every page in the vault.
var capabilities = []plugin.Capability{
	plugin.CapSidebarNav,
	plugin.CapSearchResolvers,
}

// Plugin is the house rules feature plugin.
//
// It holds the page store and the host's clock, captured at Register, because a
// route has to answer with them and the Host offers no way to ask a second time.
// It holds no vault content: everything below is derived from the store per
// request and discarded with the request.
type Plugin struct {
	// pages is the authz-filtered page read surface captured at Register.
	//
	// It may be the host's empty store rather than a real one — a composition
	// root that wired no page store hands every plugin an empty one — so every
	// call below tolerates an answer of zero rows with no error, and a nil here
	// (a plugin whose Register never ran) is the same answer rather than a
	// panic.
	pages plugin.PageStore

	// now is the host's clock, captured at Register as a method value. A plugin
	// never calls time.Now: a clock the host does not own is a clock no test
	// can freeze, and the alternative to a frozen clock is a test that only
	// passes at one time of day.
	now func() time.Time

	// routes is the router the host handed the plugin in RegisterRoutes, kept so
	// that a test can walk the patterns really mounted rather than a table of the
	// ones this package says it mounts.
	routes *chi.Mux
}

// New returns a plugin that has not yet been registered against a host.
//
// The zero value would answer a request about its clock with a nil call, so the
// constructor installs the one honest stand-in — the zero time — and Register
// replaces it with the host's.
func New() *Plugin {
	return &Plugin{now: func() time.Time { return time.Time{} }}
}

// Compile-time proof that the Plugin and both halves of the contract are
// implemented. The host asserts the same thing from its side; a plugin that
// quietly stopped satisfying one half would otherwise fail at the registry
// boundary with a message about an interface rather than about this package.
var (
	_ plugin.Plugin     = (*Plugin)(nil)
	_ plugin.PluginCore = (*Plugin)(nil)
	_ plugin.PluginUI   = (*Plugin)(nil)
)

// Descriptor returns the whole static declaration.
//
// It is a method rather than a package-level value because a Descriptor is
// mutable — a caller may reorder its slices — and a shared one would let the
// first caller to touch it change what every later caller sees.
func (p *Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:      ID,
		Name:    Name,
		Kind:    plugin.KindFeature,
		Version: Version,
		// APILevel is the host this plugin was written against, which is the host
		// it ships with. Anything else is a version skew the boot report exists
		// to make visible.
		APILevel: plugin.APILevel,
		// PageTypes, ConfigSchema and Migrations are all nil, and each is nil for
		// the same reason: a feature expresses content through a frontmatter
		// convention, holds no configuration, and owns no table. The Markdown
		// file is canonical; a table of derived house rules would be a second
		// source of truth for a list the files already are.
		PageTypes: nil,
		NavItems:  navItems(),
		// searchResolvers is a method because the resolver closes over this
		// plugin: the page store it reads is captured at Register, and the
		// resolver is declared before that has happened.
		SearchResolvers: p.searchResolvers(),
		Capabilities:    capabilities,
	}
}

// navItems returns the sidebar contribution: exactly one link.
func navItems() []plugin.NavItem {
	return []plugin.NavItem{
		{
			ID:    NavID,
			Label: Name,
			Href:  IndexHref,
			Icon:  NavIcon,
			Order: navOrder,
			// Badge is nil on purpose. A badge is a live count, and the count this
			// plugin could produce is the one already on its own index page beside
			// the list the count describes — which is the property a badge is
			// supposed to have and the reason internal/httpapi drops the field: a
			// number a reader cannot check against a list is a number nobody can
			// verify. The count is rendered, on the page, from
			// CountPagesByType.
		},
	}
}

// searchResolvers returns the one derived-row contribution.
//
// The rows are built from page titles, paths and the named frontmatter keys the
// index itself filters on. That is a security property and not a simplicity one:
// IndexRow.Summary is rendered into a search result for whoever asked, and a
// summary assembled from a page body would be a second path to page text that
// does not go through the redaction a page render goes through. `store.Page`
// has no body column, so the path is not merely unused here — it does not exist
// on the surface this plugin is given.
func (p *Plugin) searchResolvers() []plugin.SearchResolver {
	return []plugin.SearchResolver{
		{
			ID: ResolverID,
			Query: func(ctx context.Context, q string) ([]plugin.IndexRow, error) {
				return p.search(ctx, q)
			},
		},
	}
}

// Register wires this plugin into a host.
//
// Everything the host needs is derived from Descriptor, so the sequence is:
// check the declaration is admissible, then capture what the host offers. Every
// step returns an error rather than panicking, because a panic during boot takes
// the app down for a condition that is contained to this plugin — the lifecycle
// disables a plugin whose Register fails, and it can only do that if Register
// fails normally.
//
// No route is mounted here, and that is the host's shape rather than an
// oversight. The host builds a sub-router already prefixed at /plugin/houserules
// and already wrapped in its middleware, and it hands that router to the
// plugin's own RegisterRoutes once Register has returned. The reserved-segment
// checks below run now, before anything is mounted, so a pattern that would be
// refused is never reached.
func (p *Plugin) Register(ctx context.Context, h plugin.Host) error {
	d := p.Descriptor()

	if err := d.ValidateID(); err != nil {
		return fmt.Errorf("houserules: descriptor id: %w", err)
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("houserules: descriptor kind %q is neither system nor feature", d.Kind)
	}
	if d.Kind != plugin.KindFeature {
		return fmt.Errorf("houserules: descriptor kind is %q: this package's whole content model is a frontmatter convention, which only a feature plugin may use", d.Kind)
	}
	// The host refuses a feature plugin that declares a page type, and it does so
	// with a boot error for this plugin alone. Checking it here as well is
	// deliberate: the host's message is a report entry an operator reads weeks
	// later, and this one names the line of code that has to change.
	if len(d.PageTypes) > 0 {
		return fmt.Errorf("houserules: a %s plugin may not register page types: %d declared, and a page type is a game system's vocabulary", plugin.KindFeature, len(d.PageTypes))
	}
	// ParseCapabilities is what catches a typo'd capability name. Without it a
	// misspelling is a capability the plugin believes it holds and nobody does,
	// and the consequence is not an error — it is a silently absent sidebar
	// group or a resolver the host never calls.
	declared, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		return fmt.Errorf("houserules: declared capabilities: %w", err)
	}

	// The host may grant less than the plugin declared, and that is not a
	// failure: the boot report says which names were refused. Every check below
	// is against what was actually granted, through the same functions the host
	// itself runs, so a disagreement about a reserved name is impossible rather
	// than merely likely.
	granted := declared & h.Capability()
	for _, pt := range d.PageTypes {
		if err := plugin.CheckReservedPageType(pt.ID, h.Kind(), granted); err != nil {
			return fmt.Errorf("houserules: page type %q: %w", pt.ID, err)
		}
	}
	for _, pattern := range routePatterns() {
		if err := plugin.CheckReservedRoute(pattern, h.Kind(), granted); err != nil {
			return fmt.Errorf("houserules: route %q: %w", pattern, err)
		}
	}

	p.pages = h.Pages()
	p.now = h.Now

	h.Log(ctx, plugin.LevelInfo, "houserules registered",
		plugin.KV{Key: "page_type", Value: PageTypeHouseRule},
		plugin.KV{Key: "capabilities", Value: d.Capabilities},
		plugin.KV{Key: "granted", Value: granted},
	)
	return nil
}

// routePatterns returns every pattern this plugin mounts, relative to its own
// prefix.
//
// It is a function rather than a hand-kept list so that the pattern Register
// checks against the reserved table and the pattern RegisterRoutes mounts are
// read from one place. A list kept twice is a route that was checked and a
// different route that was mounted.
func routePatterns() []string {
	return []string{indexRoute, rulesRoute}
}

// Now returns the host's clock.
//
// It is the host's and not this package's: a plugin that called time.Now would
// make every timestamp it wrote unfixable in a test, and a frozen clock is the
// only way to assert that two renders of the same page agree.
func (p *Plugin) Now() time.Time {
	if p.now == nil {
		return time.Time{}
	}
	return p.now()
}

// Validate checks the configuration this plugin declares.
//
// It declares none, so there is nothing to check and this returns nil. That is
// an answer and not an omission: a settings table with no reader is a promise to
// a future contributor that a value will be honoured, and a promise nobody keeps
// is how a campaign ends up with a setting the operator can change and the app
// ignores. A key from a newer version of this plugin is likewise not an error —
// refusing to boot because the stored config is from the future is precisely what
// the API-level window in the host exists to prevent.
func (p *Plugin) Validate(plugin.Config) error { return nil }

// reader is the principal every store call this plugin makes is evaluated under,
// and it is resolved rather than chosen.
//
// authz.PrincipalFrom reads the principal the request path already resolved, and
// this package has exactly one call site for it. That is the whole of the
// plugin's authorization story, and every part of it is a property of the host:
//
//   - The request path writes it. httpapi's session middleware calls
//     authz.WithPrincipal once per request, under a key in authz that no other
//     package can name, so there is exactly one key and one writer and two layers
//     cannot disagree about who is asking.
//   - A context that never went through WithPrincipal yields the *zero*
//     Principal: anonymous, and CanReadPublic() == false. Losing a request's
//     identity therefore fails closed — the store answers no rows and the page
//     says so — rather than open.
//
// So there is no default, no fallback and no anonymous stand-in anywhere in this
// package. The two shapes a plugin usually reaches for are both wrong here, and
// each is a leak rather than a degradation:
//
//   - authz.Anonymous(true) as a constant reader would be a plugin deciding who
//     its readers are, and it would under-report every one of them who may read
//     more — a DM would be shown less than a player.
//   - authz.ForUser(id, name, authz.RoleDM, false) would be a plugin inventing an
//     authorization it was never given, which is the one forgery with a working
//     route behind it.
//
// The zero value is worth one more sentence, because it is the direction that
// matters. Do not write `if who.Role != ""` or any other role comparison: the
// Perm middleware is the only place a role is compared, this package has a
// method for the question it actually has, and the zero Principal already answers
// it correctly. Branch on IsDM().
func reader(ctx context.Context) authz.Principal { return authz.PrincipalFrom(ctx) }

// store is the captured page store, or nil when Register never ran.
//
// Descriptor is read before Register, so a resolver declared there can be asked
// a question before this plugin has been given a page store. The answer then is
// no rows and no error: there is no index to read yet, and a resolver that
// invented rows would be worse than one that is quiet.
func (p *Plugin) store() plugin.PageStore {
	if p.pages == nil {
		return nil
	}
	return p.pages
}

// Rule is one house rule, as this plugin understands it.
//
// It is a flat value with no vault type in it — no store.Page, no render model,
// no secret — and that is the point. A component that took a store row would be
// a component whose fields are somebody else's decisions, and the first one
// anybody added would be a frontmatter block with a secret's worth of text in
// it. store.Page carries a raw Frontmatter column, so what reaches a template
// here is four named fields read from it and nothing else.
type Rule struct {
	// ID is the page's index id, which is what an internal link carries in its
	// data-wikilink attribute.
	ID int64
	// Path is vault-relative, and is the same value the page's own URL is built
	// from.
	Path string
	// Title is the page's title, or its basename when it declares none. A rule
	// with an empty title in a list is a rule the reader cannot find.
	Title string
	// System is the `system:` frontmatter value this rule belongs to, or
	// UnassignedSystem.
	System string
	// Tags are the rule's own `tags:`, sorted, and are the only tags this
	// package ever renders. A tag written inside a secret is not in a page's
	// frontmatter at all, so there is nothing here to filter.
	Tags []string
}

// Href is the core page URL for this rule.
//
// It is a method rather than a string in a template because the shape of a core
// page URL is a thing that should be written down once: this package knows the
// prefix the way it knows the sprite's icon tokens, by agreement, and a
// disagreement is a broken link rather than a broken page.
func (r Rule) Href() string {
	if r.Path == "" {
		return ""
	}
	return pluginPageHref + r.Path
}

// HasTag reports whether this rule carries tag, compared the way the tag cloud
// compares: case-insensitively, because a reader who clicks #Combat and is then
// offered #combat has been handed a filter that does not filter.
func (r Rule) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// TagList is the rule's tags as one string, for a chip and for a haystack.
func (r Rule) TagList() string { return strings.Join(r.Tags, " ") }

// conventionFields are the frontmatter keys this package reads.
//
// The list is closed on purpose. An open list would be every key in the page's
// frontmatter, and a page's frontmatter is whatever its author typed — which is
// the difference between reading a convention and reading a page. A key added to
// this list is a key that starts reaching a reader's screen, and the test beside
// it is what makes adding one a decision rather than a slip.
var conventionFields = []string{"type", "title", "system", "tags"}

// conventionOnly parses a page's frontmatter down to the keys this package
// reads, and binds nothing else.
//
// That narrowing is the security property, not a tidy-up. The store hands this
// plugin a page's *raw* frontmatter verbatim — every key the author typed, in
// the order they typed it — and a map that still held all of it is a map a
// later edit could index a snippet out of. A future contributor adding a
// `summary:` field to the search row would be reaching for a key that is here
// today and gone the moment this function stops copying it, and the failure
// looks like a missing field rather than a removed guard.
//
// A block that does not parse yields no fields. The page view is where a
// `frontmatter.invalid` problem is reported, because that is where an author is
// looking; a list that refused to render because one house rule has a typo in
// its YAML would be a worse failure than a list that omits that rule's system
// and tags.
func conventionOnly(fm []byte) map[string]any {
	all, err := md.ParseFields(fm)
	if err != nil {
		return nil
	}
	out := make(map[string]any, len(conventionFields))
	for _, key := range conventionFields {
		if v, ok := all[key]; ok {
			out[key] = v
		}
	}
	return out
}

// ruleOf projects one store page onto a Rule, or reports that the page is not a
// house rule.
//
// The type is re-checked here even though the query already filtered on it. The
// query is the store's statement about the pages column; this is this package's
// statement about what it will render, and a row that arrived with a different
// type — a store that answered a broader question, a fake that did not filter —
// must not be rendered as a rule it is not.
func ruleOf(row store.Page) (Rule, bool) {
	fields := conventionOnly([]byte(row.Frontmatter))
	if md.FieldString(fields, "type") != PageTypeHouseRule {
		return Rule{}, false
	}
	title := row.Title
	if title == "" {
		title = md.FieldString(fields, "title")
	}
	if title == "" {
		title = md.Basename(row.Path)
	}
	system := md.FieldString(fields, "system")
	if system == "" {
		system = UnassignedSystem
	}
	tags := md.FieldStrings(fields, "tags")
	sort.Slice(tags, func(i, j int) bool { return strings.ToLower(tags[i]) < strings.ToLower(tags[j]) })
	return Rule{
		ID:     row.ID,
		Path:   row.Path,
		Title:  title,
		System: system,
		Tags:   tags,
	}, true
}

// rules returns every house rule the store will show who, in title order.
//
// who is the request's own principal, resolved by the caller from the context.
// The order is the store's, not a sort here: ListPagesByType orders by title and
// id, and a second sort could only lose that tie-break. The error is returned as
// well as being visible on the page — this list's whole claim is that it is
// complete, and a complete-looking list built from a query that failed is the
// one output that would make the claim false.
//
// A page who may not see is not in the answer at all rather than present and
// withheld: the store applies the read rules, and a list that filtered a row out
// afterwards would be a filter the count beside it never saw.
func (p *Plugin) rules(ctx context.Context, who authz.Principal) ([]Rule, error) {
	pages := p.store()
	if pages == nil {
		return nil, nil
	}
	rows, err := pages.ListPagesByType(ctx, who, PageTypeHouseRule)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(rows))
	for _, row := range rows {
		rule, ok := ruleOf(row)
		if !ok {
			continue
		}
		out = append(out, rule)
	}
	return out, nil
}

// count is how many house rules the store holds for who.
//
// It is a second query rather than len(rules), and that is the whole point:
// CountPagesByType counts over the identical statement ListPagesByType reads, so
// a badge on this page cannot disagree with the list under it. Deriving the
// number from the list would be right today and wrong the day the list is
// windowed, and AGENTS.md §2.4 is entirely about that day.
func (p *Plugin) count(ctx context.Context, who authz.Principal) (int, error) {
	pages := p.store()
	if pages == nil {
		return 0, nil
	}
	return pages.CountPagesByType(ctx, who, PageTypeHouseRule)
}

// haystack is everything about a rule this package is willing to match a
// reader's term against.
//
// It is the title, the path, the system and the tags — the four fields the
// convention is made of — and nothing else. There is no body to reach, so a
// term that appears only in the prose of a rule matches nothing here, which is
// correct: the core FTS answers body search under the canonical predicate, and a
// plugin that answered it too would be a second answer with no predicate at all.
func (r Rule) haystack() string {
	return strings.ToLower(r.Title + "\x00" + r.Path + "\x00" + r.System + "\x00" + r.TagList())
}

// matches reports whether every term in a reader's query appears in this rule.
//
// Conjunctive, because "two words in a row" is what a reader typing a filter
// means and a disjunctive search is a list of everything, which is the list they
// already had. A query of nothing matches everything: the filter box starts
// empty, and an empty box is not a filter.
func (r Rule) matches(terms []string) bool {
	haystack := r.haystack()
	for _, term := range terms {
		if !strings.Contains(haystack, term) {
			return false
		}
	}
	return true
}

// search turns a search term into derived rows.
//
// The principal is the request's own, resolved from the context, so the rows a
// resolver returns are the rows that reader may have. Scoring is two levels
// rather than a relevance model: a title match outranks a field match, and within
// a level the store's own order stands. There is no tokenizer either — this is a
// substring test over four named fields, not a query language.
//
// A term of nothing asks for nothing, which is what keeps the core's own
// "browse everything" path from being answered by a resolver that would happily
// return the whole list of house rules at the head of it.
func (p *Plugin) search(ctx context.Context, term string) ([]plugin.IndexRow, error) {
	needle := strings.ToLower(strings.TrimSpace(term))
	if needle == "" {
		return nil, nil
	}
	rules, err := p.rules(ctx, reader(ctx))
	if err != nil {
		return nil, err
	}

	type scored struct {
		row   plugin.IndexRow
		score float64
	}
	matches := make([]scored, 0, len(rules))
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		score := rule.score(needle)
		if score == 0 {
			continue
		}
		matches = append(matches, scored{row: rule.row(score), score: score})
	}
	// Insertion sort rather than sort.Slice. The list is bounded by
	// maxSearchRows, so a comparison sort would be O(n log n) on a slice whose
	// construction is already O(pages in the index) — and the store query is the
	// cost either way, so making the sort clever buys nothing but a comparator.
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].score > matches[j-1].score; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
	if len(matches) > maxSearchRows {
		matches = matches[:maxSearchRows]
	}

	out := make([]plugin.IndexRow, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.row)
	}
	return out, nil
}

// score is one rule's match strength for one term: 0 is no match.
//
// The two levels are the two things a reader would search by — what the rule is
// called, and what it is filed under — checked in that order so a title match
// always outranks a tag match.
func (r Rule) score(needle string) float64 {
	if strings.Contains(strings.ToLower(r.Title), needle) {
		return 1
	}
	haystack := strings.ToLower(r.Path + "\x00" + r.System + "\x00" + r.TagList())
	if strings.Contains(haystack, needle) {
		return 0.5
	}
	return 0
}

// row renders a rule as a search row.
//
// The row carries the page id in the href's sibling attribute and never any
// text: everything on it is a name the author typed in the frontmatter or the
// filesystem derived from the file's own path.
func (r Rule) row(score float64) plugin.IndexRow {
	return plugin.IndexRow{
		Kind:  ResultKind,
		Title: r.Title,
		Href:  r.Href(),
		// Summary names the system and the tags, which is what the core row for
		// the same page cannot tell a reader: the core knows the page, and a house
		// rule's filing is what this resolver is for.
		Summary: r.summary(),
		// Ref is the vault-relative path: the object the row points at, and
		// enough to find the file again without a title lookup.
		Ref: r.Path,
		// Score carries the two-level match strength through unchanged, so a host
		// that merges plugin rows into its own ordering has the plugin's ranking
		// rather than a guess at it.
		Score: score,
	}
}

// summary is the one line a search result shows under a title.
func (r Rule) summary() string {
	parts := []string{ResultKind, r.System}
	if tags := r.TagList(); tags != "" {
		parts = append(parts, tags)
	}
	return strings.Join(parts, " · ")
}

// Compile-time proof that the router this plugin hands the host is the type the
// host's RouteMounter names. Without it, a change to either alias would surface
// as a registration failure at boot rather than as a compile error here.
var _ plugin.RouteMounter = (*chi.Mux)(nil)

// itoa is strconv.Itoa, for the places a template wants a number. A function
// rather than an inline conversion in the template, because templ has no
// conversion expression and because one definition is one thing to test.
func itoa(n int) string { return strconv.Itoa(n) }
