package linkpreview

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/a-h/templ"
)

const (
	// ID is this plugin's registry name, kebab-case and stable forever.
	//
	// It is also the last segment of the summary endpoint's URL, which is why it
	// is a constant rather than a literal at each use: core's client builds
	// /plugin/{id}/summary/{pageID} from the id it was given, and a plugin whose
	// id is spelled two ways is a preview that 404s on every hover.
	ID = "linkpreview"

	// Name is what an operator reads in the boot report.
	Name = "Link preview"

	// Version is this plugin's own semver, and not the APILevel: the two move
	// independently, and a plugin bump is what tells a reader a behaviour
	// changed while the host contract stood still.
	Version = "0.1.0"

	// providerID is the summary provider's id, unique within this plugin, and
	// what the host's provider registry tells two contributions apart by.
	providerID = "linkpreview.page_summary"
)

// capabilities is what this plugin declares: one, and only one.
//
// CapPageSummaries is what binds the core link-preview interaction, and it is
// the whole of what this plugin does. The ten others the host knows are each the
// gate on a contribution that does not exist here — no page type, no panel, no
// nav item, no resolver, no backlink resolver, no exporter — and declaring one
// anyway is the shape AGENTS.md §7 calls a control with nothing behind it.
// Omitting CapPageSummaries is the worse failure: the host would discard the
// provider and the preview would simply never appear.
var capabilities = []plugin.Capability{
	plugin.CapPageSummaries,
}

// Plugin is the link-preview feature plugin.
//
// It holds what the host granted it at Register and nothing else: the clock and
// the page read surface. It holds no vault content — every string a card renders
// was read through the page store with the request's own principal and is
// discarded with the request.
type Plugin struct {
	// now is the host's clock, captured at Register as a method value. A plugin
	// never calls time.Now: a clock the host does not own is a clock no test can
	// freeze.
	now func() time.Time

	// pages is the authz-filtered read surface the host granted, captured at
	// Register and read at request time. Both halves matter, and the second is
	// the surprising one: the host collects a plugin's summary providers while
	// building the host, which is before Register has run, so a provider that
	// captured the store by value would be holding the one a host without a page
	// store hands out — the one that answers ErrNoRows to everything.
	pages plugin.PageStore
}

// New returns a plugin that has not yet been registered against a host.
//
// The zero value would answer a question about the clock with a nil call, so the
// constructor installs the one honest stand-in — the zero time — and Register
// replaces it with the host's.
func New() *Plugin {
	return &Plugin{now: func() time.Time { return time.Time{} }}
}

// Compile-time proof that the Plugin and both halves of the contract are
// implemented. PluginUI is not optional here: Summaries is on it, and a host
// that cannot reach Summaries cannot reach a preview at all.
var (
	_ plugin.Plugin     = (*Plugin)(nil)
	_ plugin.PluginCore = (*Plugin)(nil)
	_ plugin.PluginUI   = (*Plugin)(nil)
)

// Descriptor returns the whole static declaration.
//
// Every slice in it is empty on purpose, and not by omission: a feature plugin
// may not register page types, and a nav item without a route behind it is the
// broken control the working agreement rules out. The empty ones are asserted by
// name in the descriptor test rather than left to a reader to notice.
func (p *Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:        ID,
		Name:      Name,
		Kind:      plugin.KindFeature,
		Version:   Version,
		APILevel:  plugin.APILevel,
		PageTypes: nil,
		NavItems:  nil,
		// Cloned because a Descriptor is mutable and a caller may reorder its
		// slices; handing out the package-level table would let the first caller
		// to touch it change what every later caller sees. The cost is one
		// allocation per call, which happens at boot.
		Capabilities: slices.Clone(capabilities),
	}
}

// Register wires this plugin into a host.
//
// Everything the host needs is derived from Descriptor, so the sequence is: check
// the declaration is admissible, then capture what the host granted and what it
// offers. Every step returns an error rather than panicking, because a panic
// during boot takes the app down for a condition that is contained to this
// plugin.
//
// Nothing is mounted here and no router is touched. The host builds a sub-router
// already prefixed at /plugin/linkpreview and already wrapped in its middleware,
// and it hands that router to RegisterRoutes afterwards; the summary endpoint is
// core's own, and mounting a second one would put a plugin in front of the
// byte-identical 404 a plugin cannot produce.
func (p *Plugin) Register(ctx context.Context, h plugin.Host) error {
	d := p.Descriptor()

	if err := d.ValidateID(); err != nil {
		return fmt.Errorf("linkpreview: descriptor id: %w", err)
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("linkpreview: descriptor kind %q is neither system nor feature", d.Kind)
	}
	// ParseCapabilities is what catches a typo'd capability name. Without it a
	// misspelling is a capability the plugin believes it holds and nobody does,
	// and the consequence is not an error — it is a preview that never appears.
	declared, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		return fmt.Errorf("linkpreview: declared capabilities: %w", err)
	}

	// The host may grant less than the plugin declared, and that is not a
	// failure: the boot report says which names were refused, and it discards the
	// provider itself. Every check below is against what was actually granted,
	// through the same function the host itself runs, so a disagreement about a
	// capability is impossible rather than merely unlikely.
	granted := declared & h.Capability()

	p.now = h.Now
	p.pages = h.Pages()

	h.Log(ctx, plugin.LevelInfo, "linkpreview registered",
		plugin.KV{Key: "capabilities", Value: d.Capabilities},
		plugin.KV{Key: "granted", Value: granted},
		plugin.KV{Key: "provider", Value: providerID},
	)
	return nil
}

// CoreTypes returns the page types this plugin claims: none.
//
// A feature plugin is refused a page type whether it declares one or builds one
// here, and a page type is a game system's vocabulary. A feature expresses
// content through frontmatter conventions, and a preview card expresses content
// through store.PageSummary.
func (p *Plugin) CoreTypes() []plugin.PageType { return nil }

// MarkdownExtenders returns the goldmark extenders this plugin contributes: none.
//
// The card renders a store.PageSummary, not markdown, so there is nothing for an
// extender to parse. Returning an empty list keeps the composite goldmark from
// growing a parser that draws nothing on every page in the vault.
func (p *Plugin) MarkdownExtenders() []any { return nil }

// ConfigSchema returns the configuration this plugin declares: none.
//
// There is a setting worth having here — a maximum excerpt length, an excerpt on
// or off — and it is deliberately absent. A schema is a promise that a value will
// be read and validated, and a promise with no reader is a control with nothing
// behind it. The one length that does exist is store.SummaryExcerptMaxChars,
// which is applied in SQL by the query rather than by whoever reads its result,
// and a plugin-side copy of that number would be a second source of truth for a
// length a reader is already protected by.
func (p *Plugin) ConfigSchema() map[string]any { return nil }

// Panels returns the sidebar panels this plugin contributes: none.
//
// The card is a hover affordance, not a place a reader keeps a panel open in, and
// a panel is the one contribution that renders on every page in the vault whether
// or not a reader ever points at a link.
func (p *Plugin) Panels() []plugin.Panel { return nil }

// RegisterRoutes mounts nothing.
//
// This is a decision and not an oversight, and it is the same one the reference
// system plugin makes for its summary provider. The summary endpoint is
// GET /plugin/{id}/summary/{pageID}, and core mounts it in
// internal/httpapi/routes.go and resolves the provider this package registered.
// A second mount of the same path would be chi's rule — first handler wins, and
// the second is invisible — and would put a plugin in front of the
// byte-identical 404 that httpapi.writeError produces and a plugin cannot
// reproduce. A route nothing calls is a control with nothing behind it, so this
// package mounts none and its own prefix stays empty.
func (p *Plugin) RegisterRoutes(plugin.RouteMounter) {}

// NavItems returns the sidebar items this plugin contributes: none.
//
// There is nothing on a sidebar to link to. The card appears on hover over a
// link the reader is already looking at, and the one URL this plugin is ever
// reached at is core's summary endpoint, which is not a page a reader navigates
// to.
func (p *Plugin) NavItems() []plugin.NavItem { return nil }

// Summaries returns the one summary provider this plugin contributes.
//
// It is returned unconditionally rather than on some capability this package
// checks for itself. The host already gated it: plugin.Host collects providers
// only from a plugin holding CapPageSummaries, and discards the rest with a
// warning. A plugin re-deriving that decision would give the same answer twice
// and a chance to disagree once.
func (p *Plugin) Summaries() []plugin.SummaryProvider {
	return []plugin.SummaryProvider{summaryProvider{pages: p.pageStore}}
}

// pageStore returns the read surface captured at Register.
//
// It is a method rather than a field read so that a provider holding it does not
// capture a value: the host collects providers before Register has run, so the
// store is only ever known as a method to call later.
func (p *Plugin) pageStore() plugin.PageStore { return p.pages }

// Validate checks this plugin's configuration.
//
// There is none, and the method is empty for the same reason ConfigSchema is: an
// implementation that validated nothing would be a second, unused code path, and
// the interface requires the method rather than the behaviour.
func (p *Plugin) Validate(plugin.Config) error { return nil }

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

// summaryProvider answers one page: what a card says about it.
//
// A named type rather than a closure so that the provider can be identified in
// the host's registry and asserted on in a test without matching a string. It
// holds no state at all — the read surface and the principal are both resolved
// per request — so there is nothing on it that can go stale between an
// authorization decision and the read that follows it.
type summaryProvider struct {
	// pages reads the store the host granted, at request time. See the field
	// comment on Plugin.pages for why it is a call and not a value.
	pages func() plugin.PageStore
}

// Compile-time proof that this type is the provider the host invokes.
var _ plugin.SummaryProvider = summaryProvider{}

// ID names the provider, so two plugins contributing one cannot collide in the
// host's provider registry.
func (summaryProvider) ID() string { return providerID }

// Summary answers one page, or declines it.
//
// The three answers are the whole contract, and they are produced in order of how
// much they can hurt:
//
//  1. ok=false with no error, for a page this principal may not have.
//     store.ErrNoRows means three things a reader must not be able to tell apart
//     — the page does not exist, the principal may not read it, or it has no
//     public text — and collapsing them here is what keeps a preview from
//     becoming a probe for pages. Core turns this into a 404 byte-identical to
//     navigating to the page.
//  2. An error, for anything else. Core logs it with a type and a hash and
//     answers 404 rather than 500, because a 500 says "this page exists" to
//     anyone who can tell the two apart. The error names the page id and wraps
//     the cause; it never carries page text, because an error that quoted the
//     page would be a way to get vault text into a log line.
//  3. A component, for a page this principal may read.
func (s summaryProvider) Summary(ctx context.Context, pageID int64) (templ.Component, bool, error) {
	// A page id that could not have come from the route. Core parses the URL
	// parameter and refuses a non-integer or a non-positive one before it gets
	// here, so reaching this is a second caller's bug rather than a reader's
	// input — and the answer is the same decline either way, because a decline
	// and a refusal cost the reader nothing and cost a probe nothing.
	if pageID <= 0 {
		return nil, false, nil
	}
	pages := s.pages()
	if pages == nil {
		// Unreachable in a booted app: the host builds its sub-router and its
		// page store before it serves anything. It is here because a nil
		// dereference inside a request handler is a panic the reader sees as a
		// dropped connection, and a decline is the same answer a missing page
		// gets.
		return nil, false, nil
	}

	// The principal is the request's own, read out of the context core passed
	// straight through, and it is the only one this package will ever use. There
	// is no default, no fallback and no anonymous stand-in: a plugin that could
	// answer "who is this, roughly" would be one that could be edited into
	// answering "who is this, generously" without a test noticing.
	//
	// A context that never went through authz.WithPrincipal yields the zero
	// Principal, which is anonymous and cannot read public content, so the page
	// store declines every page. That is the safe direction — a caller that lost
	// the request's identity reads nothing rather than reading everything — and
	// it is why this function does not have to check for a missing principal:
	// asking is safe, and not asking is not.
	who := authz.PrincipalFrom(ctx)

	sum, err := pages.GetPageSummary(ctx, who, pageID)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("linkpreview: summary for page %d: %w", pageID, err)
	}
	return summaryCard(cardFrom(sum)), true, nil
}

// Card is what a preview says about a page.
//
// A flat value over fields this package chose, with no core type in it — no
// store.PageSummary, no page, no secret, no render model. A card built over a
// core row would be a component whose fields are somebody else's decisions, and
// the first one anybody added would be a field the store had deliberately not
// selected. Every string below came back from a single call that took a
// principal, and none of them is reachable by a route that did not.
type Card struct {
	// Title is the page's title, or its basename when it has none.
	Title string
	// Excerpt is the leading public text, already capped and already marked with
	// an ellipsis by the query when there was more. It is never secret-derived,
	// because the row it came from is written from the page's public body and
	// nothing else — the spans a secret occupied are not in the source, so there
	// is nothing here to redact and no placeholder whose shape could leak the
	// size of what it hid.
	Excerpt string
	// Tags are the page's public tags, sorted. A tag written inside a secret
	// this principal may not read is absent rather than greyed out, for the same
	// reason the excerpt has no placeholder.
	Tags []string
	// UpdatedAt is the page's last indexed modification time. The zero value
	// means the indexer has not stamped it, and the card omits the row rather
	// than showing the year 1.
	UpdatedAt time.Time
}

// cardFrom builds a card from the one row the page store returns.
//
// Every field is copied out by name. Reading the struct as a whole would carry
// whatever a future field turns out to be into the card without anybody deciding
// that a preview should show it, which is the direction this field list has to be
// reviewed in.
func cardFrom(sum store.PageSummary) Card {
	return Card{
		Title:     sum.Title,
		Excerpt:   sum.Excerpt,
		Tags:      slices.Clone(sum.Tags),
		UpdatedAt: sum.UpdatedAt,
	}
}
