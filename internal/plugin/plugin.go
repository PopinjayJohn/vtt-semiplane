package plugin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// Kind discriminates the two shapes of plugin. There is one interface, one
// registry, one lifecycle and one route prefix for both; Kind exists so that
// the host can enforce the two rules that actually differ between them.
type Kind string

const (
	// KindSystem models a roleplaying game: registered page types with custom
	// editors and viewers, character sheets, rules.
	KindSystem Kind = "system"
	// KindFeature adds system-agnostic functionality: navigation, previews,
	// import. A feature plugin may not register page types.
	KindFeature Kind = "feature"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k == KindSystem || k == KindFeature }

// Capability is a permission a plugin declares to be granted. Declaration is
// checked against the host's own grant at boot; declaring something the host
// does not hold is a startup error for that plugin.
type Capability string

const (
	// CapCharacterSheet is the character page type and per-field rolls.
	CapCharacterSheet Capability = "character_sheet"
	// CapMaps is the map page type, tokens and fog.
	CapMaps Capability = "maps"
	// CapEncounters is the encounter builder and initiative tracker.
	CapEncounters Capability = "encounters"
	// CapDice is dice notation and the roll UI.
	CapDice Capability = "dice"
	// CapRules is rules reference pages.
	CapRules Capability = "rules"

	// CapUIPanels contributes sidebar and editor panels.
	CapUIPanels Capability = "ui_panels"
	// CapSidebarNav contributes left-sidebar navigation items.
	CapSidebarNav Capability = "sidebar_nav"
	// CapPageSummaries serves per-page summaries for link previews.
	CapPageSummaries Capability = "page_summaries"
	// CapSearchResolvers contributes derived search rows.
	CapSearchResolvers Capability = "search_resolvers"
	// CapBacklinks contributes extra related-entity resolvers.
	CapBacklinks Capability = "backlinks"
	// CapExporters contributes export formats.
	CapExporters Capability = "exporters"
)

// Capabilities is the runtime bitmask form of a declared capability slice. The
// slice is declaration sugar; the bitmask is what the host checks.
type Capabilities uint16

const capCount = 11

// Set reports whether c is present in the set.
func (s Capabilities) Set(c Capability) bool {
	b, ok := capBits[c]
	return ok && s&b != 0
}

// Has reports whether c is in the set. It is the check the host makes at every
// point where it would otherwise act on a plugin's word.
func (s Capabilities) Has(c Capability) bool { return s.Set(c) }

// With returns the set with c added.
func (s Capabilities) With(c Capability) Capabilities {
	b, ok := capBits[c]
	if !ok {
		return s
	}
	return s | b
}

// All returns every known capability. The host grants this to a
// first-party, in-tree plugin; a subprocess host would grant less.
func All() Capabilities {
	var s Capabilities
	for _, c := range AllCapabilities {
		s = s.With(c)
	}
	return s
}

// List returns the capabilities in the set, in declaration order, for display.
func (s Capabilities) List() []Capability {
	out := make([]Capability, 0, capCount)
	for _, c := range AllCapabilities {
		if s.Has(c) {
			out = append(out, c)
		}
	}
	return out
}

// AllCapabilities is every capability the host knows, in a stable order.
var AllCapabilities = []Capability{
	CapCharacterSheet, CapMaps, CapEncounters, CapDice, CapRules,
	CapUIPanels, CapSidebarNav, CapPageSummaries, CapSearchResolvers,
	CapBacklinks, CapExporters,
}

var capBits = func() map[Capability]Capabilities {
	m := make(map[Capability]Capabilities, len(AllCapabilities))
	for i, c := range AllCapabilities {
		m[c] = Capabilities(1) << i
	}
	return m
}()

// ParseCapabilities converts a declared slice into a bitmask, reporting an
// unknown capability rather than ignoring it.
func ParseCapabilities(names []Capability) (Capabilities, error) {
	var s Capabilities
	for _, n := range names {
		if _, ok := capBits[n]; !ok {
			return 0, errors.New("unknown capability " + string(n))
		}
		s = s.With(n)
	}
	return s, nil
}

// APILevel is the host interface level this binary implements. It is bumped on
// any breaking change to Plugin, PluginCore, PluginUI, Descriptor, PageType,
// NavItem, Panel or the host surface.
const APILevel = 1

// APIWindow is how far below the current level a plugin may be. Outside the
// window the plugin is refused: a plugin written against a newer host may rely
// on a host that does not exist yet, and one written against a much older host
// costs more to shim than it is worth.
const APIWindow = 2

// Admit reports the admission decision for a plugin declaring the given API
// level: ok, or skipped with a reason.
func Admit(hostLevel, pluginLevel int) (admitted bool, reason string) {
	switch {
	case pluginLevel > hostLevel:
		return false, fmt.Sprintf("plugin requires host API level %d, this host is level %d",
			pluginLevel, hostLevel)
	case pluginLevel < hostLevel-APIWindow:
		return false, fmt.Sprintf("plugin targets host API level %d, this host supports %d and up",
			pluginLevel, hostLevel-APIWindow)
	default:
		return true, ""
	}
}

// Compat reports whether an admitted plugin is old enough to need the compat
// shim, which supplies zero values for struct fields added since it was
// written. Version skew is always visible in the boot report, never silent.
func Compat(hostLevel, pluginLevel int) bool { return pluginLevel < hostLevel }

// WikiLinkAttr is the attribute the core link renderer puts on every internal
// link, carrying the target page id. The core link-preview interaction in
// app.js binds to exactly this attribute; a plugin that wants its links
// previewable emits it, and never emits its own hover behaviour. The attribute
// value is an integer page id and never a title, a path, or any content.
const WikiLinkAttr = "data-wikilink"

// WikiLink returns the attribute map for an internal link to pageID.
func WikiLink(pageID int64) templ.Attributes {
	return templ.Attributes{WikiLinkAttr: strconv.FormatInt(pageID, 10)}
}

// SchemaField is one editable frontmatter field of a registered page type.
type SchemaField struct {
	// Key is the frontmatter key.
	Key string
	// Name is the human label.
	Name string
	// Type is "text", "textarea", "number", "bool", "select" or "tags".
	Type string
	// Options applies to "select".
	Options []string
	// Required marks the field as mandatory on save.
	Required bool
	// Help is optional inline guidance.
	Help string
}

// PageType is a registered page type with an optional custom editor and
// viewer.
//
// A registered page type is a system-plugin concern. A page-type *convention* —
// a plain `type:` string in frontmatter that the core markdown viewer renders
// like any other page — is free-form and may be claimed by a feature plugin
// with no registration at all. That distinction is what lets `type: houserule`
// work without a game system being installed.
type PageType struct {
	// ID is the frontmatter `type:` value this page type claims.
	ID string
	// Name is the human label.
	Name string
	// Icon is a token from the core icon set, never raw HTML or a URL.
	Icon string
	// FrontmatterSchema is the set of fields the structured editor manages.
	FrontmatterSchema map[string]SchemaField
	// Editor is an optional custom editor surface. nil means the core
	// Markdown editor.
	Editor templ.Component
	// Viewer is an optional custom viewer. nil means the core Markdown view.
	Viewer templ.Component
	// SidePanels are panels shown for pages of this type.
	SidePanels []Panel
}

// NavItem is one entry in the left sidebar's plugin navigation group. It is a
// link, not a live list, so it behaves identically whether the sidebar is
// expanded, collapsed, or a mobile drawer.
type NavItem struct {
	// ID is unique across the whole registry.
	ID string
	// Label is the visible text.
	Label string
	// Href must be inside the owning plugin's own route prefix. A violation is
	// a registration error, not a broken link.
	Href string
	// Icon is a token from the core icon set.
	Icon string
	// Order sorts the group; lower comes first.
	Order int
	// Badge is an optional live count, e.g. an unread total. It is evaluated
	// per request with the request's own principal, so it is authz-filtered by
	// construction.
	Badge func(ctx context.Context) (text string, show bool)
	// MinimumRole is the role a principal needs for the item to appear.
	MinimumRole string
}

// Slot names the region a panel occupies. Core renders the slot containers;
// a panel declaring an unknown slot is dropped with a warning.
type Slot string

const (
	SlotRightTop      Slot = "right-top"
	SlotRightMid      Slot = "right-mid"
	SlotRightBottom   Slot = "right-bottom"
	SlotLeftBottom    Slot = "left-bottom"
	SlotEditorToolbar Slot = "editor-toolbar"
	SlotPageActions   Slot = "page-actions"
)

// KnownSlots is the set of slots core renders. Anything else is dropped.
var KnownSlots = map[Slot]bool{
	SlotRightTop: true, SlotRightMid: true, SlotRightBottom: true,
	SlotLeftBottom: true, SlotEditorToolbar: true, SlotPageActions: true,
}

// Panel is a templ component contributed for a slot. It is a first-class
// templ.Component, so it is escaped by construction; a plugin may still write
// templ.Raw, which is why the review checklist mentions it.
type Panel struct {
	// Slot is where the panel is rendered.
	Slot Slot
	// Order sorts panels within a slot; lower comes first.
	Order int
	// Component is the panel body. It receives no vault content that the
	// requesting principal may not read.
	Component templ.Component
	// PageType restricts the panel to pages of one type. Empty means all.
	PageType string
}

// PageStore is the read surface a plugin is given over indexed pages.
//
// It is an interface over store's authz-filtered queries rather than a *sql.DB,
// and the difference is the whole design. A plugin that could reach a database
// would be one SQL statement away from every secret in the vault; a plugin that
// can only call these four methods cannot compose its own predicate at all, so
// the "did you remember to filter" question has no wrong answer available.
//
// Every method takes the principal. That is not ceremony: a query whose filtering
// is added later by someone in a hurry is a query where the count and the list
// stop agreeing, and taking the principal as a parameter is what forces the
// decision to be made at the signature rather than at the call site.
//
// Nothing here returns secret-derived text. A summary's excerpt comes from
// page_text.body, which the indexer writes from md.Doc.PublicBody() and nothing
// else, so a secret body is not in the table to be selected — the guarantee is a
// property of what is stored rather than of a filter a caller has to remember.
type PageStore interface {
	// GetPageSummary returns the public card for one page: title, a bounded
	// public excerpt, the public tags, and the last-updated time. A page that
	// does not exist, one the principal may not read, and one with no public text
	// all return store.ErrNoRows, because a preview must not become a way to
	// probe for pages.
	GetPageSummary(ctx context.Context, who authz.Principal, pageID int64) (store.PageSummary, error)
	// ListPagesByType returns the pages carrying one frontmatter type. This is
	// how a feature plugin reads a convention such as `type: houserule` without
	// registering a page type for it.
	ListPagesByType(ctx context.Context, who authz.Principal, pageType string) ([]store.Page, error)
	// CountPagesByType returns the number of rows ListPagesByType would return,
	// over the identical statement. A badge built from a separate count is how a
	// list and its number come to disagree.
	CountPagesByType(ctx context.Context, who authz.Principal, pageType string) (int, error)
	// ListTags returns the tag cloud, filtered by the same predicate the tag page
	// uses. A preview card and a tag page that disagree about what exists are one
	// of the more confusing pairs of surfaces there is to ship.
	ListTags(ctx context.Context, who authz.Principal) ([]store.TagCount, error)
}

// IndexRow is one derived row a search resolver contributes to /search and
// /api/search. The resolver is authz-filtered by construction, using the same
// predicate as the core query, and rows it must not expose are simply not
// returned.
type IndexRow struct {
	// Kind is the badge shown for the row, e.g. "House rule".
	Kind string
	// Title is the display title.
	Title string
	// Href is where the row navigates to.
	Href string
	// Summary is a short public excerpt. Never secret-derived.
	Summary string
	// Score is the resolver's own relevance, combined with core ranking.
	Score float64
	// Ref is the object the row points at, for the audit trail.
	Ref string
}

// SearchResolver contributes derived rows to search. It requires
// CapSearchResolvers; without it the host discards the resolver and never
// calls it.
type SearchResolver struct {
	ID    string
	Query func(ctx context.Context, q string) ([]IndexRow, error)
}

// Migration is one plugin-owned schema step, applied by the host inside the
// host's migration transaction. A plugin cannot run arbitrary DDL at register
// time, and a plugin migration that collides is rolled back on its own without
// touching other plugins.
type Migration struct {
	// Version is the monotonic step number, starting at 1.
	Version int
	// Name is a human label, used in the boot report.
	Name string
	// SQL is the statement. Additive only: new table, new nullable column, new
	// index.
	SQL string
}

// Descriptor is everything a plugin declares about itself. It is static data:
// the host reads it before calling Register, and the version gate and the
// Kind rules run against it.
type Descriptor struct {
	// ID is kebab-case and stable forever, e.g. "dnd5e", "houserules".
	ID string
	// Name is the human label.
	Name string
	// Kind discriminates a system plugin from a feature plugin.
	Kind Kind
	// Version is the plugin's own semver.
	Version string
	// APILevel is the host interface level this plugin was written against.
	APILevel int
	// Capabilities is the declaration; the host grants a subset.
	Capabilities []Capability
	// PageTypes MUST be empty when Kind is KindFeature. A violation is a boot
	// error for that plugin alone.
	PageTypes []PageType
	// NavItems requires CapSidebarNav; without it they are discarded at boot
	// with a warning and the sidebar renders no plugin group at all.
	NavItems []NavItem
	// SearchResolvers requires CapSearchResolvers.
	SearchResolvers []SearchResolver
	// ConfigSchema describes the plugin's namespaced configuration.
	ConfigSchema map[string]any
	// Migrations are the plugin's own tables, applied by the host.
	Migrations []Migration
}

// ValidateID reports whether id is a usable plugin id: non-empty, kebab-case,
// and not one of the reserved names.
func (d Descriptor) ValidateID() error {
	if d.ID == "" {
		return errors.New("plugin id is empty")
	}
	if strings.ToLower(d.ID) != d.ID {
		return errors.New("plugin id " + d.ID + " must be lowercase")
	}
	for _, r := range d.ID {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return errors.New("plugin id " + d.ID + " contains an invalid character")
		}
	}
	return nil
}

// Config is a plugin's namespaced configuration, already typed by the host.
type Config struct {
	// ID is the owning plugin.
	ID string
	// Values are the plugin's settings, unmarshalled from the plugin's own
	// table. The host never exposes core configuration here.
	Values map[string]any
}

// Get returns a string setting, or def when unset.
func (c Config) Get(key, def string) string {
	if s, ok := c.Values[key].(string); ok && s != "" {
		return s
	}
	return def
}

// Bool returns a boolean setting, or def when unset.
func (c Config) Bool(key string, def bool) bool {
	if b, ok := c.Values[key].(bool); ok {
		return b
	}
	return def
}

// Int returns an integer setting, or def when unset.
func (c Config) Int(key string, def int) int {
	switch n := c.Values[key].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return def
	}
}

// KV is a log key/value pair handed to Host.Log.
type KV struct {
	Key   string
	Value any
}

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelError:
		return "error"
	default:
		return "warn"
	}
}

// PluginCore is the process-agnostic half of the plugin contract: everything a
// plugin does that produces data rather than markup — page types' schemas,
// markdown extenders, search resolvers, navigation descriptors, config.
//
// The split exists so that a future subprocess or wasm host can implement
// PluginCore without templ components crossing the boundary. PluginUI is the
// in-process half. Both are optional except for Descriptor and Register.
type PluginCore interface {
	// CoreTypes returns page-type descriptors without their templ components.
	CoreTypes() []PageType
	// MarkdownExtenders returns goldmark extenders. The host builds one
	// composite parser from core extenders plus every plugin's, in sorted
	// plugin order.
	MarkdownExtenders() []any
	// ConfigSchema describes the plugin's settings.
	ConfigSchema() map[string]any
}

// PluginUI is the in-process half: templ components and mounted routes. A
// host that cannot call Go in-process implements PluginCore only.
type PluginUI interface {
	// Panels returns the panels this plugin contributes.
	Panels() []Panel
	// RegisterRoutes mounts routes on a sub-router that is already prefixed at
	// /plugin/{id} and already wrapped in session and role middleware. A
	// plugin cannot register outside its prefix and cannot remove middleware.
	RegisterRoutes(sub RouteMounter)
	// NavItems returns left-sidebar navigation entries.
	NavItems() []NavItem
	// Summaries returns the page-summary providers for link previews.
	Summaries() []SummaryProvider
}

// SummaryProvider serves a short, authz-filtered summary of a page for the core
// link-preview interaction. The plugin supplies content; core owns the hover,
// focus, pin and ARIA behaviour, so a plugin ships no JavaScript.
type SummaryProvider interface {
	// ID identifies the provider within its plugin.
	ID() string
	// Summary returns a templ component for the page. Returning ok=false makes
	// the preview degrade to a plain link.
	Summary(ctx context.Context, pageID int64) (body templ.Component, ok bool, err error)
}

// RouteMounter is the router surface the host hands to a plugin. It is a named
// type rather than a raw *chi.Mux so that the plugin import boundary test has
// a single name to look for, and so a future subprocess host can swap the
// implementation for a recording proxy without changing the interface.
type RouteMounter = *chi.Mux

// Plugin is the one interface every plugin implements, of either kind. There
// is no second code path for features.
type Plugin interface {
	// Descriptor returns the plugin's static declaration.
	Descriptor() Descriptor
	// Register hands the plugin its capability-scoped host. A returned error
	// disables the plugin and is reported in /admin/plugins; boot continues.
	Register(ctx context.Context, h Host) error
	// Validate checks configuration after registration.
	Validate(cfg Config) error
	// Now returns the host clock, so plugins never call time.Now directly and
	// a test can freeze it.
	Now() time.Time
}

// Host is the narrow, capability-scoped surface a plugin is given. Its full
// definition arrives with the plugin phase; the shape is fixed now.
type Host interface {
	// Log writes a structured log line through the host's redacting handler.
	// It never carries vault content.
	Log(ctx context.Context, l Level, msg string, kv ...KV)
	// Capability returns what this plugin was actually granted.
	Capability() Capabilities
	// Kind lets a plugin branch once, at register time.
	Kind() Kind
	// Config returns the plugin's namespaced, persisted configuration.
	Config() Config
	// FS returns a read-only, vault-relative view of public content. It
	// cannot reach a secret body: the FS handed to a plugin is built from
	// public spans only.
	FS() fs.FS
	// Pages returns the authz-filtered page read surface. It is a named set of
	// queries rather than a database, so a plugin cannot compose its own
	// visibility predicate and cannot be handed a *sql.DB from which one could be
	// composed.
	Pages() PageStore
	// RegisterRoutes mounts routes inside the plugin's own prefix.
	RegisterRoutes(sub RouteMounter)
	// RegisterPanels returns the panels this plugin contributes. Results are
	// discarded with a warning when CapUIPanels is not granted.
	RegisterPanels() []Panel
	// RegisterMarkdown returns goldmark extenders.
	RegisterMarkdown() []any
	// RegisterPageTypes returns the page types this plugin claims. Calling it
	// from a KindFeature plugin is a boot error.
	RegisterPageTypes() []PageType
	// Now returns the host clock.
	Now() time.Time
}
