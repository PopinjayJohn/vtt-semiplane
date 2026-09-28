// Package dnd5e is the reference system plugin: the character and rule page
// types, a sheet editor, one right-sidebar panel, and a search resolver.
//
// It exists so that the plugin architecture is proven against real code rather
// than against its own documentation. A change to core that only this plugin
// needs is a bug in the architecture, and the two reserved page-type ids it
// claims — character and rule — are among the few names in the system whose
// reservation is exercised by something that ships.
//
// The files are split by what they own. plugin.go is the Plugin implementation
// and the static declaration behind it: capabilities, page types, nav, config,
// migration, and the search resolver. hostcall.go is the two halves the host
// calls into — PluginCore and PluginUI — and the HTTP handlers behind them. The
// .templ files are components over Go values this package owns. None of them is
// handed vault content this package cannot already reach, and none of them
// contains a script, a style or a DOM handle, because the Host interface has no
// method that could install one.
package dnd5e

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/go-chi/chi/v5"
)

const (
	// ID is this plugin's registry name, kebab-case and stable forever. The
	// same string is the migration table prefix and the route prefix, so it is a
	// constant rather than a literal repeated at each use.
	ID = "dnd5e"

	// Name is what an operator reads in the boot report.
	Name = "D&D 5e"

	// Version is this plugin's own semver, and not the APILevel: the two move
	// independently, and a plugin bump is what tells a reader a behaviour
	// changed while the host contract stood still.
	Version = "0.1.0"

	// PageTypeCharacter is the reserved page-type id claimed with
	// CapCharacterSheet.
	PageTypeCharacter = "character"

	// PageTypeRule is the reserved page-type id claimed with CapRules. It is
	// registered so that `type: rule` in frontmatter carries a schema rather
	// than rendering as an unknown type.
	PageTypeRule = "rule"

	// NavID is the sidebar nav item's id. Nav ids are unique across the whole
	// registry rather than per plugin, so the id is namespaced.
	NavID = "dnd5e.index"

	// IndexHref is where the nav item points, and it is the plugin's own route
	// prefix and nothing else. A nav href outside the prefix is a registration
	// error rather than a working link, and a link to a page the plugin did not
	// mount is a control with nothing behind it.
	IndexHref = "/plugin/" + ID

	// characterRoute is the sheet route, relative to the plugin prefix.
	//
	// The catch-all is deliberate rather than a shorthand for {id}. Page paths
	// are vault-relative and therefore contain slashes, so a {id} parameter
	// would not match Characters/Gundren.md and the route would answer 404 for
	// most of the pages it exists to serve. The plan's /character/{id} is a
	// page *id*; the only page surface a plugin can reach today is
	// Host.FS(), which is keyed by path, so the route is keyed by path too.
	characterRoute = "/character/*"

	// indexRoute is the plugin's root route. RouteReservation trims the
	// separator and finds no segment in it, so the root claims no reserved name
	// and needs no capability — the correct answer for a route that carries the
	// plugin's own name and links to nothing outside its prefix.
	indexRoute = "/"

	// maxSearchRows bounds what one resolver call contributes. The core clamps
	// its own limits; a plugin that did not would make a single keystroke walk
	// a whole vault.
	maxSearchRows = 20

	// maxSheetBytes is the largest file the sheet and search readers open. A
	// vault can hold a megabyte on a single unbroken line — internal/md/testdata
	// has one — and a route that reads every note in the vault to render a
	// field list is a way to make one request consume the machine.
	maxSheetBytes = 1 << 20
)

// capabilities is what this plugin declares.
//
// Each name here is load-bearing, and the reason differs for each, which is why
// the list is written out rather than assembled from a table:
// CapCharacterSheet and CapRules are what make the two reserved page-type ids
// admissible; CapUIPanels is what keeps the panel from being discarded with a
// warning; CapSidebarNav is what keeps the sidebar from hiding the group;
// CapPageSummaries is what binds the core link-preview interaction;
// CapSearchResolvers is what keeps the host from discarding the rows below.
//
// A capability that is declared and unused is a control with nothing behind it,
// so each of the six has a contribution in hostcall.go. A capability that is
// omitted is the worse failure: the name it gates is refused, and the plugin
// takes a reserved name away from whoever legitimately holds it.
var capabilities = []plugin.Capability{
	plugin.CapCharacterSheet,
	plugin.CapRules,
	plugin.CapUIPanels,
	plugin.CapSidebarNav,
	plugin.CapPageSummaries,
	plugin.CapSearchResolvers,
}

// Plugin is the D&D 5e system plugin.
//
// It holds what the host gave it — the clock, the public filesystem, the
// configuration table — because the Host interface offers no way to ask for any
// of them a second time and a route has to answer with them. It holds no vault
// content: everything below is derived from the public filesystem on demand and
// discarded with the request.
type Plugin struct {
	// now is the host's clock, captured at Register as a method value. A plugin
	// never calls time.Now: a clock the host does not own is a clock no test
	// can freeze, and the alternative to a frozen clock is a test that only
	// passes at one time of day.
	now func() time.Time

	// fsys is the vault-relative public filesystem captured at Register. It
	// cannot reach a secret body — the host builds it from public spans only —
	// which is what makes it safe to hand to a search resolver whose rows are
	// rendered to whoever asked.
	fsys fs.FS

	// config is the plugin's own namespaced configuration, captured at Register.
	// It is captured rather than re-read because the Host offers Config once per
	// registration and a route has to read the same values the validator
	// accepted rather than whatever is in the table at request time.
	config plugin.Config

	// routes is the router the host handed the plugin in RegisterRoutes, kept so
	// that a test can walk the patterns really mounted rather than a table of
	// the ones this package says it mounts.
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
// first caller to touch it change what every later caller sees. The cost is one
// allocation per call, which happens at boot.
func (p *Plugin) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{
		ID:        ID,
		Name:      Name,
		Kind:      plugin.KindSystem,
		Version:   Version,
		APILevel:  plugin.APILevel,
		PageTypes: pageTypes(),
		NavItems:  navItems(),
		// searchResolvers is a method because the resolver closes over this
		// plugin: the filesystem it reads is captured at Register, and the
		// resolver is declared before that has happened.
		SearchResolvers: p.searchResolvers(),
		ConfigSchema:    configSchema(),
		Migrations:      migrations(),
		Capabilities:    capabilities,
	}
}

// pageTypes returns the two page types this plugin claims.
func pageTypes() []plugin.PageType {
	return []plugin.PageType{
		{
			ID:   PageTypeCharacter,
			Name: "Character",
			// The sprite has no sword and no shield, and a token that is not in
			// the sprite is a silently empty <use>: the affordance looks broken
			// rather than absent, which is the harder of the two to notice.
			Icon: "i-book",
			FrontmatterSchema: map[string]plugin.SchemaField{
				"name": {
					Key: "name", Name: "Name", Type: "text", Required: true,
					Help: "The character's name as the table knows it.",
				},
				"class": {
					Key: "class", Name: "Class", Type: "text",
					Help: "Class and subclass, if the campaign tracks one.",
				},
				"level": {
					Key: "level", Name: "Level", Type: "number",
					Help: "1 to 20. A value outside that is the author's business, not a validation error.",
				},
				"hp_max": {
					Key: "hp_max", Name: "Hit point maximum", Type: "number",
					Help: "Maximum hit points.",
				},
				"ac": {
					Key: "ac", Name: "Armour class", Type: "number",
					Help: "Armour class as a single number rather than a formula.",
				},
				"speed": {
					Key: "speed", Name: "Speed", Type: "number",
					Help: "Walking speed, in the unit the speed_unit setting names.",
				},
				"tags": {
					Key: "tags", Name: "Tags", Type: "tags",
					Help: "Free-form. A party is usually #party; the app reads a tag like any other.",
				},
			},
			// Editor and Viewer are nil on purpose. Both fields are
			// templ.Component values, which take no arguments, so a component
			// registered here cannot be bound to the page it is for: a
			// character sheet registered as an Editor would render the same
			// empty form for every character in the vault. The schema is what
			// the host needs here — it is what makes these fields first-class
			// in search, in the campaign status panel and in the core editor —
			// and the sheet itself is rendered from characterRoute, where it
			// can be populated from the page it names.
		},
		{
			ID:   PageTypeRule,
			Name: "Rule",
			Icon: "i-book",
			FrontmatterSchema: map[string]plugin.SchemaField{
				"title": {
					Key: "title", Name: "Title", Type: "text", Required: true,
					Help: "Usually the page title, carried explicitly so a rule can be titled differently from its file.",
				},
				"source": {
					Key: "source", Name: "Source", Type: "text",
					Help: "Where the rule comes from: 'Player's Handbook p. 192', or 'house rule'.",
				},
				"tags": {
					Key: "tags", Name: "Tags", Type: "tags",
					Help: "Free-form. #combat, #spell and #exploration are the ones the index groups by.",
				},
			},
		},
	}
}

// navItems returns the sidebar contribution: exactly one link.
func navItems() []plugin.NavItem {
	return []plugin.NavItem{
		{
			ID:    NavID,
			Label: "D&D 5e",
			Href:  IndexHref,
			Icon:  "i-d20",
			Order: 10,
			// Badge is nil on purpose. A badge is a live count, and the only
			// live count available here would be a page count the dashboard
			// already shows. A badge whose number a reader cannot also read in
			// a list is decoration that costs a query on every render.
		},
	}
}

// searchResolvers returns the one derived-row contribution.
//
// The rows are built from frontmatter only. That is a security property and not
// a simplicity one: IndexRow.Summary is rendered into a search result for
// whoever asked, and a summary assembled from a page body would be a second
// path to page text that does not go through the redaction a page render goes
// through. The core's own FTS already indexes the body under the canonical
// predicate, so a body-derived row adds reach rather than coverage.
func (p *Plugin) searchResolvers() []plugin.SearchResolver {
	return []plugin.SearchResolver{
		{
			ID: "dnd5e.frontmatter",
			Query: func(ctx context.Context, q string) ([]plugin.IndexRow, error) {
				return p.pageIndex().query(ctx, q)
			},
		},
	}
}

// migrations returns this plugin's own DDL: exactly one table, and it is
// derived state.
//
// The Markdown file is canonical and every table is disposable — dropping this
// one and rebuilding it from the vault must be indistinguishable from never
// having dropped it. That is why it holds no authored text: only a number
// derived from a number.
func migrations() []plugin.Migration {
	return []plugin.Migration{
		{
			Version: 1,
			Name:    "sheet_state",
			SQL: `-- The plugin_<id>_* prefix is required, not conventional. The host
-- runs plugin DDL inside its own migration transaction, and without the
-- prefix two plugins in one vault could name the same table: the second
-- CREATE would either be a silent no-op against the first plugin's schema or
-- a migration error that disables the wrong plugin. The prefix makes the
-- collision impossible to write rather than merely unlikely.
--
-- Derived and disposable. page_id is a core page id; hp_current and
-- updated_at cache what the file says and are not a second source of truth.
CREATE TABLE IF NOT EXISTS plugin_dnd5e_sheet_state (
    page_id    INTEGER PRIMARY KEY,
    hp_current INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL
);
`,
		},
	}
}

// SettingKind is how a config value is read and type-checked. It is a named
// type rather than a bare string so that a setting whose kind nothing
// implements is a value the compiler can see is incomplete.
type SettingKind string

const (
	// KindInt is an integer setting. It accepts int, int64 and an integral
	// float64, which are the three shapes a decoder produces for a whole
	// number.
	KindInt SettingKind = "int"
	// KindString is a text setting.
	KindString SettingKind = "string"
)

// Setting is one entry of the config schema.
//
// The schema is the plugin's own declaration of what it reads, and Validate
// walks the same table rather than keeping a second list: two lists would be a
// setting defaulted by one and validated by the other, which is the shape of
// every configuration bug that survives a release.
type Setting struct {
	// Kind is how the value is read and type-checked.
	Kind SettingKind
	// Label and Help are what an operator's settings surface would show. The
	// host has no such surface yet, so nothing renders them; they are here
	// because a schema without them is a list of keys.
	Label string
	Help  string
	// Default is the value used when the key is absent. It is a string for both
	// kinds because Config.Get takes a string default and Config.Int takes none
	// at all, so the integer default has to live somewhere — and the schema is
	// the only place that can hold it without a second source of truth.
	Default string
	// Min and Max bound an integer setting, inclusive. Zero is unbounded on
	// that side, which is why Min: 0 is not a constraint.
	Min, Max int
	// Options is the fixed set a string setting may take. A string setting with
	// no Options takes any string.
	Options []string
}

// settings is this plugin's configuration and the single source of truth for
// both the defaults and the validation.
//
// Three settings, each read somewhere: the two integers prefill a newly
// created character sheet and the unit string is the suffix on the speed field.
// A setting nothing reads is a promise to a future contributor that the value
// will be honoured, and a promise nobody keeps.
var settings = map[string]Setting{
	"new_sheet_level": {
		Kind:    KindInt,
		Label:   "Level for a new character sheet",
		Help:    "Prefilled into a sheet with no level in its frontmatter. Must be 1 to 20.",
		Default: "1",
		Min:     1,
		Max:     20,
	},
	"new_sheet_hp": {
		Kind:    KindInt,
		Label:   "Hit point maximum for a new character sheet",
		Help:    "Prefilled into a sheet with no hp_max. A level 1 character with no hit points yet is an author in progress, not an error.",
		Default: "1",
		Min:     0,
		Max:     999,
	},
	"speed_unit": {
		Kind:    KindString,
		Label:   "Unit for the speed field",
		Help:    "Rendered as the suffix on the speed input. It changes the label and nothing else; it does not convert.",
		Default: "ft",
		Options: []string{"ft", "m"},
	},
}

// configSchema is the schema as the Descriptor carries it. The vocabulary types
// it as map[string]any, so the values are the named Setting above rather than an
// untyped description a future host would have to guess at.
func configSchema() map[string]any {
	out := make(map[string]any, len(settings))
	for key, s := range settings {
		out[key] = s
	}
	return out
}

// Register wires this plugin into a host.
//
// Everything the host needs is derived from Descriptor, so the sequence is:
// check the declaration is admissible, then capture what the host granted and
// what it offers. Every step returns an error rather than panicking, because a
// panic during boot takes the app down for a condition that is contained to
// this plugin — the lifecycle disables a plugin whose Register fails, and it can
// only do that if Register fails normally.
//
// No route is mounted here, and that is the host's shape rather than an
// oversight. The host builds a sub-router already prefixed at /plugin/dnd5e and
// already wrapped in its middleware, and it hands that router to the plugin's own
// RegisterRoutes once Register has returned; a router the plugin built and handed
// over instead would be mounted outside the prefix and outside the session
// wrapper, and the host refuses it. The reserved-segment checks below run now,
// before anything is mounted, so a pattern that would be refused is never
// reached.
func (p *Plugin) Register(ctx context.Context, h plugin.Host) error {
	d := p.Descriptor()

	if err := d.ValidateID(); err != nil {
		return fmt.Errorf("dnd5e: descriptor id: %w", err)
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("dnd5e: descriptor kind %q is neither system nor feature", d.Kind)
	}
	// ParseCapabilities is what catches a typo'd capability name. Without it a
	// misspelling is a capability the plugin believes it holds and nobody does,
	// and the consequence is not an error — it is a silently absent panel.
	declared, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		return fmt.Errorf("dnd5e: declared capabilities: %w", err)
	}

	// The host may grant less than the plugin declared, and that is not a
	// failure: the boot report says which names were refused. Every check below
	// is against what was actually granted, through the same functions the host
	// itself runs, so a disagreement about a reserved name is impossible rather
	// than merely unlikely. The grant is not kept: a plugin has nothing to do
	// with a capability the host withheld — the host discards the contribution
	// and says why — so storing it would be state no code reads.
	granted := declared & h.Capability()
	for _, pt := range d.PageTypes {
		if err := plugin.CheckReservedPageType(pt.ID, h.Kind(), granted); err != nil {
			return fmt.Errorf("dnd5e: page type %q: %w", pt.ID, err)
		}
	}
	for _, pattern := range routePatterns() {
		if err := plugin.CheckReservedRoute(pattern, h.Kind(), granted); err != nil {
			return fmt.Errorf("dnd5e: route %q: %w", pattern, err)
		}
	}

	p.fsys = h.FS()
	p.config = h.Config()
	p.now = h.Now

	h.Log(ctx, plugin.LevelInfo, "dnd5e registered",
		plugin.KV{Key: "page_types", Value: len(d.PageTypes)},
		plugin.KV{Key: "capabilities", Value: d.Capabilities},
		plugin.KV{Key: "granted", Value: granted},
	)
	return nil
}

// routePatterns returns every pattern this plugin mounts, relative to its own
// prefix.
//
// It is a function rather than a hand-kept list so that a pattern and the
// capability that reserves it are read from one place: the character route
// exists because the character page type exists.
func routePatterns() []string {
	return []string{indexRoute, characterRoute}
}

// pageIndex returns an index over the public filesystem, or an empty one.
//
// Descriptor is read before Register, so a resolver declared there can be asked
// a question before this plugin has been given a filesystem. The answer then is
// no rows and no error: there is no vault to read yet, and a resolver that
// invented rows would be worse than one that is quiet.
func (p *Plugin) pageIndex() pageIndex {
	return pageIndex{fsys: p.fsys}
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

// Validate checks the settings this plugin declares.
//
// Boot continues when it fails and the boot report says so, so this returns an
// error rather than repairing anything. A plugin that silently coerced a bad
// value would render a campaign with a level cap nobody chose and no way to
// find out which value was dropped.
//
// An unrecognised key is not an error. It is a key a newer version of this
// plugin wrote, and refusing to boot because the stored config is from the
// future is precisely the behaviour the API-level window in §2.5 exists to
// prevent.
func (p *Plugin) Validate(cfg plugin.Config) error {
	for key, setting := range settings {
		raw, present := cfg.Values[key]
		if !present {
			continue
		}
		if err := setting.check(key, raw); err != nil {
			return err
		}
	}
	return nil
}

// check validates one configured value against its setting.
func (s Setting) check(key string, raw any) error {
	switch s.Kind {
	case KindInt:
		n, ok := asInt(raw)
		if !ok {
			return fmt.Errorf("dnd5e: config %q is %T, which is not a number this plugin can use", key, raw)
		}
		if n < s.Min || n > s.Max {
			return fmt.Errorf("dnd5e: config %q is %d, outside the range %d to %d", key, n, s.Min, s.Max)
		}
		return nil
	case KindString:
		str, ok := raw.(string)
		if !ok {
			return fmt.Errorf("dnd5e: config %q is %T, which is not text this plugin can use", key, raw)
		}
		if len(s.Options) == 0 {
			return nil
		}
		for _, want := range s.Options {
			if str == want {
				return nil
			}
		}
		return fmt.Errorf("dnd5e: config %q is %q, which is not one of %s", key, str, strings.Join(s.Options, ", "))
	default:
		// A kind nothing implements would otherwise be a setting that passes
		// every check because no check ran.
		return fmt.Errorf("dnd5e: config %q has unknown kind %q", key, s.Kind)
	}
}

// asInt reports the integer value of a configured value.
//
// The three accepted shapes are the three a decoder produces for a whole
// number. A fractional float64 is refused rather than truncated: a level of 3.7
// is a mistake, and rounding it to 3 would hide it.
func asInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	default:
		return 0, false
	}
}

// configInt returns an integer setting, falling back to the schema's default.
func configInt(cfg plugin.Config, key string) int {
	if raw, ok := cfg.Values[key]; ok {
		if n, ok := asInt(raw); ok {
			return n
		}
	}
	n, err := strconv.Atoi(settings[key].Default)
	if err != nil {
		return 0
	}
	return n
}

// configString returns a string setting, falling back to the schema's default.
func configString(cfg plugin.Config, key string) string {
	if raw, ok := cfg.Values[key]; ok {
		if s, ok := raw.(string); ok {
			return s
		}
	}
	return settings[key].Default
}

// pageIndex reads frontmatter out of the public filesystem.
//
// It is the only place this plugin reads vault bytes, and it reads exactly one
// thing: the frontmatter block. md.SplitFrontmatter hands the body back as
// well, and the body is dropped on the floor immediately and bound to nothing,
// so there is no path from page text to anything this plugin returns.
type pageIndex struct {
	fsys fs.FS
}

// dnd5ePage is one page this plugin recognises.
type dnd5ePage struct {
	// path is the vault-relative path, which is the href (/p/ + path) and the
	// audit reference.
	path string
	// title is the frontmatter name or title, falling back to the file's base
	// name. A page with neither is still a page; a page with an empty title in
	// a search result is not.
	title string
	// pageType is the frontmatter type, and is the only reason this page is
	// here at all.
	pageType string
	// fields is the parsed frontmatter. It is unexported, never serialised
	// anywhere, and read only through the named keys below.
	fields map[string]any
}

// walk visits every dnd5e page in the vault.
//
// A file that cannot be read is skipped and the walk continues: one unreadable
// note must not empty the index. A directory that cannot be read is fatal,
// because continuing would mean the result was quietly partial.
func (ix pageIndex) walk() ([]dnd5ePage, error) {
	if ix.fsys == nil {
		return nil, nil
	}
	var out []dnd5ePage
	err := fs.WalkDir(ix.fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return err
			}
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".md") {
			return nil
		}
		// .semiplane is the app's own directory inside the vault: a lock file
		// and a database. Nothing in it is a page and nothing in it is
		// readable content.
		if strings.HasPrefix(name, ".semiplane/") {
			return nil
		}
		page := ix.read(name)
		if page == nil {
			return nil
		}
		out = append(out, *page)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// read parses one file's frontmatter, or returns nil when the file is not a
// page this plugin claims.
//
// Too large, unreadable, unparseable and wrong type are all nil with no error,
// because all four are ordinary: a vault contains notes this plugin has no
// opinion about, and a search over a plugin's own pages must not fail because
// one unrelated note is malformed.
func (ix pageIndex) read(name string) *dnd5ePage {
	if ix.fsys == nil {
		return nil
	}
	info, err := fs.Stat(ix.fsys, name)
	if err != nil || info.Size() > maxSheetBytes {
		return nil
	}
	src, err := fs.ReadFile(ix.fsys, name)
	if err != nil {
		return nil
	}
	// The body is discarded here and bound to nothing. That assignment is the
	// security property: from this line on, read cannot reach page text, so a
	// later edit that adds a summary field cannot begin indexing the body.
	_, _, fm, _, err := md.SplitFrontmatter(src)
	if err != nil || len(fm) == 0 {
		return nil
	}
	fields, err := md.ParseFields(fm)
	if err != nil {
		return nil
	}
	pageType := fieldText(fields, "type")
	if pageType != PageTypeCharacter && pageType != PageTypeRule {
		return nil
	}
	title := fieldText(fields, "name")
	if title == "" {
		title = fieldText(fields, "title")
	}
	if title == "" {
		title = md.Basename(name)
	}
	return &dnd5ePage{path: name, title: title, pageType: pageType, fields: fields}
}

// fieldText reads one frontmatter value as a single line of text.
//
// md.FieldString returns the empty string for anything that is not a Go string,
// which would silently swallow `level: 3` — an int in YAML and therefore a
// field this schema declares as a number and the reader never sees. So a
// non-string scalar is formatted, and a list is joined, which is what makes
// `tags: [a, b]` and `tags: a` the same value here.
func fieldText(fields map[string]any, key string) string {
	return strings.Join(md.FieldStrings(fields, key), ", ")
}

// searchableFields is which frontmatter keys a page of each type is searched
// by.
//
// A type's list is closed on purpose. An open list would be every key in the
// schema, and a schema is about rendering: a field is there because the editor
// draws a box for it, not because it should be findable.
var searchableFields = map[string][]string{
	PageTypeCharacter: {"name", "class", "tags"},
	PageTypeRule:      {"title", "source", "tags"},
}

// query turns a search term into derived rows.
//
// Scoring is two levels rather than a relevance model: a title match outranks a
// field match, and within a level the vault's own order stands. There is no
// tokenizer either — this is a substring test over names the plugin declared,
// not a query language, and the core FTS is what answers "crit" across page
// text.
func (ix pageIndex) query(ctx context.Context, term string) ([]plugin.IndexRow, error) {
	needle := strings.ToLower(strings.TrimSpace(term))
	if needle == "" {
		return nil, nil
	}
	pages, err := ix.walk()
	if err != nil {
		return nil, err
	}

	type scored struct {
		row   plugin.IndexRow
		score float64
	}
	matches := make([]scored, 0, len(pages))
	for _, page := range pages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		score := page.score(needle)
		if score == 0 {
			continue
		}
		matches = append(matches, scored{row: page.row(score), score: score})
	}
	// Insertion sort rather than sort.Slice. The list is bounded by
	// maxSearchRows, so a comparison sort would be O(n log n) on a slice whose
	// construction is already O(files in the vault) — and the walk is the cost
	// either way, so making the sort clever buys nothing but a comparator.
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

// score is one page's match strength for one term: 0 is no match.
//
// The two levels are the two things a reader would search by — what the page is
// called, and what its sheet says — and they are checked in that order so a
// title match always outranks a field match.
func (p dnd5ePage) score(needle string) float64 {
	if strings.Contains(strings.ToLower(p.title), needle) {
		return 1
	}
	for _, key := range searchableFields[p.pageType] {
		if strings.Contains(strings.ToLower(fieldText(p.fields, key)), needle) {
			return 0.5
		}
	}
	return 0
}

// row renders a page as a search row.
//
// PageID is zero, and that is a decision rather than an omission: the public
// filesystem is keyed by path and this plugin has no page-id surface, so it
// does not invent one. A row carrying a wrong id would be worse than a row
// carrying none, because the core keys status and push handling on it.
func (p dnd5ePage) row(score float64) plugin.IndexRow {
	return plugin.IndexRow{
		// Kind is the filter token, and a stable one: a reader who filters
		// search results to "Rule" is asking a question the index has to answer
		// the same way tomorrow.
		Kind:  p.pageType,
		Title: p.title,
		Href:  pluginPageHref + p.path,
		// Summary is assembled from the same named keys score reads, so a hit
		// and its snippet cannot describe different pages.
		Summary: p.summary(),
		// Ref is the vault-relative path: the object the row points at, and
		// enough to find the file again without a title lookup.
		Ref: p.path,
		// Score carries the two-level match strength through unchanged, so a
		// host that merges plugin rows into its own ordering has the plugin's
		// ranking rather than a guess at it.
		Score: score,
	}
}

// summary is the one line a search result shows under a title.
func (p dnd5ePage) summary() string {
	if p.pageType == PageTypeCharacter {
		parts := make([]string, 0, 3)
		if class := fieldText(p.fields, "class"); class != "" {
			parts = append(parts, class)
		}
		if level := fieldText(p.fields, "level"); level != "" {
			parts = append(parts, "level "+level)
		}
		if ac := fieldText(p.fields, "ac"); ac != "" {
			parts = append(parts, "AC "+ac)
		}
		if len(parts) == 0 {
			return "Character sheet with no class or level recorded."
		}
		return strings.Join(parts, " · ")
	}
	parts := []string{"Rule"}
	if source := fieldText(p.fields, "source"); source != "" {
		parts = append(parts, source)
	}
	if tags := md.FieldStrings(p.fields, "tags"); len(tags) > 0 {
		parts = append(parts, strings.Join(tags, " "))
	}
	return strings.Join(parts, " · ")
}
