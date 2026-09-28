package dnd5e

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// CoreTypes returns the page types this plugin claims.
//
// It is the same value the Descriptor carries and not a second declaration. A
// system plugin and a feature plugin differ in whether this is empty, and that
// is a boot error rather than a silently degraded view, so the two must not be
// able to disagree.
func (p *Plugin) CoreTypes() []plugin.PageType { return pageTypes() }

// MarkdownExtenders returns the goldmark extenders this plugin contributes.
//
// It contributes none, and that is an answer rather than a gap. The block
// syntax a system wants is mostly campaign convention — a callout, a statblock —
// and the constructs this plugin's pages use are core's already. Returning an
// empty list keeps the composite goldmark from growing an extender that draws
// nothing on every page in the vault.
func (p *Plugin) MarkdownExtenders() []any { return nil }

// ConfigSchema returns the configuration this plugin declares and validates.
func (p *Plugin) ConfigSchema() map[string]any { return configSchema() }

// Panels returns the one sidebar panel this plugin contributes.
//
// Restricting it to a page type is the only shape a plugin has that cannot be
// mistaken for something page-independent: a global panel renders on every page
// in the vault, including the ones a system plugin knows nothing about.
func (p *Plugin) Panels() []plugin.Panel {
	return []plugin.Panel{
		{
			Slot:  plugin.SlotRightMid,
			Order: 20,
			// The panel is a static component, and that is a limit of the
			// vocabulary rather than a choice. Panel.Component is a
			// templ.Component and takes no page; a templ.Component's only input
			// is the request context, which carries no page and no principal a
			// plugin may read — authz has no context-lookup helper, and httpapi
			// is outside the plugin boundary. So this card names what the page
			// type is and links to the plugin's own route, rather than
			// pretending to describe the character beside it.
			Component: characterPanel(),
			PageType:  PageTypeCharacter,
		},
	}
}

// NavItems returns the one sidebar link this plugin contributes.
func (p *Plugin) NavItems() []plugin.NavItem { return navItems() }

// Summaries returns the one page-summary provider this plugin contributes.
//
// It declines every page, and the reason is a gap in the vocabulary rather than
// a decision about summaries. SummaryProvider.Summary is keyed by pageID, while
// the only page surface a plugin can reach is Host.FS(), which is keyed by
// path; nothing in the Host interface turns one into the other. Guessing —
// treating the id as a row number, say — would answer a hover card with some
// other page's frontmatter, which is worse than no card at all.
//
// ok=false is the documented degradation: the core link-preview interaction
// falls back to a plain link and the reader loses nothing. It is also why this
// package mounts no /summary route: a route nothing calls is a control with
// nothing behind it, and the provider is what the host actually invokes.
func (p *Plugin) Summaries() []plugin.SummaryProvider {
	return []plugin.SummaryProvider{decliningSummary{}}
}

// decliningSummary is a SummaryProvider that answers no page.
//
// A named type rather than a closure, so the provider registry can identify it
// and a test can assert on what it returns without matching a string.
type decliningSummary struct{}

// ID names the provider, so two plugins contributing one cannot collide in the
// host's provider registry.
func (decliningSummary) ID() string { return "dnd5e.frontmatter" }

// Summary declines. See Summaries for why, and do not "fix" it by reading a
// path out of the id.
func (decliningSummary) Summary(ctx context.Context, pageID int64) (templ.Component, bool, error) {
	return nil, false, nil
}

// RegisterRoutes mounts this plugin's routes on the router the host supplies.
//
// The router arrives already prefixed at /plugin/dnd5e and already wrapped in
// the host's session and role middleware, so there is nothing here to mount at
// and nothing here to unwrap: a pattern is a pattern, and a method is a method.
// It is the host that calls this, once, after Register has returned — so the
// filesystem and the configuration this plugin captured are already in place by
// the time the handlers can run.
func (p *Plugin) RegisterRoutes(sub plugin.RouteMounter) {
	p.routes = sub
	sub.Get(indexRoute, p.index)
	sub.Get(characterRoute, p.characterSheet)
}

// index renders the plugin's own page: what it contributes, and the character
// sheets it found.
//
// It is the nav item's destination, so it has to be a working page rather than
// a redirect, and rather than a page whose only content is the fact that the
// plugin is installed.
func (p *Plugin) index(w http.ResponseWriter, r *http.Request) {
	view, err := p.indexView(r.Context())
	if err != nil {
		view.Problem = vaultUnreadable
		writeComponent(w, r, http.StatusInternalServerError, dnd5eIndex(view))
		return
	}
	writeComponent(w, r, http.StatusOK, dnd5eIndex(view))
}

// characterSheet renders one character page's fields.
//
// The path comes from the URL and is used to open a file, so it is checked with
// fs.ValidPath before anything touches the filesystem. A plugin that joined a
// request parameter into a path without that check would be a traversal hole
// with a route in front of it.
func (p *Plugin) characterSheet(w http.ResponseWriter, r *http.Request) {
	path := chi.URLParam(r, "*")
	if !fs.ValidPath(path) || !strings.HasSuffix(path, ".md") {
		writeComponent(w, r, http.StatusNotFound, characterEditor(Sheet{}))
		return
	}
	page := p.pageIndex().read(path)
	if page == nil || page.pageType != PageTypeCharacter {
		// One answer for "no such page" and for "not a character sheet",
		// because two answers would let a reader enumerate which paths in the
		// vault hold character pages.
		writeComponent(w, r, http.StatusNotFound, characterEditor(Sheet{}))
		return
	}
	writeComponent(w, r, http.StatusOK, characterEditor(page.sheet(p.config, path)))
}

// vaultUnreadable is what the index says when the filesystem cannot be walked.
// It names the failure rather than showing an empty list, because an empty
// character list and a vault that could not be read look identical otherwise.
const vaultUnreadable = "The vault could not be read, so the list below is not the whole vault."

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
		// A render error that quoted the page would be a way to get vault text
		// into a response body, which is the one thing §2.2 rules out.
		http.Error(w, "dnd5e: the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// indexView is what the plugin index renders. It is a value and not a
// component, so a template never reaches back into this package.
type indexView struct {
	// PageTypes is what the plugin claims, with the fields it renders for each.
	PageTypes []pageTypeView
	// Characters is every character page the public filesystem holds.
	Characters []Sheet
	// SpeedUnit is the configured unit, shown so the index's numbers and the
	// sheet's numbers are read the same way.
	SpeedUnit string
	// Problem is set when the walk failed, and is the only case in which the
	// list below is not the whole truth.
	Problem string
}

// pageTypeView is one claimed page type and the fields it renders.
type pageTypeView struct {
	ID     string
	Name   string
	Icon   string
	Fields []fieldView
}

// fieldView is one frontmatter field as the index describes it.
type fieldView struct {
	Key      string
	Label    string
	Kind     string
	Help     string
	Required bool
}

// indexView builds the index's data from the public filesystem.
//
// The error is returned as well as recorded in the view. The index's whole claim
// is that it is complete, and a complete-looking list built from a walk that
// failed is the one output that would make the claim false.
func (p *Plugin) indexView(ctx context.Context) (indexView, error) {
	view := indexView{
		PageTypes: pageTypeViews(pageTypes()),
		SpeedUnit: configString(p.config, "speed_unit"),
	}
	pages, err := p.pageIndex().walk()
	if err != nil {
		view.Problem = vaultUnreadable
		return view, err
	}
	for _, page := range pages {
		if err := ctx.Err(); err != nil {
			return view, err
		}
		if page.pageType == PageTypeCharacter {
			view.Characters = append(view.Characters, page.sheet(p.config, page.path))
		}
	}
	return view, nil
}

// pageTypeViews flattens the declared schemas into renderable descriptions.
//
// It reads the schema the descriptor declares rather than a list beside it, so
// the index cannot describe a field the sheet does not render.
func pageTypeViews(types []plugin.PageType) []pageTypeView {
	out := make([]pageTypeView, 0, len(types))
	for _, pt := range types {
		view := pageTypeView{ID: pt.ID, Name: pt.Name, Icon: pt.Icon}
		for key, field := range pt.FrontmatterSchema {
			view.Fields = append(view.Fields, fieldView{
				Key:      key,
				Label:    field.Name,
				Kind:     field.Type,
				Help:     field.Help,
				Required: field.Required,
			})
		}
		// A map has no order and a list that reorders itself on every render is
		// unreadable, so the fields are sorted. Alphabetically, because
		// importance is not a property the vocabulary carries: a plugin that
		// wanted its own order would need an Order on SchemaField, and adding
		// one to the vocabulary for a reference plugin is not a trade worth
		// making.
		sort.Slice(view.Fields, func(i, j int) bool { return view.Fields[i].Key < view.Fields[j].Key })
		out = append(out, view)
	}
	return out
}

// characterFieldViews returns the character schema's fields, in render order.
//
// It reads the schema the descriptor declares, so the panel, the index card and
// the sheet are all describing one list. A field added to the schema and not to
// this package would render a label with an empty input beside it, and a field
// listed in a template instead would be a field the schema does not know about.
func characterFieldViews() []fieldView {
	for _, pt := range pageTypeViews(pageTypes()) {
		if pt.ID == PageTypeCharacter {
			return pt.Fields
		}
	}
	return nil
}

// inputType is the HTML input type for a declared schema field type.
//
// The fallthrough is deliberate. An unrecognised type renders as text rather
// than as nothing, because a field that is missing from a form is a field the
// reader cannot see exists, and one rendered with the wrong control is a field
// they can still read. The schema test keeps the declared set inside the types
// this function and the template both handle.
func inputType(kind string) string {
	switch kind {
	case "number":
		return "number"
	case "textarea":
		return "text"
	default:
		return "text"
	}
}

// Sheet is one character, as the sheet surface renders it.
//
// It is a flat value with no vault type in it — no Page, no Secret, no render
// model — and that is the point. A plugin component that took a core page would
// be a component whose fields are somebody else's decisions, and the first one
// anybody added would be a secret body.
type Sheet struct {
	// Path is the vault-relative path the sheet was read from. It is rendered as
	// the link back to the page. It is not a title: a title is a thing a reader
	// typed, and a path is a thing the filesystem knows.
	Path string
	// Name, Class, Level, HPMax, AC, Speed and Tags mirror the character
	// schema's keys one for one.
	Name  string
	Class string
	Level int
	HPMax int
	AC    int
	Speed int
	Tags  []string
	// SpeedUnit is the unit the speed value is in, from the plugin's config. It
	// is a label and nothing converts it, so a campaign that switches from feet
	// to metres edits its sheets.
	SpeedUnit string
}

// Href is the core page URL for this sheet's page.
//
// It is one Go function rather than a string in two templates because the shape
// of a core page URL is a thing that should be written down once. The plugin
// knows this prefix the way it knows the sprite's icon tokens: by agreement,
// and a disagreement is a broken link rather than a broken page.
func (s Sheet) Href() string {
	if s.Path == "" {
		return ""
	}
	return pluginPageHref + s.Path
}

// Missing reports that no sheet was loaded.//
// It is a method on the zero value rather than a separate error path, because
// the two cases render the same component: a 404 for a path that is not a
// character sheet and the 404 for a path that does not exist are the same
// answer, and a template that had to be told which is which would be one
// template-width branch wider than the difference deserves.
func (s Sheet) Missing() bool { return s.Path == "" }

// classAndLevel is the one-line description the index shows beside a sheet.
//
// It is a method rather than markup in the template because a reader seeing
// "level 3" beside a name and a reader seeing "3" are being told different
// things, and the second one is only a different thing by accident of layout.
func (s Sheet) classAndLevel() string {
	parts := make([]string, 0, 2)
	if s.Class != "" {
		parts = append(parts, s.Class)
	}
	if s.Level > 0 {
		parts = append(parts, "level "+itoa(s.Level))
	}
	if len(parts) == 0 {
		return "no class or level recorded"
	}
	return strings.Join(parts, " · ")
}

// value is a sheet field as the string an input's value attribute carries.
//
// It exists so that character.templ is one loop over the declared schema rather
// than seven hand-written inputs that would drift the first time the schema
// gained a field. A key with no case here renders empty, which is why the schema
// test asserts that every declared field is one this switch and the template
// between them render.
func (s Sheet) value(key string) string {
	switch key {
	case "name":
		return s.Name
	case "class":
		return s.Class
	case "level":
		return itoa(s.Level)
	case "hp_max":
		return itoa(s.HPMax)
	case "ac":
		return itoa(s.AC)
	case "speed":
		return itoa(s.Speed)
	case "tags":
		return strings.Join(s.Tags, ", ")
	default:
		return ""
	}
}

// sheet builds a Sheet from a page's frontmatter.
//
// A number that is not a number becomes zero rather than an error: a sheet whose
// frontmatter says `hp_max: lots` should render as a sheet with no hit points
// recorded, and a 500 for a typo in a field is more authority than a plugin
// should have over somebody's campaign.
//
// A number that is absent takes the configured default, which is what makes the
// two integer settings mean something. A value that is present is the author's,
// and a campaign that writes 3 in the file gets 3 whatever the setting says.
func (p dnd5ePage) sheet(cfg plugin.Config, path string) Sheet {
	return Sheet{
		Path:      path,
		Name:      p.title,
		Class:     fieldText(p.fields, "class"),
		Level:     atoiOr(fieldText(p.fields, "level"), configInt(cfg, "new_sheet_level")),
		HPMax:     atoiOr(fieldText(p.fields, "hp_max"), configInt(cfg, "new_sheet_hp")),
		AC:        atoiOrZero(fieldText(p.fields, "ac")),
		Speed:     atoiOrZero(fieldText(p.fields, "speed")),
		Tags:      md.FieldStrings(p.fields, "tags"),
		SpeedUnit: configString(cfg, "speed_unit"),
	}
}

// atoiOr parses a frontmatter number, or returns the fallback when the value is
// absent or is not a number.
func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}

// atoiOrZero parses a frontmatter number, or returns zero.
func atoiOrZero(s string) int { return atoiOr(s, 0) }

// itoa is strconv.Itoa, for the places a template wants a number. A function
// rather than an inline conversion in the template, because templ has no
// conversion expression and because one definition is one thing to test.
func itoa(n int) string { return strconv.Itoa(n) }

// pluginPageHref is the core route a page is served at, relative to the host
// root. It is a constant so that a plugin link and the core's own page card
// cannot disagree, and so that TestNoPluginSwitchInCore — which is the gate on
// this plugin reaching into core — has a single literal to look at.
const pluginPageHref = "/p/"

// spriteHref is the icon sprite's asset path, with the fragment separator.
//
// It is a second copy of a string internal/web owns, and it has to be: httpapi
// imports internal/app, internal/app imports the plugin registry, and the
// registry imports this package, so a plugin cannot import internal/web without
// closing a cycle. A plugin package that is allowed to import the view layer but
// cannot is a finding for core, not a thing a plugin works around quietly — so
// it is written down here instead.
const spriteHref = "/_/assets/icons.svg#"

// compile-time proof that the router this plugin hands the host is the type the
// host's RouteMounter names. Without it, a change to either alias would surface
// as a registration failure at boot rather than as a compile error here.
var _ plugin.RouteMounter = (*chi.Mux)(nil)

// countLabel is a number with the noun it counts, so the index's counts read as
// counts. A bare number in a sentence is the kind of thing a reader learns to
// stop reading.
func countLabel(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
