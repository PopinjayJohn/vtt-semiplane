package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/a-h/templ"
)

// Renderer is the httpapi.Renderer this package provides.
//
// It is the whole of the boundary between the two packages: the router decides
// what a request is allowed to see and hands the result over as a view model,
// and this type decides what the response looks like. Neither imports the
// other's internals, and neither can grow a permission check, because this one
// has no database, no session and no policy to check anything against.
type Renderer struct{}

// NewRenderer returns the renderer.
func NewRenderer() *Renderer { return &Renderer{} }

// Document writes a whole HTML page.
func (r *Renderer) Document(w http.ResponseWriter, req *http.Request, v httpapi.View) error {
	shell, err := shellOf(v)
	if err != nil {
		return err
	}
	body, err := regionOf(v)
	if err != nil {
		return err
	}
	doc := Doc{
		Title:   shell.Title,
		Shell:   shell,
		Body:    body,
		Context: contextOf(v),
	}
	return Layout(doc).Render(req.Context(), w)
}

// Fragment writes only the content region.
//
// The bytes are what Layout puts inside #page-region and nothing else, which is
// what makes "the fragment is a strict subset of the document" checkable: the
// same component, the same view model, the same escaping, minus the shell. It
// is also what lets a later phase's live-push path re-render under a
// subscriber's own principal and swap the result into the reader's page without
// the client having to know anything about authorization.
func (r *Renderer) Fragment(w http.ResponseWriter, req *http.Request, v httpapi.View) error {
	body, err := regionOf(v)
	if err != nil {
		return err
	}
	return Region(v, body).Render(req.Context(), w)
}

// Region is the swappable element itself.
//
// It is a separate component from the one Document nests inside the layout, so
// that the fragment has the same id and the same tabindex the document's copy
// has: a morph that replaced the region with a differently-identified element
// would work once and then fail, because the next response would look for an id
// that is no longer in the document.
func Region(v httpapi.View, body templ.Component) templ.Component {
	return RegionView(RegionDoc{Shell: mustShell(v), Body: body})
}

// The named sub-regions a patch may ask for. The set is closed because the
// name arrives from a request and an open set would be a runtime error in the
// middle of a palette.
const (
	// RegionCommandGroups is the palette's rows: the three grouped lists and
	// nothing else. It is a region rather than the whole Commands component
	// because the whole component contains the form, and a patch that replaced
	// the form would replace the input that asked the question.
	RegionCommandGroups = "command-groups"
)

// Region renders one named sub-region of a view.
//
// It is the third of the renderer's three shapes for one reason: a patch
// replaces a chosen element, the chosen element is usually a part of a view, and
// the part is a component rather than a type. Making it a case here means the
// markup for a palette row is written once, in commands.templ, and a handler
// that wanted different bytes would have to build HTML itself — which is the
// thing this package exists to make impossible.
//
// It returns bytes rather than writing to a ResponseWriter because a patch has to
// inspect the element before it goes on the wire: the element-patch frame cannot
// carry a newline, and that is a property of the rendered bytes.
func (r *Renderer) Region(v httpapi.View, name string) ([]byte, error) {
	body, err := namedRegionOf(v, name)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := body.Render(context.Background(), &buf); err != nil {
		return nil, fmt.Errorf("web: render the %q region: %w", name, err)
	}
	return buf.Bytes(), nil
}

// namedRegionOf is the one place a region name becomes a component.
func namedRegionOf(v httpapi.View, name string) (templ.Component, error) {
	commands, ok := v.(httpapi.CommandsView)
	if !ok {
		return nil, fmt.Errorf("web: %T has no region %q", v, name)
	}
	switch name {
	case RegionCommandGroups:
		return CommandGroups(commands.Commands, commands.Shell.CurrentPageURL), nil
	default:
		return nil, fmt.Errorf("web: no region named %q", name)
	}
}

// shellOf is the layout's half of a view model.
func shellOf(v httpapi.View) (httpapi.Shell, error) {
	if v == nil {
		return httpapi.Shell{}, errors.New("web: no view model was given to render")
	}
	return v.ViewShell(), nil
}

// mustShell is shellOf for the fragment path, where a view model that is not
// one of ours is a programming error rather than a request to report.
//
// The rendered result is still an escaped, empty region rather than a panic: a
// view model this package does not recognise is a mistake, and a mistake should
// not be able to take the process down from a request path.
func mustShell(v httpapi.View) httpapi.Shell {
	shell, err := shellOf(v)
	if err != nil {
		return httpapi.Shell{}
	}
	return shell
}

// regionOf is the type switch, once, so that Document and Fragment cannot
// disagree about what a view model looks like.
func regionOf(v httpapi.View) (templ.Component, error) {
	switch t := v.(type) {
	case httpapi.HomeView:
		return Home(t), nil
	case httpapi.PageView:
		return Page(t), nil
	case httpapi.SearchView:
		return Search(t), nil
	case httpapi.FilesView:
		return Files(t), nil
	case httpapi.TagsView:
		return Tags(t), nil
	case httpapi.TagView:
		return Tag(t), nil
	case httpapi.ContextView:
		return Context(t), nil
	case httpapi.CommandsView:
		return Commands(t), nil
	case httpapi.AdminPluginsView:
		return AdminPlugins(t), nil
	case httpapi.LoginView:
		return Login(t), nil
	case httpapi.SetupView:
		return Setup(t), nil
	case httpapi.InviteView:
		return Invite(t), nil
	case httpapi.ErrorView:
		return ErrorPage(t), nil
	case nil:
		return nil, errors.New("web: no view model was given to render")
	default:
		return nil, fmt.Errorf("web: this view model has no template: %T", v)
	}
}

// ContextData is everything the right column renders.
//
// It is one type for two placements — the aside a document carries and the
// region the context route answers with — because two of them are the same
// panel and a panel that renders differently depending on which request
// produced it cannot be reasoned about.
type ContextData struct {
	// Card is the page the column is about, or nil for a view that is not about
	// one. The page-derived panels are omitted without it: a table of contents
	// and a backlink count for a page that does not exist would be the
	// existence leak with extra steps.
	Card *httpapi.PageCard
	// Toc is the page's table of contents, already filtered by the canonical
	// predicate by whoever filled this in.
	Toc []httpapi.TocEntry
	// Backlinks are the references the viewer may see, and BacklinkCount is what
	// the identical query would have returned in total. The two come from one
	// query, so the badge and the list cannot disagree.
	Backlinks     []httpapi.BacklinkChip
	BacklinkCount int
	// Related are the pages sharing the most tags. The panel is omitted when the
	// list is empty rather than shown with nothing in it.
	Related []httpapi.PageCard
	// Panels are the plugin panels registered for this page's type. The handler
	// has already put them in slot order, and this column renders them in slot
	// order again: the layout owns where a slot goes, so a handler that sorted
	// them wrongly puts a panel in the wrong column rather than next to the
	// panel it belongs with, and a context region fetched on its own renders the
	// same order as the document it replaces.
	//
	// A body here is escaped text, not markup. See httpapi.PluginPanel for why
	// that is the shape and what it costs.
	Panels []httpapi.PluginPanel
	// Campaign is the campaign-wide panel, or nil when this view model carries
	// none at all.
	//
	// The pointer is the whole distinction the panel needs, and it is a
	// distinction between two absences. A carried panel with every field empty is
	// a reader who may see none of it, and it renders a smaller panel. No panel
	// at all is a surface that has no campaign state to show — a search form, a
	// command list — and rendering an empty campaign panel there would claim the
	// campaign has no session, no threads and no system, which is a claim about
	// the vault that nothing in the view model supports.
	Campaign *httpapi.CampaignStatus
}

// Empty reports whether this column would render nothing at all.
//
// The layout asks, so that the toggle which opens the column is rendered only
// where there is something behind it. A plugin panel counts: a column holding
// one is not empty, and a toggle that opens an empty panel is a control with
// nothing behind it, which is the same fault whether the missing thing was
// invented by a template or omitted by a plugin.
func (d ContextData) Empty() bool {
	return d.Card == nil && d.Campaign == nil && len(d.Panels) == 0
}

// contextOf is the right column's half of a view model, for the column the shell
// owns.
//
// A ContextView contributes nothing: its own body *is* the column, so filling the
// aside from it as well would render the table of contents, the backlinks and
// the campaign panel twice on one page, with two elements per heading id. A view
// with no context contributes an empty one rather than nothing, because the
// column is chrome: it is on every page, and a column that appears on some pages
// is a layout that reflows under the reader.
func contextOf(v httpapi.View) ContextData {
	switch t := v.(type) {
	case httpapi.PageView:
		return pageContext(t.Card, t.Toc, t.Backlinks, t.BacklinkCount, t.Related, t.Status, t.Panels)
	case httpapi.HomeView:
		// The dashboard is not about a page, so it has no contents and no
		// backlinks, but the campaign is campaign-wide and belongs here anyway.
		return ContextData{Campaign: &t.Status}
	default:
		return ContextData{}
	}
}

// contextDataOf is the context region's own data.
//
// It is a separate accessor from contextOf because the two answer different
// questions about the same view model: "what does the shell's column show" and
// "what does this view model carry". Merging them is what renders a column
// twice.
func contextDataOf(v httpapi.ContextView) ContextData {
	return pageContext(v.Card, v.Toc, v.Backlinks, v.BacklinkCount, v.Related, v.Status, v.Panels)
}

// pageContext is the one construction of a page's column, so that the aside and
// the region cannot be filled from two different field lists.
func pageContext(card httpapi.PageCard, toc []httpapi.TocEntry, backlinks []httpapi.BacklinkChip, count int, related []httpapi.PageCard, campaign httpapi.CampaignStatus, panels []httpapi.PluginPanel) ContextData {
	return ContextData{
		Card:          &card,
		Toc:           toc,
		Backlinks:     backlinks,
		BacklinkCount: count,
		Related:       related,
		Campaign:      &campaign,
		Panels:        panels,
	}
}

// shellSignals is the client's initial signal state, and the whole of it.
//
// Two keys, both of them facts about the request rather than about the vault: the
// URL the shell refetches when the stream fires, and whether a stream is open at
// all. A signal is read by every script on the page and is written into the
// response twice over, so the set of keys is a security boundary and the tripwire
// in internal/httpapi audits the payload the same way it audits the HTML. A third
// key would have to earn its place against that.
type shellSignals struct {
	// CurrentPageURL is the page this response is about, empty for a view that
	// is not about a page.
	CurrentPageURL string `json:"currentPageUrl"`
	// Push reports whether a live-update stream is open for this session.
	Push bool `json:"push"`
}

// shellAttributes are the shell element's computed attributes.
//
// The signals are marshalled here rather than in the template so that the JSON
// is escaped as an attribute value and not interpolated into markup: a page
// whose path contained a quote would otherwise be able to break out of the
// attribute that carries it.
func shellAttributes(shell httpapi.Shell) templ.Attributes {
	return templ.Attributes{"data-signals": shellSignalJSON(shell)}
}

// shellSignalJSON is shellSignals as the data-signals attribute's value.
func shellSignalJSON(shell httpapi.Shell) string {
	// A struct of one string and one bool cannot fail to marshal, and an
	// attribute has nowhere to report an error to. The fallback is the same
	// shape with the neutral values, so a client that could not read the seed
	// falls back to a full load rather than to a broken page.
	payload, err := templ.JSONString(shellSignals{
		CurrentPageURL: shell.CurrentPageURL,
		Push:           shell.PushEnabled,
	})
	if err != nil {
		return `{"currentPageUrl":"","push":false}`
	}
	return payload
}
