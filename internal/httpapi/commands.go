package httpapi

import (
	"net/http"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The command palette's windows.
//
// The tag cap is tighter than the page cap on purpose: a tag list is a long
// tail, and a reader who has typed three characters wants the page they meant
// more than they want the campaign's whole vocabulary.
const (
	// commandPageLimit is how many pages the palette offers for one term.
	commandPageLimit = 8
	// commandTagLimit is how many tags the palette offers for one term.
	commandTagLimit = 10
)

// commandsAPI is the command palette's data source.
//
// Every row is a real same-origin absolute path, so the palette is a list of
// links and works with the JavaScript that enhances it switched off: with no
// script, the browser follows the same hrefs and lands on the same pages. That
// is the reason there is no separate "open in the app" code path, and the reason
// a row's href is never assembled from anything but a constant prefix and one
// escaped name.
//
// The route is PermSession rather than PermAnonRead because the palette is an
// affordance, not a capability: every row it returns is a destination inside the
// campaign, and an anonymous reader with anonymous read on has the campaign
// already. Refusing the palette to a reader who can navigate everything in it
// would be refusing a convenience on the grounds that it is convenient.
func (s *Server) commandsAPI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	// searchQuery is the search route's own reader, and maxQueryBytes is its own
	// cap. A second constant with a different value is how two routes come to
	// disagree about how long a term may be; a term over the cap matches nothing
	// rather than being truncated into something the reader did not type.
	query := searchQuery(r)
	term := query
	if len(term) > maxQueryBytes {
		term = ""
	}

	view := CommandsView{
		Shell:    s.liveShell(r, "Commands"),
		Query:    query,
		Commands: commandActions(),
	}
	if term != "" {
		pages, err := store.ListCommandPages(ctx, s.db.Reader(), who, term, commandPageLimit)
		if err != nil {
			s.fail(w, r, "list the palette's pages", err)
			return
		}
		for _, row := range pages {
			card := cardOf(row)
			view.Commands = append(view.Commands, Command{
				Label: card.Title,
				Href:  card.Href(),
				Kind:  CommandPage,
			})
		}
		tags, err := store.ListTags(ctx, s.db.Reader(), who)
		if err != nil {
			s.fail(w, r, "list the palette's tags", err)
			return
		}
		view.Commands = append(view.Commands, tagCommands(term, tags)...)
	}
	s.renderCommands(w, r, view)
}

// renderCommands writes the palette in the shape the request asked for.
//
// The split is this package's ordinary content negotiation with one extra
// question, and neither half is optional.
//
// The document half is what a reader with the enhancement switched off gets, and
// that is not a courtesy: every row is a real href, so /_/commands has to be a
// page a browser can be sent to, or the promise that the palette works without
// JavaScript would be a promise about a URL that answers with a payload.
//
// The fragment half answers with the bare region as HTML. It is not an event
// stream and it is not JSON, and datastar.go records why: the vendored bundle's
// element-patch format could not be established from outside with confidence, and
// its handling of an application/json response is a signals patch that would
// write every matched page's title into the document's reactive state.
func (s *Server) renderCommands(w http.ResponseWriter, r *http.Request, view CommandsView) {
	if r.URL.Query().Get(fragmentParam) == "" {
		if err := s.Render(w, r, view); err != nil {
			s.fail(w, r, "render the command palette", err)
		}
		return
	}
	if err := s.writeRegion(w, r, view, patchIntoParam, defaultRegionName); err != nil {
		s.fail(w, r, "write the command palette's rows", err)
	}
}

// commandActions are the destinations in the shell itself.
//
// They are first in the list and they are present whatever the term, because
// they are the three places a reader goes when nothing they typed matched —
// the campaign, its tags, its files. Their hints are the keyboard map, and they
// are written here rather than in the client so that the map has one source:
// a hint that exists in a stylesheet and not in the payload is a shortcut the
// palette will not offer.
func commandActions() []Command {
	return []Command{
		{Label: "Campaign home", Href: "/", Kind: CommandAction, Hint: "h"},
		{Label: "Tags", Href: "/tags", Kind: CommandAction, Hint: "t"},
		{Label: "Files", Href: "/files", Kind: CommandAction, Hint: "f"},
	}
}

// tagCommands is the palette's tag rows for a term.
//
// The list is the filtered tag cloud rather than a second query, because a tag
// is a page and ListTags already answers "which tags may this principal see"
// under the canonical predicate. Asking the database the same question twice
// would be a second place for that answer to be wrong.
func tagCommands(term string, tags []store.TagCount) []Command {
	out := make([]Command, 0, commandTagLimit)
	for _, t := range tags {
		if len(out) == commandTagLimit {
			break
		}
		if !strings.HasPrefix(t.Name, term) {
			continue
		}
		out = append(out, Command{
			Label: "#" + t.Name,
			Href:  tagHref(t.Name),
			Kind:  CommandTag,
		})
	}
	return out
}
