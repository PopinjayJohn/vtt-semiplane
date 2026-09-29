package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/a-h/templ"
)

// View is a view model: everything a template is allowed to see about one
// request. It is an interface so that a handler can hand the renderer a page, a
// home page, a search result or an error without a type switch at every call
// site, and so that a missing view is a compile error rather than an empty
// page.
//
// The types behind it live here, in httpapi, rather than in web, because the
// dependency arrow runs httpapi → web and not the other way round: web imports
// httpapi for these types, so httpapi must not import web to define them.
//
// A view model is a security boundary. Nothing behind it is a store row or a
// doc, so a template cannot reach a page's raw frontmatter, a file's bytes or a
// secret body except through a field that was put there on purpose.
type View interface {
	// isView is unexported so that only this package's types are views.
	isView()
	// ViewShell returns the part of the model the layout needs. It is on the
	// interface rather than recovered by a type switch, so that adding a view is
	// a compile error here rather than an empty page at runtime.
	ViewShell() Shell
}

// Shell is the part of every view model that the layout needs. It is embedded
// rather than passed separately so that a template cannot be handed a shell
// belonging to a different view.
type Shell struct {
	// Title is the document title. A page view uses the page's own title; every
	// other view uses a fixed name for the surface.
	Title string
	// Principal is the identity the response was produced under. The layout
	// renders it and never inspects it: a role comparison belongs in the Perm
	// middleware, and a template that branched on one would be the second place
	// in the codebase answering that question.
	Principal authz.Principal
	// CSRF is the token every form on the page must carry. It is minted per
	// session, or per pre-session cookie before there is a session.
	CSRF string
	// Campaign is the vault directory's name, shown in the masthead. It is a
	// filesystem name and never a page title: nothing in a vault names itself.
	Campaign string
	// Dev reports development mode, so the layout can say so out loud.
	Dev bool
	// CurrentPageID is the page this response is about, or 0 for a view that is
	// not a page. It is what the last-activity panel excludes and what the live
	// push's refetch target is seeded from, so neither has to guess.
	CurrentPageID int64
	// Push is the seed for the client's DataStar signals: whether a stream is
	// open for this tab, and the URL the shell refetches when it is triggered.
	// Both are plain strings, and a stream is only ever opened for an
	// authenticated principal, so nothing here is a capability.
	PushEnabled bool
	// CurrentPageURL is the page's canonical URL, empty for a view that is not
	// about a page.
	CurrentPageURL string
	// PreviewsEnabled reports whether any registered plugin contributed a
	// page-summary provider. It is a fact about the build rather than about the
	// request, which is why it is a bool and not a path: the client binds the
	// preview interaction when it is true and does not bind anything at all when
	// it is false, so a campaign with no preview plugin never issues a hover
	// request. It carries no page id, no path and no title — the summary route
	// is a constant in core and a plugin's prefix is a build fact.
	PreviewsEnabled bool
	// PluginNav is the left sidebar's plugin group, already ordered and already
	// filtered. It is empty when no registered plugin holds CapSidebarNav, and
	// the sidebar renders no group at all in that case — see LeftNav.
	//
	// It is on the shell rather than on a page view because it is chrome: the
	// same group is on every page, and a sidebar that gained or lost a group
	// per page would be a layout that reflows under the reader. Nothing here
	// says which plugin contributed an entry, and no template compares a role —
	// PluginNavFor has already asked the policy which entries this request's
	// principal may see.
	PluginNav []PluginNavItem
}

// PluginNavItem is one left-sidebar entry a plugin contributed.
//
// It is a projection rather than a plugin.NavItem for the reason PluginReportLine
// gives: a change to the plugin vocabulary's Go shape must not become a change
// to the markup by accident.
//
// Two of the plugin's fields are deliberately not carried. MinimumRole is
// resolved by PluginNavFor against the policy and disappears — a role on a view
// model is an authorization decision that a template could re-answer, and
// AGENTS.md §2.7 wants exactly one place that answers it. Badge is a function of
// the request, and a count that no column renders is a number on a page that
// cannot be checked by the reader looking at it.
type PluginNavItem struct {
	// ID is the nav item's own id, unique across the whole registry.
	ID string
	// Plugin is the id of the plugin that contributed it, and therefore the
	// route prefix Href has to sit inside.
	Plugin string
	// Label is the visible text.
	Label string
	// Href is where the entry navigates. PluginNavFor drops any href that is not
	// inside /plugin/{Plugin}, so an entry that reached a template points at a
	// route the plugin's own sub-router answers — a sidebar link that 404s is a
	// broken control by AGENTS.md §7 and not a cosmetic fault.
	Href string
	// Icon is a token from the core icon set, never raw HTML and never a URL.
	Icon string
	// Order is the plugin's own sort weight. It is not rendered: the registry
	// already sorted NavItems by it, and re-sorting a list that arrived in
	// order would only be able to lose that order. It is carried so the
	// projection is lossless and so a future group that merges contributions
	// from two sources has the weight without going back to the registry.
	Order int
}

// WithinPrefix reports whether the item's href is inside its own plugin's route
// prefix, /plugin/{Plugin}.
//
// The boundary is checked at the path separator rather than with a bare
// HasPrefix, so "dnd5e" cannot claim "/plugin/dnd5e-rogue/x" by name
// resemblance. A plugin whose own prefix is a prefix of another's is exactly the
// sort of accident the boot report is for; the check here costs a comparison
// and turns a bad href into a missing link rather than a 404 in the sidebar.
func (p PluginNavItem) WithinPrefix() bool {
	if p.Href == "" || p.Plugin == "" {
		return false
	}
	prefix := "/plugin/" + p.Plugin
	return p.Href == prefix ||
		strings.HasPrefix(p.Href, prefix+"/") ||
		strings.HasPrefix(p.Href, prefix+"?") ||
		strings.HasPrefix(p.Href, prefix+"#")
}

// PluginPanel is one panel a plugin contributed, in a shape a template can
// render without importing the plugin package.
type PluginPanel struct {
	// Slot is the region the panel was registered for, as the slot's own string.
	// The template groups by slot rather than trusting the order it was handed,
	// so a panel cannot be misplaced by a handler that sorted wrongly.
	Slot string
	// Title is the panel's heading, and it is never empty. plugin.Panel carries
	// no title field, so this is derived from the slot; a panel is a labelled
	// section or it is a block of markup nobody can identify.
	Title string
	// Body is the panel's rendered output as a string that the template emits
	// as escaped text. It is never marked raw here or anywhere else, and that
	// is the whole of the panel's security story.
	//
	// It is a string rather than the plugin's templ.Component because the
	// component cannot cross this boundary: internal/web sits above httpapi in
	// the dependency order, so httpapi cannot name a template and can only hand
	// one text. The cost is real and worth stating plainly — **a panel's markup
	// reaches the reader as visible text**, so a panel that renders <strong>
	// shows a reader the characters "<strong>". In this stage a panel is a
	// heading and a line or two of plain words, which is what the dnd5e panel
	// needs; anything richer wants the view model to carry the component
	// itself, which is a change to this field and not to the panel vocabulary.
	//
	// What the string buys is the property that matters more: a body that is
	// escaped on the way out cannot be a script, even if a plugin writes
	// templ.Raw. "A plugin cannot ship JavaScript" (AGENTS.md §7) is therefore
	// a fact about this pipeline rather than a claim about the plugins
	// currently in the tree, and it holds for the first plugin that decides
	// otherwise.
	//
	// The body is rendered per request, with the request's context, and that
	// context carries nothing a plugin can read: the principal, the page and
	// the vault row all sit behind keys this package owns, and a plugin may not
	// import httpapi. So every reader is shown the same panel text, which is
	// what makes rendering it per request safe — a panel that could see the
	// principal would be a panel with an authorization decision inside it, and
	// there is none anywhere in this path.
	Body string
}

// PageCard is a page as a view model: an identity and a display string.
//
// It is deliberately not store.Page. That row also carries the page's raw
// frontmatter and its content hash, and a view model that could reach either
// is a view model that can render either.
type PageCard struct {
	// ID is the page's index id.
	ID int64
	// Path is the vault-relative path, slash-separated.
	Path string
	// Title is the display title.
	Title string
	// PageType is the frontmatter `type:`, or "note".
	PageType string
	// UpdatedAt is when the page was last indexed.
	UpdatedAt time.Time
}

// Href is the canonical URL of the page.
func (p PageCard) Href() string { return "/p/" + p.Path }

// TagCard is a tag and the number of pages carrying it.
type TagCard struct {
	// Name is the normalised tag, without the '#'.
	Name string
	// Count is how many pages the viewer may see carrying it. It is computed
	// with the canonical visibility predicate, so a tag that only appears
	// inside a secret the viewer may not read counts as zero.
	Count int
}

// BacklinkChip is one referring page, for the page's aside.
type BacklinkChip struct {
	// Card identifies the referring page.
	Card PageCard
	// Line is the line in that page the reference is written on.
	Line int
}

// TocEntry is one table-of-contents row.
type TocEntry struct {
	// Level is the heading level, 1 to 6.
	Level int
	// Text is the heading's text.
	Text string
	// Slug is the anchor the heading is reachable at.
	Slug string
}

// SecretView is one secret fence on a page, as this viewer sees it.
//
// A hidden secret carries its id and nothing else. Not the body, not the byte
// length, not the author, not the title, not a visibility label finer than
// "hidden": every one of those is a fact about a secret the viewer was refused,
// and §8.8's rule is that a response's size must not be usable to infer what
// is behind a lock. A lock that named its contents' length would be a lock
// with the door ajar.
type SecretView struct {
	// ID is the fence's id: an opaque handle, and the only thing a hidden
	// secret contributes to the response.
	ID string
	// Ordinal is the fence's position in the file, from zero.
	Ordinal int
	// Hidden reports that this viewer may not read the secret.
	Hidden bool
	// Body is the plaintext. It is empty whenever Hidden is true, and it is
	// only ever filled by secrets.Service.Load.
	Body string
	// Visibility is the fence's visibility, reported only for a secret this
	// viewer may read.
	Visibility string
	// Label is the generic text shown in place of a hidden secret.
	Label string
}

// HomeView is the dashboard: the most recently indexed pages and the tag list.
type HomeView struct {
	Shell
	// Pages are the most recently updated pages the viewer may see.
	Pages []PageCard
	// Tags are the tags the viewer may see.
	Tags []TagCard
	// PageCount is how many pages the index holds.
	PageCount int
	// Status is the campaign status panel, which appears on every page because
	// it is campaign state rather than page state.
	Status CampaignStatus
}

// PageView is one page, with everything around it that is authorized for this
// viewer.
type PageView struct {
	Shell
	// Card identifies the page.
	Card PageCard
	// EditHref is where the editor for this page is, or "" when this viewer may
	// not write it.
	//
	// It is empty rather than a URL nobody may follow, so that a reader who
	// cannot edit this page is shown no control for it at all: app.js's `e` key
	// acts on the link this field decides about, and that link's absence is the
	// permission check. A shortcut that navigated to a refused editor would be a
	// broken control rather than a refused one, and a client-side guess at the
	// same question would be a second answer to it in a place with no policy to
	// ask.
	EditHref string
	// Body is the rendered public body. It is HTML produced by md.Renderer and
	// by nothing else; see web.PreRendered.
	Body string
	// Toc is the table of contents, filtered by the canonical predicate.
	Toc []TocEntry
	// Backlinks are the references to this page the viewer may see.
	Backlinks []BacklinkChip
	// BacklinkCount is what Backlinks would have held in total. It comes from
	// the identical query, so the number and the list cannot disagree.
	BacklinkCount int
	// Secrets are the page's fences in file order.
	Secrets []SecretView
	// Problems are the parse problems the file carries, as codes and short
	// messages. They never carry file content.
	Problems []string
	// Truncated reports that the file is longer than the render budget and
	// that the body shown here is a prefix of it. The file is untouched; only
	// the view is clipped.
	Truncated bool
	// Status is the campaign status panel. It is on the page view rather than
	// fetched separately because the right column is rendered with the page and
	// a panel that arrived a request later is a panel that flashed.
	Status CampaignStatus
	// Related are the pages sharing the most tags with this one. They are
	// rendered in the right column, and the panel is omitted when the list is
	// empty rather than shown with nothing in it.
	Related []PageCard
	// Panels are the panels registered for this page's type, in slot order. They
	// are additional to Status, not a replacement for it: the campaign panel
	// says what the campaign is, and a plugin panel says what a system makes of
	// it. A page with panels and a system-absent note shows both.
	//
	// It is empty for every page when no plugin holds CapUIPanels, and the right
	// column then renders nothing at all for it — a slot with no panel in it
	// leaves no heading behind.
	Panels []PluginPanel
	// PageType is the `type:` this page's frontmatter names, or "" when it names
	// none. It is on the page view rather than read from Card because it is what
	// selects the viewer, and the selection has to be made once, here, from the
	// file: a registered page type and a page-type *convention* are different
	// things, and `type: houserule` renders with the core Markdown view on a
	// campaign with no plugin installed.
	PageType string
	// Viewer is the custom viewer the plugin registered for PageType, or nil.
	//
	// Nil is the normal case and it is the one that must work: a nil Viewer
	// renders the core Markdown view, so a campaign with no system plugin, or
	// with one that registered a page type and no viewer, gets the whole page
	// rather than a blank article. A viewer receives no arguments, so it is a
	// decoration around the page rather than a replacement for its body — which
	// is the limit of the plugin vocabulary's PageType.Viewer, not of this
	// field.
	Viewer templ.Component
}

// SearchView is a search result page.
type SearchView struct {
	Shell
	// Query is what the viewer typed, echoed so the form keeps it.
	Query string
	// Total is how many hits exist across both sources.
	Total int
	// Hits are the hits in the requested window, pages before secrets.
	Hits []SearchHit
	// Failed reports that the query itself was unusable, so the form can say so
	// instead of showing an empty result as though the vault were empty.
	Failed bool
}

// SearchHit is one search result row.
type SearchHit struct {
	// Card identifies the owning page.
	Card PageCard
	// Kind is "page" or "secret". A secret hit names the page and never the
	// secret, because the hit's own existence is already the disclosure.
	Kind string
	// Snippet is an escaped excerpt, for a page hit, and empty for a secret
	// hit: no excerpt of a revealed secret is ever rendered.
	Snippet string
}

// FileNode is one directory in the file tree, or a file with no children.
//
// A directory is a path prefix and nothing else: it carries no counts, no
// timestamps and no existence flags, because a count in a sidebar is a number
// whose derivation a reader cannot check and a mismatch is a leak. The leaves
// carry the pages.
type FileNode struct {
	// Name is the final path segment, for display.
	Name string
	// Path is the directory's vault-relative path, slash-separated, without a
	// trailing slash. It is empty for the root.
	Path string
	// Dir reports whether this node has children of its own rather than
	// holding pages directly.
	Dir bool
	// Pages are the files in a leaf node, by title.
	Pages []PageCard
	// Children are the subdirectories of a directory node, by name.
	Children []FileNode
}

// FilesView is the whole vault as a tree.
type FilesView struct {
	Shell
	// Tree is the root node. Its Path is empty and its Dir is true.
	Tree FileNode
	// PageCount is how many pages the tree holds in total.
	PageCount int
}

// TagsView is the tag cloud, with every tag the viewer may see.
type TagsView struct {
	Shell
	// Tags are the tags, alphabetically, each with its own filtered count.
	Tags []TagCard
}

// TagView is one tag and the pages carrying it.
type TagView struct {
	Shell
	// Tag is the tag being shown, with the count from the same query that
	// produced Pages.
	Tag TagCard
	// Pages are the pages this viewer may see carrying the tag.
	Pages []PageCard
	// All is every tag, so the page can render the same cloud as /tags with
	// this one marked, without a second request.
	All []TagCard
}

// SessionRef is the current session log, as the campaign status panel names it.
type SessionRef struct {
	// Card identifies the log.
	Card PageCard
	// Number is the session's own number, from its `session:` frontmatter, or 0
	// when the file does not declare one. It is a value the author wrote; it is
	// never inferred from a position in a list.
	Number int
	// Date is the `date:` frontmatter rendered as a day, or empty when the file
	// declares none. It is a day and not a timestamp because that is what a
	// session log carries.
	Date string
}

// PartyMember is one character in the party list.
//
// The one-liner is a system-specific value that no core code can produce, so
// the field exists and is empty until a plugin fills it. An empty field is
// omitted by the template rather than rendered blank, which is the same
// field-level rule the rest of the panel follows.
type PartyMember struct {
	// Card identifies the character sheet.
	Card PageCard
	// Owner is the display name of the player who owns the sheet, or "" when it
	// is unowned. It is a name the account table holds, never a username that
	// would let a reader enumerate accounts.
	Owner string
	// Note is the system plugin's one-liner, empty in v1.
	Note string
}

// CampaignStatus is the right sidebar's campaign-wide panel.
//
// It is built as a list of independently authorized fields, and a field the
// reader may not see is *omitted* rather than blanked or locked: a player sees
// a smaller panel, not the same panel with holes in it. Every field below is
// resolved through the same canonical predicate as a page render, and the two
// rollups — Threads and LastActivity — are counted under that same predicate,
// so a page whose only mention is inside a secret the reader cannot read
// contributes zero rather than one.
type CampaignStatus struct {
	// Session is the current session log, or nil when the viewer may not see
	// one or the vault has no `#session` page.
	Session *SessionRef
	// Threads are the open threads, newest first.
	Threads []PageCard
	// ThreadCount is what Threads would have held in total. It comes from a
	// count over the identical predicate, so the badge and the list cannot
	// disagree.
	ThreadCount int
	// LastActivity is the most recently updated pages other than the one open.
	LastActivity []PageCard
	// Party are the character sheets, by title.
	Party []PartyMember
	// SystemNote is the plugin layer's contribution. It is a fixed phrase naming
	// the absence of a system, never a blank: a missing plugin must look like a
	// missing plugin rather than like a panel that failed to render.
	SystemNote string
}

// ContextView is everything a page view's right column carries, in one model.
//
// It is one type rather than four because it is one route: §9.2's
// /api/pages/{id}/context exists so that opening a page costs one request, and
// four separate models would be four places where the same page's context could
// be assembled inconsistently.
type ContextView struct {
	Shell
	// Card identifies the page.
	Card PageCard
	// Toc is the table of contents, filtered by the canonical predicate.
	Toc []TocEntry
	// Backlinks are the references to this page the viewer may see.
	Backlinks []BacklinkChip
	// BacklinkCount is what Backlinks would have held in total, from the
	// identical query.
	BacklinkCount int
	// Related are the pages this one shares the most tags with, and the panels
	// around it do not show when it is empty.
	Related []PageCard
	// Panels are the panels registered for this page's type, in slot order, and
	// they are the same ones the page view's right column carries: this route
	// and that column are one surface, and a client that swapped the context
	// region in must not get a different answer about what is in it.
	Panels []PluginPanel
	// Status is the campaign-wide panel.
	Status CampaignStatus
}

// Command is one row of the command palette.
type Command struct {
	// Label is what the reader sees.
	Label string
	// Href is where activating it navigates. Every command is a real URL, so
	// the palette is a list of links and works with JavaScript disabled.
	Href string
	// Kind is "page", "tag" or "action", and is what the palette's icon and its
	// grouping key are. It is a closed set of three so that a caller cannot
	// invent a fourth kind that nothing renders.
	Kind string
	// Hint is the keyboard tail shown at the right, empty when there is none.
	Hint string
}

// CommandsView is the command palette's result set.
//
// It is a View so that the palette can be rendered as a full page — which is what
// it is, with JavaScript disabled, and what makes the same rows reachable by
// following a link.
type CommandsView struct {
	Shell
	// Query is what the reader typed, echoed so the field keeps it.
	Query string
	// Commands are the rows, in the order the palette shows them: actions first,
	// then pages, then tags.
	Commands []Command
}

// The command kinds. A closed set of three, because a kind is what a template
// switches on and an open set is a runtime error in the middle of a palette.
const (
	// CommandPage is a destination inside the vault.
	CommandPage = "page"
	// CommandTag is a tag page.
	CommandTag = "tag"
	// CommandAction is a destination in the shell itself, such as the search
	// form or the campaign home.
	CommandAction = "action"
)

// PluginReportLine is one plugin's row on the boot report.
//
// It is a projection rather than a `plugin.Entry` so that a change to the
// report's Go shape cannot become a change to the page's markup by accident, and
// so that the reasons a plugin was refused are copied into a field the template
// can render without importing the plugin package.
type PluginReportLine struct {
	// ID is the plugin's id, rendered as the row's heading.
	ID string
	// Name is its human label.
	Name string
	// Kind is "system" or "feature", and it is what the row's badge shows.
	Kind string
	// Version is the plugin's own semver.
	Version string
	// Status is "ok", "compat" or "skipped", and is the row's state.
	Status string
	// Reason is why it was skipped, empty for a healthy row. It is a host
	// message carrying ids and counts, never a line of vault content, and
	// plugins are not handed vault content to put in one.
	Reason string
	// APILevel and HostLevel are both shown so a "compat" row is explainable
	// without leaving the page.
	APILevel  int
	HostLevel int
	// Capabilities is what the host granted this plugin, as stable strings.
	// A declaration the host refused appears here as an absence, which is
	// exactly how it affected the plugin.
	Capabilities []string
	// Counts is the per-plugin contribution summary, as pre-formatted short
	// strings ("2 page types, 1 panel") rather than six integers the template
	// would have to join. The joining is presentation, and presentation that
	// lives in a view model is presentation that can be tested.
	Counts []string
}

// AdminPluginsView is /admin/plugins: the boot report.
type AdminPluginsView struct {
	Shell
	// Lines is every registered plugin, sorted by id, including the skipped
	// ones. A report that lists only the healthy hides the problem it exists to
	// report.
	Lines []PluginReportLine
	// Warnings are the refusals that are not about one plugin: a panel dropped
	// for naming an unknown slot, a nav item pointing outside its prefix. They
	// are shown even when every plugin is healthy, because that is exactly when
	// they are most surprising.
	Warnings []string
	// HostLevel and APIWindow are the host's own numbers, shown once rather
	// than repeated per row.
	HostLevel int
	APIWindow int
	// Counts is the headline: how many registered, how many were skipped.
	Registered int
	Skipped    int
	// Compat is how many registered but are running the shim.
	Compat int
}

// LoginView is the login form, and the form's own error.
type LoginView struct {
	Shell
	// Problem is a short, fixed phrase for the form's error line. It never
	// echoes the submitted username or passphrase, and there is exactly one of
	// them for every failed login, so the form cannot be used to enumerate
	// accounts.
	Problem string
	// Next is the path to return to after a successful login, already
	// validated as a same-origin absolute path.
	Next string
}

// SetupView is the first-run form, and the form's own error.
type SetupView struct {
	Shell
	// Problem is a short phrase naming the field that was refused.
	Problem string
	// Field is the form field the problem belongs to.
	Field string
}

// InviteView is the invite redemption form, and the form's own error.
type InviteView struct {
	Shell
	// Role is the role the invite grants, shown before the form is submitted.
	// It is empty until the token has been resolved, because an unresolved
	// token grants nothing and displaying a role for one would be a claim the
	// server has not made.
	Role string
	// Problem is a short phrase for the form's error line.
	Problem string
	// Invalid reports that the token cannot be redeemed at all, which is one
	// answer for a token that never existed, one that was used, and one that
	// expired.
	Invalid bool
	// Token is the raw invite token, so the form can post to the same URL it
	// was served from. It is not a secret the app holds: it is the bearer
	// credential the invitee was already sent, in the URL they are already on,
	// and it is never written to a log.
	Token string
}

// EditView is the editor: one page's buffer, the hash it was built from, and
// the problems the file carries.
//
// Content is the buffer to put in the textarea and Mode says what it is. In
// EditModeFull it is the file verbatim; in EditModeRedacted it holds one
// restore sentinel per body in HiddenIDs and never a body. The two are a pair
// rather than a flag a template reads on its own, because a template that
// rendered a redacted buffer as though it were the file would put a body it
// cannot see into a form, and a form is a place a body is submitted from.
type EditView struct {
	Shell
	// Card identifies the page being edited.
	Card PageCard
	// Action is where the form posts. It is the page's own edit URL rather
	// than a constant, so the form keeps working on a page whose path the
	// router will route back to this handler.
	Action string
	// PageHref is the page this editor is for, so the form can offer "back to
	// the page" without the template reconstructing a URL.
	PageHref string
	// RawHref is the page's raw Markdown view.
	RawHref string
	// HistoryHref is the page's revision list.
	HistoryHref string
	// Content is the buffer to edit. It is the file's true bytes only when Mode
	// is EditModeFull.
	Content string
	// BaseHash is vault.HashHex of the bytes on disk when this buffer was built,
	// and is what a submission must carry back.
	BaseHash string
	// Mode is "full" or "redacted": whether Content holds the file or sentinels.
	Mode string
	// HiddenIDs are the secret ids whose bodies Content does not carry, sorted.
	// They are ids and nothing else — no length, no author, no digest — because
	// a marker in an editor is a place a disclosure would be.
	HiddenIDs []string
	// HiddenCount is len(HiddenIDs) as a number, for the editor's own summary
	// line. It is a convenience for the template and not a second source: it is
	// the same slice, counted.
	HiddenCount int
	// Problems are the page's recoverable parse problem codes, in file order.
	// They never carry file content.
	Problems []string
	// Saved reports that this response is the answer to a successful save rather
	// than to a request for the form, so the template can say so. It is a bool
	// and not a message: a message per outcome is a string table in a template,
	// and the outcome is the only fact the handler knows.
	Saved bool
	// MayWrite is false when the route's coarse gate let the request through but
	// the page-scoped write permission — the one that carries this page's
	// ownership — refused it. The editor then renders read-only rather than a
	// form whose submission would be refused.
	MayWrite bool
}

// The editor's two modes, as the string the view model carries.
//
// They are strings rather than the secrets package's EditMode so that a
// template compares against a constant it can read in one place, and so that
// internal/httpapi's view models do not carry a type from a package whose
// constants would be a second spelling of the same two states.
const (
	// EditModeFull says Content is the file verbatim.
	EditModeFull = "full"
	// EditModeRedacted says Content holds a sentinel in place of every body in
	// HiddenIDs.
	EditModeRedacted = "redacted"
)

// DiffLine is one line of a rendered diff.
type DiffLine struct {
	// Op is the unified-diff marker for the line: " ", "-" or "+".
	Op string
	// No is the 1-based line number the line has in the side it belongs to.
	No int
	// Text is the line's content without its terminator. It is escaped text,
	// never markup: nothing a vault contains reaches a template unescaped.
	Text string
}

// DiffHunk is one run of changed lines with context on both ends.
type DiffHunk struct {
	// FromA is the first line of the run on the left side, 1-based.
	FromA int
	// CountA is how many left-side lines the hunk covers, context included.
	CountA int
	// FromB is the first line of the run on the right side, 1-based.
	FromB int
	// CountB is how many right-side lines the hunk covers, context included.
	CountB int
	// Lines are the hunk's own lines in order, context lines included. A hunk
	// is renderable from this slice alone, so the counts are for the header
	// and the lines are for the body.
	Lines []DiffLine
}

// Conflict is the two sides of a lost race, already authorized.
//
// Both strings are renderings this principal is entitled to read and nothing
// else. Theirs went through the same redacted read path the page view and the
// editor use, so a secret this principal may not read is a fixed label in it
// and never a body and never a length. Mine is the actor's own submitted
// buffer, echoed back: the only way a body is in it is that the actor typed it
// or pasted it, and a save that does not echo it is a save that throws away the
// work it refused.
type Conflict struct {
	// Theirs is the file as it is on disk right now, as this principal may
	// read it.
	Theirs string
	// Mine is the buffer that lost the race, echoed.
	Mine string
	// Hunks is the line diff between the two, computed over the two authorized
	// renderings and never over a raw file.
	Hunks []DiffHunk
	// BaseHash is the on-disk hash now, as hex, so the editor can be re-opened
	// against the current bytes rather than against the ones that lost.
	BaseHash string
	// Reason is a fixed phrase naming what was being written: "save" or
	// "revert". It is a closed set of two because a handler is the only thing
	// that fills it in.
	Reason string
}

// ConflictView is the 409 a lost optimistic-concurrency race answers with.
//
// It is a view and not an error page for a reason that is worth stating, because
// every other non-2xx response in this package is the fixed errorCopy: a 409 is
// not a refusal. The two documents on it are the current file as this principal
// may read it and the actor's own submission, both re-derived through the
// authorized read path, and the actor is the only reader. Nothing here is shown
// to anybody who could not already read it, so the fixed copy has nothing to
// add and a template with two text areas does.
type ConflictView struct {
	Shell
	// Card identifies the page the race was on.
	Card PageCard
	// Conflict holds the two authorized renderings and the diff between them.
	Conflict Conflict
}

// RevisionRow is one revision in a page's history list.
//
// It carries no content and no diff. secrets.Service.History reads metadata
// only, and the reason is not merely economy: fifty rows of a with-content read
// would be fifty whole files, each of which may hold secret plaintext that no
// read-time authorization has touched yet.
type RevisionRow struct {
	// ID is the revision's id, and what the open and revert URLs carry.
	ID int64
	// At is when the revision was recorded.
	At time.Time
	// Source is one of the four store.RevisionSource values.
	Source string
	// Author is the account responsible, and empty for an external change.
	Author string
	// External reports that no account is responsible, so an empty Author means
	// "nobody" rather than "the name was not shown".
	External bool
	// Visible is secrets' cheap answer to "can this principal open it". It is an
	// approximation and is documented as one: a row marked true can still fail
	// to open, and a row marked false can still open. It never gates a body —
	// the single-revision read re-decides from the revision's own bytes.
	Visible bool
	// Href opens the revision.
	Href string
	// RevertHref restores the page to this revision. It is present on every row
	// regardless of Visible, because a revert is authorized as an edit and the
	// edit authorization is the gate, not this flag.
	RevertHref string
}

// HistoryView is a page's revision list.
type HistoryView struct {
	Shell
	// Card identifies the page.
	Card PageCard
	// Revisions are the rows, newest first, capped at the retention limit.
	Revisions []RevisionRow
	// Total is how many revisions the page has. It comes from the count over
	// the identical predicate, so the badge cannot disagree with the list
	// about anything a reader may see.
	Total int
	// Truncated reports that Revisions is the most recent slice of Total.
	Truncated bool
	// PageHref is the page these revisions belong to.
	PageHref string
}

// RevisionView is one revision and, when it may be compared, the diff against
// the page as it is now.
type RevisionView struct {
	Shell
	// Card identifies the page.
	Card PageCard
	// ID is the revision's id.
	ID int64
	// At is when the revision was recorded.
	At time.Time
	// Source is one of the four store.RevisionSource values.
	Source string
	// Author is the account responsible, and empty for an external change.
	Author string
	// Content is the file as it was. It is populated only when every secret in
	// the revision's own bytes is readable by this principal: a revision
	// holding one body the reader may not see is not served with a placeholder,
	// it is not served at all.
	Content string
	// Hunks is the line diff against the page as it is now, or nil.
	//
	// It is nil whenever Comparable is false, and the reason is stated in
	// DiffOpaque: a diff is computed over two renderings, and the only way to
	// make the current side safe to show is to redact it, and md.Redact's
	// sentinel carries the hidden body's length and a digest of it. So the diff
	// is offered only to a principal who can read every secret the page holds
	// now, for whom the redaction is a no-op.
	Hunks []DiffHunk
	// Comparable reports whether Hunks means anything.
	Comparable bool
	// DiffOpaque is a fixed phrase explaining why not, or empty.
	DiffOpaque string
	// PageHref is the page the revision belongs to.
	PageHref string
	// HistoryHref is the page's revision list.
	HistoryHref string
}

// The reasons a revision's diff is not offered.
//
// They are constants rather than a format string because a template should not
// be assembling sentences, and a closed set of two means a template can switch
// on them without a default case that hides a third.
const (
	// DiffOpaqueUnreadable is the reason for a principal who may not read every
	// secret the page holds right now.
	DiffOpaqueUnreadable = "This page holds content you may not read, so no comparison is offered."
	// DiffOpaqueIdentical is the reason for a revision whose authorized
	// rendering is byte-identical to the page as it is now.
	DiffOpaqueIdentical = "This revision is the page as it is now."
)

// BrokenLinkRow is one dangling reference, as a page names it.
type BrokenLinkRow struct {
	// Card is the page the reference is written on.
	Card PageCard
	// Target is the reference as the author wrote it, which is what is
	// dangling: a path with no extension is a page that does not exist.
	Target string
	// Line is the line the reference is on, 1-based.
	Line int
	// Kind is the reference kind, one of the store.LinkKind values.
	Kind string
}

// BrokenLinksView is the broken-links panel: every reference in the vault that
// does not resolve to a page.
type BrokenLinksView struct {
	Shell
	// Rows are the dangling references this principal may see, in the order the
	// identical count query produces, capped at ShownLimit.
	Rows []BrokenLinkRow
	// Total is how many the principal may see in total, from the count over the
	// identical predicate. It is the badge; Rows is the list; Truncated says
	// when the two differ because the list was capped.
	Total int
	// ShownLimit is the cap, carried so a template can say what the cap is
	// rather than inventing a number.
	ShownLimit int
	// Truncated reports that Rows is the first ShownLimit of Total.
	Truncated bool
}

// ShownLimit is how many broken links the panel renders.
//
// The count is unbounded in the store, and a campaign that has just been
// restructured can hold tens of thousands of them. The panel is a diagnostic
// surface, not an export: a reader who needs the rest has the files, and a
// response that grows without bound is a denial-of-service lever a single GET
// can pull.
const ShownLimit = 200

// ErrorView is the one shape every non-2xx response uses.
//
// It carries a status, a heading and a detail, and nothing that varies per
// request. That is deliberate: the body a viewer is shown for a page they may
// not read has to be byte-identical to the body for a page that does not
// exist, and the only way to guarantee that is for there to be nothing in it
// that could differ.
type ErrorView struct {
	Shell
	// Status is the HTTP status code.
	Status int
	// Heading is the short title of the page.
	Heading string
	// Detail is one sentence of explanation. It is a constant per status.
	Detail string
}

func (v HomeView) isView()         {}
func (v PageView) isView()         {}
func (v SearchView) isView()       {}
func (v FilesView) isView()        {}
func (v TagsView) isView()         {}
func (v TagView) isView()          {}
func (v ContextView) isView()      {}
func (v CommandsView) isView()     {}
func (v AdminPluginsView) isView() {}
func (v LoginView) isView()        {}
func (v SetupView) isView()        {}
func (v InviteView) isView()       {}
func (v EditView) isView()         {}
func (v HistoryView) isView()      {}
func (v RevisionView) isView()     {}
func (v BrokenLinksView) isView()  {}
func (v ConflictView) isView()     {}
func (v ErrorView) isView()        {}

// The ViewShell methods hand the layout's half of each model back through the
// interface, so that a renderer can be handed a View without knowing what kind it
// is. Each is a one-liner because each view model carries a Shell by embedding it,
// and spelling that out seven times would be seven chances to forget.

// ViewShell returns the layout's half of the HomeView.
func (v HomeView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the PageView.
func (v PageView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the SearchView.
func (v SearchView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the FilesView.
func (v FilesView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the TagsView.
func (v TagsView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the TagView.
func (v TagView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the ContextView.
func (v ContextView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the CommandsView.
func (v CommandsView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the AdminPluginsView.
func (v AdminPluginsView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the LoginView.
func (v LoginView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the SetupView.
func (v SetupView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the InviteView.
func (v InviteView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the EditView.
func (v EditView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the HistoryView.
func (v HistoryView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the RevisionView.
func (v RevisionView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the BrokenLinksView.
func (v BrokenLinksView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the ConflictView.
func (v ConflictView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the ErrorView.
func (v ErrorView) ViewShell() Shell { return v.Shell }

// Renderer turns a view model into a response body.
//
// internal/web implements it. httpapi cannot import web, because web sits
// above httpapi in the dependency order and the arrow only runs one way. An
// interface at a package boundary is the point of one, and this is that
// boundary: the router decides *what* a request is allowed to see, and the
// template library decides what the response looks like.
type Renderer interface {
	// Document writes a whole HTML document for v: the shell, the head, the
	// asset tags, and the content region.
	Document(w http.ResponseWriter, r *http.Request, v View) error
	// Fragment writes only the content region, without the shell, the head or
	// the asset tags. Its bytes are a strict subset of Document's for the same
	// view, which is what lets a swapped region and a full page be compared.
	Fragment(w http.ResponseWriter, r *http.Request, v View) error
	// Region renders one named sub-region of v, and returns its bytes: the rows
	// of the command palette rather than the palette's form, the body of a dialog
	// rather than the dialog.
	//
	// It returns bytes rather than taking a writer because a patch has to look at
	// the element before it goes on the wire — the element-patch frame cannot
	// carry a newline — and a caller holding a writer would have to buffer it
	// itself to do the same check.
	//
	// It exists because a patch replaces a chosen element, and the chosen element
	// is usually smaller than the view. A handler that assembled the patch body
	// itself would be the second place that knows what a palette row looks like,
	// and the second copy is the one that stops being updated.
	//
	// An unknown name is an error, not empty bytes: a caller asking for a region
	// that does not exist has a bug, and rendering nothing for it would turn that
	// bug into a permanently blank panel.
	Region(v View, name string) ([]byte, error)
}
