package httpapi

import (
	"net/http"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
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

func (v HomeView) isView()     {}
func (v PageView) isView()     {}
func (v SearchView) isView()   {}
func (v FilesView) isView()    {}
func (v TagsView) isView()     {}
func (v TagView) isView()      {}
func (v ContextView) isView()  {}
func (v CommandsView) isView() {}
func (v LoginView) isView()    {}
func (v SetupView) isView()    {}
func (v InviteView) isView()   {}
func (v ErrorView) isView()    {}

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

// ViewShell returns the layout's half of the LoginView.
func (v LoginView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the SetupView.
func (v SetupView) ViewShell() Shell { return v.Shell }

// ViewShell returns the layout's half of the InviteView.
func (v InviteView) ViewShell() Shell { return v.Shell }

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
