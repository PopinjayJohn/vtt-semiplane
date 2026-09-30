package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// recentLimit is how many pages the dashboard shows.
const recentLimit = 20

// home is the dashboard: the most recently indexed pages, and the tags.
//
// It is a content-bearing route, so its permission is PermAnonRead and an
// unauthenticated visitor is refused unless anonymous read is on. The list it
// shows is a page list, which is public content by the same measure as any
// other page: a viewer who could not read a page must not learn that it was
// edited yesterday.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	db := s.db.Reader()

	pages, err := store.ListRecentPages(ctx, db, recentLimit)
	if err != nil {
		s.fail(w, r, "list the recent pages", err)
		return
	}
	tags, err := store.ListTags(ctx, db, who)
	if err != nil {
		s.fail(w, r, "list the tags", err)
		return
	}
	total, err := store.CountPages(ctx, db)
	if err != nil {
		s.fail(w, r, "count the pages", err)
		return
	}
	status, err := s.campaignStatus(ctx, who, 0)
	if err != nil {
		s.fail(w, r, "read the campaign status", err)
		return
	}

	view := HomeView{
		Shell:     s.liveShell(r, "Campaign"),
		Pages:     pageCards(pages),
		Tags:      tagCards(tags),
		PageCount: int(total),
		Status:    status,
	}
	// The dashboard is not about a page, so it has no panels; it still has the
	// sidebar's plugin group, because the sidebar is chrome and a group that
	// appeared on some pages and not others would be a layout that reflows
	// under the reader.
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the dashboard", err)
	}
}

// page is the page view: the file rendered, with the table of contents, the
// backlinks and the secrets this viewer is allowed to see.
//
// Every query it makes is filtered in SQL by the canonical predicate, so a row
// that must not be seen never leaves the database. The secret list is the one
// place the decision is made in Go, and it is made by authz.CanReadSecret — the
// same rule the predicate implements — over the fences in the file, with the
// body of an indexed one then read through secrets.Service.Load, which applies
// the predicate again. Two independent gates, neither of them a re-statement of
// the other's logic. See pageSecrets for why the set comes from the file.
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	path := selectedPath(r)
	if path == "" {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	row, err := s.lookupPage(ctx, path)
	if errors.Is(err, store.ErrNoRows) {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, "load the page", err)
		return
	}

	// The file is canonical: the index says the page exists, and the bytes come
	// from the file rather than from a derived column. A file that has gone or
	// cannot be read is a 404, because a page the viewer may not read is a 404
	// too and the two must not be distinguishable.
	src, err := s.readPage(ctx, row.Path)
	if err != nil {
		s.log.WarnContext(ctx, "a page in the index could not be read from the vault",
			"action", "http.page", "request_id", obs.RequestID(ctx),
			"path", row.Path, "reason", err.Error())
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	doc := md.Parse(row.Path, src)
	body, truncated, err := s.renderBody(ctx, row.ID, doc)
	if err != nil {
		s.fail(w, r, "render the page", err)
		return
	}

	// The right column is resolved once, by the same builder the context API
	// uses, so the HTML view and the JSON view cannot describe two different
	// campaigns for one page.
	aside, err := s.pageAsideFor(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "read the page's context", err)
		return
	}
	pageSecrets, unattributed, err := s.pageSecrets(ctx, who, row, doc)
	if err != nil {
		s.fail(w, r, "list the page's secrets", err)
		return
	}

	card := cardOf(row)
	// The edit affordance is the page's own editor URL or nothing at all.
	// mayWritePage is the page-scoped gate the editor itself asks before it
	// renders a form, so a viewer who may not write this page is handed no
	// control that would be refused — a link whose activation answers 403 is a
	// broken control wearing a permission's clothes.
	editHref := ""
	mayWrite, err := s.mayWritePage(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "resolve the page's write permission", err)
		return
	}
	if mayWrite {
		editHref = card.Href() + "/edit"
	}
	// The frontmatter's `type:` selects the viewer and the panel set, and it is
	// read from the file rather than from the URL: a registered page type and a
	// page-type convention are different things, and both arrive the same way —
	// as a `type:` in a file nobody edited through this app.
	pageType := s.currentPageType(row)
	view := PageView{
		Shell:         s.liveShell(r, card.Title),
		Card:          card,
		EditHref:      editHref,
		Body:          body,
		Toc:           aside.toc,
		Backlinks:     aside.backlinks,
		BacklinkCount: aside.backlinkCount,
		Related:       aside.related,
		Status:        aside.status,
		Panels:        s.pluginPanels(ctx, pageType),
		PageType:      pageType,
		Viewer:        s.pageViewer(pageType),
		Secrets:       pageSecrets,
		Truncated:     truncated,
	}
	// The open page is named in the shell so that the last-activity panel can
	// leave it out and the live-push path knows what to refetch, neither of
	// which has to guess from the URL.
	view.Shell.CurrentPageID = row.ID
	view.Shell.CurrentPageURL = card.Href()
	for _, p := range doc.Problems {
		view.Problems = append(view.Problems, p.Code+": "+p.Message)
	}
	// Appended rather than interleaved: the parser found its problems walking the
	// bytes and these are found walking the fences, and the two orders are not
	// the same sequence. One list beats two, and a reader working down it is
	// told what is wrong either way.
	view.Problems = append(view.Problems, unattributed...)

	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the page view", err)
	}
}

// lookupPage finds a page by the URL the app itself emits.
//
// The canonical URL of a page is its vault path without the extension — /p/Tavern
// rather than /p/Tavern.md — because that is what a wikilink resolves to and what
// the links in a rendered page carry. So the handler accepts both: the bare form
// first, because it is the one the app generates, and the path with .md appended
// for a hand-typed or bookmarked one. A path that already ends in .md is looked
// up as it stands, so a vault containing both Tavern.md and a directory named
// Tavern cannot be shadowed by the fallback.
func (s *Server) lookupPage(ctx context.Context, path string) (store.Page, error) {
	row, err := store.GetPageByPath(ctx, s.db.Reader(), path)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, store.ErrNoRows) {
		return store.Page{}, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".md") {
		return store.Page{}, err
	}
	return store.GetPageByPath(ctx, s.db.Reader(), path+".md")
}

// renderBody turns a page's public body into HTML, inside the render budget.
//
// Only the public body reaches the renderer: the secret spans are dropped from
// the document that is handed over, and the fences are rendered separately by
// pageSecrets under the visibility rule. There is no path from a secret span to
// this function, which is what makes "never render a secret body" a property
// rather than an intention.
func (s *Server) renderBody(ctx context.Context, pageID int64, doc *md.Doc) (string, bool, error) {
	clipped, truncated := clipRenderable(doc.PublicBody())
	if truncated {
		// A clipped document rather than a clipped string: RenderDoc re-derives
		// the public body from the spans, so a shortened body has to be
		// presented as a document whose spans say it is all public.
		doc = clipDoc(doc, clipped)
	}
	out, err := s.markdown.RenderDoc(doc)
	if err != nil {
		return "", false, err
	}
	return string(s.decorateWikilinks(ctx, pageID, out)), truncated, nil
}

// clipDoc returns a copy of d whose whole body is the given public bytes.
//
// It keeps the path — a canvas stays a canvas — and drops everything that
// described the original body, because a span pointing into bytes that are no
// longer there is a bounds error waiting to happen.
func clipDoc(d *md.Doc, body []byte) *md.Doc {
	out := *d
	out.Bytes = body
	out.Body = body
	out.BodyRange = md.Range{Start: 0, End: len(body)}
	out.Spans = []md.Span{{Kind: md.SpanPublic, StartByte: 0, EndByte: len(body)}}
	out.Frontmatter = nil
	out.FrontmatterRange = md.Range{}
	out.FrontmatterYAMLRange = md.Range{}
	out.Fields = nil
	return &out
}

// pageSecrets returns the page's fences, in file order, with a body only for the
// ones this viewer may read.
//
// **The set comes from the file, not from the index, and that is the whole
// property of this function.** renderBody has already removed every secret span
// from the document it rendered, so every fence in the file needs an answer here
// or the page has a hole where a secret used to be. Taking the set from
// store.ListSecretRowsByPage instead means a fence the indexer declined to write
// — one whose `author=` is not a known account, or one with no conforming `id=` —
// produced no row and therefore no box, no lock, no body and no complaint: the
// body was stripped from the page and nothing took its place. That is the same
// defect pageraw.go's own comment names ("the redaction is decided against the
// FILE, not against the index"), and it is why the secret survived only on the
// two surfaces that serve bytes: /raw and the editor. So this walks
// secrets.Parse over the same *md.Doc the renderer was given, which is
// hiddenFences' input too, and asks the same question with the same rule.
//
// The index still earns its place, for two jobs and no others. It corroborates —
// a fence it holds has its body re-read through secrets.Service.Load, so the
// canonical SQL predicate stays a second independent gate on every body this
// page serves. And it decides **addressability**: a reveal posts a secret id, so
// a fence with no row is a fence the route could not act on, and offering the
// control would be a broken control wearing a permission's clothes (AGENTS.md §7).
//
// The list is deliberately unfiltered: a fence is a visible box in the page's
// layout, and hiding the box would tell the reader something was there while
// showing nothing. What differs is the *content* of the box, and it differs down
// to nothing at all: a hidden secret contributes its id — an opaque handle, and
// not a credential — and not one more byte of metadata. That is why the response
// for a page carrying a 40 KiB hidden secret differs from the response for one
// carrying an empty fence by the length of "⟨secret:… hidden⟩" and not by 40 KiB.
//
// The second return value is one problem line per fence the index declined and
// the parser did not already report, shown only to a reader who may read that
// fence, so that a box always has a reason beside it for the person who can fix
// it. The only indexer refusal that leaves the parser silent is an unresolvable
// `author=` — a missing id or an unreadable visibility is md's own problem and is
// already in doc.Problems — so this names that, and says nothing about the body.
func (s *Server) pageSecrets(
	ctx context.Context,
	who authz.Principal,
	row store.Page,
	doc *md.Doc,
) ([]SecretView, []string, error) {
	// Which of this page's fences the index holds, by id, and at which ordinal.
	// The ordinal is part of the key because the index is keyed on the id alone:
	// two fences in one file claiming one id — a malformed page — would otherwise
	// make both of them addressable, and the second one's box would offer a
	// reveal that rewrites the first one's directive.
	indexed, err := store.ListSecretRowsByPage(ctx, s.db.Reader(), row.ID)
	if err != nil {
		return nil, nil, err
	}
	held := make(map[string]int, len(indexed))
	for _, sec := range indexed {
		held[sec.ID] = sec.Ordinal
	}

	owner, err := s.pageOwned(ctx, who, row.ID)
	if err != nil {
		return nil, nil, err
	}
	// Asked once for the page rather than per fence, and through the policy rather
	// than through a role comparison: the route's Perm column is PermDM, so this
	// is the same question the gate asks and the button cannot disagree with it.
	// TestNoRoleComparisonOutsidePerm fails the build on a role comparison outside the
	// policy, and the deeper
	// reason is that a control whose visibility is a second, hand-written copy of
	// its gate is a control that can be wrong.
	mayChange := s.mayChangeSecretVisibility(who)
	base := cardOf(row).Href()

	fences, fenceProblems := secrets.Parse(doc)
	// A problem keyed on the fence's id, so a fence the parser has already
	// reported is not reported a second time in this handler's words, and so the
	// closed-to-everyone branch below can ask one question of one map.
	reported := secrets.UnusableFenceIDs(doc.Problems, fenceProblems)

	out := make([]SecretView, 0, len(fences))
	var unattributed []string
	for _, f := range fences {
		author, err := s.authorID(ctx, f.Author)
		if err != nil {
			return nil, nil, err
		}
		f.AuthorID = author

		ordinal, inIndex := held[f.ID]
		// The index row that is *this* fence, not merely a row carrying its id.
		ours := inIndex && ordinal == f.Ordinal

		// Both actions, and both empty unless the index holds this exact fence:
		// a reveal names an id, so an unaddressable fence is a control the route
		// would refuse. Both are on the hidden shape too, and that is deliberate: a
		// DM reads every secret on the page, so for that principal no fence is
		// hidden and the branch below is the only one that runs — but a principal
		// who may neither see nor broadcast must not find a page where the
		// control's presence depended on which branch produced the row.
		view := SecretView{ID: f.ID, Ordinal: f.Ordinal}
		if mayChange && ours {
			view.RevealAction = base + "/secrets/" + f.ID + "/reveal"
			view.RevokeAction = base + "/secrets/" + f.ID + "/revoke"
		}
		// A fence whose directive could not be read is closed to everybody, and
		// this is the branch that says so. The indexer declines to write a row
		// for such a fence, so without it this falls through to the `!ours` path
		// below and hands a principal who *may* read it the body — turning a
		// fence that is fail-closed into one that is merely hidden from the table,
		// which is exactly the demotion AGENTS.md §6 and
		// TestAnUnunderstoodSecretFenceNeverBecomesPublic exist to prevent.
		//
		// The rule itself is secrets.Secret.Openable, which the raw view, the
		// export and the conflict page all ask, because they were once four
		// copies of it and two of them were wrong.
		//
		// lockLabel and not a sentinel, for the reason AGENTS.md §6 gives: this is
		// a surface meant to be looked at, and a sentinel carries the hidden body's
		// length and a digest of it. The editor needs that because a save has to
		// put the body back; nothing else does.
		if !f.Openable(who, owner, reported[f.ID]) {
			view.Hidden = true
			view.Label = lockLabel(f.ID)
			out = append(out, view)
			continue
		}

		// One problem line for a fence the index declined and the parser did not
		// already report — and only to a reader who may read the fence, because
		// the line is about the fence's directive and a directive is not shown to
		// somebody the box above has just refused. The complaint is about the file
		// rather than the reader, but a page where half the boxes can be explained
		// and half cannot is a page a DM debugs in a text editor instead.
		if !ours && !reported[f.ID] {
			unattributed = append(unattributed, unattributedNote(f))
		}

		body := f.Body
		if ours {
			// The only body-bearing read in the codebase for an indexed fence.
			// Load applies the canonical predicate itself, so a mistake in the
			// check above is a mistake that still cannot reach a body.
			loaded, err := s.secrets.Load(ctx, who, f.ID)
			if err != nil {
				if errors.Is(err, store.ErrNoRows) {
					// The index and the file disagreed between the two reads
					// above. The lock is the direction that leaks nothing.
					view.Hidden = true
					view.Label = lockLabel(f.ID)
					out = append(out, view)
					continue
				}
				return nil, nil, err
			}
			body = loaded.Body
		}
		view.Body = body
		// The visibility this reader's answer came from, which for a fence whose
		// directive could not be read is the fail-safe default rather than the
		// token on disk. It is what the decision used, so it is what the view
		// model reports; nothing renders it, and a template that compared it
		// against a literal would be re-answering a rule authz owns.
		view.Visibility = string(f.Visibility)
		view.Revealed = f.IsOpen()
		out = append(out, view)
	}
	return out, unattributed, nil
}

// unattributedNote is the problem line for a fence the file has and the index
// does not.
//
// Its wording is the indexer's own (sync.ProblemAuthorUnknown), because the two
// describe one refusal and a page that said it differently from the log would be
// two descriptions of one fact. The id is in the line because the id is the fence
// the reader can see boxed on this page, and a line about a secret with nothing
// to point at is a line about which secret.
func unattributedNote(f secrets.Secret) string {
	what := "the fence names an author that is not a known account"
	if f.Author == "" {
		what = "the fence names no author"
	}
	return secrets.ProblemAuthorUnknown + ": " + what + " (" + f.ID + ")"
}

// lockLabel is the text shown in place of a secret this viewer may not read.
//
// It is secrets.LockPlaceholder's rule, and the reason it exists in that
// package is that this is the one value in the response that stands in for a
// body. The id is an opaque handle; the word "hidden" says everything the
// viewer is entitled to know. A length, an author or a title here would each be
// a disclosure, and all three together would be a description.
func lockLabel(id string) string { return secrets.LockPlaceholder(id) }

// readPage reads a vault file, refusing anything that does not resolve inside
// the vault. Resolve re-establishes containment, so a corrupted index row
// cannot name a file outside the vault root.
func (s *Server) readPage(ctx context.Context, rel string) ([]byte, error) {
	p, err := vault.Resolve(s.root, rel)
	if err != nil {
		return nil, err
	}
	return vault.Read(ctx, p)
}

// fail records an internal failure and answers 500.
//
// The error's own text never reaches the response. It is logged — reduced to a
// type, a hash and a length, because an error on this codebase can name a vault
// path and a short one can name more — and the body is the fixed 500 copy and
// nothing else.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, doing string, err error) {
	s.log.ErrorContext(r.Context(), "the request could not be completed",
		"action", "http.fail", "request_id", obs.RequestID(r.Context()),
		"route", RouteFrom(r.Context()), "doing", doing,
		"err", logRecord(err).String())
	s.writeError(w, r, http.StatusInternalServerError)
}

// cardOf converts a store row into the view model, dropping the two fields a
// template must never be able to reach: the raw frontmatter and the content
// hash.
func cardOf(p store.Page) PageCard {
	return PageCard{
		ID:        p.ID,
		Path:      p.Path,
		Title:     p.TitleOr(p.Basename),
		PageType:  p.PageType,
		UpdatedAt: p.UpdatedAt,
	}
}

// titleOr returns the title, or a fallback when it is empty.
func titleOr(title, fallback string) string {
	if title != "" {
		return title
	}
	return fallback
}

// pageCards converts a list of rows, for the dashboard.
func pageCards(pages []store.Page) []PageCard {
	out := make([]PageCard, 0, len(pages))
	for _, p := range pages {
		out = append(out, cardOf(p))
	}
	return out
}

// decorateWikilinks adds the link-preview attribute to every internal link the
// index resolved to a page.
//
// The rendered HTML is the output of a renderer that escapes by construction and
// never enables html.WithUnsafe, so the only `<a href="` in it is one the
// renderer wrote. Scanning for that exact prefix and rewriting that one
// attribute is therefore safe against vault content: a vault file cannot
// contribute the byte sequence, because goldmark escapes `<` in text and inside
// attribute values alike. The hostile-fixture test is what keeps that claim
// honest rather than assumed.
func (s *Server) decorateWikilinks(ctx context.Context, pageID int64, out []byte) []byte {
	ids, err := s.wikilinkIDs(ctx, pageID)
	if err != nil || len(ids) == 0 {
		return out
	}
	return insertWikilinkAttrs(out, ids)
}

// wikilinkIDs maps each resolvable internal href on a page to its page id.
//
// It reads the links table rather than re-resolving: the indexer already ran
// §5.6's resolution and stored the answer, and running it again here would be a
// second implementation of the tie-break rules that could disagree with the
// first. Only public links are mapped — a link written inside a secret the
// viewer may not read is a fact about a hidden secret, and its target path
// would be a disclosure.
func (s *Server) wikilinkIDs(ctx context.Context, pageID int64) (map[string]int64, error) {
	links, err := store.ListLinksByPage(ctx, s.db.Reader(), pageID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(links))
	// One lookup per distinct target, not per link row: a page that links the
	// same neighbour forty times costs one query, and a page whose links are
	// resolved row by row is a per-render query storm.
	paths := make(map[int64]string, len(links))
	for _, l := range links {
		if l.SecretID != "" || l.TargetPageID == nil {
			continue
		}
		switch l.Kind {
		case store.LinkWikilink, store.LinkMarkdown:
		default:
			continue
		}
		page, ok := paths[*l.TargetPageID]
		if !ok {
			// The page's own path is needed only for a link that names a file,
			// because that is addressed at the page's attachment route. The URL
			// itself is md's to build — see md.LinkHref, which exists because
			// this function used to rebuild the rule from the raw target and got
			// the fragment encoding and the attachment route wrong, so the
			// preview silently never appeared on a link with a heading or on a
			// link that named a file. A rule the code owns twice is a rule that
			// disagrees.
			row, err := store.GetPageByID(ctx, s.db.Reader(), *l.TargetPageID)
			if err != nil {
				continue
			}
			page = row.Path
			paths[*l.TargetPageID] = page
		}
		if href, ok := md.LinkHref(l.TargetRaw, page); ok {
			if key, ok := hrefKey(href); ok {
				out[key] = *l.TargetPageID
			}
		}
	}
	return out, nil
}

// hrefKey reduces a rendered href to the form the map is keyed by, so a link
// matches whatever the renderer chose to emit.
//
// The comparison is encoding-insensitive on purpose. The renderer escapes what
// it writes, so the rendered form of a heading link carries percent-encoding the
// link row does not, and requiring the two to agree byte for byte is requiring
// an encoder to be duplicated. Decoding with the standard library is not a second
// encoder: it is the inverse of whatever the renderer used, and two hrefs that
// decode alike name the same destination, which is the only question the
// attribute answers.
func hrefKey(href string) (string, bool) {
	base, fragment, hasFragment := strings.Cut(href, "#")
	if base == "" {
		return "", false
	}
	if u, err := url.PathUnescape(base); err == nil {
		base = u
	}
	if hasFragment {
		if u, err := url.PathUnescape(fragment); err == nil {
			fragment = u
		}
		base += "#" + fragment
	}
	return base, true
}

// anchorOpen is the exact byte sequence an internal link starts with.
const anchorOpen = `<a href="`

// insertWikilinkAttrs adds data-wikilink to every anchor whose href is in ids.
func insertWikilinkAttrs(out []byte, ids map[string]int64) []byte {
	// Spelled from the constant the plugin contract owns rather than as a literal
	// here. web/static/app.js looks for this attribute by name, and plugin.go
	// documents it as the one a component returns — so writing the bytes out in
	// this function was a third copy of the name, in a package that could not see
	// the two it had to agree with, and a rename would have left the shell's
	// hover quietly finding nothing.
	attr := []byte(` ` + plugin.WikiLinkAttr + `="`)
	buf := make([]byte, 0, len(out)+64)
	rest := out
	for {
		i := bytes.Index(rest, []byte(anchorOpen))
		if i < 0 {
			return append(buf, rest...)
		}
		buf = append(buf, rest[:i+len(anchorOpen)]...)
		rest = rest[i+len(anchorOpen):]
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			return append(buf, rest...)
		}
		buf = append(buf, rest[:j]...)
		// The href's own closing quote first, then the extra attributes: the
		// other order produces href="/p/Tavern data-wikilink="1" and a link
		// whose destination is the name of an attribute.
		buf = append(buf, '"')
		if key, ok := hrefKey(string(rest[:j])); ok {
			if id, found := ids[key]; found {
				buf = append(buf, attr...)
				buf = strconv.AppendInt(buf, id, 10)
				buf = append(buf, '"')
			}
		}
		rest = rest[j+1:]
	}
}
