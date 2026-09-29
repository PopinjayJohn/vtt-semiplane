package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
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
// same rule the predicate implements — with the body then read through
// secrets.Service.Load, which applies the predicate again. Two independent
// gates, neither of them a re-statement of the other's logic.
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
	pageSecrets, err := s.pageSecrets(ctx, who, row)
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
// The list is deliberately unfiltered: a fence is a visible box in the page's
// layout, and hiding the box would tell the reader something was there while
// showing nothing. What differs is the *content* of the box, and it differs down
// to nothing at all: a hidden secret contributes its id — an opaque handle, and
// not a credential — and not one more byte of metadata. That is why the response
// for a page carrying a 40 KiB hidden secret differs from the response for one
// carrying an empty fence by the length of "⟨secret:… hidden⟩" and not by 40 KiB.
func (s *Server) pageSecrets(ctx context.Context, who authz.Principal, row store.Page) ([]SecretView, error) {
	rows, err := store.ListSecretRowsByPage(ctx, s.db.Reader(), row.ID)
	if err != nil {
		return nil, err
	}
	owner, err := s.pageOwned(ctx, who, row.ID)
	if err != nil {
		return nil, err
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
	out := make([]SecretView, 0, len(rows))
	for _, sec := range rows {
		hidden := SecretView{ID: sec.ID, Ordinal: sec.Ordinal, Hidden: true, Label: lockLabel(sec.ID)}
		// Both actions are on the hidden shape too, and that is deliberate: a DM
		// reads every secret on the page, so for that principal no fence is hidden
		// and the branch below is the only one that runs — but a principal who may
		// neither see nor broadcast must not find a page where the control's
		// presence depended on which branch produced the row.
		if mayChange {
			hidden.RevealAction = base + "/secrets/" + sec.ID + "/reveal"
			hidden.RevokeAction = base + "/secrets/" + sec.ID + "/revoke"
		}
		if !authz.CanReadSecret(who, owner, sec.AuthorID, authz.Visibility(sec.Visibility)) {
			out = append(out, hidden)
			continue
		}
		// The only body-bearing read in the codebase. Load applies the canonical
		// predicate itself, so a mistake in the check above is a mistake that
		// still cannot reach a body.
		loaded, err := s.secrets.Load(ctx, who, sec.ID)
		if errors.Is(err, store.ErrNoRows) {
			out = append(out, hidden)
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, SecretView{
			ID:           loaded.ID,
			Ordinal:      loaded.Ordinal,
			Body:         loaded.Body,
			Visibility:   string(loaded.Visibility),
			Revealed:     loaded.IsOpen(),
			RevealAction: hidden.RevealAction,
			RevokeAction: hidden.RevokeAction,
		})
	}
	return out, nil
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
	for _, l := range links {
		if l.SecretID != "" || l.TargetPageID == nil {
			continue
		}
		if href, ok := internalHref(l.TargetRaw, l.Kind); ok {
			out[href] = *l.TargetPageID
		}
	}
	return out, nil
}

// internalHref is the URL the renderer will have produced for a link row.
//
// It mirrors md.VaultResolver: a target with no extension is a page and gains
// the /p/ prefix, a target with one is a file and does not, and the fragment
// the author wrote is appended. A target that is not a page reference is
// skipped, because the renderer did not turn it into an <a href> and an
// attribute on nothing is worse than no attribute.
func internalHref(target string, kind store.LinkKind) (string, bool) {
	switch kind {
	case store.LinkWikilink, store.LinkMarkdown:
	default:
		return "", false
	}
	target = strings.TrimSpace(target)
	page, fragment, _ := strings.Cut(target, "#")
	if page == "" {
		// A [[#heading]] points into the page it is written on, so it has no
		// other page's id to carry.
		return "", false
	}
	for _, scheme := range []string{"://", "mailto:", "tel:", "data:"} {
		if strings.Contains(page, scheme) {
			return "", false
		}
	}
	if !strings.Contains(lastSegment(page), ".") {
		page = "/p/" + page
	}
	if fragment != "" {
		page += "#" + fragment
	}
	return page, true
}

// lastSegment is the last path segment of a target, which is where md looks for
// the extension that tells a page from a file.
func lastSegment(target string) string {
	if i := strings.LastIndex(target, "/"); i >= 0 {
		return target[i+1:]
	}
	return target
}

// anchorOpen is the exact byte sequence an internal link starts with.
const anchorOpen = `<a href="`

// insertWikilinkAttrs adds data-wikilink to every anchor whose href is in ids.
func insertWikilinkAttrs(out []byte, ids map[string]int64) []byte {
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
		if id, ok := ids[string(rest[:j])]; ok {
			buf = append(buf, ` data-wikilink="`...)
			buf = strconv.AppendInt(buf, id, 10)
			buf = append(buf, '"')
		}
		rest = rest[j+1:]
	}
}
