package httpapi

import (
	"net/http"
	"net/url"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// tagCards projects the store's tag list into the view model.
//
// It is the one projection of a TagCount, so /tags, /tag/{name} and the
// command palette cannot each decide for themselves what a tag row holds. The
// count comes from the store's own filtered query and is never recomputed here:
// a count derived in the view layer would be a second answer to a question the
// database has already answered under the canonical predicate.
func tagCards(tags []store.TagCount) []TagCard {
	out := make([]TagCard, 0, len(tags))
	for _, t := range tags {
		out = append(out, TagCard{Name: t.Name, Count: t.PageCount})
	}
	return out
}

// tagHref is the URL of one tag's page.
//
// It escapes the name as a *path segment* rather than with urlQueryEscape, and
// the difference is load-bearing: Obsidian tags nest, so "area/port" is one tag
// and it is a tag this app will hold. A slash left unescaped is the router's
// own separator, so /tag/area/port matches no route at all and the tag cloud
// and the palette would both be listing a link that 404s. Escaping the slash
// makes chi route on the escaped form and hand the handler one segment, which
// tagPage unescapes again.
func tagHref(name string) string {
	return "/tag/" + url.PathEscape(name)
}

// requestedTag is the tag name a /tag/{name} request is asking about.
//
// chi does not unescape a URL parameter for us. It routes on the decoded path
// when the escaped and decoded forms are the same, which is why an ordinary
// name arrives already decoded, and on RawPath when they differ — so a name
// that had to carry an escape arrives still escaped, and a nested tag arrives
// as "area%2Fport". Unescaping is therefore correct in both cases: for the
// first it is the identity, because a decoded value can never hold a bare
// percent (net/http rejects such a URL before it reaches a handler).
//
// The normalisation is md.NormalizeTag, the indexer's own function, because
// Obsidian tags are case-insensitive and a lookup that did not normalise would
// find only the spelling the first author happened to use.
func requestedTag(r *http.Request) string {
	raw := chi.URLParam(r, "name")
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	return md.NormalizeTag(raw)
}

// tagsPage is the tag cloud: every tag this viewer may see, with the number of
// pages they may see carrying it.
//
// A tag cloud is one query and an empty state. It is PermAnonRead because every
// name on it is a name the campaign's public pages already carry, and the
// counts come from the same filtered query that would answer "may this reader
// see that page" — a tag whose only occurrence is inside a secret the reader
// may not read is absent here entirely, not present at zero.
func (s *Server) tagsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tags, err := store.ListTags(ctx, s.db.Reader(), PrincipalFrom(ctx))
	if err != nil {
		s.fail(w, r, "list the tags", err)
		return
	}
	view := TagsView{
		Shell: s.liveShell(r, "Tags"),
		Tags:  tagCards(tags),
	}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the tag cloud", err)
	}
}

// tagPage is one tag and the pages this viewer may see carrying it.
//
// A tag that exists but that this viewer may not see any page of is *not* a
// 404, and neither is a tag that has never existed. Both answer the same
// thing: the page, with no rows and a count of zero. The distinction is
// deliberate and not a convenience — the campaign is public in v1, so a reader
// who cannot read every page of a tag is still entitled to be told the tag
// exists, and a page that refused to render would tell them less than an empty
// one does while giving an outsider a way to tell the two cases apart. The
// filtered query already produces that answer, so nothing here has to decide
// which of the two it is.
func (s *Server) tagPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	name := requestedTag(r)
	db := s.db.Reader()

	count, err := store.TagCountFor(ctx, db, who, name)
	if err != nil {
		s.fail(w, r, "count the pages of the tag", err)
		return
	}
	pages, err := store.ListTaggedPages(ctx, db, who, name)
	if err != nil {
		s.fail(w, r, "list the pages of the tag", err)
		return
	}
	all, err := store.ListTags(ctx, db, who)
	if err != nil {
		s.fail(w, r, "list the tags", err)
		return
	}

	view := TagView{
		Shell: s.liveShell(r, tagTitle(name)),
		Tag:   TagCard{Name: name, Count: count},
		Pages: pageCards(pages),
		All:   tagCards(all),
	}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the tag", err)
	}
}

// tagTitle names the tag page in the document title. A name is only echoed
// when there is one, so a request that normalises to nothing does not produce a
// dangling colon in the browser's title bar.
func tagTitle(name string) string {
	if name == "" {
		return "Tag"
	}
	return "Tag: " + name
}
