package httpapi

import (
	"context"
	"net/http"
	"path"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The page export, §8.3's serve path in a form a reader can keep.
//
// **There is no whole-vault export, and there is not going to be one in v1.** The
// reason is not a missing feature; it is that the vault-wide form has no
// authorization question to ask and would therefore be a copy of the plaintext on
// disk. A page has no visibility of its own — `pages` has no visibility column,
// `authz.PermReadPage` is resource-free, and AGENTS.md §7 says so — so "export the
// campaign" has no per-page decision behind it. Every fence would ride out
// together or not at all, and the honest answer to "which of these may this
// reader have" over a whole directory is *all of them*, which is the plaintext
// ADR-0004 already accepts is on the disk. An export that handed a principal a
// zip of the campaign would be a way around redaction that required no bug at all
// to work: the reader would run it on their own machine.
//
// So the unit is a page, and each page is redacted by the rule the page view and
// the raw view already use. The export is a second *spelling* of the raw view and
// must never become a second *implementation* of its redaction — see exportPage.

// exportContentType is what an export declares. It is a constant so that the
// tripwire and the handler cannot disagree about it, for the reason rawContentType
// is one.
const exportContentType = "text/markdown; charset=utf-8"

// exportPage answers GET /p/*/export.
//
// The redaction is the raw view's, function for function: the file is parsed,
// s.hiddenFences decides which fences this reader may not read over that *file*
// rather than over the index, and lockFences replaces each one whole with the
// fixed lock label. Those two functions are shared with pageraw.go and with the
// conflict page on purpose. A second implementation here would be a second chance
// to be wrong about the rule, and the rule is the whole of this design's safety:
// there is one predicate, authz.CanReadSecret, and a place that re-states it is a
// place that can drift from it.
//
// A page this reader may not read is a 404 — the same value, from the same
// constructor, as a page that does not exist, so a probe cannot tell them apart.
func (s *Server) exportPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	// readablePage rather than the raw view's own open-coded sequence, and the
	// reason is not tidiness: readablePage asks exactly the three questions
	// pageraw.go asks — is the path named, is there a row, is it campaign content
	// rather than the app's own state — in the same order, and answers all three
	// with the same s.writeError. Sharing it is what makes the two refusals
	// identical rather than merely similar. It is also AGENTS.md §2.9's
	// requirement, satisfied by the same call: vault.Ignored is asked before the
	// file is touched, so a request naming .semiplane/semiplane.lock is refused
	// without the vault being read at all.
	row, ok := s.readablePage(w, r, ctx)
	if !ok {
		return
	}

	// The file is canonical, so the export is made from the file. A row in the
	// index whose file has gone is a 404 for the same reason it is for the page
	// view and the raw view: the row is derived and disposable, and an export of
	// nothing is not a smaller answer, it is a different one.
	src, err := s.readPage(ctx, row.Path)
	if err != nil {
		s.log.WarnContext(ctx, "a page in the index could not be read from the vault",
			"action", "http.export", "request_id", obs.RequestID(ctx),
			"path", row.Path, "reason", err.Error())
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	owner, err := s.pageOwned(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "resolve the page's ownership", err)
		return
	}
	doc := md.Parse(row.Path, src)
	hidden, err := s.hiddenFences(ctx, who, owner, doc)
	if err != nil {
		s.fail(w, r, "decide which secrets are hidden", err)
		return
	}
	out := lockFences(doc, hidden)

	// Every header here is the raw view's, and each is load-bearing rather than
	// polite. no-store because the bytes are authorization-dependent and a
	// shared cache holding this for one principal is exactly where a full export
	// and a redacted one would be confused — a leak with an expiry date on it.
	// nosniff so the browser cannot be talked into reading a page's Markdown as
	// HTML. Vary: Cookie because the same URL answers differently per session.
	s.noStore(w)
	w.Header().Set("Content-Type", exportContentType)
	w.Header().Set("Content-Disposition", exportDisposition(exportFilename(row.Path)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Vary", "Cookie")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// pageOwned is store.IsPageOwner with an anonymous principal answered first.
//
// A user id of 0 is nobody: authz.CanReadSecret matches an author against the
// principal's own id and no authenticated principal has 0, so asking the store
// about account 0 is a query whose answer can only be false. Skipping it saves
// the query and makes "anonymous owns nothing" a fact of this package rather than
// a property of the users table.
func (s *Server) pageOwned(ctx context.Context, who authz.Principal, pageID int64) (bool, error) {
	if who.UserID == 0 {
		return false, nil
	}
	return store.IsPageOwner(ctx, s.db.Reader(), pageID, who.UserID)
}

// exportDisposition is the Content-Disposition an export carries.
//
// attachment rather than inline, so that a reader who clicks "export" gets a file
// and not a second copy of the page rendered in a window the app does not control
// — the rendered page is what the app redacts per request, and a downloaded file
// is one that outlives the session that fetched it.
func exportDisposition(name string) string {
	return `attachment; filename="` + headerFilename(name) + `"`
}

// exportFilename is the name the downloaded file gets: the page's own base name,
// extension and all.
//
// md.Basename is the wrong one and it is worth saying why it is tempting: it is
// the function the rename form uses, and it deliberately drops the extension,
// because a page's canonical name is its path without one. An export is the other
// kind of thing — it is a *file*, and a file whose name does not end in .md opens
// in the wrong application on half the systems a vault is likely to be on. So the
// name is taken here rather than reused, from the page's own path, which is
// canonical and already free of anything a user can type into a header.
func exportFilename(pagePath string) string {
	name := path.Base(pagePath)
	if name == "." || name == "/" {
		return "page.md"
	}
	return name
}

// headerFilename reduces a file name to the characters a quoted-string filename
// may carry.
//
// The page's own name is an author's file name and is therefore whatever they
// typed, so it cannot be pasted into a response header unexamined. Three classes
// are removed: control characters, because a header is a line and a newline in a
// filename is how a response is split; the quote and the backslash, because they
// end the quoted string the name is written into; and everything outside ASCII,
// because RFC 6266's plain `filename=` form is a Latin-1 token and a browser that
// cannot read the name still saves the bytes correctly under a name it chooses.
//
// The last of those is a real loss for a page called Café.md, and it is the
// direction that loses nothing that matters: the *bytes* are unaffected, and a
// reader who wants the exact name has the file tree.
func headerFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
		case r == '"' || r == '\\':
			b.WriteByte('_')
		case r > 0x7e:
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "page.md"
	}
	return b.String()
}
