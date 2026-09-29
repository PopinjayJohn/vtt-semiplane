package httpapi

import (
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

// The raw Markdown view: the file, with every fence this reader may not read
// replaced by a fixed label.
//
// It is a text/plain response and not a view, and the reason is that the
// alternatives are both worse. A template would escape the Markdown into
// something a reader cannot copy back into an editor, and marking it raw is
// forbidden by AGENTS.md §2.6 and would make every vault file a stored-XSS
// vector. So the bytes are written as bytes, with a content type that says they
// are text and nosniff that says do not guess.

// rawPage answers GET /p/*/raw.
//
// The redaction is decided against the FILE, not against the index, and that is
// the whole security property of this route. An index-derived hidden set misses
// a fence the indexer has not got to, or one whose author was not an account
// when its page was indexed, and a raw view that passes such a fence through is
// a DM's plaintext served to a player at a guessable URL. The file is canonical;
// so is the decision.
func (s *Server) rawPage(w http.ResponseWriter, r *http.Request) {
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
	// Every surface that takes a path from a request asks this before touching
	// the vault. Resolve establishes containment; this establishes that the
	// thing inside the vault is campaign content.
	if vault.Ignored(row.Path) {
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	src, err := s.readPage(ctx, row.Path)
	if err != nil {
		s.log.WarnContext(ctx, "a page in the index could not be read from the vault",
			"action", "http.raw", "request_id", obs.RequestID(ctx),
			"path", row.Path, "reason", err.Error())
		s.writeError(w, r, http.StatusNotFound)
		return
	}

	owner, err := store.IsPageOwner(ctx, s.db.Reader(), row.ID, who.UserID)
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

	// Authorization-dependent, so never cached: a shared cache between two
	// principals is exactly where this response and a fuller one would be
	// confused, and the whole point of the route is that the two differ.
	w.Header().Set("Cache-Control", "private, max-age=0, no-store")
	w.Header().Set("Content-Type", rawContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// hiddenFences returns the fences in doc that who may not read, in file order.
//
// It is secrets.hiddenIn re-derived over the file rather than the index, and
// that duplication is the point: the index is derived and disposable, so an
// index-derived answer to "which of these bodies may this reader not see"
// answers about the index. The rule itself is one line — authz.CanReadSecret,
// through secrets.Secret.CanRead, with a fence whose directive could not be
// read defaulting to private in secrets.Parse and so being hidden from everyone
// but a DM — and an unparseable fence is the fail-closed case AGENTS.md §6 is
// about.
func (s *Server) hiddenFences(ctx context.Context, who authz.Principal, owner bool, doc *md.Doc) ([]secrets.Secret, error) {
	all, _ := secrets.Parse(doc)
	out := make([]secrets.Secret, 0, len(all))
	for _, f := range all {
		id, err := s.authorID(ctx, f.Author)
		if err != nil {
			return nil, err
		}
		f.AuthorID = id
		if !f.CanRead(who, owner) {
			out = append(out, f)
		}
	}
	// File order, so the replacements are produced in increasing offset order
	// and the back-to-front application is one pass over a sorted list. A
	// two-line insertion sort rather than sort.Slice: the list is the number of
	// secrets on one page, which is a handful, and the closure would be more
	// code than the sort.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].StartByte < out[j-1].StartByte; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// authorID resolves a fence's author= username to the account it names.
//
// A username with no account is 0, and 0 is nobody: authz.CanReadSecret matches
// an author against the principal's own user id, and no authenticated principal
// has 0, so a fence naming an account that does not exist is readable by DMs
// and by page owners and by nobody else. That is the same rule the indexer and
// internal/secrets apply, and it is stated here because it is the one place a
// reader of this file would otherwise have to go looking for.
func (s *Server) authorID(ctx context.Context, username string) (int64, error) {
	if username == "" {
		return 0, nil
	}
	u, err := store.GetUserByUsername(ctx, s.db.Reader(), username)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, err
	}
	return u.ID, nil
}

// lockFences returns the document's bytes with every hidden fence replaced by
// the fixed lock label.
//
// The *whole* fence goes, opening line and closing line both, not just the body.
// The directive line carries the author, the title and the creation time, and
// each of those is a fact about a secret this reader was refused; a raw view
// that kept the fence line would disclose all three. What replaces it is
// secrets.LockPlaceholder — an id, the word "hidden", and a fixed length — so
// two responses differing only in what is behind the locks are the same size,
// which is §8.8's rule and the reason a length is not in the label.
//
// md.Redact is deliberately not used. Its sentinel is a restore token for the
// editor and carries the hidden body's length and a digest of it, which is
// exactly the disclosure this route exists not to make; the editor needs it
// because a save has to put the body back, and nothing else does.
func lockFences(doc *md.Doc, hidden []secrets.Secret) []byte {
	if doc == nil || len(hidden) == 0 {
		return doc.Bytes
	}
	type edit struct {
		start, end int
		with       []byte
	}
	edits := make([]edit, 0, len(hidden))
	for _, f := range hidden {
		if f.StartByte < 0 || f.EndByte > len(doc.Bytes) || f.EndByte < f.StartByte {
			continue
		}
		// A label on its own line, so the rendering still has one line per
		// secret and the line numbers a reader counts still line up.
		with := append([]byte("\n"), secrets.LockPlaceholder(f.ID)...)
		edits = append(edits, edit{start: f.StartByte, end: f.EndByte, with: with})
	}
	// Back to front, so the offsets of the edits not yet applied stay valid.
	// The same discipline md.Redact and secrets' visibility rewrite use, and for
	// the same reason.
	out := doc.Bytes
	for i := len(edits) - 1; i >= 0; i-- {
		out = append(append(append([]byte{}, out[:edits[i].start]...), edits[i].with...), out[edits[i].end:]...)
	}
	return out
}

// rawContentType is what a raw response declares. It is a constant so that the
// tripwire and the handler cannot disagree about it.
const rawContentType = "text/plain; charset=utf-8"

// revIDParam reads a revision id from the dispatch's parameters.
//
// A value that is not a positive integer is a revision that does not exist, and
// it is answered as one rather than as a bad request: a 400 would confirm that
// the address is one this route understands, which is a fact about the router
// that an outsider has no business having, and the same answer the context API
// gives for a page id that is not a number.
func revIDParam(r *http.Request, name string) (int64, bool) {
	raw := selectedParam(r, name)
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
