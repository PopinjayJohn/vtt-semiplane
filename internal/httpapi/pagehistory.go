package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The history panel and one revision.
//
// Both are re-authorized at read time, and that is the property worth stating
// first because it is the reason a revision is a whole file in the database at
// all: revisions.content is the plaintext, so a revision recorded before a
// revoke is exactly the copy that must stop being readable when the revoke
// happens. secrets.Service.Revision therefore asks twice — once about the
// revision's own bytes and once about the fence as the file holds it now — and
// answers a revision it cannot serve with the same value it uses for a revision
// that never existed.

// historyPage answers GET /p/*/history.
func (s *Server) historyPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	row, ok := s.readablePage(w, r, ctx)
	if !ok {
		return
	}
	rows, err := s.secrets.History(ctx, who, row.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			s.writeError(w, r, http.StatusNotFound)
			return
		}
		s.fail(w, r, "read the revision list", err)
		return
	}
	// The badge's number, from the count over the same WHERE. It is a count of
	// rows, not of rows this principal may open: History keeps every row and
	// marks each one, because a row that is filtered out would make the list
	// shorter for a player than for a DM in a way neither can see the reason
	// for. Visible is carried on the row and is an approximation, documented on
	// secrets.RevisionView.
	total, err := store.CountRevisionsByPage(ctx, s.db.Reader(), row.ID)
	if err != nil {
		s.fail(w, r, "count the revisions", err)
		return
	}
	card := cardOf(row)
	page := card.Href()
	out := make([]RevisionRow, 0, len(rows))
	for _, rev := range rows {
		row := RevisionRow{
			ID:         rev.ID,
			At:         rev.At,
			Source:     rev.Source,
			Visible:    rev.Visible,
			Href:       page + "/revisions/" + strconv.FormatInt(rev.ID, 10),
			RevertHref: page + "/revert/" + strconv.FormatInt(rev.ID, 10),
		}
		if rev.Author != nil {
			row.Author = *rev.Author
		} else {
			row.External = true
		}
		out = append(out, row)
	}
	view := HistoryView{
		Shell:     s.liveShell(r, "History of "+card.Title),
		Card:      card,
		Revisions: out,
		Total:     total,
		Truncated: total > len(out),
		PageHref:  page,
	}
	s.noStore(w)
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the revision list", err)
	}
}

// revisionPage answers GET /p/*/revisions/{revID}.
func (s *Server) revisionPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	revID, ok := revIDParam(r, "revID")
	if !ok {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	row, ok := s.readablePage(w, r, ctx)
	if !ok {
		return
	}
	rev, err := s.secrets.Revision(ctx, who, row.ID, revID)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			s.writeError(w, r, http.StatusNotFound)
			return
		}
		if isDenial(err) {
			s.writeError(w, r, http.StatusForbidden)
			return
		}
		s.fail(w, r, "read the revision", err)
		return
	}
	card := cardOf(row)
	page := card.Href()
	view := RevisionView{
		Shell:       s.liveShell(r, "Revision of "+card.Title),
		Card:        card,
		ID:          rev.ID,
		At:          rev.At,
		Source:      rev.Source,
		Content:     rev.Content,
		PageHref:    page,
		HistoryHref: page + "/history",
	}
	if rev.Author != nil {
		view.Author = *rev.Author
	}
	s.fillRevisionDiff(ctx, who, row, &view)
	s.noStore(w)
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the revision", err)
	}
}

// fillRevisionDiff decides whether a comparison is offered, and computes it when
// it is.
//
// The condition is not "the revision is readable" — that is already settled, or
// this response would be a 404. It is "this principal may read every secret the
// page holds *now*". The reason is the current side of the diff: the only way to
// make a rendering of the current file safe to show is to redact it, and
// md.Redact's sentinel carries the hidden body's length and a digest of it, so a
// diff built over a redacted side discloses a secret's size to somebody who may
// not read it. For a principal who can read everything, the redaction is a
// no-op and the comparison is exact.
//
// internal/secrets' own Diff field is a change envelope computed over both
// sides redacted with the hidden set, and is deliberately not used here: for a
// principal this branch refuses it is exactly the field that would carry the
// sentinel. Its failure mode is the one this design is about.
func (s *Server) fillRevisionDiff(ctx context.Context, who authz.Principal, row store.Page, view *RevisionView) {
	current, err := s.secrets.EditView(ctx, who, row.ID)
	if err != nil {
		// A failure here leaves the revision readable and the comparison absent,
		// which is a smaller answer rather than a wrong one. It is logged with a
		// hash and a length and never with the bytes it failed on.
		s.log.ErrorContext(ctx, "the revision's comparison could not be prepared",
			"action", "http.revision", "route", RouteFrom(ctx), "path", row.Path,
			"err", logRecord(err).String())
		view.DiffOpaque = DiffOpaqueUnreadable
		return
	}
	if current.Mode.Redacted() {
		view.DiffOpaque = DiffOpaqueUnreadable
		return
	}
	if hunks := diffHunks(current.Content, []byte(view.Content)); hunks != nil {
		view.Hunks = hunks
		view.Comparable = true
		return
	}
	view.DiffOpaque = DiffOpaqueIdentical
}

// readablePage resolves the catch-all's path to a page a read surface is about.
//
// Every path-taking surface asks the two questions in the same order and answers
// them the same way, because the order is what makes a refusal byte-identical:
// the row first, so a path that names nothing is a 404, and the file's own
// nature second, so a row naming the application's state is a 404 with the same
// bytes.
func (s *Server) readablePage(w http.ResponseWriter, r *http.Request, ctx context.Context) (store.Page, bool) {
	path := selectedPath(r)
	if path == "" {
		s.writeError(w, r, http.StatusNotFound)
		return store.Page{}, false
	}
	row, err := s.lookupPage(ctx, path)
	if errors.Is(err, store.ErrNoRows) {
		s.writeError(w, r, http.StatusNotFound)
		return store.Page{}, false
	}
	if err != nil {
		s.fail(w, r, "load the page", err)
		return store.Page{}, false
	}
	if vault.Ignored(row.Path) {
		s.writeError(w, r, http.StatusNotFound)
		return store.Page{}, false
	}
	return row, true
}
