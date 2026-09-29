package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/diff"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The editor, the save and the revert.
//
// Two gates, and the reason both are here.
//
// The route table says PermWritePage, and permit asks the policy with a zero
// Resource — authz.Page(0, false) — which is the resource-free form of the
// permission. That form is "may this principal write a page at all", and its
// answer for a player is no. So the coarse gate refuses every principal but a DM
// or an admin, and the page-scoped decision — the one that carries this page's
// ownership — is made here, by mayWritePage, with the page's real ownership
// resolved from the index. The secrets service makes exactly the same check
// before it writes, so the second gate is not decorative: it is the one whose
// Resource is right, and it is what would catch a caller that reached the
// service without the table in front of it.
//
// It is worth saying plainly what that costs, because a DM or an admin is the
// only principal who can reach this route today, and internal/secrets is built
// so that a page *owner* can: Save asks the policy with authz.Page(pageID, owner)
// precisely so that "the author owns the note" is enough to edit their own
// note. The coarse gate in the table is what takes that away, and the change
// that would give it back is one row — PermSession, the gate that needs no
// resource, which is what internal/secrets itself checks first. The route as
// written fails closed, which is the right direction for a rule this
// consequential to get backwards.

// maxEditorBytes bounds a submitted editor buffer.
//
// It is a separate cap from readForm's 8 KiB because an editor POST carries a
// whole page of Markdown and an 8 KiB form is a page about forty lines long.
// It is vault.MaxFileBytes rather than a number chosen here, so the bound is
// the one the rest of the pipeline already uses: the indexer refuses to index a
// file larger than this, and vault.Read refuses to read one, so a submission
// above it could not be written and then read back anyway. It is still a hard
// cap — http.MaxBytesReader stops the read at the limit and ParseForm then
// reports the error, so an unbounded body is never allocated.
const maxEditorBytes = vault.MaxFileBytes

// diffContextLines is how many shared lines a hunk carries on each side. Three
// is the convention a unified diff prints and enough to recognise a line
// without printing the file.
const diffContextLines = 3

// mayWritePage is the page-scoped write gate: the policy asked with this page's
// ownership resolved rather than with a zero Resource.
//
// It is the check internal/secrets makes, and it is a function rather than an
// inline sequence so that the two handlers that need it and the test that
// proves it non-vacuous all ask the same question.
func (s *Server) mayWritePage(ctx context.Context, who authz.Principal, pageID int64) (bool, error) {
	owner := false
	if who.UserID != 0 {
		var err error
		if owner, err = store.IsPageOwner(ctx, s.db.Reader(), pageID, who.UserID); err != nil {
			return false, err
		}
	}
	return s.policy.Check(who, authz.PermWritePage, authz.Page(pageID, owner)) == nil, nil
}

// editForm answers GET /p/*/edit.
func (s *Server) editForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	row, ok := s.writablePage(w, r, ctx, who)
	if !ok {
		return
	}
	view, err := s.secrets.EditView(ctx, who, row.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			s.writeError(w, r, http.StatusNotFound)
			return
		}
		s.fail(w, r, "read the editor buffer", err)
		return
	}
	// Reached only when the table's gate and the policy agree, which they do for
	// every principal the table lets through; asked again so that the view model
	// carries the fact rather than the template assuming it.
	mayWrite, err := s.mayWritePage(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "resolve the page's write permission", err)
		return
	}
	s.noStore(w)
	if err := s.Render(w, r, s.editViewFor(r, row, view, mayWrite, false)); err != nil {
		s.fail(w, r, "render the editor", err)
	}
}

// editViewFor projects secrets.EditView into the view model, with the four URLs
// a template would otherwise have to build.
func (s *Server) editViewFor(r *http.Request, row store.Page, ev secrets.EditView, mayWrite, saved bool) EditView {
	path := cardOf(row)
	page := path.Href()
	return EditView{
		Shell:       s.liveShell(r, "Edit "+path.Title),
		Card:        path,
		Action:      page + "/edit",
		PageHref:    page,
		RawHref:     page + "/raw",
		HistoryHref: page + "/history",
		Content:     string(ev.Content),
		BaseHash:    hex.EncodeToString(ev.BaseHash),
		Mode:        editModeName(ev.Mode),
		HiddenIDs:   ev.HiddenIDs,
		HiddenCount: len(ev.HiddenIDs),
		Problems:    ev.Problems,
		Saved:       saved,
		MayWrite:    mayWrite,
	}
}

// editModeName is the mode as the view model spells it.
func editModeName(m secrets.EditMode) string {
	if m.Redacted() {
		return EditModeRedacted
	}
	return EditModeFull
}

// writablePage resolves the catch-all's path to the page a write surface is
// about, applying the two refusals that are the same answer.
//
// A path that names no page, and a path naming a page whose file is not
// campaign content, are both a 404 — the same bytes as a page that does not
// exist, so a probe cannot tell them apart.
func (s *Server) writablePage(w http.ResponseWriter, r *http.Request, ctx context.Context, who authz.Principal) (store.Page, bool) {
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
	mayWrite, err := s.mayWritePage(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "resolve the page's write permission", err)
		return store.Page{}, false
	}
	if !mayWrite {
		// 403 and not 404: the principal got here having been let past the
		// table's gate, so it already knows the page exists, and a 404 would be a
		// lie about a resource it has just read.
		s.writeError(w, r, http.StatusForbidden)
		return store.Page{}, false
	}
	return row, true
}

// editSubmit answers POST /p/*/edit.
func (s *Server) editSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	// The page and this principal's right to write it are settled before the
	// body is touched. A page's editor form is a whole file of Markdown, so
	// parsing it first would let anybody with a session make this process read
	// up to maxEditorBytes before being told no — an eight-megabyte write
	// amplifier for a principal who was never going to be allowed the write.
	row, ok := s.writablePage(w, r, ctx, who)
	if !ok {
		return
	}
	if err := readEditorForm(w, r); err != nil {
		// The body was refused, not the writer. A 413 is not in the fixed error
		// copy, so this is the 400 that is — and the reason is logged with a
		// length and no content, because a body that arrived is a body this
		// process has now read and must not describe.
		s.log.WarnContext(ctx, "an editor submission was too large or malformed",
			"action", "http.edit", "route", RouteFrom(ctx), "limit", maxEditorBytes)
		s.writeError(w, r, http.StatusBadRequest)
		return
	}
	content := []byte(r.PostFormValue("content"))
	base, ok := decodeBaseHash(r.PostFormValue("base_hash"))
	if !ok {
		// A base hash that is not one is a forged or a truncated form field, and
		// there is nothing to check the write against; the write is refused
		// rather than performed against a guess.
		s.writeError(w, r, http.StatusBadRequest)
		return
	}
	s.serveSave(w, r, who, row, content, base, "save")
}

// serveSave is the save both writes go through, so that a revert cannot acquire
// a weaker gate than an ordinary save by taking a different path.
//
// The 409 decision is here, and it is the one the plan asks for: the conflict
// page re-derives *both* versions through the authorized read path rather than
// showing neither. "Theirs" is secrets.EditView's Content for this principal
// now — the same redacted buffer the editor was handed, so a secret this
// principal may not read is a fixed label in it and never a body and never a
// length. "Mine" is the actor's own submission, echoed. The actor is the only
// reader of either, and a save that answered 409 by throwing the work away
// would be a save that loses a page's worth of typing to say "try again".
func (s *Server) serveSave(w http.ResponseWriter, r *http.Request, who authz.Principal, row store.Page, content, base []byte, reason string) {
	ctx := r.Context()
	err := s.secrets.Save(ctx, who, row.ID, content, base)
	switch {
	case err == nil:
		s.answerSaved(w, r, who, row, reason)
	case errors.Is(err, secrets.ErrRefusedSave):
		// The buffer will not be written and md.Problem never carries document
		// content, so the codes are safe to log — and a 4xx is the honest status,
		// because the file is not changed and the submission was the problem. 400
		// rather than 422 because 422 is not in the fixed error copy, and
		// writeError answers a status it has no entry for with a 500, which
		// would turn a refused buffer into a claim that the server broke.
		var refused *secrets.SaveRefusedError
		codes := make([]string, 0, 4)
		if errors.As(err, &refused) {
			for _, p := range refused.Problems {
				codes = append(codes, p.Code)
			}
		}
		s.log.WarnContext(ctx, "a page save was refused",
			"action", "http.save", "route", RouteFrom(ctx), "path", row.Path,
			"reason", reason, "problems", codes)
		s.writeError(w, r, http.StatusBadRequest)
	case errors.Is(err, vault.ErrConflict):
		s.answerConflict(w, r, who, row, string(content), reason)
	default:
		// Anything else is a policy denial or an internal failure, and the two
		// are told apart by whether the policy is the reason. A denial is a 403
		// and an internal failure is a 500, because a save that was refused by
		// the policy and a save that broke are different events and one of them
		// is the operator's problem.
		if isDenial(err) {
			s.log.WarnContext(ctx, "a page save was refused by the policy",
				"action", "http.save", "route", RouteFrom(ctx), "path", row.Path, "reason", reason)
			s.writeError(w, r, http.StatusForbidden)
			return
		}
		s.fail(w, r, "save the page", err)
	}
}

// isDenial reports whether a service error is a policy refusal rather than a
// failure. authz.ErrDenied and authz.ErrNotAuthenticated are the two the policy
// returns, and both are refusals of the request rather than faults in it.
func isDenial(err error) bool {
	return errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrNotAuthenticated)
}

// answerSaved re-renders the editor with a fresh base hash and the saved flag.
//
// It is a 200 and not a 303, because the form posts into the region the editor
// occupies and a redirect would land the reader on the page they were editing
// rather than back in the editor with a hash to submit against. The bytes are
// the editor's own for this principal, so the answer is the buffer they had,
// with the sentinels recomputed from the file that was just written.
func (s *Server) answerSaved(w http.ResponseWriter, r *http.Request, who authz.Principal, row store.Page, reason string) {
	ctx := r.Context()
	view, err := s.secrets.EditView(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "re-read the editor buffer after the save", err)
		return
	}
	mayWrite, err := s.mayWritePage(ctx, who, row.ID)
	if err != nil {
		s.fail(w, r, "resolve the page's write permission", err)
		return
	}
	s.log.InfoContext(ctx, "a page was written",
		"action", "http.save", "route", RouteFrom(ctx), "path", row.Path, "why", reason)
	s.noStore(w)
	if err := s.Render(w, r, s.editViewFor(r, row, view, mayWrite, true)); err != nil {
		s.fail(w, r, "render the editor after the save", err)
	}
}

// answerConflict renders the 409 both versions, re-derived.
//
// Both sides come from a call that is itself authorized: the on-disk side is
// re-derived through the canonical predicate, and the submitted side is the
// actor's own. If that derivation cannot be done the answer is the page's own
// 404 when the file has gone and a 500 when anything else failed — not a 409
// carrying a body that does not say what the status promised. errorCopy does
// carry a 409 now, so a template that could not be filled in *has* a shape
// available; it is still the wrong one, because it would say "this changed,
// reload and try again" to a reader whose work has not been shown to them, and
// the honest answer to a derivation this package failed to produce is that the
// server broke.
func (s *Server) answerConflict(w http.ResponseWriter, r *http.Request, who authz.Principal, row store.Page, mine, reason string) {
	ctx := r.Context()
	conflict, err := s.conflictFor(ctx, who, row, mine, reason)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) || errors.Is(err, store.ErrNoRows) {
			// The page the conflict was on is gone between the write failing and
			// this. A 404 is the same answer the page route gives for a row with
			// no file, and it is the same document.
			s.writeError(w, r, http.StatusNotFound)
			return
		}
		s.fail(w, r, "re-read the page to describe the conflict", err)
		return
	}
	view := ConflictView{
		Shell:    s.liveShell(r, conflictTitle(reason)),
		Card:     cardOf(row),
		Conflict: conflict,
	}
	// Not cached, and no-store rather than the private, max-age=0 the other
	// authorization-dependent reads use: a 409 is the one response a client will
	// want to keep out of every cache it can reach.
	s.noStore(w)
	w.WriteHeader(http.StatusConflict)
	if err := s.Render(w, r, view); err != nil {
		s.log.ErrorContext(ctx, "the conflict page could not be rendered",
			"action", "http.conflict", "route", RouteFrom(ctx), "path", row.Path)
	}
}

// conflictTitle is the heading for a lost race, and it is a function rather than
// a format string because Reason is a closed set of two and a template should
// not be assembling sentences.
func conflictTitle(reason string) string {
	if reason == "revert" {
		return "This page changed while you were reverting it"
	}
	return "This page changed while you were editing it"
}

// conflictFor derives the two sides of a lost race, both authorized, and nothing
// else — no shell, no writer.
//
// It is split from answerConflict so that the property worth testing can be
// reached at all. The redaction of the on-disk side is only ever non-trivial for
// a principal with a non-empty hidden set, and through HTTP the only principals
// who reach this page are a DM and an admin, whose hidden set is empty by
// definition. So the redaction is asserted in the in-package test
// TestTheConflictPageRedactsTheOnDiskSideForAnActorWhoCannotReadIt, against a
// real service and a real page, with a player who may read neither fence.
//
// The on-disk side is the same rendering the raw view gives: the file with every
// fence this principal may not read replaced by the fixed lock label. It is NOT
// secrets.EditView's Content, and the reason is worth recording because getting
// it wrong is a disclosure rather than a wrong picture:
//
// EditView is the *editor's* buffer, and md.Redact stands a hidden body in with
// a restore sentinel so that a save can put the body back. A sentinel carries
// the body's length and four bytes of its digest. That is a restore token, and it
// is exactly what §8.8 forbids in a response that is only being looked at: two
// principals reading the same conflict page would see different-sized documents
// for a secret neither may read, and a secret's size is a thing about the secret
// that its reader is not entitled to. So this route re-derives the same decision
// through the same rule — secrets.Parse and authz.CanReadSecret, with the page's
// ownership from store.IsPageOwner — and applies the fixed label instead. One
// redaction implementation in this package, used by the raw view and the
// conflict page alike, so the two cannot disagree about what a reader may see.
//
// Mine is the actor's own submission, echoed: the only way a body is in it is
// that the actor typed it, and a save that does not echo it throws away the work
// it refused.
func (s *Server) conflictFor(ctx context.Context, who authz.Principal, row store.Page, mine, reason string) (Conflict, error) {
	onDisk, err := s.readPage(ctx, row.Path)
	if err != nil {
		return Conflict{}, err
	}
	owner := false
	if who.UserID != 0 {
		if owner, err = store.IsPageOwner(ctx, s.db.Reader(), row.ID, who.UserID); err != nil {
			return Conflict{}, err
		}
	}
	doc := md.Parse(row.Path, onDisk)
	hidden, err := s.hiddenFences(ctx, who, owner, doc)
	if err != nil {
		return Conflict{}, err
	}
	theirs := lockFences(doc, hidden)
	return Conflict{
		Theirs:   string(theirs),
		Mine:     mine,
		Hunks:    diffHunks(theirs, []byte(mine)),
		BaseHash: hex.EncodeToString(vault.Hash(onDisk)),
		Reason:   reason,
	}, nil
}

// revertPage answers POST /p/*/revert/{revID}.
//
// The revision is read under the same read-time authorization every other read
// of it uses and the bytes are then handed to the ordinary save path with the
// actor attached, so a revert re-runs every write authorization there is. That
// is §8.10's "revert is authz'd as an edit, not as a read" and it is why this
// handler has no write logic of its own beyond picking the revision.
//
// A successful revert answers 303 to the page. It is a redirect rather than a
// re-rendered editor because the reader asked to put a page back, and the page
// is what they want to see; the bytes that came back are the page's, and a
// redirect cannot carry a body at all, so a 409's worth of content can never be
// attached to one by accident.
func (s *Server) revertPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)
	revID, ok := revIDParam(r, "revID")
	if !ok {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	row, ok := s.writablePage(w, r, ctx, who)
	if !ok {
		return
	}
	err := s.secrets.Revise(ctx, who, row.ID, revID)
	switch {
	case err == nil:
		s.log.InfoContext(ctx, "a page was reverted",
			"action", "http.revert", "route", RouteFrom(ctx), "path", row.Path, "revision", revID)
		http.Redirect(w, r, cardOf(row).Href(), http.StatusSeeOther)
	case errors.Is(err, store.ErrNoRows):
		// A revision that does not exist, one that belongs to another page, and
		// one holding a body this principal may not read are the same value from
		// one constructor inside internal/secrets, so there is nothing here to
		// tell them apart.
		s.writeError(w, r, http.StatusNotFound)
	case errors.Is(err, vault.ErrConflict):
		// A revert answers the same 409 as a save, through the same derivation, so
		// the two cannot drift apart on what a conflict page is allowed to show.
		// Revise has already read the revision under the actor, so the revision's
		// content is the actor's own to echo, and EditView is the authorized
		// current side.
		rev, rerr := s.secrets.Revision(ctx, who, row.ID, revID)
		if rerr != nil {
			s.fail(w, r, "re-read the revision to describe the conflict", rerr)
			return
		}
		s.answerConflict(w, r, who, row, rev.Content, "revert")
	case errors.Is(err, secrets.ErrRefusedSave):
		s.log.WarnContext(ctx, "a revert was refused",
			"action", "http.revert", "route", RouteFrom(ctx), "path", row.Path, "revision", revID)
		s.writeError(w, r, http.StatusBadRequest)
	case isDenial(err):
		s.log.WarnContext(ctx, "a revert was refused by the policy",
			"action", "http.revert", "route", RouteFrom(ctx), "path", row.Path, "revision", revID)
		s.writeError(w, r, http.StatusForbidden)
	default:
		s.fail(w, r, "revert the page", err)
	}
}

// diffHunks renders internal/diff's change script as view rows.
//
// The two inputs are the two AUTHORIZED renderings and nothing else. That is
// the only reason this is safe to put on a 409, and it is why the caller never
// hands it a raw file: a diff over raw bytes prints a secret body in the middle
// of a page the actor is not entitled to, and the diff is where that leak would
// be hardest to notice.
func diffHunks(theirs, mine []byte) []DiffHunk {
	a := diff.Split(theirs)
	b := diff.Split(mine)
	edits := diff.Lines(theirs, mine)
	if len(edits) == 0 {
		return nil
	}
	raw := diff.Hunks(a, b, edits, diffContextLines)
	out := make([]DiffHunk, 0, len(raw))
	for _, h := range raw {
		row := DiffHunk{FromA: h.FromA, CountA: h.CountA, FromB: h.FromB, CountB: h.CountB}
		for _, e := range h.Edits {
			// An equal or a deleted line numbers into the left side; an
			// inserted one into the right. diff.Edit's Line already says which,
			// and a line number past the end yields an empty line rather than a
			// slice out of range — which a malformed script can produce, and
			// which must not be able to take the process down from a 409.
			lines := a
			if e.Op == diff.OpInsert {
				lines = b
			}
			text := ""
			if e.Line >= 1 && e.Line <= len(lines) {
				text = string(lines[e.Line-1].Text)
			}
			row.Lines = append(row.Lines, DiffLine{Op: e.Op.String(), No: e.Line, Text: text})
		}
		out = append(out, row)
	}
	return out
}

// decodeBaseHash reads the form's base_hash field.
//
// Anything that is not exactly 32 bytes of hex is refused, and a truncated or
// uppercased form is refused with the same answer rather than being normalised:
// a hash is compared for equality, and a caller that sends a different spelling
// of the right value is a caller whose editor is not the one this server built.
func decodeBaseHash(raw string) ([]byte, bool) {
	if len(raw) != 64 {
		return nil, false
	}
	out, err := hex.DecodeString(raw)
	if err != nil || len(out) != 32 {
		return nil, false
	}
	return out, true
}

// readEditorForm is readForm under the editor's own cap.
func readEditorForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxEditorBytes)
	return r.ParseForm()
}

// noStore marks a response as one that must never be stored anywhere.
//
// Every response this package produces depends on the principal, and §2.8 puts
// a shared cache between two principals at the top of the list of things that
// are not built. The page view and the error page set it themselves; the
// surfaces added here set it here so that a new one cannot forget.
func (s *Server) noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, max-age=0, no-store")
}
