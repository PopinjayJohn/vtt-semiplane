package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// historyLimit is how many revisions a history panel is given.
//
// It is store.AppRevisionRetention because that is how many app-made revisions a
// page can hold; asking for more would return fewer than asked for without
// saying so, and a panel that silently truncates at a number nobody wrote down
// is a panel nobody can reason about. store.CountRevisionsByPage is the count to
// render beside the list, and it uses the identical predicate.
const historyLimit = store.AppRevisionRetention

// HunkSummary is one run of changed lines, with the four numbers a unified diff
// header carries.
//
// It is a summary and not a diff. internal/diff owns the general line diff and
// sits ABOVE this package in the dependency order, so it cannot be imported from
// here and writing a second one would be exactly the kind of second
// implementation this codebase refuses elsewhere. What is computed instead is the
// change envelope — the common prefix and the common suffix removed — which is
// linear in the size of the two sides and is never wrong, only coarse: it can
// claim a larger region changed than a real diff would, and it can never claim a
// region did not change. A handler that renders line-level diffs owns that
// rendering and can call internal/diff itself, because it is above both.
type HunkSummary struct {
	// FromA is the 1-based first line of the run on the revision side.
	FromA int
	// CountA is how many of the revision's lines the run covers. Zero for a pure
	// insertion.
	CountA int
	// FromB is the 1-based first line of the run on the current side.
	FromB int
	// CountB is how many of the current page's lines the run covers. Zero for a
	// pure deletion.
	CountB int
}

// RevisionView is one revision, as one principal may see it.
//
// Content is populated only when every secret in the revision's own bytes is
// readable by the principal asking. It is not redacted when it is populated: a
// revision holding one body the reader may not see is not served with a
// placeholder, it is not served at all, and answered exactly as a revision that
// never existed is. Redacting instead would make the refusal observable — the
// row would be present, the body would not, and the length of what was withheld
// is a disclosure.
type RevisionView struct {
	// ID is the surrogate key, and what a single-revision read takes.
	ID int64
	// At is when the revision was recorded.
	At time.Time
	// Source is one of the four store.RevisionSource values.
	Source string
	// Author is the account responsible, or nil for an external change.
	Author *string
	// Visible is this package's cheap answer to "can this principal open it?",
	// and it is deliberately not the same question Revision answers. See History.
	Visible bool
	// Content is the file as it was, and is empty for every row History returns.
	Content string
	// Diff is the change envelope against the page as it is now, over the two
	// AUTHORIZED renderings of each. Empty when the principal may not open the
	// revision, and when the two renderings are identical.
	Diff []HunkSummary
}

// Revision returns one revision of a page, re-segmented and re-authorized
// against its own bytes and against the fence as the file holds it now.
//
// Both are asked and both must agree, because each one alone gets a case wrong.
// The revision's own bytes say which fences the document contains and what each
// one claims; the file says what may be served now. Authorizing only the
// revision treats the directive as a historical fact and a revoke becomes a
// change of nothing but the present — and revisions.content is the whole file, so
// that copy is exactly the plaintext that outlives the token changing under it.
// Authorizing only the file makes the present the authority over a document that
// is no longer on disk, and answers for a fence the file has dropped, which is the
// one fence whose removal the revision is the last record of.
//
// A revision holding a body the actor may not read is answered with the same
// not-found error as a revision that never existed, built by the same
// constructor: the same value, not merely the same shape, so there is nothing in
// the answer, in its length, or in the absence of a diff to compare.
func (s *Service) Revision(ctx context.Context, actor authz.Principal, pageID, revisionID int64) (RevisionView, error) {
	// readPage is resource-free in v1, so this gate needs no lookup and a
	// principal refused here never learns whether the page or the revision exists.
	if err := s.policy.Check(actor, authz.PermReadPage, authz.Resource{}); err != nil {
		return RevisionView{}, err
	}
	page, _, doc, err := s.readPage(ctx, pageID)
	if err != nil {
		// A page that does not exist has no revisions, and the answer is this
		// package's one not-found answer rather than the store's, so that a caller
		// comparing two refusals is comparing two values this package built. A page
		// that IS the app's own state is a different error and stays one: the path
		// is a configuration fact, not a fact about the asker's rights.
		if errors.Is(err, store.ErrNoRows) {
			return RevisionView{}, notFoundRevision(revisionID)
		}
		return RevisionView{}, err
	}
	owner, err := store.IsPageOwner(ctx, s.db.Reader(), pageID, actor.UserID)
	if err != nil {
		return RevisionView{}, err
	}
	rev, err := store.GetRevision(ctx, s.db.Reader(), revisionID)
	if err != nil || rev.PageID != pageID {
		// A revision id belonging to another page is a revision of this page that
		// does not exist, which is the same answer.
		return RevisionView{}, notFoundRevision(revisionID)
	}
	out := RevisionView{ID: rev.ID, At: rev.At, Source: string(rev.Source)}
	if rev.AuthorID != nil {
		name, usernameErr := s.username(ctx, *rev.AuthorID)
		if usernameErr != nil {
			return RevisionView{}, usernameErr
		}
		out.Author = &name
	}

	// Read-time authorization against the bytes being served AND against the
	// fence as the file has it now. Both are asked and both must say yes, and the
	// reason is that each one alone gets a case wrong.
	//
	// Asking only the revision's own copy treats the fence's directive as a
	// historical fact, and a revoke becomes a change of nothing but the present:
	// §8.10 exists because revisions.content is a whole file, and this is the copy
	// of the plaintext that outlives the token changing under it.
	//
	// Asking only the current file makes the present the authority over a document
	// that is no longer on disk, and it silently answers for a fence the file no
	// longer holds at all — which is the one fence whose removal the revision is
	// the last record of.
	//
	// So the revision's bytes supply the set of fences and what each claims, the
	// file supplies the ceiling, and a fence the file has dropped falls back to
	// its own directive: there is nothing left to revoke, and a directive the file
	// once held was not forged by the revision.
	revisionBytes := []byte(rev.Content)
	now := make(map[string]Secret, 4)
	for _, f := range fences(doc) {
		now[f.ID] = f
	}
	for _, f := range fences(md.Parse(page.Path, revisionBytes)) {
		ok, mayServeRevisionFenceErr := s.mayServeRevisionFence(ctx, actor, owner, f, now)
		if mayServeRevisionFenceErr != nil {
			return RevisionView{}, mayServeRevisionFenceErr
		}
		if !ok {
			// One fence is enough, and the answer names none of them: the existence
			// of the secret is not disclosed either, and no length and no diff is
			// produced that a reader could measure.
			return RevisionView{}, notFoundRevision(revisionID)
		}
	}
	out.Content = rev.Content
	out.Visible = true
	out.Diff, err = s.diffAgainstCurrent(ctx, actor, owner, doc, revisionBytes)
	if err != nil {
		return RevisionView{}, err
	}
	return out, nil
}

// mayServeRevisionFence asks one fence of a revision whether this principal may
// be served it, using Secret.CanReadSecret — the one rule — on the revision's own
// copy and, where the file still holds the same fence, on the file's current one.
//
// A fence the file no longer holds is answered from its own copy alone. That is
// deliberate and it is the fail-closed half: a directive the file once carried is
// not something the revision invented, and a fence whose visibility nobody can
// revoke any more was either readable then or is not readable now either.
func (s *Service) mayServeRevisionFence(
	ctx context.Context,
	actor authz.Principal,
	owner bool,
	rev Secret,
	now map[string]Secret,
) (bool, error) {
	authorID, err := s.authorID(ctx, rev.Author)
	if err != nil {
		return false, err
	}
	rev.AuthorID = authorID
	if !rev.CanRead(actor, owner) {
		return false, nil
	}
	current, present := now[rev.ID]
	if !present {
		return true, nil
	}
	authorID, err = s.authorID(ctx, current.Author)
	if err != nil {
		return false, err
	}
	current.AuthorID = authorID
	return current.CanRead(actor, owner), nil
}

// diffAgainstCurrent summarises how the revision differs from the page as it is
// now, over the two AUTHORIZED renderings.
//
// Both sides go through md.Redact with the hidden set of the CURRENT file. That
// matters and is easy to get backwards: a revision read above was authorised
// against its own fences, but the page today may hold a secret this principal
// never did, and a diff computed against the raw file would print it. So the
// current side is redacted, the revision side is redacted with the same set — so
// a fence that changed visibility between the two is redacted on both rather than
// leaking through one of them — and only then are the two compared.
func (s *Service) diffAgainstCurrent(
	ctx context.Context,
	actor authz.Principal,
	owner bool,
	doc *md.Doc,
	revision []byte,
) ([]HunkSummary, error) {
	hidden, err := s.hiddenIn(ctx, actor, owner, doc)
	if err != nil {
		return nil, err
	}
	before := md.Redact(md.Parse(doc.Path, revision), hidden)
	after := md.Redact(doc, hidden)
	return hunksBetween(before, after), nil
}

// fences is Parse's first result, so a caller that wants the fences and has no use
// for the problems does not have to name an underscore for them.
func fences(d *md.Doc) []Secret {
	out, _ := Parse(d)
	return out
}

// Revise restores the page to a revision.
//
// §8.10: "Revert is authz'd as an edit, not as a read." So it is not a privileged
// back door. It reads the revision under the same read-time authorization every
// other read of it uses, and then hands the bytes to the ordinary save path with
// the actor attached — which re-runs every write authorization there is: the page
// permission, the per-secret permission for each fence the revert changes, the DM
// gate on any visibility it moves, and the refusal to write through a secret whose
// body this actor cannot see.
//
// The two layers are both needed and they catch different things. The read above
// is what stops the smuggle: a revision whose secret has since been made `dm`
// still says `table` in its own bytes, and the read is refused before a single
// byte of it reaches the writer. The write below is what stops the version where
// that first layer is bypassed — a future caller holding content it got
// elsewhere — because the redacted save still refuses a buffer that carries real
// text where a sentinel belongs. A DM passes both, because a DM may read every
// secret and is for that reason the one principal for whom an old secret state is
// not a leak.
func (s *Service) Revise(ctx context.Context, actor authz.Principal, pageID, revisionID int64) error {
	view, err := s.Revision(ctx, actor, pageID, revisionID)
	if err != nil {
		return err
	}
	_, onDisk, _, err := s.readPage(ctx, pageID)
	if err != nil {
		return err
	}
	return s.write(ctx, actor, pageID, []byte(view.Content), vault.Hash(onDisk), "revert")
}

// History returns a page's revisions, newest first, without their content.
//
// store.ListRevisionMetaByPage selects no content and cannot reach it: fifty rows
// of this are fifty ids and timestamps, and fifty rows of the with-content read
// would be fifty whole files, each of which may hold secret plaintext that no
// read-time authorization has touched yet. So Diff is empty on every row and
// Content is empty on every row, and this function's only question is which
// rows to say are open.
//
// Visible is a metadata-only approximation and it is documented rather than
// promised. It is true when this principal may read EVERY secret the page holds
// right now, which is the strongest statement the file can support: a revision
// is a copy of this file, so every fence in it is one the page has held, and if
// every fence the page holds is readable then so was every fence the revision
// held. What it cannot see, and what no metadata answers, is a fence that has
// since been DELETED — a revision may still contain its body, and there is no
// tombstone table to ask. So a row marked true can still fail to open, and a row
// marked false may still open, because a secret added since can be a secret this
// principal may read.
//
// Neither direction is a leak, because Visible never gates a body: Revision
// re-decides from the revision's own bytes on every call, and a promise the panel
// displays is not an authorization. Making the flag exact would mean either
// reading all fifty revisions' content here — which is precisely what the
// metadata type exists to avoid — or recording a per-page "has held a secret
// that was removed" fact, which is a schema change owned by internal/store. The
// cheap answer is the one that errs toward showing a row that needs one more
// check, and the next check is free.
func (s *Service) History(ctx context.Context, actor authz.Principal, pageID int64) ([]RevisionView, error) {
	if err := s.policy.Check(actor, authz.PermReadPage, authz.Resource{}); err != nil {
		return nil, err
	}
	// One read of the file, not fifty: the page is what decides the per-row answer,
	// and reading it here costs the same as reading it for the view.
	_, _, doc, err := s.readPage(ctx, pageID)
	if err != nil {
		return nil, err
	}
	owner, err := store.IsPageOwner(ctx, s.db.Reader(), pageID, actor.UserID)
	if err != nil {
		return nil, err
	}
	hidden, err := s.hiddenIn(ctx, actor, owner, doc)
	if err != nil {
		return nil, err
	}
	open := len(hidden) == 0

	metas, err := store.ListRevisionMetaByPage(ctx, s.db.Reader(), pageID, historyLimit)
	if err != nil {
		return nil, err
	}
	out := make([]RevisionView, 0, len(metas))
	for _, m := range metas {
		row := RevisionView{
			ID:      m.ID,
			At:      m.At,
			Source:  string(m.Source),
			Visible: open,
		}
		if m.AuthorID != nil {
			name, err := s.username(ctx, *m.AuthorID)
			if err != nil {
				return nil, err
			}
			row.Author = &name
		}
		out = append(out, row)
	}
	return out, nil
}

// notFoundRevision is the single answer this package gives for a revision that
// does not exist, does not belong to the page, or holds a body its asker may not
// read. One constructor for all three is what keeps them indistinguishable: a
// second spelling would differ in the id it named, in whether it wrapped
// store.ErrNoRows, or in how long the two took.
func notFoundRevision(id int64) error {
	return fmt.Errorf("revision %d: %w", id, store.ErrNoRows)
}

// hunksBetween returns the change envelope of two documents, over
// authorization-independent bytes: the caller has already redacted both sides.
//
// It is linear and it stops moving its cursors. Both of those are the reason
// this exists instead of a real diff — the whole class of hangs this repository
// has shipped came from a scanner that recognised something and did not advance.
func hunksBetween(a, b []byte) []HunkSummary {
	la, lb := splitLines(a), splitLines(b)
	prefix := 0
	for prefix < len(la) && prefix < len(lb) && bytes.Equal(la[prefix], lb[prefix]) {
		prefix++
	}
	suffix := 0
	for suffix < len(la)-prefix && suffix < len(lb)-prefix &&
		bytes.Equal(la[len(la)-1-suffix], lb[len(lb)-1-suffix]) {
		suffix++
	}
	countA := len(la) - prefix - suffix
	countB := len(lb) - prefix - suffix
	if countA == 0 && countB == 0 {
		return nil
	}
	return []HunkSummary{{
		FromA:  prefix + 1,
		CountA: countA,
		FromB:  prefix + 1,
		CountB: countB,
	}}
}

// splitLines splits on LF and keeps the CR, so a document that changed nothing
// but its line terminator reports a change. That is the honest answer here: the
// file is canonical and its bytes are what is compared, and a caller that does
// not care can ignore a hunk it recognises as terminator-only.
func splitLines(src []byte) [][]byte {
	if len(src) == 0 {
		return nil
	}
	out := make([][]byte, 0, bytes.Count(src, []byte{'\n'})+1)
	for len(src) > 0 {
		i := bytes.IndexByte(src, '\n')
		if i < 0 {
			out = append(out, src)
			break
		}
		out = append(out, src[:i+1])
		src = src[i+1:]
	}
	return out
}
