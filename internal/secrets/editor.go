package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// ErrAppState reports a page whose path is the application's own state rather
// than campaign content.
//
// It exists because vault.Resolve establishes containment and nothing more. A
// page row naming .semiplane/semiplane.lock is a row the index could in
// principle carry, and serving it — to an editor, to a revision diff, or to a
// save — would hand out the database's own bytes as though they were a note, and
// a save of it would release the single-instance lock the running process still
// believes it holds. vault.Ignored answers the question; this names it.
var ErrAppState = errors.New("that path is the application's own state, not a page")

// ErrRefusedSave is the sentinel a SaveRefusedError wraps, so a handler can tell
// a refusal from a policy denial without matching on the concrete type. The two
// answer differently: a denial means this principal may never do this, a refusal
// means this buffer may not be written and another one might.
var ErrRefusedSave = errors.New("the submitted buffer was refused")

// Problem codes this file adds. md's codes describe what the segmenter found in
// a buffer; these describe what the save path decided about it, which is a
// different question and would otherwise have nowhere to live.
const (
	// ProblemDuplicateSecretID is a submission holding two fences with one id.
	// The bytes would restore into whichever one the writer looked at, and the
	// next redacted edit could not tell them apart, so it is refused rather than
	// resolved by a last-one-wins that nothing downstream would know about.
	ProblemDuplicateSecretID = "secret.duplicate_id"
	// ProblemUnaddressableID is a submission that adds a secret fence with no
	// conforming id. md substitutes a placeholder so the block is still redacted,
	// and a placeholder is deliberately not twelve hex characters — so the fence
	// would never be addressable, never indexed and never revealed. An author who
	// typed one is told; one that was already on disk is left alone, because it is
	// already hidden and refusing the save would make an existing page
	// uneditable.
	ProblemUnaddressableID = "secret.unaddressable_id"
)

// SaveRefusedError reports a save the service will not perform, and why.
//
// It carries md.Problem values, which are documented never to contain document
// content, and the path. It carries no bytes: the file is unchanged, the buffer
// is the caller's own, and a secret body is in neither.
type SaveRefusedError struct {
	// Path is the vault-relative page path.
	Path string
	// Problems names every problem found, not just the first. An author who
	// changed three hidden secrets should learn about all three rather than
	// fixing one and being refused again.
	Problems []md.Problem
}

// Error implements error.
func (e *SaveRefusedError) Error() string {
	if len(e.Problems) == 0 {
		return fmt.Sprintf("%s: the submitted buffer was refused", e.Path)
	}
	return fmt.Sprintf("%s: %d problem(s) in the submitted buffer, starting with %s",
		e.Path, len(e.Problems), e.Problems[0].Code)
}

// Unwrap makes errors.Is(err, ErrRefusedSave) true.
func (e *SaveRefusedError) Unwrap() error { return ErrRefusedSave }

// EditMode says whether an editor buffer holds the page's true bytes.
//
// It is a property of the buffer, decided by this package and nowhere else: a
// handler that re-derived it would be re-implementing an authorization decision,
// and the two would disagree the first time a page grew a secret.
type EditMode int

const (
	// EditModeFull means every secret on the page is readable by the actor, so
	// Content is the file verbatim and Save writes whatever arrives.
	EditModeFull EditMode = iota
	// EditModeRedacted means at least one secret is not readable, so Content
	// holds a sentinel in place of that body and Save reconciles the sentinel
	// back to the on-disk bytes before writing.
	EditModeRedacted
)

// String renders the mode for a log line and a template.
func (m EditMode) String() string {
	if m == EditModeRedacted {
		return "redacted"
	}
	return "full"
}

// Redacted reports whether the buffer holds sentinels rather than secret bodies.
func (m EditMode) Redacted() bool { return m == EditModeRedacted }

// EditView is what GET /p/{path}/edit is given.
//
// It is a struct rather than three return values because the three travel
// together and must not be taken out of step: Content is the true bytes only when
// Mode says so, and a caller that read Content without Mode would be handing a
// secret body to whoever is next.
type EditView struct {
	// Path is the vault-relative page path.
	Path string
	// Mode says whether Content is the file or a redacted buffer.
	Mode EditMode
	// BaseHash is vault.Hash of the bytes on disk when the view was built. It is
	// what Save checks against, so an editor that was left open over somebody
	// else's change is refused rather than overwriting it.
	BaseHash []byte
	// Content is the buffer to render. In EditModeRedacted it holds a sentinel in
	// place of every body in HiddenIDs and never the body itself.
	Content []byte
	// HiddenIDs are the secret ids whose bodies Content does not carry, sorted.
	// They are the ids the editor may show as markers, and nothing else about
	// them: no length, no author, no excerpt, no digest.
	HiddenIDs []string
	// Problems are the recoverable parse problem codes of the page, in file
	// order — md.Problem.Code values, not their prose. A renderer localises them
	// by code, and no byte of the page can reach this field by accident.
	Problems []string
}

// EditView returns the editor buffer for a page, redacted if the actor may not
// read some of its secrets.
//
// The mode is one question asked once per fence — authz.CanReadSecret, through
// Secret.CanRead — and the whole package answers it the same way: redacting,
// splicing, deleting and serving a revision all take their answer from this one
// rule, so there is no state in which two of them disagree about which bodies a
// principal may read.
func (s *Service) EditView(ctx context.Context, actor authz.Principal, pageID int64) (EditView, error) {
	// readPage is resource-free in v1 — a page is a file anybody who may read
	// public content may open — so this check needs no lookup and nothing that
	// follows it can vary with the page id before it runs.
	if err := s.policy.Check(actor, authz.PermReadPage, authz.Resource{}); err != nil {
		return EditView{}, err
	}
	page, onDisk, doc, err := s.readPage(ctx, pageID)
	if err != nil {
		return EditView{}, err
	}
	owner, err := store.IsPageOwner(ctx, s.db.Reader(), pageID, actor.UserID)
	if err != nil {
		return EditView{}, err
	}
	hidden, err := s.hiddenIn(ctx, actor, owner, doc)
	if err != nil {
		return EditView{}, err
	}
	view := EditView{
		Path:     page.Path,
		BaseHash: vault.Hash(onDisk),
		Problems: problemCodes(doc),
	}
	if len(hidden) == 0 {
		view.Mode = EditModeFull
		// Copied rather than aliased. The editor hands this buffer back to Save,
		// and a caller that edited it in place — a formatter, a middleware that
		// trims a byte — must not be able to reach back into the slice the read
		// of the file handed out.
		view.Content = append([]byte(nil), onDisk...)
		return view, nil
	}
	view.Mode = EditModeRedacted
	view.Content = md.Redact(doc, hidden)
	view.HiddenIDs = sortedIDs(hidden)
	return view, nil
}

// Save writes a page's submitted editor buffer.
//
// It is one operation with three parts that must not be separable: reconcile the
// buffer against the file, authorise every secret the submission changes under
// the permission that governs it, and then write through vault.Writer with the
// hash the editor was based on. A partial version of any of the three is a file
// whose secrets and public text came from two different documents.
func (s *Service) Save(ctx context.Context, actor authz.Principal, pageID int64, content, baseHash []byte) error {
	return s.write(ctx, actor, pageID, content, baseHash, "save")
}

// write is Save with a reason for the audit record, so that a revert and an
// ordinary save run the same checks and are told apart in the trail.
func (s *Service) write(ctx context.Context, actor authz.Principal, pageID int64, content, baseHash []byte, reason string) error {
	// The gate that needs no lookup runs first, and it is PermSession rather than
	// PermWritePage: an unauthenticated principal fails it whatever the resource
	// says, so it cannot refuse anybody the real check would have allowed, and a
	// signed-out caller learns nothing from the difference between "no such page"
	// and "you may not write this one". PermWritePage is not usable for this
	// because its resource carries the ownership, and asking it with a zero
	// Resource would refuse every player — including the page owners who are the
	// whole point of the redacted editor.
	if err := s.policy.Check(actor, authz.PermSession, authz.Resource{}); err != nil {
		return err
	}
	page, _, doc, err := s.readPage(ctx, pageID)
	if err != nil {
		return err
	}
	owner, err := store.IsPageOwner(ctx, s.db.Reader(), pageID, actor.UserID)
	if err != nil {
		return err
	}
	if checkErr := s.policy.Check(actor, authz.PermWritePage, authz.Page(pageID, owner)); checkErr != nil {
		return checkErr
	}
	hidden, err := s.hiddenIn(ctx, actor, owner, doc)
	if err != nil {
		return err
	}

	next, err := reconcile(doc, content, hidden)
	if err != nil {
		return err
	}
	change, err := s.authorise(ctx, actor, pageID, owner, doc, next)
	if err != nil {
		return err
	}

	// The permission the write is performed under is the one the change actually
	// requires, so a save that touches a secret cannot be mounted on a page route
	// and a save that touches no secret is not asked for a secret permission.
	expect := authz.PermWritePage
	if change.any() {
		expect = authz.PermWriteSecret
	}
	err = s.writer.Save(ctx, vault.SaveRequest{
		Path:            page.Path,
		NewContent:      next,
		BaseContentHash: baseHash,
		ActorID:         actor.UserID,
		ExpectPerm:      expect,
	})
	if errors.Is(err, vault.ErrConflict) {
		// Both versions of the file are in vault's error, and on a page with a
		// secret fence one of them is a secret body. See RaceLostError.
		return &RaceLostError{Path: page.Path, Reason: reason}
	}
	if err != nil {
		return err
	}

	// The audit rows and the generation move in one transaction, for the reason
	// SetVisibility's do: a crash cannot leave a generation bumped with nothing to
	// explain it. The file write is outside it on purpose, because the file is
	// canonical and the index is derived.
	generation := int64(0)
	rows := change.events(actor.UserID, s.clock())
	if change.any() {
		tx, err := s.db.Writer().BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("secrets: begin the audit of %s: %w", page.Path, err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, ev := range rows {
			if _, appendSecretEventErr := store.AppendSecretEvent(ctx, tx, ev); appendSecretEventErr != nil {
				return appendSecretEventErr
			}
		}
		if change.movedAuthorization() {
			// A create, a delete, or a fence whose visibility changed changes what
			// some principal's rendering of this page would be, so every live
			// stream is torn down. A body edit does not: the reindex below already
			// publishes the new bytes to the readers who could read them.
			generation, err = store.BumpAuthzGeneration(ctx, tx)
			if err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("secrets: commit the audit of %s: %w", page.Path, err)
		}
	}

	if err := s.reindexer.Reindex(ctx, page.Path); err != nil {
		return fmt.Errorf("secrets: %s wrote %s but the index could not be updated: %w",
			reason, page.Path, err)
	}
	for _, ev := range rows {
		s.log.Audit(ctx, "page save touched a secret",
			"action", ev.Action, "page_path", page.Path, "actor", actor.Username,
			"secret_id", ev.SecretID, "from_vis", ev.FromVis, "to_vis", ev.ToVis,
			"save_reason", reason)
	}
	s.log.InfoContext(ctx, "page saved",
		"action", reason+".page", "path", page.Path, "actor_id", actor.UserID,
		"bytes", len(next), "mode", modeName(hidden),
		"secrets_created", len(change.created), "secrets_edited", len(change.edited),
		"secrets_deleted", len(change.deleted),
		"authz_generation", generation)
	return nil
}

// reconcile turns a submitted editor buffer into the bytes to write, or refuses
// the whole save.
//
// hidden is the set of secrets the actor may not read. When it is empty the
// submission is written as it stands: there is nothing in the file the actor is
// not allowed to see, so there is nothing to restore over, and the changes the
// submission makes to fences the actor CAN read are checked by authorise instead.
//
// When hidden is not empty, md.Splice restores every body it is given a token
// for and reports every case it will not touch. All of those reports refuse the
// whole save, including a fence that is simply gone, and the reason for that is
// worth stating because it looks like an omission: a principal who may not read a
// fence may not delete it either, and the only principal who could be given that
// permission is a DM — who by definition reads every fence on the page, and is
// therefore served by the empty-hidden branch above and never reaches this code.
// A permission check that can only ever pass for a caller who cannot reach it is
// not a second authorisation, it is a comment with a runtime cost. So the rule
// is stated once, here: a deletion of a secret you cannot see is refused, and a
// DM needs no exemption because a DM never has a secret to ask about.
func reconcile(doc *md.Doc, submitted []byte, hidden map[string]bool) ([]byte, error) {
	if len(hidden) == 0 {
		return submitted, nil
	}
	next, problems, err := md.Splice(doc, submitted, hidden)
	if err != nil {
		return nil, fmt.Errorf("secrets: reconcile a save of %s: %w", doc.Path, err)
	}
	if len(problems) > 0 {
		// A partial write is not a smaller version of the operation, so nothing is
		// written and every problem is reported, not only the first.
		return nil, &SaveRefusedError{Path: doc.Path, Problems: problems}
	}
	return next, nil
}

// edit is one secret the submission changed, with the visibility it had in the
// file beside the one the submission gives it. The pair is what a revoke or a
// reveal looks like in an audit row, and it is only knowable because both
// versions were compared here.
type edit struct {
	Secret
	// FromVisibility is the fence's visibility before the save.
	FromVisibility Visibility
	// visibilityMoved reports whether the save changed it, as opposed to only
	// changing the body or the metadata around it.
	visibilityMoved bool
}

// change is what one save did to a page's secrets, in the three shapes a
// submission can change them.
//
// It exists so that the permission checks, the audit rows and the authorization
// generation all read one list. Three passes over the same comparison would be
// three places for what was authorised and what was recorded to disagree, and an
// audit trail that disagrees with the authorization is worse than none.
type change struct {
	created []Secret
	edited  []edit
	deleted []Secret
}

func (c change) any() bool {
	return len(c.created)+len(c.edited)+len(c.deleted) > 0
}

// movedAuthorization reports whether anything about this change alters what a
// principal's rendering of the page would be, as opposed to only altering its
// bytes for the principals who could already read them.
func (c change) movedAuthorization() bool {
	if len(c.created) > 0 || len(c.deleted) > 0 {
		return true
	}
	for _, f := range c.edited {
		if f.visibilityMoved {
			return true
		}
	}
	return false
}

// events renders the change as audit rows: one per secret, carrying ids and
// visibilities and never a byte of a body.
func (c change) events(actorID int64, at time.Time) []store.SecretEvent {
	out := make([]store.SecretEvent, 0, len(c.created)+len(c.edited)+len(c.deleted))
	for _, f := range c.created {
		out = append(out, store.SecretEvent{
			SecretID: f.ID, ActorID: actorID, Action: store.SecretActionCreate,
			ToVis: string(f.Visibility), At: at,
		})
	}
	for _, f := range c.edited {
		out = append(out, store.SecretEvent{
			SecretID: f.ID, ActorID: actorID, Action: store.SecretActionEdit,
			FromVis: string(f.FromVisibility), ToVis: string(f.Visibility), At: at,
		})
	}
	for _, f := range c.deleted {
		out = append(out, store.SecretEvent{
			SecretID: f.ID, ActorID: actorID, Action: store.SecretActionDelete,
			FromVis: string(f.Visibility), At: at,
		})
	}
	return out
}

// authorise is the second half of a save: it decides which of the page's
// secrets the submission created, edited or removed, and checks the permission
// that governs each one. It returns the change so the audit trail and the
// generation read the same list the checks read.
//
// Every resource here is built from the fence as the FILE has it, never from the
// submission. A buffer that decided its own authorization would edit
// `author=` to somebody else and thereby grant itself the write, or edit
// `visibility=` and thereby grant itself the reveal; asking about the file is
// what makes those two fields unforgeable by the thing they describe.
func (s *Service) authorise(
	ctx context.Context,
	actor authz.Principal,
	pageID int64,
	owner bool,
	doc *md.Doc,
	submitted []byte,
) (change, error) {
	var out change

	onDisk, _ := Parse(doc)
	before := map[string]Secret{}
	for _, f := range onDisk {
		before[f.ID] = f
	}

	after, _ := Parse(md.Parse(doc.Path, submitted))
	seen := make(map[string]bool, len(after))
	for _, f := range after {
		if seen[f.ID] {
			return change{}, &SaveRefusedError{Path: doc.Path, Problems: []md.Problem{{
				Code:     ProblemDuplicateSecretID,
				SecretID: f.ID,
				Message:  "the submission holds two fences with one secret id",
			}}}
		}
		seen[f.ID] = true

		old, exists := before[f.ID]
		if !exists {
			if !ValidSecretID(f.ID) {
				return change{}, &SaveRefusedError{Path: doc.Path, Problems: []md.Problem{{
					Code:     ProblemUnaddressableID,
					SecretID: f.ID,
					Message:  "a new secret fence has no id that can be addressed",
				}}}
			}
			authorID, err := s.authorID(ctx, f.Author)
			if err != nil {
				return change{}, err
			}
			// Authoring. §6: a page owner may create and edit their own secrets —
			// ownership grants authoring rights, not broadcast rights. So the
			// resource is the new fence's own author and visibility, and the page's
			// write permission above is what already established that this actor
			// may touch this page at all.
			res := authz.SecretOf(pageID, owner, authorID, f.Visibility)
			if err := s.policy.Check(actor, authz.PermWriteSecret, res); err != nil {
				return change{}, err
			}
			// `table` is a broadcast: it is the one visibility that reaches every
			// other player, so a new one is a DM's to make. A new `dm` fence needs
			// nothing more — the policy already refuses it to anybody who is not a
			// DM, which is the negative case worth stating rather than relying on.
			if f.Visibility == VisibilityTable {
				if err := s.policy.Check(actor, authz.PermDM, authz.Resource{}); err != nil {
					return change{}, err
				}
			}
			out.created = append(out.created, f)
			continue
		}

		if f.BodyHash != nil && bytes.Equal(f.BodyHash, old.BodyHash) &&
			f.Directive == old.Directive {
			// Unchanged, or moved. A fence that keeps its id, its body and its
			// directive is the same secret wherever it sits, and a move is an edit
			// of the public text around it: nothing about the secret changed, so
			// there is nothing to authorise over and nothing to record.
			continue
		}
		authorID, err := s.authorID(ctx, old.Author)
		if err != nil {
			return change{}, err
		}
		if err := s.policy.Check(actor, authz.PermWriteSecret,
			authz.SecretOf(pageID, owner, authorID, old.Visibility)); err != nil {
			return change{}, err
		}
		edited := edit{Secret: f, FromVisibility: old.Visibility, visibilityMoved: f.Visibility != old.Visibility}
		if edited.visibilityMoved {
			// Any visibility change is a reveal or a revoke however it arrived —
			// through this save rather than through SetVisibility — so it takes the
			// same gate. Without this, the author of a private secret could reach
			// `table` with nothing but the permission to edit their own words.
			if err := s.policy.Check(actor, authz.PermDM, authz.Resource{}); err != nil {
				return change{}, err
			}
		}
		out.edited = append(out.edited, edited)
	}

	for _, f := range onDisk {
		if seen[f.ID] {
			continue
		}
		authorID, err := s.authorID(ctx, f.Author)
		if err != nil {
			return change{}, err
		}
		// The same rule as an edit: a player may remove a secret they authored, a
		// DM may remove any. A removal of a secret this actor could NOT read never
		// reaches this loop — reconcile refuses it, because the fence is in the
		// hidden set by definition. So this loop only ever sees deletions somebody
		// was entitled to look at, which is why the gate is authorship and not
		// visibility.
		if err := s.policy.Check(actor, authz.PermWriteSecret,
			authz.SecretOf(pageID, owner, authorID, f.Visibility)); err != nil {
			return change{}, err
		}
		out.deleted = append(out.deleted, f)
	}

	return out, nil
}

// readPage loads a page row, reads the file and parses it. The three travel
// together because every caller needs all three and a caller that skipped the
// parse would have to re-implement the fence enumeration.
func (s *Service) readPage(ctx context.Context, pageID int64) (store.Page, []byte, *md.Doc, error) {
	page, err := store.GetPageByID(ctx, s.db.Reader(), pageID)
	if err != nil {
		return store.Page{}, nil, nil, err
	}
	onDisk, doc, err := s.readPath(ctx, page.Path)
	if err != nil {
		return store.Page{}, nil, nil, err
	}
	return page, onDisk, doc, nil
}

// readPath reads a page's file and parses it, refusing the application's own
// state.
//
// The refusal belongs at the boundary that takes a path, not in vault.Writer:
// Resolve establishes containment and nothing more, so a page row naming
// .semiplane/semiplane.lock would otherwise be read, parsed and handed to an
// editor as though it were campaign content — and a save of it would release the
// single-instance lock the running process still believes it holds.
func (s *Service) readPath(ctx context.Context, rel string) ([]byte, *md.Doc, error) {
	if vault.Ignored(rel) {
		return nil, nil, fmt.Errorf("%w: %s", ErrAppState, rel)
	}
	p, err := vault.Resolve(s.writer.Root, rel)
	if err != nil {
		return nil, nil, err
	}
	onDisk, err := vault.Read(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	return onDisk, md.Parse(rel, onDisk), nil
}

// hiddenIn returns the ids of the document's fences that actor may not read.
//
// It is the one place this package asks that question. Redaction, the redacted
// save, the audit of a deletion and the history panel's per-row answer all take
// their answer from here, so there is no state in which two of them disagree
// about which bodies a principal may read.
func (s *Service) hiddenIn(ctx context.Context, actor authz.Principal, owner bool, doc *md.Doc) (map[string]bool, error) {
	fences, _ := Parse(doc)
	out := make(map[string]bool, len(fences))
	for _, f := range fences {
		authorID, err := s.authorID(ctx, f.Author)
		if err != nil {
			return nil, err
		}
		f.AuthorID = authorID
		if !f.CanRead(actor, owner) {
			out[f.ID] = true
		}
	}
	return out, nil
}

// authorID resolves a fence's author= username to the account it names.
//
// A username with no account is 0, and 0 is nobody: authz.CanReadSecret matches
// an author against the principal's own user id, and no authenticated principal
// has 0, so a fence naming an account that does not exist is readable by DMs and
// by page owners and by nobody else. The indexer refuses to index such a fence
// for the same reason, and for the same reason it must not be more permissive
// here.
func (s *Service) authorID(ctx context.Context, username string) (int64, error) {
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

// username resolves a revision's author id back to a name for the history panel.
// A deleted account yields an empty name rather than an error: the revision
// happened, and who did it is not the panel's business to fail over.
func (s *Service) username(ctx context.Context, id int64) (string, error) {
	u, err := store.GetUserByID(ctx, s.db.Reader(), id)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return "", nil
	case err != nil:
		return "", err
	}
	return u.Username, nil
}

// problemCodes collects a document's recoverable problem codes, in file order.
func problemCodes(d *md.Doc) []string {
	if d == nil || len(d.Problems) == 0 {
		return nil
	}
	out := make([]string, 0, len(d.Problems))
	for _, pr := range d.Problems {
		out = append(out, pr.Code)
	}
	return out
}

// sortedIDs returns a map's keys in a stable order, so an editor view of the
// same page is byte-identical for the same principal on two consecutive calls.
func sortedIDs(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// modeName renders which save path was taken, for the audit record.
func modeName(hidden map[string]bool) string {
	if len(hidden) == 0 {
		return EditModeFull.String()
	}
	return EditModeRedacted.String()
}
