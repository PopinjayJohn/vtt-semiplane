package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/go-chi/chi/v5"
)

// Renaming a page, and the opt-in bulk link updater (§5.6).
//
// Three routes, and the shape of all three is the same: the route table's Perm
// column is a *coarse* gate and the real, resource-bearing decision is made
// inside, against store.IsPageOwner. That is the preview.go shape, and for
// PermWritePage it matters more than it did there: the middleware asks the
// policy with a zero authz.Resource, which is the question "may this principal
// write something at all", and the answer that gives is a DM or an admin. The
// per-page question is asked here, once per page the operation touches, and the
// policy is the only thing that answers it.
//
// The two orders that matter, stated here because they are the whole security
// story of the updater:
//
//	rename:  the destination is validated and the source's write access is
//	         checked *before* either file is touched, and Move then hash-checks
//	         the bytes under both path locks.
//	updater: the affected set is re-read from the index and the caller's
//	         permission is re-checked per page *before* any file is read; every
//	         recorded occurrence is then verified byte for byte against the file
//	         it names, and a link whose range lands inside a secret is never
//	         turned into an edit at all.
//
// Nothing here mutates a byte range the index did not record, and nothing here
// re-renders a page: the rewrite splices the target token and copies every
// other byte of the file, so a DM's prose, their line endings and their
// Obsidian quirks come out of a rename exactly as they went in.

// The reason a recorded occurrence is not rewritten.
//
// They are constants because a reason reaches a reader, who quotes it back, and
// because the values are what TestStalePreviewIsHarmless and
// TestUpdaterSkipsAnUnrecordedOccurrence assert on. None of them carries
// content: a reason that named the bytes it refused to touch would be a way to
// read that range.
const (
	// ConflictStale is an occurrence whose recorded range no longer holds the
	// recorded target, which means the file was edited after it was indexed.
	// §5.6 step 3 exists for this case and for nothing else.
	ConflictStale = "stale"
	// ConflictUnrecorded is an occurrence the index holds with no byte range at
	// all, which is what a destination written escaped, in angle brackets or
	// percent-encoded gets. It is *not* "at the start of the file": store records
	// LinkByteStartUnset and a zero length for these, and treating the zero as
	// an offset would rewrite the first bytes of the document with a link.
	ConflictUnrecorded = "unrecorded"
	// ConflictOutOfRange is a recorded range that is not inside the file, which
	// means the record was made against a different document.
	ConflictOutOfRange = "out of range"
	// ConflictInsideSecret is an occurrence whose range lands inside a secret
	// fence. Nobody's updater rewrites one: the range is what the edit would
	// touch, and an edit inside a fence is a way to alter a body its reader may
	// not have.
	ConflictInsideSecret = "inside a secret"
	// ConflictOverlapping is two occurrences claiming the same bytes, which has
	// no correct answer for either of them.
	ConflictOverlapping = "overlapping"
	// ConflictUnmatched is an occurrence that resolves to the page and whose
	// recorded range is still exactly right, and which the rename will not touch
	// because it is not a reference to the name. `[y](Tavern\.md)` is the
	// example: the resolver unescapes it and finds the page, the recorded range
	// covers the ten bytes of `Tavern\.md`, and there is no spelling of "rename
	// the target" that leaves an author who wrote a backslash with the page they
	// meant. Reporting it as a conflict is the honest answer; calling it stale
	// would blame the index for something the index got right.
	ConflictUnmatched = "not a reference to the name"
)

// The reason a page or an occurrence is listed but not rewritten, from
// ApplyLinkUpdate's details. They are the plan's own phrases where the plan
// gives one, so a reader comparing the two is comparing like with like.
const (
	// SkipNoPermission is the phrase §5.6 asks for, and the only one of these
	// that describes a refusal rather than a failure.
	SkipNoPermission = "no permission"
	// SkipUnreadable is a page whose file could not be read at all.
	SkipUnreadable = "the file could not be read"
	// SkipAppState is a page whose path is the application's own state, which no
	// request may name and which the writer would not touch.
	SkipAppState = "the path is the application's own state"
	// SkipNothingToDo is a page whose every occurrence was refused, so writing it
	// would have put the file back unchanged.
	SkipNothingToDo = "nothing to rewrite"
	// SkipWriteFailed is a page the writer refused, for any reason it did not
	// name. A rename is a whole-file mutation and a partial one is not a thing a
	// vault file can be.
	SkipWriteFailed = "the file could not be written"
)

// renameFormName is the form field and query parameter carrying the new name.
//
// It is the plan's own spelling — `?new=` on the preview, `{ new: … }` on the
// update — and it is one name for both verbs so that a client cannot preview one
// destination and confirm another.
const renameFormName = "new"

// confirmedValue is what the update route requires before it will touch a single
// file. A rename that rewrites twelve links in somebody else's prose is not
// something a GET may do, and the word is what the dialog's button says.
const confirmedValue = "true"

// maxRenameNameBytes caps the name a rename may be given.
//
// It is a cap rather than a rule about which characters are allowed because the
// only characters that are genuinely unsafe are the ones that escape the vault,
// and vault.Resolve refuses those. This one bounds a request line and a file
// name, and a page whose name is longer is a page nobody named.
const maxRenameNameBytes = 255

// renamePage answers POST /api/pages/{id}/rename.
//
// It is a door and nothing else: the id, the form field and the status codes
// live here, and everything that decides anything is in RenamePage, which the
// tests drive directly for the same reason the two updater operations are
// exported — a rename that can only be exercised through HTTP cannot be asked
// what it did to a principal who never got as far as the router.
func (s *Server) renamePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	pageID, ok := renamePageID(s, w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, http.StatusBadRequest)
		return
	}
	result, err := s.RenamePage(ctx, who, pageID, r.PostFormValue(renameFormName))
	if err != nil {
		s.writePlanError(w, r, err)
		return
	}
	s.writeJSON(w, r, result)
}

// RenamePage moves a page's file to a new name and records the names it used to
// answer to. It is the whole of what POST /api/pages/{id}/rename does.
//
// It is exported because it is the operation rather than a helper of it, and
// because the four questions it has to answer — may this principal write the
// page, is the destination inside the vault, is the destination the app's own
// state, does the destination already exist — are four questions a test cannot
// ask of a route that has already answered them.
//
// It does not touch a single referring page. That is the updater's job and the
// reader's decision, and the result is a pointer to it rather than a rewrite.
func (s *Server) RenamePage(ctx context.Context, who authz.Principal, pageID int64, newName string) (RenameResult, error) {
	row, newRel, err := s.renameTarget(ctx, who, pageID, newName)
	if err != nil {
		return RenameResult{}, err
	}
	name := strings.TrimSpace(newName)

	// The bytes the move is based on are the bytes on disk now, read outside the
	// locks. Move re-reads under them and refuses if anything landed in between,
	// so this is the check for a writer that fires during the request rather
	// than a check against a version the reader never chose — which is the
	// difference between an optimistic-concurrency race and a rename based on a
	// stale index row.
	onDisk, err := s.readPage(ctx, row.Path)
	if err != nil {
		return RenameResult{}, fmt.Errorf("%w: the page to rename could not be read", store.ErrNoRows)
	}

	oldName := md.Basename(row.Path)
	// Read before the old row goes: the aliases belong to the row that is about
	// to be removed, and the new row only ever gets its own frontmatter ones.
	carried, err := s.aliasesToCarry(ctx, row)
	if err != nil {
		return RenameResult{}, err
	}
	// Ownership, for the same reason and with a heavier consequence.
	//
	// page_owners.page_id is ON DELETE CASCADE, so removing the departed row
	// takes every owner with it, and a rename would silently strip the page of
	// the people who could write it. That is not a lost permission: the grant is
	// what lets its owner read the private secrets authored on it, and what
	// makes the page editable at all. Renaming a page you own would leave you
	// unable to edit it and unable to read your own notes — the rename would
	// report success and the page would come back a stranger's.
	owners, err := store.ListPageOwners(ctx, s.db.Reader(), row.ID)
	if err != nil {
		return RenameResult{}, err
	}
	// And the pages that refer to it, for the same reason and for a second one.
	//
	// Removing the departed row sets target_page_id to NULL on every reference to
	// it — links.target_page_id is ON DELETE SET NULL, not CASCADE, so the rows
	// survive as dangling references rather than vanishing. That is right for a
	// deletion: the reference is still in a file on disk and the broken-links
	// panel needs it. It is wrong for a rename, where the reference has not
	// broken, it has been given a new name. So the references the rename orphaned
	// are re-pointed, which is what makes [[the old name]] resolve to the new page
	// at once rather than sitting in the broken-links panel until somebody touches
	// the file again.
	referrers, err := s.referrerPaths(ctx, row.ID)
	if err != nil {
		return RenameResult{}, err
	}

	if err := s.writer.Move(ctx, vault.MoveRequest{
		From:            row.Path,
		To:              newRel,
		BaseContentHash: vault.Hash(onDisk),
		ActorID:         who.UserID,
		ExpectPerm:      authz.PermWritePage,
	}); err != nil {
		return RenameResult{}, err
	}

	// The departed row first, the new one second.
	//
	// The order is not cosmetic. A secret's id is the primary key of the secrets
	// table and is carried by the fence, so a page with a secret re-indexed
	// under a new path while the old row still holds that id fails on the
	// uniqueness constraint — and the file has already moved by then, which would
	// make the failure a corrupt rename rather than a refused one. Deleting the
	// old row first releases the ids. It also records the page as vanished, which
	// is what lets the indexer's own rename detection fire later and find nothing
	// left to do.
	if err := s.reindexer.Reindex(ctx, row.Path); err != nil {
		// The file has already moved, so this is a stale index and not a failed
		// rename: the reconciling scan collects the old row, and reporting failure
		// here would tell the reader the rename did not happen when it did.
		s.log.WarnContext(ctx, "the departed page's index row could not be removed",
			"action", "http.rename", "path", row.Path)
	}
	if err := s.reindexer.Reindex(ctx, newRel); err != nil {
		return RenameResult{}, fmt.Errorf("httpapi: index the renamed page: %w", err)
	}
	var movedID int64
	moved, movedErr := store.GetPageByPath(ctx, s.db.Reader(), newRel)
	switch {
	case movedErr == nil:
		movedID = moved.ID
		for _, alias := range carried {
			if err := store.AddPageAlias(ctx, s.db.Writer(), movedID, alias); err != nil {
				return RenameResult{}, err
			}
		}
	case errors.Is(movedErr, store.ErrNoRows):
		// The file moved and the index did not take. The reconciling scan will
		// create the row and it carries the frontmatter aliases; the rename's own
		// alias is then lost until somebody renames again, which is a stale index
		// rather than a wrong one.
		return RenameResult{}, fmt.Errorf("httpapi: the renamed page has no index row: %w", movedErr)
	default:
		return RenameResult{}, fmt.Errorf("httpapi: read the renamed page's row: %w", movedErr)
	}
	// The grants, on the new row and after the old one is gone. Re-granting from
	// the copy taken before the move is the only way they can survive a cascade,
	// and a failure here is not a stale index the reconciling scan will fix: the
	// owners are not derivable from the file, so a rename that dropped them has
	// silently changed who may read the page's private secrets.
	for _, owner := range owners {
		if err := store.AddPageOwner(ctx, s.db.Writer(), store.PageOwner{
			PageID:  movedID,
			UserID:  owner.UserID,
			IsOwner: owner.IsOwner,
			AddedAt: owner.AddedAt,
		}); err != nil {
			return RenameResult{}, err
		}
	}
	for _, ref := range referrers {
		// The alias exists by now, which is the only reason this resolves. A
		// referring page that fails to re-derive is a stale index, not a failed
		// rename, and the reconciling scan will collect it.
		if err := s.reindexer.Reindex(ctx, ref.path); err != nil {
			s.log.WarnContext(ctx, "a page that refers to the renamed one could not be re-derived",
				"action", "http.rename", "path", ref.path)
			continue
		}
		orphans, err := orphanedLinkIDs(ctx, s.db.Reader(), ref.pageID, carried)
		if err != nil {
			return RenameResult{}, err
		}
		if len(orphans) == 0 {
			continue
		}
		if err := store.SetLinkTargets(ctx, s.db.Writer(), orphans, movedID); err != nil {
			return RenameResult{}, fmt.Errorf("httpapi: re-point the references to a renamed page: %w", err)
		}
	}

	s.log.InfoContext(ctx, "a page was renamed through the app",
		"action", "http.rename", "page_id", movedID, "from", row.Path, "to", newRel,
		"actor_id", who.UserID)

	return RenameResult{
		OldPath: row.Path,
		NewPath: newRel,
		OldName: oldName,
		NewName: name,
		PageID:  movedID,
		Aliases: carried,
		Updater: linkUpdaterPointer(movedID, name),
	}, nil
}

// renamePreview answers GET /api/pages/{id}/rename-preview?new=<name>.
//
// The question it answers is "what would pressing the button do", and the only
// honest answer to that is the one computed now from the vault as it is. It
// says so in the per-page rows: CanWrite is false for a page this reader may not
// rewrite, and the page is still listed — a preview that quietly left it out
// would be a preview reporting "twelve links will update" when four can.
func (s *Server) renamePreview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	pageID, ok := renamePageID(s, w, r)
	if !ok {
		return
	}
	newName := strings.TrimSpace(r.URL.Query().Get(renameFormName))
	if newName == "" || len(newName) > maxRenameNameBytes {
		s.writeError(w, r, http.StatusBadRequest)
		return
	}

	plan, err := s.PlanLinkUpdate(ctx, who, pageID, newName)
	if err != nil {
		s.writePlanError(w, r, err)
		return
	}
	// The payload carries page paths and link targets, so a shared cache holding
	// it for one principal and serving it to another is a leak with no header to
	// explain it. writeJSON sets the three headers that close that.
	s.writeJSON(w, r, plan)
}

// updateLinks answers POST /api/pages/{id}/update-links with { new, confirmed }.
//
// The confirmation is not a formality. The whole point of the updater, in the
// plan's own words, is that "the app should not silently mutate prose a human
// typed" — so a caller that has not said the word gets a 400, and a caller that
// has gets exactly the plan it was shown, re-derived rather than replayed.
func (s *Server) updateLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	who := PrincipalFrom(ctx)

	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, http.StatusBadRequest)
		return
	}
	pageID, ok := renamePageID(s, w, r)
	if !ok {
		return
	}
	newName := strings.TrimSpace(r.PostFormValue(renameFormName))
	if newName == "" || len(newName) > maxRenameNameBytes {
		s.writeError(w, r, http.StatusBadRequest)
		return
	}
	if r.PostFormValue("confirmed") != confirmedValue {
		s.writeError(w, r, http.StatusBadRequest)
		return
	}

	result, err := s.ApplyLinkUpdate(ctx, who, pageID, newName)
	if err != nil {
		s.writePlanError(w, r, err)
		return
	}
	s.writeJSON(w, r, result)
}

// PlanLinkUpdate computes what the bulk link updater would do to a page, for
// this principal, right now.
//
// It is exported because it *is* the operation rather than a helper of it: both
// HTTP handlers are wrappers around it, the authorization inside it is the
// feature's own authorization, and a test that could only reach it through a
// route could not ask the question the feature exists for — what a principal
// who may write one page and not another is told about the pages they may not
// rewrite.
//
// It never trusts a stored preview. Step 1 of §5.6's algorithm is to re-run
// resolution for the old name, and the re-run is one indexed query: after a
// rename the departed name resolves to the renamed page through the alias the
// rename recorded, so every reference written against the old name is now a
// reference to this page, and store.ListLinksToPage is that set.
//
// The occurrences a principal may not see are absent from the result entirely —
// not present with a blank Found, and not counted in the summary — because a
// dangling reference inside a secret is a fact about that secret. The same rule
// the backlinks panel and the broken-links panel apply in SQL is applied here
// in Go, because this package may not add a store query, and a filter placed
// before the row is put in a view model is the same guarantee as one in SQL:
// the row is never built, so it cannot be rendered, counted or logged.
func (s *Server) PlanLinkUpdate(ctx context.Context, who authz.Principal, pageID int64, newName string) (LinkUpdatePlan, error) {
	plan, _, err := s.planLinkUpdate(ctx, who, pageID, newName)
	return plan, err
}

// planLinkUpdate is PlanLinkUpdate with the recorded rows handed back, because
// the apply needs them and re-reading them would be a second statement that
// could disagree with the first about which references exist.
func (s *Server) planLinkUpdate(ctx context.Context, who authz.Principal, pageID int64, newName string) (LinkUpdatePlan, []store.Link, error) {
	row, err := s.renameSource(ctx, pageID)
	if err != nil {
		return LinkUpdatePlan{}, nil, err
	}
	if err := s.requirePageWrite(ctx, who, row.ID); err != nil {
		return LinkUpdatePlan{}, nil, err
	}
	if _, err := s.renameDestinationPath(row.Path, newName); err != nil {
		return LinkUpdatePlan{}, nil, err
	}

	plan := LinkUpdatePlan{
		NewName:   newName,
		Affected:  []LinkUpdatePage{},
		Conflicts: []LinkConflict{},
		Summary:   LinkUpdateSummary{},
	}
	recorded, err := store.ListLinksToPage(ctx, s.db.Reader(), row.ID)
	if err != nil {
		return LinkUpdatePlan{}, nil, fmt.Errorf("httpapi: read the references to a page: %w", err)
	}
	plan.OldName = renameOldName(row.Path, newName, recorded)
	if len(recorded) == 0 {
		return plan, recorded, nil
	}

	// One pass to resolve each referring page once — its row, its owners, its
	// secret rows — and one pass to decide which of its occurrences this reader
	// is allowed to know about at all.
	type referring struct {
		page     LinkUpdatePage
		secrets  map[string]store.SecretRow
		isOwner  bool
		vanished bool
	}
	state := make(map[int64]*referring, 4)
	order := make([]int64, 0, 4)
	for _, l := range recorded {
		ref, ok := state[l.SourcePageID]
		if !ok {
			ref = &referring{secrets: map[string]store.SecretRow{}}
			src, srcErr := store.GetPageByID(ctx, s.db.Reader(), l.SourcePageID)
			switch {
			case srcErr == nil:
				ref.page = LinkUpdatePage{PageID: src.ID, Path: src.Path, Occurrences: []LinkOccurrence{}}
				owner, ownerErr := store.IsPageOwner(ctx, s.db.Reader(), src.ID, who.UserID)
				if ownerErr != nil {
					return LinkUpdatePlan{}, nil, fmt.Errorf("httpapi: read a page's owners: %w", ownerErr)
				}
				ref.isOwner = owner
				rows, secErr := store.ListSecretRowsByPage(ctx, s.db.Reader(), src.ID)
				if secErr != nil {
					return LinkUpdatePlan{}, nil, fmt.Errorf("httpapi: read a page's secrets: %w", secErr)
				}
				for _, sec := range rows {
					ref.secrets[sec.ID] = sec
				}
			case errors.Is(srcErr, store.ErrNoRows):
				// The referring page has gone from the index and the
				// reconciling scan has not caught up. It is listed with no
				// occurrences rather than dropped, because the count of affected
				// pages is a statement about the campaign.
				ref.vanished = true
				ref.page = LinkUpdatePage{PageID: l.SourcePageID, Path: "", Occurrences: []LinkOccurrence{}}
			default:
				return LinkUpdatePlan{}, nil, fmt.Errorf("httpapi: read a referring page: %w", srcErr)
			}
			state[l.SourcePageID] = ref
			order = append(order, l.SourcePageID)
		}
		if ref.vanished {
			continue
		}
		if !isAffectedReference(l) {
			continue
		}
		if l.SecretID != "" && !occurrenceVisible(who, ref.isOwner, ref.secrets[l.SecretID]) {
			continue
		}
		ref.page.Occurrences = append(ref.page.Occurrences, LinkOccurrence{
			Line:      l.Line,
			ByteStart: l.ByteStart,
			ByteLen:   l.ByteLen,
			Found:     l.TargetRaw,
		})
	}

	for _, id := range order {
		ref := state[id]
		ref.page.Count = len(ref.page.Occurrences)
		if ref.page.Count == 0 {
			// Every occurrence on this page was inside a secret this reader may
			// not see. The page contributes nothing at all — not a row, not a
			// count — because the fact that it refers to this page at all is
			// part of what the secret holds.
			continue
		}
		if !ref.vanished {
			writable, err := s.mayWritePage(ctx, who, id)
			if err != nil {
				return LinkUpdatePlan{}, nil, err
			}
			ref.page.CanWrite = writable
			if !writable {
				plan.Summary.Unwritable++
				plan.Conflicts = append(plan.Conflicts, LinkConflict{
					PageID: id, Path: ref.page.Path, Reason: SkipNoPermission,
					Message: "this reader may not write " + ref.page.Path,
				})
			}
		}
		plan.Summary.Pages++
		plan.Summary.Links += ref.page.Count
		plan.Affected = append(plan.Affected, ref.page)
	}

	conflicts, err := s.verifyOccurrences(ctx, plan.Affected, recorded, plan.OldName, newName)
	if err != nil {
		return LinkUpdatePlan{}, nil, err
	}
	plan.Conflicts = append(plan.Conflicts, conflicts...)
	plan.Summary.Conflicts = len(plan.Conflicts)
	return plan, recorded, nil
}

// ApplyLinkUpdate performs the confirmed bulk rewrite §5.6 describes and reports
// every page and every occurrence it left alone.
//
// The order is the algorithm's and each step gates the next: re-derive the
// affected set rather than trusting a stored plan, ask the policy about each
// page, read the file and verify the recorded bytes, splice only the target
// token, write atomically through the one writer, reindex, and move on. A
// failure on one page is a row in Details and not a reason to stop, because a
// rename that rewrote four of five pages and reported nothing is worse than one
// that rewrote four and said why the fifth is untouched.
func (s *Server) ApplyLinkUpdate(ctx context.Context, who authz.Principal, pageID int64, newName string) (LinkUpdateResult, error) {
	plan, recorded, err := s.planLinkUpdate(ctx, who, pageID, newName)
	if err != nil {
		return LinkUpdateResult{}, err
	}
	out := LinkUpdateResult{Details: []LinkUpdateDetail{}}

	byPage := make(map[int64][]store.Link, len(plan.Affected))
	for _, l := range recorded {
		byPage[l.SourcePageID] = append(byPage[l.SourcePageID], l)
	}

	for _, page := range plan.Affected {
		rows := byPage[page.PageID]
		switch {
		case !page.CanWrite:
			out.Skipped++
			out.Details = append(out.Details, LinkUpdateDetail{
				Path: page.Path, Reason: SkipNoPermission,
				Message: "this reader may not write " + page.Path,
			})
			continue
		case vault.Ignored(page.Path):
			// Defence in depth. The path came from the index rather than from a
			// request, so this should be unreachable; the writer would move the
			// app's own state if it were, and a check that is only ever made in
			// one place is a check the next caller forgets.
			out.Skipped++
			out.Details = append(out.Details, LinkUpdateDetail{
				Path: page.Path, Reason: SkipAppState,
				Message: "the path is the application's own state and is never rewritten",
			})
			continue
		}
		src, readErr := s.readPage(ctx, page.Path)
		if readErr != nil {
			out.Skipped++
			out.Details = append(out.Details, LinkUpdateDetail{
				Path: page.Path, Reason: SkipUnreadable,
				Message: "the file could not be read, so nothing in it was changed",
			})
			continue
		}
		rewritten, applied, refused := rewritePageLinks(src, page.Path, rows, plan.OldName, newName)
		// The refusals are reported per occurrence whether or not the rest of the
		// page was rewritten, so a file with four good links and one conflict
		// does not read as a clean success.
		out.Details = append(out.Details, refused...)
		if applied == 0 {
			out.Skipped++
			if len(refused) == 0 {
				out.Details = append(out.Details, LinkUpdateDetail{
					Path: page.Path, Reason: SkipNothingToDo,
					Message: "every reference on this page was refused, so the file is unchanged",
				})
			}
			continue
		}
		if err := s.writer.Save(ctx, vault.SaveRequest{
			Path:            page.Path,
			NewContent:      rewritten,
			BaseContentHash: vault.Hash(src),
			ActorID:         who.UserID,
			ExpectPerm:      authz.PermWritePage,
		}); err != nil {
			out.Skipped++
			out.Details = append(out.Details, LinkUpdateDetail{
				Path: page.Path, Reason: SkipWriteFailed,
				Message: "the file could not be written, so it is unchanged",
			})
			s.log.WarnContext(ctx, "a page's references could not be rewritten",
				"action", "http.update_links", "request_id", obs.RequestID(ctx),
				"path", page.Path, "err", logRecord(err).String())
			continue
		}
		if err := s.reindexer.Reindex(ctx, page.Path); err != nil {
			// The bytes are on disk and correct; the index is stale for at most a
			// reconciliation interval, and failing here would report a rewrite
			// that happened as one that did not.
			s.log.WarnContext(ctx, "a rewritten page could not be reindexed",
				"action", "http.update_links", "request_id", obs.RequestID(ctx), "path", page.Path)
		}
		out.Updated++
	}
	return out, nil
}

// rewritePageLinks returns the file with its recorded references rewritten, how
// many were applied, and one report row per refusal.
//
// The edit list is md.LinkEdits' and the selection is the recorded rows', and
// the order matters. md.LinkEdits knows the rules this file must not re-decide —
// that a link inside a secret is never an edit, that a self-reference names no
// page, that a .md on a relative destination is carried across, that a fragment
// stays where it is — and it locates every target token by verifying the bytes
// at the range before it returns one. The recorded rows know *which* references
// the index holds for this page, and an occurrence with no recorded byte range
// is one this function must refuse rather than guess at.
//
// Intersecting the two means neither can talk the other into something it would
// not do alone, and md.RewriteLinks then re-verifies the bytes once more against
// the caller's own read, which is what makes a file edited between the index and
// here a conflict rather than a corruption.
func rewritePageLinks(src []byte, path string, recorded []store.Link, oldName, newName string) ([]byte, int, []LinkUpdateDetail) {
	doc := md.Parse(path, src)
	facts, _ := md.Extract(doc, nil)
	edits := md.LinkEdits(doc, facts, oldName, newName)

	// Offsets md located, so a recorded occurrence is matched against the
	// freshly-located token rather than against nothing.
	byRange := make(map[[2]int]md.LinkEdit, len(edits))
	for _, e := range edits {
		byRange[[2]int{e.Offset, e.Offset + e.Length}] = e
	}

	keep := make([]md.LinkEdit, 0, len(edits))
	refused := make([]LinkUpdateDetail, 0, 4)
	for _, l := range recorded {
		// The same filter the plan applied, so the apply cannot report a refusal
		// the preview never listed. A self-reference and an attachment are not
		// references to the page's name; a plan that counted them and an apply
		// that reported them would be two different answers to one question.
		if !isAffectedReference(l) {
			continue
		}
		switch {
		case l.ByteLen <= 0:
			// Not "at offset 0". A recorded length of zero is the absence of a
			// recording, and rewriting there would replace the first bytes of the
			// file with a link target.
			refused = append(refused, LinkUpdateDetail{
				Path: path, Reason: ConflictUnrecorded,
				Message: fmt.Sprintf("line %d: the index recorded no byte range for this reference, so it cannot be rewritten safely", l.Line),
			})
		case l.ByteStart < 0 || l.ByteStart+l.ByteLen > len(src):
			refused = append(refused, LinkUpdateDetail{
				Path: path, Reason: ConflictOutOfRange,
				Message: fmt.Sprintf("line %d: the recorded byte range is not inside this file", l.Line),
			})
		default:
			e, ok := byRange[[2]int{l.ByteStart, l.ByteStart + l.ByteLen}]
			if !ok {
				reason, message := unlocatableReason(doc, l, src)
				refused = append(refused, LinkUpdateDetail{Path: path, Reason: reason, Message: message})
				continue
			}
			keep = append(keep, e)
		}
	}

	out, problems := md.RewriteLinks(doc, keep)
	applied := len(keep)
	for _, p := range problems {
		applied--
		reason, message := rewriterRefusal(p)
		refused = append(refused, LinkUpdateDetail{Path: path, Reason: reason, Message: message})
	}
	return out, applied, refused
}

// unlocatableReason names why a recorded occurrence produced no edit even though
// its range is inside the file.
//
// Three answers, and which one applies is the difference between a report a
// reader can act on and one that sends them to look in the wrong place. A range
// inside a secret is a rule about bytes. A range whose bytes are no longer the
// recorded target is a stale record. A range that is current, holds no secret and
// still produced no edit is a reference the rename does not touch — an escaped
// spelling that resolves to the page, which is not a spelling this operation can
// rewrite without guessing.
func unlocatableReason(doc *md.Doc, l store.Link, src []byte) (string, string) {
	if l.SecretID != "" || insideSecret(doc, l.ByteStart, l.ByteStart+l.ByteLen) {
		return ConflictInsideSecret,
			fmt.Sprintf("line %d: this reference is written inside a secret, and a secret's bytes are never rewritten", l.Line)
	}
	if l.ByteStart+l.ByteLen <= len(src) && !bytes.Equal(src[l.ByteStart:l.ByteStart+l.ByteLen], []byte(linkToken(l))) {
		return ConflictStale,
			fmt.Sprintf("line %d: the bytes at the recorded offset are not the recorded target, so the file changed after it was indexed", l.Line)
	}
	return ConflictUnmatched,
		fmt.Sprintf("line %d: this reference reaches the page as %q, which is not a spelling of its name, so the rename leaves it alone", l.Line, l.TargetRaw)
}

// rewriterRefusal maps a md rewriter problem onto a report row.
//
// The reason is one of the same constants the preview uses, so a reader who
// compared the two is comparing like with like, and the message names a line
// number and nothing else about the file.
func rewriterRefusal(p md.Problem) (string, string) {
	switch p.Code {
	case md.ProblemLinkStale:
		return ConflictStale,
			fmt.Sprintf("line %d: the bytes at the recorded link offset are not the recorded target, so it was left alone", p.Line)
	case md.ProblemLinkOutOfRange:
		return ConflictOutOfRange,
			fmt.Sprintf("line %d: the recorded byte range is not inside this file", p.Line)
	case md.ProblemLinkOverlap:
		return ConflictOverlapping,
			fmt.Sprintf("line %d: two references claim the same bytes, so neither was rewritten", p.Line)
	default:
		return ConflictStale,
			fmt.Sprintf("line %d: the reference was not rewritten", p.Line)
	}
}

// insideSecret reports whether any secret span of the document covers any part
// of [start, end).
//
// The test is on the intersection rather than on the start offset, because a
// range that only partly overlaps a fence is as much a disclosure as one wholly
// inside it, and md.LinkEdits makes the same test. It is repeated here so that a
// recorded occurrence md did not produce is still *classified* correctly rather
// than reported as merely stale.
func insideSecret(doc *md.Doc, start, end int) bool {
	if end <= start {
		return false
	}
	for _, s := range doc.SecretSpans() {
		if s.SecretID != "" && s.StartByte < end && start < s.EndByte {
			return true
		}
	}
	return false
}

// verifyOccurrences reads each affected page and records every occurrence the
// updater will not rewrite, which is the preview's conflict list.
//
// The check runs in the preview as well as the apply, and it reuses the apply's
// own classifier rather than a second one. A preview that reported no conflicts
// and an apply that reported four would be a preview that lied, and the reason
// the plan has a conflict list at all is that the reader is shown the diff before
// agreeing to it. Two classifiers would be two answers to one question, and the
// one that drifted would be the one nobody noticed.
func (s *Server) verifyOccurrences(ctx context.Context, pages []LinkUpdatePage, recorded []store.Link, oldName, newName string) ([]LinkConflict, error) {
	byPage := make(map[int64][]store.Link, len(pages))
	for _, l := range recorded {
		byPage[l.SourcePageID] = append(byPage[l.SourcePageID], l)
	}
	var out []LinkConflict
	for _, page := range pages {
		src, err := s.readPage(ctx, page.Path)
		if err != nil {
			continue
		}
		doc := md.Parse(page.Path, src)
		facts, _ := md.Extract(doc, nil)
		rewritable := make(map[[2]int]bool)
		for _, e := range md.LinkEdits(doc, facts, oldName, newName) {
			rewritable[[2]int{e.Offset, e.Offset + e.Length}] = true
		}
		for _, l := range byPage[page.PageID] {
			if !isAffectedReference(l) {
				continue
			}
			reason, ok := occurrenceVerdict(src, l, rewritable)
			if !ok {
				continue
			}
			out = append(out, LinkConflict{
				PageID: page.PageID, Path: page.Path, Line: l.Line, Found: l.TargetRaw,
				Reason: reason, Message: conflictMessage(reason),
			})
		}
	}
	return out, nil
}

// occurrenceVerdict reports a conflict reason for a recorded occurrence, or "" and
// false when the updater will rewrite it.
//
// rewritable is the set of ranges md.LinkEdits produced for this document, so
// the last case can tell "the file moved underneath the record" from "this
// spelling is not a spelling of the name" — two different answers for a reader
// and two different fixes.
func occurrenceVerdict(src []byte, l store.Link, rewritable map[[2]int]bool) (string, bool) {
	switch {
	case l.ByteLen <= 0:
		return ConflictUnrecorded, true
	case l.ByteStart < 0 || l.ByteStart+l.ByteLen > len(src):
		return ConflictOutOfRange, true
	case !bytes.Equal(src[l.ByteStart:l.ByteStart+l.ByteLen], []byte(linkToken(l))):
		return ConflictStale, true
	case !rewritable[[2]int{l.ByteStart, l.ByteStart + l.ByteLen}]:
		return ConflictUnmatched, true
	}
	return "", false
}

// linkToken is the bytes a recorded range covers, which is the target *token* and
// not store's TargetRaw.
//
// The two differ, and the difference is a fragment: for `[[Tavern#The Cellar]]`
// the range covers `Tavern` and TargetRaw is `Tavern#The Cellar`, because the
// fragment is part of the reference and the page part is the part a rename
// replaces. Comparing a range against TargetRaw would find six bytes of `Tavern`
// unequal to nineteen bytes of `Tavern#The Cellar` and call every heading
// reference in the campaign a conflict.
//
// The fragment is removed by matching the suffix md recorded, not by splitting
// on the first '#': a page's name is allowed to contain one, and guessing where
// the fragment starts is exactly the kind of guess this whole feature refuses to
// make. A TargetRaw with no recorded fragment is returned unchanged.
func linkToken(l store.Link) string {
	for _, frag := range []string{l.Heading, l.BlockRef} {
		if frag == "" {
			continue
		}
		if suffix := "#" + frag; strings.HasSuffix(l.TargetRaw, suffix) {
			return strings.TrimSuffix(l.TargetRaw, suffix)
		}
	}
	return l.TargetRaw
}

// isSelfReference reports whether a recorded reference names a position inside
// the page it is written in rather than the page itself.
//
// A `[[#heading]]` or `[x](#anchor)` names a position inside the page it is
// written in, not the page's name, so a rename cannot affect it and counting it
// would tell a reader that the renamed page refers to itself. store.Link does not
// carry md's SelfLink flag — it is not a column — so the leading '#' is the
// signal the store has, and by the grammar a target that begins with one is never
// a path.
func isSelfReference(l store.Link) bool {
	return strings.HasPrefix(l.TargetRaw, "#")
}

// isAffectedReference reports whether a recorded reference is one a rename
// could possibly act on: a page reference, and not a self-reference.
//
// One predicate for the plan, the preview's verifier and the rename's re-pointing
// pass, because those three answer one question — "is this reference to the
// page's name?" — and three functions would be three answers.
func isAffectedReference(l store.Link) bool {
	if isSelfReference(l) {
		return false
	}
	switch l.Kind {
	case store.LinkWikilink, store.LinkEmbed, store.LinkMarkdown:
		return true
	}
	return false
}

// conflictMessage is the reader-facing form of a conflict reason, with no line
// number and no content: the same phrase is used wherever the reason is shown
// without knowing which line it is about.
func conflictMessage(reason string) string {
	switch reason {
	case ConflictStale:
		return "the file changed after this reference was indexed, so it was left alone"
	case ConflictUnrecorded:
		return "this reference has no recorded byte range, so it cannot be rewritten safely"
	case ConflictOutOfRange:
		return "the recorded byte range is not inside the file"
	case ConflictInsideSecret:
		return "this reference is written inside a secret, and a secret's bytes are never rewritten"
	case ConflictOverlapping:
		return "two references claim the same bytes, so neither was rewritten"
	case ConflictUnmatched:
		return "this reference reaches the page by a spelling that is not its name, so the rename leaves it alone"
	default:
		return "this reference was not rewritten"
	}
}

// renameSource loads the page a rename names and refuses anything that is not
// campaign content.
func (s *Server) renameSource(ctx context.Context, pageID int64) (store.Page, error) {
	row, err := store.GetPageByID(ctx, s.db.Reader(), pageID)
	if err != nil {
		return store.Page{}, fmt.Errorf("httpapi: load the page to rename: %w", err)
	}
	// vault.Ignored on a reachable path, before anything reads it. A rename naming
	// .semiplane/semiplane.lock would otherwise move the lock the running
	// process still believes it holds, which is a second instance away.
	if vault.Ignored(row.Path) {
		return store.Page{}, fmt.Errorf("%w: %s", secrets.ErrAppState, row.Path)
	}
	return row, nil
}

// renameTarget validates a request into the page to rename and the path it
// should answer to.
//
// The order is the authorization order the whole feature has: load the page,
// refuse the app's own state, ask the policy about the page, and only then look
// at what the caller asked to call it. A destination is never resolved before
// the source's write access is known, so a request that names a page the caller
// may not write learns nothing about a path that does not exist yet.
func (s *Server) renameTarget(ctx context.Context, who authz.Principal, pageID int64, rawName string) (store.Page, string, error) {
	row, err := s.renameSource(ctx, pageID)
	if err != nil {
		return store.Page{}, "", err
	}
	if err := s.requirePageWrite(ctx, who, row.ID); err != nil {
		return store.Page{}, "", err
	}
	name := strings.TrimSpace(rawName)
	if name == "" || len(name) > maxRenameNameBytes {
		return store.Page{}, "", errBadRenameName
	}
	newRel, err := s.renameDestinationPath(row.Path, name)
	if err != nil {
		return store.Page{}, "", err
	}
	return row, newRel, nil
}

// requirePageWrite refuses a principal that may not write the page a rename or
// an update is about.
//
// The route table's Perm is a coarse gate and this is the question it cannot
// ask: whether *this* principal holds writePage on *this* page. It goes through
// the shared s.mayWritePage — the same page-scoped gate the editor's save path
// asks — and it is asked once, before the operation reads a file or records an
// occurrence.
//
// It is a function rather than an inline sequence precisely so that the two
// features that need it ask the same question: a page the editor will not let
// you save and a page the updater will not let you rewrite are one decision, and
// two implementations of it would be two answers.
func (s *Server) requirePageWrite(ctx context.Context, who authz.Principal, pageID int64) error {
	ok, err := s.mayWritePage(ctx, who, pageID)
	if err != nil {
		return err
	}
	if !ok {
		return authz.ErrDenied
	}
	return nil
}

// occurrenceVisible applies the secret visibility rule to one recorded
// occurrence, in Go.
//
// The rule is authz.CanReadSecret's, which is the rule authz.SecretVisibleSQL
// implements and which the store already applies to the backlinks and
// broken-links panels. It is applied here rather than in a query because this
// package may not add a store function, and a filter placed before the row is
// built is the same guarantee as one in SQL: the row never exists, so it cannot
// be rendered, counted or logged.
//
// A secret the index has no row for is treated as unreadable. That is the
// fail-closed direction: an occurrence attributed to a fence the index does not
// know is most often one the file has moved on from, and a stale record must not
// be the way a body becomes visible.
func occurrenceVisible(who authz.Principal, isPageOwner bool, sec store.SecretRow) bool {
	if sec.ID == "" {
		return true
	}
	return authz.CanReadSecret(who, isPageOwner, sec.AuthorID, authz.Visibility(sec.Visibility))
}

// referrer is one page that referenced a page the rename has just moved.
type referrer struct {
	path   string
	pageID int64
}

// referrerPaths are the pages that reference a page.
//
// It is the same set the indexer's own rename detection collects into its
// vanished window, read from the same table, and a rename through the app needs
// it for the reason in RenamePage: removing the departed row un-points every
// reference to it, and only the rename knows which references those were.
func (s *Server) referrerPaths(ctx context.Context, pageID int64) ([]referrer, error) {
	links, err := store.ListLinksToPage(ctx, s.db.Reader(), pageID)
	if err != nil {
		return nil, fmt.Errorf("httpapi: read the references to a page: %w", err)
	}
	seen := make(map[int64]bool, len(links))
	out := make([]referrer, 0, len(links))
	for _, l := range links {
		if seen[l.SourcePageID] {
			continue
		}
		seen[l.SourcePageID] = true
		row, err := store.GetPageByID(ctx, s.db.Reader(), l.SourcePageID)
		if err != nil {
			// A referring page that has gone from the index is not a rename
			// failure; the reconciling scan will report it.
			continue
		}
		out = append(out, referrer{path: row.Path, pageID: row.ID})
	}
	return out, nil
}

// orphanedLinkIDs are the links rows a page wrote in one of the names a rename
// has just carried to a new page, and which are now dangling.
//
// They are found by name rather than remembered from before the move, because
// the rows that pointed at the departed page are exactly the ones whose
// target_page_id the delete set to NULL — the set is recoverable from the file's
// own current rows and there is no need to have been watching. A row qualifies
// when it points at no page, is one of the three page-reference kinds, is not a
// self-reference, and carries one of the names the departed page answered to.
//
// A reference that was already dangling before the rename and happens to spell
// one of those names is included, and re-pointing it is the right answer anyway:
// the page that answers to that name is now this one, which is what resolution
// would say on the next pass. A row that resolves to some *other* page is not
// touched, because a rename is not a reason to overrule a resolution that
// succeeded.
func orphanedLinkIDs(ctx context.Context, q store.Queryer, pageID int64, names []string) ([]int64, error) {
	rows, err := store.ListLinksByPage(ctx, q, pageID)
	if err != nil {
		return nil, fmt.Errorf("httpapi: read a page's own references: %w", err)
	}
	var out []int64
	for _, l := range rows {
		if l.TargetPageID != nil || !isAffectedReference(l) {
			continue
		}
		token := linkToken(l)
		for _, name := range names {
			if strings.EqualFold(token, name) {
				out = append(out, l.ID)
				break
			}
		}
	}
	return out, nil
}

// aliasesToCarry returns the names the departed page answered to: its own
// basename first, then every alias its row held.
//
// The basename is the one the rename itself creates — the plan's "on a confirmed
// rename the old basename is inserted into page_aliases" — and it is first
// because it is the spelling a reference in somebody else's prose is most likely
// to use, so a client listing the result should show it first.
//
// The rest is the indexer's own rule for a rename it detects by itself: the whole
// alias set carried across rather than one name, because a page renamed twice
// would otherwise lose the first name when the intermediate row went away, and
// the first name is exactly the reference that has to keep working.
func (s *Server) aliasesToCarry(ctx context.Context, row store.Page) ([]string, error) {
	rows, err := store.ListPageAliases(ctx, s.db.Reader(), row.ID)
	if err != nil {
		return nil, fmt.Errorf("httpapi: read a page's aliases: %w", err)
	}
	seen := make(map[string]bool, len(rows)+1)
	out := make([]string, 0, len(rows)+1)
	for _, a := range append([]string{md.Basename(row.Path)}, rows...) {
		if a = strings.TrimSpace(a); a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// renameDestinationPath turns a requested name into a vault-relative path.
//
// The name is accepted as a path rather than as a bare name so that moving a
// page between folders is the same operation as renaming it, and so that the
// traversal cases are refused by vault.Resolve — the one function that
// establishes containment — rather than by a character check written here.
// Resolve also refuses a path that leaves the vault, and vault.Ignored refuses
// the app's own state, and neither check can be skipped by calling this from
// anywhere else.
func (s *Server) renameDestinationPath(from, newName string) (string, error) {
	rel, err := renameRelPath(newName)
	if err != nil {
		return "", err
	}
	resolved, err := vault.Resolve(s.root, rel)
	if err != nil {
		return "", fmt.Errorf("%w: the new name is not a path inside the vault", vault.ErrOutsideVault)
	}
	if resolved.IsDir() {
		return "", fmt.Errorf("%w: the new name is a directory", secrets.ErrAppState)
	}
	if vault.Ignored(resolved.Rel()) {
		return "", fmt.Errorf("%w: %s", secrets.ErrAppState, resolved.Rel())
	}
	if resolved.Rel() == from {
		return "", errBadRenameName
	}
	return resolved.Rel(), nil
}

// renameRelPath validates a requested new name and gives it the .md extension
// when it does not have one.
//
// The extension is appended rather than required because the name a reader
// types is the name a wikilink uses, which has no extension, and a page called
// "Inn.md.md" because a form wanted an extension is a page nobody links to. A
// name that already ends in .md is left alone, case included: a file is `.md`
// and not `.MD`.
func renameRelPath(newName string) (string, error) {
	name := strings.TrimSpace(newName)
	if name == "" {
		return "", errBadRenameName
	}
	if len(name) > maxRenameNameBytes {
		return "", errBadRenameName
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return "", errBadRenameName
		}
	}
	// A last element made only of dots is not a name. `.` and `..` are the two
	// directory entries, and this function is about to append an extension, so
	// without this a rename to ".." would create a file called `...md` rather
	// than being refused as the traversal it is.
	leaf := name
	if i := strings.LastIndexByte(leaf, '/'); i >= 0 {
		leaf = leaf[i+1:]
	}
	if leaf == "" || strings.Trim(leaf, ".") == "" {
		return "", errBadRenameName
	}
	if !strings.HasSuffix(name, ".md") {
		name += ".md"
	}
	return name, nil
}

// renameOldName is the name the affected references were written against.
//
// Before the move it is the page's own basename, which is the spelling the
// references use. After the move the page answers to the new name and the old
// one survives only as an alias, so the name is read off the affected set: one
// distinct spelling is that name, and several spellings are not one name at all,
// so the answer is empty and the per-occurrence Found fields carry the detail.
// An empty OldName is a legitimate answer — it says the references do not all
// agree on a name, not that there are none.
func renameOldName(pagePath, newName string, links []store.Link) string {
	base := md.Basename(pagePath)
	if !strings.EqualFold(strings.TrimSuffix(base, ".md"), strings.TrimSuffix(newName, ".md")) {
		return base
	}
	found := ""
	for _, l := range links {
		if found == "" {
			found = l.TargetRaw
			continue
		}
		if !strings.EqualFold(found, l.TargetRaw) {
			return ""
		}
	}
	return found
}

// linkUpdaterPointer names the two calls that finish a rename. The preview is a
// GET and needs the new name; the update is a POST and needs the new name and
// the word "confirmed", which the reader supplies by pressing the button the
// diff is drawn above.
func linkUpdaterPointer(pageID int64, newName string) LinkUpdaterPointer {
	query := url.Values{renameFormName: []string{newName}}.Encode()
	base := "/api/pages/" + strconv.FormatInt(pageID, 10)
	return LinkUpdaterPointer{
		Preview: base + "/rename-preview?" + query,
		Update:  base + "/update-links",
	}
}

// renamePageID is the {id} the three routes share, refused as a 404 when it is
// not a page id at all — a 400 would confirm that the address is one this route
// understands, which is itself a fact about the campaign's internals.
func renamePageID(s *Server, w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, r, http.StatusNotFound)
		return 0, false
	}
	return id, true
}

// errBadRenameName is the internal marker for a name that cannot be a page's
// path: empty, too long, holding a control character, naming a directory, or
// naming the page it already has. It is not authz.ErrDenied and it is not a
// vault error, because none of those is what went wrong.
var errBadRenameName = errors.New("the new name is not a page path this vault will answer to")

// writePlanError answers a rename or a link update that could not be carried
// out.
//
// The refusals are a 404 and a 403 and nothing else carries a reason, for the
// reason pageSummary gives: a body that differed between "no such page" and
// "not yours" would be a probe. A name that will not resolve and a path that
// names the app's own state are a 400, which says the request was wrong and
// nothing at all about the campaign. A lost race is a 409 and nothing else:
// the file changed between this request's read and the writer's, which the
// reader can retry, and calling it a 404 would tell them the page is gone.
func (s *Server) writePlanError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNoRows), errors.Is(err, vault.ErrNotFound):
		s.writeError(w, r, http.StatusNotFound)
	case errors.Is(err, authz.ErrDenied), errors.Is(err, vault.ErrNotPermitted):
		s.writeError(w, r, http.StatusForbidden)
	case errors.Is(err, errBadRenameName), errors.Is(err, secrets.ErrAppState), errors.Is(err, vault.ErrOutsideVault):
		s.writeError(w, r, http.StatusBadRequest)
	case errors.Is(err, vault.ErrConflict):
		s.writeError(w, r, http.StatusConflict)
	default:
		s.log.ErrorContext(r.Context(), "a rename could not be carried out",
			"action", "http.rename", "request_id", obs.RequestID(r.Context()),
			"route", RouteFrom(r.Context()), "err", logRecord(err).String())
		s.writeError(w, r, http.StatusInternalServerError)
	}
}
