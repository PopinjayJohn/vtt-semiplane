package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// failingReindexer is a Reindexer that refuses, so a test can assert that a
// write whose derivation failed is reported rather than left as a file the app
// has stopped agreeing with.
type failingReindexer struct{}

func (failingReindexer) Reindex(context.Context, string) error {
	return errors.New("the indexer is not available")
}

// TestThePageEntryPointsRefuseAnonymousPrincipals covers the gate that runs
// before any lookup on all four of them. Anonymous read is off in this harness,
// so these are the refusals a deployment without it makes — and they are the ones
// that must cost a signed-out caller nothing: no page id enumeration, no
// existence oracle, nothing written.
func TestThePageEntryPointsRefuseAnonymousPrincipals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	id := pageID(t, h, "Page.md")
	anon := authz.Anonymous(true)
	before := h.vault.ReadFile(t, "Page.md")
	indexes := h.reindexes.Load()

	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{"edit view", func() error { _, err := h.svc.EditView(ctx, anon, id); return err }},
		{"save", func() error {
			// PermSession refuses an anonymous principal with its own sentinel,
			// because a player who may write pages has to have an account. The
			// assertion below accepts either, so this stays a single table.
			return h.svc.Save(ctx, anon, id, []byte("# replaced\n"), vault.Hash(before))
		}},
		{"revert", func() error { return h.svc.Revise(ctx, anon, id, 1) }},
		{"events", func() error { _, err := h.svc.EventsFor(ctx, anon, secretID); return err }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.do()
			if !errors.Is(err, authz.ErrDenied) && !errors.Is(err, authz.ErrNotAuthenticated) {
				t.Fatalf("the error is %v, want a refusal from the policy", err)
			}
			if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
				t.Fatal("a refused call changed the file")
			}
			if h.reindexes.Load() != indexes {
				t.Fatal("a refused call re-indexed")
			}
		})
	}
	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{"revision", func() error { _, err := h.svc.Revision(ctx, anon, id, 1); return err }},
		{"history", func() error { _, err := h.svc.History(ctx, anon, id); return err }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(); !errors.Is(err, authz.ErrDenied) {
				t.Fatalf("the error is %v, want authz.ErrDenied", err)
			}
		})
	}
}

// TestThePageEntryPointsRefuseAPageThatDoesNotExist asserts the shape of a
// missing page on all four entry points, and that none of them wrote anything
// while finding out.
func TestThePageEntryPointsRefuseAPageThatDoesNotExist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	const missing = 987654321

	if _, err := h.svc.EditView(ctx, h.dm(), missing); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("edit view returned %v, want ErrNoRows", err)
	}
	if err := h.svc.Save(ctx, h.dm(), missing, []byte("# x\n"), vault.Hash(nil)); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("save returned %v, want ErrNoRows", err)
	}
	if _, err := h.svc.Revision(ctx, h.dm(), missing, 1); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("revision returned %v, want ErrNoRows", err)
	}
	if err := h.svc.Revise(ctx, h.dm(), missing, 1); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("revert returned %v, want ErrNoRows", err)
	}
	if _, err := h.svc.History(ctx, h.dm(), missing); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("history returned %v, want ErrNoRows", err)
	}
	if h.reindexes.Load() != 0 {
		t.Error("a missing page still reached the indexer")
	}
}

// TestALostSaveRaceCarriesNoBytes is the save path's version of the reveal path's
// TestALostRaceIsSafe. vault.ConflictError carries BOTH versions of the file, and
// on a page with a secret fence one of them is a secret body in plaintext, so the
// mapping to a RaceLostError has to hold here too.
func TestALostSaveRaceCarriesNoBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)
	view, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	before := h.vault.ReadFile(t, "Page.md")

	// A stale hash is the optimistic-concurrency loss, arrived at from the other
	// direction: somebody else wrote after the editor was built.
	stale := append([]byte(nil), view.BaseHash...)
	stale[0] ^= 0xff

	err = h.svc.Save(ctx, h.player(), id, view.Content, stale)
	if !errors.Is(err, vault.ErrConflict) {
		t.Fatalf("the error is %v, want vault.ErrConflict", err)
	}
	var conflict *vault.ConflictError
	if errors.As(err, &conflict) {
		t.Fatal("a lost save carries the file, which on a secret page is a secret body")
	}
	var lost *secrets.RaceLostError
	if !errors.As(err, &lost) {
		t.Fatalf("the error is %T, want *secrets.RaceLostError", err)
	}
	if !strings.Contains(lost.Error(), "Page.md") {
		t.Errorf("the error does not name the page: %q", lost)
	}
	assertNoFileContent(t, err.Error(), secretBody)
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a lost save changed the file")
	}
	if h.reindexes.Load() != 0 {
		t.Error("a lost save re-indexed")
	}
}

// TestASaveWhoseFileCannotBeWrittenIsReported covers the one writer failure that
// is not a conflict: the directory is made read-only, so the atomic write's temp
// file cannot be created. The file is canonical, so the service must say so
// rather than report a success it cannot back up.
func TestASaveWhoseFileCannotBeWrittenIsReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})

	before := h.vault.ReadFile(t, "Page.md")

	dir := filepath.Join(h.vault.Root, "nested")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	h.vault.WriteFile(t, "nested/Page.md", "# Nested\n\nText.\n")
	// The directory loses its write permission after the file exists: the atomic
	// write creates its temp file beside the target, so this is the one thing it
	// cannot do around.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	// A chmod is a request, and not every volume honours one: root ignores it,
	// Windows has no mode bit to set (os.Chmod toggles the read-only attribute
	// and nothing else), and a volume mounted without mode support ignores it
	// too. The refusal this test asserts is the one the filesystem produced, so
	// the refusal is attempted here first — a positive control, because a test
	// that assumed the directory was unwritable would go on to assert over a
	// save that succeeded and report it as "a save into an unwritable directory
	// was accepted", which sends a reader to the service when the service is
	// fine.
	if created, err := os.CreateTemp(dir, "semiplane-deny-probe-"); err == nil {
		_ = created.Close()
		t.Skip("this volume let a file be created in a directory whose mode is 0500, " +
			"so there is no unwritable directory here to refuse a save against")
	}
	h.indexAll()
	nested := pageID(t, h, "nested/Page.md")
	nestedView, err := h.svc.EditView(ctx, h.dm(), nested)
	if err != nil {
		t.Fatalf("nested edit view: %v", err)
	}

	if err := h.svc.Save(ctx, h.dm(), nested, []byte("# replaced\n"), nestedView.BaseHash); err == nil {
		t.Fatal("a save into an unwritable directory was accepted")
	}
	if got := h.vault.ReadFile(t, "nested/Page.md"); string(got) != "# Nested\n\nText.\n" {
		t.Fatalf("the unwritable file changed: %q", got)
	}
	// And nothing was indexed from a write that did not happen.
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("an unrelated page changed")
	}
}

// TestAWriteWhoseDerivationFailedIsReported is the other half of "the file is
// canonical and the index is derived": the file write succeeded, so the service
// must not pretend the save did not. The error names the path and the reason.
func TestAWriteWhoseDerivationFailedIsReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	id := pageID(t, h, "Page.md")

	svc, err := secrets.NewService(secrets.Options{
		DB: h.db, Writer: h.writer, Policy: authz.NewPolicy(false),
		Reindexer: failingReindexer{}, Log: h.log,
		Clock: func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	view, err := svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	edited := bytes.Replace(view.Content, []byte("Public after the fences."),
		[]byte("Public after the fences, edited."), 1)

	err = svc.Save(ctx, h.dm(), id, edited, view.BaseHash)
	if err == nil {
		t.Fatal("a save whose reindex failed was accepted")
	}
	if !strings.Contains(err.Error(), "Page.md") {
		t.Errorf("the error does not name the page: %q", err)
	}
	assertNoFileContent(t, err.Error(), secretBody)
	// The file was written, because the file is canonical and it is the index
	// that failed. Saying otherwise would send a DM looking for a save that is
	// there.
	if !bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte("fences, edited.")) {
		t.Error("the file does not hold the edit the service reported as failed")
	}
}

// TestASecondFenceClaimingOneSecretIdIsRefused is the case where the file must
// not be allowed to hold two fences for one secret: the index has one row per id,
// so the second fence is either invisible to every authorization decision or it
// overwrites the first. md.Splice catches this only for a hidden id, because
// that is the only id it is looking at.
func TestASecondFenceClaimingOneSecretIdIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	id := pageID(t, h, "Page.md")

	doubledView, err := h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	doubled := bytes.Replace(doubledView.Content,
		[]byte("Public after the fence.\n"),
		[]byte("Public after the fence.\n\n```secret id="+secretID+
			" visibility=dm author=dorn\nA second body.\n```\n"), 1)
	before := h.vault.ReadFile(t, "Page.md")

	err = h.svc.Save(ctx, h.dm(), id, doubled, doubledView.BaseHash)
	if !errors.Is(err, secrets.ErrRefusedSave) {
		t.Fatalf("the error is %v, want ErrRefusedSave", err)
	}
	var refused *secrets.SaveRefusedError
	if !errors.As(err, &refused) || refused.Problems[0].Code != secrets.ProblemDuplicateSecretID {
		t.Fatalf("the refusal is %+v, want one duplicate id", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a refused save changed the file")
	}
}

// TestANewFenceWithNoAddressableIdIsRefused: a fence whose id is not twelve hex
// characters cannot be revealed, revoked, indexed or audited, so accepting one
// from an editor would create content the app can hold but never manage. The
// indexer refuses to index it for the same reason.
func TestANewFenceWithNoAddressableIdIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": "# The Page\n\nPublic text.\n"})
	id := pageID(t, h, "Page.md")

	view, err := h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	bad := append(append([]byte(nil), view.Content...),
		[]byte("\n```secret id=1 visibility=dm author=dorn\nA body with no address.\n```\n")...)
	before := h.vault.ReadFile(t, "Page.md")

	err = h.svc.Save(ctx, h.dm(), id, bad, view.BaseHash)
	if !errors.Is(err, secrets.ErrRefusedSave) {
		t.Fatalf("the error is %v, want ErrRefusedSave", err)
	}
	var refused *secrets.SaveRefusedError
	if !errors.As(err, &refused) || refused.Problems[0].Code != secrets.ProblemUnaddressableID {
		t.Fatalf("the refusal is %+v, want one unaddressable id", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a refused save changed the file")
	}
	// A fence already on disk with no conforming id is left alone, because it is
	// already redacted and refusing would make the page uneditable. The editor
	// still reports the problem rather than hiding it.
	h.vault.WriteFile(t, "Page.md", "# The Page\n\nPublic text.\n\n```secret id=1 visibility=dm author=dorn\nAlready here.\n```\n")
	h.indexAll()
	id = pageID(t, h, "Page.md")
	view, err = h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view after a malformed fence: %v", err)
	}
	if err := h.svc.Save(ctx, h.dm(), id, view.Content, view.BaseHash); err != nil {
		t.Fatalf("a page holding a malformed fence became uneditable: %v", err)
	}
}

// TestASecretBodyEditIsRecordedWithoutMovingAuthorization is the body-edit case:
// the audit trail gets an edit row, and the authorization generation does NOT
// move, because a body edit changes the bytes for the principals who could
// already read them and changes nothing about who may read what. The reindex
// publishes the new bytes; the generation is for authorization changes.
func TestASecretBodyEditIsRecordedWithoutMovingAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	id := pageID(t, h, "Page.md")
	genBefore := mustGen(t, h)

	view, err := h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	edited := bytes.Replace(view.Content,
		[]byte("The vault door is oak and the key is with the mayor."),
		[]byte("The vault door is oak and the key is with the harbourmaster."), 1)

	if saveErr := h.svc.Save(ctx, h.dm(), id, edited, view.BaseHash); saveErr != nil {
		t.Fatalf("save: %v", saveErr)
	}
	after := h.vault.ReadFile(t, "Page.md")
	if !bytes.Contains(after, []byte("harbourmaster")) {
		t.Fatal("the edit was not written")
	}
	if bytes.Contains(after, []byte("mayor.")) {
		t.Error("the old body survived")
	}
	if got := mustGen(t, h); got != genBefore {
		t.Errorf("the authorization generation moved from %d to %d for a body edit", genBefore, got)
	}
	events, err := h.svc.EventsFor(ctx, h.dm(), secretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 1 || events[0].Action != store.SecretActionEdit {
		t.Fatalf("the trail is %+v, want one edit", events)
	}
	if events[0].FromVis != "dm" || events[0].ToVis != "dm" {
		t.Errorf("the edit event says %q -> %q, want dm -> dm", events[0].FromVis, events[0].ToVis)
	}
	if !bytes.Contains([]byte(events[0].Action), []byte("edit")) {
		t.Error("the event action is not edit")
	}
	// And the index followed the file.
	if got := h.text(`SELECT body FROM secrets WHERE id = ?`, secretID); !strings.Contains(got, "harbourmaster") {
		t.Errorf("the indexed body is %q", got)
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, secretID); n != 0 {
		t.Error("a dm body reached the search index")
	}
}

// TestTheSavePathReturnsItsDatabaseFailures asserts that every query on the way
// has an error path that is returned rather than swallowed, by closing the
// database under a service and calling everything. A nil error here would mean a
// save that reported success having changed nothing at all.
func TestTheSavePathReturnsItsDatabaseFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)
	revID := revisionIDs(t, h, id)[0]

	// Both principals are resolved while the database is still open: looking one
	// up afterwards would fail in the test rather than in the code under test.
	player, dm := h.player(), h.dm()
	view, err := h.svc.EditView(ctx, player, id)
	if err != nil {
		t.Fatalf("edit view before the failure: %v", err)
	}
	if err := h.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Cleanup(func() { _ = h.db.Close() })

	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{"edit view", func() error { _, err := h.svc.EditView(ctx, player, id); return err }},
		{"save", func() error {
			return h.svc.Save(ctx, player, id, view.Content, view.BaseHash)
		}},
		{"revision", func() error { _, err := h.svc.Revision(ctx, player, id, revID); return err }},
		{"history", func() error { _, err := h.svc.History(ctx, player, id); return err }},
		{"events", func() error { _, err := h.svc.EventsFor(ctx, dm, secretID); return err }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(); err == nil {
				t.Fatal("the call reported success with the database closed")
			}
		})
	}
	// A DM's Revise reaches the same failure, from the write side rather than the
	// read side, and it must not have written the file.
	if err := h.svc.Revise(ctx, dm, id, revID); err == nil {
		t.Fatal("a revert reported success with the database closed")
	}
	if !bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte(secretBody)) {
		t.Error("the file changed while the database was closed")
	}
}

// TestAFenceNamingAnAccountThatDoesNotExistIsHiddenFromEverybodyButADM asserts
// the fail-closed resolution of an unresolvable author. A private secret whose
// author names no account is readable by DMs and by page owners and by nobody
// else, because authorID 0 matches no principal's user id — which is the same
// reason the indexer refuses to index the fence at all.
func TestAFenceNamingAnAccountThatDoesNotExistIsHiddenFromEverybodyButADM(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const orphan = "888888888888"
	h := newHarness(t, map[string]string{
		"Page.md": "# The Page\n\n" +
			fenceBlock(orphan, "private", "nobody", "The ledger names a real family.") +
			"\nPublic after.\n",
	})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)

	// The page owner CAN read it, because `private` is readable by a page owner.
	// What the orphan breaks is the other half: there is no account to match, so
	// nobody gets in by being the author.
	view, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	if view.Mode != secrets.EditModeFull {
		t.Fatalf("a page owner got mode %v for a private orphan secret", view.Mode)
	}
	// A player who is not an owner, and not a DM, cannot.
	other, err := h.svc.EditView(ctx, authz.ForUser(h.admin().UserID, "mara", authz.RolePlayer, false), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	if other.Mode != secrets.EditModeRedacted {
		t.Fatalf("a non-owner got mode %v for an orphan secret", other.Mode)
	}
	if bytes.Contains(other.Content, []byte("real family")) {
		t.Fatal("the buffer carried an orphan secret's body")
	}
	// A DM can, and the index never held it for anybody else.
	if _, editViewErr := h.svc.EditView(ctx, h.dm(), id); editViewErr != nil {
		t.Fatalf("a dm could not read the page: %v", editViewErr)
	}
	if n := h.count(`SELECT COUNT(*) FROM secrets WHERE id = ?`, orphan); n != 0 {
		t.Error("an orphan fence was indexed")
	}
	// A DM round-trips the file unchanged. The save never touches the orphan's
	// author, because md.Splice restores the body byte for byte and the fence's
	// directive and digest are what say whether anything about it moved.
	before := h.vault.ReadFile(t, "Page.md")
	dmView, err := h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("dm edit view: %v", err)
	}
	if err := h.svc.Save(ctx, h.dm(), id, dmView.Content, dmView.BaseHash); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a no-op save changed the file")
	}
}

// TestAProblemInTheFileIsReportedByTheEditor asserts that EditView surfaces md's
// problem codes instead of swallowing them, because an author whose fence is
// hidden from them needs to know that a malformed directive is why.
func TestAProblemInTheFileIsReportedByTheEditor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// An unquoted title with a space reads as title=The plus two unknown keys,
	// which md reports and refuses to treat as a directive.
	h := newHarness(t, map[string]string{
		"Page.md": "# The Page\n\n```secret id=" + closedSecretID +
			" visibility=dm author=dorn created=2026-09-28T10:04:11Z title=The cellar key\n" +
			secretBody + "\n```\n",
	})
	id := pageID(t, h, "Page.md")
	view, err := h.svc.EditView(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	if len(view.Problems) == 0 {
		t.Fatal("the editor reported no problem for a malformed directive")
	}
	found := false
	for _, code := range view.Problems {
		if code == md.ProblemSecretUnknownKey || code == md.ProblemSecretBadDirective {
			found = true
		}
	}
	if !found {
		t.Errorf("the reported codes are %v, want one naming the directive", view.Problems)
	}
	// The body is still redacted for a principal who cannot read it, whatever the
	// directive says — fail-closed is the direction §6 requires.
	if _, editViewErr := h.svc.EditView(ctx, h.player(), id); editViewErr != nil {
		t.Fatalf("player edit view: %v", editViewErr)
	}
	player, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("player edit view: %v", err)
	}
	if bytes.Contains(player.Content, []byte(secretBody)) {
		t.Error("a malformed directive turned a dm secret public")
	}
}

// TestAPlayerMayNotEditASecretSomebodyElseAuthored is the edit half of §6's rule,
// and it is a different refusal from the visibility one: the player can READ a
// revealed secret — every authenticated user can — and can still not change it,
// because PermWriteSecret is about authorship rather than about visibility.
func TestAPlayerMayNotEditASecretSomebodyElseAuthored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{
		"Page.md": "# The Page\n\n" +
			fenceBlock(openSecretID, "table", "dorn", "The mayor's ledger is forged.") +
			"\nPublic after.\n",
	})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)

	view, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	before := h.vault.ReadFile(t, "Page.md")
	edited := bytes.Replace(view.Content, []byte("The mayor's ledger is forged."),
		[]byte("The mayor's ledger is genuine."), 1)

	if err := h.svc.Save(ctx, h.player(), id, edited, view.BaseHash); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("the error is %v, want authz.ErrDenied", err)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("a refused edit changed the file")
	}
	if n := h.count(`SELECT COUNT(*) FROM secret_events`); n != 0 {
		t.Errorf("a refused edit wrote %d audit rows", n)
	}
	// The author may, which is what makes the refusal about authorship and not
	// about the page.
	if err := h.svc.Save(ctx, h.dm(), id, edited, view.BaseHash); err != nil {
		t.Fatalf("the author could not edit the secret: %v", err)
	}
}

// TestAPageRowThatPointsOutsideTheVaultOrAtNothing is the other half of the
// readPage guard: vault.Ignored covers the app's own state, and Resolve covers a
// path that escapes the vault. Neither is reachable from a correctly indexed
// vault, so both are tested by writing the row the indexer would never write —
// which is the point, because the index is derived and therefore not trusted.
func TestAPageRowThatPointsOutsideTheVaultOrAtNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	outside := filepath.Join(h.vault.Root, "..", "outside.md")
	if err := os.WriteFile(outside, []byte("# Outside the vault\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	for _, tc := range []struct {
		name string
		path string
	}{
		{"a path that escapes the vault", "../outside.md"},
		{"a path under a hidden directory", ".semiplane/secret.md"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pid, err := store.UpsertPage(ctx, h.db.Writer(), store.Page{
				Path: tc.path, Basename: "x", Title: "x",
				ContentHash: vault.Hash(nil), SizeBytes: 1, PageType: "note",
				CreatedAt: clockNow, UpdatedAt: clockNow,
			})
			if err != nil {
				t.Fatalf("seed a page row: %v", err)
			}
			if _, err := h.svc.EditView(ctx, h.dm(), pid); err == nil {
				t.Fatal("an editor buffer was produced for a path outside the vault")
			}
			if err := h.svc.Save(ctx, h.dm(), pid, []byte("# replaced\n"), vault.Hash(nil)); err == nil {
				t.Fatal("a save wrote outside the vault")
			}
			if got, err := os.ReadFile(outside); err != nil || string(got) != "# Outside the vault\n" {
				t.Fatalf("the file outside the vault changed: %q %v", got, err)
			}
		})
	}

	t.Run("a page whose file is gone", func(t *testing.T) {
		t.Parallel()
		h2 := newHarness(t, map[string]string{"Page.md": "# The Page\n\nText.\n"})
		pid := pageID(t, h2, "Page.md")
		h2.vault.Remove(t, "Page.md")
		if _, err := h2.svc.EditView(ctx, h2.dm(), pid); !errors.Is(err, vault.ErrNotFound) {
			t.Fatalf("the error is %v, want vault.ErrNotFound", err)
		}
		if err := h2.svc.Save(ctx, h2.dm(), pid, []byte("# back\n"), vault.Hash(nil)); !errors.Is(err, vault.ErrNotFound) {
			t.Fatalf("the error is %v, want vault.ErrNotFound", err)
		}
		if h2.vault.Exists("Page.md") {
			t.Fatal("a save recreated a deleted page")
		}
	})
}
