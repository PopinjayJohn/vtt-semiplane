package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The rename and the opt-in bulk link updater (§5.6).
//
// The properties, in the order they matter:
//
//   - A rename moves a file byte for byte, records the names the page used to
//     answer to, and re-points the references that the move orphaned so that a
//     link written against the old spelling resolves again immediately.
//   - The updater rewrites the target token and nothing else. Every other byte
//     of every other page, including the bytes inside a secret, is copied.
//   - A stale preview is harmless: a file edited between the preview and the
//     apply is a reported conflict and an unchanged file.
//   - Permission is per page, in the preview as well as the apply, and a page
//     the caller cannot write is *listed* rather than hidden — hiding it would
//     tell the reader that a page exists which refers to this one.
//
// The three operations are driven as RenamePage, PlanLinkUpdate and
// ApplyLinkUpdate rather than through HTTP. That is deliberate: the route table
// is shared with the editor stage and is not in this file's hands, and a test
// that can only reach its subject through a route it does not own cannot ask the
// two questions this feature is about — what a principal who may write one page
// and not another is told, and what happens to a file when nobody may write it.

// renamePrincipal is one of the fixture's accounts as a Principal the policy
// answers.
func (fx *fixture) renamePrincipal(t *testing.T, username string) authz.Principal {
	t.Helper()
	role := authz.RolePlayer
	switch username {
	case adminName:
		role = authz.RoleAdmin
	case dmName:
		role = authz.RoleDM
	}
	return authz.ForUser(fx.userID(username), username, role, fx.cfg.AllowAnonymousRead)
}

// renamePageID is a page's id by its vault-relative path.
func (fx *fixture) renamePageID(t *testing.T, path string) int64 {
	t.Helper()
	row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), path)
	if err != nil {
		t.Fatalf("look up %s: %v", path, err)
	}
	return row.ID
}

// onDisk reads a vault file directly, bypassing the writer and the index.
//
// The tests that assert "the file is unchanged" read it this way rather than
// through a page view, because a page view renders the file *after* the pipeline
// that is under test has had its say.
func (fx *fixture) onDisk(t *testing.T, path string) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(fx.Root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return src
}

// existsOnDisk reports whether a vault-relative path is a file.
func (fx *fixture) existsOnDisk(rel string) bool {
	_, err := os.Stat(filepath.Join(fx.Root, filepath.FromSlash(rel)))
	return err == nil
}

// editOutsideTheApp writes a file the way Obsidian would: straight to the disk,
// with no writer, no hash check and no reindex.
//
// It is how a test makes a preview stale, and it is the whole point of §5.6
// step 3: the recorded offsets the preview was built from now point at different
// bytes, and nothing has told the server.
func (fx *fixture) editOutsideTheApp(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fx.Root, filepath.FromSlash(path)), []byte(body), 0o600); err != nil {
		t.Fatalf("edit %s outside the app: %v", path, err)
	}
}

// aliasesOf is a page's recorded names, sorted, for comparison.
func (fx *fixture) aliasesOf(t *testing.T, pageID int64) []string {
	t.Helper()
	rows, err := store.ListPageAliases(context.Background(), fx.DB.Reader(), pageID)
	if err != nil {
		t.Fatalf("read the aliases of page %d: %v", pageID, err)
	}
	sort.Strings(rows)
	return rows
}

// reindex runs the indexer over some paths, which is what the watcher does when
// it reports events for files this process did not write.
func (fx *fixture) reindex(t *testing.T, paths ...string) {
	t.Helper()
	if _, err := fx.Indexer.IndexBatch(context.Background(), paths); err != nil {
		t.Fatalf("reindex %v: %v", paths, err)
	}
}

// ownPage grants an account ownership of a page and returns the page's id.
//
// It exists because fx.accountsFor's own grant does not survive: accountsFor
// adds the page_owners row and then calls fx.reindexAll, which reaches
// Indexer.RemoveMissing first and drops the whole derived index — so the row is
// written against a page id the next walk hands to a different page. Every test
// here that needs a page owner calls this *after* accountsFor.
func (fx *fixture) ownPage(t *testing.T, path, username string) int64 {
	t.Helper()
	if err := fx.addOwner(path, fx.userID(username)); err != nil {
		t.Fatalf("make %s an owner by %s: %v", path, username, err)
	}
	return fx.renamePageID(t, path)
}

// affectedPage finds the row a plan lists for a referring page, and whether there
// was one.
func affectedPage(plan httpapi.LinkUpdatePlan, pageID int64) (httpapi.LinkUpdatePage, bool) {
	for _, page := range plan.Affected {
		if page.PageID == pageID {
			return page, true
		}
	}
	return httpapi.LinkUpdatePage{}, false
}

// countPlanReasons and countDetailReasons are how many rows of one kind a plan or
// an apply reported. They are two functions rather than one taking both because a
// preview and an apply report the *same* facts, and a helper that added them
// together would double every count in every assertion.
func countPlanReasons(plan httpapi.LinkUpdatePlan, reason string) int {
	n := 0
	for _, c := range plan.Conflicts {
		if c.Reason == reason {
			n++
		}
	}
	return n
}

func countDetailReasons(result httpapi.LinkUpdateResult, reason string) int {
	n := 0
	for _, d := range result.Details {
		if d.Reason == reason {
			n++
		}
	}
	return n
}

// TestRenameMovesTheFileAndRecordsTheAlias is the rename's own accept list: the
// file moved, its bytes did not change, the name it used to answer to now
// resolves to it, and the response points at the updater rather than running it.
func TestRenameMovesTheFileAndRecordsTheAlias(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	before := fx.onDisk(t, "Tavern.md")

	result, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, "The Drowned Lantern Inn")
	if err != nil {
		t.Fatalf("rename Tavern.md as a dm: %v", err)
	}

	if fx.existsOnDisk("Tavern.md") {
		t.Error("Tavern.md is still on disk after the rename")
	}
	if !fx.existsOnDisk("The Drowned Lantern Inn.md") {
		t.Fatal("the renamed file is not on disk")
	}
	// The move is a move, not a re-render: the bytes are the bytes.
	if got := fx.onDisk(t, "The Drowned Lantern Inn.md"); string(got) != string(before) {
		t.Errorf("the moved file is %d bytes, want the %d it had before the rename", len(got), len(before))
	}

	// The alias is the point of the rename: a reference written as [[Tavern]] has
	// to keep resolving. The page's own frontmatter alias comes across with it,
	// which is the indexer's rule for a rename it detects itself, not an
	// invention of this handler.
	want := "Tavern,the lantern"
	if got := strings.Join(fx.aliasesOf(t, result.PageID), ","); got != want {
		t.Errorf("the renamed page's aliases are %q, want %q", got, want)
	}

	// The departed path answers to nothing, so the campaign has one page and not
	// two. The assertion is on the path rather than on the old id, because SQLite
	// hands back the highest freed rowid and the vacated id may be reused by the
	// row the rename creates.
	if _, getPageByPathErr := store.GetPageByPath(ctx, fx.DB.Reader(), "Tavern.md"); !errors.Is(getPageByPathErr, store.ErrNoRows) {
		t.Errorf("the departed path still has a page row: %v", getPageByPathErr)
	}
	if row, getPageByPathErr := store.GetPageByPath(ctx, fx.DB.Reader(), result.NewPath); getPageByPathErr != nil || row.ID != result.PageID {
		t.Errorf("the rename reported the page as %d, but the new path's row is %+v (getPageByPathErr %v)", result.PageID, row, getPageByPathErr)
	}
	if result.Updater.Preview == "" || result.Updater.Update == "" {
		t.Errorf("the rename returned no pointer to the updater: %+v", result.Updater)
	}

	// And the reference written against the old name points at the new page
	// *immediately*, without waiting for the reconciling scan: the rename
	// re-points the references the move orphaned, precisely so that the alias is
	// not a promise somebody else has to keep.
	links, err := store.ListLinksToPage(ctx, fx.DB.Reader(), result.PageID)
	if err != nil {
		t.Fatalf("read the references to the renamed page: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("no reference to [[Tavern]] follows the rename, so the alias is not resolving and the updater would find nothing to do")
	}
	for _, l := range links {
		if l.TargetRaw != "Tavern" {
			t.Errorf("a reference to %q is listed against the renamed page, want %q", l.TargetRaw, "Tavern")
		}
	}
}

// TestRenameAndTheIndexerDoNotDoubleAlias pins the answer to "who records the
// alias": both of them, and the overlap is harmless.
//
// The handler records it, because a rename that waited for the watcher's event or
// the sixty-second reconciliation scan to notice leaves [[the old name]] dangling
// in the meantime, and the response would be claiming a rename whose whole
// purpose had not happened yet. The indexer records it too, for a rename nobody
// performed through the app: an Obsidian move is a delete and a create, and only
// a content-hash match inside the window can pair them.
//
// Both write the same rows, and store.AddPageAlias is ON CONFLICT DO NOTHING, so
// the second is a no-op. The test gives the indexer its own chance — IndexBatch
// is the only path that runs RenameDetect — and asserts the alias set is exactly
// what it was: not twice as long, and not missing.
// TestARenameCarriesThePageOwners pins the grant across the move.
//
// page_owners.page_id is ON DELETE CASCADE and a rename removes the departed
// row, so without an explicit carry every owner is dropped. The failure is not
// cosmetic: the grant is what makes the page writable and what lets its owner
// read the private secrets authored on it, so a rename would report success and
// hand the page back to people who can no longer write it or read their own
// notes on it.
func TestARenameCarriesThePageOwners(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	const before, after = "Tavern.md", "The Drowned Lantern Inn.md"
	wasOwner, err := store.IsPageOwner(ctx, fx.DB.Reader(), mustPageID(t, fx, before), fx.userID(playerName))
	if err != nil {
		t.Fatalf("read the fixture's ownership: %v", err)
	}
	if !wasOwner {
		t.Fatal("the fixture granted no ownership, so a carry would be asserted against nothing")
	}

	resp := fx.asUser(playerName, playerPass).do(fx.asUser(playerName, playerPass).post(
		"/api/pages/"+strconv.FormatInt(mustPageID(t, fx, before), 10)+"/rename",
		url.Values{"new": {"The Drowned Lantern Inn"}}))
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner could not rename her own page: %d", resp.StatusCode)
	}

	moved, err := store.GetPageByPath(ctx, fx.DB.Reader(), after)
	if err != nil {
		t.Fatalf("read the renamed page: %v", err)
	}
	still, err := store.IsPageOwner(ctx, fx.DB.Reader(), moved.ID, fx.userID(playerName))
	if err != nil {
		t.Fatalf("read the renamed page's ownership: %v", err)
	}
	if !still {
		t.Error("the rename dropped the page's owner; the page came back unwritable to the person who renamed it")
	}
	owners, err := store.ListPageOwners(ctx, fx.DB.Reader(), moved.ID)
	if err != nil {
		t.Fatalf("list the renamed page's owners: %v", err)
	}
	if len(owners) == 0 {
		t.Error("the renamed page has no owners at all")
	}
}

// TestARenameOfAnUnownedPageGrantsNobody pins the other direction: a page with
// no grants does not acquire any by being moved. A carry that ran against an
// unowned page would hand it to whoever renamed it.
func TestARenameOfAnUnownedPageGrantsNobody(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	ctx := context.Background()

	as := fx.asUser(dmName, dmPass)
	resp := as.do(as.post("/api/pages/"+strconv.FormatInt(mustPageID(t, fx, "Index.md"), 10)+"/rename",
		url.Values{"new": {"The Ledger"}}))
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a dm could not rename a page: %d", resp.StatusCode)
	}
	moved, err := store.GetPageByPath(ctx, fx.DB.Reader(), "The Ledger.md")
	if err != nil {
		t.Fatalf("read the renamed page: %v", err)
	}
	owners, err := store.ListPageOwners(ctx, fx.DB.Reader(), moved.ID)
	if err != nil {
		t.Fatalf("list the renamed page's owners: %v", err)
	}
	if len(owners) != 0 {
		t.Errorf("the renamed page acquired %d owner(s) it did not have", len(owners))
	}
}

func TestRenameAndTheIndexerDoNotDoubleAlias(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	result, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, "The Inn")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	afterHandler := strings.Join(fx.aliasesOf(t, result.PageID), ",")
	if afterHandler != "Tavern,the lantern" {
		t.Fatalf("the handler recorded the aliases %q, want the old basename and the frontmatter one", afterHandler)
	}

	// What the watcher hands the indexer when it reports the delete and the
	// create it saw.
	fx.reindex(t, "Tavern.md", result.NewPath)

	if got := strings.Join(fx.aliasesOf(t, result.PageID), ","); got != afterHandler {
		t.Errorf("after the indexer ran its own rename detection the aliases are %q, want %q: the two paths disagree about the same rename", got, afterHandler)
	}
	// And the property the alias exists for, checked after the indexer has had
	// its own pass: a reference written against the old spelling still resolves.
	fx.reindex(t, "Index.md")
	links, err := store.ListLinksToPage(ctx, fx.DB.Reader(), result.PageID)
	if err != nil {
		t.Fatalf("read the references after the indexer's pass: %v", err)
	}
	if len(links) == 0 {
		t.Error("[[Tavern]] stopped resolving once the indexer ran its own rename detection")
	}
}

// TestRenameOfAPageYouDoNotOwnIsRefused is the coarse-gate-is-not-the-decision
// half of the authorization story: the route table's Perm already refused this
// principal, and the per-page check refuses it again on its own.
//
// The second refusal is the one worth having. A player who owns nothing must not
// be able to rename a page by naming it, and the test asks the question without
// the router so the answer comes from the policy and the ownership table rather
// than from a middleware that was never entered.
func TestRenameOfAPageYouDoNotOwnIsRefused(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	before := fx.onDisk(t, "Tavern.md")

	_, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, otherName), tavern, "Not Yours")
	if !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("rename as a player who owns nothing: %v, want a policy denial", err)
	}
	if got := fx.onDisk(t, "Tavern.md"); string(got) != string(before) {
		t.Error("Tavern.md changed while a rename was being refused")
	}
	if fx.existsOnDisk("Not Yours.md") {
		t.Error("a refused rename created Not Yours.md")
	}
}

// TestRenameRefusesAPageYouDoNotOwnBeforeResolvingTheDestination is the order
// half of the authorization story, and it is a leak if it is wrong.
//
// A destination is resolved *after* the caller's permission on the source has
// been decided, which is why a principal who may not write the page learns
// nothing about where a path would have landed — and a path that would have
// landed outside the vault is exactly the sort of thing a probe is for.
func TestRenameRefusesAPageYouDoNotOwnBeforeResolvingTheDestination(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	before := fx.onDisk(t, "Tavern.md")

	for _, name := range []string{"../escape", "Fine Name", ""} {
		if _, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, otherName), tavern, name); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("rename to %q as a player who owns nothing: %v, want a policy denial", name, err)
		}
	}
	if got := fx.onDisk(t, "Tavern.md"); string(got) != string(before) {
		t.Error("Tavern.md changed while renames were being refused")
	}
}

// TestRenameIntoAnExistingPageIsRefused is the case where the destination is
// perfectly legal and the move would destroy a file.
//
// vault.Writer.Move refuses it under the destination's own lock, and the file it
// refused to overwrite is still there — which is the only part of this that
// matters.
func TestRenameIntoAnExistingPageIsRefused(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	ruinBefore := fx.onDisk(t, "Ruin.md")
	tavernBefore := fx.onDisk(t, "Tavern.md")

	if _, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, "Ruin"); err == nil {
		t.Fatal("a rename onto an existing page succeeded")
	}
	if got := fx.onDisk(t, "Ruin.md"); string(got) != string(ruinBefore) {
		t.Error("Ruin.md was overwritten by a refused rename")
	}
	if got := fx.onDisk(t, "Tavern.md"); string(got) != string(tavernBefore) {
		t.Error("Tavern.md changed when the rename onto Ruin.md was refused")
	}
}

// TestRenameRefusesAPathOutsideTheVault walks the shapes of traversal a caller
// can send.
//
// Every case is refused, and the assertion after each is that nothing appeared
// outside the vault root — a refusal that removed a file on the way out would
// still be a refusal, and this is what proves it was not.
func TestRenameRefusesAPathOutsideTheVault(t *testing.T) {
	t.Parallel()
	// The label is not the name: t.Run turns a slash into a directory, so
	// "../../etc/passwd" would name a subdirectory rather than the case.
	for name, want := range map[string]string{
		"parent":       "../escape",
		"two parents":  "../../etc/passwd",
		"climbs out":   "Nested/../../../escape",
		"the vault":    "..",
		"a bare dot":   ".",
		"only dots":    "...",
		"sibling tree": "../sibling/escape",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t)
			fx.accountsFor()
			ctx := context.Background()

			tavern := fx.renamePageID(t, "Tavern.md")
			before := fx.onDisk(t, "Tavern.md")
			if _, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, want); err == nil {
				t.Fatalf("renaming to %q succeeded", want)
			}
			if got := fx.onDisk(t, "Tavern.md"); string(got) != string(before) {
				t.Errorf("Tavern.md changed while %q was being refused", want)
			}
			if fx.existsOnDisk("escape.md") || fx.existsOnDisk("../escape.md") {
				t.Error("a refused rename created a file outside the vault")
			}
		})
	}
}

// TestRenameTreatsALeadingSlashAsVaultRelative is the other half of the same
// property, and it is worth pinning because the naive expectation is wrong.
//
// `/etc/passwd` is not a traversal: vault.Resolve reads a leading slash as the
// vault root, which is the same convention /p/{path} uses, and the destination it
// produces is <vault>/etc/passwd.md. Accepting it is correct. What must be
// impossible is the thing a reader of the code is worried about — the real
// /etc/passwd being overwritten — so that is what the test asserts.
func TestRenameTreatsALeadingSlashAsVaultRelative(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	result, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, "/etc/passwd")
	if err != nil {
		t.Fatalf("rename to an absolute-looking path: %v", err)
	}
	if result.NewPath != "etc/passwd.md" {
		t.Errorf("the rename resolved %q to %q, want the vault-relative %q", "/etc/passwd", result.NewPath, "etc/passwd.md")
	}
	if !fx.existsOnDisk("etc/passwd.md") {
		t.Error("the file was not created inside the vault")
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Errorf("the real /etc/passwd is gone: %v", err)
	}
}

// TestRenameRefusesTheAppsOwnState is the case the vault agent flagged and the
// one that is not a traversal at all.
//
// .semiplane/semiplane.lock is inside the vault, so containment accepts it, and a
// rename that moved it would release the single-instance lock the running process
// still believes it holds. Every name in this table is refused with
// vault.Ignored on the *destination*, before the move.
func TestRenameRefusesTheAppsOwnState(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"the single-instance lock": ".semiplane/semiplane.lock",
		"the index":                ".semiplane/semiplane.db",
		"a backup":                 ".semiplane/backups/whatever",
		"the obsidian config":      ".obsidian/workspace",
		"a git config":             ".git/config",
		"a git hook":               "Campaign/.git/hooks/pre-commit",
		"the trash":                ".trash/Tavern.md",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t)
			fx.accountsFor()
			ctx := context.Background()

			tavern := fx.renamePageID(t, "Tavern.md")
			before := fx.onDisk(t, "Tavern.md")
			if _, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, want); err == nil {
				t.Fatalf("renaming to %q succeeded", want)
			}
			if got := fx.onDisk(t, "Tavern.md"); string(got) != string(before) {
				t.Errorf("Tavern.md changed while %q was being refused", want)
			}
		})
	}
}

// TestRenameRefusesTheNameItAlreadyHas is the no-op, refused rather than
// performed: a rename to the page's own name would be a move onto itself.
func TestRenameRefusesTheNameItAlreadyHas(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Tavern", "Tavern.md"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t)
			fx.accountsFor()
			ctx := context.Background()

			tavern := fx.renamePageID(t, "Tavern.md")
			before := fx.onDisk(t, "Tavern.md")
			if _, err := fx.Server.RenamePage(ctx, fx.renamePrincipal(t, dmName), tavern, name); err == nil {
				t.Fatalf("renaming Tavern.md to %q succeeded", name)
			}
			if got := fx.onDisk(t, "Tavern.md"); string(got) != string(before) {
				t.Error("Tavern.md changed during a refused no-op rename")
			}
		})
	}
}

// TestUpdaterRespectsWritePermissionPerPage is §5.6's authorization paragraph,
// end to end.
//
// The plan says: "the caller needs writePage on the renamed page *and* on every
// affected page. A page the caller cannot write is listed as `unwritable` in the
// preview and skipped, with `no permission` in the details. This is checked in
// the preview so the user is never told '12 links will update' when only 4 can."
//
// Every clause of that is asserted here, and the caller is a page owner rather
// than a dm, because a dm may write every page and the per-page check would then
// have nothing to decide.
func TestUpdaterRespectsWritePermissionPerPage(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	ctx := context.Background()
	// Thia owns the Tavern and nothing else, so a plan she asks for is a plan
	// about two pages she may not touch. The grant is made here rather than
	// relying on accountsFor's, which fx.reindexAll undoes.
	tavern := fx.ownPage(t, "Tavern.md", playerName)
	index := fx.renamePageID(t, "Index.md")
	ruin := fx.renamePageID(t, "Ruin.md")

	thia := fx.renamePrincipal(t, playerName)
	plan, err := fx.Server.PlanLinkUpdate(ctx, thia, tavern, "The Inn")
	if err != nil {
		t.Fatalf("plan as the page owner: %v", err)
	}

	if plan.OldName != "Tavern" {
		t.Errorf("the plan's old name is %q, want %q", plan.OldName, "Tavern")
	}
	if plan.Summary.Pages != 2 {
		t.Errorf("the plan lists %d affected pages, want 2 (Index.md and Ruin.md): a page left out is a page whose existence was hidden", plan.Summary.Pages)
	}
	if plan.Summary.Unwritable != 2 {
		t.Errorf("the plan reports %d unwritable pages, want 2: the preview must say so before the button is pressed", plan.Summary.Unwritable)
	}
	for _, id := range []int64{index, ruin} {
		page, ok := affectedPage(plan, id)
		if !ok {
			t.Errorf("the plan does not list page %d at all, and a page the reader cannot write must still be listed", id)
			continue
		}
		if page.CanWrite {
			t.Errorf("page %s is reported writable by a principal who does not own it", page.Path)
		}
		if page.Count == 0 {
			t.Errorf("page %s is listed with no occurrences, so the reader is told it exists but not what it says", page.Path)
		}
	}
	if got := countPlanReasons(plan, httpapi.SkipNoPermission); got != 2 {
		t.Errorf("the preview carries %d `no permission` reasons, want one per unwritable page: %+v", got, plan.Conflicts)
	}

	// The apply writes nothing, and the two files are byte-identical.
	indexBefore := fx.onDisk(t, "Index.md")
	ruinBefore := fx.onDisk(t, "Ruin.md")
	result, err := fx.Server.ApplyLinkUpdate(ctx, thia, tavern, "The Inn")
	if err != nil {
		t.Fatalf("apply as the page owner: %v", err)
	}
	if result.Updated != 0 {
		t.Errorf("the updater rewrote %d pages for a principal who owns none of them", result.Updated)
	}
	if result.Skipped != 2 {
		t.Errorf("the updater skipped %d pages, want 2", result.Skipped)
	}
	if len(result.Details) != 2 {
		t.Fatalf("the updater reported %d details, want one per skipped page: %+v", len(result.Details), result.Details)
	}
	if got := fx.onDisk(t, "Index.md"); string(got) != string(indexBefore) {
		t.Error("Index.md was rewritten by an updater the caller had no permission for")
	}
	if got := fx.onDisk(t, "Ruin.md"); string(got) != string(ruinBefore) {
		t.Error("Ruin.md was rewritten by an updater the caller had no permission for")
	}
	for _, d := range result.Details {
		if d.Reason != httpapi.SkipNoPermission {
			t.Errorf("%s was skipped for %q, want %q", d.Path, d.Reason, httpapi.SkipNoPermission)
		}
	}

	// The same plan as a dm says the opposite, from the same code and the same
	// rows: a dm may write every page, so nothing is unwritable.
	dmPlan, err := fx.Server.PlanLinkUpdate(ctx, fx.renamePrincipal(t, dmName), tavern, "The Inn")
	if err != nil {
		t.Fatalf("plan as a dm: %v", err)
	}
	if dmPlan.Summary.Unwritable != 0 {
		t.Errorf("a dm's plan reports %d unwritable pages, want 0", dmPlan.Summary.Unwritable)
	}
	if dmPlan.Summary.Pages != 2 || dmPlan.Summary.Links != 2 {
		t.Errorf("a dm's plan reports %d pages and %d links, want 2 and 2", dmPlan.Summary.Pages, dmPlan.Summary.Links)
	}
}

// updaterGoldenInput is the page TestUpdaterIsBytePreserving rewrites.
//
// Everything a reflowing rewriter would touch is here on purpose: trailing
// spaces, a tab, a run of blank lines, a fenced code block that contains the old
// name as *text* rather than as a link, a link with a fragment, a link with an
// alias, a relative markdown link carrying .md, and a self-reference.
const updaterGoldenInput = "---\ntitle: The Drowned Lantern\naliases: [the lantern]\ntags: [area/port]\n---\n\n" +
	"# The Drowned Lantern   \n\n" +
	"Landlord Orrin keeps the only dry room in [[Index]].\n" +
	"   \n" +
	"The cellar is under [[Tavern#The Cellar]], and the sign outside\n" +
	"reads [[Tavern|the lantern]] on a board nobody has repainted.\n" +
	"See also [the cellar](Tavern.md) and [[#The Cellar]] itself.\n" +
	"\n\n\n" +
	"```\n" +
	"the [[Tavern]] in this block is text, not a link\n" +
	"```\n" +
	"\ta line mentioning Tavern without brackets\n"

// updaterGoldenOutput is the same page after the rewrite.
//
// Only the three page references change. The trailing spaces on the heading, the
// three blank lines, the tab, and the [[Tavern]] inside the code fence all come
// out unchanged — the fence is the canary, because a fenced code block's
// contents are not links and must not be rewritten by anything that thinks they
// are. The self-reference is unchanged too, and is not even in the plan: it
// names a position inside the page rather than the page's name.
const updaterGoldenOutput = "---\ntitle: The Drowned Lantern\naliases: [the lantern]\ntags: [area/port]\n---\n\n" +
	"# The Drowned Lantern   \n\n" +
	"Landlord Orrin keeps the only dry room in [[Index]].\n" +
	"   \n" +
	"The cellar is under [[The Inn#The Cellar]], and the sign outside\n" +
	"reads [[The Inn|the lantern]] on a board nobody has repainted.\n" +
	"See also [the cellar](The Inn.md) and [[#The Cellar]] itself.\n" +
	"\n\n\n" +
	"```\n" +
	"the [[Tavern]] in this block is text, not a link\n" +
	"```\n" +
	"\ta line mentioning Tavern without brackets\n"

// TestUpdaterIsBytePreserving is the golden fixture the plan asks for.
//
// Two assertions, and the second is the one that would catch a regression the
// first would miss. The first compares the rewritten file against a golden
// string, which says what the result should be. The second rebuilds the expected
// output by splicing the new name into every rewritable token of the input and
// nothing else, and compares — so a rewrite that re-rendered the page, normalised
// a line ending, dropped a trailing space or reflowed a paragraph fails even if
// the golden were wrong in the same direction.
func TestUpdaterIsBytePreserving(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, map[string]string{
		"Index.md":  "---\ntitle: Index\n---\n\n# Index\n\nThe [[Tavern]] is where the party met.\n",
		"Tavern.md": updaterGoldenInput,
	})
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	plan, err := fx.Server.PlanLinkUpdate(ctx, fx.renamePrincipal(t, dmName), tavern, "The Inn")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if plan.Summary.Conflicts != 0 {
		t.Fatalf("the preview reports %d conflicts against an unedited file, want 0: %+v", plan.Summary.Conflicts, plan.Conflicts)
	}
	if plan.Summary.Pages != 2 {
		t.Errorf("the preview names %d affected pages, want 2 (Index.md and Tavern.md itself)", plan.Summary.Pages)
	}
	// Three references in Tavern.md and one in Index.md. The self-reference and
	// the fenced `[[Tavern]]` are not among them, and neither is a count of five
	// that included them.
	if plan.Summary.Links != 4 {
		t.Errorf("the preview counts %d links, want 4: the self-reference and the fenced text are not links to the page's name", plan.Summary.Links)
	}

	result, err := fx.Server.ApplyLinkUpdate(ctx, fx.renamePrincipal(t, dmName), tavern, "The Inn")
	if err != nil {
		t.Fatalf("apply the rewrite: %v", err)
	}
	if result.Updated != 2 {
		t.Fatalf("the updater rewrote %d pages, want 2 (Index.md and Tavern.md itself): %+v", result.Updated, result.Details)
	}
	if len(result.Details) != 0 {
		t.Errorf("the updater reported %d refusals, want 0: %+v", len(result.Details), result.Details)
	}
	if got := string(fx.onDisk(t, "Index.md")); !strings.Contains(got, "The [[The Inn]] is where the party met.") {
		t.Errorf("the reference in the other page was not rewritten:\n%q", got)
	}

	got := string(fx.onDisk(t, "Tavern.md"))
	if got != updaterGoldenOutput {
		t.Errorf("the rewritten page is not the golden fixture.\n--- got ---\n%q\n--- want ---\n%q", got, updaterGoldenOutput)
	}
	assertOnlyTheseReplacements(t, updaterGoldenInput, got, [][2]string{
		{"[[Tavern#The Cellar]]", "[[The Inn#The Cellar]]"},
		{"[[Tavern|the lantern]]", "[[The Inn|the lantern]]"},
		{"](Tavern.md)", "](The Inn.md)"},
	})
}

// assertOnlyTheseReplacements fails unless `after` is exactly `before` with the
// listed substrings substituted and nothing else touched.
//
// It is the assertion that does not depend on the golden being right. Every
// substring here is one whole page reference, so a rewrite that re-rendered the
// page, normalised a line ending, dropped a trailing space or reflowed a
// paragraph changes bytes the substitution cannot reach, and fails here even if
// the golden fixture had been regenerated to match the same regression.
func assertOnlyTheseReplacements(t *testing.T, before, after string, pairs [][2]string) {
	t.Helper()
	want := before
	for _, p := range pairs {
		if !strings.Contains(want, p[0]) {
			t.Fatalf("the input does not contain %q, so this assertion would pass vacuously", p[0])
		}
		if strings.Contains(want, p[1]) {
			t.Fatalf("the input already contains the rewritten form %q", p[1])
		}
		want = strings.ReplaceAll(want, p[0], p[1])
	}
	if want != after {
		t.Errorf("bytes outside the recorded tokens changed.\n--- expected ---\n%q\n--- written ---\n%q", want, after)
	}
}

// updaterSecretsTavern refers to [[Gundren]] three times: once in public prose,
// once inside a fence only a dm may read, and once inside a fence the table may
// read. The last two exist to be different answers and must not become the same
// one.
const updaterSecretsTavern = "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
	"Orrin mentions [[Gundren]] in the common room, loudly.\n\n" +
	"```secret id=d1d1d1d1d1d1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The trap\"\n" +
	"Gundren waits at [[Gundren]]\n```\n" +
	"```secret id=e2e2e2e2e2e2 visibility=table author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The pact\"\n" +
	"The pact names [[Gundren]]\n```\n" +
	"and that is the whole of it.  \n"

// TestUpdaterSkipsLinksInsideHiddenSecretsForNonDM is the security core, and the
// plan's own test name.
//
// The property has two halves and the fixture has to carry both.
//
// The first is what the plan says: a non-DM must not trigger a rewrite that
// touches a link inside a secret. Here the caller is a page owner who may write
// both affected pages, so nothing but the secret stops her — and the occurrence
// inside the DM fence is absent from the plan entirely rather than listed and
// skipped, because a listed occurrence with a line and an offset is itself a
// disclosure.
//
// The second is stronger than the plan and is what the implementation actually
// guarantees: a link inside a secret is never rewritten for *anybody*, including a
// dm who may read every byte of it. That is md.LinkEdits' rule, and pinning it
// here matters because a rule that holds only for the principals who cannot see
// the secret is a rule about authorization rather than about bytes — and bytes
// are what a rename touches.
func TestUpdaterSkipsLinksInsideHiddenSecretsForNonDM(t *testing.T) {
	t.Parallel()

	fx := newFixtureWith(t, map[string]string{
		"Tavern.md":  updaterSecretsTavern,
		"Gundren.md": "---\ntitle: Gundren\n---\n\n# Gundren\n\nA dwarf with a grudge.\n",
	})
	fx.accountsFor()
	// Thia owns the Tavern already, but accountsFor's grant does not survive its
	// own reindexAll, so it is made again here. She is given Gundren as well so
	// that the plan below is a plan about a page she may write, which is what
	// makes the secret the only thing standing between her and a rewrite inside a
	// fence.
	tavernID := fx.ownPage(t, "Tavern.md", playerName)
	gundren := fx.ownPage(t, "Gundren.md", playerName)
	ctx := context.Background()
	thia := fx.renamePrincipal(t, playerName)

	t.Run("a reference inside a secret the reader may not see is absent from the plan", func(t *testing.T) {
		plan, err := fx.Server.PlanLinkUpdate(ctx, thia, gundren, "Gundren the Bold")
		if err != nil {
			t.Fatalf("plan as the page owner: %v", err)
		}
		page, ok := affectedPage(plan, tavernID)
		if !ok {
			t.Fatal("the Tavern is not listed at all, so the plan is asserting nothing about it")
		}
		// Exactly two occurrences: the public one and the table one. The dm
		// fence's is not in the plan at all, and the table fence's is, because
		// this principal may read it. A count of 1 would be the table fence being
		// filtered by something other than its visibility, and a count of 3 would
		// be the dm fence leaking as a dangling reference.
		if page.Count != 2 {
			t.Errorf("the plan lists %d occurrences on a page with three references to the renamed page, want 2 (the public one and the table one)", page.Count)
		}
		if plan.Summary.Links != 2 {
			t.Errorf("the plan counts %d links, want 2", plan.Summary.Links)
		}
	})

	t.Run("a reader's updater leaves every secret byte alone", func(t *testing.T) {
		before := fx.onDisk(t, "Tavern.md")
		result, err := fx.Server.ApplyLinkUpdate(ctx, thia, gundren, "Gundren the Bold")
		if err != nil {
			t.Fatalf("apply as the page owner: %v", err)
		}
		if result.Updated != 1 {
			t.Fatalf("the updater rewrote %d pages, want 1: %+v", result.Updated, result.Details)
		}
		after := string(fx.onDisk(t, "Tavern.md"))
		// The public reference moved; the two inside fences did not. Each
		// assertion is on the bytes of its own fence, so a rewrite that touched
		// one and not the other fails on the one it touched.
		if !strings.Contains(after, "Orrin mentions [[Gundren the Bold]] in the common room, loudly.") {
			t.Error("the public reference was not rewritten")
		}
		for _, secret := range []string{
			"Gundren waits at [[Gundren]]",
			"The pact names [[Gundren]]",
		} {
			if !strings.Contains(after, secret) {
				t.Errorf("a reference inside a secret was rewritten; the fence that held it no longer reads %q", secret)
			}
		}
		// The trailing spaces on the last line are the canary for a rewriter
		// that reflowed the file rather than splicing into it.
		if !strings.HasSuffix(after, "and that is the whole of it.  \n") {
			t.Error("the rewritten file is not byte-identical outside the public reference")
		}
		if len(after) != len(before)+len("Gundren the Bold")-len("Gundren") {
			t.Errorf("the file grew by %d bytes, want %d: something other than the one token changed",
				len(after)-len(before), len("Gundren the Bold")-len("Gundren"))
		}
	})

	t.Run("a dm's updater does not rewrite a secret reference either", func(t *testing.T) {
		// A dm may read every fence, so the occurrences are in the plan — and are
		// still refused. This is the half that makes the property a fact about
		// bytes rather than about who is asking.
		//
		// It gets a vault of its own rather than the one above, because the
		// subtest before it rewrote the public reference and a shared fixture
		// would make this one assert against a file the previous subtest edited.
		dmFx := newFixtureWith(t, map[string]string{
			"Tavern.md":  updaterSecretsTavern,
			"Gundren.md": "---\ntitle: Gundren\n---\n\n# Gundren\n\nA dwarf with a grudge.\n",
		})
		dmFx.accountsFor()
		dmGundren := dmFx.renamePageID(t, "Gundren.md")
		dmTavern := dmFx.renamePageID(t, "Tavern.md")
		dm := dmFx.renamePrincipal(t, dmName)

		plan, err := dmFx.Server.PlanLinkUpdate(ctx, dm, dmGundren, "Gundren the Very Bold")
		if err != nil {
			t.Fatalf("plan as a dm: %v", err)
		}
		page, ok := affectedPage(plan, dmTavern)
		if !ok {
			t.Fatal("the Tavern is not listed for a dm")
		}
		if page.Count != 3 {
			t.Errorf("a dm's plan lists %d occurrences, want 3: the secret references must be visible to a principal who may read them, or a row hiding them proves nothing", page.Count)
		}
		before := dmFx.onDisk(t, "Tavern.md")
		result, err := dmFx.Server.ApplyLinkUpdate(ctx, dm, dmGundren, "Gundren the Very Bold")
		if err != nil {
			t.Fatalf("apply as a dm: %v", err)
		}
		after := string(dmFx.onDisk(t, "Tavern.md"))
		if !strings.Contains(after, "Orrin mentions [[Gundren the Very Bold]] in the common room, loudly.") {
			t.Error("the public reference was not rewritten for a dm")
		}
		for _, secret := range []string{
			"Gundren waits at [[Gundren]]",
			"The pact names [[Gundren]]",
		} {
			if !strings.Contains(after, secret) {
				t.Error("a dm's updater rewrote a reference inside a secret; the byte-range exclusion is not unconditional")
			}
		}
		// And the two secret occurrences are reported rather than quietly
		// dropped: a rename that rewrote one of three references has to say so.
		if got := countDetailReasons(result, httpapi.ConflictInsideSecret); got != 2 {
			t.Errorf("the apply reported %d `inside a secret` refusals, want 2: %+v", got, result.Details)
		}
		if len(after) == len(before) {
			t.Error("nothing at all changed, so the dm's updater is not running")
		}
	})

	t.Run("a principal who owns nothing cannot start one", func(t *testing.T) {
		before := fx.onDisk(t, "Tavern.md")
		if _, err := fx.Server.ApplyLinkUpdate(ctx, fx.renamePrincipal(t, otherName), gundren, "Gundren the Bold"); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("a player who owns nothing ran the updater: %v, want a policy denial", err)
		}
		if got := string(fx.onDisk(t, "Tavern.md")); got != string(before) {
			t.Error("a refused updater changed the file anyway")
		}
	})
}

// TestUpdaterSkipsAnUnrecordedOccurrence is the store's sentinel arriving at the
// updater.
//
// A destination written in angle brackets parses to the right *name* and so
// resolves to the right page, but the bytes at the range md located are
// `<Tavern.md>` and the destination the parser read is `Tavern.md` — two different
// strings, and md will not decide which the author meant. It records no range,
// and the row that reaches the updater carries a zero length, which is the
// absence of a recording and not an offset of zero.
//
// The backslash form is in the fixture too, and for the opposite reason: it does
// get a range, and a correct one, and it is still not rewritten — because
// `Tavern\.md` is not a spelling of the name and the rename will not guess which
// spelling the author meant. The two are different refusals with different
// reasons, and conflating them is how a preview ends up promising a rewrite it
// cannot perform.
func TestUpdaterSkipsAnUnrecordedOccurrence(t *testing.T) {
	t.Parallel()

	const page = "---\ntitle: Index\n---\n\n# Index\n\n" +
		"An ordinary [[Tavern]] and an angle-bracketed [one](<Tavern.md>)\n" +
		"beside a backslashed [two](Tavern\\.md).\n"

	fx := newFixtureWith(t, map[string]string{
		"Index.md":  page,
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\nOrrin's room.\n",
	})
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	dm := fx.renamePrincipal(t, dmName)
	plan, err := fx.Server.PlanLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	row, ok := affectedPage(plan, fx.renamePageID(t, "Index.md"))
	if !ok {
		t.Fatal("Index.md is not listed as an affected page")
	}
	if row.Count != 3 {
		t.Fatalf("Index.md is listed with %d occurrences, want 3 (the wikilink and the two escaped destinations)", row.Count)
	}

	var unrecorded int
	for _, o := range row.Occurrences {
		if o.ByteLen == 0 {
			unrecorded++
			if o.ByteStart != store.LinkByteStartUnset {
				t.Errorf("an unrecorded occurrence reports byteStart %d, want %d: zero is a real offset and this row is not at one",
					o.ByteStart, store.LinkByteStartUnset)
			}
		}
	}
	if unrecorded != 1 {
		t.Errorf("%d of the %d occurrences are unrecorded, want 1: the angle-bracketed destination was supposed to be",
			unrecorded, row.Count)
	}
	if got := countPlanReasons(plan, httpapi.ConflictUnrecorded); got != 1 {
		t.Errorf("the preview carries %d `unrecorded` conflicts, want 1: a reader cannot tell a rewritable reference from one that will be skipped: %+v",
			got, plan.Conflicts)
	}
	// And the backslashed one is reported as what it is: current, in range, and
	// not a spelling of the name.
	if got := countPlanReasons(plan, httpapi.ConflictUnmatched); got != 1 {
		t.Errorf("the preview carries %d `not a reference to the name` conflicts, want 1: %+v", got, plan.Conflicts)
	}

	// And the apply rewrites the one reference it can and leaves the other two.
	before := fx.onDisk(t, "Index.md")
	result, err := fx.Server.ApplyLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	after := string(fx.onDisk(t, "Index.md"))
	if !strings.Contains(after, "An ordinary [[The Inn]] and an angle-bracketed [one](<Tavern.md>)") {
		t.Errorf("the recorded reference was not rewritten:\n%q", after)
	}
	if !strings.Contains(after, "[one](<Tavern.md>)") || !strings.Contains(after, "[two](Tavern\\.md)") {
		t.Errorf("an escaped reference was rewritten:\n%q", after)
	}
	if len(after) != len(before)+len("The Inn")-len("Tavern") {
		t.Errorf("the file grew by %d bytes, want %d: more than the one token changed",
			len(after)-len(before), len("The Inn")-len("Tavern"))
	}
	if got := countDetailReasons(result, httpapi.ConflictUnrecorded); got != 1 {
		t.Errorf("the apply reported %d `unrecorded` refusals, want 1: %+v", got, result.Details)
	}
}

// TestUpdaterNeverTreatsZeroAsAnOffset is the same sentinel pinned from the side
// that matters, which is the file.
//
// store.LinkByteStartUnset is -1 and a zero ByteLen is the absence of a
// recording; zero is a legitimate offset, a link in the first byte of a file, and
// the Go zero value of a struct field a caller forgot to set. Treating the second
// as the first would make the updater replace the first eight bytes of every page
// whose destination was escaped with a link target, and the fixture below is
// shaped so that doing it is unmissable.
func TestUpdaterNeverTreatsZeroAsAnOffset(t *testing.T) {
	t.Parallel()

	// The first line of the body is the one a rewrite at offset zero would
	// destroy, so the canary is not subtle on purpose.
	const page = "---\ntitle: Index\n---\n\nCANARY-AT-THE-TOP-OF-THE-BODY\n\n" +
		"An ordinary [[Tavern]] and an escaped one [here](<Tavern.md>).\n"

	fx := newFixtureWith(t, map[string]string{
		"Index.md":  page,
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\nOrrin's room.\n",
	})
	fx.accountsFor()
	ctx := context.Background()

	tavern := fx.renamePageID(t, "Tavern.md")
	dm := fx.renamePrincipal(t, dmName)
	plan, err := fx.Server.PlanLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	result, err := fx.Server.ApplyLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	after := string(fx.onDisk(t, "Index.md"))
	if !strings.HasPrefix(after, "---\ntitle: Index\n---\n\nCANARY-AT-THE-TOP-OF-THE-BODY") {
		t.Errorf("the first bytes of the file were rewritten, so an unrecorded occurrence was treated as an offset:\n%.80q", after)
	}
	if !strings.Contains(after, "An ordinary [[The Inn]] and an escaped one [here](<Tavern.md>).") {
		t.Errorf("the recorded reference was not rewritten:\n%q", after)
	}
	if got := countPlanReasons(plan, httpapi.ConflictUnrecorded); got != 1 {
		t.Errorf("the preview reported %d `unrecorded` conflicts, want 1: %+v", got, plan.Conflicts)
	}
	if got := countDetailReasons(result, httpapi.ConflictUnrecorded); got != 1 {
		t.Errorf("the apply reported %d `unrecorded` refusals, want 1: %+v", got, result.Details)
	}
	if result.Updated != 1 {
		t.Errorf("the updater rewrote %d pages, want 1: the recorded reference was rewritable", result.Updated)
	}
}

// TestStalePreviewIsHarmless is the plan's own name for §5.6 step 3.
//
// The file is edited between the preview and the apply, out of band, with nothing
// reindexed — which is what a second person with the vault open looks like. The
// recorded offsets now point at different bytes, and the answer has to be: a
// reported conflict, and a file byte-identical to the *edit* rather than to the
// preview.
func TestStalePreviewIsHarmless(t *testing.T) {
	t.Parallel()

	const index = "---\ntitle: Index\n---\n\n# Index\n\nThe [[Tavern]] is where the party met.\n"
	// The edit a second author would make: two lines added at the top, which
	// shifts every offset in the file without touching the link's own text.
	const edited = "---\ntitle: Index\n---\n\n# Index\n\nAdded by somebody else.\n" +
		"And a second line, for good measure.\n\nThe [[Tavern]] is where the party met.\n"

	fx := newFixtureWith(t, map[string]string{
		"Index.md":  index,
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\nOrrin's room.\n",
	})
	fx.accountsFor()
	ctx := context.Background()
	dm := fx.renamePrincipal(t, dmName)
	tavern := fx.renamePageID(t, "Tavern.md")

	// The preview, against a file that is still the one the index recorded.
	plan, err := fx.Server.PlanLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if plan.Summary.Conflicts != 0 {
		t.Fatalf("the preview reports %d conflicts against an unedited file, want 0: %+v", plan.Summary.Conflicts, plan.Conflicts)
	}
	if plan.Summary.Links != 1 {
		t.Fatalf("the preview counts %d links, want 1", plan.Summary.Links)
	}

	// Somebody else saves, behind the app's back and with no reindex.
	fx.editOutsideTheApp(t, "Index.md", edited)

	// The apply re-derives its own plan and finds the conflict.
	applyPlan, err := fx.Server.PlanLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("plan after the edit: %v", err)
	}
	if applyPlan.Summary.Conflicts == 0 {
		t.Error("the plan taken after the file changed reports no conflict, so the stale preview would have been trusted")
	}
	if got := countPlanReasons(applyPlan, httpapi.ConflictStale); got == 0 {
		t.Errorf("the conflict is not reported as stale: %+v", applyPlan.Conflicts)
	}

	result, err := fx.Server.ApplyLinkUpdate(ctx, dm, tavern, "The Inn")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Updated != 0 {
		t.Errorf("the updater rewrote %d pages from a stale preview, want 0", result.Updated)
	}
	if result.Skipped != 1 {
		t.Errorf("the updater skipped %d pages, want 1", result.Skipped)
	}
	// The file is exactly what the other author wrote. Not the preview's version,
	// not a splice at the stale offset, not a re-render.
	if got := string(fx.onDisk(t, "Index.md")); got != edited {
		t.Errorf("a stale preview changed the file.\n--- got ---\n%q\n--- want ---\n%q", got, edited)
	}
	// And the conflict is reported rather than swallowed.
	if got := countDetailReasons(result, httpapi.ConflictStale); got == 0 {
		t.Errorf("the apply reported no stale conflict: %+v", result.Details)
	}
}

// TestUpdaterOnlyRewritesTheRecordedToken is the half of byte preservation a
// golden fixture cannot make visible: a caller cannot talk the updater into
// writing an arbitrary byte range.
//
// The three operations take a page id and a new name and nothing else, so there
// is no parameter through which a caller could name an offset. What the test can
// do is show that every name the handler refuses leaves the file alone, and that
// a refused apply does not get half way through first — the order is the claim.
func TestUpdaterOnlyRewritesTheRecordedToken(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"a traversal":     "../../etc/passwd",
		"app state":       ".semiplane/semiplane.db",
		"its own name":    "Tavern",
		"its own ext":     "Tavern.md",
		"empty":           "",
		"over the length": "Campaign/" + strings.Repeat("x", 300),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newFixtureWith(t, map[string]string{
				"Index.md":  "---\ntitle: Index\n---\n\n# Index\n\nThe [[Tavern]] is where the party met.\n",
				"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\nOrrin's room.\n",
			})
			fx.accountsFor()
			ctx := context.Background()

			tavern := fx.renamePageID(t, "Tavern.md")
			before := fx.onDisk(t, "Index.md")
			if _, err := fx.Server.ApplyLinkUpdate(ctx, fx.renamePrincipal(t, dmName), tavern, want); err == nil {
				t.Fatalf("the updater accepted the name %q", want)
			}
			if got := string(fx.onDisk(t, "Index.md")); got != string(before) {
				t.Errorf("a refused updater changed Index.md to %q", got)
			}
		})
	}
}
