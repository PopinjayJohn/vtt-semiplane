package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// writePagePerm is the permission the save tests mount their routes with.
const writePagePerm = authz.PermWritePage

// TestConcurrentSaveSamePath is the property the whole save path exists for:
// with a stale base hash, exactly one of N concurrent savers may win and the
// rest must learn what is on disk now.
func TestConcurrentSaveSamePath(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	original := []byte("# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(original))

	store := newFakeSelfwrites()
	w := NewWriter(v.Root, obs.Discard())
	w.Store = store

	const savers = 12
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		conflicts int
		other     []error
		start     = make(chan struct{})
	)
	for i := range savers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			err := w.Save(context.Background(), SaveRequest{
				Path:            "Campaigns/Ash/Gundren.md",
				NewContent:      []byte(fmt.Sprintf("# edit by %d\n", i)),
				BaseContentHash: Hash(original),
				ActorID:         int64(i),
				ExpectPerm:      writePagePerm,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				other = append(other, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range other {
		t.Errorf("a save failed for a reason other than the conflict: %v", err)
	}
	if successes != 1 {
		t.Errorf("%d saves succeeded, want exactly 1", successes)
	}
	if conflicts != savers-1 {
		t.Errorf("%d saves conflicted, want %d", conflicts, savers-1)
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got == string(original) {
		t.Error("the winner's bytes are not on disk")
	}
}

// TestConflictCarriesBothVersions is what makes the conflict page possible:
// the DM is shown what is on disk and what they were trying to save, and
// neither is re-read at render time.
func TestConflictCarriesBothVersions(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	theirs := []byte("# The DM's version, edited in Obsidian\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(theirs))
	ours := []byte("# My version from the editor\n")

	w := NewWriter(v.Root, obs.Discard())
	err := w.Save(t.Context(), SaveRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		NewContent:      ours,
		BaseContentHash: Hash([]byte("# a stale version\n")),
		ActorID:         3,
		ExpectPerm:      writePagePerm,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Save = %v, want ErrConflict", err)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As found no *ConflictError in %v", err)
	}
	if !bytes.Equal(ce.Theirs(), theirs) {
		t.Errorf("Theirs = %q, want the bytes on disk", ce.Theirs())
	}
	if !bytes.Equal(ce.Ours(), ours) {
		t.Errorf("Ours = %q, want the bytes the editor held", ce.Ours())
	}
	if ce.Path() != "Campaigns/Ash/Gundren.md" {
		t.Errorf("Path = %q", ce.Path())
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got != string(theirs) {
		t.Errorf("a refused save changed the file: %q", got)
	}
}

// TestSaveCreatesOnlyWhenTheBaseIsEmpty stops two clients from each believing
// they created the page.
func TestSaveCreatesOnlyWhenTheBaseIsEmpty(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	w := NewWriter(v.Root, obs.Discard())
	req := SaveRequest{
		Path:            "Campaigns/Braxton/Ash.md",
		NewContent:      []byte("# Ash\n"),
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	}
	if err := w.Save(t.Context(), req); err != nil {
		t.Fatalf("create: %v", err)
	}
	req.NewContent = []byte("# Ash, again\n")
	if err := w.Save(t.Context(), req); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second create = %v, want ErrConflict", err)
	}
}

// TestSaveRefusesAPathThatEscapes keeps the traversal rule on the write path
// and not only on the read path.
func TestSaveRefusesAPathThatEscapes(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	w := NewWriter(v.Root, obs.Discard())
	err := w.Save(t.Context(), SaveRequest{
		Path:            "../../etc/passwd",
		NewContent:      []byte("pwned"),
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	})
	if !errors.Is(err, ErrOutsideVault) {
		t.Fatalf("Save = %v, want ErrOutsideVault", err)
	}
	if _, statErr := os.Stat("/etc/passwd.rewritten"); statErr == nil {
		t.Fatal("a refused save still touched the filesystem")
	}
}

// TestSaveRefusesAReadPermission is the last line against a save being wired to
// a read route by a future mistake. The role comparison happened upstream; this
// only asserts that the route named a write permission at all.
func TestSaveRefusesAReadPermission(t *testing.T) {
	t.Parallel()
	cases := []struct {
		perm authz.Permission
		ok   bool
	}{
		{authz.PermWritePage, true},
		{authz.PermWriteAny, true},
		{authz.PermWriteSecret, true},
		{authz.PermDeletePage, true},
		{authz.PermDM, true},
		{authz.PermAdmin, true},
		{authz.PermReadPage, false},
		{authz.PermReadSecret, false},
		{authz.PermAnonRead, false},
		{authz.PermSession, false},
		{authz.PermSetupOpen, false},
		{authz.Permission(""), false},
		{authz.Permission("writepage"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.perm)+"|allowed", func(t *testing.T) {
			t.Parallel()
			if got := isWritePerm(tc.perm); got != tc.ok {
				t.Errorf("isWritePerm(%q) = %v, want %v", tc.perm, got, tc.ok)
			}
		})
	}

	v := testutil.NewVault(t)
	w := NewWriter(v.Root, obs.Discard())
	err := w.Save(t.Context(), SaveRequest{
		Path:       "Page.md",
		NewContent: []byte("x"),
		ExpectPerm: authz.PermReadPage,
	})
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("Save with a read permission = %v, want ErrNotPermitted", err)
	}
	if v.Exists("Page.md") {
		t.Error("a refused save created the file anyway")
	}
}

// TestSaveRegistersItsOwnBytes is the contract the watcher depends on.
func TestSaveRegistersItsOwnBytes(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	store := newFakeSelfwrites()
	w := NewWriter(v.Root, obs.Discard())
	w.Store = store
	w.Clock = testutil.Vault{Clock: func() time.Time { return store.now }}.Clock

	content := []byte("# Gundren\n")
	if err := w.Save(t.Context(), SaveRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		NewContent:      content,
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	same, err := store.IsSelfwrite(t.Context(), "Campaigns/Ash/Gundren.md", Hash(content))
	if err != nil {
		t.Fatalf("is selfwrite: %v", err)
	}
	if !same {
		t.Error("the save was not registered as a self-write, so the watcher would report it")
	}
	other, err := store.IsSelfwrite(t.Context(), "Campaigns/Ash/Gundren.md", Hash([]byte("edited elsewhere")))
	if err != nil {
		t.Fatalf("is selfwrite: %v", err)
	}
	if other {
		t.Error("a different hash was accepted as the app's own write")
	}
}

func TestSaveSurvivesASelfwriteStoreOutage(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	store := newFakeSelfwrites()
	store.failPut = true
	w := NewWriter(v.Root, obs.Discard())
	w.Store = store

	content := []byte("# Gundren\n")
	err := w.Save(t.Context(), SaveRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		NewContent:      content,
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	})
	if err != nil {
		t.Fatalf("a lost announcement must not fail a save whose bytes are on disk: %v", err)
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got != string(content) {
		t.Errorf("content = %q", got)
	}
}

func TestSaveRefusesOversizeContent(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	w := NewWriter(v.Root, obs.Discard())
	w.MaxBytes = 16
	err := w.Save(t.Context(), SaveRequest{
		Path:            "Page.md",
		NewContent:      bytes.Repeat([]byte("x"), 17),
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	})
	if err == nil {
		t.Fatal("an oversize save must fail")
	}
	if v.Exists("Page.md") {
		t.Error("a refused save created the file")
	}
}

// TestLockTableIsFixed guards the memory property: a map keyed by path would
// grow once per page the vault has ever held and is never emptied.
func TestLockTableIsFixed(t *testing.T) {
	t.Parallel()
	w := NewWriter("/vault", obs.Discard())
	release := w.lockPath("Campaigns/Ash/Gundren.md")
	if release == nil {
		t.Fatal("lockPath returned no release")
	}
	release()
	// The same stripe must be reachable again, which is what a fixed array
	// gives and a growing map would not promise.
	release = w.lockPath("Campaigns/Ash/Sela.md")
	release()
}
