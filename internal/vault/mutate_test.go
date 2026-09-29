package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// deletePagePerm is the permission a delete route is mounted with. It is the
// constant that had a policy case and no route behind it until now.
const deletePagePerm = authz.PermDeletePage

func TestDeleteRemovesTheFileAndIsDurable(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")

	store := newFakeSelfwrites()
	w := NewWriter(v.Root, obs.Discard())
	w.Store = store

	if err := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		BaseContentHash: Hash([]byte("# Gundren\n")),
		ActorID:         7,
		ExpectPerm:      deletePagePerm,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if v.Exists("Campaigns/Ash/Gundren.md") {
		t.Error("the file is still in the vault")
	}
	// Durability is the directory entry rather than the data, and it is not
	// observable from a test — a tmp filesystem has no power to lose. What is
	// observable is that Delete returns only after the flush: a directory handle
	// that would not open or sync surfaces as an error from Delete, which is what
	// the t.Fatalf above is asserting against.
	//
	// The rest of the campaign is untouched: a delete is one file.
	if !v.Exists("Campaigns") || !v.Exists("Campaigns/Ash") {
		t.Error("the delete took a directory with it")
	}
	// Nothing was registered as a self-write. The mechanism has no vocabulary for
	// a removal, and a registration keyed by a path whose bytes no longer exist
	// would suppress a later, unrelated file written to the same name.
	if store.count() != 0 {
		t.Errorf("the store was asked %d times, want none: a delete registers nothing", store.count())
	}
	same, err := store.IsSelfwrite(t.Context(), "Campaigns/Ash/Gundren.md", Hash([]byte("# Gundren\n")))
	if err != nil {
		t.Fatalf("is selfwrite: %v", err)
	}
	if same {
		t.Error("a deleted path was registered as a self-write, so a later file of the same bytes would be suppressed")
	}
}

func TestDeleteRefusesAStaleHash(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	theirs := []byte("# The DM's version, edited in Obsidian\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(theirs))

	w := NewWriter(v.Root, obs.Discard())
	err := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		BaseContentHash: Hash([]byte("# a version nobody is holding any more\n")),
		ExpectPerm:      deletePagePerm,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Delete = %v, want ErrConflict", err)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As found no *ConflictError in %v", err)
	}
	if !bytes.Equal(ce.Theirs(), theirs) {
		t.Errorf("Theirs = %q, want the bytes on disk", ce.Theirs())
	}
	// A deleted page has no second version, and putting the file's own bytes in
	// both fields would render a page in an error message.
	if len(ce.Ours()) != 0 {
		t.Errorf("Ours = %q, want empty: a delete has no version of its own", ce.Ours())
	}
	if ce.Path() != "Campaigns/Ash/Gundren.md" {
		t.Errorf("Path = %q", ce.Path())
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got != string(theirs) {
		t.Errorf("a refused delete changed the file: %q", got)
	}
}

func TestDeleteRefusesAPathThatEscapes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"above the root":         "../../etc/passwd",
		"through a symlink":      "Campaigns/Ash/link/escaped.md",
		"a UNC path":             "//etc/passwd",
		"a homoglyph traversal":  "Campaigns/∕..∕..∕escaped.md",
		"a drive letter":         "C:/escaped.md",
		"a control character":    "Campaigns/Ash/Gundren\n.md",
		"a Windows-dropped tail": "Campaigns/Ash/Gundren. ",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := testutil.NewVault(t)
			v.MkdirAll(t, "Campaigns/Ash")
			if err := os.Symlink("/tmp", filepath.Join(v.Root, "Campaigns/Ash/link")); err != nil {
				t.Skipf("this platform does not permit the symlink the case needs: %v", err)
			}
			w := NewWriter(v.Root, obs.Discard())
			err := w.Delete(t.Context(), DeleteRequest{
				Path:            path,
				BaseContentHash: Hash(nil),
				ExpectPerm:      deletePagePerm,
			})
			if !errors.Is(err, ErrOutsideVault) {
				t.Fatalf("Delete(%q) = %v, want ErrOutsideVault", path, err)
			}
			if _, statErr := os.Stat("/tmp/escaped.md"); statErr == nil {
				t.Fatal("a refused delete still removed a file")
			}
		})
	}
}

func TestDeleteRefusesAnUnknownPermission(t *testing.T) {
	t.Parallel()
	cases := []authz.Permission{
		authz.PermReadPage,
		authz.PermReadSecret,
		authz.PermAnonRead,
		authz.PermSession,
		authz.PermSetupOpen,
		authz.Permission(""),
		authz.Permission("deletePage "),
	}
	for _, perm := range cases {
		t.Run("perm="+string(perm), func(t *testing.T) {
			t.Parallel()
			v := testutil.NewVault(t)
			v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
			w := NewWriter(v.Root, obs.Discard())
			err := w.Delete(t.Context(), DeleteRequest{
				Path:            "Campaigns/Ash/Gundren.md",
				BaseContentHash: Hash([]byte("# Gundren\n")),
				ExpectPerm:      perm,
			})
			if !errors.Is(err, ErrNotPermitted) {
				t.Fatalf("Delete with %q = %v, want ErrNotPermitted", perm, err)
			}
			if !v.Exists("Campaigns/Ash/Gundren.md") {
				t.Error("a refused delete removed the file anyway")
			}
		})
	}
}

func TestDeleteOfAMissingFile(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	w := NewWriter(v.Root, obs.Discard())

	// A delete of a file that is not there is an error, not a success. The
	// reasons are all about what a caller cannot tell afterwards: idempotence
	// makes "I removed it" indistinguishable from "it was never there" and from
	// "I removed a copy somebody else had already deleted", and the hash check
	// exists precisely to make the last of those impossible.
	err := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash/Ghost.md",
		BaseContentHash: Hash(nil),
		ExpectPerm:      deletePagePerm,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete of a missing file = %v, want ErrNotFound", err)
	}
	// The error names the path and nothing else: no content, because there is
	// none, and no absolute path, because that is the vault's own layout.
	if !strings.Contains(err.Error(), "Campaigns/Ash/Ghost.md") {
		t.Errorf("the error does not name the path: %v", err)
	}
	if strings.Contains(err.Error(), v.Root) {
		t.Errorf("the error leaked the absolute vault root: %v", err)
	}

	// And it is still an error on the second attempt, so a retried delete does
	// not report work it did not do.
	if again := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash/Ghost.md",
		BaseContentHash: Hash(nil),
		ExpectPerm:      deletePagePerm,
	}); !errors.Is(again, ErrNotFound) {
		t.Fatalf("a repeated delete = %v, want ErrNotFound", again)
	}
}

// TestDeleteIsSerialisedWithASaveOfTheSamePath is the reason the delete takes a
// stripe at all: a save and a delete that both believed they had the last word
// would leave whichever lost the race looking successful.
func TestDeleteIsSerialisedWithASaveOfTheSamePath(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	original := []byte("# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(original))

	w := NewWriter(v.Root, obs.Discard())
	const rounds = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		both  []error
		start = make(chan struct{})
	)
	for i := range 2 * rounds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx := context.Background()
			var err error
			if i%2 == 0 {
				err = w.Delete(ctx, DeleteRequest{
					Path:            "Campaigns/Ash/Gundren.md",
					BaseContentHash: original,
					ExpectPerm:      deletePagePerm,
				})
			} else {
				err = w.Save(ctx, SaveRequest{
					Path:            "Campaigns/Ash/Gundren.md",
					NewContent:      original,
					BaseContentHash: original,
					ExpectPerm:      writePagePerm,
				})
			}
			mu.Lock()
			defer mu.Unlock()
			both = append(both, err)
		}(i)
	}
	close(start)
	wg.Wait()

	// Both verbs are hash-checked and mutually exclusive, so the first one to
	// take the stripe wins and every other one is told what is on disk now —
	// either ErrConflict or ErrNotFound, never a silent success.
	for i, err := range both {
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
			t.Errorf("operation %d failed for an unrelated reason: %v", i, err)
		}
	}
	if got := len(v.Paths(t)); got != 1 {
		t.Errorf("%d files remain, want exactly 1: the hash check admitted a second writer", got)
	}
}

// TestDeleteOfADirectoryIsRefused keeps a directory from being removed by a
// request that named one. The hash check refuses it first — a directory has no
// bytes to hash — so the refusal never depends on the filesystem cooperating.
func TestDeleteOfADirectoryIsRefused(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	w := NewWriter(v.Root, obs.Discard())
	err := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash",
		BaseContentHash: Hash(nil),
		ExpectPerm:      deletePagePerm,
	})
	if err == nil {
		t.Fatal("a directory was removed by a delete that named it")
	}
	if !v.Exists("Campaigns/Ash") || !v.Exists("Campaigns/Ash/Gundren.md") {
		t.Error("the campaign directory did not survive")
	}
}

func TestMoveRenamesWithinTheVault(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	body := "# Gundren\n\nThe same bytes under a new name.\n"
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", body)
	v.WriteFile(t, "Campaigns/Ash/Sela.md", "# Sela\n")

	w := NewWriter(v.Root, obs.Discard())
	if err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Gundren.md",
		To:              "Campaigns/Ash/Gundren the Brave.md",
		BaseContentHash: Hash([]byte(body)),
		ActorID:         9,
		ExpectPerm:      writePagePerm,
	}); err != nil {
		t.Fatalf("move: %v", err)
	}
	if v.Exists("Campaigns/Ash/Gundren.md") {
		t.Error("the source is still in the vault")
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren the Brave.md"); got != body {
		t.Errorf("destination content = %q, want the source bytes unchanged", got)
	}
	if !v.Exists("Campaigns/Ash/Sela.md") {
		t.Error("the move took an unrelated file with it")
	}
}

func TestMoveCreatesTheDestinationDirectory(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	body := "# Map of Ash\n"
	v.WriteFile(t, "Campaigns/Ash/Map.md", body)

	w := NewWriter(v.Root, obs.Discard())
	if err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Map.md",
		To:              "Campaigns/Braxton/Ash/Assets/Map.md",
		BaseContentHash: Hash([]byte(body)),
		ExpectPerm:      writePagePerm,
	}); err != nil {
		t.Fatalf("move into a new directory: %v", err)
	}
	if got := v.MustReadFile(t, "Campaigns/Braxton/Ash/Assets/Map.md"); got != body {
		t.Errorf("destination content = %q", got)
	}
	// The directories are ours, so they are private: the mode a save would have
	// created them with, not the one the umask picks.
	st, err := os.Stat(filepath.Join(v.Root, "Campaigns/Braxton/Ash/Assets"))
	if err != nil {
		t.Fatalf("stat the created directory: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("the created directory is %04o, want 0700", perm)
	}
}

func TestMoveRefusesAnExistingDestination(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Sela.md", "# Sela\n")

	w := NewWriter(v.Root, obs.Discard())
	err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Gundren.md",
		To:              "Campaigns/Ash/Sela.md",
		BaseContentHash: Hash([]byte("# Gundren\n")),
		ExpectPerm:      writePagePerm,
	})
	if err == nil {
		t.Fatal("a move overwrote a page that already existed")
	}
	if !strings.Contains(err.Error(), "Campaigns/Ash/Sela.md") {
		t.Errorf("the refusal does not name the destination: %v", err)
	}
	// Both files are intact: the existence check is before the rename, so a
	// refusal is a refusal and not a loss.
	if !v.Exists("Campaigns/Ash/Gundren.md") || !v.Exists("Campaigns/Ash/Sela.md") {
		t.Error("a refused move lost a file")
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Sela.md"); got != "# Sela\n" {
		t.Errorf("the destination was overwritten: %q", got)
	}
}

func TestMoveRefusesToEscapeTheVault(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ from, to string }{
		"the destination":                 {"Campaigns/Ash/Gundren.md", "../../escaped.md"},
		"the source":                      {"../../etc/passwd", "Campaigns/Ash/Gundren.md"},
		"both ends":                       {"../../a.md", "../../b.md"},
		"a UNC destination":               {"Campaigns/Ash/Gundren.md", "//escaped.md"},
		"a homoglyph traversal":           {"Campaigns/Ash/Gundren.md", "Campaigns/∕..∕..∕escaped.md"},
		"a destination through a symlink": {"Campaigns/Ash/Gundren.md", "Campaigns/Ash/link/escaped.md"},
		"a source through a symlink":      {"Campaigns/Ash/link/Gundren.md", "Campaigns/Ash/Sela.md"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := testutil.NewVault(t)
			v.MkdirAll(t, "Campaigns/Ash")
			v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
			if err := os.Symlink("/tmp", filepath.Join(v.Root, "Campaigns/Ash/link")); err != nil {
				t.Skipf("this platform does not permit the symlink the case needs: %v", err)
			}
			w := NewWriter(v.Root, obs.Discard())
			err := w.Move(t.Context(), MoveRequest{
				From:            tc.from,
				To:              tc.to,
				BaseContentHash: Hash([]byte("# Gundren\n")),
				ExpectPerm:      writePagePerm,
			})
			if !errors.Is(err, ErrOutsideVault) {
				t.Fatalf("Move(%q, %q) = %v, want ErrOutsideVault", tc.from, tc.to, err)
			}
			if !v.Exists("Campaigns/Ash/Gundren.md") {
				t.Error("a refused move removed the source anyway")
			}
			if _, statErr := os.Stat("/tmp/escaped.md"); statErr == nil {
				t.Fatal("a refused move still wrote a file")
			}
		})
	}
}

func TestMoveRefusesAnUnknownPermission(t *testing.T) {
	t.Parallel()
	cases := []authz.Permission{
		authz.PermReadPage,
		authz.PermReadSecret,
		authz.PermAnonRead,
		authz.PermSession,
		authz.PermSetupOpen,
		authz.Permission(""),
		authz.Permission("writePage\n"),
	}
	for _, perm := range cases {
		t.Run("perm="+string(perm), func(t *testing.T) {
			t.Parallel()
			v := testutil.NewVault(t)
			v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
			w := NewWriter(v.Root, obs.Discard())
			err := w.Move(t.Context(), MoveRequest{
				From:            "Campaigns/Ash/Gundren.md",
				To:              "Campaigns/Ash/Sela.md",
				BaseContentHash: Hash([]byte("# Gundren\n")),
				ExpectPerm:      perm,
			})
			if !errors.Is(err, ErrNotPermitted) {
				t.Fatalf("Move with %q = %v, want ErrNotPermitted", perm, err)
			}
			if !v.Exists("Campaigns/Ash/Gundren.md") || v.Exists("Campaigns/Ash/Sela.md") {
				t.Error("a refused move touched the filesystem")
			}
		})
	}
}

func TestMoveOfAMissingSource(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	w := NewWriter(v.Root, obs.Discard())
	err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Ghost.md",
		To:              "Campaigns/Ash/Spectre.md",
		BaseContentHash: Hash(nil),
		ExpectPerm:      writePagePerm,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Move of a missing source = %v, want ErrNotFound", err)
	}
	if v.Exists("Campaigns/Ash/Spectre.md") {
		t.Error("a refused move created the destination")
	}
}

func TestMoveToItself(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ from, to string }{
		"the same string":       {"Campaigns/Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		"a leading slash":       {"Campaigns/Ash/Gundren.md", "/Campaigns/Ash/Gundren.md"},
		"a doubled separator":   {"Campaigns/Ash/Gundren.md", "Campaigns//Ash/./Gundren.md"},
		"a backslash separator": {"Campaigns/Ash/Gundren.md", `Campaigns\Ash\Gundren.md`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := testutil.NewVault(t)
			v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
			w := NewWriter(v.Root, obs.Discard())
			err := w.Move(t.Context(), MoveRequest{
				From:            tc.from,
				To:              tc.to,
				BaseContentHash: Hash([]byte("# Gundren\n")),
				ExpectPerm:      writePagePerm,
			})
			if err == nil {
				t.Fatal("a move of a file onto itself succeeded")
			}
			// The spellings differ; the paths they resolve to do not. Comparing
			// the resolved paths rather than the strings is what makes the second
			// case a refusal instead of a rename that unlinks its own source.
			if !errors.Is(err, ErrConflict) && !strings.Contains(err.Error(), "same file") {
				t.Fatalf("Move(%q, %q) = %v", tc.from, tc.to, err)
			}
			if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got != "# Gundren\n" {
				t.Errorf("the file changed: %q", got)
			}
		})
	}
}

func TestMoveRefusesAStaleHash(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")

	w := NewWriter(v.Root, obs.Discard())
	err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Gundren.md",
		To:              "Campaigns/Ash/Sela.md",
		BaseContentHash: Hash([]byte("# a version nobody is holding any more\n")),
		ExpectPerm:      writePagePerm,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Move = %v, want ErrConflict", err)
	}
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As found no *ConflictError in %v", err)
	}
	if !bytes.Equal(ce.Theirs(), []byte("# Gundren\n")) {
		t.Errorf("Theirs = %q, want the bytes on disk", ce.Theirs())
	}
	if ce.Path() != "Campaigns/Ash/Gundren.md" {
		t.Errorf("Path = %q, want the source the request named", ce.Path())
	}
	if v.Exists("Campaigns/Ash/Sela.md") {
		t.Error("a refused move created the destination anyway")
	}
}

// TestMoveRefusesADirectory is the half of the move rules that a hash check
// cannot cover on its own: a directory has no bytes, so the comparison would
// pass on an empty base hash and the rename would move a whole tree.
func TestMoveRefusesADirectory(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash/NPCs")
	v.WriteFile(t, "Campaigns/Ash/NPCs/Sela.md", "# Sela\n")

	w := NewWriter(v.Root, obs.Discard())
	for name, tc := range map[string]struct{ from, to string }{
		"a directory as the source":      {"Campaigns/Ash/NPCs", "Campaigns/Braxton/NPCs"},
		"a directory as the destination": {"Campaigns/Ash/NPCs/Sela.md", "Campaigns/Ash/NPCs"},
	} {
		t.Run(name, func(t *testing.T) {
			err := w.Move(t.Context(), MoveRequest{
				From:            tc.from,
				To:              tc.to,
				BaseContentHash: Hash(nil),
				ExpectPerm:      writePagePerm,
			})
			if err == nil {
				t.Fatalf("Move(%q, %q) moved a directory", tc.from, tc.to)
			}
			if !v.Exists("Campaigns/Ash/NPCs/Sela.md") {
				t.Error("a refused move lost a file")
			}
		})
	}
}

// TestConcurrentMovesBetweenTheSameTwoStripesDoNotDeadlock is the property the
// acquisition order exists for. Two moves that want the same two stripes in
// opposite orders hold one stripe each and wait for the other, and neither ever
// returns; the timeout turns that into a stack dump naming this test rather than
// a CI run that never finishes.
func TestConcurrentMovesBetweenTheSameTwoStripesDoNotDeadlock(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	const (
		first  = "Campaigns/Ash/Gundren.md"
		second = "Campaigns/Braxton/Sela.md"
	)
	body := []byte("# Gundren\n")
	v.WriteFile(t, first, string(body))
	v.WriteFile(t, second, string(body))

	w := NewWriter(v.Root, obs.Discard())
	const rounds = 40
	var (
		mu    sync.Mutex
		errs  []error
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	run := func(i int) {
		defer wg.Done()
		<-start
		for range rounds {
			from, to := first, second
			if i == 1 {
				from, to = second, first
			}
			err := w.Move(context.Background(), MoveRequest{
				From:            from,
				To:              to,
				BaseContentHash: body,
				ExpectPerm:      writePagePerm,
			})
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}
	}
	wg.Add(2)
	go run(0)
	go run(1)
	close(start)
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()

	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	select {
	case <-finished:
	case <-timeout.C:
		t.Fatal("the moves did not finish: two operations that want the same two stripes in opposite orders have deadlocked")
	}

	// Every refusal is a lost race, a conflict or a destination that already
	// exists. Nothing else is a valid outcome, and nothing else is what a
	// deadlock would look like from in here.
	for _, err := range errs {
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrConflict) && !strings.Contains(err.Error(), "already exists") {
			t.Errorf("a move failed for an unrelated reason: %v", err)
		}
	}
	if got := len(v.Paths(t)); got != 2 {
		t.Errorf("%d files remain, want 2: a move interleaved with another", got)
	}
}

// TestMoveAndSaveOfTheSamePathSerialise is the same ordering property seen from
// a third direction: a move and a save that name the same path must not both
// believe they acted on the same bytes.
func TestMoveAndSaveOfTheSamePathSerialise(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	body := []byte("# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(body))
	v.WriteFile(t, "Campaigns/Ash/Sela.md", string(body))

	w := NewWriter(v.Root, obs.Discard())
	const rounds = 20
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		errs  []error
		start = make(chan struct{})
	)
	run := func(fn func() error) {
		defer wg.Done()
		<-start
		for range rounds {
			if err := fn(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}
	}
	wg.Add(3)
	go run(func() error {
		return w.Move(context.Background(), MoveRequest{
			From: "Campaigns/Ash/Gundren.md", To: "Campaigns/Ash/Sela.md",
			BaseContentHash: body, ExpectPerm: writePagePerm,
		})
	})
	go run(func() error {
		return w.Move(context.Background(), MoveRequest{
			From: "Campaigns/Ash/Sela.md", To: "Campaigns/Ash/Gundren.md",
			BaseContentHash: body, ExpectPerm: writePagePerm,
		})
	})
	go run(func() error {
		return w.Save(context.Background(), SaveRequest{
			Path: "Campaigns/Ash/Gundren.md", NewContent: body,
			BaseContentHash: body, ExpectPerm: writePagePerm,
		})
	})
	close(start)
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(20 * time.Second):
		t.Fatal("a move and a save of the same paths did not finish")
	}

	for _, err := range errs {
		if !errors.Is(err, ErrConflict) &&
			!errors.Is(err, ErrNotFound) &&
			!strings.Contains(err.Error(), "already exists") {
			t.Errorf("an operation failed for an unrelated reason: %v", err)
		}
	}
	// The bytes are the one invariant no interleaving can break: whatever ended
	// up at either path, it is the file's content and not a half-written mixture.
	for _, rel := range v.Paths(t) {
		if got := v.MustReadFile(t, rel); got != string(body) {
			t.Errorf("%s = %q, want the file's own bytes", rel, got)
		}
	}
}

// TestMoveReportsBothPathsToTheWatcher is the self-write decision, asserted
// rather than argued: a move must deliver the name it left *and* the name it
// took, in one batch, with nothing registered as a self-write.
//
// The alternative loses data. The watcher decides what to report by stat-ing the
// path and comparing hashes, so a vanished source is always reported — but a
// destination whose hash was registered as the app's own write would be
// suppressed, and the indexer would then be told that a page was deleted and
// never told where it went. The page would be gone from the app for a full
// reconciliation cycle, and its alias would be recorded against nothing.
func TestMoveReportsBothPathsToTheWatcher(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	body := []byte("# Gundren\n\nThe same bytes, whichever name they answer to.\n")
	v.WriteFile(t, "Campaigns/Ash/Old Name.md", string(body))

	store := newFakeSelfwrites()
	_, col := startWatcher(t, v, store)
	settle(t)

	w := NewWriter(v.Root, obs.Discard())
	w.Store = store
	if err := w.Move(t.Context(), MoveRequest{
		From:            "Campaigns/Ash/Old Name.md",
		To:              "Campaigns/Ash/New Name.md",
		BaseContentHash: Hash(body),
		ExpectPerm:      writePagePerm,
	}); err != nil {
		t.Fatalf("move: %v", err)
	}
	waitFor(t, col, "Campaigns/Ash/Old Name.md")
	waitFor(t, col, "Campaigns/Ash/New Name.md")
	settle(t)

	got := map[string]bool{}
	for _, p := range col.all() {
		got[p] = true
	}
	if len(got) != 2 {
		t.Errorf("the watcher delivered %v, want exactly the two paths of the move", got)
	}
	if !got["Campaigns/Ash/Old Name.md"] || !got["Campaigns/Ash/New Name.md"] {
		t.Errorf("the watcher delivered %v, want the source and the destination", got)
	}
	// Nothing was registered, so a later DM edit of the moved page is still news.
	same, err := store.IsSelfwrite(t.Context(), "Campaigns/Ash/New Name.md", Hash(body))
	if err != nil {
		t.Fatalf("is selfwrite: %v", err)
	}
	if same {
		t.Error("the move registered its destination as a self-write, which suppresses the create the indexer needs")
	}
}

// TestADeletionIsAlwaysReportedToTheWatcher is the other half of the same
// mechanism: a file that no longer exists cannot be hashed, so the watcher can
// never classify a deletion as the app's own write, and the indexer always hears
// about a page that left.
func TestADeletionIsAlwaysReportedToTheWatcher(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	body := []byte("# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(body))

	store := newFakeSelfwrites()
	_, col := startWatcher(t, v, store)
	settle(t)

	w := NewWriter(v.Root, obs.Discard())
	w.Store = store
	if err := w.Delete(t.Context(), DeleteRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		BaseContentHash: Hash(body),
		ExpectPerm:      deletePagePerm,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	waitFor(t, col, "Campaigns/Ash/Gundren.md")
	if got := col.all(); len(got) != 1 {
		t.Errorf("the watcher delivered %v, want only the deleted path", got)
	}
}

// TestLockTableIsFixedForEveryVerb extends the save path's fixed-table property
// to the two new verbs, which is the only reason the table is an array and not a
// map keyed by path: a move touches two paths, so a per-path map would grow
// twice as fast for the same lifetime.
func TestLockTableIsFixedForEveryVerb(t *testing.T) {
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

	pair := w.lockStripes(
		New("/vault", "Campaigns/Ash/Gundren.md"),
		New("/vault", "Campaigns/Braxton/Sela.md"),
	)
	if pair == nil {
		t.Fatal("lockStripes returned no release")
	}
	pair()
	// A pair that hashes to one stripe must not deadlock against itself, which is
	// the case a two-lock acquisition gets wrong by not noticing the collision.
	same := w.lockStripes(
		New("/vault", "Campaigns/Ash/Gundren.md"),
		New("/vault", "Campaigns/Ash/Gundren.md"),
	)
	same()
}
