package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// TestSecondInstanceOnSameVaultIsRefused is S18. A second flock in the same
// process conflicts, because the lock belongs to the open file description
// rather than the process, so the rule is testable without a subprocess.
func TestSecondInstanceOnSameVaultIsRefused(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)

	first, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.Release()

	second, err := Lock(t.Context(), v.Root)
	if err == nil {
		second.Release()
		t.Fatal("a second instance took the same vault")
	}
	if !errors.Is(err, ErrAlreadyLocked) {
		t.Fatalf("second lock = %v, want ErrAlreadyLocked", err)
	}

	// The refusal must name the holder and where it is holding it, because
	// "already open" without a pid sends the operator hunting through a task
	// manager on a machine with four terminals open.
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("the refusal does not name the holder's pid: %v", err)
	}
	if !strings.Contains(err.Error(), LockPath(v.Root)) {
		t.Errorf("the refusal does not name the lock file: %v", err)
	}
	if !strings.Contains(err.Error(), "another semiplane process") {
		t.Errorf("the refusal lost the sentinel's wording: %v", err)
	}
}

func TestLockWritesItsOwnPid(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)

	h, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	if h.PID() != os.Getpid() {
		t.Errorf("PID = %d, want %d", h.PID(), os.Getpid())
	}
	if h.Path() != LockPath(v.Root) {
		t.Errorf("Path = %q, want %q", h.Path(), LockPath(v.Root))
	}

	raw, err := os.ReadFile(LockPath(v.Root))
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || fields[0] != strconv.Itoa(os.Getpid()) {
		t.Errorf("the lock file holds %q, want this pid first", raw)
	}
	h.Release()
}

// TestLockIsReclaimedAfterRelease is the half that makes the rule safe: the
// lock belongs to the kernel, so a process that exits or crashes without
// releasing it leaves nothing to clean up by hand.
func TestLockIsReclaimedAfterRelease(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)

	first, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	first.Release()

	second, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("the lock was not reclaimed after a release: %v", err)
	}
	second.Release()
}

func TestLockReleaseIsIdempotent(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)

	h, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	h.Release()
	h.Release()
	if closeErr := h.Close(); closeErr != nil {
		t.Errorf("Close after Release = %v", closeErr)
	}
	h.Release()

	// And the vault is still claimable afterwards: a double release that closed
	// the wrong descriptor would have left the lock held.
	again, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	again.Release()
}

// TestLockCreatesItsDirectoryPrivately pins the mode of the directory holding
// the database and the backups.
func TestLockCreatesItsDirectoryPrivately(t *testing.T) {
	t.Parallel()
	skipUnlessModeBitsAreEnforced(t)
	v := testutil.NewVault(t)

	h, err := Lock(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer h.Release()

	st, err := os.Stat(filepath.Join(v.Root, HiddenDir))
	if err != nil {
		t.Fatalf("stat hidden dir: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("%s mode = %o, want 700", HiddenDir, perm)
	}
	lockInfo, err := os.Stat(LockPath(v.Root))
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if perm := lockInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("lock file mode = %o, want 600", perm)
	}
}

// TestConcurrentLocksElectOneWinner is what a DM running the binary twice by
// accident actually sees.
func TestConcurrentLocksElectOneWinner(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)

	const attempts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		held    int
		refused int
		start   = make(chan struct{})
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			h, err := Lock(t.Context(), v.Root)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if errors.Is(err, ErrAlreadyLocked) {
					refused++
					return
				}
				t.Errorf("unexpected error: %v", err)
				return
			}
			held++
			h.Release()
		}()
	}
	close(start)
	wg.Wait()

	if held == 0 {
		t.Fatal("no attempt ever took the lock")
	}
	if held+refused != attempts {
		t.Errorf("%d held and %d refused, want %d in total", held, refused, attempts)
	}
}
