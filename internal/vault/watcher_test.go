package vault

import (
	"context"
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

// batchCollector accumulates the batches a watcher delivers. A test asserts
// against it after a quiet period rather than racing a channel.
type batchCollector struct {
	mu      sync.Mutex
	batches [][]string
}

func (b *batchCollector) add(_ context.Context, paths []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.batches = append(b.batches, append([]string(nil), paths...))
}

func (b *batchCollector) all() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, batch := range b.batches {
		out = append(out, batch...)
	}
	return out
}

func (b *batchCollector) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.batches)
}

// startWatcher wires a watcher with a debounce wide enough to absorb a test's
// writes and returns its collector.
func startWatcher(t *testing.T, v *testutil.Vault, store SelfwriteStore) (*Watcher, *batchCollector) {
	t.Helper()
	return startWatcherWithDebounce(t, v, store, 40*time.Millisecond)
}

func startWatcherWithDebounce(t *testing.T, v *testutil.Vault, store SelfwriteStore, debounce time.Duration) (*Watcher, *batchCollector) {
	t.Helper()
	w, err := NewWatcher(WatchOptions{
		Root:     v.Root,
		Debounce: debounce,
		Store:    store,
		Log:      obs.Discard(),
	})
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	col := &batchCollector{}
	w.OnBatch(col.add)
	if err := w.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, col
}

// waitFor polls until want appears in the delivered paths, and reports what did
// arrive so a failure is diagnosable.
func waitFor(t *testing.T, col *batchCollector, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, got := range col.all() {
			if got == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the watcher never delivered %q; it delivered %v", want, col.all())
}

func settle(t *testing.T) { time.Sleep(400 * time.Millisecond) }

// TestWatcherSuppressesSelfWritesButNotExternalEdits is the whole point of the
// hash-based suppression: a write the app made is not news, and a write the DM
// made to the same file inside the same window is.
func TestWatcherSuppressesSelfWritesButNotExternalEdits(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	store := newFakeSelfwrites()
	_, col := startWatcher(t, v, store)

	w := NewWriter(v.Root, obs.Discard())
	w.Store = store

	first := []byte("# Gundren, saved by the app\n")
	if err := w.Save(t.Context(), SaveRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		NewContent:      first,
		BaseContentHash: Hash([]byte("# Gundren\n")),
		ExpectPerm:      authz.PermWritePage,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	settle(t)
	if got := col.all(); len(got) != 0 {
		t.Errorf("the watcher reported the app's own write: %v", got)
	}

	// The DM opens Obsidian and edits the same page. The self-write
	// registration is still live — the window is ten seconds — and the hash
	// differs, so the edit must land.
	external := []byte("# Gundren, edited in Obsidian inside the window\n")
	if err := os.WriteFile(filepath.Join(v.Root, "Campaigns/Ash/Gundren.md"), external, 0o600); err != nil {
		t.Fatalf("external write: %v", err)
	}
	waitFor(t, col, "Campaigns/Ash/Gundren.md")
	if store.count() == 0 {
		t.Error("the watcher never asked the store, so suppression is not hash-based")
	}
}

// TestWatcherWithoutAStoreSuppressesNothing is the honest default before the
// index is open: an unknown write is treated as somebody else's.
func TestWatcherWithoutAStoreSuppressesNothing(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	_, col := startWatcher(t, v, nil)

	v.WriteFile(t, "Campaigns/Ash/Sela.md", "# Sela\n")
	waitFor(t, col, "Campaigns/Ash/Sela.md")
}

// TestWatcherPicksUpNewSubdirectories covers the reason a whole-directory tree
// appears in Obsidian and the app must not need a restart to see it.
func TestWatcherPicksUpNewSubdirectories(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	_, col := startWatcher(t, v, nil)

	if err := os.MkdirAll(filepath.Join(v.Root, "Campaigns/Braxton/Ash/NPCs"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The files are written into the new tree immediately, before the watcher
	// can have installed a watch on it. addTree reads the directory for
	// exactly this case.
	v.WriteFile(t, "Campaigns/Braxton/Ash/Map.md", "# Map\n")
	v.WriteFile(t, "Campaigns/Braxton/Ash/NPCs/Sela.md", "# Sela\n")

	waitFor(t, col, "Campaigns/Braxton/Ash/Map.md")
	waitFor(t, col, "Campaigns/Braxton/Ash/NPCs/Sela.md")
}

// TestWatcherDoesNotLoopOnItsOwnTempFiles: an atomic write creates and renames
// a temporary file, and a watcher that reported it would index a file the DM
// cannot see and then index it away again.
func TestWatcherDoesNotLoopOnItsOwnTempFiles(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	store := newFakeSelfwrites()
	_, col := startWatcher(t, v, store)

	w := NewWriter(v.Root, obs.Discard())
	w.Store = store
	for i := range 3 {
		if err := w.Save(t.Context(), SaveRequest{
			Path:            "Campaigns/Ash/Gundren.md",
			NewContent:      []byte("# Gundren\nedit " + string(rune('a'+i)) + "\n"),
			BaseContentHash: Hash(readOrEmpty(t, v, "Campaigns/Ash/Gundren.md")),
			ExpectPerm:      authz.PermWritePage,
		}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	settle(t)

	for _, got := range col.all() {
		if strings.Contains(got, tempSuffix) {
			t.Errorf("the watcher delivered its own temp file: %s", got)
		}
	}
	for _, got := range v.Paths(t) {
		if strings.Contains(got, tempSuffix) {
			t.Errorf("a temp file is still in the vault: %s", got)
		}
	}
}

// TestWatcherCoalescesABurst is the reason batching exists: pasting forty notes
// must be one index pass, not forty.
func TestWatcherCoalescesABurst(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	// A wide window is the point of the test: forty writes land inside one
	// debounce, so the batch count measures coalescing rather than scheduling.
	_, col := startWatcherWithDebounce(t, v, nil, 300*time.Millisecond)

	for i := range 40 {
		v.WriteFile(t, "Campaigns/Ash/Note"+string(rune('a'+i%26))+string(rune('a'+i/26))+".md", "# note\n")
	}
	waitFor(t, col, "Campaigns/Ash/Noteaa.md")
	settle(t)

	if got := len(col.all()); got < 40 {
		t.Fatalf("only %d of 40 files were delivered", got)
	}
	if batches := col.count(); batches > 2 {
		t.Errorf("a burst of 40 files arrived in %d batches, want the burst coalesced", batches)
	}
	for _, batch := range col.batches {
		if len(batch) > 1 {
			return
		}
	}
	t.Error("no batch carried more than one path, so nothing was coalesced")
}

func TestWatcherIgnoresTheAppAndToolDirectories(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	_, col := startWatcher(t, v, nil)

	v.WriteFile(t, ".obsidian/workspace.json", "{}")
	v.WriteFile(t, ".git/HEAD", "ref: refs/heads/main")
	v.WriteFile(t, ".trash/Old.md", "gone")
	v.WriteFile(t, "node_modules/pkg/index.js", "module.exports = {}")
	v.WriteFile(t, ".semiplane/semiplane.db", "sqlite")
	v.WriteFile(t, "Campaigns/Ash/scratch.md"+tempSuffix, "half written")
	v.WriteFile(t, ".semiplane/semiplane.db-wal", "wal")
	settle(t)

	if got := col.all(); len(got) != 0 {
		t.Errorf("the watcher reported ignored paths: %v", got)
	}
}

// TestWatcherFlushesAtThePendingCap proves the bound is a flush and not a drop:
// a path that arrives after the cap is full is still delivered.
func TestWatcherFlushesAtThePendingCap(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")
	w, err := NewWatcher(WatchOptions{
		Root:       v.Root,
		Debounce:   5 * time.Second,
		MaxPending: 4,
		Log:        obs.Discard(),
	})
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	col := &batchCollector{}
	w.OnBatch(col.add)
	if err := w.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = w.Close() }()

	// A five-second debounce means nothing would ever be delivered on the
	// timer: only the cap can produce a batch here.
	for i := range 12 {
		v.WriteFile(t, "Campaigns/Ash/Note"+string(rune('a'+i))+".md", "# n\n")
	}
	waitFor(t, col, "Campaigns/Ash/Notea.md")
	for _, got := range col.all() {
		if strings.Contains(got, tempSuffix) {
			t.Errorf("a temp file was delivered: %s", got)
		}
	}
}

func TestNewWatcherNeedsARoot(t *testing.T) {
	t.Parallel()
	if _, err := NewWatcher(WatchOptions{}); err == nil {
		t.Fatal("a watcher with no root must be refused")
	}
}

func TestWatcherCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	w, err := NewWatcher(WatchOptions{Root: v.Root, Debounce: 20 * time.Millisecond, Log: obs.Discard()})
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	if err := w.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := w.Start(t.Context()); err != nil {
		t.Errorf("a second Start = %v, want idempotence", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func readOrEmpty(t *testing.T, v *testutil.Vault, rel string) []byte {
	t.Helper()
	b, err := Read(context.Background(), New(v.Root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}
