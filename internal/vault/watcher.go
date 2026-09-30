package vault

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// DefaultDebounce is how long a path must be quiet before it is delivered.
const DefaultDebounce = 300 * time.Millisecond

// MaxPendingPaths bounds the debounce table.
//
// The bound is not a drop policy. Hitting it flushes immediately and starts a
// new batch, so the table can never grow without limit and no path is ever
// forgotten; the worst case is two index passes instead of one.
const MaxPendingPaths = 2000

// WatchOptions configures NewWatcher.
type WatchOptions struct {
	// Root is the vault root. Every directory under it, minus the ignored ones,
	// is registered at Start.
	Root string
	// Debounce overrides DefaultDebounce.
	Debounce time.Duration
	// MaxPending overrides MaxPendingPaths.
	MaxPending int
	// Store is queried to decide whether an event is the app's own write. A
	// nil Store suppresses nothing.
	Store SelfwriteStore
	// Log receives watch failures. A nil Log discards.
	Log *obs.Logger
	// Clock overrides the system clock. A nil Clock is the system clock.
	Clock obs.Clock
}

// Watcher delivers vault changes to the indexer in batches.
//
// It is a latency optimisation and nothing more. fsnotify is not recursive, its
// events can be dropped when the kernel queue overflows, and on a network
// mount it may not fire at all — so the 60 second reconciliation scan is the
// correctness guarantee and this is what makes a change show up in seconds
// instead of a minute. Nothing may depend on a path being reported here; a
// dropped event is recovered by the scan, not by a retry.
//
// Events are batched because the alternative is pathological: pasting forty
// notes produces forty index passes, each re-reading the whole vault, when one
// pass would do.
type Watcher struct {
	opts    WatchOptions
	fsw     *fsnotify.Watcher
	onBatch func(ctx context.Context, paths []string)

	mu      sync.Mutex
	pending map[string]bool // absolute paths seen since the last flush
	stopped bool
}

// NewWatcher builds a watcher. Nothing is registered until Start.
func NewWatcher(opts WatchOptions) (*Watcher, error) {
	if opts.Root == "" {
		return nil, errors.New("watcher: a vault root is required")
	}
	if opts.Debounce <= 0 {
		opts.Debounce = DefaultDebounce
	}
	if opts.MaxPending <= 0 {
		opts.MaxPending = MaxPendingPaths
	}
	return &Watcher{opts: opts, pending: map[string]bool{}}, nil
}

// OnBatch registers the callback that receives a settled batch of
// vault-relative paths. It must be set before Start.
//
// The paths are relative and sorted. One call is one index pass, whatever the
// size of the burst that caused it.
func (w *Watcher) OnBatch(fn func(ctx context.Context, paths []string)) { w.onBatch = fn }

// Start registers every directory in the vault and begins delivering batches.
// It is idempotent.
func (w *Watcher) Start(ctx context.Context) error {
	if w.fsw != nil {
		return nil
	}
	dirs, err := w.directories()
	if err != nil {
		return err
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if err := fsw.Add(dir); err != nil {
			w.logger().WarnContext(ctx, "could not watch a vault directory",
				"action", "watch.add", "dir", filepath.Base(dir), "err", err.Error())
		}
	}
	w.fsw = fsw
	go w.run(ctx)
	return nil
}

// Close stops the watcher and releases every registration. It is idempotent.
func (w *Watcher) Close() error {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
	if w.fsw == nil {
		return nil
	}
	return w.fsw.Close()
}

// run is the event loop. It owns the debounce table, so a batch is only ever
// assembled on one goroutine and needs no lock beyond Stop's.
func (w *Watcher) run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.handle(ctx, ev)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			// A watcher error is not fatal and must not stop the loop: the
			// reconciliation scan covers whatever was missed.
			w.logger().WarnContext(ctx, "vault watcher error",
				"action", "watch.error", "err", err.Error())
		case <-timer.C:
			w.flush(ctx)
		}
		w.resetTimer(timer)
	}
}

// handle records one event, or registers a directory that appeared.
func (w *Watcher) handle(ctx context.Context, ev fsnotify.Event) {
	rel, ok := w.rel(ev.Name)
	if !ok || ignoredRel(rel) {
		return
	}
	if ev.Op.Has(fsnotify.Create) {
		if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
			w.addTree(ctx, ev.Name)
			return
		}
	}
	// The operation is not inspected. Every op on a file means "its bytes may
	// have changed" and the indexer re-reads the path by name, so treating a
	// chmod as a change costs one cheap re-read while missing a write costs a
	// page that does not appear until the next reconciliation scan.
	w.mark(ctx, ev.Name)
}

// addTree registers a directory and everything already inside it.
//
// The read is not paranoia. A pasted tree arrives as a create for the top
// directory and creates for its contents in the same instant, and by the time
// the watch for the new directory is installed those creates are gone. Reading
// the directory afterwards recovers the ones that were already there, and the
// 60 second scan recovers any that were not.
func (w *Watcher) addTree(ctx context.Context, dir string) {
	// A directory that appeared under an ignored parent is not a new tree: the
	// parent was never watched, and this is the only path that would notice.
	if rel, ok := w.rel(dir); !ok || ignoredDirName(baseOf(rel)) {
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Best-effort recovery of a tree that appeared; the 60 second scan
			// is the guarantee and an entry that cannot be read here is read
			// there. Propagating would abandon the rest of the tree, which is
			// the one outcome that loses more than it recovers.
			return nil //nolint:nilerr // the scan is the correctness guarantee
		}
		if d.IsDir() {
			if p != dir && ignoredDirName(d.Name()) {
				return fs.SkipDir
			}
			if err := w.fsw.Add(p); err != nil {
				w.logger().WarnContext(ctx, "could not watch a new vault directory",
					"action", "watch.add", "dir", filepath.Base(p), "err", err.Error())
			}
			return nil
		}
		// A symlinked directory is not followed: nothing prevents it pointing at
		// its own ancestor, and the watcher's job is not to walk cycles.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, ok := w.rel(p)
		if !ok || ignoredRel(rel) {
			return nil
		}
		w.mark(ctx, p)
		return nil
	})
}

// baseOf is the last element of a vault-relative path, for an ignore check that
// wants a name rather than a path.
func baseOf(rel string) string {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

// mark records a path as changed.
func (w *Watcher) mark(ctx context.Context, abs string) {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	full := len(w.pending) >= w.opts.MaxPending
	w.pending[abs] = true
	w.mu.Unlock()
	if full {
		// The table is at its bound. Flush now and let the next burst start
		// clean: capping the table by forgetting paths would trade a bound for
		// a silent hole in the index.
		w.flush(ctx)
	}
}

// flush delivers every path seen since the last flush, as one batch.
//
// The debounce is a trailing edge with no starvation. Anything still arriving
// while the window is open joins this batch, so a burst of forty pastes is one
// index pass; a file being edited continuously is delivered once per window
// rather than never. The alternative — flushing only the paths whose own
// deadline has passed — starves whatever arrived last, because a burst's
// deadlines are spread by exactly the time the burst took to arrive.
func (w *Watcher) flush(ctx context.Context) {
	w.mu.Lock()
	due := make([]string, 0, len(w.pending))
	for path := range w.pending {
		due = append(due, path)
		delete(w.pending, path)
	}
	w.mu.Unlock()

	if len(due) == 0 {
		return
	}
	sort.Strings(due)

	rel := make([]string, 0, len(due))
	for _, abs := range due {
		r, ok := w.rel(abs)
		if !ok {
			continue
		}
		if w.isSelfwrite(ctx, r) {
			continue
		}
		rel = append(rel, r)
	}
	if len(rel) == 0 || w.onBatch == nil {
		return
	}
	w.onBatch(ctx, rel)
}

// isSelfwrite reports whether the file's current bytes are ones the app just
// wrote.
//
// The comparison is by content hash, so a DM who edited the same page inside
// the window still produces an event. A file that has been deleted is never a
// self-write, so it is always reported.
func (w *Watcher) isSelfwrite(ctx context.Context, rel string) bool {
	if w.opts.Store == nil {
		return false
	}
	p := New(w.opts.Root, rel)
	st, err := os.Stat(p.Abs())
	if err != nil || st.IsDir() || st.Size() > MaxFileBytes {
		return false
	}
	b, err := Read(ctx, p)
	if err != nil {
		return false
	}
	same, err := w.opts.Store.IsSelfwrite(ctx, rel, Hash(b))
	if err != nil {
		w.logger().WarnContext(ctx, "self-write check failed",
			"action", "selfwrite.check", "path", rel, "err", err.Error())
		return false
	}
	return same
}

// resetTimer arms the debounce window while anything is pending, and parks the
// timer when nothing is. It always leaves the timer armed when the table is
// non-empty: a timer that is only re-armed while its deadline is still in the
// future loses every event that arrives between a flush and the reset, because
// the timer has already fired and nothing wakes it again.
func (w *Watcher) resetTimer(timer *time.Timer) {
	w.mu.Lock()
	pending := len(w.pending)
	w.mu.Unlock()

	if pending == 0 {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return
	}
	timer.Reset(w.opts.Debounce)
}

// directories lists every directory to watch, by walking the vault with the
// ignore rules applied. It does not follow symlinked directories.
func (w *Watcher) directories() ([]string, error) {
	root := w.opts.Root
	out := []string{root}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			w.logger().Warn("skipping an unreadable vault directory",
				"action", "watch.scan", "dir", filepath.Base(p), "err", err.Error())
			return nil
		}
		if !d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if ignoredDirName(d.Name()) {
			return fs.SkipDir
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// rel converts an absolute path to a vault-relative one, or reports that it is
// not inside the vault at all. Watch events are the least trustworthy input the
// watcher has: they come from the kernel, through a symlinked temp directory on
// macOS, and are checked anyway.
func (w *Watcher) rel(abs string) (string, bool) {
	real, err := filepath.EvalSymlinks(w.opts.Root)
	if err != nil {
		real = w.opts.Root
	}
	r, err := filepath.Rel(real, abs)
	if err != nil {
		return "", false
	}
	if !within(real, abs) {
		return "", false
	}
	rel := filepath.ToSlash(r)
	if rel == "." {
		return "", false
	}
	return rel, true
}

func (w *Watcher) logger() *obs.Logger {
	if w.opts.Log != nil {
		return w.opts.Log
	}
	return obs.Discard()
}
