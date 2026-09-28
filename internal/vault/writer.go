package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// lockStripes is the width of the save path's lock table. Fixed rather than a
// map keyed by path: a map grows for every path the vault has ever held and is
// never emptied, which is a slow memory leak in a process that runs for weeks.
// Stripes bound it, and the collision cost is one extra serialised save.
const lockStripes = 256

// SelfwriteWindow is how long a self-write registration is honoured.
//
// The window exists only to absorb the latency between our write and the
// watcher's delivery of the resulting event. Suppression is by content hash and
// not by time, so a DM who edits the same page inside the window still lands
// their edit: the bytes differ, so the hash differs, so the event is reported.
const SelfwriteWindow = 10 * time.Second

// SelfwriteStore records the hashes the app itself just wrote, so the watcher
// can tell its own writes from a DM's edit in Obsidian.
//
// It is an interface declared here rather than imported from the indexer so
// that the dependency arrow runs sync -> vault. Nothing in this package may
// import internal/store: vault sits below it.
type SelfwriteStore interface {
	PutSelfwrite(ctx context.Context, path string, hash []byte, expires time.Time) error
	IsSelfwrite(ctx context.Context, path string, hash []byte) (bool, error)
}

// ErrNotPermitted is returned by Save when the request names no write
// permission. The real authorization decision was made upstream by the Perm
// middleware; this is the last line that refuses a save nobody authorised.
var ErrNotPermitted = errors.New("save requires a write permission")

// ErrConflict is the sentinel a Save that lost the race returns. Match it with
// errors.Is; get the two versions with errors.As on *ConflictError.
var ErrConflict = errors.New("file changed on disk")

// ConflictError carries both sides of a lost save so the conflict page can
// render them.
//
// The two versions are held in the error rather than re-read on demand because
// a second read is a second race: by the time the page renders, the file may
// have moved again and the DM would be shown a "their" version that is neither.
type ConflictError struct {
	path   string
	theirs []byte
	ours   []byte
}

// Conflict builds a ConflictError. It is exported so the reveal and fence paths
// can report a lost race they detected themselves.
func Conflict(path string, theirs, ours []byte) *ConflictError {
	return &ConflictError{path: path, theirs: theirs, ours: ours}
}

// Error implements error.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("%v: %s has %d bytes on disk and %d in the editor",
		ErrConflict, e.path, len(e.theirs), len(e.ours))
}

// Unwrap makes errors.Is(err, ErrConflict) true for a ConflictError.
func (e *ConflictError) Unwrap() error { return ErrConflict }

// Path is the vault-relative path the conflict happened on.
func (e *ConflictError) Path() string { return e.path }

// Theirs is what is on disk now.
func (e *ConflictError) Theirs() []byte { return e.theirs }

// Ours is what the editor was trying to save.
func (e *ConflictError) Ours() []byte { return e.ours }

// SaveRequest is one editor save.
//
// BaseContentHash is the hash of the bytes the editor was looking at. It is a
// hash and not the content itself because the content is vault text and this
// struct crosses a boundary where content must not travel.
type SaveRequest struct {
	// Path is the vault-relative page path, as it arrived from the router.
	Path string
	// NewContent is the full file, frontmatter and all, exactly as it is to be
	// written. The writer never reflows it.
	NewContent []byte
	// BaseContentHash is Hash of the bytes the editor was based on.
	BaseContentHash []byte
	// ActorID is the user who saved, for the audit record.
	ActorID int64
	// ExpectPerm is the permission the route was mounted with. The save path
	// refuses anything that is not a write permission.
	ExpectPerm authz.Permission
}

// Writer is the only way the application changes a vault file.
//
// It exists so that the file is authoritative and the index is derived: a save
// goes through here, the bytes land atomically, and only then is the change
// announced to the indexer. Nothing else may call os.WriteFile on a vault file
// the user can reach.
type Writer struct {
	// Root is the vault root. Every request path is resolved against it, so a
	// traversal in Path is refused rather than followed.
	Root string
	// MaxBytes caps one save. Zero means MaxFileBytes.
	MaxBytes int64
	// Store receives a registration for every write the watcher must not
	// report. A nil Store suppresses nothing, which is the honest default
	// before the index is open.
	Store SelfwriteStore
	// Clock is the time source. A nil Clock is the system clock.
	Clock obs.Clock
	// Log receives one record per save. A nil Log discards.
	Log *obs.Logger
	// SelfwriteWindow overrides SelfwriteWindow. Zero means the default.
	SelfwriteWindow time.Duration

	// beforeReplace is the seam the atomic-write tests inject a failure into.
	beforeReplace func(temp, dest string) error
	locks         [lockStripes]sync.Mutex
}

// NewWriter returns a Writer for a vault root.
func NewWriter(root string, log *obs.Logger) *Writer {
	return &Writer{Root: root, Log: log}
}

// Save writes a page file, refusing to overwrite an edit the editor never saw.
//
// The order is the whole point: take the path's lock, re-read, compare, write
// atomically, then announce. Comparing before writing under the same lock is
// what makes TestConcurrentSaveSamePath have exactly one winner; announcing
// after the rename is what keeps the indexer from reading a file that is still
// the old one.
func (w *Writer) Save(ctx context.Context, req SaveRequest) error {
	if !isWritePerm(req.ExpectPerm) {
		return fmt.Errorf("%w: %q may not save", ErrNotPermitted, req.ExpectPerm)
	}
	p, err := Resolve(w.Root, req.Path)
	if err != nil {
		return err
	}
	if limit := w.maxBytes(); int64(len(req.NewContent)) > limit {
		return fmt.Errorf("save %s: content is %d bytes, over the %d byte limit",
			p.Rel(), len(req.NewContent), limit)
	}

	unlock := w.lockPath(p.Rel())
	defer unlock()

	current, err := Read(ctx, p)
	switch {
	case errors.Is(err, ErrNotFound):
		// A create has no base content, so an empty base hash is the only
		// acceptable one.
		current = nil
	case err != nil:
		return err
	}

	if !bytes.Equal(Hash(current), req.BaseContentHash) {
		return Conflict(p.Rel(), current, req.NewContent)
	}

	if err := writeFile(ctx, p, req.NewContent, w.beforeReplace); err != nil {
		return err
	}
	if err := w.registerSelfwrite(ctx, p, req.NewContent); err != nil {
		// The bytes are on disk and correct. A self-write registration that
		// fails only costs one redundant index pass, so it is logged rather
		// than unwound — unwinding would mean re-reporting a save the user
		// already watched succeed.
		w.logger().WarnContext(ctx, "self-write registration failed",
			"action", "selfwrite.put", "path", p.Rel(), "err", err.Error())
	}

	w.logger().InfoContext(ctx, "vault file saved",
		"action", "page.save", "path", p.Rel(), "actor_id", req.ActorID,
		"bytes", len(req.NewContent), "expect_perm", string(req.ExpectPerm))
	return nil
}

// registerSelfwrite tells the store the exact bytes this path now holds.
func (w *Writer) registerSelfwrite(ctx context.Context, p Path, content []byte) error {
	if w.Store == nil {
		return nil
	}
	sum := sha256.Sum256(content)
	return w.Store.PutSelfwrite(ctx, p.Rel(), sum[:], w.clock().Add(w.window()))
}

// lockPath takes the stripe for a vault-relative path and returns its release.
// Hashing the path picks the stripe, so the table is a fixed array rather than
// a map that grows once per path the vault has ever seen.
func (w *Writer) lockPath(rel string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(rel))
	m := &w.locks[h.Sum32()%lockStripes]
	m.Lock()
	return m.Unlock
}

func (w *Writer) maxBytes() int64 {
	if w.MaxBytes > 0 {
		return w.MaxBytes
	}
	return MaxFileBytes
}

func (w *Writer) window() time.Duration {
	if w.SelfwriteWindow > 0 {
		return w.SelfwriteWindow
	}
	return SelfwriteWindow
}

func (w *Writer) clock() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

func (w *Writer) logger() *obs.Logger {
	if w.Log != nil {
		return w.Log
	}
	return obs.Discard()
}

// isWritePerm reports whether a permission may mutate a file. The role
// comparison itself happened in the Perm middleware; this is the assertion that
// the route was mounted with a write permission at all, so a save cannot be
// reached through a read route by a future wiring mistake.
func isWritePerm(perm authz.Permission) bool {
	switch perm {
	case authz.PermWritePage, authz.PermWriteAny, authz.PermWriteSecret,
		authz.PermDeletePage, authz.PermDM, authz.PermAdmin:
		return true
	}
	return false
}
