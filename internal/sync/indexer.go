package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// DefaultRenameWindow is how long a page that disappeared can still be matched
// to a page that appeared with the same content.
//
// Sixty seconds is the gap between an `mv` on a sync client and the file
// appearing under its new name, and it is the whole tolerance for acting on a
// guess. A page that vanished a week ago and a page created today that happen
// to hold the same bytes are not a rename, and a copy of a page is not a
// rename; the only signal strong enough to act on is "these two events were the
// same event", and the window is how that is said.
const DefaultRenameWindow = 60 * time.Second

// allPagesLimit is the limit handed to ListRecentPages when something needs
// every page. It is the only lister in store that can answer "all of them" and
// no vault holds a sixteenth of a million pages — a vault that did would exhaust
// memory long before the limit did.
const allPagesLimit = 1 << 24

// Problem codes the indexer adds to md's own.
const (
	// ProblemAuthorUnknown is a fence naming an author= that is not a known
	// account, or naming none. The secret is not indexed rather than indexed
	// against a fabricated author, so the fence stays redacted and the index
	// simply does not know it exists.
	ProblemAuthorUnknown = secrets.ProblemAuthorUnknown
	// ProblemUnreadable is a path the indexer could not index at all: a
	// directory, or a file the filesystem would not stat.
	ProblemUnreadable = "index.unreadable"
	// ProblemOversize is a file over the read cap. It is reported rather than
	// truncated, because a truncated page is indistinguishable from a correct
	// one until the day it matters.
	ProblemOversize = "index.oversize"
	// ProblemUnknownLinkKind is a reference whose kind is not one of the five
	// the schema knows. It is dropped with a problem rather than written
	// through, because the column is free text and a wrong value would sit in
	// the index looking valid.
	ProblemUnknownLinkKind = "index.unknown_link_kind"
	// ProblemUnusableFence is a secret fence whose id is not the twelve hex
	// characters the on-disk format specifies, which includes every fence md had
	// to give a placeholder id to. The bytes stay a secret on the page; the index
	// declines to give them an identity it cannot name.
	ProblemUnusableFence = "index.secret_unusable"
)

// Options configures an Indexer.
type Options struct {
	// DB is the index this indexer writes. Required.
	DB *store.DB
	// Root is the vault root. Required.
	Root string
	// Renderer is the Markdown parser used for extraction. Nil selects a
	// default renderer with no plugin extenders, which is what an index built
	// before any plugin has registered wants.
	Renderer *md.Renderer
	// Bus receives one invalidation per changed page. Nil publishes nothing,
	// which is the honest state before the HTTP layer exists.
	Bus *Bus
	// Log receives the indexer's own records. Nil discards.
	Log *obs.Logger
	// Clock is the time source. Nil is the system clock. It must be set before
	// the first pass, and the race detector is what enforces that rather than a
	// comment.
	Clock obs.Clock
	// RenameWindow overrides DefaultRenameWindow. Zero means the default.
	RenameWindow time.Duration
	// AllowCaseCollisions downgrades a case collision from a walk error to a
	// warning. See vault.WalkOptions.
	AllowCaseCollisions bool
	// DanglingCapacity overrides DefaultDanglingCapacity, which is how many
	// distinct names the index remembers an unresolved reference for. Zero means
	// the default.
	DanglingCapacity int
	// UnresolvedAuthorCapacity overrides DefaultUnresolvedAuthorCapacity, which
	// is how many pages the index remembers an unattributable secret fence for.
	// Zero means the default.
	UnresolvedAuthorCapacity int
	// ResolveSystem maps a page type to the plugin that owns it. Nil means every
	// page is core-owned, which is the correct answer until a plugin registers
	// a page type.
	ResolveSystem func(pageType string) (systemID string, ok bool)
}

// Indexer turns vault files into index rows and announces what changed.
//
// Two properties are the whole contract:
//
//   - Idempotence. A file whose content hash already matches its indexed row
//     costs one read and one comparison and writes nothing, so a pass may run at
//     any time, as often as the watcher likes, and a reconciliation scan over an
//     unchanged vault is free.
//   - One transaction per changed file. A reader never sees a page without its
//     links, headings, tags, text and secrets, because all of them are written
//     through the same transaction as the page row. A crash mid-transaction rolls
//     it back and the next scan re-indexes the file from its bytes, which are
//     still on disk because the file is canonical.
//
// Nothing here writes to the vault. The only write path is vault.Writer, and
// this package reaches it only to re-read a file the writer has already changed.
type Indexer struct {
	db                  *store.DB
	root                string
	renderer            *md.Renderer
	bus                 *Bus
	log                 *obs.Logger
	clock               obs.Clock
	window              time.Duration
	allowCaseCollisions bool
	resolveSystem       func(string) (string, bool)
	// capacity bounds the unresolved-reference index. See
	// DefaultDanglingCapacity.
	capacity int
	// unresolvedCapacity bounds the unattributable-author index. See
	// DefaultUnresolvedAuthorCapacity.
	unresolvedCapacity int

	// scanner is the index's own view of the vault for the reconciliation
	// scan. It is owned here rather than exposed, because a scan that a caller
	// could mark as done would report a file as indexed before it had been.
	//
	// scanMu serialises every call into it. The scanner keeps plain maps and is
	// documented for one goroutine at a time, and the indexer genuinely has two
	// callers at once: the watcher's batch goroutine and whatever periodic
	// reconciliation runs beside it. The lock is held for a stat and a map
	// assignment, never for a read of the file or a transaction.
	scanner *vault.Scanner
	scanMu  sync.Mutex

	mu sync.Mutex
	// vanished holds the pages a pass found gone and has already deleted, for
	// the length of the rename window. The row is gone; the identity is not,
	// because a page that reappears with the same bytes has to be told which
	// name it used to have.
	vanished map[string]vanishedPage
	// dangling holds the references this index could not resolve, keyed by the
	// name they name, so that creating a page with that name re-points only the
	// references that want it.
	dangling map[string]map[string]bool
	// danglingOrder is the arrival order of the keys in dangling, for eviction.
	danglingOrder []string
	// unresolved holds the paths whose last committed write left a secret fence
	// naming an account that did not exist, mapped to the lower-cased usernames
	// it named. It is what makes creating that account enough to index the
	// secret, without the DM editing the file; see RetryUnresolvedAuthors.
	unresolved map[string]map[string]bool
	// unresolvedOrder is the arrival order of the keys in unresolved, for
	// eviction.
	unresolvedOrder []string
}

// DefaultDanglingCapacity is how many distinct names the index remembers an
// unresolved reference for.
//
// The map is what makes a link written before its target exist resolve later, and
// it is bounded because a vault full of typos would otherwise accumulate a
// dangling reference for ever. Past the bound the oldest name is forgotten, which
// costs a re-link the next time that name is written; it never costs a wrong
// answer, because a forgotten reference is simply left unresolved.
const DefaultDanglingCapacity = 4096

// DefaultUnresolvedAuthorCapacity is how many pages the index remembers an
// unattributable secret fence for.
//
// A fence names its author by username and secrets.author_id is a foreign key,
// so a fence written before its author's account exists cannot be indexed. This
// is the set of pages waiting for that account to be created, and it is bounded
// for the same reason the dangling-reference index is: a vault with a typo in
// every note would otherwise accumulate a promise to re-read a page for ever.
// Past the bound the oldest page is forgotten, which costs that page the
// automatic retry and nothing else — a forgotten page stays a problem reported
// on the page, and a full reindex still picks it up.
const DefaultUnresolvedAuthorCapacity = 4096

// vanishedPage is what a deletion leaves behind for the rename window: the names
// the page answered to and the bytes it had them with.
type vanishedPage struct {
	path string
	// referrers are the pages that linked to this one. Deleting the row sets
	// their links.target_page_id to NULL, because the foreign key is ON DELETE
	// SET NULL — so without them a rename would silently blank the backlinks of
	// every page that pointed at the old name.
	referrers []string
	// aliases is the whole set of names, the old basename first. A rename creates
	// a *new* page row, so without carrying the names across, a page renamed
	// twice would lose the first name when the intermediate row it was attached
	// to was deleted.
	aliases []string
	hash    []byte
	at      time.Time
}

// New returns an Indexer.
func New(opts Options) (*Indexer, error) {
	if opts.DB == nil {
		return nil, errors.New("sync: an index database is required")
	}
	if opts.Root == "" {
		return nil, errors.New("sync: a vault root is required")
	}
	log := loggerOf(opts.Log)
	clock := opts.Clock
	if clock == nil {
		clock = obs.SystemClock
	}
	renderer := opts.Renderer
	if renderer == nil {
		renderer = md.New(md.Options{})
	}
	window := opts.RenameWindow
	if window <= 0 {
		window = DefaultRenameWindow
	}
	capacity := opts.DanglingCapacity
	if capacity <= 0 {
		capacity = DefaultDanglingCapacity
	}
	unresolvedCapacity := opts.UnresolvedAuthorCapacity
	if unresolvedCapacity <= 0 {
		unresolvedCapacity = DefaultUnresolvedAuthorCapacity
	}
	return &Indexer{
		db:                  opts.DB,
		root:                opts.Root,
		renderer:            renderer,
		bus:                 opts.Bus,
		log:                 log,
		clock:               clock,
		window:              window,
		allowCaseCollisions: opts.AllowCaseCollisions,
		resolveSystem:       opts.ResolveSystem,
		capacity:            capacity,
		unresolvedCapacity:  unresolvedCapacity,
		scanner:             vault.NewScanner(log),
		vanished:            map[string]vanishedPage{},
		dangling:            map[string]map[string]bool{},
		unresolved:          map[string]map[string]bool{},
	}, nil
}

// Walk enumerates the vault with the walker's rules — ignore list, size cap,
// case-collision detection — and returns the files to index. The boot sequence
// indexes what it returns and then calls RemoveMissing with the same list.
func (ix *Indexer) Walk(ctx context.Context) (vault.WalkResult, error) {
	return vault.Walk(ctx, ix.root, vault.WalkOptions{AllowCaseCollisions: ix.allowCaseCollisions})
}

// Watch starts a vault watcher whose batches index straight into this indexer,
// with a self-write store over the same index as the suppression table.
//
// The watcher is a latency optimisation, not a guarantee: fsnotify drops events
// when the kernel queue overflows and does not fire at all on some network
// mounts. What makes the index eventually correct is Reconcile, which the boot
// sequence must therefore schedule on a ticker.
func (ix *Indexer) Watch(ctx context.Context) (*vault.Watcher, error) {
	w, err := vault.NewWatcher(vault.WatchOptions{
		Root:  ix.root,
		Store: NewSelfwrites(ix.db, ix.log),
		Log:   ix.log,
		Clock: ix.clock,
	})
	if err != nil {
		return nil, err
	}
	w.OnBatch(func(ctx context.Context, paths []string) {
		if _, err := ix.IndexBatch(ctx, paths); err != nil {
			ix.log.WarnContext(ctx, "a watch batch could not be indexed",
				"action", "index.batch", "paths", len(paths), "err", err.Error())
		}
	})
	if err := w.Start(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

// Reconcile runs one stat-only scan and applies everything it found.
//
// It is the correctness half of the change pipeline. The scanner compares the
// files it has been told about against the files on disk and returns only the
// ones that differ — on disk and unrecorded, recorded and gone, or changed in
// size or mtime — so a pass over a vault of ten thousand untouched files costs
// ten thousand stats and no writes at all.
func (ix *Indexer) Reconcile(ctx context.Context) (BatchResult, error) {
	changed, err := ix.scanFiles(ctx)
	if err != nil {
		return BatchResult{}, err
	}
	if len(changed) == 0 {
		return BatchResult{}, nil
	}
	return ix.IndexBatch(ctx, changed)
}

// Result is what one file's index pass did.
type Result struct {
	// Path is the vault-relative path.
	Path string
	// PageID is the page row's id, or 0 when the file was gone and there was no
	// row to delete.
	PageID int64
	// Hash is the sha256 of the bytes now indexed, or nil for a deletion.
	Hash []byte
	// Kind is what happened. A file whose bytes already matched reports
	// ChangeUpdated with Unchanged set: nothing moved, and a subscriber must not
	// be woken for it.
	Kind ChangeKind
	// Unchanged reports that the content hash already matched and that no row
	// was written.
	Unchanged bool
	// Problems are the parse and validation problems the pass recorded, from md
	// and from this package. A file with problems is still indexed.
	Problems []Problem
}

// Problem is one recoverable problem with a file, as the indexer saw it.
type Problem struct {
	// Code is stable and machine-readable.
	Code string
	// Path is the vault-relative path.
	Path string
	// SecretID is set when the problem concerns one secret.
	SecretID string
	// Message is lowercase, unpunctuated, and never contains file content.
	Message string
}

// String describes the problem, naming the secret when there is one.
func (p Problem) String() string {
	if p.SecretID != "" {
		return p.Code + ": " + p.SecretID + ": " + p.Message
	}
	return p.Code + ": " + p.Message
}

func problemsFromMD(path string, in []md.Problem) []Problem {
	if len(in) == 0 {
		return nil
	}
	out := make([]Problem, 0, len(in))
	for _, p := range in {
		out = append(out, Problem{Code: p.Code, Path: path, SecretID: p.SecretID, Message: p.Message})
	}
	return out
}

// Appeared is a page a pass created: its path, its row id, and the hash of the
// bytes that created it.
//
// The hash is passed rather than re-read because the pass already has it, and a
// rename is matched on it. Re-reading the file to ask whether it has changed
// since the pass read it would be a race with no useful answer.
type Appeared struct {
	// Path is the vault-relative path the page was created at.
	Path string
	// PageID is the created page's id.
	PageID int64
	// ContentHash is the sha256 of the bytes that created the page.
	ContentHash []byte
}

// Rename is a confirmed rename: two files, one set of bytes, inside the window.
type Rename struct {
	// From is the name the page had, which is the alias now recorded.
	From string
	// To is the path the page appeared at.
	To string
	// PageID is the surviving page's id.
	PageID int64
}

// BatchResult is what one pass over a set of paths did.
type BatchResult struct {
	// Indexed is the per-file result, in path order.
	Indexed []Result
	// Renames are the confirmed renames, each already applied.
	Renames []Rename
	// Unchanged counts the paths whose content hash already matched.
	Unchanged int
}

// Changed reports whether the pass wrote anything at all, which is the question
// a boot sequence asks when it wants to report "nothing to do".
func (b BatchResult) Changed() bool {
	for _, r := range b.Indexed {
		if !r.Unchanged {
			return true
		}
	}
	return false
}

// Index reads one vault file and brings its index rows up to date.
//
// A path whose file no longer exists is removed from the index instead, because
// the watcher reports a deletion with the same shape as a write and a caller
// that had to tell them apart would have to stat the file twice.
func (ix *Indexer) Index(ctx context.Context, path string) (Result, error) {
	resolver, err := newLinkResolver(ctx, ix.db.Reader())
	if err != nil {
		return Result{Path: path}, err
	}
	return ix.indexOne(ctx, path, resolver, indexIfChanged)
}

// Reindex re-reads one page and publishes its invalidation, discarding the
// per-file detail.
//
// It exists because internal/secrets cannot import this package — sync sits
// above secrets in the dependency order — so the reveal and revoke paths need a
// method here that does not return a type they could not name.
func (ix *Indexer) Reindex(ctx context.Context, path string) error {
	_, err := ix.Index(ctx, path)
	return err
}

// IndexBatch applies a set of paths and then applies the rename window.
//
// The order inside a batch is the design: files that vanished are applied first,
// so their identity is recorded before any file that appeared is written, and a
// rename whose two halves arrived in the same batch is detected in the same pass
// as the two events it describes.
func (ix *Indexer) IndexBatch(ctx context.Context, paths []string) (BatchResult, error) {
	var out BatchResult
	if len(paths) == 0 {
		return out, nil
	}
	resolver, err := newLinkResolver(ctx, ix.db.Reader())
	if err != nil {
		return out, err
	}

	ordered := dedupePaths(paths)
	var gone []string
	for _, rel := range ordered {
		if ix.isGone(rel) {
			gone = append(gone, rel)
		}
	}
	for _, rel := range gone {
		res, err := ix.removeOne(ctx, rel)
		if err != nil {
			return out, err
		}
		out.Indexed = append(out.Indexed, res)
	}

	var appeared []Appeared
	for _, rel := range ordered {
		if contains(gone, rel) {
			continue
		}
		res, err := ix.indexOne(ctx, rel, resolver, indexIfChanged)
		if err != nil {
			return out, err
		}
		out.Indexed = append(out.Indexed, res)
		switch {
		case res.Unchanged:
			out.Unchanged++
		case res.Kind == ChangeCreated:
			appeared = append(appeared, Appeared{Path: rel, PageID: res.PageID, ContentHash: res.Hash})
		}
	}

	// Renames are detected before the re-point, and not only for tidiness: the
	// alias a rename records is a new name for a page, so a reference written
	// under the old name is waiting for exactly the name the rename just created.
	// Read before the rename detection, which consumes the entries it matches:
	// the pages that referenced a renamed page are exactly the pages whose
	// references the rename is about to break.
	referrers := ix.vanishedReferrers()
	renames, err := ix.RenameDetect(ctx, appeared)
	if err != nil {
		return out, err
	}
	out.Renames = renames

	// A page created after a reference to it was written leaves that reference
	// dangling, which is what happens whenever a DM creates Gundren.md after the
	// page that links to it. The re-point is targeted: the index remembered which
	// page wants which name, so creating a page — or renaming one — re-links the
	// pages that named it and nothing else.
	if err := ix.relink(ctx, appeared, renames, referrers); err != nil {
		return out, err
	}
	return out, nil
}

// relink rewrites the outgoing references of the pages that were waiting for a
// name the pass has just created.
//
// Only the links table is touched: a page's other derived rows do not depend on
// what a link points at, and rewriting them would append a revision for a change
// that is not a change to the file.
func (ix *Indexer) relink(ctx context.Context, appeared []Appeared, renames []Rename, referrers []string) error {
	names := make([]string, 0, len(appeared)+len(renames))
	for _, a := range appeared {
		names = append(names, a.Path)
	}
	// A rename is two names for one page: the path it now answers to and every
	// name it used to.
	for _, r := range renames {
		names = append(names, r.To, r.From)
	}
	wanted := append(ix.takeDangling(names), referrers...)
	wanted = dedupePaths(wanted)
	if len(wanted) == 0 {
		return nil
	}
	resolver, err := newLinkResolver(ctx, ix.db.Reader())
	if err != nil {
		return err
	}
	for _, rel := range wanted {
		p := vault.New(ix.root, rel)
		src, err := vault.Read(ctx, p)
		if err != nil {
			// The file went away between the two passes; its row is already gone
			// or will be on the next scan.
			continue
		}
		page, err := store.GetPageByPath(ctx, ix.db.Reader(), rel)
		if err != nil {
			continue
		}
		doc := md.Parse(rel, src)
		facts, _ := md.Extract(doc, ix.renderer)
		tx, err := ix.db.Writer().BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := store.DeleteLinksByPage(ctx, tx, page.ID); err != nil {
			_ = tx.Rollback()
			return err
		}
		res := Result{Path: rel, PageID: page.ID}
		if _, err := writeLinks(ctx, tx, page.ID, facts.Links, resolver, &res); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		ix.publish(PageInvalidated{
			PageID: page.ID, Path: rel, Hash: page.ContentHash, Kind: ChangeUpdated,
		})
		ix.log.InfoContext(ctx, "references re-pointed after the page they name appeared",
			"action", "index.relink", "path", rel, "page_id", page.ID)
	}
	return nil
}

// takeDangling forgets and returns the pages that were waiting for any of the
// names a pass has just made real.
func (ix *Indexer) takeDangling(names []string) []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var out []string
	for _, target := range names {
		name := strings.ToLower(md.Basename(target))
		waiters := ix.dangling[name]
		if len(waiters) == 0 {
			continue
		}
		for path := range waiters {
			out = append(out, path)
		}
		delete(ix.dangling, name)
		ix.dropDanglingLocked(name)
	}
	sort.Strings(out)
	return dedupePaths(out)
}

// vanishedReferrers returns every page that was linked to by a page a pass
// deleted. They are re-linked because a deletion or a rename may have left their
// references dangling, and the resolver is the thing that fixes that.
func (ix *Indexer) vanishedReferrers() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var out []string
	for _, v := range ix.vanished {
		out = append(out, v.referrers...)
	}
	return out
}

// rememberDangling records that one page's reference could not be resolved, so
// that creating a page by that name re-links it.
func (ix *Indexer) rememberDangling(rel string, targets []string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for _, target := range targets {
		name := strings.ToLower(md.Basename(target))
		if name == "" {
			continue
		}
		waiters := ix.dangling[name]
		if waiters == nil {
			if len(ix.dangling) >= ix.capacity {
				ix.evictDanglingLocked()
			}
			ix.danglingOrder = append(ix.danglingOrder, name)
			waiters = map[string]bool{}
			ix.dangling[name] = waiters
		}
		waiters[rel] = true
	}
}

func (ix *Indexer) evictDanglingLocked() {
	for len(ix.danglingOrder) > 0 {
		oldest := ix.danglingOrder[0]
		ix.danglingOrder = ix.danglingOrder[1:]
		if _, live := ix.dangling[oldest]; !live {
			continue
		}
		delete(ix.dangling, oldest)
		ix.log.Warn("too many unresolved references, forgetting the oldest name",
			"action", "index.dangling_evict", "name", oldest, "limit", ix.capacity)
		return
	}
}

func (ix *Indexer) dropDanglingLocked(name string) {
	for i, key := range ix.danglingOrder {
		if key == name {
			ix.danglingOrder = append(ix.danglingOrder[:i], ix.danglingOrder[i+1:]...)
			return
		}
	}
}

// indexOne is the whole per-file pipeline: read, compare, write, announce.
func (ix *Indexer) indexOne(ctx context.Context, rel string, resolver *linkResolver, mode indexMode) (Result, error) {
	p := vault.New(ix.root, rel)
	st, err := os.Stat(p.Abs())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ix.removeOne(ctx, rel)
	case err != nil:
		return Result{Path: rel}, fmt.Errorf("sync: stat %s: %w", rel, err)
	case st.IsDir():
		// A directory is not a page. The watcher delivers a directory create,
		// and answering it with a page row would put a path in the index that
		// can never be read.
		ix.forget(rel)
		ix.forgetUnresolvedAuthors(rel)
		return Result{Path: rel, Kind: ChangeUpdated, Problems: []Problem{{
			Code: ProblemUnreadable, Path: rel, Message: "path is a directory, not a page",
		}}}, nil
	case st.Size() > vault.MaxFileBytes:
		// Observed rather than skipped, so the scan does not report the same
		// oversize file every sixty seconds for ever; the next size change puts
		// it back in the queue.
		ix.observe(rel, st)
		return Result{Path: rel, Problems: []Problem{{
			Code:    ProblemOversize,
			Path:    rel,
			Message: fmt.Sprintf("file is %d bytes, over the %d byte limit", st.Size(), vault.MaxFileBytes),
		}}}, nil
	}

	src, err := vault.Read(ctx, p)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return ix.removeOne(ctx, rel)
		}
		// A file that stats but cannot be read is a warning, not a failure. The
		// walk already reports unreadable paths, and §7.4 says they surface in
		// the sync panel rather than silently vanishing. Propagating the error
		// instead would abort the whole batch — and the boot walk is one batch —
		// so a single file with the wrong permissions would stop the app from
		// starting. That is a denial of service created by one chmod, and the
		// 60-second reconciliation scan retries it anyway.
		return Result{Path: rel, Problems: []Problem{{
			Code:    ProblemUnreadable,
			Path:    rel,
			Message: "file could not be read",
		}}}, nil
	}
	hash := vault.Hash(src)

	// The idempotence check, deliberately outside the transaction: a file that
	// has not changed is the common case by a wide margin, and paying for the
	// single write connection to discover there is nothing to write is what
	// turns a ten-thousand-file scan into a stall.
	//
	// A forced pass skips it, which is the only reason RetryUnresolvedAuthors
	// exists in the shape it does: the hash says the bytes are the same, and it
	// is right about that, but the index it was compared against was built
	// before an account existed that the same bytes ask for by name.
	prev, err := store.GetPageByPath(ctx, ix.db.Reader(), rel)
	switch {
	case mode == indexIfChanged && err == nil && bytes.Equal(prev.ContentHash, hash):
		ix.observe(rel, st)
		return Result{Path: rel, PageID: prev.ID, Hash: hash, Kind: ChangeUpdated, Unchanged: true}, nil
	case err != nil && !errors.Is(err, store.ErrNoRows):
		return Result{Path: rel}, err
	}

	res, err := ix.writeOne(ctx, rel, src, hash, st, resolver, mode)
	if err != nil {
		return Result{Path: rel, Hash: hash}, err
	}
	ix.observe(rel, st)
	return res, nil
}

// writeOne writes one file's whole derived state in one transaction.
//
// Every store call below takes an Execer or a Queryer and the transaction is the
// caller's, which is the store API's split and the reason the atomicity property
// is expressible at all: the page row, its links, its headings, its tags, its
// text, its secrets, its search-index rows and its revision are all written
// through the same transaction, so a reader on the read pool sees either all of
// them or none.
func (ix *Indexer) writeOne(
	ctx context.Context,
	rel string,
	src []byte,
	hash []byte,
	st os.FileInfo,
	resolver *linkResolver,
	mode indexMode,
) (Result, error) {
	doc := md.Parse(rel, src)
	facts, mdProblems := md.Extract(doc, ix.renderer)
	fences, fenceProblems := secrets.Parse(doc)

	res := Result{Path: rel, Hash: hash}
	res.Problems = append(problemsFromMD(rel, mdProblems), problemsFromMD(rel, fenceProblems)...)

	now := ix.clock()
	tx, err := ix.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("sync: begin indexing %s: %w", rel, err)
	}
	// Rollback after a successful commit is a no-op, so this one deferred call
	// is the whole error path rather than a second return to remember.
	defer tx.Rollback()

	// The page row is re-read inside the transaction, because the check above
	// happened on the read pool and another pass may have written since.
	cur, err := store.GetPageByPath(ctx, tx, rel)
	if err != nil && !errors.Is(err, store.ErrNoRows) {
		return res, err
	}
	if err == nil && mode == indexIfChanged && bytes.Equal(cur.ContentHash, hash) {
		// Two passes raced and both saw an unindexed file. The second one to
		// reach the write connection finds the first one's work already done and
		// writes nothing, which is what makes idempotence hold under concurrency
		// as well as in sequence. The deferred rollback undoes the empty
		// transaction.
		res.PageID, res.Kind, res.Unchanged = cur.ID, ChangeUpdated, true
		return res, nil
	}
	kind := ChangeCreated
	createdAt := now
	if err == nil {
		kind = ChangeUpdated
		createdAt = cur.CreatedAt
	}

	title := publicTitle(doc, facts)
	var systemID string
	if ix.resolveSystem != nil {
		if id, ok := ix.resolveSystem(facts.PageType); ok {
			systemID = id
		}
	}
	pageID, err := store.UpsertPage(ctx, tx, store.Page{
		Path:        rel,
		Basename:    md.Basename(rel),
		Title:       title,
		Frontmatter: string(doc.Frontmatter),
		ContentHash: hash,
		MTimeUnix:   st.ModTime().Unix(),
		SizeBytes:   st.Size(),
		PageType:    facts.PageType,
		SystemID:    systemID,
		CreatedAt:   createdAt,
		UpdatedAt:   now,
	})
	if err != nil {
		return res, err
	}
	res.PageID, res.Kind = pageID, kind
	// Registered before anything is resolved, so a page's own name and every
	// later file in this batch can find it.
	resolver.note(pageID, rel)

	// The previous visibilities are read before the fences are replaced, because
	// after the replacement they are gone and every fence would look new.
	previous, err := store.ListSecretRowsByPage(ctx, tx, pageID)
	if err != nil {
		return res, err
	}

	unresolved, err := ix.writeFacts(ctx, tx, rel, pageID, doc, facts, fences, title, resolver, &res)
	if err != nil {
		return res, err
	}

	source := store.RevisionExternal
	if kind == ChangeCreated {
		source = store.RevisionCreate
	}
	if _, err := store.AppendRevision(ctx, tx, store.Revision{
		PageID:      pageID,
		ContentHash: hash,
		Content:     string(src),
		At:          now,
		Source:      source,
	}); err != nil {
		return res, err
	}
	if _, err := store.PruneRevisions(ctx, tx, pageID); err != nil {
		return res, err
	}
	if err := touchLastChange(ctx, tx, st.ModTime()); err != nil {
		return res, err
	}
	// A visibility that moved under the index is an authorization change whether
	// or not anybody pressed a button: a DM who edits a fence in Obsidian has
	// revoked a secret, and every live stream carrying the old answer has to be
	// terminated. It is detected here, in the transaction that caused it, because
	// the generation is only meaningful together with the index it describes.
	bumped, err := bumpOnVisibilityChange(ctx, tx, pageID, previous, fences)
	if err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("sync: commit indexing %s: %w", rel, err)
	}
	// After the commit and not before, because the set is only true of what the
	// index now holds: a rolled-back write must not leave a promise behind, and
	// a committed one must not leave the old promise behind either.
	ix.setUnresolvedAuthors(rel, unresolved)
	if bumped {
		ix.log.InfoContext(ctx, "a secret visibility changed in the file, authorization generation bumped",
			"action", "index.authz_bump", "path", rel, "page_id", pageID)
	}
	for _, p := range res.Problems {
		// One line per problem, because a page with six problems and a count of
		// six is a page the DM cannot fix.
		ix.log.WarnContext(ctx, "page indexed with a problem",
			"action", "index.problem", "path", rel, "problem", p.String())
	}
	ix.publish(PageInvalidated{PageID: pageID, Path: rel, Hash: hash, Kind: kind})
	ix.log.InfoContext(ctx, "page indexed",
		"action", "index.page", "path", rel, "page_id", pageID, "kind", string(kind),
		"bytes", len(src), "problems", len(res.Problems))
	return res, nil
}

// writeFacts replaces every derived row of one page. It returns the usernames a
// fence on the page named that no account answered, which is the pending-retry
// set for that path and nothing else.
func (ix *Indexer) writeFacts(
	ctx context.Context,
	tx store.Execer,
	rel string,
	pageID int64,
	doc *md.Doc,
	facts md.Extracted,
	fences []secrets.Secret,
	title string,
	resolver *linkResolver,
	res *Result,
) ([]string, error) {
	// The derived rows are replaced wholesale rather than diffed. A diff would
	// have to know what changed, and the file is right there: the hash already
	// said this is not the same content, so the cheapest correct answer is to
	// delete what the old content produced and write what the new one does.
	if err := store.DeleteLinksByPage(ctx, tx, pageID); err != nil {
		return nil, err
	}
	if err := store.DeleteHeadingsByPage(ctx, tx, pageID); err != nil {
		return nil, err
	}
	// DeleteSecretByPage removes the search-index copies first, because the
	// cascade from the secrets table would leave the FTS rows behind: a
	// content-backed fts5 table has no triggers.
	if err := store.DeleteSecretByPage(ctx, tx, pageID); err != nil {
		return nil, err
	}
	missed, err := writeLinks(ctx, tx, pageID, facts.Links, resolver, res)
	if err != nil {
		return nil, err
	}
	// Remembered rather than acted on: a reference to a page that does not exist
	// yet is not an error, it is a reference to a page the DM has not written.
	ix.rememberDangling(rel, missed)
	if err := writeHeadings(ctx, tx, pageID, facts.Headings); err != nil {
		return nil, err
	}
	if err := store.ReplacePageTags(ctx, tx, pageID, pageTags(facts.Tags)); err != nil {
		return nil, err
	}
	if err := store.ReplacePageText(ctx, tx, pageText(doc, facts, pageID, title)); err != nil {
		return nil, err
	}
	unresolved, err := ix.writeSecrets(ctx, tx, rel, pageID, fences, res)
	if err != nil {
		return nil, err
	}
	if err := writeAliases(ctx, tx, pageID, facts.Aliases); err != nil {
		return nil, err
	}
	return unresolved, nil
}

// writeLinks resolves and inserts one page's outgoing references, and returns the
// targets that resolved to nothing.
//
// The unresolved ones are returned rather than logged because they are the input
// to the index's ability to fix them later: a reference to Gundren written before
// Gundren exists is ordinary, and the moment Gundren is created the reference has
// to start working without the DM touching the file again.
func writeLinks(ctx context.Context, e store.Execer, pageID int64, links []md.Link, resolver *linkResolver, res *Result) ([]string, error) {
	var missed []string
	for _, l := range links {
		kind, ok := mapLinkKind(l.Kind)
		if !ok {
			res.Problems = append(res.Problems, Problem{
				Code: ProblemUnknownLinkKind, Path: res.Path,
				Message: "link kind is not one of the five known values",
			})
			continue
		}
		var target *int64
		switch {
		case l.SelfLink:
			// [[#heading]] points at the page it is written in. Resolving it to
			// itself is what makes a section link produce a self-reference
			// instead of dangling for ever.
			id := pageID
			target = &id
		case l.Target != "":
			if id, found := resolver.resolve(ctx, l.Target); found {
				target = &id
			} else {
				missed = append(missed, l.Target)
			}
		}
		if _, err := store.InsertLink(ctx, e, store.Link{
			SourcePageID: pageID,
			TargetPageID: target,
			TargetRaw:    l.TargetRaw,
			Kind:         kind,
			Alias:        l.Alias,
			Heading:      l.Heading,
			BlockRef:     l.BlockRef,
			SecretID:     l.Span.SecretID,
			Line:         l.Line,
		}); err != nil {
			return missed, err
		}
	}
	return missed, nil
}

// writeHeadings inserts a page's headings, each carrying the secret it lives in.
//
// The secret id is the whole reason this loop is not a bulk insert: a heading
// inside a secret is a fact about that secret, and store.TOC filters it out for
// exactly this reason.
func writeHeadings(ctx context.Context, e store.Execer, pageID int64, headings []md.Heading) error {
	for i, h := range headings {
		if err := store.InsertHeading(ctx, e, store.Heading{
			PageID:   pageID,
			Ordinal:  i + 1,
			Level:    h.Level,
			Slug:     h.Slug,
			Text:     h.Text,
			SecretID: h.Span.SecretID,
		}); err != nil {
			return err
		}
	}
	return nil
}

// pageTags converts extracted tags into page_tags rows.
//
// The source is decided by the span, and the reason is that md is the only thing
// that knows which tags came from the frontmatter block: a frontmatter offset
// lies outside the body, so SpanAt finds no span for it and the tag arrives
// carrying the zero span. An inline tag always carries a real span, because
// every inline tag is written at a body offset and a body offset inside a
// non-empty public span is not zero.
func pageTags(tags []md.Tag) []store.PageTag {
	out := make([]store.PageTag, 0, len(tags))
	for _, t := range tags {
		src := store.TagFromInline
		if t.Span.StartByte == 0 && t.Span.EndByte == 0 {
			src = store.TagFromFrontmatter
		}
		out = append(out, store.PageTag{Tag: t.Name, Source: src, SecretID: t.Span.SecretID})
	}
	return out
}

// pageText builds the public text row.
//
// Every byte of Body comes from Doc.PublicBody, which is the concatenation of
// the public spans, so a secret body cannot reach page_text or page_fts by
// construction rather than by a filter somebody has to remember. Headings is
// filtered for the same reason: a heading written inside a secret is part of the
// secret, and its text sitting in the public search index would be the leak.
func pageText(doc *md.Doc, facts md.Extracted, pageID int64, title string) store.PageText {
	headings := make([]string, 0, len(facts.Headings))
	for _, h := range facts.Headings {
		if h.Span.SecretID != "" {
			continue
		}
		headings = append(headings, h.Text)
	}
	return store.PageText{
		PageID:   pageID,
		Title:    title,
		Headings: strings.Join(headings, "\n"),
		Body:     string(doc.PublicBody()),
	}
}

// publicTitle picks the title that may be indexed and shown.
//
// md.Extract takes the first H1 wherever it was found, including inside a
// secret, so its Title is not safe to put in page_text.title: that column is
// indexed with weight 10, and a secret's first heading would become the
// highest-weighted term in the whole search index. The first *public* H1 is
// used, then the frontmatter title, then the basename.
func publicTitle(doc *md.Doc, facts md.Extracted) string {
	for _, h := range facts.Headings {
		if h.Span.SecretID == "" && h.Level == 1 {
			return h.Text
		}
	}
	if t := md.FieldString(doc.Fields, "title"); t != "" {
		return t
	}
	return md.Basename(doc.Path)
}

// writeAliases records a page's frontmatter aliases.
//
// The insert is add-only, and that is a deliberate gap rather than an oversight.
// An alias recorded by a rename has no representation in the file, so a pass
// that replaced the alias set exactly would delete every rename alias the next
// time the page was indexed; and the alternative, tracking which aliases came
// from where, is state this package would have to reconstruct across a restart
// to get right. A frontmatter alias that is later removed therefore keeps
// resolving until the page is deleted, which is a stale link rather than a
// missing page.
func writeAliases(ctx context.Context, e store.Execer, pageID int64, aliases []string) error {
	for _, a := range aliases {
		if err := store.AddPageAlias(ctx, e, pageID, a); err != nil {
			return err
		}
	}
	return nil
}

// writeSecrets writes one page's fences, and returns the usernames their
// directives named that no account answered.
//
// The visibility decides whether the body reaches the search index, and that is
// structural rather than a filter: store.IndexSecretText refuses anything that is
// not table-visible, and a hidden body never reaches the call at all. A secret
// that was revealed and is being hidden again therefore has its index copy
// deleted rather than filtered — the terms in a revoked secret stop being
// searchable immediately, not at the next restart.
func (ix *Indexer) writeSecrets(
	ctx context.Context,
	e store.Execer,
	rel string,
	pageID int64,
	fences []secrets.Secret,
	res *Result,
) ([]string, error) {
	now := ix.clock()
	var unresolved []string
	for _, f := range fences {
		if !f.Valid() {
			// A fence with no id carries md's placeholder, and a fence whose id is
			// not the twelve hex characters the format specifies is malformed
			// either way. It is reported and skipped: a fence that is on the page
			// as a secret stays one — md's span is what redacts it — but the index
			// does not pretend it has an identity it cannot name.
			res.Problems = append(res.Problems, Problem{
				Code:     ProblemUnusableFence,
				Path:     rel,
				SecretID: f.ID,
				Message:  "the fence does not carry a conforming id, a known visibility and a body",
			})
			continue
		}
		author, err := store.GetUserByUsername(ctx, e, f.Author)
		switch {
		case errors.Is(err, store.ErrNoRows):
			// A directive naming an account that does not exist, or naming none.
			// The row is not written: secrets.author_id is a foreign key, and
			// inventing an owner would put the secret in somebody's private list.
			// The fence stays redacted on disk and absent from the index, which
			// is a miss and not a leak — the opposite of what a zero would be,
			// had the column allowed one.
			message := "the fence names an author that is not a known account"
			if f.Author == "" {
				message = "the fence names no author"
			}
			res.Problems = append(res.Problems, Problem{
				Code: ProblemAuthorUnknown, Path: rel, SecretID: f.ID, Message: message,
			})
			ix.log.WarnContext(ctx, "secret fence names an unknown author, not indexing it",
				"action", "index.secret_author", "path", rel,
				"secret_id", f.ID, "author", f.Author)
			// A named author is worth remembering: the account may exist by the
			// time the next account is created, and RetryUnresolvedAuthors turns
			// that into an indexed secret without the DM touching the file. An
			// authorless fence is not, because no account can ever be created for
			// the empty name — only an edit can fix that one, and the problem on
			// the page is what tells the DM so.
			if f.Author != "" {
				unresolved = append(unresolved, f.Author)
			}
			continue
		case err != nil:
			return nil, err
		}
		created := f.CreatedAt
		if created.IsZero() {
			created = now
		}
		if err := store.InsertSecret(ctx, e, store.Secret{
			ID:         f.ID,
			PageID:     pageID,
			Ordinal:    f.Ordinal,
			Visibility: f.Visibility,
			AuthorID:   author.ID,
			Title:      f.Title,
			Body:       f.Body,
			BodyHash:   f.BodyHash,
			CreatedAt:  created,
			UpdatedAt:  now,
		}); err != nil {
			return nil, err
		}
		if f.Visibility == secrets.VisibilityTable {
			if err := store.IndexSecretText(ctx, e, f.ID, f.Visibility, f.Body); err != nil {
				return nil, err
			}
			continue
		}
		if err := store.DeleteSecretText(ctx, e, f.ID); err != nil {
			return nil, err
		}
	}
	return unresolved, nil
}

// bumpOnVisibilityChange increments the authorization generation when this pass
// moved a secret's visibility on a page that was already indexed.
//
// The first sighting of a page cannot be a change — there is nothing to have
// changed from — so a new page bumps nothing. An edit that moves a fence from
// table to dm is a revoke nobody pressed a button for, and the generation is
// what terminates a live stream still carrying the old answer.
func bumpOnVisibilityChange(
	ctx context.Context,
	e store.Execer,
	pageID int64,
	previous []store.SecretRow,
	fences []secrets.Secret,
) (bool, error) {
	if len(previous) == 0 || len(fences) == 0 {
		return false, nil
	}
	was := make(map[string]string, len(previous))
	for _, p := range previous {
		was[p.ID] = p.Visibility
	}
	changed := false
	for _, f := range fences {
		if before, seen := was[f.ID]; seen && before != string(f.Visibility) {
			changed = true
			break
		}
	}
	if !changed {
		return false, nil
	}
	if _, err := store.BumpAuthzGeneration(ctx, e); err != nil {
		return false, err
	}
	return true, nil
}

// touchLastChange advances meta['last_change_at'] to the newest mtime seen.
//
// The value is a timestamp, not a counter, so it is read and compared as a time
// rather than through MetaGetInt — and it only ever moves forward, because the
// answer the backup policy wants is "the newest change this vault has seen" and a
// file restored from a backup with an old mtime must not rewind that.
func touchLastChange(ctx context.Context, e store.Execer, mtime time.Time) error {
	when := mtime.UTC()
	raw, err := store.MetaGet(ctx, e, store.KeyLastChangeAt)
	switch {
	case errors.Is(err, store.ErrNoRows):
		// Never seen: the first change is the current one.
	case err != nil:
		return err
	default:
		seen, err := store.ParseTime(raw)
		switch {
		case err != nil:
			// A value this build cannot read is overwritten rather than refused.
			// It is derived state, and a parse failure must not make a page
			// unindexable.
		case !when.After(seen):
			return nil
		}
	}
	return store.MetaSet(ctx, e, store.KeyLastChangeAt, store.FormatTime(when))
}

// removeOne drops a page whose file is gone.
//
// The row is deleted immediately rather than held for the rename window: a page
// whose file vanished a week ago is not a page anybody is looking at, and a
// stale row outliving its file is a page that 404s when it is opened. What the
// rename needs — the old basename and the content hash — is kept in memory for
// the window instead, which is where a rename is decided.
func (ix *Indexer) removeOne(ctx context.Context, rel string) (Result, error) {
	prev, err := store.GetPageByPath(ctx, ix.db.Reader(), rel)
	if errors.Is(err, store.ErrNoRows) {
		ix.forget(rel)
		ix.forgetUnresolvedAuthors(rel)
		return Result{Path: rel, Kind: ChangeDeleted}, nil
	}
	if err != nil {
		return Result{Path: rel}, err
	}

	ix.rememberVanished(ctx, rel, prev)
	ix.forget(rel)
	// A path whose file is gone is not waiting for an account any more; keeping
	// the entry would have the retry re-read a file that is not there.
	ix.forgetUnresolvedAuthors(rel)

	tx, err := ix.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return Result{Path: rel}, fmt.Errorf("sync: begin removing %s: %w", rel, err)
	}
	defer tx.Rollback()
	if err := store.DeletePage(ctx, tx, prev.ID); err != nil {
		return Result{Path: rel}, err
	}
	// A deleted page is the common way a tag loses its last carrier, so the
	// orphan sweep belongs here rather than in a periodic job.
	if _, err := store.PruneOrphanTags(ctx, tx); err != nil {
		return Result{Path: rel}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{Path: rel}, fmt.Errorf("sync: commit removing %s: %w", rel, err)
	}
	ix.publish(PageInvalidated{PageID: prev.ID, Path: rel, Kind: ChangeDeleted})
	ix.log.InfoContext(ctx, "page removed from the index",
		"action", "index.remove", "path", rel, "page_id", prev.ID)
	return Result{Path: rel, PageID: prev.ID, Kind: ChangeDeleted}, nil
}

// rememberVanished records a deletion's identity for the rename window and
// sweeps the entries that have aged out.
//
// The sweep is inline rather than a job: the map is one entry per path ever
// deleted, and a process that runs for weeks would otherwise accumulate a row's
// worth of memory for every file the DM has ever removed.
func (ix *Indexer) rememberVanished(ctx context.Context, rel string, p store.Page) {
	now := ix.clock()
	// Read before the delete, because the delete cascades the aliases away and a
	// rename needs to carry them to the page's new row.
	aliases, err := store.ListPageAliases(ctx, ix.db.Reader(), p.ID)
	if err != nil {
		// Without the alias set a confirmed rename still records the old
		// basename, which is the case the rule exists for. Losing the frontmatter
		// aliases of a renamed page is a miss.
		ix.log.WarnContext(ctx, "could not read the aliases of a page that is going away",
			"action", "index.aliases", "path", rel, "page_id", p.ID, "err", err.Error())
		aliases = nil
	}
	names := make([]string, 0, len(aliases)+1)
	if p.Basename != "" {
		names = append(names, p.Basename)
	}
	names = append(names, aliases...)

	// Read before the delete, for the same reason: the cascade is what erases
	// the evidence of who pointed here.
	referrers, err := ix.referrersOf(ctx, p.ID)
	if err != nil {
		ix.log.WarnContext(ctx, "could not read the pages that referenced a page that is going away",
			"action", "index.referrers", "path", rel, "page_id", p.ID, "err", err.Error())
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.vanished[rel] = vanishedPage{
		path: rel, aliases: names, hash: p.ContentHash, at: now, referrers: referrers,
	}
	for path, v := range ix.vanished {
		if now.Sub(v.at) > ix.window {
			delete(ix.vanished, path)
		}
	}
}

// referrersOf returns the paths of the pages that link to one page.
//
// It is read before the row goes away, because the links table's foreign key is
// ON DELETE SET NULL: after the delete there is nothing left to say who pointed
// here, and a rename would leave every one of those references dangling.
func (ix *Indexer) referrersOf(ctx context.Context, pageID int64) ([]string, error) {
	refs, err := store.ListLinksToPage(ctx, ix.db.Reader(), pageID)
	if err != nil {
		return nil, err
	}
	// One query per distinct referring page rather than one per link, because a
	// hub page can be linked from a hundred places and they usually repeat.
	seen := make(map[int64]bool, len(refs))
	var out []string
	for _, r := range refs {
		if seen[r.SourcePageID] {
			continue
		}
		seen[r.SourcePageID] = true
		page, err := store.GetPageByID(ctx, ix.db.Reader(), r.SourcePageID)
		if errors.Is(err, store.ErrNoRows) {
			continue
		}
		if err != nil {
			return out, err
		}
		out = append(out, page.Path)
	}
	return dedupePaths(out), nil
}

// RemoveMissing deletes every indexed page whose path is not in seen.
//
// It is the other half of a full pass: indexing the files a walk found says
// nothing about the ones it did not, and a page whose file was deleted while the
// app was closed would otherwise stay in the index for ever. The boot sequence
// calls it with the walk's own file list.
func (ix *Indexer) RemoveMissing(ctx context.Context, seen []string) ([]Result, error) {
	keep := make(map[string]bool, len(seen))
	for _, p := range seen {
		keep[p] = true
	}
	pages, err := store.ListRecentPages(ctx, ix.db.Reader(), allPagesLimit)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, p := range pages {
		if keep[p.Path] {
			continue
		}
		res, err := ix.removeOne(ctx, p.Path)
		if err != nil {
			return out, err
		}
		out = append(out, res)
	}
	// A pass that also indexed files may have created pages this call did not
	// know about, so the rename window is applied once more against every page
	// young enough to still be a candidate.
	appeared, err := ix.appearedSince(ctx)
	if err != nil {
		return out, err
	}
	if _, err := ix.RenameDetect(ctx, appeared); err != nil {
		return out, err
	}
	return out, nil
}

// appearedSince returns the pages this indexer created that are still inside the
// rename window.
//
// It is how a rename is detected across a restart: the vanished side of the pair
// is a row the walk did not find, and the appeared side is a row younger than the
// window. Both are in the index, and the content hash is what pairs them.
func (ix *Indexer) appearedSince(ctx context.Context) ([]Appeared, error) {
	pages, err := store.ListRecentPages(ctx, ix.db.Reader(), allPagesLimit)
	if err != nil {
		return nil, err
	}
	now := ix.clock()
	var out []Appeared
	for _, p := range pages {
		if now.Sub(p.CreatedAt) > ix.window {
			continue
		}
		out = append(out, Appeared{Path: p.Path, PageID: p.ID, ContentHash: p.ContentHash})
	}
	return out, nil
}

// RenameDetect pairs the pages a pass created against the pages that vanished
// inside the window, and records the names they used to answer to as aliases of
// the new page.
//
// A content-hash match inside the window is the only signal acted on. A page
// that merely shares a name with a broken link is reported as a suggestion and
// nothing is written, because a name match is evidence about a spelling and not
// about an identity: a page called Notes.md would otherwise capture every
// dangling [[Notes]] in the vault.
//
// The old page's whole alias set is carried across, not just its basename. A
// rename creates a new row, so a page renamed twice would otherwise lose the
// first name when the intermediate row went away — and [[the first name]] is
// exactly the link that has to keep working.
func (ix *Indexer) RenameDetect(ctx context.Context, appeared []Appeared) ([]Rename, error) {
	if len(appeared) == 0 {
		return nil, nil
	}
	candidates := ix.renameCandidates()
	var out []Rename
	for _, a := range appeared {
		for _, v := range candidates {
			if len(v.aliases) == 0 || !bytes.Equal(v.hash, a.ContentHash) {
				continue
			}
			for _, name := range v.aliases {
				if err := store.AddPageAlias(ctx, ix.db.Writer(), a.PageID, name); err != nil {
					return out, err
				}
			}
			ix.forgetVanished(v.path)
			out = append(out, Rename{From: v.aliases[0], To: a.Path, PageID: a.PageID})
			break
		}
	}
	for _, r := range out {
		ix.log.InfoContext(ctx, "rename detected, the old names are now aliases",
			"action", "index.rename", "page_id", r.PageID, "from", r.From, "to", r.To)
		ix.publish(PageInvalidated{PageID: r.PageID, Path: r.To, Kind: ChangeRenamed})
	}
	return out, nil
}

// renameCandidates snapshots the deletions still inside the window, oldest
// first, so a run is reproducible: two pages that vanished with the same bytes
// is a copy, and which one wins should not depend on a map's iteration order.
func (ix *Indexer) renameCandidates() []vanishedPage {
	now := ix.clock()
	ix.mu.Lock()
	candidates := make([]vanishedPage, 0, len(ix.vanished))
	for _, v := range ix.vanished {
		if len(v.hash) > 0 && now.Sub(v.at) <= ix.window {
			candidates = append(candidates, v)
		}
	}
	ix.mu.Unlock()
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].path < candidates[j].path
	})
	return candidates
}

func (ix *Indexer) forgetVanished(path string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	delete(ix.vanished, path)
}

func (ix *Indexer) publish(ev PageInvalidated) {
	if ix.bus != nil {
		ix.bus.Publish(ev)
	}
}

// isGone reports that nothing is at a vault-relative path at all.
//
// Only an outright "no such file" counts. A path that exists but is a directory,
// or that the filesystem would not stat, is not a deletion: it is something
// indexOne has to report a problem about, and a batch that classified it as gone
// would delete the row of a page that is merely unreachable.
// scanFiles runs one reconciliation scan under the scanner's lock.
func (ix *Indexer) scanFiles(ctx context.Context) ([]string, error) {
	ix.scanMu.Lock()
	defer ix.scanMu.Unlock()
	return ix.scanner.Scan(ctx, ix.root)
}

// observe records what the index now believes about a file's size and mtime, so
// the next scan compares against the state the index was built from.
func (ix *Indexer) observe(rel string, st os.FileInfo) {
	ix.scanMu.Lock()
	defer ix.scanMu.Unlock()
	ix.scanner.Observe(rel, vault.FileState{Size: st.Size(), ModTime: st.ModTime()})
}

// forget drops a file from the scanner's record, because there is nothing left to
// compare it against.
func (ix *Indexer) forget(rel string) {
	ix.scanMu.Lock()
	defer ix.scanMu.Unlock()
	ix.scanner.Forget(rel)
}

func (ix *Indexer) isGone(rel string) bool {
	_, err := os.Stat(vault.New(ix.root, rel).Abs())
	return errors.Is(err, fs.ErrNotExist)
}

func dedupePaths(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
