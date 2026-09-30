package vault

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// FileState is what the indexer records about a file it has indexed: enough to
// notice a change without reading the file again.
type FileState struct {
	Size    int64
	ModTime time.Time
}

// Scanner finds the files whose on-disk state has diverged from the index.
//
// It exists because the watcher is not a guarantee (see Watcher): fsnotify
// drops events when the kernel queue overflows, does not fire at all on some
// network mounts, and is not recursive. The 60 second scan is what makes the
// index eventually correct; the watcher only makes it quickly correct.
//
// The scan is stat-only. It never reads content, which is why ten thousand
// files cost a stat each and nothing more — and also why it can miss an edit
// that lands within the same mtime tick at the same length. That residue is
// covered by the next full reconciliation, and by the watcher's content-hash
// self-write check.
type Scanner struct {
	// Record is the index's view of the vault, keyed by vault-relative path.
	// Scan reads it and never writes it: the indexer owns the record, and a
	// scan that updated it would mark a changed file as indexed before it had
	// been.
	Record map[string]FileState
	// Log receives a note about each unreadable directory. A nil Log discards.
	Log *obs.Logger
}

// NewScanner returns a Scanner over an empty record.
func NewScanner(log *obs.Logger) *Scanner {
	return &Scanner{Record: map[string]FileState{}, Log: log}
}

// Observe records a file's state, for the caller that just indexed it.
func (s *Scanner) Observe(rel string, st FileState) {
	if s.Record == nil {
		s.Record = map[string]FileState{}
	}
	s.Record[rel] = st
}

// Scan returns the vault-relative paths whose state differs from Record, in
// three ways: a file is on disk and not recorded, a file is recorded and gone,
// or a file's size or mtime moved. A caller that indexes what it is given and
// then calls Observe for each is in sync again.
func (s *Scanner) Scan(ctx context.Context, root string) ([]string, error) {
	if root == "" {
		return nil, fmt.Errorf("scan: a vault root is required")
	}
	if s.Record == nil {
		s.Record = map[string]FileState{}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve vault root: %w", err)
	}

	seen := make(map[string]bool, len(s.Record))
	var changed []string
	var visited int

	walkErr := filepath.WalkDir(realRoot, func(abs string, d fs.DirEntry, err error) error {
		visited++
		// Checking the context every few hundred entries costs one comparison
		// per file and keeps a cancelled scan from running to completion.
		if visited%256 == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
		}
		if err != nil {
			// Never a silent omission: an entry the scan cannot read is logged,
			// because the reconciliation is the only thing that will notice a
			// hole the watcher left.
			if s.Log != nil {
				s.Log.Warn("scan could not read an entry",
					"action", "scan.entry", "err", err.Error())
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if ignoredDirName(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if ignoredFileName(d.Name()) {
			return nil
		}
		rel := relOf(realRoot, abs)
		if rel == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			// The entry exists but cannot be stat'd: report it, because a file
			// the indexer has never seen is better surfaced than dropped.
			// Returning nil is the WalkDirFunc contract — the walk continues and
			// the scan stays whole — and `changed` is where this entry is
			// reported, so the error is consumed rather than dropped.
			changed = append(changed, rel)
			return nil //nolint:nilerr // recorded in changed, and the walk must continue
		}
		// A symlink is marked seen but never compared: its own mtime is the
		// link's rather than its target's, so statting it would report a change
		// on every scan for ever. If it is replaced by a real file, the entry
		// disappears and the walk reports the new page.
		seen[rel] = true
		if !info.Mode().IsRegular() {
			return nil
		}
		want, known := s.Record[rel]
		if !known || want.Size != info.Size() || !want.ModTime.Equal(info.ModTime()) {
			changed = append(changed, rel)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	for rel := range s.Record {
		if !seen[rel] {
			changed = append(changed, rel)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

// Forget drops a path from the record. The indexer calls it for a deletion it
// has already applied, so the scan does not keep reporting it.
func (s *Scanner) Forget(rel string) { delete(s.Record, rel) }
