package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxFileBytes is the largest a single vault file may be. A page is measured
// in kilobytes; eight megabytes is a bound on a hostile or accidental paste, not
// a budget a note is expected to spend. A file over the cap is an error naming
// the path and the size, never a silent truncation: a truncated vault file is
// indistinguishable from a correct one until the day it matters.
const MaxFileBytes int64 = 8 << 20

// tempSuffix is the marker on an in-progress write. The watcher ignores it, so
// the app cannot cause itself an index pass, and a leftover one is recognisable
// as a crash rather than as a page.
const tempSuffix = ".semiplane-tmp"

// Read returns the exact bytes of a vault file.
//
// The size cap is enforced twice: once against the stat, so the error can name
// the size, and once against the read, because the file can grow between the
// two and a stat is not a promise.
func Read(ctx context.Context, p Path) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st, err := os.Stat(p.Abs())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, p.Rel())
	}
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", p.Rel(), err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("read %s: is a directory", p.Rel())
	}
	if st.Size() > MaxFileBytes {
		return nil, fmt.Errorf("read %s: file is %d bytes, over the %d byte limit",
			p.Rel(), st.Size(), MaxFileBytes)
	}

	f, err := os.Open(p.Abs())
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p.Rel(), err)
	}
	defer func() { _ = f.Close() }()

	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p.Rel(), err)
	}
	if int64(len(b)) > MaxFileBytes {
		return nil, fmt.Errorf("read %s: file is over the %d byte limit", p.Rel(), MaxFileBytes)
	}
	return b, nil
}

// Write replaces a vault file atomically.
//
// The temporary file is created in the target's own directory, not in the
// system temp dir: a rename across a filesystem boundary is a copy, and a copy
// is not atomic. The file is fsynced before the rename and the directory is
// fsynced after it, so a crash leaves either the previous bytes or the new ones
// and never a name that points at nothing.
func Write(ctx context.Context, p Path, content []byte) error {
	return writeFile(ctx, p, content, nil)
}

// writeFile is Write with a test seam. beforeReplace runs after the temporary
// file is complete on disk and before the rename, which is the only window in
// which a crash can leave debris; a test injects a failure there.
func writeFile(ctx context.Context, p Path, content []byte, beforeReplace func(temp, dest string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(content)) > MaxFileBytes {
		return fmt.Errorf("write %s: content is %d bytes, over the %d byte limit",
			p.Rel(), len(content), MaxFileBytes)
	}

	dir := filepath.Dir(p.Abs())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", p.Dir(), err)
	}

	tmp, err := os.CreateTemp(dir, p.Name()+".*"+tempSuffix)
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", p.Dir(), err)
	}
	tmpName := tmp.Name()
	// Until the rename succeeds the temporary file is ours to clean up; a
	// leftover one is a crash artefact, not a page.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", p.Rel(), err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", p.Rel(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", p.Rel(), err)
	}
	// CreateTemp already uses 0600, but the mode is stated because a vault file
	// holds secrets and the default is not a decision this package should leave
	// to the umask.
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", p.Rel(), err)
	}
	if beforeReplace != nil {
		if err := beforeReplace(tmpName, p.Abs()); err != nil {
			return fmt.Errorf("write %s: %w", p.Rel(), err)
		}
	}
	if err := atomicReplace(tmpName, p.Abs()); err != nil {
		return fmt.Errorf("replace %s: %w", p.Rel(), err)
	}
	tmpName = ""

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync directory of %s: %w", p.Rel(), err)
	}
	return nil
}

// Hash is the content hash the index and the save path both speak. It is the
// one place a "content hash" is defined, so a SaveRequest's BaseContentHash and
// a selfwrite registration cannot be computed two subtly different ways.
func Hash(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// HashHex is Hash rendered for a JSON manifest.
func HashHex(b []byte) string { return hex.EncodeToString(Hash(b)) }
