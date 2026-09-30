package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HiddenDir is the vault's private directory: the database, the lock, the
// backups and the temporary files. The walker never descends into it and the
// watcher never watches it.
const HiddenDir = ".semiplane"

// LockName is the advisory lock file inside HiddenDir.
const LockName = "semiplane.lock"

// Handle is an exclusive claim on one vault directory.
//
// It is not called Lock because Lock is the constructor: a package cannot have
// both a func Lock and a type Lock, and the constructor is the name every call
// site writes.
//
// It must be taken before any file or database in the vault is opened. Two
// semiplane processes on one vault would each hold their own SQLite connection
// and their own index, and the loser's writes would be overwritten by the
// winner's watcher with no trace of the conflict.
//
// The claim is the kernel's, not the file's: a process that dies without
// releasing is reclaimed by the OS, so a stale pid in the file is a hint, never
// a reason to break the lock.
type Handle struct {
	file    *os.File
	path    string
	pid     int
	release func() error
	once    sync.Once
}

// LockPath returns the lock file a vault root would use, without creating it.
func LockPath(vaultRoot string) string {
	return filepath.Join(vaultRoot, HiddenDir, LockName)
}

// Lock takes the exclusive advisory lock on vaultRoot.
//
// It is deliberately non-blocking: a second instance must fail immediately and
// be told who holds the vault, not block for the lifetime of the first.
func Lock(ctx context.Context, vaultRoot string) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := filepath.Join(vaultRoot, HiddenDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", HiddenDir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", HiddenDir, err)
	}

	path := LockPath(vaultRoot)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", LockName, err)
	}

	release, err := lockFile(f)
	if err != nil {
		return nil, heldError(f, path, err)
	}

	pid := os.Getpid()
	if _, err := fmt.Fprintf(f, "%d\n%d\n", pid, time.Now().UTC().Unix()); err != nil {
		_ = release()
		_ = f.Close()
		return nil, fmt.Errorf("write %s: %w", LockName, err)
	}
	if err := f.Sync(); err != nil {
		_ = release()
		_ = f.Close()
		return nil, fmt.Errorf("sync %s: %w", LockName, err)
	}
	return &Handle{file: f, path: path, pid: pid, release: release}, nil
}

// heldError builds the refusal a second instance shows the operator. The pid
// comes out of the lock file, which is advisory: it is the courtesy that turns
// "already open" into "open in another terminal", and a wrong or absent one
// changes nothing about the refusal.
func heldError(f *os.File, path string, cause error) error {
	pid, _ := readPid(f)
	_ = f.Close()
	if pid > 0 {
		return fmt.Errorf("%w (pid %d in %s)", ErrAlreadyLocked, pid, path)
	}
	return fmt.Errorf("%w (lock file %s could not be claimed: %w)", ErrAlreadyLocked, path, cause)
}

// readPid reads the holder's pid from the lock file without disturbing the
// offset the next writer will use.
func readPid(f *os.File) (int, error) {
	off, err := f.Seek(0, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = f.Seek(off, 0) }()

	b, err := os.ReadFile(f.Name())
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, os.ErrNotExist
	}
	return strconv.Atoi(fields[0])
}

// Path is the lock file's location, for the boot report.
func (h *Handle) Path() string { return h.path }

// PID is the process that holds the lock, which is this one until Release.
func (h *Handle) PID() int { return h.pid }

// Release drops the lock. It is idempotent and safe to call from a signal
// handler's successor path as well as from ordinary shutdown.
//
// The file is left in place with its contents intact. Removing it would race
// with a second instance that has already opened it: the unlink would succeed,
// the newcomer would create a fresh inode and lock *that*, and two processes
// would each believe they hold the vault.
func (h *Handle) Release() {
	h.once.Do(func() {
		if h.file == nil {
			return
		}
		if h.release != nil {
			_ = h.release()
		}
		_ = h.file.Close()
		h.file = nil
	})
}

// Close makes Handle an io.Closer, for the deferred release on the exit path.
func (h *Handle) Close() error {
	h.Release()
	return nil
}
