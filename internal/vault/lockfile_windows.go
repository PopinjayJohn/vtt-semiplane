//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on the first byte of f and returns its
// release.
//
// LockFileEx has no non-blocking "wait a moment" mode, so the pair
// LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY is how a second instance
// learns the vault is open instead of hanging on it. The OVERLAPPED is captured
// by the release closure because unlocking must name the same byte range the
// lock took.
func lockFile(f *os.File) (func() error, error) {
	var ol windows.Overlapped
	h := windows.Handle(f.Fd())
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err := windows.LockFileEx(h, flags, 0, 1, 0, &ol); err != nil {
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(h, 0, 1, 0, &ol)
	}, nil
}
