//go:build !windows

package vault

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive advisory lock on f and returns its release.
//
// flock(2) is non-blocking here on purpose: a second instance must be told
// immediately that the vault is open, not wait for the first one to exit. The
// lock is attached to the open file description, so a second open in the *same*
// process conflicts too — which is what makes the single-instance rule
// testable without spawning a subprocess.
//
// The release closure keeps the file open; the caller closes it afterwards.
func lockFile(f *os.File) (func() error, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	return func() error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }, nil
}
