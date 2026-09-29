//go:build unix

package app

import (
	"os"
	"syscall"
	"testing"
)

// mkfifo is the test's opt-in to the fifo case, and on a platform without
// syscalls for it the case is skipped by name rather than silently absent.
func mkfifo(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("no /dev/null to prove the platform has files at all: %v", err)
	}
}

func mkfifoAt(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
