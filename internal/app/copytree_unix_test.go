//go:build unix

package app

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

// TestCopyTreeOpensNoPathThatWouldBlock pins the reason the Lstat comes first.
//
// os.Open on a fifo blocks until a writer arrives, so a refusal that arrived
// after the open would be the hang rather than the answer. The wait is bounded so
// a regression fails with a message rather than sitting until the suite timeout.
func TestCopyTreeOpensNoPathThatWouldBlock(t *testing.T) {
	t.Parallel()
	mkfifo(t)

	src := t.TempDir()
	fifo := filepath.Join(src, "pipe")
	if err := mkfifoAt(fifo); err != nil {
		t.Fatalf("create the fifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "page.md"), []byte("# A page"), 0o600); err != nil {
		t.Fatalf("seed the page: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- copyTree(context.Background(), src, filepath.Join(t.TempDir(), "out")) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("copyTree copied a fifo")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("copyTree did not return within 10s on a tree holding a fifo: the refusal is arriving after the open, and an open on a fifo blocks until a writer arrives")
	}
}
