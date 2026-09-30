package app

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestCopyTreeCopiesBytesAndCreatesDirectories is the ordinary case, kept first
// so a refusal that is too eager is as visible as one that is too lax.
func TestCopyTreeCopiesBytesAndCreatesDirectories(t *testing.T) {
	t.Parallel()
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	if err := os.MkdirAll(filepath.Join(src, "files", "deep"), 0o700); err != nil {
		t.Fatalf("build the source tree: %v", err)
	}
	for path, body := range map[string]string{
		"manifest.json":      `{"v":1}`,
		"files/page.md":      "# A page",
		"files/deep/note.md": "# A note",
	} {
		if err := os.WriteFile(filepath.Join(src, filepath.FromSlash(path)), []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}

	if err := copyTree(context.Background(), src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	for path, want := range map[string]string{
		"manifest.json":      `{"v":1}`,
		"files/page.md":      "# A page",
		"files/deep/note.md": "# A note",
	} {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(path)))
		if err != nil {
			t.Errorf("the copy has no %s: %v", path, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

// TestCopyTreeRefusesAnythingThatIsNotARegularFile is the rule the function
// documents, stated as a walk over the three things a vault directory can hold
// that a file is not.
func TestCopyTreeRefusesAnythingThatIsNotARegularFile(t *testing.T) {
	t.Parallel()
	// The symlink's target lives outside src, so a copy that followed it would
	// place a byte in the destination that the walk never saw.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("not the backup"), 0o600); err != nil {
		t.Fatalf("seed the target: %v", err)
	}

	cases := []struct {
		name string
		seed func(t *testing.T, src string)
	}{
		{"a symlink out of the tree", func(t *testing.T, src string) {
			t.Helper()
			if err := os.Symlink(outside, filepath.Join(src, "link.md")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"a symlink to a directory", func(t *testing.T, src string) {
			t.Helper()
			target := filepath.Join(t.TempDir(), "adir")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Symlink(target, filepath.Join(src, "dirlink")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
		{"a dangling symlink", func(t *testing.T, src string) {
			t.Helper()
			if err := os.Symlink(filepath.Join(src, "gone.md"), filepath.Join(src, "dangling.md")); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := t.TempDir()
			dst := filepath.Join(t.TempDir(), "out")
			if err := os.WriteFile(filepath.Join(src, "page.md"), []byte("# A page"), 0o600); err != nil {
				t.Fatalf("seed the page: %v", err)
			}
			tc.seed(t, src)

			err := copyTree(context.Background(), src, dst)
			if err == nil {
				t.Fatalf("copyTree copied a tree holding %s", tc.name)
			}
			// The refusal is the whole answer: whatever was copied before the
			// walk reached the bad entry is a partial copy of a tree the
			// operator asked to take off the machine, and reporting the refusal
			// is what tells them not to trust it.
			if got := err.Error(); got == "" {
				t.Error("the refusal carries no reason")
			}
		})
	}
}

// TestTheWalkEntryIsNotTheRefusal pins the fix this file exists for.
//
// The vulnerable shape was `d.Type().IsRegular()` followed by a read of the same
// name, where d is the entry filepath.WalkDir read out of the directory. The
// first half of this test is that shape, kept verbatim and run against a tree
// that changed after the entry was taken, because a gate that only asserts the
// new code is right has not shown that the old code was wrong. The second half
// is what the code does now, on the identical fixture.
//
// The swap is the whole finding: the entry says regular, the name is a symlink,
// and a check that believes the entry reads the symlink's target. An argument
// that the walk "refuses non-regular entries" is an argument about the entry,
// and the entry is the thing that went stale.
func TestTheWalkEntryIsNotTheRefusal(t *testing.T) {
	t.Parallel()
	const target = "the file behind the link"

	build := func(t *testing.T) (page string, stale fs.DirEntry) {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, "backup")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		page = filepath.Join(dir, "page.md")
		if err := os.WriteFile(page, []byte("# A page"), 0o600); err != nil {
			t.Fatalf("seed the page: %v", err)
		}
		outside := filepath.Join(root, "outside.txt")
		if err := os.WriteFile(outside, []byte(target), 0o600); err != nil {
			t.Fatalf("seed the target: %v", err)
		}
		// The walk's view, taken exactly where filepath.WalkDir takes it: the
		// ReadDir that produces the DirEntry the callback is handed.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read the directory: %v", err)
		}
		if len(entries) != 1 || !entries[0].Type().IsRegular() {
			t.Fatalf("the fixture does not begin as one regular file: %v", entries)
		}
		stale = entries[0]
		if err := os.Remove(page); err != nil {
			t.Fatalf("remove the page: %v", err)
		}
		if err := os.Symlink(outside, page); err != nil {
			// A probed skip rather than a failure: whether a symlink can be
			// created is a property of the host — Windows needs the
			// unprivileged-create flag to be honoured, which it is only for an
			// administrator or with Developer Mode on — and it is not a property
			// of the copy. The error is the probe and it says what it found.
			t.Skipf("this platform will not take a symlink over an existing file: %v", err)
		}
		return page, stale
	}

	t.Run("the check-then-use shape reads through the swap", func(t *testing.T) {
		t.Parallel()
		page, stale := build(t)
		// Deliberately the removed code: the walk's own DirEntry, and then a
		// read of the same name. This is the shape being refuted, not something
		// this repository may contain.
		if !stale.Type().IsRegular() {
			t.Fatalf("the fixture's entry is %v, not the regular file the race needs", stale.Type())
		}
		b, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("the old shape refused: %v", err)
		}
		if string(b) != target {
			t.Fatalf("the old shape read %q, so this fixture no longer shows the race", b)
		}
		t.Logf("a stale DirEntry said regular, and the read of the same name returned %q", b)
	})

	t.Run("what the code does now refuses it", func(t *testing.T) {
		t.Parallel()
		page, _ := build(t)
		b, err := readRegularFile(page)
		if err == nil {
			t.Fatalf("readRegularFile read a path that had become a symlink, and returned %q", b)
		}
		if string(b) == target {
			t.Fatal("readRegularFile refused but returned the target's bytes")
		}
	})
}
