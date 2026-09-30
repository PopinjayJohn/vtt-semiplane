package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// Whether this volume keeps POSIX mode bits, measured rather than asked for.
//
// Several tests in this package assert a mode: a vault file is written 0600
// because it holds secrets, the lock directory is 0700, a backup is a vault in a
// folder. Those assertions are about the mode the writer asked for, and the
// mode the filesystem reports back is the only evidence there is — so on a
// volume with no mode bits there is nothing to assert and the honest answer is
// to say so.
//
// Windows has no mode bits at all. os.Stat synthesises 0666 for a file and 0777
// for a directory out of the read-only attribute, so a vault file created 0600
// reads back 0666 and a lock directory created 0700 reads back 0777, whatever
// was requested. A POSIX volume mounted without mode support, and a CIFS or
// WebDAV share, answer the same way. runtime.GOOS would get Windows right and
// every one of those wrong, which is the shape AGENTS.md §11 calls a gate that
// skips for a reason nobody reads: the test vanishes and nothing records what
// the platform could not do. The probe below runs instead, and the skip it
// produces names what the volume actually answered.

type modeProbe struct {
	file os.FileMode
	dir  os.FileMode
}

// keepModeBits reports the mode this volume gave a file created 0600 and a
// directory created 0700, read back through the same os.Stat the assertions
// under test use.
func keepModeBits(t *testing.T) modeProbe {
	t.Helper()
	// A directory of its own rather than the vault: every vault assertion in
	// this package is about a vault's contents, and a probe file left in one is
	// a fixture that changed the thing it is measuring. t.TempDir is the same
	// volume as the vaults these tests build, which is the answer that matters —
	// mode support is a property of the filesystem, not of the directory.
	dir := t.TempDir()
	file := filepath.Join(dir, "probe")
	sub := filepath.Join(dir, "probe-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("create the mode probe file: %v", err)
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("create the mode probe directory: %v", err)
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat the mode probe file: %v", err)
	}
	di, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("stat the mode probe directory: %v", err)
	}
	return modeProbe{file: st.Mode().Perm(), dir: di.Mode().Perm()}
}

// skipUnlessModeBitsAreEnforced skips when the volume does not keep the mode a
// file or a directory was created with, and the message says what it reported.
func skipUnlessModeBitsAreEnforced(t *testing.T) {
	t.Helper()
	p := keepModeBits(t)
	if p.file == 0o600 && p.dir == 0o700 {
		return
	}
	t.Skipf("this volume does not keep POSIX mode bits: a file created 0600 reads back %04o and a directory created 0700 reads back %04o, "+
		"so the mode the writer asked for is not observable here", p.file, p.dir)
}

// skipUnlessCaseIsDistinct skips when the volume treats "Gundren.md" and
// "gundren.md" as one file, and the message says how it found out.
//
// A case-collision fixture writes two names that differ only in case and then
// asserts the walk found a collision. On a volume that folds case the second
// write lands on the first, there is no collision to find, and the assertion
// fails having tested nothing — which is the macOS and Windows default volume
// and the reason these two tests were the only case-collision failures there.
//
// The answer is probed with a real create and a differently-cased read rather
// than taken from runtime.GOOS, because a platform and a filesystem are
// different things: a macOS volume formatted case-sensitive, a Linux volume
// mounted case-insensitively, and a case-insensitive Linux volume are all real,
// and the two tests are meaningful on all of them. An assumed skip would hide a
// regression on the case-sensitive ones; a silent one is the failure mode
// AGENTS.md §11 calls a gate that skips for a reason nobody reads.
//
// The walk's own probe is filesystemIgnoresCase, and the two agree by
// construction: both write a name and look for it under a different case, and
// both fail loudly rather than defaulting, because a wrong answer in either
// direction is a bug (walk.go says so at the call site).
func skipUnlessCaseIsDistinct(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	upper := filepath.Join(dir, "Gundren.md")
	lower := filepath.Join(dir, "gundren.md")
	if err := os.WriteFile(upper, []byte("upper\n"), 0o600); err != nil {
		t.Fatalf("create the first name: %v", err)
	}
	if err := os.WriteFile(lower, []byte("lower\n"), 0o600); err != nil {
		// A volume that refuses the second write will not hold both at all.
		t.Skipf("this volume refused a second file named gundren.md beside Gundren.md (%v), "+
			"so the two names are one file here and there is no collision to detect", err)
	}
	first, err := os.ReadFile(upper)
	if err != nil {
		t.Fatalf("read the first name back: %v", err)
	}
	if string(first) != "upper\n" {
		t.Skipf("this volume stored gundren.md over Gundren.md (the first now holds %d bytes of the second's contents), "+
			"so the two names are one file here and there is no collision to detect", len(first))
	}
}
