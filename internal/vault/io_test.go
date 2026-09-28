package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

func TestReadReturnsExactBytes(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	// Bytes that a reflowing writer would lose: CRLF, a BOM, a lone CR, a
	// trailing space, and a final line with no newline.
	want := []byte("\xef\xbb\xbf---\r\ntitle: Ash\r\n---\r\n\r\nBody with trailing space \r\x00\n")
	v.WriteFile(t, "Campaigns/Ash.md", string(want))

	got, err := Read(t.Context(), New(v.Root, "Campaigns/Ash.md"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read changed the bytes:\n got %q\nwant %q", got, want)
	}
}

func TestReadRefusesAnOversizeFile(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	big := strings.Repeat("x", int(MaxFileBytes)+1)
	v.WriteFile(t, "Huge.md", big)

	_, err := Read(t.Context(), New(v.Root, "Huge.md"))
	if err == nil {
		t.Fatal("an oversize file must be an error, never a silent truncation")
	}
	if !strings.Contains(err.Error(), "Huge.md") {
		t.Errorf("the error should name the path: %v", err)
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Errorf("the error should say why: %v", err)
	}
}

func TestReadReportsMissingAndDirectorySeparately(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.MkdirAll(t, "Campaigns/Ash")

	if _, err := Read(t.Context(), New(v.Root, "Nope.md")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing file = %v, want ErrNotFound", err)
	}
	if _, err := Read(t.Context(), New(v.Root, "Campaigns/Ash")); err == nil {
		t.Error("reading a directory must fail")
	} else if strings.Contains(err.Error(), "not found") {
		t.Errorf("a directory was reported as missing: %v", err)
	}
}

func TestWriteIsAtomicAndLeavesTheModeAt0600(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	p := New(v.Root, "Campaigns/Ash/Gundren.md")

	if err := Write(t.Context(), p, []byte("first\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Write(t.Context(), p, []byte("second\n")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if got := string(v.ReadFile(t, p.Rel())); got != "second\n" {
		t.Errorf("content = %q", got)
	}
	st, err := os.Stat(p.Abs())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: a vault file holds secrets", perm)
	}
	assertNoTempFiles(t, v)
}

// TestWriteCreatesParentDirectories matters because a save into a new campaign
// is the common case, not an edge case.
func TestWriteCreatesParentDirectories(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	p := New(v.Root, "Campaigns/Braxton/Ash/NPCs/Sela.md")
	if err := Write(t.Context(), p, []byte("# Sela\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(v.ReadFile(t, p.Rel())); got != "# Sela\n" {
		t.Errorf("content = %q", got)
	}
	st, err := os.Stat(filepath.Dir(p.Abs()))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %o, want 700", perm)
	}
}

// TestAtomicWriteLeavesNoTempOnCrash injects a failure in the only window
// where debris can exist: after the temporary file is complete on disk and
// before the rename. A crash there must leave the original file and nothing
// else, because a leftover temp file is a file the walk would index.
func TestAtomicWriteLeavesNoTempOnCrash(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	original := []byte("# Gundren\n\nThe original bytes, byte for byte.\n")
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", string(original))

	crashed := errors.New("the power went out")
	w := NewWriter(v.Root, nil)
	w.beforeReplace = func(temp, dest string) error {
		if !strings.HasSuffix(temp, tempSuffix) {
			t.Errorf("the seam ran with %q, which is not a temp file", temp)
		}
		return crashed
	}

	err := w.Save(t.Context(), SaveRequest{
		Path:            "Campaigns/Ash/Gundren.md",
		NewContent:      []byte("# Replacement\n"),
		BaseContentHash: Hash(original),
		ActorID:         7,
		ExpectPerm:      writePagePerm,
	})
	if !errors.Is(err, crashed) {
		t.Fatalf("Save = %v, want the injected crash", err)
	}
	if got := v.ReadFile(t, "Campaigns/Ash/Gundren.md"); !bytes.Equal(got, original) {
		t.Errorf("the original file was disturbed:\n got %q\nwant %q", got, original)
	}
	assertNoTempFiles(t, v)
	if got := v.Paths(t); len(got) != 1 {
		t.Errorf("the vault holds %v, want only the original page", got)
	}
}

// TestWriteRefusesOversizeContent keeps a paste from filling the disk.
func TestWriteRefusesOversizeContent(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	p := New(v.Root, "Huge.md")
	err := Write(t.Context(), p, bytes.Repeat([]byte("x"), int(MaxFileBytes)+1))
	if err == nil {
		t.Fatal("an oversize write must fail")
	}
	if v.Exists("Huge.md") {
		t.Error("a refused write left a file behind")
	}
	assertNoTempFiles(t, v)
}

func assertNoTempFiles(t *testing.T, v *testutil.Vault) {
	t.Helper()
	for _, rel := range v.Paths(t) {
		if strings.Contains(rel, tempSuffix) {
			t.Errorf("a temp file survived: %s", rel)
		}
	}
	entries, err := os.ReadDir(v.Root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), tempSuffix) {
			t.Errorf("a temp file survived in the root: %s", e.Name())
		}
	}
}
