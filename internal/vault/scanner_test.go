package vault

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// indexerOf records every file the walk found, as the indexer would after it
// has indexed them. It is the record the scan compares against.
func indexerOf(t *testing.T, v *testutil.Vault) *Scanner {
	t.Helper()
	s := NewScanner(obs.Discard())
	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, rel := range res.Files {
		st, err := os.Stat(New(v.Root, rel).Abs())
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		s.Observe(rel, FileState{Size: st.Size(), ModTime: st.ModTime()})
	}
	return s
}

func TestScanIsQuietOnAnUnchangedVault(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Sela.md", "# Sela\n")
	v.WriteFile(t, ".semiplane/semiplane.db", "sqlite")
	v.WriteFile(t, ".obsidian/workspace.json", "{}")

	s := indexerOf(t, v)
	got, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("an unchanged vault reported %v", got)
	}
}

// TestScanFindsEveryKindOfDivergence is the correctness property the 60 second
// reconciliation exists for: created, changed, grown and deleted all come back.
func TestScanFindsEveryKindOfDivergence(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Untouched.md", "# Untouched\n")
	v.WriteFile(t, "Campaigns/Ash/Edited.md", "# Edited\n")
	v.WriteFile(t, "Campaigns/Ash/Deleted.md", "# Deleted\n")
	s := indexerOf(t, v)

	// A new file, an edit that changes the size, and a deletion.
	v.WriteFile(t, "Campaigns/Ash/Created.md", "# Created\n")
	v.WriteFile(t, "Campaigns/Ash/Edited.md", "# Edited, at greater length\n")
	v.Remove(t, "Campaigns/Ash/Deleted.md")

	got, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []string{"Campaigns/Ash/Created.md", "Campaigns/Ash/Deleted.md", "Campaigns/Ash/Edited.md"}
	if !equal(got, want) {
		t.Errorf("Scan = %v, want %v", got, want)
	}

	// The indexer applies what it was given and records it; a second scan is
	// then quiet, which is what makes a 60 second loop affordable.
	for _, rel := range got {
		p := New(v.Root, rel)
		if _, err := os.Stat(p.Abs()); err != nil {
			s.Forget(rel)
			continue
		}
		st, err := os.Stat(p.Abs())
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		s.Observe(rel, FileState{Size: st.Size(), ModTime: st.ModTime()})
	}
	again, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("the second scan still reported %v", again)
	}
}

// TestScanIgnoresTheHiddenAndToolDirectories keeps the scan from reporting the
// database it is reading, which would be an infinite loop of "changed".
func TestScanIgnoresTheHiddenAndToolDirectories(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	s := indexerOf(t, v)

	v.WriteFile(t, ".semiplane/semiplane.db", "changed")
	v.WriteFile(t, ".semiplane/semiplane.db-wal", "wal")
	v.WriteFile(t, ".git/HEAD", "ref: refs/heads/main")
	v.WriteFile(t, "node_modules/x/index.js", "js")

	got, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("the scan reported ignored paths: %v", got)
	}
}

// TestScanDoesNotFollowSymlinks keeps a link from being reported on every scan
// forever: a link's own mtime is the link's, not its target's.
func TestScanDoesNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	if err := os.Symlink(filepath.Join(v.Root, "Campaigns/Ash/Gundren.md"), filepath.Join(v.Root, "Link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := indexerOf(t, v)

	first, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(first) != 0 {
		t.Errorf("the first scan reported %v", first)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := s.Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("the scan reported a symlink on the second pass: %v", second)
	}
}

func TestScanRejectsABadRequest(t *testing.T) {
	t.Parallel()
	if _, err := NewScanner(obs.Discard()).Scan(t.Context(), ""); err == nil {
		t.Error("Scan with no root must fail")
	}
	if _, err := NewScanner(obs.Discard()).Scan(t.Context(), filepath.Join(t.TempDir(), "no-such-vault")); err == nil {
		t.Error("Scan on a missing root must fail")
	}
}

// TestScanStopsOnACancelledContext keeps a cancelled scan from running to
// completion over a large vault.
func TestScanStopsOnACancelledContext(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	for i := range 600 {
		v.WriteFile(t, "Campaigns/Ash/Note"+pad(i, 3)+".md", "# note\n")
	}
	s := indexerOf(t, v)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Scan(ctx, v.Root); err == nil {
		t.Error("a cancelled scan returned no error")
	}
}

// TestScanOfAnEmptyRecordReportsEverything is the first boot: nothing is
// recorded, so everything on disk is new.
func TestScanOfAnEmptyRecordReportsEverything(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "A.md", "# A\n")
	v.WriteFile(t, "B.md", "# B\n")
	got, err := NewScanner(obs.Discard()).Scan(t.Context(), v.Root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !equal(got, []string{"A.md", "B.md"}) {
		t.Errorf("Scan = %v", got)
	}
}

// BenchmarkScan10kFiles is the number the 60 second reconciliation interval is
// chosen against: a stat-only walk of ten thousand files has to cost a small
// fraction of the interval, on a vault a DM can plausibly own.
func BenchmarkScan10kFiles(b *testing.B) {
	root := b.TempDir()
	// Built once, outside the timed section: creating ten thousand files is
	// fixture setup, not the measurement.
	seed10k(b, root)

	s := NewScanner(obs.Discard())
	res, err := Walk(context.Background(), root, WalkOptions{})
	if err != nil {
		b.Fatalf("walk: %v", err)
	}
	for _, rel := range res.Files {
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			b.Fatalf("stat: %v", err)
		}
		s.Observe(rel, FileState{Size: st.Size(), ModTime: st.ModTime()})
	}

	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		got, err := s.Scan(ctx, root)
		if err != nil {
			b.Fatalf("scan: %v", err)
		}
		if len(got) != 0 {
			b.Fatalf("a scan of an unchanged vault reported %d paths", len(got))
		}
	}
}

// BenchmarkWalk10kFiles is the boot path, for comparison: a walk hashes nothing
// but stats everything, so it should be in the same class as a scan.
func BenchmarkWalk10kFiles(b *testing.B) {
	root := b.TempDir()
	seed10k(b, root)
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		res, err := Walk(ctx, root, WalkOptions{})
		if err != nil {
			b.Fatalf("walk: %v", err)
		}
		if len(res.Files) != 10000 {
			b.Fatalf("walk found %d files", len(res.Files))
		}
	}
}

// seed10k builds the fixture the scan benchmarks measure against: ten thousand
// files across a hundred directories, created outside the timed section.
func seed10k(b *testing.B, root string) {
	b.Helper()
	for d := range 100 {
		if err := os.MkdirAll(fixturePath(root, d, ""), 0o700); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
	}
	for i := range 10000 {
		name := fixturePath(root, i%100, "n"+pad(i, 5)+".md")
		if err := os.WriteFile(name, []byte("# note\n"), 0o600); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

// fixturePath builds a fixture path without fmt.Sprintf, because
// TestEveryQueryUsesBindParameters fails the build on any Sprintf line that
// mentions a SQL verb and filepath.Join says "join".
func fixturePath(root string, dir int, file string) string {
	return filepath.Join(root, "d"+pad(dir, 2), file)
}

func pad(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	a := append([]string(nil), got...)
	c := append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(c)
	for i := range a {
		if a[i] != c[i] {
			return false
		}
	}
	return true
}
