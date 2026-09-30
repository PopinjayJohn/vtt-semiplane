package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// An unreadable file must not stop the vault from indexing. This is a
// regression test: indexOne degraded gracefully for a missing file, a
// directory and an oversize file, but returned the raw read error for a
// permission failure, which IndexBatch propagated — and the boot walk is one
// batch, so a single `chmod 000` stopped the app from starting. A denial of
// service created by one file's mode bit.
func TestOneUnreadableFileDoesNotStopTheWalk(t *testing.T) {
	skipUnlessModesGateReads(t)
	t.Parallel()

	h := newHarness(t, map[string]string{
		"Alpha.md":    "# Alpha\n\nSee [[Beta]].\n",
		"Beta.md":     "# Beta\n\nBody.\n",
		"Gamma.md":    "# Gamma\n\nBody.\n",
		"Locked.md":   "# Locked\n\nNobody can read me.\n",
		"Delta.md":    "# Delta\n\nBody.\n",
		"readable.md": "# Readable\n\nBody.\n",
	})
	locked := lockUnreadable(t, h, "Locked.md")

	// The boot path is walk then one batch, so that is what is reproduced here.
	ctx := context.Background()
	walk, err := h.ix.Walk(ctx)
	if err != nil {
		t.Fatalf("the walk aborted on an unreadable file: %v", err)
	}
	if _, err := h.ix.IndexBatch(ctx, walk.Files); err != nil {
		t.Fatalf("the index batch aborted on an unreadable file: %v", err)
	}
	if _, err := h.ix.RemoveMissing(ctx, walk.Files); err != nil {
		t.Fatalf("remove missing: %v", err)
	}

	// Every readable page indexed, and the cross-reference between two of them
	// still resolved: one bad file must not degrade the pass to a partial one.
	for _, want := range []string{"Alpha.md", "Beta.md", "Gamma.md", "Delta.md", "readable.md"} {
		if h.pageID(want) == 0 {
			t.Errorf("%s was not indexed because a sibling was unreadable", want)
		}
	}
	// An unreadable file leaves no row behind: a half-written page would be
	// worse than a missing one, because the next reconcile would treat it as
	// current and never retry.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM pages WHERE path = ?`, "Locked.md"); n != 0 {
		t.Errorf("an unreadable file produced %d page rows, want 0", n)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_text WHERE body LIKE ?`, "%Nobody can read%"); n != 0 {
		t.Errorf("an unreadable file reached page_text in %d rows", n)
	}
	if locked == "" {
		t.Fatal("the fixture was not locked")
	}
}

// The same property one file at a time: a permission error on a single path
// must not abort its neighbours in the same batch, and the failure has to be
// reportable so the sync panel can count it.
func TestAnUnreadableFileIsReportedAsAProblem(t *testing.T) {
	skipUnlessModesGateReads(t)
	t.Parallel()

	h := newHarness(t, map[string]string{
		"Good.md":   "# Good\n",
		"Locked.md": "# Locked\n",
	})
	lockUnreadable(t, h, "Locked.md")

	batch, err := h.ix.IndexBatch(context.Background(), []string{"Good.md", "Locked.md"})
	if err != nil {
		t.Fatalf("IndexBatch aborted: %v", err)
	}
	if len(batch.Indexed) != 2 {
		t.Fatalf("indexed %d of 2 paths: %+v", len(batch.Indexed), batch.Indexed)
	}

	var problems int
	for _, r := range batch.Indexed {
		switch r.Path {
		case "Locked.md":
			if len(r.Problems) == 0 {
				t.Error("the unreadable file reported no problem, so nothing can be counted in the sync panel")
				continue
			}
			problems++
			if r.Problems[0].Code != ProblemUnreadable {
				t.Errorf("problem code = %q, want %q", r.Problems[0].Code, ProblemUnreadable)
			}
			// A problem must never carry the bytes it failed to read.
			if containsAny(r.Problems[0].Message, "Locked", "# ") {
				t.Errorf("the problem message carries file content: %q", r.Problems[0].Message)
			}
		case "Good.md":
			if len(r.Problems) != 0 {
				t.Errorf("the readable file reported problems: %+v", r.Problems)
			}
		}
	}
	if problems != 1 {
		t.Errorf("the unreadable file reported %d problems, want 1", problems)
	}
}

// skipUnlessModesGateReads skips where the premise does not hold: a mode of 000
// is a request, and a volume that does not honour it would let the test read the
// very file whose unreadability it is asserting. That is three different
// situations — Windows has no mode bits at all and os.Chmod toggles the
// read-only attribute instead, root reads a mode-000 file, and a volume mounted
// without mode support ignores the request — and they are told apart here by
// performing the read the test depends on being refused.
//
// The previous form of this asked runtime.GOOS, which got Windows right and
// named no reason for the other two, and the reason nobody reads is the whole
// problem: a test that vanishes with a one-line message is a test a reader
// cannot tell apart from one that was deleted.
func skipUnlessModesGateReads(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "probe.md")
	if err := os.WriteFile(p, []byte("readable\n"), 0o000); err != nil {
		t.Fatalf("create the mode probe: %v", err)
	}
	// Restore it so the temp directory can be removed: a 000 file with no
	// permission bits is unremovable by its own directory on a POSIX volume.
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	if b, err := os.ReadFile(p); err == nil {
		t.Skipf("this volume let a mode-000 file be read (%d bytes), so a mode-000 file here is not an unreadable one", len(b))
	}
}

func lockUnreadable(t *testing.T, h *harness, rel string) string {
	t.Helper()
	p := filepath.Join(h.vault.Root, rel)
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", rel, err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	return p
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if n != "" && len(s) >= len(n) && indexOf(s, n) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
