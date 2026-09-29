package app

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sample"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The non-clobbering walk is the one behaviour in this change that can lose an
// operator's work, so most of what follows is about it. A walk that refuses to
// clobber is not the same as a walk that does not happen: the first test here
// writes every campaign file, and the ones after it can then say "the operator's
// bytes survived" and have it mean something.

// campaignFilesOnDisk is every campaign file's vault-relative destination.
func campaignFilesOnDisk(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, f := range embeddedCampaign(t) {
		out = append(out, sample.Root+"/"+f.Name)
	}
	sort.Strings(out)
	return out
}

func embeddedCampaign(t *testing.T) []sample.File {
	t.Helper()
	files, err := sample.Files()
	if err != nil {
		t.Fatalf("the bundled sample campaign cannot be read: %v", err)
	}
	return files
}

// hashTree returns every file's content hash under root, outside the app's own
// state directory.
func hashTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range walkFiles(t, root) {
		out[rel] = vault.HashHex(readFile(t, root, rel))
	}
	return out
}

// walkFiles lists the vault's files, skipping the app's own state directory.
//
// That skip is the claim being made, not a convenience. The hidden directory
// holds the index, the lock, the backups and the audit log, and every one of
// those is expected to differ between two boots — a backup may be taken, the
// lock is re-taken, the index is rebuilt. AGENTS.md §1 is explicit that every
// derived artefact is disposable, so hashing it would be asserting something
// false. The page count covers the index separately.
func walkFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == vault.HiddenDir || strings.HasPrefix(rel, vault.HiddenDir+"/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

func readFile(t *testing.T, root, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func fileModTime(t *testing.T, root, rel string) time.Time {
	t.Helper()
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("stat %s: %v", rel, err)
	}
	return st.ModTime()
}

// TestTheFirstBootWritesTheCampaign is the positive control every non-clobber
// assertion below depends on.
//
// "The operator's bytes survived" is satisfiable by a walk that writes nothing,
// so the walk is first shown to write every campaign file, byte for byte, at
// the path the campaign's own attachment references assume.
func TestTheFirstBootWritesTheCampaign(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.boot(t, f.opts)

	files := embeddedCampaign(t)
	for _, want := range campaignFilesOnDisk(t) {
		rel := strings.TrimPrefix(want, sample.Root+"/")
		var embedded []byte
		for _, file := range files {
			if file.Name == rel {
				embedded = file.Content
			}
		}
		got := readFile(t, f.vault.Root, want)
		if !bytes.Equal(got, embedded) {
			t.Errorf("%s was written with %d bytes, want the campaign's %d", want, len(got), len(embedded))
		}
	}
	if got, want := f.pages(), samplePages(); got != want {
		t.Errorf("the index holds %d pages, want the campaign's %d: the boot indexed the vault before it wrote to it", got, want)
	}
}

// TestFirstBootIsIdempotent is the claim the plan makes about re-running a
// downloaded binary in place, which is how a self-hosted tool is actually
// upgraded: a second boot changes nothing.
//
// Two assertions, and the second is the stronger one. The hashes say the bytes
// are the same, which a walk that rewrote identical content would also satisfy.
// The modification times say no file was rewritten at all.
func TestFirstBootIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	first := f.boot(t, f.opts)

	before := hashTree(t, f.vault.Root)
	times := map[string]time.Time{}
	for rel := range before {
		times[rel] = fileModTime(t, f.vault.Root, rel)
	}
	if len(before) != samplePages() {
		t.Fatalf("the first boot left %d files in the vault, want the campaign's %d", len(before), samplePages())
	}
	pagesBefore, err := store.CountPages(context.Background(), first.DB().Reader())
	if err != nil {
		t.Fatalf("count pages: %v", err)
	}

	second := f.boot(t, f.opts)

	after := hashTree(t, f.vault.Root)
	if len(after) != len(before) {
		t.Errorf("the second boot left %d files, want %d", len(after), len(before))
	}
	for rel, hash := range before {
		got, ok := after[rel]
		switch {
		case !ok:
			t.Errorf("%s was removed by a second boot", rel)
		case got != hash:
			t.Errorf("%s changed on a second boot: the extraction is not non-clobbering", rel)
		}
		if got := fileModTime(t, f.vault.Root, rel); !got.Equal(times[rel]) {
			t.Errorf("%s was rewritten on a second boot: %s became %s", rel, times[rel], got)
		}
	}
	pagesAfter, err := store.CountPages(context.Background(), second.DB().Reader())
	if err != nil {
		t.Fatalf("count pages: %v", err)
	}
	if pagesAfter != pagesBefore {
		t.Errorf("the index holds %d pages after a second boot, want %d", pagesAfter, pagesBefore)
	}
}

// TestSampleExtractDoesNotClobber is the behaviour the plan is explicit about
// and U25 gives the reason for: re-running a downloaded binary in place is the
// common case, and reuse-without-clobber is what makes it safe.
//
// The two cases are different in kind and both are needed. A file where the
// campaign wants one is the clobber a DM would actually lose work to. A file the
// operator added at a path the campaign does not use is the other half: an
// extraction that reconciled the directory rather than adding to it would delete
// it, and no assertion about a colliding path would notice.
func TestSampleExtractDoesNotClobber(t *testing.T) {
	t.Parallel()
	const operatorBytes = "This is the DM's own page and the app is not allowed to touch it.\n"

	t.Run("a file where the campaign wants one", func(t *testing.T) {
		t.Parallel()
		const own = sample.Root + "/Overview.md"
		f := newFixture(t, map[string]string{own: operatorBytes})
		f.boot(t, f.opts)

		if got := string(readFile(t, f.vault.Root, own)); got != operatorBytes {
			t.Errorf("the campaign overwrote a file the operator had written:\n%q", got)
		}
		// And the rest of the campaign still arrived, so this is a refusal and
		// not a walk that gave up at the first collision.
		for _, want := range campaignFilesOnDisk(t) {
			if want == own {
				continue
			}
			if _, err := os.Stat(filepath.Join(f.vault.Root, filepath.FromSlash(want))); err != nil {
				t.Errorf("%s was not written because an earlier file was left alone: %v", want, err)
			}
		}
	})

	t.Run("a file the campaign does not use", func(t *testing.T) {
		t.Parallel()
		const own = sample.Root + "/Sessions/Our Own Game.md"
		f := newFixture(t, map[string]string{own: operatorBytes})
		f.boot(t, f.opts)

		if got := string(readFile(t, f.vault.Root, own)); got != operatorBytes {
			t.Errorf("extraction changed a file the campaign does not use:\n%q", got)
		}
		if got, want := f.pages(), 1+samplePages(); got != want {
			t.Errorf("the index holds %d pages, want the operator's page plus the campaign's %d", got, want)
		}
	})
}

// TestTheExtractionLeavesAnOccupiedPathAlone is the half of non-clobbering that
// a test of "does not overwrite" is easy to miss.
//
// The walk decides a file is absent only when vault.Read says ErrNotFound. A
// path occupied by a directory, and a file over the read cap, are both occupied
// paths Read cannot return; treating either as absence is the overwrite this
// design exists to refuse. A directory in the campaign's way is the case
// reachable without a mount option, so it is the one pinned here — and it is
// also the case that proves one refusal does not take the other thirty-seven
// files with it.
func TestTheExtractionLeavesAnOccupiedPathAlone(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	occupied := filepath.Join(f.vault.Root, filepath.FromSlash(sample.Root), "Overview.md")
	if err := os.MkdirAll(occupied, 0o700); err != nil {
		t.Fatalf("occupy the campaign's path with a directory: %v", err)
	}
	a := f.boot(t, f.opts)

	if st, err := os.Stat(occupied); err != nil || !st.IsDir() {
		t.Fatalf("the directory at the campaign's path is gone: %v", err)
	}
	if !anyWarningContains(a, "Overview.md") {
		t.Errorf("the boot report does not name the refused path: %v", a.Status().Warnings)
	}
	// A refusal that says nothing is a mystery the operator solves by deleting
	// the directory, so the warning names the path and the kind.
	written := 0
	for _, want := range campaignFilesOnDisk(t) {
		st, err := os.Stat(filepath.Join(f.vault.Root, filepath.FromSlash(want)))
		if err == nil && st.Mode().IsRegular() {
			written++
		}
	}
	if want := samplePages() - 1; written != want {
		t.Errorf("%d campaign files were written, want %d: one occupied path took the rest of the campaign with it", written, want)
	}
	if !anyWarningContains(a, "not a file is already at that path") {
		t.Errorf("the boot report does not say that the occupied path is not a file: %v", a.Status().Warnings)
	}
}

// TestTheExtractionRefusesWhatTheVaultWouldNotIndex covers the two guards on a
// destination path, and both are asked about names the campaign does not carry —
// which is exactly why they need a test rather than a comment.
func TestTheExtractionRefusesWhatTheVaultWouldNotIndex(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, rel string }{
		{"the app's own state directory", vault.HiddenDir + "/notes.db"},
		{"a write-ahead log", "index.db-wal"},
		{"another tool's directory", ".obsidian/workspace.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if rel, ok := sampleDestination(tc.rel); ok {
				t.Errorf("%s was accepted as a destination, at %s", tc.rel, rel)
			}
		})
	}
	if rel, ok := sampleDestination("Overview.md"); !ok || rel != sample.Root+"/Overview.md" {
		t.Errorf("an ordinary campaign file resolved to %q (accepted=%v), want %s", rel, ok, sample.Root+"/Overview.md")
	}
}

// TestTheExtractionRefusesANameTheVaultWouldNotIndex is the other half of the
// choice of vault.Resolve over vault.New.
//
// New cleans a path and performs no containment check and no name validation,
// and its own comment licenses it for a path that came from a walk of the vault.
// These came from a walk of a filesystem compiled into the binary, so that is
// not the case New documents. Each name below is one vault.Write would have
// created and vault.Walk would then have refused or mis-indexed — a ".."
// element, a control character, a trailing dot Windows drops — and the walk's
// refusals are the point: a file the app will not index is a page the operator
// has and cannot find, which is the silence walkWarnings exists to break.
//
// The checks at the *head* of a path — a UNC prefix, a drive letter, a leading
// slash — are deliberately not here, because the walk always prefixes
// sample.Root and no campaign name can reach them. They matter for a path off
// the wire, and the tests that cover them are the ones that put a path off the
// wire.
func TestTheExtractionRefusesANameTheVaultWouldNotIndex(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, tc := range []struct{ name, rel string }{
		{"a name leaving the campaign root", "../Escaped.md"},
		{"a name with a control character", "Bell\x07.md"},
		{"a trailing dot Windows drops", "Ledger.md."},
		{"a trailing space Windows drops", "Ledger.md "},
		{"a name stepping above the vault root", "Notes/../../Escaped.md"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := vault.Resolve(root, sample.Root+"/"+tc.rel)
			if err == nil {
				t.Errorf("vault.Resolve accepted %q as %s, and vault.Write would have created a file the walk refuses to index",
					tc.rel, p.Rel())
			}
			// New is the constructor this is not, and the difference is the
			// whole reason for the choice: it takes the name.
			n := vault.New(root, sample.Root+"/"+tc.rel)
			if _, err := vault.Read(context.Background(), n); err == nil {
				t.Errorf("the name is harmless, so this case proves nothing about Resolve")
			}
		})
	}
}

// TestThatTheExtractionRefusesToWriteThroughASymlinkedCampaignRoot is the case
// that makes the choice executable rather than argued, and it is the one a
// reader is most likely to assume goes the other way.
//
// A DM who links Campaigns/ at a shared drive is doing something entirely
// ordinary. vault.New performs no symlink resolution, so with it the walk would
// follow the link and write thirty-eight files outside the vault — which the
// walk then refuses to index as a symlink out of the vault, leaving an operator
// with a vault that reports itself empty. vault.Resolve refuses the write
// instead, and names it in the boot report.
func TestThatTheExtractionRefusesToWriteThroughASymlinkedCampaignRoot(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, vault.HiddenDir), 0o700); err != nil {
		t.Fatalf("prepare the vault: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "Campaigns")); err != nil {
		t.Skipf("this filesystem will not take a symlink: %v", err)
	}
	f := &fixture{t: t, banner: &strings.Builder{}, opts: Options{
		Config: config.Config{
			Vault: root, VaultSource: "flag:--vault",
			Host: "127.0.0.1", Port: 0, LogLevel: "error", MaxAttachmentSize: 32 << 20,
		},
		Logger: obs.Discard(),
		Clock:  obs.SystemClock,
	}}
	a := f.boot(t, f.opts)

	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("read the linked directory: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the extraction wrote %d entries through a symlink out of the vault: %v", len(entries), names)
	}
	if !anyWarningContains(a, "sample campaign") {
		t.Errorf("the boot report does not name the refused campaign: %v", a.Status().Warnings)
	}
}

// TestTheExtractionIsRecordedInTheBootLog is the operator-facing half: the walk
// says what it did, in one line, with no vault content in it.
//
// It is checked here rather than in internal/obs because the claim is not that
// the handler refuses content — that has its own tests — it is that this call
// site's arguments cannot carry any. A path, the campaign's name and two counts
// are the whole vocabulary, and the last assertion is the one that says the
// redacting handler did not have to intervene.
func TestTheExtractionIsRecordedInTheBootLog(t *testing.T) {
	t.Parallel()
	// A page whose body is unmistakably the campaign's, so "the line does not
	// contain it" is a claim rather than a tautology.
	const body = "THE PALE BELL TOLLS BENEATH THE DROWNED CHAPTERHOUSE"
	var logs bytes.Buffer
	f := newFixture(t, map[string]string{sample.Root + "/Overview.md": body})
	f.opts.Logger = obs.NewLogger(&logs, obs.Options{Level: slog.LevelDebug})
	f.boot(t, f.opts)

	got := logs.String()
	if !strings.Contains(got, "the bundled sample campaign was written into the vault") {
		t.Fatalf("the boot log does not mention the extraction:\n%s", got)
	}
	for _, want := range []string{
		`"campaign":"` + sample.Name + `"`,
		`"root":"` + sample.Root + `"`,
		`"written":` + strconv.Itoa(samplePages()-1),
		`"kept":1`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the extraction log line does not carry %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, body) {
		t.Error("the boot log printed a byte of vault content")
	}
	if strings.Contains(got, obs.Redacted) {
		t.Error("the extraction log line was refused or truncated by the redacting handler, so a call site is passing something content-shaped")
	}
}

// TestTheExtractionRunsWithoutTheHandler is the one-shot path. `semiplane
// reindex`, `backup` and `vault info` all boot without an HTTP handler, and a
// walk placed after the handler check would leave every one of them extracting
// into a vault the operator never asked it to.
func TestTheExtractionRunsWithoutTheHandler(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	if indexOf(f.steps, stepSample) >= 0 {
		t.Fatal("the sample extraction ran before the boot, so the trace does not show it in Boot")
	}
	f.boot(t, f.opts)
	if indexOf(f.steps, stepSample) < 0 {
		t.Errorf("a boot with no handler did not extract the campaign: %v", f.steps)
	}
	if got, want := f.pages(), samplePages(); got != want {
		t.Errorf("the index holds %d pages, want the campaign's %d", got, want)
	}
	// A one-shot boot must not leave the walk's own state behind, or a command
	// that exits in a second would have taken the lock and the campaign with it
	// and given neither back cleanly.
	if err := shutdownAnd(f.app); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	f.app = nil
	assertVaultIsLockable(t, f.vault.Root)
}
