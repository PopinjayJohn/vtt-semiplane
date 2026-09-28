package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// TestCaseCollisionHaltsIndexing is S19. Two files that differ only by case are
// two files here and one arbitrary file on the player's laptop, so the default
// is to stop before the index is built rather than after a page has vanished.
func TestCaseCollisionHaltsIndexing(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# lower\n")
	v.WriteFile(t, "Campaigns/Ash/gundren.md", "# upper\n")

	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err == nil {
		t.Fatalf("a case collision did not halt the walk; it indexed %v", res.Files)
	}
	if !errors.Is(err, ErrCaseCollision) {
		t.Fatalf("Walk = %v, want ErrCaseCollision", err)
	}
	var ce *CaseCollisionError
	if !errors.As(err, &ce) {
		t.Fatalf("errors.As found no *CaseCollisionError in %v", err)
	}
	if len(ce.Group) != 2 {
		t.Errorf("Group = %v, want both members", ce.Group)
	}
	for _, want := range []string{"Campaigns/Ash/Gundren.md", "Campaigns/Ash/gundren.md"} {
		if !contains(ce.Group, want) {
			t.Errorf("Group %v does not name %q", ce.Group, want)
		}
	}
	if !strings.Contains(err.Error(), "allow-case-collisions") {
		t.Errorf("the error should name the way out: %v", err)
	}

	// The result still reports what it found, so a boot report can show the
	// operator the colliding pair even though indexing halted.
	if len(res.CaseCollisions) != 1 {
		t.Errorf("the result dropped the collision report: %v", res.CaseCollisions)
	}
}

// TestCaseCollisionAllowedIsExplicit pins the escape hatch: one member is
// indexed, the other is reported as skipped, and the report is on every boot.
func TestCaseCollisionAllowedIsExplicit(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# upper-first\n")
	v.WriteFile(t, "Campaigns/Ash/gundren.md", "# lower-first\n")
	v.WriteFile(t, "Campaigns/Ash/SelA.md", "# unrelated\n")

	opts := WalkOptions{AllowCaseCollisions: true}
	res, err := Walk(t.Context(), v.Root, opts)
	if err != nil {
		t.Fatalf("Walk with the flag = %v", err)
	}
	if len(res.CaseCollisions) != 1 {
		t.Fatalf("CaseCollisions = %v, want one group", res.CaseCollisions)
	}
	group := res.CaseCollisions[0]
	if len(group) != 2 {
		t.Fatalf("group = %v, want both members so the skip is visible", group)
	}
	// The choice is lexicographic, not "whichever the walk saw first": the
	// walk's order is the filesystem's and differs on the next boot.
	winner := group[0]
	if winner != "Campaigns/Ash/Gundren.md" {
		t.Errorf("the indexed member is %q, want the lexicographically first", winner)
	}
	for _, f := range res.Files {
		if f == "Campaigns/Ash/gundren.md" {
			t.Error("both members were indexed, so the collision was not resolved")
		}
	}
	if !contains(res.Files, "Campaigns/Ash/Gundren.md") {
		t.Errorf("the winner is not in Files: %v", res.Files)
	}
	if !contains(res.Files, "Campaigns/Ash/SelA.md") {
		t.Errorf("an unrelated file was dropped: %v", res.Files)
	}

	// A second boot must repeat the warning. A vault that reported this once
	// would quietly index a different file tomorrow.
	second, err := Walk(t.Context(), v.Root, opts)
	if err != nil {
		t.Fatalf("second walk: %v", err)
	}
	if len(second.CaseCollisions) != len(res.CaseCollisions) {
		t.Errorf("the second boot reported %v, want the same collision again", second.CaseCollisions)
	}
}

// TestCaseCollisionDetectionIsCaseInsensitiveToPlatform is the other half of
// the rule: on a filesystem that already folds case, the walk still reports the
// collision, because the operator is running on a machine where the test
// created it differently.
func TestCaseCollisionDetectionIsCaseInsensitiveToPlatform(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# one\n")
	v.WriteFile(t, "Campaigns/Ash/gundren.md", "# two\n")

	ignores := filesystemIgnoresCase(v.Root)
	if ignores {
		// A case-insensitive mount cannot hold both, so the second write landed
		// on the first. The walk must not invent a collision out of that.
		res, err := Walk(t.Context(), v.Root, WalkOptions{})
		if err != nil {
			t.Fatalf("Walk on a case-insensitive filesystem = %v", err)
		}
		if len(res.CaseCollisions) != 0 {
			t.Errorf("CaseCollisions = %v, want none on a case-insensitive mount", res.CaseCollisions)
		}
		return
	}
	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err == nil {
		t.Fatalf("the collision was missed on a case-sensitive filesystem: %v", res.Files)
	}
	if len(res.CaseCollisions) != 1 {
		t.Errorf("CaseCollisions = %v", res.CaseCollisions)
	}
}

func TestFilesystemIgnoresCaseIsCachedAndConsistent(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	first := filesystemIgnoresCase(v.Root)
	second := filesystemIgnoresCase(v.Root)
	if first != second {
		t.Errorf("the cached answer changed between calls: %v then %v", first, second)
	}
	if first {
		t.Skipf("this filesystem ignores case, so the probe is not exercised")
	}
	// The probe must leave nothing behind in the vault: a walk that found a
	// .semiplane-caseprobe directory would index it.
	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(res.Files) != 0 {
		t.Errorf("the case probe left files behind: %v", res.Files)
	}
	if res.Ignored != 0 {
		t.Errorf("the case probe was counted as ignored content: %d", res.Ignored)
	}
}

// TestIgnoredFilesAreCounted keeps the ignore rules from becoming a silent
// omission: everything skipped is counted, so the boot report can say so.
func TestIgnoredFilesAreCounted(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	v.WriteFile(t, ".obsidian/workspace.json", "{}")
	v.WriteFile(t, ".obsidian/plugins/x/manifest.json", "{}")
	v.WriteFile(t, ".semiplane/semiplane.db", "sqlite")
	v.WriteFile(t, ".git/HEAD", "ref: refs/heads/main")
	v.WriteFile(t, ".trash/Deleted.md", "gone")
	v.WriteFile(t, "node_modules/pkg/index.js", "js")
	v.WriteFile(t, "Campaigns/Ash/half.md"+tempSuffix, "half written")
	v.WriteFile(t, ".semiplane/semiplane.db-wal", "wal")
	v.WriteFile(t, ".semiplane/semiplane.db-shm", "shm")

	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0] != "Campaigns/Ash/Gundren.md" {
		t.Errorf("Files = %v, want only the page", res.Files)
	}
	// Five ignored directories and one ignored file. The -wal and -shm sidecars
	// are inside .semiplane, which is skipped whole, so they are never counted:
	// their suffix rules exist for a database that is not hidden, and
	// .obsidian/plugins/x/manifest.json is likewise never enumerated.
	if want := 6; res.Ignored != want {
		t.Errorf("Ignored = %d, want %d", res.Ignored, want)
	}
}

// TestWalkRefusesASymlinkOutOfTheVault is the walk's half of S6.
func TestWalkRefusesASymlinkOutOfTheVault(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "loot.md"), []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(v.Root, "Escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	if err := os.Symlink(filepath.Join(v.Root, "Campaigns"), filepath.Join(v.Root, "Campaigns/Loop")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !contains(res.SymlinksOutside, "Escape") {
		t.Errorf("SymlinksOutside = %v, want the link out of the vault", res.SymlinksOutside)
	}
	if contains(res.Files, "Escape/loot.md") {
		t.Error("the walk followed a symlink out of the vault")
	}
	if !contains(res.Symlinks, "Campaigns/Loop") {
		t.Errorf("Symlinks = %v, want the in-vault link recorded", res.Symlinks)
	}
	if contains(res.Files, "Campaigns/Loop") {
		t.Error("a symlinked directory was indexed as a page")
	}
	if !contains(res.Files, "Campaigns/Ash/Gundren.md") {
		t.Errorf("Files = %v", res.Files)
	}
}

func TestWalkRefusesAnOversizeFile(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Huge.md", strings.Repeat("x", 64))
	v.WriteFile(t, "Campaigns/Ash/Small.md", "# small\n")

	res, err := Walk(t.Context(), v.Root, WalkOptions{MaxFileBytes: 32})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if contains(res.Files, "Campaigns/Ash/Huge.md") {
		t.Errorf("an oversize file was indexed: %v", res.Files)
	}
	if !contains(res.Files, "Campaigns/Ash/Small.md") {
		t.Errorf("Files = %v", res.Files)
	}
	if len(res.Unreadable) != 1 {
		t.Fatalf("Unreadable = %v, want the oversize file reported", res.Unreadable)
	}
	if !strings.Contains(res.Unreadable[0].Reason, "over the") {
		t.Errorf("Reason = %q", res.Unreadable[0].Reason)
	}
	if res.Unreadable[0].Path != "Campaigns/Ash/Huge.md" {
		t.Errorf("Path = %q", res.Unreadable[0].Path)
	}
}

// TestWalkReportsUnreadableFiles is the "never a silent omission" rule. A
// permission-denied file is reported; the test cannot rely on a chmod on a
// filesystem that ignores it, so it uses a dangling symlink, which every
// platform refuses.
func TestWalkReportsUnreadableFiles(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	if err := os.Symlink(filepath.Join(v.Root, "nowhere.md"), filepath.Join(v.Root, "Dangling.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := Walk(t.Context(), v.Root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(res.Unreadable) != 1 || res.Unreadable[0].Path != "Dangling.md" {
		t.Fatalf("Unreadable = %v, want the dangling symlink", res.Unreadable)
	}
	if !strings.Contains(res.Unreadable[0].Reason, "dangling") {
		t.Errorf("Reason = %q", res.Unreadable[0].Reason)
	}
}

func TestWalkRejectsABadRequest(t *testing.T) {
	t.Parallel()
	if _, err := Walk(t.Context(), "", WalkOptions{}); err == nil {
		t.Error("Walk with no root must fail")
	}
	if _, err := Walk(t.Context(), filepath.Join(t.TempDir(), "no-such-vault"), WalkOptions{}); err == nil {
		t.Error("Walk on a missing root must fail")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Walk(ctx, t.TempDir(), WalkOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Walk with a cancelled context = %v", err)
	}
}

func TestInvalidNameFlagsUnportableNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{"Gundren.md", false},
		{"My Notes.md", false},
		{"npc-2.png", false},
		{"notes…md", false},
		{"bad\x01name.md", true},
		{"", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := invalidName(tc.name) != ""; got != tc.want {
				t.Errorf("invalidName(%q) flagged = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestIgnoredRelChecksEveryElement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rel  string
		want bool
	}{
		{"Campaigns/Ash/Gundren.md", false},
		{"", false},
		{".", false},
		{".obsidian/workspace.json", true},
		{"Campaigns/.git/config", true},
		{"Campaigns/node_modules/x/y.js", true},
		{".semiplane/semiplane.db", true},
		{"Campaigns/Ash/x.md" + tempSuffix, true},
		{".semiplane/semiplane.db-wal", true},
		{"Campaigns/Ash/Gundren.md", false},
		{"a/trash/b.md", false},
	}
	for _, tc := range cases {
		t.Run(tc.rel, func(t *testing.T) {
			t.Parallel()
			if got := ignoredRel(tc.rel); got != tc.want {
				t.Errorf("ignoredRel(%q) = %v, want %v", tc.rel, got, tc.want)
			}
		})
	}
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}
