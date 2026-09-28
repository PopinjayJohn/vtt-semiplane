package testutil

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewVaultIsEmptyAndIsolated(t *testing.T) {
	t.Parallel()
	a, b := NewVault(t), NewVault(t)

	if a.Root == b.Root {
		t.Fatal("two vaults share a root")
	}
	if got := a.Paths(t); len(got) != 0 {
		t.Fatalf("a new vault is not empty: %v", got)
	}
	// The clock is deterministic, so a stored timestamp is a literal.
	want := time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)
	if got := a.Clock(); !got.Equal(want) {
		t.Errorf("clock = %v, want %v", got, want)
	}
}

func TestWithVaultSeedsFilesAndDirs(t *testing.T) {
	t.Parallel()
	v := WithVault(t, map[string]string{
		"Campaigns/Ash/NPCs/Gundren.md": "# Gundren\n",
		"Campaigns/Ash/empty/":          "",
		"README.md":                     "# Ashes of the Hollow Crown\n",
	})

	want := []string{"Campaigns/Ash/NPCs/Gundren.md", "README.md"}
	got := v.Paths(t)
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if !v.Exists("Campaigns/Ash/empty") {
		t.Error("an empty directory entry was not created")
	}
}

func TestFileRoundTripIsByteExact(t *testing.T) {
	t.Parallel()
	v := NewVault(t)

	// CRLF, a BOM, trailing whitespace and a NUL byte: the shapes a naive
	// write path normalises away.
	content := "\xef\xbb\xbf# Title\r\n\r\ntrailing spaces   \n\x00"
	v.WriteFile(t, "Campaigns/Ash/Weird.md", content)

	if got := v.MustReadFile(t, "Campaigns/Ash/Weird.md"); got != content {
		t.Errorf("round trip changed the bytes:\n got %q\nwant %q", got, content)
	}
}

func TestRenameAndRemove(t *testing.T) {
	t.Parallel()
	v := NewVault(t)
	v.WriteFile(t, "NPC-Gundren.md", "x")
	v.Rename(t, "NPC-Gundren.md", "NPCs/Gundren.md")

	if v.Exists("NPC-Gundren.md") {
		t.Error("the old name still exists after a rename")
	}
	if got := v.MustReadFile(t, "NPCs/Gundren.md"); got != "x" {
		t.Errorf("content after rename = %q", got)
	}

	v.Remove(t, "NPCs/Gundren.md")
	if v.Exists("NPCs/Gundren.md") {
		t.Error("Remove did not remove the file")
	}
}

func TestWriteSecretFileProducesTheDocumentedSyntax(t *testing.T) {
	t.Parallel()
	v := NewVault(t)
	v.WriteSecretFile(t, "Ash.md", "7f3a91c40d2e", "private", "johan",
		"The vault door is warded.", "public text")

	got := v.MustReadFile(t, "Ash.md")
	for _, want := range []string{
		"public text",
		"```secret id=7f3a91c40d2e visibility=private author=johan created=2026-09-28T10:04:11Z",
		"The vault door is warded.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("secret file is missing %q:\n%s", want, got)
		}
	}
}

func TestDBDirIsPrivate(t *testing.T) {
	t.Parallel()
	v := NewVault(t)
	dir := v.DBDir(t)
	if filepath.Base(dir) != HiddenDir {
		t.Errorf("db dir = %q, want %q", dir, HiddenDir)
	}
}

func TestISOIsUTCRFC3339(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("plus2", 2*3600)
	got := ISO(time.Date(2026, 9, 28, 12, 4, 11, 0, loc))
	if got != "2026-09-28T10:04:11Z" {
		t.Errorf("ISO = %q, want the UTC form", got)
	}
}

func TestAssertNoSecretNamesTheFixture(t *testing.T) {
	t.Parallel()
	// A passing call must not fail; the failing case is exercised by the leak
	// suite itself, where a leak should name the fixture that escaped.
	AssertNoSecret(t, "<p>no secret here</p>", "the vault door is warded")
	AssertNoSecret(t, "<p>ignore empty fixtures</p>", "")
}

func TestRoleUser(t *testing.T) {
	t.Parallel()
	u := RoleUser(3, "johan", "dm")
	if u.ID != 3 || u.Username != "johan" || u.DisplayName != "johan" || u.Role != "dm" {
		t.Errorf("RoleUser = %+v", u)
	}
}
