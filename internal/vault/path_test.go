package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNewNormalisesRelativePaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Campaigns/Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"leading slash", "/Campaigns/Ash.md", "Campaigns/Ash.md"},
		{"backslash", `Campaigns\Ash.md`, "Campaigns/Ash.md"},
		{"dot prefix", "./Campaigns/Ash.md", "Campaigns/Ash.md"},
		{"double slash", "Campaigns//Ash.md", "Campaigns/Ash.md"},
		{"dot segment", "Campaigns/./Ash.md", "Campaigns/Ash.md"},
		{"trailing slash", "Campaigns/", "Campaigns"},
		{"escape attempt is clipped to the root", "../../etc/passwd", "etc/passwd"},
		{"root", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New("/vault", tc.in)
			if p.Rel() != tc.want {
				t.Errorf("Rel = %q, want %q", p.Rel(), tc.want)
			}
			if !p.contained() {
				t.Errorf("%q escaped the root", tc.in)
			}
		})
	}
}

func TestPathAccessors(t *testing.T) {
	t.Parallel()
	p := New("/vault", "Campaigns/Ash/NPCs/Gundren.md")
	if p.Name() != "Gundren.md" {
		t.Errorf("Name = %q", p.Name())
	}
	if p.Dir() != "Campaigns/Ash/NPCs" {
		t.Errorf("Dir = %q", p.Dir())
	}
	if p.Root() != "/vault" {
		t.Errorf("Root = %q", p.Root())
	}
	if p.String() != "Campaigns/Ash/NPCs/Gundren.md" {
		t.Errorf("String = %q", p.String())
	}
	if want := filepath.Join("/vault", "Campaigns/Ash/NPCs/Gundren.md"); p.Abs() != want {
		t.Errorf("Abs = %q, want %q", p.Abs(), want)
	}
	if p.IsDir() {
		t.Error("a file is a directory")
	}

	root := New("/vault", "")
	if root.Dir() != "." {
		t.Errorf("root Dir = %q, want %q", root.Dir(), ".")
	}
}

// TestStringNeverLeaksTheAbsolutePath matters because a Path is logged freely.
func TestStringNeverLeaksTheAbsolutePath(t *testing.T) {
	t.Parallel()
	p := New("/home/dm/Campaigns/Ash", "Gundren.md")
	if strings.Contains(p.String(), "/home/dm") {
		t.Fatalf("String leaked the absolute path: %q", p.String())
	}
}

func TestJoinIsContained(t *testing.T) {
	t.Parallel()
	p := New("/vault", "Campaigns/Ash")

	ok, err := p.Join("Npcs/Gundren.png")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if ok.Rel() != "Campaigns/Ash/Npcs/Gundren.png" {
		t.Errorf("Rel = %q", ok.Rel())
	}

	// A traversal in the child is clipped rather than honoured.
	clipped, err := p.Join("../../etc/passwd")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if !clipped.contained() {
		t.Fatalf("clipped path escaped the vault: %q", clipped.Abs())
	}
}

func TestErrorsAreDistinctSentinels(t *testing.T) {
	t.Parallel()
	// A caller must be able to tell "you asked for something outside the vault"
	// from "it is not there", because the first is an attack and the second is
	// a 404.
	if ErrOutsideVault == ErrNotFound {
		t.Fatal("the two sentinels are the same value")
	}
	if !strings.Contains(ErrAlreadyLocked.Error(), "another semiplane process") {
		t.Errorf("the lock error should name the other process: %q", ErrAlreadyLocked)
	}
}
