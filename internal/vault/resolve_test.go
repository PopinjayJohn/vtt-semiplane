package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// TestResolveRejectsAdversarialInput is the table the whole package is built
// around. Every case is something an attacker would put in a URL, a wikilink or
// a form field, and every one of them must be refused before the filesystem is
// touched.
func TestResolveRejectsAdversarialInput(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	// A symlink out of the vault, the case a lexical check cannot see.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "loot.md"), []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("seed outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(v.Root, "Escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{"parent traversal", "../../etc/passwd"},
		{"traversal in the middle", "Campaigns/../../etc/passwd"},
		{"traversal after a real directory", "Campaigns/Ash/../../../etc/passwd"},
		{"a climb that lands back inside is still a climb", "Campaigns/Ash/../Ash/Gundren.md"},
		{"traversal with a backslash", `..\..\etc\passwd`},
		{"double leading slash is a UNC path", "//etc/passwd"},
		{"unc path", `\\server\share\x`},
		{"windows drive", `C:\Windows\x`},
		{"windows drive with slashes", "C:/Windows/x"},
		{"nul byte", "Campaigns/\x00Ash.md"},
		{"newline", "Campaigns/Ash\nGundren.md"},
		{"carriage return", "Campaigns/Ash\rGundren.md"},
		{"tab", "Campaigns/\tAsh.md"},
		{"delete character", "Campaigns/\x7fAsh.md"},
		{"four kilobytes", strings.Repeat("a", 4096)},
		{"four kilobytes of traversal", "../" + strings.Repeat("a", 4090)},
		{"just a dot", "."},
		{"just a dot slash", "./"},
		{"just two dots", ".."},
		{"just a slash", "/"},
		{"empty", ""},
		{"last element is a dot dot", "Campaigns/Ash/.."},
		{"last element is a dot dot slash", "Campaigns/.."},
		{"escape through a dot", "Campaigns/./../../etc"},
		{"symlink to outside", "Escape/loot.md"},
		{"symlink to outside with a traversal tail", "Escape/../Escape/loot.md"},
		{"homoglyph slash hides a traversal", "Campaigns/Ash∕..∕..∕etc"},
		{"fraction slash hides a traversal", "Campaigns⁄..⁄..⁄etc"},
		{"fullwidth reverse solidus hides a traversal", `Campaigns＼..＼etc`},
		{"a trailing space", "Campaigns/Ash.md "},
		{"a trailing dot", "Campaigns/Ash.md."},
		{"only dots", "..."},
		{"a leading space with a trailing one", " Campaigns/Ash.md "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := Resolve(v.Root, tc.input)
			if err == nil {
				t.Fatalf("Resolve(%q) = %q, want a refusal", tc.input, p.Rel())
			}
			if !errors.Is(err, ErrOutsideVault) {
				t.Errorf("Resolve(%q) = %v, want ErrOutsideVault", tc.input, err)
			}
		})
	}
}

// TestResolveErrorCarriesTheInputAndNotThePath pins the two halves of the error
// contract: the operator needs to see what they typed, and nobody needs to see
// where the vault lives.
func TestResolveErrorCarriesTheInputAndNotThePath(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	_, err := Resolve(v.Root, "../../etc/passwd")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "../../etc/passwd") {
		t.Errorf("the error does not name the input: %v", err)
	}
	if strings.Contains(err.Error(), v.Root) {
		t.Errorf("the error leaked the vault root: %v", err)
	}
}

// TestResolveClipsAHugeInput keeps a four kilobyte string out of every log line
// downstream of it.
func TestResolveClipsAHugeInput(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	huge := strings.Repeat("z", MaxPathBytes*4)
	_, err := Resolve(v.Root, huge)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if len(err.Error()) > 512 {
		t.Errorf("the error is %d bytes: an untrusted string was not clipped", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("a clipped error should say so: %v", err)
	}
}

func TestResolveAcceptsRealPaths(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "Campaigns/Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"a not-yet-created page", "Campaigns/Ash/NPCs/Sela.md", "Campaigns/Ash/NPCs/Sela.md"},
		{"a not-yet-created tree", "Campaigns/Braxton/Map.md", "Campaigns/Braxton/Map.md"},
		{"a leading slash is the url form", "/Campaigns/Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"a rooted path stays a vault-relative path", "/etc/passwd", "etc/passwd"},
		{"percent escapes are the router's business", "..%2f..%2fetc", "..%2f..%2fetc"},
		{"backslash separators", `Campaigns\Ash\Gundren.md`, "Campaigns/Ash/Gundren.md"},
		{"trailing slash", "Campaigns/Ash/Gundren.md/", "Campaigns/Ash/Gundren.md"},
		{"double slash", "Campaigns//Ash//Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"dot prefix", "./Campaigns/Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"dot segment that does not climb", "Campaigns/./Ash/Gundren.md", "Campaigns/Ash/Gundren.md"},
		{"deep nest", "a/b/c/d/e/f/g/h/Page.md", "a/b/c/d/e/f/g/h/Page.md"},
		{"four hundred directories", strings.Repeat("d/", 400) + "x.md", strings.Repeat("d/", 400) + "x.md"},
		{"a name with spaces", "Campaigns/Ash/My Notes.md", "Campaigns/Ash/My Notes.md"},
		{"a name with unicode", "Campaigns/Ash/Gün dren’s notes.md", "Campaigns/Ash/Gün dren’s notes.md"},
		{"a homoglyph slash that does not traverse", "Campaigns∕Ash.md", "Campaigns/Ash.md"},
		{"a folded fullwidth solidus is contained like any slash", "Campaigns／Ash.md／x", "Campaigns/Ash.md/x"},
		{"a leading space is part of the name", " Campaigns/Ash.md", " Campaigns/Ash.md"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := Resolve(v.Root, tc.input)
			if err != nil {
				t.Fatalf("Resolve(%q) = %v", tc.input, err)
			}
			if p.Rel() != tc.want {
				t.Errorf("Rel = %q, want %q", p.Rel(), tc.want)
			}
			if p.Root() != v.Root {
				t.Errorf("Root = %q, want %q", p.Root(), v.Root)
			}
		})
	}
}

// TestResolveAllowsASymlinkInsideTheVault is the other half of S6: a link that
// stays inside is content, not an attack, and refusing it would break a vault
// that links its handouts folder.
func TestResolveAllowsASymlinkInsideTheVault(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Handouts/Map.png", "png")
	if err := os.Symlink(filepath.Join(v.Root, "Handouts"), filepath.Join(v.Root, "Campaigns/Assets")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p, err := Resolve(v.Root, "Campaigns/Assets/Map.png")
	if err != nil {
		t.Fatalf("an in-vault symlink was refused: %v", err)
	}
	if p.Rel() != "Campaigns/Assets/Map.png" {
		t.Errorf("Rel = %q", p.Rel())
	}
}

// TestResolveIsSafeUnderAChangedRoot is the macOS case: a temp dir under /var
// is reached through a symlink, so an unresolved root would make every
// legitimate path look like an escape.
func TestResolveIsSafeUnderAChangedRoot(t *testing.T) {
	t.Parallel()
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "vault")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(real, "Page.md"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	p, err := Resolve(link, "Page.md")
	if err != nil {
		t.Fatalf("resolve through a symlinked root: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if p.Root() != resolved {
		t.Errorf("Root = %q, want the resolved root %q", p.Root(), resolved)
	}
}

func TestResolveRefusesAMissingRoot(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	if _, err := Resolve(filepath.Join(v.Root, "no-such-dir"), "Page.md"); err == nil {
		t.Fatal("a missing vault root must be refused rather than used as a path")
	}
}

// FuzzResolveNeverEscapes is the property the table cannot enumerate: no
// matter what bytes arrive, a resolved path is inside the root or an error.
func FuzzResolveNeverEscapes(f *testing.F) {
	f.Add("Campaigns/Ash/Gundren.md")
	f.Add("../../etc/passwd")
	f.Add("..%2f..%2fetc")
	f.Add("Campaigns/../..")
	f.Add("∕..∕..∕etc")

	root := f.TempDir()
	f.Fuzz(func(t *testing.T, in string) {
		p, err := Resolve(root, in)
		if err != nil {
			if !errors.Is(err, ErrOutsideVault) {
				t.Fatalf("Resolve(%q) failed with a non-ErrOutsideVault error: %v", in, err)
			}
			return
		}
		if p.Rel() == "" {
			t.Fatalf("Resolve(%q) returned the vault root", in)
		}
		if !within(root, p.Abs()) {
			t.Fatalf("Resolve(%q) = %q, which is outside %q", in, p.Abs(), root)
		}
		for _, elem := range strings.Split(p.Rel(), "/") {
			// A name may legitimately contain dots — "notes..md" is a real file
			// — so the property is about elements, not substrings.
			if elem == ".." {
				t.Fatalf("Resolve(%q) = %q, which still has a dot-dot element", in, p.Rel())
			}
		}
	})
}

// TestResolveAndReadReportDifferentFailures keeps the refusals apart, because
// a handler maps them to different responses: a missing file is a 404 and a
// traversal attempt is a 400.
func TestResolveAndReadReportDifferentFailures(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "x")

	if _, err := Read(t.Context(), New(v.Root, "Missing.md")); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read on a missing file = %v, want ErrNotFound", err)
	}
	_, err := Resolve(v.Root, "../escape")
	if err == nil {
		t.Fatal("an escape was accepted")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("an escape was reported as a missing file: %v", err)
	}
	if ErrOutsideVault == ErrNotFound {
		t.Error("the two sentinels are not distinct values")
	}
}
