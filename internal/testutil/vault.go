package testutil

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Vault is a temporary vault directory for one test.
//
// It is not a full app: it is a place to put files and a way to assert on them.
// A test that needs the whole application uses Harness.
type Vault struct {
	// Root is the absolute vault root. It is a t.TempDir, so it is removed
	// when the test finishes.
	Root string
	// Clock is deterministic. Every component that needs a time takes one, so
	// that a test never depends on wall time.
	Clock func() time.Time
}

// NewVault creates an empty vault for the test. The test must call t.Parallel
// itself; NewVault cannot, because t.TempDir on a non-parallel test is fine but
// the convention is that the caller is explicit about it.
//
// Use it like this:
//
//	v := testutil.NewVault(t)
//	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
func NewVault(t *testing.T) *Vault {
	t.Helper()
	return &Vault{
		Root:  t.TempDir(),
		Clock: FixedClock(2026, 9, 28, 10, 4, 11),
	}
}

// WithVault creates a vault pre-seeded with the given files, keyed by
// vault-relative path. A directory entry with an empty value creates a
// directory, so a test can assert that an empty directory is indexed.
func WithVault(t *testing.T, files map[string]string) *Vault {
	t.Helper()
	v := NewVault(t)
	for _, path := range sortedKeys(files) {
		if files[path] == "" {
			v.MkdirAll(t, path)
			continue
		}
		v.WriteFile(t, path, files[path])
	}
	return v
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WriteFile writes a file, creating parent directories. The mode is 0600
// because a vault file holds secrets; the tests that care about permissions
// assert on it.
func (v *Vault) WriteFile(t *testing.T, rel, content string) string {
	t.Helper()
	abs := filepath.Join(v.Root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(abs), err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return abs
}

// ReadFile returns a vault file's exact bytes. Tests that assert round-trip
// fidelity use this, never a re-serialisation.
func (v *Vault) ReadFile(t *testing.T, rel string) []byte {
	t.Helper()
	abs := filepath.Join(v.Root, filepath.FromSlash(rel))
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// MustReadFile is ReadFile for a file the test itself created.
func (v *Vault) MustReadFile(t *testing.T, rel string) string {
	t.Helper()
	return string(v.ReadFile(t, rel))
}

// Exists reports whether a vault-relative path exists.
func (v *Vault) Exists(rel string) bool {
	_, err := os.Stat(filepath.Join(v.Root, filepath.FromSlash(rel)))
	return err == nil
}

// Remove deletes a vault file, which is how a test simulates a deletion.
func (v *Vault) Remove(t *testing.T, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(v.Root, filepath.FromSlash(rel))); err != nil {
		t.Fatalf("remove %s: %v", rel, err)
	}
}

// Rename moves a file inside the vault, which is how a test simulates a rename
// and how the rename-detection code is exercised.
func (v *Vault) Rename(t *testing.T, from, to string) {
	t.Helper()
	absTo := filepath.Join(v.Root, filepath.FromSlash(to))
	if err := os.MkdirAll(filepath.Dir(absTo), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Rename(
		filepath.Join(v.Root, filepath.FromSlash(from)),
		absTo,
	); err != nil {
		t.Fatalf("rename %s -> %s: %v", from, to, err)
	}
}

// MkdirAll creates a vault directory.
func (v *Vault) MkdirAll(t *testing.T, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(v.Root, filepath.FromSlash(rel)), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
}

// WriteSecretFile writes a markdown file containing one secret fence, using the
// on-disk syntax from the plan. It exists so that a test does not hand-assemble
// a fence and get the directive order subtly wrong.
func (v *Vault) WriteSecretFile(t *testing.T, rel, id, visibility, author, body, around string) string {
	t.Helper()
	fence := "```secret id=" + id + " visibility=" + visibility +
		" author=" + author + " created=2026-09-28T10:04:11Z\n" + body + "\n```"
	return v.WriteFile(t, rel, around+"\n"+fence+"\n")
}

// Paths returns every file in the vault, vault-relative and slash-separated,
// sorted. A directory walk in a test almost always wants this.
func (v *Vault) Paths(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(v.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(v.Root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(out)
	return out
}

// HiddenDir is where the database, the lock and the backups live.
const HiddenDir = ".semiplane"

// DBDir returns the vault's private directory, creating it.
func (v *Vault) DBDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(v.Root, HiddenDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", HiddenDir, err)
	}
	return dir
}

// FixedClock returns a clock that reports the given wall time forever. Tests
// that assert on a stored timestamp use it so the expected value is a literal
// rather than a formatted "now".
func FixedClock(year int, month time.Month, day, hour, min, sec int) func() time.Time {
	fixed := time.Date(year, month, day, hour, min, sec, 0, time.UTC)
	return func() time.Time { return fixed }
}

// ISO is the timestamp format stored in every text column: RFC 3339 in UTC, so
// that a string comparison and a time comparison agree.
func ISO(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// User is a seeded user for a test that needs one.
type User struct {
	ID          int64
	Username    string
	DisplayName string
	Role        string
}

// RoleUser is a convenience constructor for the three stored roles.
func RoleUser(id int64, username, role string) User {
	return User{ID: id, Username: username, DisplayName: username, Role: role}
}

// NoFixtureSecret is the assertion helper for the leak suite. A test that seeds
// a secret body calls AssertNoSecret, so a leak fails with a message that names
// the fixture rather than printing a wall of HTML.
func AssertNoSecret(t *testing.T, body string, forbidden ...string) {
	t.Helper()
	for _, f := range forbidden {
		if f == "" {
			continue
		}
		if strings.Contains(body, f) {
			t.Fatalf("a secret body leaked into the response: %q", f)
		}
	}
}
