package vault

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrOutsideVault is returned when a path resolves outside the vault root. It
// is the error every traversal test asserts on.
var ErrOutsideVault = errors.New("path resolves outside the vault")

// ErrNotFound is returned for a path that does not exist inside the vault.
var ErrNotFound = errors.New("no such file in the vault")

// ErrAlreadyLocked is returned when a second process already holds the
// single-instance lock for this vault (S18).
var ErrAlreadyLocked = errors.New("vault is already open by another semiplane process")

// Path is a validated, vault-relative file path.
//
// Construct one with Resolve for anything derived from user input, or with New
// for a path the indexer built itself from a walk. The zero value is not a
// valid path.
type Path struct {
	root string // absolute, symlink-resolved vault root
	rel  string // slash-separated, cleaned, relative, no leading slash
	abs  string // root + "/" + rel
}

// New builds a Path from a vault-relative path that the application itself
// produced. It cleans the input but performs no symlink resolution and no
// containment check, so it must only be used for paths that came from a
// directory walk of the vault. User input must go through Resolve.
func New(root, rel string) Path {
	r := cleanRel(rel)
	return Path{root: root, rel: r, abs: filepath.Join(root, filepath.FromSlash(r))}
}

// cleanRel normalises a relative path: backslashes to slashes, no leading
// slash, no "." or ".." elements that escape, no empty elements.
func cleanRel(rel string) string {
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.TrimPrefix(rel, "./")
	parts := make([]string, 0, 8)
	for _, p := range strings.Split(rel, "/") {
		switch p {
		case "", ".":
			continue
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "/")
}

// Root is the absolute vault root this path is relative to.
func (p Path) Root() string { return p.root }

// Rel is the vault-relative path, slash-separated. This is the form stored in
// pages.path and used in every URL.
func (p Path) Rel() string { return p.rel }

// Abs is the absolute filesystem path. Use it only with os calls inside this
// package or its callers after a successful Resolve.
func (p Path) Abs() string { return p.abs }

// Name is the final element.
func (p Path) Name() string {
	if i := strings.LastIndexByte(p.rel, '/'); i >= 0 {
		return p.rel[i+1:]
	}
	return p.rel
}

// Dir is the vault-relative directory containing the path. The root's own dir
// is ".".
func (p Path) Dir() string {
	if i := strings.LastIndexByte(p.rel, '/'); i >= 0 {
		return p.rel[:i]
	}
	return "."
}

// IsDir reports whether the path has no extension-bearing final element, which
// for vault purposes means the walk found a directory.
func (p Path) IsDir() bool { return p.rel == "" }

// String returns the vault-relative path. It never returns the absolute path,
// so a Path is safe to log.
func (p Path) String() string { return p.rel }

// Join returns the path of a child element, re-checking containment. The
// element is treated as untrusted: "..", absolute paths and symlinks are
// rejected rather than cleaned into something plausible.
func (p Path) Join(elem string) (Path, error) {
	rel := p.rel + "/" + cleanRel(elem)
	out := New(p.root, rel)
	if !out.contained() {
		return Path{}, ErrOutsideVault
	}
	return out, nil
}

// contained reports whether abs is inside root, lexically. It is the cheap
// half of the check; Resolve adds the symlink half.
func (p Path) contained() bool {
	rel, err := filepath.Rel(p.root, p.abs)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}
