package vault

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrCaseCollision is returned when two vault paths differ only by case and
// the operator has not accepted that. It is a hard error on every filesystem:
// on a case-sensitive one it is a latent portability problem, and on a
// case-insensitive one a page has already become invisible.
var ErrCaseCollision = errors.New("two vault paths differ only by case")

// WalkOptions configures Walk.
type WalkOptions struct {
	// AllowCaseCollisions downgrades a case collision from an error to a
	// warning. One member of each colliding group is indexed and the rest are
	// reported as skipped; the warning is repeated on every boot, because a
	// vault that merely warned once would quietly index a different file
	// tomorrow.
	AllowCaseCollisions bool
	// MaxFileBytes overrides MaxFileBytes for this walk. Zero means the
	// default.
	MaxFileBytes int64
}

// WalkError is a file the walk could not use. It is a warning, never a silent
// omission: a page that silently fails to index is a page nobody can find.
type WalkError struct {
	// Path is the vault-relative path.
	Path string
	// Reason is why it was not indexed.
	Reason string
}

// WalkResult is what a walk found and what it refused.
type WalkResult struct {
	// Files are the vault-relative paths to index, sorted.
	Files []string
	// Ignored counts the entries the walk declined: every ignored file, and
	// every ignored directory once. The contents of an ignored directory are
	// never enumerated, so a .git with ten thousand objects counts as one.
	Ignored int
	// CaseCollisions are the groups of paths that fold to one key, each sorted
	// and with the indexed member first. Empty unless a collision exists.
	CaseCollisions [][]string
	// Unreadable are the files that could not be read or stat'd.
	Unreadable []WalkError
	// SymlinksOutside are the vault symlinks whose target is outside the vault.
	// They are never followed and never indexed.
	SymlinksOutside []string
	// Symlinks are the vault symlinks that resolve to somewhere inside the
	// vault. A link to a file is indexed and listed here; a link to a directory
	// is listed here and not descended into, because nothing stops a symlink
	// pointing at its own ancestor.
	Symlinks []string
}

// CaseCollisionError names the group that collided. It unwraps to
// ErrCaseCollision, so a caller that only wants to know whether the walk halted
// can use errors.Is and ignore the detail.
type CaseCollisionError struct {
	// Group is the colliding paths, sorted, as spelled on disk.
	Group []string
	// Ignores is the probed answer to whether this filesystem treats the two
	// members as one file. It changes the operator's next step, so the error
	// says which of the two situations they are in.
	Ignores bool
}

// Error implements error.
func (e *CaseCollisionError) Error() string {
	why := "the vault will not survive being synced to a machine with a case-insensitive filesystem"
	if e.Ignores {
		why = "this filesystem already treats them as one file, so one of them is invisible"
	}
	return fmt.Sprintf("%v: %s (%s; pass --allow-case-collisions to index one of them anyway)",
		ErrCaseCollision, strings.Join(e.Group, " and "), why)
}

// Unwrap makes errors.Is(err, ErrCaseCollision) true.
func (e *CaseCollisionError) Unwrap() error { return ErrCaseCollision }

// Walk enumerates the vault.
//
// A collision is fatal by default. Two files that differ only by case are two
// files on Linux and one file with an arbitrary winner on macOS or Windows: a
// DM edits "Gundren.md" on a laptop, a player syncs the vault, and a page
// silently becomes a different page. Detecting it before indexing is the only
// point at which the operator can be told (S19).
func Walk(ctx context.Context, root string, opts WalkOptions) (WalkResult, error) {
	var res WalkResult
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if root == "" {
		return res, errors.New("walk: a vault root is required")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return res, fmt.Errorf("resolve vault root: %w", err)
	}

	// Group by case-folded key as we go, so a collision is known before the
	// walk ends rather than needing a second pass over every path.
	groups := map[string][]string{}
	walkErr := filepath.WalkDir(realRoot, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Unreadable = append(res.Unreadable, WalkError{relOf(realRoot, abs), err.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel := relOf(realRoot, abs)
		if rel == "" {
			return nil
		}
		if d.IsDir() {
			if ignoredDirName(d.Name()) {
				res.Ignored++
				return fs.SkipDir
			}
			return nil
		}
		if ignoredFileName(d.Name()) {
			res.Ignored++
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return recordSymlink(realRoot, abs, rel, opts, &res, groups)
		}
		if bad := invalidName(d.Name()); bad != "" {
			res.Unreadable = append(res.Unreadable, WalkError{rel, bad})
			return nil
		}
		st, err := d.Info()
		if err != nil {
			res.Unreadable = append(res.Unreadable, WalkError{rel, err.Error()})
			return nil
		}
		if st.Size() > opts.maxBytes() {
			res.Unreadable = append(res.Unreadable, WalkError{
				rel, fmt.Sprintf("file is %d bytes, over the %d byte limit", st.Size(), opts.maxBytes()),
			})
			return nil
		}
		groups[strings.ToLower(rel)] = append(groups[strings.ToLower(rel)], rel)
		return nil
	})
	if walkErr != nil {
		return res, fmt.Errorf("walk %s: %w", filepath.Base(realRoot), walkErr)
	}

	res.CaseCollisions = collidingGroups(groups)
	if len(res.CaseCollisions) > 0 && !opts.AllowCaseCollisions {
		return res, &CaseCollisionError{
			Group:   res.CaseCollisions[0],
			Ignores: filesystemIgnoresCase(realRoot),
		}
	}
	res.Files = selectIndexed(groups, res.CaseCollisions)
	sort.Strings(res.Files)
	sort.Strings(res.SymlinksOutside)
	sort.Strings(res.Symlinks)
	return res, nil
}

// recordSymlink classifies a link. A link out of the vault is refused; a link
// inside it is indexed, because the bytes it points at are vault content.
func recordSymlink(root, abs, rel string, opts WalkOptions, res *WalkResult, groups map[string][]string) error {
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		res.Unreadable = append(res.Unreadable, WalkError{rel, "dangling symlink"})
		return nil
	}
	if !within(root, target) {
		res.SymlinksOutside = append(res.SymlinksOutside, rel)
		return nil
	}
	res.Symlinks = append(res.Symlinks, rel)
	st, err := os.Stat(target)
	if err != nil {
		res.Unreadable = append(res.Unreadable, WalkError{rel, err.Error()})
		return nil
	}
	if st.IsDir() {
		// Not indexed and not descended: a link to a directory is a link to
		// every file under it, which is a walk with no termination guarantee.
		return nil
	}
	if st.Size() > opts.maxBytes() {
		res.Unreadable = append(res.Unreadable, WalkError{
			rel, fmt.Sprintf("file is %d bytes, over the %d byte limit", st.Size(), opts.maxBytes()),
		})
		return nil
	}
	key := strings.ToLower(rel)
	groups[key] = append(groups[key], rel)
	return nil
}

// collidingGroups returns the case-folded groups holding more than one distinct
// path, each sorted with the member that will be indexed first.
func collidingGroups(groups map[string][]string) [][]string {
	var out [][]string
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		sort.Strings(members)
		out = append(out, members)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// selectIndexed flattens the groups, dropping every member of a collision
// except its first. The choice is lexicographic rather than "whichever the
// walk saw first", because the walk's order is the filesystem's and is not the
// same on the next boot.
func selectIndexed(groups map[string][]string, collisions [][]string) []string {
	skip := map[string]bool{}
	for _, group := range collisions {
		for _, member := range group[1:] {
			skip[member] = true
		}
	}
	out := make([]string, 0, len(groups))
	for _, members := range groups {
		for _, member := range members {
			if !skip[member] {
				out = append(out, member)
			}
		}
	}
	return out
}

func (o WalkOptions) maxBytes() int64 {
	if o.MaxFileBytes > 0 {
		return o.MaxFileBytes
	}
	return MaxFileBytes
}

func relOf(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return ""
	}
	return rel
}

// caseProbe is the one-entry cache for the filesystem's case sensitivity. It is
// a property of a mount, not of a process, and a process opens one vault, so a
// single slot keyed by the root is enough and cannot grow.
type caseProbe struct {
	root        string
	ignoresCase bool
}

var probed atomic.Pointer[caseProbe]

// filesystemIgnoresCase reports whether root's filesystem treats "Gundren.md"
// and "gundren.md" as the same file.
//
// It is probed once per root with a real create and a differently-cased stat,
// because there is no portable way to ask. A wrong answer in either direction
// is a bug: assumed-insensitive makes every scan claim collisions that are not
// there, assumed-sensitive lets a vault that will not survive a sync to a
// player's laptop boot without a word.
func filesystemIgnoresCase(root string) bool {
	if p := probed.Load(); p != nil && p.root == root {
		return p.ignoresCase
	}
	ignores := probeCaseSensitivity(root)
	probed.Store(&caseProbe{root: root, ignoresCase: ignores})
	return ignores
}

var probeMu sync.Mutex

// probeCaseSensitivity creates a file and looks for it under a different case.
func probeCaseSensitivity(root string) bool {
	probeMu.Lock()
	defer probeMu.Unlock()

	dir, err := os.MkdirTemp(root, ".semiplane-caseprobe-")
	if err != nil {
		// A read-only vault cannot be probed. Assuming it is case-sensitive is
		// the safe direction: that walk indexes both members and reports the
		// collision, which is the visible outcome.
		return false
	}
	defer func() { _ = os.RemoveAll(dir) }()

	const lower = "probe"
	if err := os.WriteFile(filepath.Join(dir, lower), []byte("x"), 0o600); err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, strings.ToUpper(lower)))
	return err == nil
}

// reservedNameChars are the characters no Windows file may contain. A vault
// written on Linux and synced to a player's laptop loses every path that uses
// one, so they are reported here rather than discovered there.
const reservedNameChars = `<>:"/\|?*`

// reservedNames are the DOS device names, which are files that cannot be
// created on Windows at all — not even with an extension.
var reservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// invalidName returns why a basename cannot survive a round trip through every
// platform a vault is synced to, or "" when it can.
//
// On unix almost everything is a legal filename, so the reserved set is nearly
// empty and this is a no-op — which is correct, because the check exists for
// the other platform.
func invalidName(name string) string {
	if name == "" {
		return "empty name"
	}
	for _, r := range name {
		if r < 0x20 {
			return fmt.Sprintf("name contains the control character %q", r)
		}
	}
	if runtime.GOOS != "windows" {
		return ""
	}
	if strings.ContainsAny(name, reservedNameChars) {
		return "name contains a character Windows does not allow in a filename"
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return "Windows silently drops a trailing dot or space from a filename"
	}
	if reservedNames[strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))] {
		return "name is a reserved Windows device name"
	}
	return ""
}
