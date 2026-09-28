package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// MaxPathBytes is the longest vault-relative path Resolve accepts. A vault
// nests a handful of directories and a filesystem caps the filename, so a
// kilobyte is already generous. The limit exists so that a hostile four-kilobyte
// string cannot be reflected whole into an error line or a log record.
const MaxPathBytes = 1024

// homoglyphSlashes are the Unicode characters a human reads as a path
// separator but the operating system does not.
//
// Folding them to "/" before the traversal check is what makes the check
// sound. Left alone, "Campaigns/..∕..∕etc" is one innocuous filename to Linux
// and to every reviewer, and it would be written to disk as a file invisible in
// Obsidian — a DM would be editing a file that is not the one the app indexed.
var homoglyphSlashes = strings.NewReplacer(
	"∕", "/", // division slash
	"⁄", "/", // fraction slash
	"／", "/", // fullwidth solidus
	"＼", "/", // fullwidth reverse solidus
)

// Resolve turns a user-supplied string into a Path, or refuses it.
//
// It is the only constructor that establishes containment, and the only one any
// handler may call with input that came off the wire. New exists for paths the
// indexer built out of a walk, where the input is already trusted.
//
// The rules, in order: a control character anywhere, an over-long string, a UNC
// path, a drive letter, a ".." element and an unportable final name are all
// refused before the filesystem is touched. Containment is then established on
// the *resolved* path — the deepest existing ancestor is passed through
// EvalSymlinks and compared against the resolved root — because a lexically
// contained path can still be a symlink out of the vault (S6).
//
// A single leading slash is stripped, because every link in the app carries one.
// What remains of an "absolute" path is then a vault-relative path like any
// other, and containment is what makes it safe; a doubled leading slash, a UNC
// path and a drive letter are refused instead.
//
// An error never carries the resolved absolute path: it carries the input,
// which is attacker-controlled but is not vault content, and a short reason.
func Resolve(root, userInput string) (Path, error) {
	rel, err := relativeInput(userInput)
	if err != nil {
		return Path{}, err
	}

	// The root itself is resolved for the same reason as the leaf: a temp dir
	// under /var on macOS is reached through a symlink, so an unresolved root
	// would make every legitimate path look like it escaped.
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Path{}, outsideErr(userInput, "the vault root cannot be resolved")
	}

	p := New(realRoot, rel)
	real, err := resolveDeepest(p.Abs())
	if err != nil {
		return Path{}, outsideErr(userInput, "the path does not exist anywhere inside the vault")
	}
	if !within(realRoot, real) {
		return Path{}, outsideErr(userInput, "it resolves outside the vault")
	}
	return p, nil
}

// relativeInput applies every syntactic rule and returns a cleaned
// vault-relative path. It is separate from Resolve so that the rules can be
// tested without a filesystem.
func relativeInput(in string) (string, error) {
	if in == "" {
		return "", outsideErr(in, "an empty path names no file")
	}
	if len(in) > MaxPathBytes {
		return "", outsideErr(in, fmt.Sprintf("it is longer than the %d byte limit", MaxPathBytes))
	}
	for _, r := range in {
		// NUL, newline, CR and tab all end up in log lines, URLs and the obs
		// redactor's length check. A path that cannot survive all three is not
		// a path we are willing to open, whatever the filesystem would allow.
		if r == 0 || unicode.IsControl(r) {
			return "", outsideErr(in, "it contains a control character")
		}
	}

	s := homoglyphSlashes.Replace(strings.ReplaceAll(in, `\`, "/"))
	if strings.HasPrefix(s, "//") {
		return "", outsideErr(in, "a UNC path names a host, not a vault file")
	}
	// One leading slash is the URL form — every link in the app carries one —
	// and is stripped. A doubled one was refused above, because that is a UNC
	// path rather than a rooted path, and this is the only reason the two are
	// distinguished.
	s = strings.TrimPrefix(s, "/")
	if s == "" {
		return "", outsideErr(in, "it names the vault root, which is not a file")
	}
	if filepath.IsAbs(filepath.FromSlash(s)) {
		return "", outsideErr(in, "an absolute path has no vault-relative form")
	}
	if hasDriveLetter(s) {
		return "", outsideErr(in, "a drive letter is not a vault path")
	}

	elems := strings.Split(s, "/")
	for _, elem := range elems {
		switch elem {
		case "", ".":
		case "..":
			// Not cleaned into place: refused. cleanRel would turn
			// "Campaigns/../../etc" into "etc", which is inside the vault and
			// still not what was asked for.
			return "", outsideErr(in, "a path may not step above the vault root")
		}
	}
	if bad := unportableTail(elems[len(elems)-1]); bad != "" {
		return "", outsideErr(in, bad)
	}
	if rel := cleanRel(s); rel != "" {
		return rel, nil
	}
	return "", outsideErr(in, "it names the vault root, which is not a file")
}

// unportableTail reports why a final element could not survive a round trip
// through a Windows machine, or "" when it can.
//
// A trailing space or dot is silently dropped by Windows, so a page saved with
// one is a page that disappears the first time the vault syncs to a player's
// laptop. Refusing it here and reporting it in the walk are the same rule seen
// from both ends: this package will not create such a name, and it will not
// stay quiet about one that arrived from elsewhere.
func unportableTail(name string) string {
	if name == "" || name == "." || name == ".." {
		return ""
	}
	switch name[len(name)-1] {
	case ' ':
		return "Windows drops a trailing space from a filename, so the page would vanish when the vault syncs"
	case '.':
		return "Windows drops a trailing dot from a filename, so the page would vanish when the vault syncs"
	}
	return ""
}

// hasDriveLetter reports whether s begins with a Windows drive specification.
// filepath.IsAbs does not recognise "C:/x" on Linux, so a vault path with a
// drive letter would be created as a directory literally called "C:" — and a
// DM pasting a Windows path would silently get the wrong tree.
func hasDriveLetter(s string) bool {
	if len(s) < 2 {
		return false
	}
	c := s[0]
	return s[1] == ':' && (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'))
}

// resolveDeepest passes the deepest existing ancestor of abs through
// EvalSymlinks and returns where it really is.
//
// Walking up is what lets an unresolved leaf be checked at all: saving a page
// into a directory that does not exist yet is normal, and the nearest existing
// ancestor is the directory whose symlinks decide where the write lands.
func resolveDeepest(abs string) (string, error) {
	probe := abs
	for {
		_, err := os.Lstat(probe)
		if err == nil {
			return filepath.EvalSymlinks(probe)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", fs.ErrNotExist
		}
		probe = parent
	}
}

// within reports whether p is root or lives under it, lexically. The halves
// must already be symlink-resolved or the comparison is meaningless.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// outsideErr builds the single error shape every refusal uses. The input is
// quoted and clipped so a hostile string cannot flood a log, and the resolved
// path is absent on purpose: it is the vault's own layout and it says more to
// an attacker than the reason does.
func outsideErr(input, reason string) error {
	return fmt.Errorf("%w: %q rejected: %s", ErrOutsideVault, clipInput(input), reason)
}

// clipInput bounds an untrusted string before it reaches a message.
func clipInput(s string) string {
	const max = 96
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}
