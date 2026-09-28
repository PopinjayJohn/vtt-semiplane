package md

import (
	"path"
	"strings"
)

// Basename returns a vault-relative path's file name with the extension
// removed: `Party/Night at the Tavern.md` is `Night at the Tavern`. A page
// whose title falls back to its basename wants the name a user would type,
// not the name on disk.
func Basename(p string) string {
	p = normalizePath(p)
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(path.Base(p), path.Ext(p))
}

// Dir returns a vault-relative path's directory, with forward slashes and no
// trailing separator, or "" for a page at the vault root.
func Dir(p string) string {
	p = normalizePath(p)
	if p == "" {
		return ""
	}
	return path.Dir(p)
}
