// Package web embeds the static assets the binary serves.
//
// It lives at the module root rather than under internal/ for a toolchain
// reason, not an architectural one: an embed pattern may not contain ".." and
// may not follow a symbolic link, so the committed asset tree is only
// embeddable by a package that lives inside it. Everything else about it is
// deliberate — the package holds an embed and an accessor, no logic, and no
// dependency on anything of ours.
//
// The assets are embedded rather than read from disk because a semiplane binary
// is one file that runs from a USB stick, and because §2.5 is then a structural
// property rather than a promise: with no code path from an asset request to a
// filesystem or a network, a page cannot fetch a script or a stylesheet from
// anywhere but this binary.
package web

import (
	"embed"
	"io/fs"
)

// static is the committed asset tree, embedded at build time.
//
// The whole directory is embedded rather than the four files by name, so a new
// asset is in the binary the moment it is committed and reachability stays the
// one question the content-type allow-list in httpapi answers.
//
//go:embed static
var static embed.FS

// FS returns the embedded asset tree, rooted at the static directory, so that
// "app.css" and "vendor/datastar.js" are the paths a caller asks for.
//
// It returns fs.FS rather than embed.FS on purpose: reading a file is all the
// asset route needs, and the concrete type would only invite a caller to reach
// past the interface for ReadDir.
//
// The tree is read-only and safe for concurrent use, so a server holds one for
// its whole life and never re-reads the embed.
func FS() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		// Unreachable: the pattern above is a constant and the directory is in
		// the binary. A page with no stylesheet and no explanation is worse than
		// a build failure, so this is a panic rather than an empty tree.
		panic("web: the embedded asset tree is missing: " + err.Error())
	}
	return sub
}
