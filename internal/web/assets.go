package web

import (
	"io/fs"

	webassets "github.com/PopinjayJohn/vtt-semiplane/web"
)

// Assets returns the embedded asset filesystem, rooted so that "app.css" and
// "vendor/datastar.js" are the paths the embed sees.
//
// The embed itself lives in the package at the module root, because an embed
// pattern may not contain "..": this package used to keep a hand-synced copy of
// the tree beside its own code, and a duplicate of a generated 72 KiB file is a
// divergence waiting to be reported by somebody else. web/static/ is now the
// only copy in the repository, and this function is the path to it.
//
// The returned filesystem is read-only and is safe for concurrent use, so the
// server holds one for its whole life and never re-reads the embed.
func Assets() fs.FS {
	return webassets.FS()
}
