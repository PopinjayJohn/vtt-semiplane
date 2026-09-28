//go:build !windows

package vault

import "os"

// atomicReplace renames src onto dst.
//
// On unix this is rename(2), which replaces the destination atomically: a
// concurrent reader sees either the whole old file or the whole new one. The
// Windows build needs MoveFileEx and lives in replace_windows.go.
func atomicReplace(src, dst string) error {
	return os.Rename(src, dst)
}
