//go:build windows

package vault

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// atomicReplace renames src onto dst.
//
// os.Rename is not an atomic replace on Windows: it fails outright when the
// destination exists, and a save that cannot overwrite its own file is not a
// save. MoveFileEx with MOVEFILE_REPLACE_EXISTING provides the replacement, and
// MOVEFILE_WRITE_THROUGH keeps the rename itself out of the write cache, so a
// power loss cannot leave the name pointing at the old bytes.
func atomicReplace(src, dst string) error {
	srcp, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return fmt.Errorf("encode source path: %w", err)
	}
	dstp, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return fmt.Errorf("encode destination path: %w", err)
	}
	return windows.MoveFileEx(srcp, dstp,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
