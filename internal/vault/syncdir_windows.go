//go:build windows

package vault

// syncDir is a no-op on Windows.
//
// There is no directory handle to fsync: NTFS journals the metadata change
// against the file's own write-through flush, and MoveFileEx with
// MOVEFILE_WRITE_THROUGH has already forced it. The unix build fsyncs the
// directory because POSIX makes no such promise.
func syncDir(string) error { return nil }
