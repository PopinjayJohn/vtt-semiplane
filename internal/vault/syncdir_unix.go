//go:build !windows

package vault

import "os"

// syncDir flushes a directory entry, so a rename survives a power loss.
//
// The data is already durable — the file was fsynced before the rename — but
// without this the directory entry can still be lost, and the vault is then
// missing a page that a backup manifest claims exists.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
