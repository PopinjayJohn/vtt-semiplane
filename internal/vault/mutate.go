package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// DeleteRequest is one deletion.
//
// BaseContentHash is the hash of the bytes the requester was looking at, and it
// is required rather than optional: without it "delete this page" and "delete
// the page I was reading" are the same request, and the second one is the only
// one a DM can undo.
type DeleteRequest struct {
	// Path is the vault-relative page path, as it arrived from the router.
	Path string
	// BaseContentHash is Hash of the bytes the requester was based on.
	BaseContentHash []byte
	// ActorID is the user who deleted, for the audit record.
	ActorID int64
	// ExpectPerm is the permission the route was mounted with. The delete path
	// refuses anything that is not a write permission.
	ExpectPerm authz.Permission
}

// Delete removes a page file.
//
// The order is Save's order, and it is the same order for the same reason: take
// the path's lock, re-read, compare, then mutate. A hash check taken outside the
// lock is a check of a value that may already be stale, which is the race the
// save path exists to close.
//
// A missing file is an error, not a silent success. Idempotence would mean a
// caller could not tell "I removed it" from "it was never there" from "I just
// removed someone else's copy", and the second of those is a deletion this
// requester was not entitled to perform. ErrNotFound says which one it was.
//
// No self-write is registered. The mechanism has no vocabulary for a removal —
// the watcher stats the file to compare hashes and cannot stat one that is gone —
// and a registration keyed by a path whose bytes no longer exist would suppress
// a later, unrelated file written to the same name.
func (w *Writer) Delete(ctx context.Context, req DeleteRequest) error {
	if !isWritePerm(req.ExpectPerm) {
		return fmt.Errorf("%w: %q may not delete", ErrNotPermitted, req.ExpectPerm)
	}
	p, err := Resolve(w.Root, req.Path)
	if err != nil {
		return err
	}

	unlock := w.lockPath(p.Rel())
	defer unlock()

	current, err := Read(ctx, p)
	switch {
	case errors.Is(err, ErrNotFound):
		return fmt.Errorf("%w: %s", ErrNotFound, p.Rel())
	case err != nil:
		return err
	}

	// Ours is empty: there is no second version of a deleted page, and putting
	// the file's own bytes in both fields of the error would render a page in a
	// message.
	if !bytes.Equal(Hash(current), req.BaseContentHash) {
		return Conflict(p.Rel(), current, nil)
	}

	if err := os.Remove(p.Abs()); err != nil {
		return fmt.Errorf("delete %s: %w", p.Rel(), err)
	}
	// The unlink is not durable until the directory entry that named it is on
	// disk. Without this a power loss can restore the page after the app has
	// already told the DM it is gone, and the file is the authority.
	if err := syncDir(filepath.Dir(p.Abs())); err != nil {
		return fmt.Errorf("sync directory of %s: %w", p.Rel(), err)
	}

	w.logger().InfoContext(ctx, "vault file deleted",
		"action", "page.delete", "path", p.Rel(), "actor_id", req.ActorID,
		"bytes", len(current), "expect_perm", string(req.ExpectPerm))
	return nil
}
