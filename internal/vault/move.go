package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// MoveRequest is one app-initiated rename.
type MoveRequest struct {
	// From is the vault-relative path the page is at now.
	From string
	// To is the vault-relative path it should answer to. A parent directory that
	// does not exist yet is created, exactly as a save into a new directory is.
	To string
	// BaseContentHash is Hash of the bytes the requester was based on.
	BaseContentHash []byte
	// ActorID is the user who renamed, for the audit record.
	ActorID int64
	// ExpectPerm is the permission the route was mounted with. The move path
	// refuses anything that is not a write permission.
	ExpectPerm authz.Permission
}

// Move renames a page file inside the vault.
//
// It is a save of the same discipline with two paths instead of one: both are
// resolved and refused before anything is touched, both locks are taken before
// either file is read, and the bytes are compared under those locks so a rename
// cannot be based on a version the requester never saw.
//
// The alias that keeps [[the old name]] resolving is not written here, and
// neither half of the move is registered as a self-write. The indexer derives
// the alias from a vanished page and an appeared one holding the same content
// inside its rename window, and it can only do that if the watcher is allowed to
// report both paths: suppressing the destination would leave the indexer to
// delete the page and never to learn the name it now answers to, and the
// reconciliation scan is a minute away rather than immediate.
//
// Both stripes, ascending, before either file is read. Two moves that touch the
// same two paths therefore queue behind each other instead of holding one stripe
// each and waiting for the other, and Save's single stripe is a degenerate case
// of the same order.
func (w *Writer) Move(ctx context.Context, req MoveRequest) error {
	if !isWritePerm(req.ExpectPerm) {
		return fmt.Errorf("%w: %q may not rename", ErrNotPermitted, req.ExpectPerm)
	}
	from, err := Resolve(w.Root, req.From)
	if err != nil {
		return err
	}
	to, err := Resolve(w.Root, req.To)
	if err != nil {
		return err
	}
	// Resolve establishes containment for both ends, but it resolves a path that
	// does not exist against its deepest existing ancestor — so a directory is a
	// perfectly valid result for either end, and a destination that resolved to
	// one would be created by the MkdirAll below and then renamed onto.
	if parentRel := to.Dir(); parentRel != "." && parentRel == to.Rel() {
		return fmt.Errorf("%w: %q rejected: it names the vault root, which is not a page's parent", ErrOutsideVault, clipInput(req.To))
	}
	// The spellings differ; the paths they resolve to do not. Comparing the
	// resolved paths is what makes "/Page.md" and "Page.md" a refusal rather
	// than a rename that unlinks its own source.
	if from.Rel() == to.Rel() {
		return fmt.Errorf("rename %s: the source and the destination are the same file", from.Rel())
	}

	// Taken before either file is read, not between the read and the rename: the
	// hash check and the rename have to be one indivisible step.
	unlock := w.lockStripes(from, to)
	defer unlock()

	content, err := Read(ctx, from)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(to.Abs()); err == nil {
		return fmt.Errorf("rename %s: the destination %s already exists", from.Rel(), to.Rel())
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", to.Rel(), err)
	}

	if !bytes.Equal(Hash(content), req.BaseContentHash) {
		return Conflict(from.Rel(), content, nil)
	}

	if err := os.MkdirAll(filepath.Dir(to.Abs()), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", to.Dir(), err)
	}
	if err := os.Rename(from.Abs(), to.Abs()); err != nil {
		return fmt.Errorf("rename %s to %s: %w", from.Rel(), to.Rel(), err)
	}

	// Two directory entries changed and either fsync alone is not enough: the
	// name that was added is not durable until the destination's directory says
	// so, and the name that was removed is not durable until the source's does.
	// A crash between the two leaves a file that exists under both names, which
	// the indexer reads as two pages, not as the rename it was.
	if err := syncDir(filepath.Dir(to.Abs())); err != nil {
		return fmt.Errorf("sync directory of %s: %w", to.Rel(), err)
	}
	if err := syncDir(filepath.Dir(from.Abs())); err != nil {
		return fmt.Errorf("sync directory of %s: %w", from.Rel(), err)
	}

	w.logger().InfoContext(ctx, "vault file renamed",
		"action", "page.rename", "path", to.Rel(), "from", from.Rel(),
		"actor_id", req.ActorID, "bytes", len(content), "expect_perm", string(req.ExpectPerm))
	return nil
}
