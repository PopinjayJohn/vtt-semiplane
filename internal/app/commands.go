package app

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"

	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The one-shot commands.
//
// Each one boots without a handler, which is the whole reason the nil-handler
// seam exists: a command that exits in a second has no listener to open and no
// watch to stop, and it still has to take the lock, migrate and index — because
// the index is derived, a command that skipped the walk would report whatever
// the last run left behind and call it current.

// Reindex rebuilds the index from the vault's files and reports what it did.
//
// A plain reindex is a full pass: every file is compared against the index and
// the rows whose files are gone are dropped, so a vault that is already in
// agreement costs one walk and writes nothing. full additionally drops every
// derived row first and rebuilds the FTS tables, so nothing the index believed
// is trusted: that is the answer to an index that is wrong in a way a file hash
// cannot reveal.
//
// It is safe to interrupt. Every write is a transaction over one file, the
// files are the source of truth, and the next run re-reads all of them.
func Reindex(ctx context.Context, opts Options, out io.Writer, full bool) error {
	// The full rebuild belongs to the boot's own pass, so that `--reindex` on
	// the serve path is the same work rather than a second implementation of it.
	opts.Reindex = opts.Reindex || full
	a, err := Boot(ctx, opts)
	if err != nil {
		return err
	}
	defer shutdown(a)

	res := a.lastResult()
	if !opts.Reindex {
		// The boot took the ordinary walk; the command takes its own pass over
		// the top of it and reports that one.
		res, err = a.reindexPass(ctx, full)
		if err != nil {
			return fmt.Errorf("reindex: %w", err)
		}
	}
	a.refreshStatus(ctx)
	a.setIndexedAt()
	st := a.Status()
	_, _ = fmt.Fprintf(out, "reindexed %d pages from %d files (%d indexed, %d already current)\n",
		st.PageCount, a.IndexFileCount(), len(res.Indexed), res.Unchanged)
	printReport(out, st, a.PluginReport())
	return nil
}

// Backup writes a backup of the vault and its index, and reports where it is.
//
// to is the --out directory: the backup is written to the canonical location
// under the vault's private directory, where vault.Backup keeps it private and
// applies its retention, and is then copied under to so the operator can take it
// off the machine.
//
// It is a copy and not a move. vault.Restore only accepts a backup that is still
// in the vault's own backups directory, so moving it away would take the vault's
// own restore point with it and answer the request by removing the thing the
// request was about. The cost is a second copy of every DM secret, which is why
// the command says so.
func Backup(ctx context.Context, opts Options, out io.Writer, to string) error {
	a, err := Boot(ctx, opts)
	if err != nil {
		return err
	}
	defer shutdown(a)

	dir, err := a.takeBackup(ctx)
	if err != nil {
		return err
	}
	if err := a.stampBackup(ctx, a.backupAt); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "backup written to %s\n", dir)
	if to != "" {
		placed, err := copyBackupTo(ctx, dir, to)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "copied to %s\n", placed)
	}
	_, _ = fmt.Fprintln(out, "this backup contains every DM secret in plaintext; treat it as you treat the vault")
	return nil
}

// copyBackupTo copies a written backup under the operator's directory, keeping
// the original where vault.Restore can still reach it.
func copyBackupTo(ctx context.Context, dir, to string) (string, error) {
	if err := os.MkdirAll(to, 0o700); err != nil {
		return "", fmt.Errorf("create the --out directory: %w", err)
	}
	// 0700 because the directory is about to hold every secret in the vault.
	if err := os.Chmod(to, 0o700); err != nil {
		return "", fmt.Errorf("secure the --out directory: %w", err)
	}
	dst := filepath.Join(to, filepath.Base(dir))
	if err := copyTree(ctx, dir, dst); err != nil {
		return "", fmt.Errorf("copy the backup to %s: %w", to, err)
	}
	return dst, nil
}

// copyTree copies a directory tree, refusing anything that is not a regular file
// and every path that leaves dst.
//
// It is here rather than in vault because the --out copy is the composition
// root's business: the backup package owns one canonical location and this is a
// second one the operator asked for. The modes are the backup's own, because a
// copy that is not private is not a copy of a backup.
//
// The refusal is readRegularFile's rather than the walk entry's. rel cannot leave
// dst — WalkDir descends no symlink, so every element of it is a name this walk
// read — but the entry is a snapshot and the read is not, and readRegularFile is
// where that difference is closed.
func copyTree(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := readRegularFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
}

// readRegularFile returns the bytes of path, and refuses anything that is not a
// regular file.
//
// The refusal is decided twice, and the second one is the point. The first is an
// Lstat, which is what refuses a symlink, a directory and a fifo without opening
// any of them — a fifo opened for reading blocks until a writer arrives, so a
// check that arrived after the open would itself be the hang. The second
// compares that Lstat against the handle the open returned, and it is what makes
// the check and the use agree.
//
// A DirEntry cannot do that job. It describes the entry as it was when the walk
// read the directory, and the walk reads the directory before it reaches this
// callback, so `d.Type().IsRegular()` followed by a read of the same name is a
// check whose answer the use can contradict: whatever replaces the entry in
// between is read through, and a symlink is the cheap version of that. Requiring
// the name and the open handle to be the same object closes the window, and the
// bytes are read only after it has been checked.
func readRegularFile(path string) ([]byte, error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(named, opened) {
		return nil, fmt.Errorf("%s changed while it was being read", filepath.Base(path))
	}
	return io.ReadAll(f)
}

// Restore copies a backup back over the vault's files and reindexes.
//
// The reindex is not decoration: the files changed under the index, so an index
// that was not rebuilt would describe the vault as it was before the restore.
// The database is deliberately not restored — vault.Restore restores the
// Markdown, which is canonical, and the index is rebuilt from it in front of the
// operator rather than carried over from the backup.
func Restore(ctx context.Context, opts Options, out io.Writer, from string, force bool) error {
	a, err := Boot(ctx, opts)
	if err != nil {
		return err
	}
	defer shutdown(a)

	if err := vault.Restore(ctx, a.root, from, force); err != nil {
		return err
	}
	if err := a.fullIndex(ctx, false); err != nil {
		return fmt.Errorf("reindex after the restore: %w", err)
	}
	st := a.Status()
	_, _ = fmt.Fprintf(out, "restored from %s and reindexed %d pages from %d files\n",
		from, st.PageCount, a.IndexFileCount())
	printReport(out, st, a.PluginReport())
	return nil
}

// VaultInfo prints the facts about a vault: where it is, what is in the index,
// how big the database is, and what the walk refused.
//
// It prints counts and paths. A page title would be vault content and a secret
// id is a handle to a body the caller has not asked to see; neither belongs in a
// line an operator pastes into a bug report.
func VaultInfo(ctx context.Context, opts Options, out io.Writer) error {
	a, err := Boot(ctx, opts)
	if err != nil {
		return err
	}
	defer shutdown(a)

	st := a.Status()
	backups, err := vault.Backups(a.root)
	if err != nil {
		return fmt.Errorf("list the backups: %w", err)
	}
	_, _ = fmt.Fprintf(out, "%s\n", Info().String())
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	printAddress(tw, st)
	_, _ = fmt.Fprintf(tw, "files:\t%d indexed\n", a.IndexFileCount())
	if size, err := fileSize(a.db.Path()); err == nil {
		_, _ = fmt.Fprintf(tw, "database:\t%s (%s)\n", a.db.Path(), size)
	} else {
		_, _ = fmt.Fprintf(tw, "database:\t%s\n", a.db.Path())
	}
	if len(backups) == 0 {
		_, _ = fmt.Fprintln(tw, "backups:\tnone")
	} else {
		_, _ = fmt.Fprintf(tw, "backups:\t%d, newest %s\n", len(backups), backups[0])
	}
	printReport(tw, st, a.PluginReport())
	return tw.Flush()
}

// shutdown releases a booted app, reporting a failure to log rather than to a
// caller that is already on its way out. The lock is released on every path.
func shutdown(a *App) {
	ctx, cancel := boundedContext()
	defer cancel()
	if err := a.Shutdown(ctx); err != nil && a.log != nil {
		a.log.Error("shutdown did not complete cleanly", "action", "boot.shutdown", "err", err.Error())
	}
}

// fileSize renders a byte count for a human reading a console.
func fileSize(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(info.Size(), 10) + " bytes", nil
}
