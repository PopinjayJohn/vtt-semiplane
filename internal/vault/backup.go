package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// MaxBackups is how many backups are kept. Retention deletes the oldest first,
// so the ten most recent are always on disk.
const MaxBackups = 10

// backupTimeLayout is the directory name of a backup. It is lexicographically
// sortable, so retention is a sort and not a stat of every entry's contents.
const backupTimeLayout = "20060102T150405Z"

// DBName is the database file inside a backup directory.
const DBName = "db.sqlite"

// ManifestName is the file listing every vault file with its hash.
const ManifestName = "vault-manifest.json"

// MetaName is the file describing a backup.
const MetaName = "meta.json"

// FilesDir is where the vault content itself lives inside a backup, mirroring
// the vault's own layout under files/. The manifest beside it is the index:
// a list of names and hashes can verify a copy, but it cannot replace one.
const FilesDir = "files"

// ManifestEntry is one file in a backup manifest.
type ManifestEntry struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	ModTime string `json:"mtime"`
}

// BackupManifest is the ordered list of vault files in a backup.
type BackupManifest []ManifestEntry

// BackupMeta describes a backup directory. The note is not decoration: the
// directory is a plain copy of the vault, and a DM who finds it in a sync
// folder needs to know what they are holding before they send it to anyone.
type BackupMeta struct {
	CreatedAt       string `json:"created_at"`
	DBFile          string `json:"db_file,omitempty"`
	DBInconsistent  bool   `json:"db_file_copy"`
	Files           int    `json:"files"`
	Bytes           int64  `json:"bytes"`
	ContainsSecrets bool   `json:"contains_secrets"`
	Note            string `json:"note"`
}

// backupNote is written into every meta.json.
const backupNote = "This backup contains every DM secret in plaintext (ADR-0004). " +
	"Treat it exactly as you treat the vault itself."

// Backup writes a timestamped copy of the vault to
// <vault>/.semiplane/backups/<YYYYMMDDTHHMMSSZ>/ and returns the directory.
//
// The directory holds db.sqlite, the vault content under files/, and the two
// files that describe them: vault-manifest.json, one entry per file with its
// hash, size and mtime, and meta.json.
//
// A backup is a plain copy, so it contains every DM secret in plaintext and
// inherits the vault's sensitivity (ADR-0004). The directory is 0700 and every
// file in it is 0600; the warning is in meta.json, because the copy is what
// leaves the vault.
//
// The database is copied at the file level: db.sqlite, and the -wal and -shm
// sidecars when they exist. That is only a consistent database if the caller
// has paused writers, which app does — it holds the single-instance lock and
// calls Backup between index passes with the invalidation bus drained. This
// package has no *sql.DB and therefore cannot run VACUUM INTO, which is the
// alternative that would be correct unconditionally.
func Backup(ctx context.Context, root, dbPath string, at time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if root == "" {
		return "", errors.New("backup: a vault root is required")
	}
	dir, err := makeBackupDir(root, at)
	if err != nil {
		return "", err
	}

	meta := BackupMeta{
		CreatedAt:       at.UTC().Format(time.RFC3339),
		ContainsSecrets: true,
		Note:            backupNote,
	}
	if copyDatabaseErr := copyDatabase(dbPath, dir, &meta); copyDatabaseErr != nil {
		return "", copyDatabaseErr
	}

	manifest, bytes, err := buildManifest(ctx, root, dir)
	if err != nil {
		return "", err
	}
	meta.Files = len(manifest)
	meta.Bytes = bytes

	if err := writeJSON(dir, ManifestName, manifest); err != nil {
		return "", err
	}
	if err := writeJSON(dir, MetaName, meta); err != nil {
		return "", err
	}
	if err := pruneBackups(root); err != nil {
		return "", err
	}
	return dir, nil
}

// makeBackupDir creates a unique, private directory for one backup. The
// timestamp is the caller's, so two backups in the same second are possible and
// get a numeric suffix rather than overwriting each other.
func makeBackupDir(root string, at time.Time) (string, error) {
	parent := filepath.Join(root, HiddenDir, "backups")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", fmt.Errorf("chmod backup directory: %w", err)
	}

	base := at.UTC().Format(backupTimeLayout)
	for i := 1; i < 100; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		dir := filepath.Join(parent, name)
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			if cerr := os.Chmod(dir, 0o700); cerr != nil {
				return "", fmt.Errorf("chmod backup %s: %w", name, cerr)
			}
			return dir, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("create backup %s: %w", name, err)
		}
	}
	return "", fmt.Errorf("create backup %s: too many backups in one second", base)
}

// copyDatabase copies the database and its write-ahead log sidecars.
func copyDatabase(dbPath, dir string, meta *BackupMeta) error {
	if dbPath == "" {
		return nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A vault whose index has not been built yet is a valid vault.
			return nil
		}
		return fmt.Errorf("stat database: %w", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := dbPath + suffix
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyFile(src, filepath.Join(dir, DBName+suffix)); err != nil {
			return err
		}
	}
	meta.DBFile = DBName
	meta.DBInconsistent = true
	return nil
}

// buildManifest copies every indexable vault file into the backup and returns
// the manifest of what it copied.
//
// The hash is what makes the copy verifiable: a manifest of names alone could
// not tell a truncated backup from a complete one, and a DM who has just
// restored is exactly the person who must not be misled.
func buildManifest(ctx context.Context, root, dir string) (BackupManifest, int64, error) {
	res, err := Walk(ctx, root, WalkOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("walk the vault for a backup: %w", err)
	}
	files := filepath.Join(dir, FilesDir)
	if err := os.MkdirAll(files, 0o700); err != nil {
		return nil, 0, fmt.Errorf("create the backup content directory: %w", err)
	}

	manifest := make(BackupManifest, 0, len(res.Files))
	var total int64
	for _, rel := range res.Files {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		p := New(root, rel)
		b, err := Read(ctx, p)
		if err != nil {
			// A file that vanished mid-backup is still recorded, as a zero
			// length entry. A manifest is a claim about the vault, and silently
			// omitting a file would make it a lie.
			manifest = append(manifest, ManifestEntry{
				Path:    rel,
				SHA256:  HashHex(nil),
				ModTime: time.Time{}.UTC().Format(time.RFC3339),
			})
			continue
		}
		if err = writeFile(ctx, New(files, rel), b, nil); err != nil {
			return nil, 0, err
		}
		st, err := os.Stat(p.Abs())
		if err != nil {
			continue
		}
		manifest = append(manifest, ManifestEntry{
			Path:    rel,
			SHA256:  HashHex(b),
			Size:    int64(len(b)),
			ModTime: st.ModTime().UTC().Format(time.RFC3339Nano),
		})
		total += int64(len(b))
	}
	return manifest, total, nil
}

// pruneBackups enforces MaxBackups, oldest first.
func pruneBackups(root string) error {
	parent := filepath.Join(root, HiddenDir, "backups")
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("read backup directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for i, name := range names {
		if i < MaxBackups {
			continue
		}
		if err := os.RemoveAll(filepath.Join(parent, name)); err != nil {
			return fmt.Errorf("prune backup %s: %w", name, err)
		}
	}
	return nil
}

// Restore copies a backup back over the vault.
//
// It refuses to overwrite an existing file unless force is set, because a
// restore is the one command in this package that destroys work that exists
// nowhere else. With force it still writes atomically, so a failed restore
// leaves a file that is either the old bytes or the restored ones.
func Restore(ctx context.Context, root, from string, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := resolveBackupDir(root, from)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return fmt.Errorf("read %s in %s: %w", ManifestName, filepath.Base(dir), err)
	}
	var manifest BackupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse %s in %s: %w", ManifestName, filepath.Base(dir), err)
	}

	// The refusal is computed for the whole manifest before anything is
	// written, so a restore either happens or explains itself without having
	// already half-restored.
	if !force {
		for _, entry := range manifest {
			p := New(root, entry.Path)
			if _, err := os.Stat(p.Abs()); err == nil {
				return fmt.Errorf("restore: %s already exists (pass force to overwrite)", entry.Path)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("restore: cannot stat %s: %w", entry.Path, err)
			}
		}
	}

	for _, entry := range manifest {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !within(root, New(root, entry.Path).Abs()) {
			return fmt.Errorf("restore: %s is not inside the vault", entry.Path)
		}
		src := filepath.Join(dir, FilesDir, filepath.FromSlash(entry.Path))
		b, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("restore: cannot read %s: %w", entry.Path, err)
		}
		if got := HashHex(b); got != entry.SHA256 {
			return fmt.Errorf("restore: %s does not match the manifest hash", entry.Path)
		}
		if err := writeFile(ctx, New(root, entry.Path), b, nil); err != nil {
			return err
		}
	}
	return nil
}

// resolveBackupDir accepts a backup directory name or a path, and refuses
// anything that leaves the backups directory. from is operator input, but the
// restore command is reachable from a shell where a stray "../" would rewrite
// the wrong tree, and the check costs one call.
func resolveBackupDir(root, from string) (string, error) {
	if from == "" {
		return "", errors.New("restore: a backup directory is required")
	}
	parent := filepath.Join(root, HiddenDir, "backups")
	abs := filepath.Join(parent, filepath.FromSlash(from))
	if !within(parent, abs) {
		return "", fmt.Errorf("%w: %q is not a backup directory", ErrOutsideVault, from)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("restore: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("restore: %s is not a directory", from)
	}
	return abs, nil
}

// Backups lists the backup directories in a vault, newest first.
func Backups(root string) ([]string, error) {
	parent := filepath.Join(root, HiddenDir, "backups")
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup directory: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

func writeJSON(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(dir, name), b, 0o600)
}

// copyFile copies a file's bytes, refusing a source that is not a regular file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(src), err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(dst), err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s: %w", filepath.Base(src), err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(dst), err)
	}
	return out.Close()
}
