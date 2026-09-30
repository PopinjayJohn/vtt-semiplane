package vault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

func backupAt(t *testing.T, v *testutil.Vault, minute int) string {
	t.Helper()
	at := time.Date(2026, 9, 28, 10, minute, 0, 0, time.UTC)
	dir, err := Backup(t.Context(), v.Root, filepath.Join(v.Root, HiddenDir, "semiplane.db"), at)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	return dir
}

// TestBackupRestoreRoundTrip is the whole point: a backup the DM can trust, and
// a restore that puts the bytes back exactly.
func TestBackupRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	original := map[string]string{
		"Campaigns/Ash/Gundren.md":       "# Gundren\n\nA line with a trailing space \n",
		"Campaigns/Ash/NPCs/Sela.md":     "# Sela\n\n```secret id=abc123 visibility=dm\nbody\n```\n",
		"Campaigns/Ash/Handouts/Map.png": "\x89PNG\r\n\x1a\n binary \r\n",
	}
	for rel, content := range original {
		v.WriteFile(t, rel, content)
	}
	dbPath := filepath.Join(v.DBDir(t), "semiplane.db")
	if err := os.WriteFile(dbPath, []byte("SQLite format 3\x00fake"), 0o600); err != nil {
		t.Fatalf("seed db: %v", err)
	}

	dir := backupAt(t, v, 4)
	if filepath.Base(dir) != "20260928T100400Z" {
		t.Errorf("backup directory is %q, want a sortable UTC stamp", filepath.Base(dir))
	}

	// The vault is then wrecked in every way a DM's is.
	for rel := range original {
		v.Remove(t, rel)
	}
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# overwritten by hand\n")
	v.WriteFile(t, "Campaigns/Ash/Extra.md", "# a note that was never backed up\n")

	if err := Restore(t.Context(), v.Root, filepath.Base(dir), true); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for rel, want := range original {
		if got := v.MustReadFile(t, rel); got != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	// A restore is a restore, not a sync: it does not delete what the backup
	// never knew about.
	if !v.Exists("Campaigns/Ash/Extra.md") {
		t.Error("the restore deleted a file that was not in the manifest")
	}
}

// TestRestoreRefusesToOverwriteWithoutForce is the guard on the one command in
// this package that destroys work which exists nowhere else.
func TestRestoreRefusesToOverwriteWithoutForce(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# original\n")
	dir := backupAt(t, v, 5)

	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# two days of work the DM has not backed up\n")
	err := Restore(t.Context(), v.Root, filepath.Base(dir), false)
	if err == nil {
		t.Fatal("a restore overwrote an existing file without force")
	}
	if !strings.Contains(err.Error(), "Gundren.md") {
		t.Errorf("the refusal should name the file: %v", err)
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); !strings.Contains(got, "two days of work") {
		t.Errorf("the refused restore still wrote: %q", got)
	}

	// A file the backup has and the vault does not is a create, not an
	// overwrite, so it does not need force.
	v.Remove(t, "Campaigns/Ash/Gundren.md")
	if err := Restore(t.Context(), v.Root, filepath.Base(dir), false); err != nil {
		t.Errorf("restoring a missing file without force = %v", err)
	}
	if got := v.MustReadFile(t, "Campaigns/Ash/Gundren.md"); got != "# original\n" {
		t.Errorf("content = %q", got)
	}
}

// TestBackupIsPrivateAndSaysItHoldsSecrets is ADR-0004 applied to the copy: a
// backup directory is a vault in a folder, and the operator must be told.
func TestBackupIsPrivateAndSaysItHoldsSecrets(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	dir := backupAt(t, v, 6)

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("backup directory mode = %o, want 700", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	for _, e := range entries {
		info, infoErr := e.Info()
		if infoErr != nil {
			t.Fatalf("stat %s: %v", e.Name(), infoErr)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if perm := info.Mode().Perm(); perm != want {
			t.Errorf("%s mode = %o, want %o", e.Name(), perm, want)
		}
	}
	// The mirrored content is checked at one level of depth, because that is
	// where a mode of 0755 on a secret would matter most.
	content, err := os.ReadDir(filepath.Join(dir, FilesDir))
	if err != nil {
		t.Fatalf("read backup content: %v", err)
	}
	for _, e := range content {
		info, infoErr := e.Info()
		if infoErr != nil {
			t.Fatalf("stat %s: %v", e.Name(), infoErr)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if perm := info.Mode().Perm(); perm != want {
			t.Errorf("files/%s mode = %o, want %o", e.Name(), perm, want)
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, MetaName))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta BackupMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if !meta.ContainsSecrets {
		t.Error("the backup does not declare that it holds secrets")
	}
	if !strings.Contains(strings.ToLower(meta.Note), "plaintext") {
		t.Errorf("Note = %q, want the plaintext warning", meta.Note)
	}
	if meta.Files != 1 {
		t.Errorf("Files = %d, want 1", meta.Files)
	}
}

// TestBackupManifestHashesEveryFile is what makes a backup verifiable: a
// manifest of names could not tell a truncated copy from a complete one.
func TestBackupManifestHashesEveryFile(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Campaigns/Ash/Gundren.md", "# Gundren\n")
	v.WriteFile(t, "Campaigns/Ash/Sela.md", "# Sela\n")
	v.WriteFile(t, ".semiplane/semiplane.db", "not in the manifest")
	dir := backupAt(t, v, 7)

	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest BackupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(manifest) != 2 {
		t.Fatalf("manifest = %+v, want the two pages", manifest)
	}
	for _, entry := range manifest {
		if strings.Contains(entry.Path, HiddenDir) {
			t.Errorf("the manifest indexed the hidden directory: %s", entry.Path)
		}
		body, err := os.ReadFile(filepath.Join(dir, FilesDir, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatalf("the manifest names a file the backup does not hold: %s", entry.Path)
		}
		if got := HashHex(body); got != entry.SHA256 {
			t.Errorf("%s hash = %s, want %s", entry.Path, got, entry.SHA256)
		}
		if entry.Size != int64(len(body)) {
			t.Errorf("%s size = %d, want %d", entry.Path, entry.Size, len(body))
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.ModTime); err != nil {
			t.Errorf("%s mtime = %q: %v", entry.Path, entry.ModTime, err)
		}
	}
}

// TestBackupCopiesTheDatabaseAndItsSidecars is the honest answer to "how do you
// copy a live database without a *sql.DB": the caller pauses the writers, and
// the sidecars come along because a -wal without its database is meaningless.
func TestBackupCopiesTheDatabaseAndItsSidecars(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	dbPath := filepath.Join(v.DBDir(t), "semiplane.db")
	for suffix, body := range map[string]string{
		"":       "SQLite format 3\x00",
		"-wal":   "wal bytes",
		"-shm":   "shm bytes",
		"-other": "not a database file",
	} {
		if err := os.WriteFile(dbPath+suffix, []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", suffix, err)
		}
	}
	dir := backupAt(t, v, 8)

	for _, want := range []string{DBName, DBName + "-wal", DBName + "-shm"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("the backup is missing %s: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "semiplane.db.other")); err == nil {
		t.Error("the backup copied a file that is not a database sidecar")
	}
	raw, err := os.ReadFile(filepath.Join(dir, MetaName))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta BackupMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if !meta.DBInconsistent {
		t.Error("meta.json does not record that the database was copied at the file level")
	}
}

// TestBackupOfAVaultWithNoDatabaseIsNotAFailure: the first boot backs up before
// the index exists.
func TestBackupOfAVaultWithNoDatabaseIsNotAFailure(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	dir := backupAt(t, v, 9)
	if _, err := os.Stat(filepath.Join(dir, DBName)); err == nil {
		t.Error("a backup of a vault with no database contains one")
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestName)); err != nil {
		t.Errorf("the manifest is missing: %v", err)
	}
	if _, err := Backup(t.Context(), v.Root, "", time.Now()); err != nil {
		t.Errorf("a backup with no database path = %v", err)
	}
}

func TestBackupRetentionKeepsTheNewestTen(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	for i := range 12 {
		v.WriteFile(t, "Page.md", "# revision\n")
		backupAt(t, v, i)
	}
	names, err := Backups(v.Root)
	if err != nil {
		t.Fatalf("backups: %v", err)
	}
	if len(names) != MaxBackups {
		t.Fatalf("%d backups on disk, want %d: %v", len(names), MaxBackups, names)
	}
	// Newest first, and the two oldest are gone.
	if names[0] != "20260928T101100Z" {
		t.Errorf("names[0] = %q, want the newest", names[0])
	}
	for _, gone := range []string{"20260928T100000Z", "20260928T100100Z"} {
		if contains(names, gone) {
			t.Errorf("%s should have been pruned", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(v.Root, HiddenDir, "backups", "20260928T100000Z")); err == nil {
		t.Error("the oldest backup directory is still on disk")
	}
}

func TestBackupsInOneSecondDoNotOverwriteEachOther(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	at := time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)
	first, err := Backup(t.Context(), v.Root, "", at)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := Backup(t.Context(), v.Root, "", at)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first == second {
		t.Fatal("two backups in one second share a directory")
	}
	names, err := Backups(v.Root)
	if err != nil {
		t.Fatalf("backups: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("backups = %v, want both", names)
	}
}

func TestRestoreRefusesAPathOutsideTheBackups(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	backupAt(t, v, 10)

	for _, from := range []string{"../..", "../../etc", filepath.Join("..", "..", "..")} {
		err := Restore(t.Context(), v.Root, from, true)
		if err == nil {
			t.Errorf("Restore(%q) was accepted", from)
			continue
		}
		if !errors.Is(err, ErrOutsideVault) && !strings.Contains(err.Error(), "restore:") {
			t.Errorf("Restore(%q) = %v", from, err)
		}
	}
	if err := Restore(t.Context(), v.Root, "", true); err == nil {
		t.Error("Restore with no directory was accepted")
	}
	if err := Restore(t.Context(), v.Root, "no-such-backup", true); err == nil {
		t.Error("Restore of a missing backup was accepted")
	}
}

func TestRestoreVerifiesTheManifestHash(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	dir := backupAt(t, v, 11)
	v.Remove(t, "Page.md")

	// A damaged backup must be refused rather than restored as if it were
	// whole: the operator is about to believe their vault is back.
	if err := os.WriteFile(filepath.Join(dir, FilesDir, "Page.md"), []byte("# Tampered\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	err := Restore(t.Context(), v.Root, filepath.Base(dir), true)
	if err == nil {
		t.Fatal("a damaged backup was restored")
	}
	if !strings.Contains(err.Error(), "manifest hash") {
		t.Errorf("Restore = %v, want a hash complaint", err)
	}
	if v.Exists("Page.md") {
		t.Error("a refused restore wrote a file anyway")
	}
}

func TestBackupHonoursACancelledContext(t *testing.T) {
	t.Parallel()
	v := testutil.NewVault(t)
	v.WriteFile(t, "Page.md", "# Page\n")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Backup(ctx, v.Root, "", time.Now()); !errors.Is(err, context.Canceled) {
		t.Errorf("Backup with a cancelled context = %v", err)
	}
}
