package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sample"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// bootNow is the instant every fixture's clock reports, so an assertion on a
// stored timestamp is a literal rather than a formatted now.
var bootNow = time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)

// leakToken appears in a seeded secret body and nowhere else, so "this token is
// not in there" is a claim rather than a tautology.
const leakToken = "zephyrite"

// secretPage is a page with a public half and a hidden half.
func secretPage(id, visibility string) string {
	return "# The Safe\n\nPublic before the fence, with a #public tag.\n\n" +
		"```secret id=" + id + " visibility=" + visibility +
		" author=mara created=2026-09-28T10:04:11Z title=\"The Vault Door\"\n" +
		"## Hidden chapter\n\nThe " + leakToken + " is kept in the vault.\n```\n\n" +
		"## Public chapter\n\nAfter the fence.\n"
}

// files is a small campaign: two ordinary pages and one page with a secret in
// each of the three visibilities, authored by an account the fixture seeds.
func campaignFiles() map[string]string {
	return map[string]string{
		"Campaign.md":         "# Campaign\n\nThe road north is watched.\n",
		"Campaigns/Ash.md":    "# Ash\n\nA courier with a letter for [[Gundren]].\n",
		"Campaigns/Safe.md":   secretPage("abcdef012345", "private"),
		"Campaigns/Table.md":  secretPage("abcdef012346", "table"),
		"Campaigns/DMOnly.md": secretPage("abcdef012347", "dm"),
	}
}

// fixture is one booted app over a temp vault.
type fixture struct {
	t      *testing.T
	vault  *testutil.Vault
	files  map[string]string
	opts   Options
	steps  []string
	banner *strings.Builder
	// app is the last app this fixture booted, so a test that boots twice —
	// which is how every test that rolls the schema back works — releases the
	// first one instead of being refused by its own lock.
	app *App
}

// samplePages is how many page rows the bundled campaign adds to every fixture
// vault.
//
// Boot writes the campaign into every vault it opens, so a test that counts
// pages is counting its own files plus these. Naming the count in one place is
// what keeps that honest: a bare literal at each call site would be a number
// that a campaign edit invalidates in eight directions at once, and the failure
// would read as "the vault was not indexed" rather than "the campaign grew".
func samplePages() int {
	files, err := sample.Files()
	if err != nil {
		// The campaign is in the binary and the enumeration is a walk of it, so
		// this is a build defect rather than a runtime condition.
		panic("the bundled sample campaign cannot be read: " + err.Error())
	}
	return len(files)
}

// pages is how many rows the index holds for this fixture: the files the test
// seeded, plus the campaign every boot writes.
func (f *fixture) pages() int { return len(f.files) + samplePages() }

// newFixture seeds a vault and builds Options for it, with a fixed clock, a
// discarding logger, and a trace that records the boot order.
func newFixture(t *testing.T, files map[string]string) *fixture {
	t.Helper()
	v := testutil.WithVault(t, files)
	f := &fixture{t: t, vault: v, files: files, banner: &strings.Builder{}}
	f.opts = Options{
		Config: config.Config{
			Vault:             v.Root,
			VaultSource:       "flag:--vault",
			Host:              "127.0.0.1",
			Port:              0,
			LogLevel:          "error",
			MaxAttachmentSize: 32 << 20,
		},
		Logger: obs.Discard(),
		Clock:  obs.FixedClock(bootNow),
		Banner: f.banner,
	}
	f.opts.trace = func(step string) { f.steps = append(f.steps, step) }
	return f
}

// options is the fixture's options with the handler set, for the tests that
// boot a listener.
func (f *fixture) withHandler() Options {
	opts := f.opts
	opts.Handler = http.NotFoundHandler()
	return opts
}

// boot boots the fixture and fails the test if the boot did not succeed. A
// previous app over the same vault is released first.
func (f *fixture) boot(t *testing.T, opts Options) *App {
	t.Helper()
	if f.app != nil {
		if err := shutdownAnd(f.app); err != nil {
			t.Fatalf("release the previous instance: %v", err)
		}
	}
	a, err := Boot(context.Background(), opts)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	f.app = a
	t.Cleanup(func() { _ = a.Shutdown(context.Background()) })
	return a
}

// dbFile is where the vault's index lives.
func (f *fixture) dbFile() string {
	return filepath.Join(f.vault.Root, store.StateDirName, store.DBName)
}

// TestBootTakesTheOrderItClaims is the test this package exists for.
//
// A reordered boot is a security bug rather than a style question: two
// processes over one vault interleave their watchers, and one process's
// self-write suppression swallows the other's real edit. So the order is
// asserted, twice over — once as the sequence of steps, and once by asking, at
// the moment each step completed, whether the database file existed yet.
func TestBootTakesTheOrderItClaims(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.withHandler())

	want := []string{
		stepVault, stepLock, stepSample, stepAudit, stepOpen, stepWire,
		stepBackup, stepSchema, stepFTS, stepIndex, stepPrune,
		// The plugin lifecycle sits between the index and the watcher, and the
		// position is the claim being made: a page type a plugin registered has
		// to exist before the first request rather than appearing on the second,
		// and a plugin migration has to land in the same boot as the index rows
		// that may reference it.
		stepPlugins,
		stepWatch, stepBind, stepBanner, stepServe,
	}
	if got := f.steps; !equalStrings(got, want) {
		t.Fatalf("the boot ran in this order:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	// The lock is claimed before anything in the vault is opened, and the
	// database is the thing that matters: at the moment the lock completed, the
	// index file did not exist yet, and by the time the open completed it did.
	//
	// A second, virgin vault is the only place that is observable, because a
	// vault that has been booted once already has an index file on disk.
	virgin := newFixture(t, map[string]string{"Campaign.md": "# Other\n"})
	var sawDBAtLock, sawDBAtOpen bool
	virgin.opts.trace = func(step string) {
		_, err := os.Stat(virgin.dbFile())
		switch step {
		case stepLock:
			sawDBAtLock = err == nil
		case stepOpen:
			sawDBAtOpen = err == nil
		}
	}
	if _, err := Boot(context.Background(), virgin.opts); err != nil {
		t.Fatalf("boot the observing instance: %v", err)
	}
	if sawDBAtLock {
		t.Error("the index database existed before the lock was claimed")
	}
	if !sawDBAtOpen {
		t.Error("the index database did not exist after the open step")
	}

	// A backup is taken by the hook store.Migrate calls, so it is recorded
	// before the migration step that required it.
	if indexOf(f.steps, stepBackup) > indexOf(f.steps, stepSchema) {
		t.Error("the backup was taken after the migration")
	}
	if last := f.steps[len(f.steps)-1]; last != stepServe {
		t.Errorf("the last boot step was %q, want the listener", last)
	}
	if a.Status().Addr == "" {
		t.Error("a handler was injected and nothing is listening")
	}
}

// TestSecondInstanceIsRefused covers the single-instance claim, and the pid in
// the refusal: "already open" with no pid sends the operator hunting for the
// process instead of telling them which one to stop.
func TestSecondInstanceIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.opts)

	_, err := Boot(context.Background(), f.opts)
	switch {
	case err == nil:
		t.Fatal("a second instance opened a vault that is already open")
	case !errors.Is(err, vault.ErrAlreadyLocked):
		t.Fatalf("the refusal is not vault.ErrAlreadyLocked: %v", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("the refusal does not name the holder's pid: %v", err)
	}
	if !strings.Contains(err.Error(), "--vault") {
		t.Errorf("the refusal does not say what to do about it: %v", err)
	}
}

// TestBootFailureReleasesTheLock covers the exit path: a process that gives up
// half way through its boot must not leave a vault that a second instance
// cannot open.
func TestBootFailureReleasesTheLock(t *testing.T) {
	t.Parallel()
	// The fixture needs two paths that differ only in case, and that is a
	// property of the filesystem rather than of this repository. macOS and
	// Windows default to a case-insensitive volume, where `NPCs/Gundren.md` and
	// `npcs/gundren.md` are one file: the collision cannot be created, boot
	// succeeds, and the assertion below fails having tested nothing.
	//
	// So it is probed rather than assumed, and the skip says what it found. An
	// assumed skip would be wrong on a case-insensitive Linux volume and would
	// hide a regression there; a silent one would be the failure mode AGENTS.md
	// §11 calls a gate that skips for a reason nobody reads.
	if !caseSensitiveFilesystem(t) {
		t.Skip("this volume is case-insensitive, so the two colliding paths would be one file; " +
			"run on a case-sensitive volume to cover the boot-failure path")
	}
	f := newFixture(t, map[string]string{
		"NPCs/Gundren.md": "# Gundren\n",
		"npcs/gundren.md": "# Gundren again\n",
	})
	// The collision is a hard error by default, and it is detected after the
	// lock is taken, which is exactly the window this test is about.
	if _, err := Boot(context.Background(), f.opts); !errors.Is(err, vault.ErrCaseCollision) {
		t.Fatalf("a vault with colliding paths booted without an error: %v", err)
	}
	assertVaultIsLockable(t, f.vault.Root)
}

// caseSensitiveFilesystem reports whether writing two names that differ only in
// case produces two files, which is the question a case-collision fixture turns
// on. It answers about the volume the test will run on, not about the OS.
func caseSensitiveFilesystem(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	upper := filepath.Join(dir, "Collide.md")
	lower := filepath.Join(dir, "collide.md")
	if err := os.WriteFile(upper, []byte("one\n"), 0o600); err != nil {
		t.Fatalf("write the first name: %v", err)
	}
	if err := os.WriteFile(lower, []byte("two\n"), 0o600); err != nil {
		// A volume that refuses the second write is case-insensitive in the
		// stronger sense that it will not hold both at all.
		return false
	}
	first, err := os.ReadFile(upper)
	if err != nil {
		t.Fatalf("read back the first name: %v", err)
	}
	// Same contents would mean the second write landed on the first name, and a
	// different size makes that impossible to confuse with a partial write.
	return string(first) == "one\n"
}

// assertVaultIsLockable fails unless the vault can be claimed right now, which
// is the only evidence that nothing is still holding it.
func assertVaultIsLockable(t *testing.T, root string) {
	t.Helper()
	handle, err := vault.Lock(context.Background(), root)
	if err != nil {
		t.Fatalf("the vault is still locked after boot gave up: %v", err)
	}
	handle.Release()
}

// TestNewerSchemaRefusesToStart covers a database written by a newer binary.
//
// It must refuse rather than downgrade, and it must refuse *before* the backup
// hook runs, because taking a backup of a file this binary cannot read and then
// refusing to open it is the most misleading thing it could do.
func TestNewerSchemaRefusesToStart(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.opts)
	head := store.SchemaVersion()
	if err := shutdownAnd(a); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	older, err := store.Open(f.vault.Root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, writerErr := older.Writer().ExecContext(context.Background(),
		"PRAGMA user_version = "+strconv.Itoa(head+1)); writerErr != nil {
		t.Fatalf("set user_version: %v", writerErr)
	}
	_ = older.Close()

	_, err = Boot(context.Background(), f.opts)
	switch {
	case err == nil:
		t.Fatal("a database from a newer schema booted")
	case !errors.Is(err, store.ErrSchemaTooNew):
		t.Fatalf("the refusal is not store.ErrSchemaTooNew: %v", err)
	}
	if !strings.Contains(err.Error(), "upgrade semiplane") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}

	// Not migrated, and not quarantined: the file is exactly as it was.
	after, err := store.Open(f.vault.Root)
	if err != nil {
		t.Fatalf("reopen after the refusal: %v", err)
	}
	defer func() { _ = after.Close() }()
	version, err := store.UserVersion(context.Background(), after.Reader())
	if err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != head+1 {
		t.Errorf("user_version is %d after the refusal, want %d: the database was migrated anyway",
			version, head+1)
	}
	assertVaultIsLockable(t, f.vault.Root)
}

// TestCorruptDatabaseIsQuarantinedNotFatal covers a database that cannot be
// opened.
//
// The vault is canonical and the index is a cache, so a cache that cannot be
// read is set aside and rebuilt rather than being the end of the boot. The
// quarantined file is kept, because an operator who has just lost an index wants
// to be able to look at it.
func TestCorruptDatabaseIsQuarantinedNotFatal(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.opts)
	if err := shutdownAnd(a); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	dir := filepath.Join(f.vault.Root, store.StateDirName)
	// The write-ahead log belongs to the schema that is about to be replaced; a
	// stale one left beside the fresh database would be replayed into it.
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(f.dbFile() + suffix)
	}
	if err := os.WriteFile(f.dbFile(), []byte("this is not a database, it is a note to self"), 0o600); err != nil {
		t.Fatalf("corrupt the database: %v", err)
	}

	a = f.boot(t, f.opts)
	quarantined := matchOne(t, dir, store.DBName+".corrupt-")
	if len(quarantined) != 1 {
		t.Fatalf("found %d quarantined databases, want exactly one: %v", len(quarantined), quarantined)
	}
	if pages := a.Status().PageCount; pages != f.pages() {
		t.Errorf("the fresh database holds %d pages, want %d: the vault was not reindexed",
			pages, f.pages())
	}
	if !anyWarningContains(a, "could not be read") {
		t.Errorf("the boot report does not mention the quarantine: %v", a.Status().Warnings)
	}
}

// TestBootWithoutAHandlerDoesNotListen covers the seam the one-shot commands
// and every test depend on.
func TestBootWithoutAHandlerDoesNotListen(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.opts)

	if addr := a.Status().Addr; addr != "" {
		t.Errorf("Addr is %q with no handler injected", addr)
	}
	if a.Status().PageCount != f.pages() {
		t.Errorf("the vault was not indexed: %d pages", a.Status().PageCount)
	}
	if a.DB() == nil {
		t.Error("the database was not opened")
	}
	if a.Indexer() == nil {
		t.Error("the indexer was not built")
	}
	if a.Vault() == nil {
		t.Error("the writer was not built")
	}
	// No listener, no watcher, no reconciliation goroutine: a process that is
	// about to exit has no use for them.
	for _, step := range []string{stepWatch, stepBind, stepServe} {
		if indexOf(f.steps, step) >= 0 {
			t.Errorf("%s ran with no handler injected", step)
		}
	}
}

// TestShutdownIsIdempotentAndReleasesEverything covers the exit path.
func TestShutdownIsIdempotentAndReleasesEverything(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a, err := Boot(context.Background(), f.withHandler())
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if err := shutdownAnd(a); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("third shutdown: %v", err)
	}
	assertVaultIsLockable(t, f.vault.Root)

	// The database is closed: a query through either pool fails rather than
	// quietly reopening the file.
	if err := a.DB().Reader().PingContext(context.Background()); err == nil {
		t.Error("the read pool is still usable after shutdown")
	}
	if err := a.DB().Writer().PingContext(context.Background()); err == nil {
		t.Error("the write pool is still usable after shutdown")
	}
}

// TestBannerPrintsWarnings covers the report the operator reads.
//
// A file that was skipped is a page the DM believes is in their campaign and is
// not in the index, so silence would make it a mystery to be discovered as a
// broken wikilink weeks later. The two refusals are different kinds on purpose:
// one is a file the ignore list declines by name, the other is a directory the
// filesystem would not open.
func TestBannerPrintsWarnings(t *testing.T) {
	t.Parallel()
	locked := "Campaigns/Locked"
	f := newFixture(t, map[string]string{
		"Campaign.md":                  "# Campaign\n",
		"Campaigns/Ash.md":             "# Ash\n",
		"drafts/scratch.semiplane-tmp": "# Scratch\n",
		locked + "/keep.md":            "# Never read\n",
	})
	if err := os.Chmod(filepath.Join(f.vault.Root, locked), 0o000); err != nil {
		t.Fatalf("chmod %s: %v", locked, err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(f.vault.Root, locked), 0o700) })

	a := f.boot(t, f.withHandler())
	banner := f.banner.String()
	for _, want := range []string{"warnings:", locked, "ignored by name", "not indexed:"} {
		if !strings.Contains(banner, want) {
			t.Errorf("the banner does not mention %q:\n%s", want, banner)
		}
	}
	if want := 2 + samplePages(); a.Status().PageCount != want {
		t.Errorf("the index holds %d pages, want %d: the two that could be read, plus the campaign",
			a.Status().PageCount, want)
	}
	if strings.Contains(banner, leakToken) {
		t.Error("the banner printed a secret body")
	}
}

// TestBannerPrintsNoVaultContent covers the other half of the banner's
// contract: it reports on the process, and a page's title is vault content.
func TestBannerPrintsNoVaultContent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.withHandler())
	banner := f.banner.String()

	for _, forbidden := range []string{leakToken, "The Safe", "The Vault Door", "abcdef012345", "A courier with a letter"} {
		if strings.Contains(banner, forbidden) {
			t.Errorf("the banner printed vault content %q:\n%s", forbidden, banner)
		}
	}
	for _, want := range []string{
		f.vault.Root,                // the resolved path
		"flag:--vault",              // and how it was chosen
		filepath.Base(f.vault.Root), // the campaign name
		"schema v",                  // the schema version
		strconv.Itoa(f.pages()) + " pages",
		"plugins:",      // the plugin boot report
		a.Status().Addr, // the listening address
		"http://",       // and the URL a browser can open
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("the banner does not mention %q:\n%s", want, banner)
		}
	}
}

// TestPrintBannerIsWrittenBeforeTheListenerServes asserts the ordering the
// banner promises: the report is complete before Serve is called, so the first
// request cannot arrive before the operator has been told what they are talking
// to.
func TestPrintBannerIsWrittenBeforeTheListenerServes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.withHandler())

	serveAt := indexOf(f.steps, stepServe)
	bannerAt := indexOf(f.steps, stepBanner)
	bindAt := indexOf(f.steps, stepBind)
	if serveAt < 0 || bannerAt < 0 || bindAt < 0 {
		t.Fatalf("the boot did not reach the listener: %v", f.steps)
	}
	if !(bindAt < bannerAt && bannerAt < serveAt) {
		t.Errorf("the banner was not written between the bind and the serve: %v", f.steps)
	}
	if f.banner.Len() == 0 {
		t.Error("the banner was not written")
	}
}

// TestAWildcardBindIsRefused covers a hand-built Config with no host.
//
// config.Load defaults the host to loopback; an empty one binds every interface,
// and this process holds plaintext DM secrets. The refusal is the difference
// between a test that constructs a Config by hand and a server on the LAN.
func TestAWildcardBindIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	opts := f.withHandler()
	opts.Config.Host = ""
	_, err := Boot(context.Background(), opts)
	if err == nil {
		t.Fatal("a handler with no bind address started a listener")
	}
	if !strings.Contains(err.Error(), "bind address") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
	assertVaultIsLockable(t, f.vault.Root)
}

// TestTheMountedHandlerIsTheOneServed covers the seam itself.
//
// A nil Handler on an http.Server means DefaultServeMux, so a composition root
// that forgot to keep the handler it was given would start a listener that
// answers — with something else entirely, and with the vault's index behind it.
func TestTheMountedHandlerIsTheOneServed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	const body = "the handler that was mounted"
	opts := f.opts
	opts.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	a := f.boot(t, opts)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+a.Status().Addr+"/", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != body {
		t.Errorf("the listener answered %q, want the mounted handler's %q", got, body)
	}
}

// TestAReconcilePassFollowsAFileWrittenWhileTheAppRuns covers the scanner's
// only real owner: the reconciliation loop, and through it the indexer.
func TestAReconcilePassFollowsAFileWrittenWhileTheAppRuns(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.withHandler())

	f.vault.WriteFile(t, "Campaigns/Late.md", "# Late\n\nWritten after the boot.\n")
	// Through the indexer, which is the only thing that may touch the scanner:
	// the app's own sixty-second loop is a caller of this same method.
	if _, err := a.Indexer().Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	pages, err := store.CountPages(context.Background(), a.DB().Reader())
	if err != nil {
		t.Fatalf("count pages: %v", err)
	}
	if want := int64(f.pages() + 1); pages != want {
		t.Errorf("the index holds %d pages, want %d", pages, want)
	}
	// The report is refreshed by whichever pass ran, so a caller that reads it
	// after its own pass sees its own numbers.
	a.refreshStatus(context.Background())
	if got := a.Status().PageCount; got != f.pages()+1 {
		t.Errorf("the boot report says %d pages, want %d", got, f.pages()+1)
	}
}

// TestTheVaultIsOnlyLockedByOneProcessAtATime is the concurrency form of the
// claim: several processes racing for one vault elect exactly one winner.
func TestTheVaultIsOnlyLockedByOneProcessAtATime(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	f.boot(t, f.opts)

	const racers = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		refused int
	)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := f.opts
			other.trace = nil
			other.Banner = nil
			if _, err := Boot(context.Background(), other); err != nil {
				if errors.Is(err, vault.ErrAlreadyLocked) {
					mu.Lock()
					refused++
					mu.Unlock()
					return
				}
				t.Errorf("boot %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if refused != racers {
		t.Errorf("%d of %d racers were refused, want %d: two processes hold one vault",
			refused, racers, racers)
	}
}

// shutdownAnd stops an app, so a test can reopen the vault's database.
func shutdownAnd(a *App) error {
	ctx, cancel := boundedContext()
	defer cancel()
	return a.Shutdown(ctx)
}

// matchOne returns the entries of dir whose names start with prefix.
func matchOne(t *testing.T, dir, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// anyWarningContains reports whether the boot report mentions a substring.
func anyWarningContains(a *App, want string) bool {
	for _, w := range a.Status().Warnings {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
