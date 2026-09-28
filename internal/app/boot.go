package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	// The indexer's package is named sync, so it is this one that is aliased:
	// reading "sync.Once" in this file should mean the standard library's.
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

const (
	// ReconcileInterval is how often the reconciliation scan runs.
	//
	// The scan is the correctness guarantee and the watcher is a latency
	// optimisation: fsnotify is not recursive, its events are dropped when the
	// kernel queue overflows, and on a network mount it may not fire at all.
	ReconcileInterval = 60 * time.Second

	// ShutdownTimeout bounds how long Shutdown waits for in-flight requests and
	// for the reconciliation goroutine before it gives up and reports that it
	// did.
	ShutdownTimeout = 15 * time.Second

	// readHeaderTimeout bounds a slow client's headers. A server that holds
	// secrets should not let one connection occupy a goroutine indefinitely.
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds reading one request's head and body.
	readTimeout = 60 * time.Second
	// idleTimeout is how long a keep-alive connection may sit unused.
	idleTimeout = 120 * time.Second

	// auditFileName is the append-only audit log inside the vault's private
	// directory. It is opened after the lock, never before: nothing in a vault
	// may be opened before the single-instance claim.
	auditFileName = "audit.log"

	// corruptStampLayout names a quarantined database. It is the backup
	// directory's layout, so a quarantined file sorts with the backups it was
	// taken beside.
	corruptStampLayout = "20060102T150405Z"
)

// The boot steps, in the order Boot runs them.
//
// The names are constants because TestBootTakesTheOrderItClaims asserts the
// sequence by name: a reordered boot is a security bug rather than a style
// question — two processes over one vault interleave their watchers and one
// process's self-write suppression swallows the other's real edit — and a
// renamed step should fail that test rather than stop being checked.
const (
	stepVault  = "resolve-vault"
	stepLock   = "lock"
	stepAudit  = "audit-log"
	stepOpen   = "open-database"
	stepWire   = "wire-index"
	stepBackup = "backup"
	stepSchema = "migrate"
	stepFTS    = "fts-rebuild"
	stepIndex  = "index"
	stepPrune  = "prune"
	// stepPlugins is named in the trace after the index and before the watcher,
	// because that is where it sits: a page type must be registered before the
	// first request and a plugin migration must land in the same boot as the rows
	// that reference it.
	stepPlugins = "plugins"
	stepWatch   = "watch"
	stepBind    = "bind"
	stepBanner  = "banner"
	stepServe   = "serve"
)

// Options configures Boot.
type Options struct {
	// Config is the validated configuration.
	Config config.Config
	// Handler is the mounted HTTP handler. When nil, Boot does not listen: it
	// locks, migrates, indexes and returns, which is exactly what
	// `semiplane reindex`, `semiplane backup` and every test wants.
	Handler http.Handler
	// Logger receives the boot records. A nil Logger discards.
	Logger *obs.Logger
	// Clock is the time source. A nil Clock is the system clock.
	Clock obs.Clock
	// Banner receives the boot report, once the index is complete. With a
	// handler injected it is written after the listener is bound and before the
	// listener serves, so that the address it names is one a client can reach
	// and the report is out before the first request. Without one there is no
	// listener to wait for and it is written at the end of the boot.
	//
	// A nil Banner writes nothing, which is what the one-shot commands want:
	// they print their own summary of the same facts.
	Banner io.Writer
	// Reindex asks the boot's indexing pass to rebuild every derived row from
	// the vault's files instead of taking the delta walk. It is `--reindex` on
	// the command line, and it is honoured on every command that boots, because
	// a flag that parses and is then discarded is a debugging detour rather
	// than a setting.
	//
	// The rebuild replaces the pass rather than preceding it: it reads every
	// file, so a second walk over the same vault would find nothing changed and
	// cost a full re-read to say so.
	Reindex bool
	// Plugins is the registry to boot with — one map entry per shipped plugin,
	// built in cmd/semiplane/registry.go. It is a parameter rather than a package
	// variable so that a test can boot with a single fake plugin and a build
	// with none, and so that `internal/app` never names a plugin id: the map is
	// the one place that is allowed to, and a composition root that could name
	// them would be a second place.
	Plugins map[string]plugin.Plugin
	// trace records every step in the order it completed, and the order is the
	// point: it is the seam the boot-order test asserts through.
	trace func(step string)
}

// withDefaults fills the optional fields, so no other code in this package has
// to ask whether a caller remembered one.
func (o Options) withDefaults() Options {
	if o.Logger == nil {
		o.Logger = obs.Discard()
	}
	if o.Clock == nil {
		o.Clock = obs.SystemClock
	}
	return o
}

// App is a booted vault: the lock, the index, the writer and, when a handler
// was injected, the listener.
//
// It is the composition root's whole output. Every component it holds was built
// here and wired to the others here, so there is no second place where a vault
// is opened and no global to reach through.
type App struct {
	opts   Options
	cfg    config.Config
	log    *obs.Logger
	audit  *obs.Logger
	clock  obs.Clock
	banner io.Writer
	trace  func(string)

	root        string
	vaultSource string
	db          *store.DB
	auditFile   *os.File
	lock        *vault.Handle
	bus         *isync.Bus
	indexer     *isync.Indexer
	selfwrites  *isync.Selfwrites
	writer      *vault.Writer
	watcher     *vault.Watcher
	// plugins is what the plugin lifecycle produced: the registries the request
	// path reads, and the boot report an administrator reads. It is built once,
	// here, and never mutated afterwards.
	plugins      plugin.Registry
	report       plugin.Report
	handler      http.Handler
	server       *http.Server
	listener     net.Listener
	addr         string
	bgCancel     context.CancelFunc
	reconcileEnd chan struct{}

	mu        sync.Mutex
	status    Status
	fileCount int
	// lastPass is what the boot's own indexing pass did, kept because the
	// reindex command reports it: a second pass over a vault the first one
	// already rebuilt finds nothing changed, and reporting that as the result
	// of `semiplane reindex --full` would say the opposite of what happened.
	lastPass isync.BatchResult
	// bootWarnings are the facts the boot itself produced, and passWarnings are
	// what the last indexing pass refused. They are kept apart because they
	// have different lifetimes: a boot warning is true for the life of the
	// process, while a pass warning is replaced every time a pass runs and must
	// not accumulate one copy per pass.
	bootWarnings []string
	passWarnings []string
	// backupAt is when the backup taken during this boot was written. It is
	// stamped into the meta table after the migration, because the table does
	// not exist before it.
	backupAt time.Time

	stopOnce sync.Once
	stopErr  error
}

// Status is the boot report: what was opened, what was found, and what the
// operator should know about it.
//
// It is what the startup banner renders and what a readiness probe answers
// with, so every field is a fact about the process and none of them is vault
// content. A path, a count and a version are safe here; a page title or a
// secret id is not, whatever else it is.
type Status struct {
	// Vault is the resolved, absolute vault root.
	Vault string
	// VaultSource is how the path was chosen: a flag, the environment, a
	// default, or a fallback the operator should know about.
	VaultSource string
	// Campaign is the campaign's name. See campaignName.
	Campaign string
	// Addr is the listening address, or "" when nothing is listening.
	Addr string
	// SchemaVersion is the database's schema version, as "6".
	SchemaVersion string
	// BootState is store.BootStateIndexing or store.BootStateReady.
	BootState string
	// PageCount is how many pages the index holds.
	PageCount int
	// IndexedAt is when the index was last brought up to date.
	IndexedAt time.Time
	// Warnings is what the walk declined, said out loud: an ignored file, an
	// unreadable file, a skipped case collision, an over-cap file. "The app
	// ignored 14 files" is visible rather than mysterious.
	Warnings []string
	// AuthzGeneration is the current authorization generation, which is what
	// terminates a stale live-push stream.
	AuthzGeneration int64
}

// Boot opens a vault, brings the index up to date, and — when a handler was
// injected — serves it.
//
// The order is the contract, not a preference:
//
//	resolve the path → single-instance lock → audit log → database →
//	backup + migrate → FTS rebuild → full walk and index → prune →
//	watcher and reconciliation → banner → listener
//
// The lock comes second and before anything is opened, because two processes
// over one vault would each hold an index and a watcher over the same files and
// the loser's writes would be overwritten by the winner's watcher with no trace
// of the conflict. Every step that fails stops the boot and names itself, and
// the lock is released on the way out of every one of them — including the paths
// that return an error — because a process that exits on a boot failure must
// not leave a vault that a second instance cannot open.
func Boot(ctx context.Context, opts Options) (a *App, err error) {
	opts = opts.withDefaults()
	a = &App{
		opts:    opts,
		cfg:     opts.Config,
		log:     opts.Logger,
		clock:   opts.Clock,
		banner:  opts.Banner,
		trace:   opts.trace,
		handler: opts.Handler,
	}
	defer func() {
		if err == nil {
			return
		}
		// A boot that failed halfway still holds whatever it managed to take.
		// Releasing it here is what keeps the error path and the exit path on
		// the same route to the lock.
		ctx, cancel := boundedContext()
		defer cancel()
		_ = a.Shutdown(ctx)
	}()

	// 1. The vault path, and the directories that hold everything else.
	choice, err := chooseVault(opts.Config)
	if err != nil {
		return a, fmt.Errorf("boot: %w", err)
	}
	a.root = choice.Root
	a.vaultSource = choice.Source
	for _, w := range choice.Warnings {
		a.addWarning(w)
	}
	if err := ensureVault(a.root); err != nil {
		return a, fmt.Errorf("boot: prepare the vault: %w", err)
	}
	a.setVaultFacts()
	a.step(stepVault)

	// 2. The single-instance claim, before any file or database is opened.
	if err = a.takeLock(ctx); err != nil {
		return a, fmt.Errorf("boot: %w", err)
	}
	a.step(stepLock)

	// 3. The audit log, which is a file in the vault and so cannot be opened
	// before the lock.
	a.openAuditLog()
	a.step(stepAudit)

	// 4. The index database, quarantining one that cannot be read.
	if err = a.openDatabase(ctx); err != nil {
		return a, err
	}
	a.step(stepOpen)

	// 5. Everything that writes the index, built once against this database and
	// this clock.
	if err = a.wire(); err != nil {
		return a, fmt.Errorf("boot: build the index components: %w", err)
	}
	a.step(stepWire)

	// 6. A backup, then the migration. store.Migrate takes the backup hook as a
	// parameter and calls it before it applies anything.
	if err = a.migrate(ctx); err != nil {
		return a, fmt.Errorf("boot: %w", err)
	}
	a.step(stepSchema)

	// 7. The search index, when the schema generation moved under it.
	if err = a.rebuildFTS(ctx, false); err != nil {
		return a, fmt.Errorf("boot: rebuild the search index: %w", err)
	}
	a.step(stepFTS)

	// 8. The pass. Unconditional: the index is derived and the vault is
	// canonical, so a boot that trusted the index would serve whatever the last
	// crash left behind. A --reindex boot drops the derived rows and rebuilds
	// them here rather than afterwards, so nothing in the index is trusted at
	// all.
	if err = a.fullIndex(ctx, opts.Reindex); err != nil {
		return a, fmt.Errorf("boot: index the vault: %w", err)
	}
	a.step(stepIndex)

	// 9. Housekeeping: the rows that expired while the app was not running.
	if err = a.prune(ctx); err != nil {
		return a, fmt.Errorf("boot: prune expired rows: %w", err)
	}
	a.step(stepPrune)

	// 8b. The plugin lifecycle: migrations, registration, and the boot report.
	//
	// It runs after the index and before anything serves, so a page type a
	// plugin registered is available to the first request rather than appearing
	// on the second. It never fails the boot: a plugin that cannot register is
	// recorded in the report with a reason and the campaign runs without it,
	// because a campaign that will not boot is a worse outcome than a missing
	// panel and a much harder one to diagnose.
	if err = a.loadPlugins(ctx); err != nil {
		return a, fmt.Errorf("boot: build the plugin host: %w", err)
	}
	a.step(stepPlugins)

	if opts.Handler == nil {
		// A one-shot command and every test take this path: the vault is locked,
		// migrated and indexed, and there is nothing left to run. A command that
		// exits in a second has no use for a watch it would have to stop, and a
		// watch that outlives it would index while the command was reporting.
		//
		// The banner is still written, because a caller that asked for one wants
		// the facts and there is no listener here to wait for: with a handler it
		// is written after the bind, so that it can name an address a client can
		// actually reach.
		a.printBanner()
		a.step(stepBanner)
		return a, nil
	}

	// 10. The watcher and the one goroutine that owns the reconciliation scan.
	if err = a.startBackground(); err != nil {
		return a, fmt.Errorf("boot: start the vault watcher: %w", err)
	}
	a.step(stepWatch)

	// 11. Bind, then print, then serve. Binding first is what lets the banner
	// name the address a client can actually reach — with --port 0 the port is
	// the kernel's choice — and printing before Serve is what keeps the report
	// ahead of the first request.
	if err = a.bind(); err != nil {
		return a, err
	}
	a.step(stepBind)
	a.printBanner()
	a.step(stepBanner)
	if err = a.serve(); err != nil {
		return a, err
	}
	a.step(stepServe)
	return a, nil
}

// step records that a boot stage finished, in the order it finished. The trace
// is a test seam, and it is the only place the boot's order is written down: a
// reordered boot is a security bug rather than a style question, and an order
// that is only ever implied by the code is an order nothing checks.
func (a *App) step(name string) {
	if a.trace != nil {
		a.trace(name)
	}
}

// takeLock claims the vault exclusively.
func (a *App) takeLock(ctx context.Context) error {
	handle, err := vault.Lock(ctx, a.root)
	if err != nil {
		if errors.Is(err, vault.ErrAlreadyLocked) {
			// vault.Lock already names the holder's pid; the advice is the part
			// it cannot know, because only the operator knows what else is
			// running.
			return fmt.Errorf("%w; stop it, or pass --vault for a different vault", err)
		}
		return fmt.Errorf("take the single-instance lock on %s: %w", a.root, err)
	}
	a.lock = handle
	a.log.InfoContext(ctx, "the vault is claimed by this process",
		"action", "boot.lock", "path", handle.Path(), "pid", handle.PID())
	return nil
}

// openAuditLog attaches the append-only audit log to a logger of its own.
//
// The audit sink is separate from the main log by construction — obs keeps two
// handlers apart precisely so a debugging record can never be mistaken for a
// security record — which is why this is a second Logger rather than an option
// on the first. A log file that cannot be opened is a warning, not a refusal:
// the event is still in the main log, and refusing to boot would leave the
// operator with neither an app nor a way to see why.
func (a *App) openAuditLog() {
	path := filepath.Join(a.root, vault.HiddenDir, auditFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		a.log.Warn("could not open the audit log; audit records will not be written",
			"action", "boot.audit", "path", path, "err", err.Error())
		return
	}
	a.auditFile = f
	a.audit = obs.NewLogger(io.Discard, obs.Options{Audit: f})
}

// openDatabase opens the index, quarantining a file that cannot be read and
// continuing with a fresh one.
//
// The vault is canonical and the index is a cache, so a cache that cannot be
// read is replaced rather than repaired — there is nothing in it that the
// Markdown files do not already say. Quarantining rather than deleting is what
// makes the failure investigable after the fact: the operator can compare the
// two.
func (a *App) openDatabase(ctx context.Context) error {
	db, err := store.Open(a.root)
	if err == nil {
		a.db = db
		return nil
	}
	if qerr := a.quarantineDatabase(ctx, err); qerr != nil {
		return fmt.Errorf("boot: open the index database: %w (and the unreadable file could not be set aside: %v)", err, qerr)
	}
	db, err = store.Open(a.root)
	if err != nil {
		return fmt.Errorf("boot: open a fresh index database after quarantining the unreadable one: %w", err)
	}
	a.db = db
	return nil
}

// quarantineDatabase moves an unreadable database aside and says so in the
// audit log.
//
// The write-ahead sidecars go with it. A -wal left lying beside a new database
// is a write log belonging to a schema that no longer exists, and the next open
// would replay it — a worse failure than the one being recovered from.
func (a *App) quarantineDatabase(ctx context.Context, cause error) error {
	dir := filepath.Join(a.root, store.StateDirName)
	stamp := a.clock().UTC().Format(corruptStampLayout)
	var moved []string
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := filepath.Join(dir, store.DBName+suffix)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := src + ".corrupt-" + stamp
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("move %s aside: %w", filepath.Base(src), err)
		}
		moved = append(moved, dst)
	}
	if len(moved) == 0 {
		return errors.New("there is no database file where the vault says there is one")
	}
	// Paths and a reason, never content: this is a record about a file, and the
	// file's own bytes are the vault's.
	a.log.ErrorContext(ctx, "the index database could not be read and was set aside; the vault was not touched",
		"action", "db.quarantine", "path", moved[0], "reason", cause.Error())
	a.auditContext(ctx, "index database quarantined and rebuilt from the vault",
		"action", "db.quarantine", "path", moved[0], "reason", cause.Error())
	a.addWarning("the index database could not be read and was set aside as " +
		filepath.Base(moved[0]) + "; the index was rebuilt from the vault")
	return nil
}

// auditContext writes one audit record through the vault's own audit log.
func (a *App) auditContext(ctx context.Context, msg string, args ...any) {
	if a.audit != nil {
		a.audit.Audit(ctx, msg, args...)
	}
}

// wire builds the components that write the index: the invalidation bus, the
// indexer, the self-write suppression table, and the only writer a vault file
// may be changed through.
//
// It happens once, after the database is open and before anything indexes, so
// that every one of them holds the same database handle and the same clock. It
// is here rather than in the indexer's constructor because this is the only
// place that knows the vault, the configuration and the clock: the Markdown
// parser is assembled here too, and the plugin phase appends its extenders to
// this one call.
func (a *App) wire() error {
	a.bus = isync.NewBus(a.log)
	selfwrites := isync.NewSelfwrites(a.db, a.log)
	selfwrites.SetClock(a.clock)
	a.selfwrites = selfwrites

	indexer, err := isync.New(isync.Options{
		DB:                  a.db,
		Root:                a.root,
		Renderer:            md.New(md.Options{}),
		Bus:                 a.bus,
		Log:                 a.log,
		Clock:               a.clock,
		AllowCaseCollisions: a.cfg.AllowCaseCollisions,
	})
	if err != nil {
		return err
	}
	a.indexer = indexer

	writer := vault.NewWriter(a.root, a.log)
	writer.Store = selfwrites
	writer.Clock = a.clock
	a.writer = writer
	return nil
}

// migrate backs up and then migrates, and records the version the database
// ended at rather than the one this binary expects.
func (a *App) migrate(ctx context.Context) error {
	if err := store.Migrate(ctx, a.db.Writer(), a.backupBeforeMigration); err != nil {
		return err
	}
	version, err := store.UserVersion(ctx, a.db.Reader())
	if err != nil {
		return err
	}
	a.setSchemaVersion(version)
	if !a.backupAt.IsZero() {
		return a.stampBackup(ctx, a.backupAt)
	}
	return nil
}

// backupBeforeMigration is the hook store.Migrate requires.
//
// It takes a backup when the plan says one is due rather than on every boot:
// before a migration, on demand from `semiplane backup`, and on the first boot
// after the vault has changed since the last one. Copying every page of a
// ten-thousand-file vault on every `semiplane vault info` would fill the disk
// with backups nobody asked for, and the retention policy is ten.
func (a *App) backupBeforeMigration(ctx context.Context) error {
	needed, reason, err := a.backupDue(ctx)
	if err != nil {
		return err
	}
	// Recorded either way: "a backup was considered and not taken" is the fact
	// an operator needs when they ask why the backups directory has not grown.
	a.step(stepBackup)
	if !needed {
		a.log.InfoContext(ctx, "no backup is due before this boot",
			"action", "boot.backup", "reason", reason)
		return nil
	}
	a.log.InfoContext(ctx, "a backup is due before the migration continues",
		"action", "boot.backup", "reason", reason)
	if _, err := a.takeBackup(ctx); err != nil {
		return err
	}
	return nil
}

// backupDue reports whether §7.6's triggers ask for a backup now, and why.
func (a *App) backupDue(ctx context.Context) (bool, string, error) {
	version, err := store.UserVersion(ctx, a.db.Reader())
	if err != nil {
		return false, "", err
	}
	if head := store.SchemaVersion(); version < head {
		return true, "a migration is pending", nil
	}
	last, err := store.MetaGet(ctx, a.db.Reader(), store.KeyLastBackup)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return true, "this vault has never been backed up", nil
	case err != nil:
		return false, "", err
	}
	changed, err := store.MetaGet(ctx, a.db.Reader(), store.KeyLastChangeAt)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return false, "the vault has not changed since the last backup", nil
	case err != nil:
		return false, "", err
	}
	// Both values are timestamps rather than counters, and a value this build
	// cannot parse is treated as "changed": taking a redundant backup costs
	// disk, and skipping a due one costs the operator their recovery point.
	lastAt, lastErr := store.ParseTime(last)
	changedAt, changedErr := store.ParseTime(changed)
	if lastErr != nil || changedErr != nil || changedAt.After(lastAt) {
		return true, "the vault changed since the last backup", nil
	}
	return false, "the vault has not changed since the last backup", nil
}

// printBanner writes the boot report to the writer Boot was given, if it was
// given one.
func (a *App) printBanner() {
	if a.banner == nil {
		return
	}
	PrintBanner(a.banner, a.Status())
}

// takeBackup writes a backup and remembers when.
//
// It does not record the time in the meta table itself: on a vault that has
// never been migrated the table does not exist yet, and the migration's own
// backup is taken before the first migration statement has run. The caller
// stamps it once the schema is there — see stampBackup.
func (a *App) takeBackup(ctx context.Context) (string, error) {
	at := a.clock()
	dir, err := vault.Backup(ctx, a.root, a.db.Path(), at)
	if err != nil {
		return "", fmt.Errorf("write a backup: %w", err)
	}
	a.backupAt = at
	a.log.InfoContext(ctx, "backup written", "action", "boot.backup", "path", dir)
	return dir, nil
}

// stampBackup records when a backup was taken, so the next boot can tell whether
// the vault has changed since.
func (a *App) stampBackup(ctx context.Context, at time.Time) error {
	return store.MetaSet(ctx, a.db.Writer(), store.KeyLastBackup, store.FormatTime(at))
}

// rebuildFTS rebuilds the search tables when the schema generation moved under
// them, or when the caller asks for it.
//
// The walk maintains the FTS rows incrementally as it indexes, so a normal boot
// with a matching generation does nothing here. A generation mismatch means the
// tables were built by a different tokenizer or column set, and only a rebuild
// can make them agree with the schema.
func (a *App) rebuildFTS(ctx context.Context, force bool) error {
	if !force {
		needed, err := store.NeedsFTSRebuild(ctx, a.db.Reader())
		if err != nil {
			return err
		}
		if !needed {
			return nil
		}
	}
	generation, err := store.MetaGetInt(ctx, a.db.Reader(), store.KeySchemaVersion)
	if err != nil {
		return err
	}
	tx, err := a.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := store.RebuildPageFTS(ctx, tx); err != nil {
		return err
	}
	if err := store.RebuildSecretFTS(ctx, tx); err != nil {
		return err
	}
	if err := store.MarkFTSGeneration(ctx, tx, generation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	a.log.InfoContext(ctx, "the search index was rebuilt", "action", "fts.rebuild", "generation", generation)
	return nil
}

// fullIndex walks the vault, indexes everything it finds, drops what is gone,
// and reports the walk's refusals as warnings.
//
// boot_state is 'indexing' for the duration, so a readiness probe can tell a
// slow first boot from a finished one.
//
// full drops every derived row first and rebuilds the search tables, so nothing
// the index believed is trusted. That is the answer to an index that is wrong
// in a way a file hash cannot reveal — and it is why the full pass takes its
// file list from vault.Walk rather than from the scanner, which after the rows
// are gone would faithfully report that nothing has changed.
func (a *App) fullIndex(ctx context.Context, full bool) error {
	if err := store.MetaSet(ctx, a.db.Writer(), store.KeyBootState, store.BootStateIndexing); err != nil {
		return err
	}
	if full {
		// An empty list of files means no page is still there, so this drops
		// every page and everything that cascades from it. It is the index's
		// own API doing it, which is what keeps the FTS rows in step.
		//
		// The window this opens — every page momentarily unindexed — is closed
		// by the boot order: nothing binds a listener until after the pass, and
		// the watcher that follows starts against a rebuilt index. Every write
		// is one file's transaction, so an interrupted rebuild costs the next
		// run a walk, not the vault a file.
		a.log.InfoContext(ctx, "every derived row is being dropped and rebuilt from the vault's files",
			"action", "boot.reindex")
		if _, err := a.indexer.RemoveMissing(ctx, nil); err != nil {
			return fmt.Errorf("drop the derived index: %w", err)
		}
		if err := a.rebuildFTS(ctx, true); err != nil {
			return fmt.Errorf("rebuild the search index: %w", err)
		}
	}
	res, err := a.reindexPass(ctx, full)
	if err != nil {
		return err
	}
	a.setLastPass(res)
	// A secret fence names its author by username, and secrets.author_id is a
	// foreign key, so a fence whose author was not an account when the page was
	// indexed has no index row and is shown to nobody. This closes the warm
	// restart case, where the account was created before this process booted.
	// It does NOT close the first-boot case, where the account arrives after
	// this line: internal/httpapi calls the same method right after a setup or
	// an invite is accepted.
	if _, err := a.indexer.RetryUnresolvedAuthors(ctx); err != nil {
		return fmt.Errorf("retry the secret fences whose author was not an account yet: %w", err)
	}
	if err := a.enforceSecretIndexInvariant(ctx); err != nil {
		return err
	}
	a.refreshStatus(ctx)
	a.setIndexedAt()
	if err := store.MetaSet(ctx, a.db.Writer(), store.KeyBootState, store.BootStateReady); err != nil {
		return err
	}
	a.setBootState(store.BootStateReady)
	return nil
}

// reindexPass is one pass over the vault: walk, index, and drop the rows whose
// files are gone.
//
// The indexer's own walk is a full vault.Walk plus the scanner's delta filter,
// so a first boot re-reads every file and a warm boot only the ones that
// changed — and the walk is what detects the refusals, because it is the only
// caller of the scanner, whose record the next pass compares against.
//
// full asks for the complete file list from vault.Walk instead. That is the
// difference between "what has changed" and "what exists", and it matters after
// the index rows have been dropped: the scanner would then report an unchanged
// vault and the rows would never come back.
func (a *App) reindexPass(ctx context.Context, full bool) (isync.BatchResult, error) {
	files, err := a.walk(ctx, full)
	if err != nil {
		return isync.BatchResult{}, err
	}
	res, err := a.indexer.IndexBatch(ctx, files)
	if err != nil {
		return isync.BatchResult{}, err
	}
	if _, err := a.indexer.RemoveMissing(ctx, files); err != nil {
		return isync.BatchResult{}, err
	}
	return res, nil
}

// walk returns the files a pass should index, and records what the walk refused.
func (a *App) walk(ctx context.Context, full bool) ([]string, error) {
	var res vault.WalkResult
	var err error
	if full {
		res, err = vault.Walk(ctx, a.root, vault.WalkOptions{
			AllowCaseCollisions: a.cfg.AllowCaseCollisions,
		})
	} else {
		res, err = a.indexer.Walk(ctx)
	}
	if err != nil {
		return nil, err
	}
	a.setWarnings(walkWarnings(res))
	a.setFileCount(len(res.Files))
	return res.Files, nil
}

// enforceSecretIndexInvariant checks that no hidden secret is in the search
// index, and repairs it if one is.
//
// store.IndexSecretText refuses anything that is not table-visible, so this
// should be structurally impossible; that is exactly why it is checked on every
// boot. The finding is loud — logged, audited, repaired, and left in the boot
// report — and the boot continues, because a poisoned cache that made the app
// unbootable would be a denial of service created by a bug.
func (a *App) enforceSecretIndexInvariant(ctx context.Context) error {
	leaked, err := store.CheckSecretIndexInvariant(ctx, a.db.Reader())
	if err != nil {
		return err
	}
	if leaked == 0 {
		return nil
	}
	finding := strconv.FormatInt(leaked, 10) +
		" hidden secret bodies were in the search index and have been removed from it"
	a.log.ErrorContext(ctx, "a hidden secret was found in the search index",
		"action", "fts.invariant", "rows", leaked)
	a.auditContext(ctx, "a hidden secret was found in the search index and the index was rebuilt",
		"action", "fts.invariant", "reason", "a non-table-visible secret body was in the search index")
	// RebuildSecretFTS drops every non-table body from secret_text and
	// repopulates it from the secrets table, so a rebuild is a real repair and
	// not a gesture.
	if err := a.rebuildFTS(ctx, true); err != nil {
		return err
	}
	still, err := store.CheckSecretIndexInvariant(ctx, a.db.Reader())
	if err != nil {
		return err
	}
	if still != 0 {
		// Unreachable while the foreign key holds: a rebuild removes every row
		// the check counts. It is asserted rather than assumed, because this is
		// the one place where "it cannot happen" would be a silent leak.
		return fmt.Errorf("%d hidden secret bodies are still in the search index after a rebuild", still)
	}
	a.addWarning(finding)
	return nil
}

// prune drops the rows that expired while the app was not running.
func (a *App) prune(ctx context.Context) error {
	now := a.clock().UTC()
	if _, err := store.DeleteExpiredSessions(ctx, a.db.Writer(), now); err != nil {
		return err
	}
	if _, err := store.DeleteExpiredInvites(ctx, a.db.Writer(), now); err != nil {
		return err
	}
	if _, err := a.selfwrites.Prune(ctx); err != nil {
		return err
	}
	return nil
}

// startBackground starts the watcher and the reconciliation loop.
//
// The reconciliation loop is the only caller of Reconcile. vault.Scanner keeps
// plain maps and is documented for one goroutine, and the watcher's batches go
// through the indexer rather than through here — that is what keeps the
// sixty-second pass single-owner instead of merely usually-single-owner.
func (a *App) startBackground() error {
	// The context is created here and only its cancel function is kept, because
	// a context is not stored in a struct; the goroutine receives it as an
	// argument like everything else.
	ctx, cancel := context.WithCancel(context.Background())
	a.bgCancel = cancel

	w, err := a.indexer.Watch(ctx)
	if err != nil {
		cancel()
		a.bgCancel = nil
		return err
	}
	a.watcher = w
	a.reconcileEnd = make(chan struct{})
	go a.reconcileLoop(ctx, a.reconcileEnd)
	return nil
}

// reconcileLoop is the sixty-second scan, in the only goroutine that owns it.
func (a *App) reconcileLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, err := a.indexer.Reconcile(ctx)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				a.log.WarnContext(ctx, "a reconciliation pass failed; the next one will try again",
					"action", "index.reconcile", "err", err.Error())
				continue
			case !res.Changed():
				continue
			}
			a.refreshStatus(ctx)
			a.setIndexedAt()
		}
	}
}

// bind opens the listening socket. Serving is a separate step so that the
// banner can be written in between.
func (a *App) bind() error {
	if a.cfg.Host == "" {
		// An empty host binds every interface, and this process holds plaintext
		// DM secrets. config.Load defaults it to loopback; a hand-built Config
		// that omits it gets a refusal rather than a LAN listener.
		return errors.New("boot: a handler was supplied but no bind address is configured: set Host and Port")
	}
	ln, err := net.Listen("tcp", a.cfg.Addr())
	if err != nil {
		return fmt.Errorf("boot: listen on %s: %w", a.cfg.Addr(), err)
	}
	a.addr = ln.Addr().String()
	a.setAddr(a.addr)
	a.listener = ln
	return nil
}

// serve starts accepting connections.
func (a *App) serve() error {
	if a.handler == nil {
		// A nil Handler on an http.Server means DefaultServeMux, which would
		// serve whatever another package in the binary registered. A listener
		// that answers is a promise about what is being served, so this refuses
		// rather than falls back.
		return errors.New("boot: no handler is mounted; nothing to serve")
	}
	srv := &http.Server{
		Handler:           a.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		// No WriteTimeout, deliberately. The live-push stream is a legitimate
		// response that never ends, and a write deadline is exactly the wrong
		// way to kill it: the client would be disconnected mid-campaign rather
		// than told to refetch. The read side is bounded, keep-alive is bounded,
		// and the number of concurrent streams is the stream endpoint's own cap.
		IdleTimeout: idleTimeout,
		// net/http's own error log is unstructured and unsanitised; routing it
		// through obs means a handler that logs a request body cannot smuggle it
		// past the redacting handler by making the server print something.
		ErrorLog: slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}
	a.server = srv
	go func() {
		if err := srv.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("the listener stopped", "action", "http.serve", "err", err.Error())
		}
	}()
	a.log.Info("listening", "action", "http.listen", "addr", a.addr)
	return nil
}

// Run blocks until ctx is cancelled and then shuts the app down.
//
// The shutdown gets a fresh context: the caller's is already cancelled, and a
// graceful drain that inherits a dead deadline is not a graceful drain.
func (a *App) Run(ctx context.Context) error {
	<-ctx.Done()
	shutdown, cancel := boundedContext()
	defer cancel()
	return a.Shutdown(shutdown)
}

// Shutdown stops everything Boot started, in the reverse of the order it
// started it, and is idempotent.
//
// The listener goes first so no new request arrives while the index is being
// put away, then the watcher, then the reconciliation goroutine — a scan that
// is still running must be finished before the database it writes to is closed
// — and only then the database and the lock.
func (a *App) Shutdown(ctx context.Context) error {
	a.stopOnce.Do(func() { a.stopErr = a.stop(ctx) })
	return a.stopErr
}

func (a *App) stop(ctx context.Context) error {
	var errs []error

	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			// Shutdown only fails on a deadline, so the connections are still
			// open: Close is what actually ends them.
			errs = append(errs, a.server.Close())
		}
	}
	if a.watcher != nil {
		if err := a.watcher.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stop the vault watcher: %w", err))
		}
	}
	if a.bgCancel != nil {
		a.bgCancel()
	}
	if a.reconcileEnd != nil {
		select {
		case <-a.reconcileEnd:
		case <-ctx.Done():
			// Reported and not waited for: a shutdown that hangs forever on a
			// scan the operator has already interrupted is worse than a log
			// line. The database close below is the hard deadline.
			errs = append(errs, errors.New("the reconciliation scan did not finish before the shutdown deadline"))
		}
	}
	if a.db != nil {
		errs = append(errs, a.db.Close())
	}
	if a.auditFile != nil {
		errs = append(errs, a.auditFile.Close())
	}
	// Last, and on every path: the lock is what keeps a second process out, and
	// a process that is giving up must not leave it held.
	if a.lock != nil {
		a.lock.Release()
	}
	return errors.Join(errs...)
}

// Status returns the boot report. It is a copy, including the warnings, so a
// caller cannot reach into the app's state through it.
func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.status
	out.Warnings = make([]string, 0, len(a.bootWarnings)+len(a.passWarnings))
	out.Warnings = append(out.Warnings, a.bootWarnings...)
	out.Warnings = append(out.Warnings, a.passWarnings...)
	return out
}

// DB returns the index database.
func (a *App) DB() *store.DB { return a.db }

// Indexer returns the indexer, which is what re-indexes a page after a save and
// what the reconciliation scan runs on.
func (a *App) Indexer() *isync.Indexer { return a.indexer }

// Vault returns the only writer a vault file may be changed through.
func (a *App) Vault() *vault.Writer { return a.writer }

// Bus returns the invalidation bus a live-push subscriber registers with. It
// carries a trigger and never content: a subscriber fetches the page again with
// its own principal.
func (a *App) Bus() *isync.Bus { return a.bus }

// Log returns the logger the app records its own boot and lifecycle events on.
func (a *App) Log() *obs.Logger { return a.log }

// IndexFileCount is how many files the last full pass read. It is the
// difference between "the app found 200 pages" and "the app indexed 200 of 214
// files", which is the number an operator with an unreadable file needs.
func (a *App) IndexFileCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fileCount
}

// lastResult is what the boot's indexing pass did, for a command that would
// otherwise run a second one to find out.
func (a *App) lastResult() isync.BatchResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastPass
}

// addWarning records something the operator should know about, in order.
func (a *App) addWarning(w string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bootWarnings = append(a.bootWarnings, w)
}

// setWarnings replaces the last indexing pass's refusals with these.
func (a *App) setWarnings(ws []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.passWarnings = append([]string(nil), ws...)
}

func (a *App) setFileCount(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fileCount = n
}

func (a *App) setLastPass(res isync.BatchResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastPass = res
}

func (a *App) setVaultFacts() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.Vault = a.root
	a.status.VaultSource = a.vaultSource
	a.status.Campaign = campaignName(a.root)
}

func (a *App) setAddr(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.Addr = addr
}

func (a *App) setSchemaVersion(v int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.SchemaVersion = "v" + strconv.Itoa(v)
}

func (a *App) setBootState(state string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.BootState = state
}

func (a *App) setIndexedAt() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.IndexedAt = a.clock()
}

// refreshStatus re-reads the counts the boot report carries. A failure is
// logged rather than propagated: the report is a convenience and the boot that
// produced it has already succeeded.
func (a *App) refreshStatus(ctx context.Context) {
	pages, err := store.CountPages(ctx, a.db.Reader())
	if err != nil {
		a.log.WarnContext(ctx, "could not count the indexed pages",
			"action", "boot.status", "err", err.Error())
		return
	}
	generation, err := store.AuthzGeneration(ctx, a.db.Reader())
	if err != nil {
		a.log.WarnContext(ctx, "could not read the authorization generation",
			"action", "boot.status", "err", err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.PageCount = int(pages)
	a.status.AuthzGeneration = generation
}

// boundedContext is the context a shutdown gets when the caller's is already
// finished: the signal context is cancelled by the very signal that started the
// shutdown, so it cannot also be the deadline for it.
func boundedContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ShutdownTimeout)
}

// walkWarnings turns what the walk refused into lines the banner can print.
//
// Every one of these is a file the operator believes is in their campaign and
// is not in the index. Silence would make "the app ignored 14 files" a mystery,
// so each refusal is counted or named.
func walkWarnings(res vault.WalkResult) []string {
	var out []string
	for _, group := range res.CaseCollisions {
		// Reachable only with --allow-case-collisions: otherwise the walk stops
		// with a CaseCollisionError and Boot fails.
		out = append(out, fmt.Sprintf("%d paths collide on a case-insensitive filesystem and were indexed as one: %s",
			len(group), strings.Join(group, ", ")))
	}
	if res.Ignored > 0 {
		out = append(out, fmt.Sprintf("%d paths were ignored by name and are not indexed", res.Ignored))
	}
	for _, u := range res.Unreadable {
		out = append(out, "not indexed: "+u.Path+": "+u.Reason)
	}
	for _, s := range res.SymlinksOutside {
		out = append(out, "symlink not followed, it points outside the vault: "+s)
	}
	if len(res.Symlinks) > 0 {
		out = append(out, fmt.Sprintf("%d symlinks inside the vault were indexed; a link to a directory is listed but not descended",
			len(res.Symlinks)))
	}
	return out
}
