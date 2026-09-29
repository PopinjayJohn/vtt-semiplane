package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The exit codes. A boot failure is 1, a usage mistake is 2, and a clean
// shutdown is 0 — including a SIGINT that arrived while serving, because a
// service that stopped because it was told to did not fail.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// usageLine is what a usage error prints, and the list of commands it names is
// the list this binary dispatches: run has no other table, so a command added to
// the switch without a mention here would be a command the help does not
// promise.
const usageLine = "usage: semiplane [--vault PATH] [--host H] [--port P] [serve|reindex|backup|restore|vault info|plugins list|version]"

// subcommandFlags are the flags each command accepts for itself.
//
// config has no reason to know them — it is the package that parses, not the
// one that dispatches — so it passes an argument it does not recognise through
// as one of the command's own, and this is where it is checked. It is the one
// list the executable still keeps, and it is a list of *commands'* flags rather
// than a second copy of the global flag set, so a new global flag cannot go
// missing from it.
var subcommandFlags = map[string]map[string]bool{
	"reindex": {"--full": true, "-full": true},
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is main, with the process globals as parameters so a test can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	// config reads the subcommand out of the arguments and puts the flags
	// before it, so every spelling of a command parses the same way. An
	// executable-side partitioner is what this replaced: it had to know which
	// flags take a value, and a flag it did not know was dropped rather than
	// refused.
	cfg, err := config.Load(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		// flag.Parse has already printed the whole flag set's usage.
		return exitOK
	case err != nil:
		fmt.Fprintln(stderr, "semiplane: "+err.Error())
		return exitUsage
	}
	if helpRequested(cfg) {
		// `--help` written after a subcommand reaches here as that subcommand's
		// own argument, and config cannot answer it: it does not know which
		// command is coming, and refusing the flag would be worse than both
		// answering it and ignoring it.
		fmt.Fprintln(stderr, usageLine)
		return exitOK
	}
	if bad := unexpectedFlag(cfg); bad != "" {
		fmt.Fprintln(stderr, "semiplane: "+bad)
		fmt.Fprintln(stderr, usageLine)
		return exitUsage
	}

	switch cfg.Command {
	case "", "serve":
		return serve(cfg, stdout, stderr)

	case "version":
		// The one command that must work with no vault at all: it reports what
		// was linked into this binary, so it is answered before anything is
		// resolved, locked or opened. A wrong --vault is irrelevant to it.
		fmt.Fprintln(stdout, app.Info())
		return exitOK

	case "reindex":
		return report(stderr, app.Reindex(context.Background(), options(cfg, stderr), stdout, wantsFullReindex(cfg)))

	case "backup":
		return report(stderr, app.Backup(context.Background(), options(cfg, stderr), stdout, cfg.BackupOut))

	case "restore":
		return report(stderr, app.Restore(context.Background(), options(cfg, stderr), stdout, cfg.RestoreFrom, cfg.Force))

	case "vault":
		return vaultCommand(cfg, stdout, stderr)

	case "plugins":
		return pluginsCommand(cfg, stdout, stderr)

	default:
		fmt.Fprintf(stderr, "semiplane: unknown command %q\n", cfg.Command)
		fmt.Fprintln(stderr, usageLine)
		return exitUsage
	}
}

// unexpectedFlag names a flag no command claims, or returns "" when there is
// none.
//
// config deliberately lets an unrecognised flag through to the command that
// might own it, so this is the last place a typo can be caught. Without it,
// `semiplane reindex --ful` would report a completed reindex of a vault the
// operator asked to rebuild in full, and a flag that is silently ignored is
// worse than one that is refused.
func unexpectedFlag(cfg config.Config) string {
	for _, arg := range cfg.SubArgs {
		if !strings.HasPrefix(arg, "-") {
			// An operand is the command's to check: `vault info` is a command
			// with an argument, not a flag.
			continue
		}
		if !subcommandFlags[cfg.Command][arg] {
			return fmt.Sprintf("unknown flag %q for %q", arg, displayCommand(cfg.Command))
		}
	}
	return ""
}

// displayCommand names the command in an error message, so an empty one reads
// as the default rather than as "".
func displayCommand(command string) string {
	if command == "" {
		return "serve"
	}
	return command
}

// helpRequested reports whether the subcommand's own arguments ask for the
// usage. Only the arguments config could not read are considered: it has already
// answered --help before the subcommand by returning flag.ErrHelp.
func helpRequested(cfg config.Config) bool {
	for _, name := range []string{"--help", "-h"} {
		if hasFlag(cfg.SubArgs, name) {
			return true
		}
	}
	return false
}

// serve is the default command: open the vault, index it, and serve until the
// process is asked to stop.
func serve(cfg config.Config, stdout, stderr io.Writer) int {
	// SIGINT and SIGTERM cancel the context, which is what unblocks Run and
	// gives the shutdown a deadline of its own. A second signal kills the
	// process outright, which is what an operator who has waited long enough
	// expects.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// app.Boot needs the handler in order to decide whether to bind, and the
	// handler needs the store and the indexer that Boot creates. A deferred
	// handler breaks that cycle: it is mounted immediately and the real one is
	// installed the moment Boot returns, so the window in which a request would
	// be answered 503 is the length of one function call rather than the length
	// of a reindex.
	mount := httpapi.NewDeferred()
	// The server is kept, not just its handler, because Shutdown on the router is
	// not enough: a live-push stream is an HTTP request that never finishes, and
	// http.Server.Shutdown waits for open requests. The registry has to be closed
	// first, and the registry belongs to the httpapi.Server rather than to the
	// stdlib one, so it is this reference that has to survive installHandler.
	var api *httpapi.Server
	a, err := app.Boot(ctx, app.Options{
		// The one map entry, from registry.go. The boot runs the plugin
		// lifecycle and hands back what it produced; installHandler below passes
		// that to the router.
		Plugins: builtinPlugins(),
		Config:  cfg,
		Handler: mount,
		Logger:  logger(cfg, stderr),
		Banner:  stdout,
		Reindex: cfg.Reindex,
	})
	if err != nil {
		fmt.Fprintln(stderr, "semiplane: "+err.Error())
		return exitFailure
	}
	if a.Status().Addr == "" {
		// The vault was locked, migrated and indexed, and then released again.
		// Saying so is the difference between a build whose router has not
		// landed yet and a server that is broken; exiting non-zero is because
		// the operator asked to serve and was not served.
		fmt.Fprintln(stderr, "semiplane: the vault was opened and indexed, but no HTTP handler is mounted in this build, so nothing is being served")
		shutdown(a, stderr)
		return exitFailure
	}
	if api, err = installHandler(cfg, a, mount, stderr); err != nil {
		fmt.Fprintln(stderr, "semiplane: "+err.Error())
		shutdown(a, stderr)
		return exitFailure
	}
	if err := a.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "semiplane: "+err.Error())
		return exitFailure
	}
	// Before a.Run's own shutdown would have run, and deliberately: the streams
	// have to be told to finish or a.Run's shutdown waits for a request that
	// ends when the client leaves. A reader who closed their laptop is not a
	// reader who should hold the process open.
	if api != nil {
		// A failure here is a deadline the operator already set, so it is
		// reported rather than returned: the exit code of this function is
		// decided by whether the campaign was served, and a slow reader who
		// would not let go is not a reason to call the run a failure.
		if err := api.Shutdown(context.Background()); err != nil {
			logger(cfg, stderr).Warn("the live-update streams did not all finish",
				"action", "http.events.shutdown", "err", err.Error())
		}
	}
	return exitOK
}

// installHandler builds the HTTP surface and mounts it.
//
// The route table, the middleware chain and every handler live in internal/httpapi;
// the templates live in internal/web, which sits above it in the dependency
// order and is handed to the router as an interface. This function is the only
// place the two are wired together, so the dependency between them is one call
// rather than an import in a dozen files.
func installHandler(cfg config.Config, a *app.App, mount *httpapi.Deferred, stderr io.Writer) (*httpapi.Server, error) {
	srv, err := httpapi.New(httpapi.Options{
		Config:        cfg,
		DB:            a.DB(),
		Writer:        a.Vault(),
		Reindexer:     a.Indexer(),
		AuthorRetryer: a.Indexer(),
		Bus:           a.Bus(),
		Log:           a.Log(),
		Build:         app.Info(),
		Assets:        web.Assets(),
		Renderer:      web.NewRenderer(),
		// What the boot's plugin lifecycle produced. It is nil in a boot that ran
		// no lifecycle — a one-shot command, or a test — and the request path
		// reads that as "no plugins" and /admin/plugins renders an explicit empty
		// state rather than an empty table that would read as a build offering
		// none.
		Plugins: a.PluginRegistry(),
	})
	if err != nil {
		return nil, err
	}
	mount.Install(srv.Handler())
	return srv, nil
}

// vaultCommand dispatches `vault info`, the only vault subcommand.
func vaultCommand(cfg config.Config, stdout, stderr io.Writer) int {
	switch {
	case len(cfg.SubArgs) == 0, len(cfg.SubArgs) == 1 && cfg.SubArgs[0] == "info":
		return report(stderr, app.VaultInfo(context.Background(), options(cfg, stderr), stdout))
	default:
		fmt.Fprintf(stderr, "semiplane: unknown vault subcommand %q; the only one is info\n", strings.Join(cfg.SubArgs, " "))
		return exitUsage
	}
}

// pluginsCommand dispatches `plugins list`, the only plugins subcommand.
//
// It is the only command that does not boot: what it answers is a fact about
// the build — the same class of question `version` answers — and an operator
// asking it has no vault yet in the common case, so taking the lock, creating
// one and walking it would be a strange price for a list.
func pluginsCommand(cfg config.Config, stdout, stderr io.Writer) int {
	switch {
	case len(cfg.SubArgs) == 0, len(cfg.SubArgs) == 1 && cfg.SubArgs[0] == "list":
		opts := options(cfg, stderr)
		// The one map entry, from registry.go, and the same one the serve path
		// boots with: a build offering a plugin to one command and not the
		// other would report two different sets of them.
		opts.Plugins = builtinPlugins()
		app.PluginsList(context.Background(), opts, stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "semiplane: unknown plugins subcommand %q; the only one is list\n", strings.Join(cfg.SubArgs, " "))
		return exitUsage
	}
}

// options builds the app options for a command that does not serve. The banner
// is left unset because each of them prints its own summary of the same facts.
func options(cfg config.Config, stderr io.Writer) app.Options {
	return app.Options{Config: cfg, Logger: logger(cfg, stderr), Reindex: cfg.Reindex}
}

// logger writes human-readable records to stderr. The banner goes to stdout, so
// the two do not interleave in a terminal or in a log collector's field split.
func logger(cfg config.Config, stderr io.Writer) *obs.Logger {
	return obs.NewLogger(stderr, obs.Options{Level: obs.Level(cfg.LogLevel), Text: true})
}

// wantsFullReindex reports whether the operator asked for the search tables to
// be rebuilt as well as the index. Both spellings are accepted because config
// defines a global --reindex for the same thing.
func wantsFullReindex(cfg config.Config) bool {
	return cfg.Reindex || hasFlag(cfg.SubArgs, "--full")
}

// hasFlag reports whether a subcommand's own arguments name a flag. Both
// spellings count, because the flag package accepts both.
func hasFlag(args []string, name string) bool {
	single := strings.Replace(name, "--", "-", 1)
	for _, arg := range args {
		if arg == name || arg == single {
			return true
		}
	}
	return false
}

// report runs a one-shot command and turns its error into an exit code.
func report(stderr io.Writer, err error) int {
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(stderr, "semiplane: "+err.Error())
	return exitFailure
}

// shutdown stops a booted app on a path that is not Run's, so a failure to
// release the vault is reported rather than swallowed.
func shutdown(a *app.App, stderr io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), app.ShutdownTimeout)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		fmt.Fprintln(stderr, "semiplane: shutdown: "+err.Error())
	}
}
