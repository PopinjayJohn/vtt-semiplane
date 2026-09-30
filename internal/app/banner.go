package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// PrintBanner writes the boot report, one line per fact.
//
// Every value here is a fact about the process — a path, a count, a version, a
// warning about a file that was not indexed. No page title, no secret id and no
// file body appears, and none can: nothing in this package holds a page's
// content, because the only thing that reads vault bytes is the indexer and it
// keeps them.
//
// report is what the plugin lifecycle produced. It is passed in rather than
// read from the App because a banner is also rendered by callers that hold a
// Status and nothing else, and a report reached by a global would be a fact
// about a package rather than about this boot.
func PrintBanner(w io.Writer, st Status, report plugin.Report) {
	// The version line is not a labelled fact, so it is written straight to the
	// writer: inside the tabwriter it would set the label column to its own
	// width and push every other value to the right edge of the terminal.
	_, _ = fmt.Fprintf(w, "%s\n", Info().String())
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	printAddress(tw, st)
	printReport(tw, st, report)
	_ = tw.Flush()
}

// printAddress is which vault this is and how it was chosen.
//
// The second line is labelled "vault name" and not "campaign" on purpose. It
// holds the vault directory's own basename, which is not a campaign name, and
// once the bundled sample campaign arrived the word "campaign" in this banner
// named something else entirely — a reader would take it for the sample's
// title. The boot log is where the sample is reported, by its own name.
func printAddress(w io.Writer, st Status) {
	_, _ = fmt.Fprintf(w, "vault:\t%s (%s)\n", st.Vault, st.VaultSource)
	_, _ = fmt.Fprintf(w, "vault name:\t%s\n", st.Campaign)
}

// printReport is what the index holds and what the process is doing with it.
func printReport(w io.Writer, st Status, report plugin.Report) {
	_, _ = fmt.Fprintf(w, "index:\t%d pages, schema %s, %s, authz generation %d\n",
		st.PageCount, st.SchemaVersion, st.BootState, st.AuthzGeneration)
	if st.Addr == "" {
		_, _ = fmt.Fprintf(w, "listen:\t%s\n", "not listening")
	} else {
		_, _ = fmt.Fprintf(w, "listen:\t%s (%s)\n", st.Addr, urlFor(st.Addr))
	}
	printPlugins(w, report)
	if !st.IndexedAt.IsZero() {
		_, _ = fmt.Fprintf(w, "indexed:\t%s\n", st.IndexedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	printWarnings(w, st.Warnings)
}

// printPlugins is the plugin boot report, in the banner's own shape.
//
// The count is the registered ones and only the registered ones, because a
// plugin the host refused and a plugin this build never offered are different
// facts and a single number cannot hold both. The refusals are therefore named
// under the count, in the same "- " form the walk's own warnings use: a panel
// that is missing is not actionable and "the plugin was refused because it
// claims a reserved page type without the capability" is.
//
// A compat entry is registered, so it is counted and not listed here; the
// per-plugin state including version skew is in `plugins list` and in
// /admin/plugins.
func printPlugins(w io.Writer, report plugin.Report) {
	_, _ = fmt.Fprintf(w, "plugins:\t%d registered\n", len(report.OKs()))
	for _, e := range report.Skipped() {
		_, _ = fmt.Fprintf(w, "\t- not registered: %s: %s\n", e.ID, e.Reason)
	}
}

// printWarnings says what the vault walk refused.
//
// A file that was skipped is a page the DM believes is in their campaign and is
// not in the index, so it is named on the console rather than left to be
// discovered as a broken wikilink weeks later.
func printWarnings(w io.Writer, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "warnings:\t%d\n", len(warnings))
	for _, warning := range warnings {
		_, _ = fmt.Fprintf(w, "\t- %s\n", warning)
	}
}

// urlFor is the address a browser can open, for the line the plan asks the
// banner to print.
func urlFor(addr string) string {
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	switch host {
	case "0.0.0.0", "[::]", "::", "":
		// A wildcard bind is not an address a browser can use; loopback is what
		// the same machine can reach it on.
		return "http://127.0.0.1:" + addr[strings.LastIndex(addr, ":")+1:] + "/"
	}
	return "http://" + addr + "/"
}

// PluginsList writes the plugin boot report, which is what `semiplane plugins
// list` prints and what the admin plugins page will render.
//
// It runs the lifecycle against a host with no vault behind it, rather than
// reading the report a boot produced, because the question the command answers
// is about the *build* — the same class of question `version` answers, and for
// the same reason it is answered before anything is resolved, locked or
// opened. A command that asked which plugins a binary has must not need a
// vault, must not take the single-instance lock, and must not create a vault on
// a machine that has none.
//
// The gap that buys is the database: a plugin's schema steps and its persisted
// configuration are the two things only a vault can answer, so a refusal caused
// by either is a refusal a boot will report and this will not. Everything else
// the lifecycle decides — the API-level gate, the descriptor checks, the
// reserved names, the kind rules, the claims, the plugin's own Register and
// Validate — it decides here, with the real plugins and the real host
// vocabulary. The caveat is printed, because a report that cannot be complete
// and does not say so is the failure mode this command exists to avoid.
//
// There is no error: plugin.Load reports a plugin's failure in the report and
// in the log rather than as an error, and that is exactly the property that
// lets a boot survive a plugin nobody can fix from a console.
func PluginsList(ctx context.Context, opts Options, out io.Writer) {
	_, report := plugin.Load(ctx, vaultlessPluginDeps(opts.withDefaults()), offeredPlugins(opts)...)
	printPluginTable(out, report)
}

// printPluginTable is the whole report: the conditions it was produced under,
// the objections the host recorded, and one row per plugin that was offered,
// healthy or not.
//
// The rows come last so that the table is everything from its header to the end
// of the output. A table followed by a sentence is a format in which "id state
// reason" and a warning are told apart by how many words they happen to have,
// and anything that reads this output would then be reading prose as a plugin.
func printPluginTable(w io.Writer, report plugin.Report) {
	if len(report.Entries) == 0 {
		_, _ = fmt.Fprintln(w, "0 plugins registered")
		_, _ = fmt.Fprintln(w, "this build offers no plugins; the registry is one map entry in cmd/semiplane/registry.go")
		return
	}
	_, _ = fmt.Fprintln(w, "loaded with no vault behind it: a plugin refused for its schema steps or its stored configuration would still register at boot")
	// A dropped contribution is a warning about a plugin that registered, so it
	// belongs with the conditions rather than inside the table: the rows are
	// outcomes and these are the host's objections to part of one.
	printWarnings(w, report.Warnings)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tSTATE\tREASON")
	for _, e := range report.Entries {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", e.ID, e.Status, e.Reason)
	}
	_ = tw.Flush()
}

// vaultlessPluginDeps is the host a plugin load can be given when there is no
// vault. Every field is either the real thing or a documented nil, and each
// choice is load-bearing rather than a placeholder.
//
// The nil-able fields are the host's own contract: a nil Config is an empty
// configuration, a nil FS is the refusal plugins.go records on purpose, and a
// nil PageStore is an empty store rather than a nil interface to dereference.
// The two that are supplied are supplied because their absence is a *false*
// report rather than a narrower one: without a clock a plugin captures the zero
// time, and without a sub-router host.mux is nil, so a plugin that registers a
// route panics and lands in the report as skipped — the one case where a
// report that is merely incomplete would instead be wrong.
func vaultlessPluginDeps(opts Options) plugin.PluginDeps {
	return plugin.PluginDeps{
		Now: opts.Clock,
		Log: func(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {
			fields := make([]any, 0, len(kv)*2)
			for _, p := range kv {
				fields = append(fields, p.Key, p.Value)
			}
			opts.Logger.Log(ctx, obsLevel(l), "plugin: "+msg, fields...)
		},
		// A plugin migration needs a transaction, and the transaction is the
		// database the vault would have supplied. Returning nil is not a claim
		// that the steps applied — nothing records that they were skipped —
		// which is why the caveat the table prints names schema steps
		// explicitly.
		Migrations: func(context.Context, string, []plugin.Migration) error { return nil },
		SubRouter:  func(string) plugin.RouteMounter { return chi.NewRouter() },
		Pages:      nil,
		Config:     nil,
		FS:         nil,
	}
}

// offeredPlugins is opts.Plugins in sorted order, which is the order the
// lifecycle would offer them in and therefore the order a report is stable in.
func offeredPlugins(opts Options) []plugin.Plugin {
	out := make([]plugin.Plugin, 0, len(opts.Plugins))
	for _, id := range sortedPluginIDs(opts.Plugins) {
		out = append(out, opts.Plugins[id])
	}
	return out
}
