package app

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// pluginEntry is one line of the plugin boot report.
//
// The state vocabulary is the plan's: ok, skipped with a reason, or compat for a
// plugin that is behind the host's API level. It is declared here rather than
// taken from the plugin package because the report is printed by the
// composition root, which is the only place that knows what was registered.
type pluginEntry struct {
	// ID is the plugin's id.
	ID string
	// State is ok, skipped or compat.
	State string
	// Reason is why a plugin was skipped or is running in compatibility mode.
	Reason string
}

// registeredPlugins is the plugin boot report.
//
// It is empty, and that is the truth: the plugin registry and the two plugins
// that will be its first entries arrive in the plugin phase. The banner and
// `plugins list` render this, so both report "0 registered" rather than
// inventing an entry, and the plugin phase fills in the table without changing
// either format.
func registeredPlugins() []pluginEntry { return nil }

// PrintBanner writes the boot report, one line per fact.
//
// Every value here is a fact about the process — a path, a count, a version, a
// warning about a file that was not indexed. No page title, no secret id and no
// file body appears, and none can: nothing in this package holds a page's
// content, because the only thing that reads vault bytes is the indexer and it
// keeps them.
func PrintBanner(w io.Writer, st Status) {
	// The version line is not a labelled fact, so it is written straight to the
	// writer: inside the tabwriter it would set the label column to its own
	// width and push every other value to the right edge of the terminal.
	fmt.Fprintf(w, "%s\n", Info().String())
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	printAddress(tw, st)
	printReport(tw, st)
	_ = tw.Flush()
}

// printAddress is which vault this is and how it was chosen.
func printAddress(w io.Writer, st Status) {
	fmt.Fprintf(w, "vault:\t%s (%s)\n", st.Vault, st.VaultSource)
	fmt.Fprintf(w, "campaign:\t%s\n", st.Campaign)
}

// printReport is what the index holds and what the process is doing with it.
func printReport(w io.Writer, st Status) {
	fmt.Fprintf(w, "index:\t%d pages, schema %s, %s, authz generation %d\n",
		st.PageCount, st.SchemaVersion, st.BootState, st.AuthzGeneration)
	if st.Addr == "" {
		fmt.Fprintf(w, "listen:\t%s\n", "not listening")
	} else {
		fmt.Fprintf(w, "listen:\t%s (%s)\n", st.Addr, urlFor(st.Addr))
	}
	fmt.Fprintf(w, "plugins:\t%d registered\n", len(registeredPlugins()))
	if !st.IndexedAt.IsZero() {
		fmt.Fprintf(w, "indexed:\t%s\n", st.IndexedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	printWarnings(w, st.Warnings)
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
	fmt.Fprintf(w, "warnings:\t%d\n", len(warnings))
	for _, warning := range warnings {
		fmt.Fprintf(w, "\t- %s\n", warning)
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
func PluginsList(w io.Writer) {
	entries := registeredPlugins()
	if len(entries) == 0 {
		fmt.Fprintln(w, "0 plugins registered")
		fmt.Fprintln(w, "no plugin is registered in this build; the registry arrives with the plugin phase")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tREASON")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.ID, e.State, e.Reason)
	}
	_ = tw.Flush()
}
