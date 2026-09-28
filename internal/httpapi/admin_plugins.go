package httpapi

import (
	"net/http"
	"strconv"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
)

// noRegistryWarning is what the report says when the server holds no registry.
//
// It is a warning rather than an empty table because the two states are not the
// same state. An empty table over a loaded registry is a build that offers no
// plugins; an empty table over a nil one is a server whose plugin layer never
// ran at all, and a reader who cannot tell those apart will read the second as
// the first and go looking for a plugin to install.
const noRegistryWarning = "This server was booted without a plugin registry, so this report describes nothing about the plugin layer of this build."

// adminPluginsPage is the boot report: every plugin this binary offered at boot,
// what it was granted, what it contributed, and — for the ones that were not
// admitted — the whole reason it was not.
//
// There is no query and no database behind it. The boot already happened, the
// registry holds what it collected, and every read of it is a pure read, so the
// only thing this handler decides is which shape the report is shown in.
func (s *Server) adminPluginsPage(w http.ResponseWriter, r *http.Request) {
	view := bootReportView(s.bootReport())
	view.Shell = s.liveShell(r, "Plugins")
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the plugin boot report", err)
	}
}

// bootReport reads the registry, or reports that there was none.
//
// The nil check is on the interface value itself and never on the emptiness of
// what it returns. A nil Registry and a Registry holding nothing are different
// facts about this build — the first says the plugin lifecycle never ran here,
// the second says it ran and admitted nothing — and a check written as
// "if the report has no entries" cannot tell them apart. It would also panic on
// the nil case, which is the failure this function exists to prevent: a page
// whose job is to explain a build that is not working must be the last thing
// that breaks when the build is broken.
func (s *Server) bootReport() plugin.Report {
	if s.plugins == nil {
		return plugin.Report{Warnings: []string{noRegistryWarning}}
	}
	return s.plugins.Report()
}

// bootReportView projects a boot report onto the view model.
//
// It is a function of its own so that the counting and the joining live in one
// place rather than being split between a handler and a template, where a count
// that disagreed with the list it counts could only be found by reading a
// rendered page. Nothing in it needs a request, a session or a vault, and the
// tests drive it through the route rather than calling it — the package's tests
// are the external `httpapi_test` one, so a private function is not reachable
// from them, and a claim about the joining that is only asserted against markup
// is the claim that actually has to hold.
func bootReportView(report plugin.Report) AdminPluginsView {
	view := AdminPluginsView{
		Lines: reportLines(report.Entries),
		// Copied rather than aliased. The registry is immutable once it is built,
		// so sharing would be safe today; a view model is a security boundary and
		// the boundary should not depend on a promise another package makes.
		Warnings: append([]string(nil), report.Warnings...),
		// The host's own numbers rather than the rows'. They are what every row's
		// API level is measured against, and repeating them per row is how a
		// reader ends up comparing a plugin against a plugin.
		HostLevel: plugin.APILevel,
		APIWindow: plugin.APIWindow,
	}
	// The three counters partition the report: a row is registered, skipped or
	// running the shim, and exactly one of the three is true of it. They are
	// counted from the statuses rather than from lengths so that the headline
	// and the rows cannot disagree. A status this switch does not know is
	// counted in none of them, which is visible: the row is still listed, with
	// whatever status it carries, so an unrecognised one shows up as a fourth
	// kind of row rather than as an arithmetic error.
	for _, e := range report.Entries {
		switch e.Status {
		case plugin.StatusOK:
			view.Registered++
		case plugin.StatusCompat:
			view.Compat++
		case plugin.StatusSkipped:
			view.Skipped++
		}
	}
	return view
}

// reportLines is one view row per report entry.
//
// The rows are in the report's own order and are deliberately not re-sorted
// here. The registry already sorts by id, and a second sort would be a second
// answer to "what order is the report in" that could disagree with the first —
// and this page is read beside `semiplane plugins list` and beside the boot
// log, so an order that matched neither of those would be an order nobody could
// check their reading against.
func reportLines(entries []plugin.Entry) []PluginReportLine {
	if len(entries) == 0 {
		return nil
	}
	out := make([]PluginReportLine, 0, len(entries))
	for _, e := range entries {
		out = append(out, PluginReportLine{
			ID:   e.ID,
			Name: e.Name,
			Kind: string(e.Kind),
			// The status and the reason go out verbatim. This is a projection, not
			// a report of its own: a host that refused a plugin wrote the reason,
			// and paraphrasing it here is a second place to be wrong about why.
			Status:    string(e.Status),
			Reason:    e.Reason,
			Version:   e.Version,
			APILevel:  e.APILevel,
			HostLevel: e.HostLevel,
			// Capabilities.List is in the plugin package's declaration order, which
			// is a fixed table rather than a map walk, so two renders of one boot
			// agree down to the row.
			Capabilities: capabilityNames(e.Capabilities),
			Counts:       contributionCounts(e.Count),
		})
	}
	return out
}

// capabilityNames is the granted set as display strings.
//
// A plugin granted nothing says so rather than rendering an empty cell. An
// empty cell is a column that failed to render, and "this plugin was granted
// nothing" is a fact a refused capability declaration turns on: a plugin that
// asked for CapUIPanels and did not get it is exactly the row where the
// difference matters.
func capabilityNames(granted plugin.Capabilities) []string {
	list := granted.List()
	if len(list) == 0 {
		return []string{"none granted"}
	}
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, string(c))
	}
	return out
}

// contributionCounts is what a plugin contributed, as one phrase per non-zero
// count.
//
// Two rules, both load-bearing. Only the non-zero counts are listed, because
// "0 search resolvers, 0 summaries, 0 routes" on a row that contributed a page
// type and two panels buries the two facts that matter under six absences. And
// a plugin that contributed nothing at all says "no contributions" rather than
// nothing, because a plugin that registered and added nothing is a different
// fact from a plugin that was never offered — and the second one is not in this
// report at all, which is what makes the two indistinguishable if the first one
// renders as an empty cell.
//
// The order is the Contribution struct's field order, fixed here rather than
// left to a map, so that the cell reads the same on every render and a test can
// assert the whole string.
func contributionCounts(c plugin.Contribution) []string {
	parts := make([]string, 0, 8)
	for _, part := range []struct {
		n        int
		singular string
		plural   string
	}{
		{c.PageTypes, "page type", "page types"},
		{c.Panels, "panel", "panels"},
		{c.NavItems, "nav item", "nav items"},
		{c.SearchResolvers, "search resolver", "search resolvers"},
		{c.Summaries, "summary", "summaries"},
		{c.Routes, "route", "routes"},
		{c.Extenders, "extender", "extenders"},
		{c.Migrations, "migration", "migrations"},
	} {
		if part.n > 0 {
			parts = append(parts, countPhrase(part.n, part.singular, part.plural))
		}
	}
	if len(parts) == 0 {
		return []string{"no contributions"}
	}
	return parts
}

// countPhrase is "3 panels" or "1 panel".
//
// The singular is spelled out rather than left to a caller appending an "s",
// because "1 search resolvers" is the kind of thing that ships.
func countPhrase(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}
