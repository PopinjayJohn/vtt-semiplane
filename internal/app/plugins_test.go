package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
)

// The boot report is the product.
//
// A plugin that fails silently fails permanently, so what matters is not only
// that plugins register — it is that the boot says which ones did, which did
// not, and why. These tests drive the lifecycle through a real boot and read the
// report the way /admin/plugins reads it.

// TestABootWithNoPluginsReportsNone is the case every deployment starts from,
// and the one a registry only exercised on a developer machine would get wrong.
func TestABootWithNoPluginsReportsNone(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.withHandler())

	report := a.PluginReport()
	if len(report.Entries) != 0 {
		t.Errorf("a boot with no plugins reported %d entries: %v", len(report.Entries), report.Entries)
	}
	if a.PluginRegistry() == nil {
		t.Error("PluginRegistry returned nil for a boot that ran the lifecycle: every reader nil-checks, " +
			"so a nil here reads as \"no lifecycle ran\" when one did, and /admin/plugins says so out loud")
	}
}

// TestTheRegistryIsAWorkingEmptyRegistry reads every accessor on a build that
// ships no plugins.
//
// A registry that panics on an empty read is a registry that works only on the
// machine it was built on, and the empty case is the one that is actually tested
// unless someone writes this.
func TestTheRegistryIsAWorkingEmptyRegistry(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	a := f.boot(t, f.withHandler())
	reg := a.PluginRegistry()

	if got := reg.NavItems(); len(got) != 0 {
		t.Errorf("NavItems = %v, want empty", got)
	}
	if got := reg.Panels(); len(got) != 0 {
		t.Errorf("Panels = %v, want empty", got)
	}
	if got := reg.PanelsFor("character"); len(got) != 0 {
		t.Errorf("PanelsFor = %v, want empty", got)
	}
	if got := reg.PageTypes(); len(got) != 0 {
		t.Errorf("PageTypes = %v, want empty", got)
	}
	if got := reg.SearchResolvers(); len(got) != 0 {
		t.Errorf("SearchResolvers = %v, want empty", got)
	}
	if got := reg.Summaries(); len(got) != 0 {
		t.Errorf("Summaries = %v, want empty", got)
	}
	if got := reg.Routes(); len(got) != 0 {
		t.Errorf("Routes = %v, want empty", got)
	}
	if _, ok := reg.PageType("character"); ok {
		t.Error("a build with no plugins resolved the character page type")
	}
	if _, ok := reg.Plugin("dnd5e"); ok {
		t.Error("a build with no plugins resolved the dnd5e plugin")
	}
	if reg.Report().HasKind(plugin.KindSystem) {
		t.Error("a build with no plugins reported a system kind present")
	}
}

// TestAPluginThatCannotRegisterIsRecordedRatherThanFatal is the containment rule
// from the other end: the boot continues.
//
// The alternative is a campaign that will not start because of a plugin nobody
// is using, which turns a small problem into an outage and hides the reason
// behind a stack trace nobody reads.
func TestAPluginThatCannotRegisterIsRecordedRatherThanFatal(t *testing.T) {
	t.Parallel()
	f := newFixture(t, campaignFiles())
	opts := f.withHandler()
	opts.Plugins = map[string]plugin.Plugin{
		"broken": alwaysFails{},
	}
	a := f.boot(t, opts)

	report := a.PluginReport()
	if len(report.Entries) != 1 {
		t.Fatalf("the report has %d entries, want 1: %v", len(report.Entries), report.Entries)
	}
	e := report.Entries[0]
	if e.Status != plugin.StatusSkipped {
		t.Errorf("status = %q, want %q", e.Status, plugin.StatusSkipped)
	}
	// The reason is the whole value of the report. "Skipped" with nothing after
	// it is indistinguishable from "not installed", and the difference is the
	// difference between a fixable problem and a mystery.
	if e.Reason == "" {
		t.Error("the entry is skipped with no reason: a skip without a reason cannot be acted on")
	}
	if len(report.Skipped()) != 1 {
		t.Errorf("Skipped() = %v, want the one entry", report.Skipped())
	}
	if len(report.OKs()) != 0 {
		t.Errorf("OKs() = %v, want empty", report.OKs())
	}
	// The boot produced a usable registry regardless.
	if a.PluginRegistry() == nil {
		t.Error("a boot with a failing plugin left no registry at all")
	}
}

// alwaysFails is a plugin that refuses to register.
//
// It is one type rather than three because the refusal is the point: a test that
// needs a *specific* failure belongs in internal/plugin, where the reason strings
// are the assertions. This one is for the boot's behaviour, which is identical
// whatever the reason was.
type alwaysFails struct{}

func (alwaysFails) Descriptor() plugin.Descriptor {
	return plugin.Descriptor{ID: "broken", Name: "Broken", Kind: plugin.KindFeature, Version: "0.0.1"}
}

func (alwaysFails) Register(context.Context, plugin.Host) error {
	return errors.New("this plugin declines to register")
}

func (alwaysFails) Validate(plugin.Config) error { return nil }

func (alwaysFails) Now() time.Time { return time.Time{} }
