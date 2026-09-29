package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
)

// The banner's plugin line is a count, and a count is where a fact gets lost:
// a plugin the host refused and a plugin this build never offered are different
// problems with different fixes, and folding either into the other is how "the
// panel is missing" becomes a mystery instead of a line somebody can act on.

// sampleReport is a report with one of each outcome the vocabulary has, so
// every branch of the renderer is exercised by one banner.
func sampleReport() plugin.Report {
	return plugin.Report{
		Entries: []plugin.Entry{
			{ID: "zzz-registered", Status: plugin.StatusOK},
			{ID: "yyy-skewed", Status: plugin.StatusCompat},
			{ID: "aaa-refused", Status: plugin.StatusSkipped, Reason: "it claims the reserved page type character without the capability"},
			{ID: "bbb-refused", Status: plugin.StatusSkipped, Reason: "the page type it registers is already claimed"},
		},
		Warnings: []string{"plugin yyy-skewed: dropped a panel scoped to the unknown page type \"nonesuch\""},
	}
}

// bannerValue is the value the banner printed for one label, so a test asserts
// on the fact rather than on the padding a tabwriter chose.
func bannerValue(t *testing.T, banner, label string) string {
	t.Helper()
	for line := range strings.SplitSeq(banner, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t"), label+":")
		if ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("the banner has no %q line:\n%s", label, banner)
	return ""
}

func TestTheBannerCountsOnlyWhatRegistered(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	PrintBanner(&out, Status{Vault: "/v", Addr: "127.0.0.1:8080"}, sampleReport())
	got := out.String()

	// ok and compat are both registered: a compat plugin is running with the
	// shim, and counting it as absent would hide version skew that the
	// lifecycle went out of its way to make visible.
	if v := bannerValue(t, got, "plugins"); v != "2 registered" {
		t.Errorf("plugins line is %q, want the two registered plugins:\n%s", v, got)
	}
	// The two refusals are named, with the reason, because "skipped" without a
	// reason is indistinguishable from "not installed".
	for _, want := range []string{"aaa-refused", "bbb-refused", "already claimed"} {
		if !strings.Contains(got, want) {
			t.Errorf("the banner does not name the refusal %q:\n%s", want, got)
		}
	}
}

// TestTheBannerDoesNotFlattenARefusalIntoAnAbsence is the other half of the
// count: a build whose every plugin was refused must not read as a build with
// no plugins, which is the state the banner used to report on every boot.
func TestTheBannerDoesNotFlattenARefusalIntoAnAbsence(t *testing.T) {
	t.Parallel()
	refused := plugin.Report{Entries: []plugin.Entry{
		{ID: "aaa-refused", Status: plugin.StatusSkipped, Reason: "it may not declare page types"},
	}}
	var out bytes.Buffer
	PrintBanner(&out, Status{Vault: "/v"}, refused)
	got := out.String()

	if v := bannerValue(t, got, "plugins"); v != "0 registered" {
		t.Errorf("plugins line is %q, want nothing registered:\n%s", v, got)
	}
	if !strings.Contains(got, "aaa-refused") {
		t.Errorf("the banner hides the refusal that makes the count zero:\n%s", got)
	}
}

// TestTheBannerCarriesTheReportFromTheBootThatProducedIt is the shape the
// threading exists for: a caller that has a report must be able to print it,
// and a caller with no plugins at all must still get a banner.
func TestTheBannerCarriesTheReportFromTheBootThatProducedIt(t *testing.T) {
	t.Parallel()
	var empty bytes.Buffer
	PrintBanner(&empty, Status{Vault: "/v", Addr: "127.0.0.1:8080"}, plugin.Report{})
	if !strings.Contains(empty.String(), "plugins:") {
		t.Errorf("a boot with no plugins printed no plugin line:\n%s", empty.String())
	}
	if strings.Contains(empty.String(), "not registered:") {
		t.Errorf("a boot with nothing offered named a refusal:\n%s", empty.String())
	}
}

// TestPluginsListWithNoRegistrySaysTheBuildIsEmpty is the whole point of the
// command: an empty registry is a fact about the build and it is reported as
// one. What it must not do is explain itself with a stage of the plan.
func TestPluginsListWithNoRegistrySaysTheBuildIsEmpty(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	PluginsList(context.Background(), Options{}, &out)
	got := out.String()

	if !strings.Contains(got, "0 plugins registered") {
		t.Errorf("the command did not report an empty registry:\n%s", got)
	}
	if strings.Contains(got, "phase") {
		t.Errorf("the command explains itself with a stage of the plan rather than with a fact:\n%s", got)
	}
}

// TestPluginsListRunsTheLifecycleRatherThanTheRegistry covers the difference
// between reading a map and loading it: a plugin the host refuses must appear
// as refused, with a reason, and not as a line the operator has to interpret.
//
// The refused plugin here is one holding a reserved page type without the
// capability that reserves it, which is the check the registry map cannot make
// and the lifecycle can.
func TestPluginsListRunsTheLifecycleRatherThanTheRegistry(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	PluginsList(context.Background(), Options{Plugins: map[string]plugin.Plugin{
		"contender": &bannerProbe{},
		"refused":   &bannerProbe{id: "refused", claimCharacter: true},
	}}, &out)
	got := out.String()

	for _, want := range []string{"contender", "refused", "skipped"} {
		if !strings.Contains(got, want) {
			t.Errorf("the table does not carry %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "ok") {
		t.Errorf("the admitted plugin is not reported as admitted:\n%s", got)
	}
	// The caveat is not decoration: a report that cannot be complete and does
	// not say so is the failure this command exists to avoid.
	if !strings.Contains(got, "no vault") {
		t.Errorf("the table does not say it was loaded without a vault:\n%s", got)
	}
}

// bannerProbe is a minimal plugin: it declares one page type and registers
// nothing, so the only thing under test is what the lifecycle decided about it.
type bannerProbe struct {
	// id overrides the declared id, so one type can be offered under two names.
	id string
	// claimCharacter asks for a page type the host reserves, which is what
	// makes the host refuse it.
	claimCharacter bool
}

func (p *bannerProbe) Descriptor() plugin.Descriptor {
	id := p.id
	if id == "" {
		id = "contender"
	}
	d := plugin.Descriptor{
		ID:        id,
		Name:      "Banner probe",
		Kind:      plugin.KindSystem,
		Version:   "0.0.1",
		APILevel:  plugin.APILevel,
		PageTypes: []plugin.PageType{{ID: "bannerprobe", Name: "Banner probe"}},
	}
	if p.claimCharacter {
		d.PageTypes = []plugin.PageType{{ID: "character", Name: "Character"}}
	}
	return d
}

func (p *bannerProbe) Register(context.Context, plugin.Host) error { return nil }

func (p *bannerProbe) Validate(plugin.Config) error { return nil }

func (p *bannerProbe) Now() time.Time { return time.Time{} }
