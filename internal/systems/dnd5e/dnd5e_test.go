package dnd5e

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	webassets "github.com/PopinjayJohn/vtt-semiplane/web"
	"github.com/go-chi/chi/v5"
)

// The canaries below live in page *bodies* and nowhere else.
//
// They exist because the interesting assertion about this plugin's search
// resolver is negative: nothing it returns may contain a page's text. A test
// that asserted only "the right rows came back" would still pass if a future
// edit started assembling a summary from the body, and that edit would be a
// second path to page text that never went through a page render's redaction.
const (
	characterBodyCanary = "BODY-CANARY-7f3a91-guild-secret"
	ruleBodyCanary      = "BODY-CANARY-b21c04-under-the-stairs"
	untypedBodyCanary   = "BODY-CANARY-000000-not-even-a-dnd5e-page"
	// bodyOnlyTerm appears in a body and in no frontmatter, so a resolver that
	// reached the body would match it and this resolver must not.
	bodyOnlyTerm = "quicksilver"
)

// newFakeFS returns a small vault with one character, one rule, one page of
// another type, and one file that is not a page at all.
//
// The untyped page and the non-markdown file are the two shapes a plugin that
// walked a vault carelessly would report as pages.
func newFakeFS(t *testing.T) fs.FS {
	t.Helper()
	return fstest.MapFS{
		"Characters/Gundren.md": &fstest.MapFile{Data: []byte(`---
type: character
name: Gundren Rockheart
class: Fighter (Battle Master)
level: 3
hp_max: 22
ac: 16
speed: 30
tags: [party, veteran]
---
` + characterBodyCanary + `
`)},
		"Rules/Critical Hits.md": &fstest.MapFile{Data: []byte(`---
type: rule
title: Critical hits
source: Player's Handbook p. 252
tags: [combat]
---
` + ruleBodyCanary + ` ` + bodyOnlyTerm + `
`)},
		"Tavern.md": &fstest.MapFile{Data: []byte(`---
type: location
---
` + untypedBodyCanary + `
`)},
		"Notes/no frontmatter.md": &fstest.MapFile{Data: []byte(untypedBodyCanary + "\n")},
		"Notes/sketch.png":        &fstest.MapFile{Data: []byte{0x89, 'P', 'N', 'G'}},
		".semiplane/semiplane.lock": &fstest.MapFile{
			Data: []byte(untypedBodyCanary + "\n"),
		},
	}
}

// recordingHost is a plugin.Host that records every call.
//
// A fake host is not a convenience here, it is the only way to test a plugin: the
// real one needs a database, a vault lock and a boot sequence, and a test that
// boots all three to assert that a plugin returned two page types is a test that
// breaks for unrelated reasons. Every method is recorded so that a test can
// assert on what Register asked for and not only on what it returned.
type recordingHost struct {
	now    time.Time
	caps   plugin.Capabilities
	kind   plugin.Kind
	config plugin.Config
	fsys   fs.FS
	// mux is the sub-router the host owns, already prefixed and already
	// wrapped. The plugin mounts on this one and never on a router of its own,
	// which is what the real host's RegisterRoutes refuses.
	mux *chi.Mux
	// routes is what the plugin actually mounted, read back from the router
	// rather than from anything the plugin said.
	routes []chi.Route

	// calls is the ordered list of method names the plugin made, one entry per
	// call, so that "the plugin asked for the clock" is checkable.
	calls []string
	// logs is every Log line the plugin emitted.
	logs []string
	// faults is every way the plugin departed from the shape the host expects.
	faults []string
}

// gather is the host's post-Register step, and the fake reproduces it exactly:
// the plugin's own RegisterRoutes is called with the host's sub-router, once,
// after Register has returned. A fake that let the plugin mount on a router it
// built would be testing a shape no real host accepts.
func (h *recordingHost) gather(p *Plugin) {
	ui, ok := any(p).(plugin.PluginUI)
	if !ok {
		h.faults = append(h.faults, "the plugin does not implement PluginUI, so the host mounts nothing for it")
		return
	}
	ui.RegisterRoutes(h.mux)
	h.routes = h.mux.Routes()
}

// The compile-time proof that a fake is a Host. It is the same assertion the
// production plugin makes about itself, and it is what makes this file a test of
// the contract rather than a test of a hand-written imitation of it: if the
// Host interface gains a method, this stops compiling.
var _ plugin.Host = (*recordingHost)(nil)

func (h *recordingHost) Log(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {
	h.calls = append(h.calls, "Log")
	h.logs = append(h.logs, msg)
}

func (h *recordingHost) Capability() plugin.Capabilities {
	h.calls = append(h.calls, "Capability")
	return h.caps
}

func (h *recordingHost) Kind() plugin.Kind {
	h.calls = append(h.calls, "Kind")
	return h.kind
}

func (h *recordingHost) Config() plugin.Config {
	h.calls = append(h.calls, "Config")
	return h.config
}

func (h *recordingHost) FS() fs.FS {
	h.calls = append(h.calls, "FS")
	return h.fsys
}

// Pages is the page read surface, and this double records it the way it records
// every other call so a test can assert a plugin reached for it. The value is
// the empty store rather than nil: a nil interface would make every read in the
// plugin under test a nil dereference, which is a test failure that says
// nothing about the plugin.
func (h *recordingHost) Pages() plugin.PageStore {
	h.calls = append(h.calls, "Pages")
	return plugin.EmptyPageStore()
}

func (h *recordingHost) RegisterRoutes(sub plugin.RouteMounter) {
	h.calls = append(h.calls, "RegisterRoutes")
	if sub != nil && sub != h.mux {
		h.faults = append(h.faults, "the plugin mounted on a router the host did not hand it")
	}
}

func (h *recordingHost) RegisterPanels() []plugin.Panel {
	h.calls = append(h.calls, "RegisterPanels")
	return nil
}

func (h *recordingHost) RegisterMarkdown() []any {
	h.calls = append(h.calls, "RegisterMarkdown")
	return nil
}

func (h *recordingHost) RegisterPageTypes() []plugin.PageType {
	h.calls = append(h.calls, "RegisterPageTypes")
	return nil
}

func (h *recordingHost) Now() time.Time {
	h.calls = append(h.calls, "Now")
	return h.now
}

// newFakeHost returns a host that grants everything this plugin declares, which
// is what a first-party host does, plus a fixed clock and the fake vault.
//
// A fixed clock is the point: a plugin that called time.Now would make every
// assertion about Now untestable, and "testable" is the whole of what Now is
// for.
func newFakeHost(t *testing.T) *recordingHost {
	t.Helper()
	p := New()
	declared, err := plugin.ParseCapabilities(p.Descriptor().Capabilities)
	if err != nil {
		t.Fatalf("the descriptor's own capabilities do not parse: %v", err)
	}
	return &recordingHost{
		now:    time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
		caps:   declared,
		kind:   plugin.KindSystem,
		config: plugin.Config{Values: map[string]any{}},
		fsys:   newFakeFS(t),
		mux:    chi.NewRouter(),
	}
}

// register returns a plugin registered against the fake host, with the host's
// post-Register gather already run — so the routes are mounted, which is the
// state a real request would arrive in.
func register(t *testing.T) (*Plugin, *recordingHost) {
	t.Helper()
	h := newFakeHost(t)
	return registerWith(t, h)
}

// registerWith is register against a host the caller has already arranged, for
// the cases where the host itself is the thing under test.
func registerWith(t *testing.T, h *recordingHost) (*Plugin, *recordingHost) {
	t.Helper()
	p := New()
	if err := p.Register(context.Background(), h); err != nil {
		t.Fatalf("Register: %v", err)
	}
	h.gather(p)
	if len(h.faults) > 0 {
		t.Fatalf("the host recorded %v", h.faults)
	}
	return p, h
}

// TestTheDescriptorIsWellFormed checks the declaration, and ParseCapabilities
// checks it for real.
//
// ParseCapabilities is the assertion that matters here. A capability name the
// host does not recognise is not an error anywhere else in the system: the
// plugin believes it holds the capability, nothing does, and the consequence is
// a silently absent panel rather than a boot failure. This is the test that
// turns that typo into a red build.
func TestTheDescriptorIsWellFormed(t *testing.T) {
	t.Parallel()
	d := New().Descriptor()

	if err := d.ValidateID(); err != nil {
		t.Errorf("ValidateID: %v", err)
	}
	if !d.Kind.Valid() {
		t.Errorf("Kind %q is not valid", d.Kind)
	}
	if d.Kind != plugin.KindSystem {
		t.Errorf("Kind = %q, want %q: this is the reference system plugin", d.Kind, plugin.KindSystem)
	}
	if d.APILevel != plugin.APILevel {
		t.Errorf("APILevel = %d, want %d: a plugin is written against the host it ships with", d.APILevel, plugin.APILevel)
	}
	if !semverRe.MatchString(d.Version) {
		t.Errorf("Version = %q, which is not a semver", d.Version)
	}

	known := map[plugin.Capability]bool{}
	for _, c := range plugin.AllCapabilities {
		known[c] = true
	}
	for _, c := range d.Capabilities {
		if !known[c] {
			t.Errorf("capability %q is not in plugin.AllCapabilities", c)
		}
	}
	// The half that catches a plausible typo: the declared slice is fed to the
	// host's own parser rather than compared to a list written beside it.
	granted, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		t.Fatalf("ParseCapabilities(%v): %v", d.Capabilities, err)
	}
	// AllCapabilities is the declaration and Capabilities is the runtime bitmask,
	// so the comparison goes through the same parser rather than through a
	// hand-written conversion that could disagree with it.
	everything, err := plugin.ParseCapabilities(plugin.AllCapabilities)
	if err != nil {
		t.Fatalf("ParseCapabilities(AllCapabilities): %v", err)
	}
	if extra := granted & ^everything; extra != 0 {
		t.Errorf("granted = %08b, which includes bits the host does not define", granted)
	}
	// The six the descriptor is required to claim, each named. A subset check
	// alone would pass for a plugin that quietly dropped CapRules and stopped
	// registering rule pages without anybody noticing.
	for _, want := range []plugin.Capability{
		plugin.CapCharacterSheet,
		plugin.CapRules,
		plugin.CapUIPanels,
		plugin.CapSidebarNav,
		plugin.CapPageSummaries,
		plugin.CapSearchResolvers,
	} {
		if !granted.Has(want) {
			t.Errorf("the descriptor does not claim %q, so the contribution behind it is discarded", want)
		}
	}
	// Six, named above, and no more. A seventh would be a capability this plugin
	// has no contribution for, which §7 of the working agreement calls a control
	// with nothing behind it; a fifth would be a contribution whose capability
	// was never declared, and that is discarded with a warning at boot.
	if len(d.Capabilities) != 6 {
		t.Errorf("the descriptor claims %d capabilities, want 6: %v", len(d.Capabilities), d.Capabilities)
	}

	if len(d.SearchResolvers) != 1 {
		t.Errorf("SearchResolvers has %d entries, want 1", len(d.SearchResolvers))
	}
	if len(d.NavItems) != 1 {
		t.Fatalf("NavItems has %d entries, want 1", len(d.NavItems))
	}
	if got := d.NavItems[0].Href; !strings.HasPrefix(got, "/plugin/"+ID) {
		t.Errorf("nav href %q is outside the plugin's own prefix; that is a registration error, not a link", got)
	}
	if len(d.Migrations) != 1 {
		t.Errorf("Migrations has %d entries, want 1", len(d.Migrations))
	}
	if len(d.ConfigSchema) != len(settings) {
		t.Errorf("ConfigSchema has %d entries, want %d", len(d.ConfigSchema), len(settings))
	}
	// Icons are sprite tokens, and a token the sprite does not have is a
	// silently empty <use>: the affordance looks broken rather than absent.
	sprite := spriteSymbols(t)
	for _, pt := range d.PageTypes {
		if !sprite[pt.Icon] {
			t.Errorf("page type %q references icon %q, which web/static/icons.svg does not define", pt.ID, pt.Icon)
		}
	}
	for _, nav := range d.NavItems {
		if !sprite[nav.Icon] {
			t.Errorf("nav item %q references icon %q, which web/static/icons.svg does not define", nav.ID, nav.Icon)
		}
	}
}

// semverRe is a three-number version, which is the whole of what this package
// claims to ship. It is deliberately not the full semver grammar: a pre-release
// suffix is a thing a release process adds, and a test that accepted it would
// not notice a version that had quietly become something else.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// TestTheReservedNamesThisPluginClaimsAreTheOnesItHolds is the point of
// reserved.go, in both directions.
//
// The direction that matters most is the negative one: a plugin that declares
// CapCharacterSheet and then claims `character` is doing exactly what the rule
// intends, and a plugin that claims `character` without it must be refused. A
// test of only the positive direction would pass for a plugin that took the name
// by accident.
func TestTheReservedNamesThisPluginClaimsAreTheOnesItHolds(t *testing.T) {
	t.Parallel()
	d := New().Descriptor()
	granted, err := plugin.ParseCapabilities(d.Capabilities)
	if err != nil {
		t.Fatalf("ParseCapabilities: %v", err)
	}
	withoutSheet := grantedExcept(plugin.CapCharacterSheet)
	withoutRules := grantedExcept(plugin.CapRules)

	tests := []struct {
		name    string
		kind    plugin.Kind
		caps    plugin.Capabilities
		pageTyp string
		route   string
		wantErr bool
	}{
		{name: "character page type with the sheet capability", kind: plugin.KindSystem, caps: granted, pageTyp: PageTypeCharacter, route: characterRoute},
		{name: "rule page type with the rules capability", kind: plugin.KindSystem, caps: granted, pageTyp: PageTypeRule},
		{name: "the character route with the sheet capability", kind: plugin.KindSystem, caps: granted, route: characterRoute},
		{name: "the index route with everything", kind: plugin.KindSystem, caps: granted, route: indexRoute},
		{name: "the character page type without the sheet capability", kind: plugin.KindSystem, caps: withoutSheet, pageTyp: PageTypeCharacter, wantErr: true},
		{name: "the character route without the sheet capability", kind: plugin.KindSystem, caps: withoutSheet, route: characterRoute, wantErr: true},
		{name: "the rule page type without the rules capability", kind: plugin.KindSystem, caps: withoutRules, pageTyp: PageTypeRule, wantErr: true},
		{name: "the character page type from a feature plugin", kind: plugin.KindFeature, caps: granted, pageTyp: PageTypeCharacter, wantErr: true},
		{name: "the character route from a feature plugin", kind: plugin.KindFeature, caps: granted, route: characterRoute, wantErr: true},
		{
			// A feature plugin is refused a reserved name even when it holds the
			// capability, because a capability says what a plugin may do and a
			// kind says what vocabulary it may speak. `linkpreview` holding
			// CapMaps would still not make it a map system.
			name: "the rule page type from a feature plugin", kind: plugin.KindFeature, caps: granted, pageTyp: PageTypeRule, wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.pageTyp != "" {
				err := plugin.CheckReservedPageType(tc.pageTyp, tc.kind, tc.caps)
				assertReserved(t, "page type "+tc.pageTyp, err, tc.wantErr)
			}
			if tc.route != "" {
				err := plugin.CheckReservedRoute(tc.route, tc.kind, tc.caps)
				assertReserved(t, "route "+tc.route, err, tc.wantErr)
			}
		})
	}
}

// grantedExcept is every capability except the named ones.
//
// Capabilities is a bitmask and Capability is a string, so there is no operator
// to subtract a capability with; a host builds a grant by adding the ones it
// allows, and this builds the same way — from the host's own list rather than
// from a copy of it, so a new capability cannot be quietly forgotten here.
func grantedExcept(except ...plugin.Capability) plugin.Capabilities {
	var out plugin.Capabilities
	for _, c := range plugin.AllCapabilities {
		skip := false
		for _, e := range except {
			if c == e {
				skip = true
			}
		}
		if !skip {
			out = out.With(c)
		}
	}
	return out
}

// assertReserved reports whether a reserved-name check agreed with the test.
func assertReserved(t *testing.T, what string, err error, wantErr bool) {
	t.Helper()
	if wantErr && err == nil {
		t.Errorf("%s was admitted, which is the failure this rule exists to prevent", what)
	}
	if !wantErr && err != nil {
		t.Errorf("%s was refused: %v", what, err)
	}
}

// TestRegisterProducesTheDeclaredContributions counts what Register yields
// against what the Descriptor declares.
//
// The routes are counted by walking the router the host was actually handed
// rather than by comparing a table of the patterns the plugin says it mounts: a
// plugin whose table and whose router disagree is precisely the bug this test
// exists to find, and only one of the two is the truth.
func TestRegisterProducesTheDeclaredContributions(t *testing.T) {
	t.Parallel()
	p, h := register(t)
	d := p.Descriptor()

	if len(h.faults) > 0 {
		t.Fatalf("the host recorded %v", h.faults)
	}
	seen := map[string]int{}
	for _, call := range h.calls {
		seen[call]++
	}
	var got []string
	for _, route := range h.routes {
		if _, ok := route.Handlers[http.MethodGet]; ok {
			got = append(got, route.Pattern)
		}
	}
	want := routePatterns()
	if len(got) != len(want) {
		t.Fatalf("the mounted GET patterns are %v, want %v", got, want)
	}
	for _, pattern := range want {
		found := false
		for _, g := range got {
			if g == pattern {
				found = true
			}
		}
		if !found {
			t.Errorf("pattern %q was not mounted; the router has %v", pattern, got)
		}
	}
	// A router with a POST or a DELETE on it would be a write route, and this
	// plugin declares no write route anywhere.
	for _, route := range h.routes {
		for method := range route.Handlers {
			if method != http.MethodGet {
				t.Errorf("pattern %q is mounted for %s; this plugin mounts read routes only", route.Pattern, method)
			}
		}
	}

	if got, want := len(p.CoreTypes()), len(d.PageTypes); got != want {
		t.Errorf("CoreTypes has %d page types, the descriptor declares %d", got, want)
	}
	for i, pt := range p.CoreTypes() {
		if pt.ID != d.PageTypes[i].ID {
			t.Errorf("CoreTypes[%d].ID = %q, the descriptor declares %q", i, pt.ID, d.PageTypes[i].ID)
		}
	}

	panels := p.Panels()
	if len(panels) != 1 {
		t.Fatalf("Panels has %d entries, want exactly 1: the panel is the whole right-mid contribution", len(panels))
	}
	if panels[0].Slot != plugin.SlotRightMid {
		t.Errorf("panel slot = %q, want %q", panels[0].Slot, plugin.SlotRightMid)
	}
	if panels[0].PageType != PageTypeCharacter {
		t.Errorf("panel PageType = %q, want %q: an unrestricted panel would render on every page in the vault", panels[0].PageType, PageTypeCharacter)
	}
	if panels[0].Component == nil {
		t.Error("the panel has no component, so the slot would render an empty box")
	}

	nav := p.NavItems()
	if len(nav) != len(d.NavItems) {
		t.Errorf("NavItems has %d entries, the descriptor declares %d", len(nav), len(d.NavItems))
	}
	if len(nav) > 0 && !strings.HasPrefix(nav[0].Href, "/plugin/"+ID) {
		t.Errorf("nav href %q is outside the plugin's own prefix", nav[0].Href)
	}
	if len(p.Summaries()) != 1 {
		t.Errorf("Summaries has %d providers, want 1: CapPageSummaries is declared, so one must be contributed", len(p.Summaries()))
	}
	if got := p.MarkdownExtenders(); got != nil {
		t.Errorf("MarkdownExtenders returned %d extenders; this plugin contributes none and nil is how it says so", len(got))
	}

	// The plugin mounted on the host's sub-router and nowhere else. A router of
	// its own would be mounted outside the prefix and outside the session
	// wrapper, and the host refuses it.
	if p.routes != h.mux {
		t.Error("the plugin mounted on a router other than the one the host handed it")
	}
	// It does not call the Host's Register* collection methods, and that is
	// worth pinning down rather than leaving to a reader's judgement: those
	// methods take no arguments, so a plugin cannot pass a page type, a panel or
	// an extender through them. This plugin's contributions come from CoreTypes,
	// Panels, NavItems and Summaries, which the host calls on the plugin, so
	// calling the host's getters would read back what the plugin already knows.
	for _, unused := range []string{"RegisterPageTypes", "RegisterPanels", "RegisterMarkdown"} {
		if seen[unused] != 0 {
			t.Errorf("the plugin called Host.%s, whose return value is the host's own collection, not a sink for the plugin's", unused)
		}
	}
	// And nothing else: a method this test does not know about is a capability
	// the plugin acquired without anyone deciding to give it.
	allowed := map[string]bool{
		"Capability": true, "Kind": true, "Log": true, "FS": true,
		"Config": true, "Now": true,
	}
	for call := range seen {
		if !allowed[call] {
			t.Errorf("Register called Host.%s, which is not one of the calls this plugin is expected to make", call)
		}
	}
	if len(h.logs) == 0 {
		t.Error("Register logged nothing, so a boot report would show the plugin appearing without a line")
	}

	// The clock is the host's. It is a method value rather than a value, so
	// asking for the clock now and rendering an hour from now must still be the
	// host's reading — which is the property a plugin calling time.Now would
	// lose.
	if got := p.Now(); !got.Equal(h.now) {
		t.Errorf("Now() = %v, want the host's %v", got, h.now)
	}
}

// TestTheHostSurfaceIsEnoughToImplementThisPlugin is the boundary test, in the
// two forms it can take from inside a plugin.
//
// The first is a compile-time one: the fake host in this file satisfies the real
// interface, so a change to Host breaks the build here rather than at boot. The
// second is a source-level one, because a plugin can satisfy the interface and
// still reach for the filesystem, the network or a subprocess — none of which
// the interface mentions, and all of which are the accepted trust model of §11
// rather than something the architecture wants.
//
// The walk skips _test.go. This file necessarily reads files and the test
// binary necessarily imports os; internal/architecture_test.go skips test files
// for the same reason, and a check that trips over its own instrumentation is a
// check somebody deletes.
func TestTheHostSurfaceIsEnoughToImplementThisPlugin(t *testing.T) {
	t.Parallel()

	// The compile-time half, asserted again here so the test is self-contained
	// rather than depending on a file-level var being noticed.
	var h plugin.Host = &recordingHost{}
	if h.Capability().Has(plugin.CapCharacterSheet) {
		t.Error("an empty capability set reported holding CapCharacterSheet")
	}

	// The imports a plugin may not name, matched as whole quoted import paths
	// rather than as bare words. A bare word would fire on this file's own prose
	// — several of these names appear in comments explaining why they are
	// forbidden — and an assertion that trips over its own documentation is an
	// assertion somebody deletes.
	//
	// net/http is deliberately absent: serving a route is an http.HandlerFunc
	// and the router's own method takes one, so a plugin that mounts routes
	// must name the type. What is forbidden is the *client* half, and a plugin
	// that reached for http.Client would be caught by the .DefaultClient and
	// .NewRequest use checks below.
	forbiddenImports := map[string]string{
		`"os"`:               "only internal/app touches the filesystem",
		`"net"`:              "a plugin has no reason to dial out",
		`"os/exec"`:          "only internal/app may run a process",
		`"runtime"`:          "a plugin is compiled in; there is nothing to load",
		`"internal/httpapi"`: "httpapi owns the redactor and the Perm middleware",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"`: "httpapi owns the redactor and the Perm middleware",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/auth"`:    "auth owns sessions",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/obs"`:     "obs owns the redacting log handler",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/sync"`:    "the indexer owns the index",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/app"`:     "app is the composition root",
		`"github.com/PopinjayJohn/vtt-semiplane/internal/config"`:  "config is read by the composition root, not by a plugin",
	}
	// os./net./exec. as a package qualifier, and the two spellings of an HTTP
	// client, which are the only ways a compiled-in plugin reaches the network.
	forbiddenUses := []*regexp.Regexp{
		regexp.MustCompile(`\bos\.[A-Z]`),
		regexp.MustCompile(`\bnet\.[A-Z]`),
		regexp.MustCompile(`\bexec\.[A-Z]`),
		regexp.MustCompile(`\bhttp\.(Client|NewRequest|DefaultClient|Get|Post)\b`),
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".templ") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++
		text := string(src)
		for needle, reason := range forbiddenImports {
			if strings.Contains(text, needle) {
				t.Errorf("%s imports %s: %s", name, needle, reason)
			}
		}
		for _, use := range forbiddenUses {
			if m := use.FindString(text); m != "" {
				t.Errorf("%s uses %q: a plugin reaches the host, not the machine", name, m)
			}
		}
	}
	if checked < 4 {
		t.Errorf("only %d source files were checked, so the boundary assertion is not looking where it thinks it is", checked)
	}
}

// TestNoJavaScriptCSSOrDOMHandleIsShipped is S21, and it is a security property
// rather than a style rule.
//
// §2.6 of the plan and §7 of the working agreement are explicit: a plugin cannot
// ship JavaScript, a stylesheet or a DOM handle. That is not a prohibition on
// cleverness — it is what keeps an arbitrary-script hole out of the content
// security policy and keeps focus management implemented once in core rather than
// once per plugin. The Host interface has no method that could install one, so
// this test is the backstop against a future contributor finding a way around
// that anyway.
//
// Both halves are checked: the .templ sources, because that is where markup is
// written, and the generated *_templ.go, because the generated file is what
// ships and a future templ version could emit something the source does not.
func TestNoJavaScriptCSSOrDOMHandleIsShipped(t *testing.T) {
	t.Parallel()

	forbidden := map[string]string{
		"<script":      "a plugin may not ship JavaScript",
		"</script":     "a plugin may not ship JavaScript",
		"<style":       "a plugin may not ship CSS; the stylesheet is core-owned",
		"onclick=":     "an inline event handler is JavaScript in an attribute",
		"oninput=":     "an inline event handler is JavaScript in an attribute",
		"onchange=":    "an inline event handler is JavaScript in an attribute",
		"onload=":      "an inline event handler is JavaScript in an attribute",
		"onsubmit=":    "an inline event handler is JavaScript in an attribute",
		"data-on:":     "a DataStar expression is a behaviour binding; behaviours are core-owned",
		"data-bind:":   "a DataStar binding is a behaviour binding; behaviours are core-owned",
		"data-effect:": "a DataStar effect is a behaviour binding; behaviours are core-owned",
		"javascript:":  "a javascript: URL is script execution with a link's clothing on",
		"templ.Raw(":   "a plugin may not mark a string raw, so no string of its own can reach a reader unescaped",
	}
	// The ids core's own client binds to. A plugin that rendered one of them
	// would be a second owner of an element the shell already owns, and the
	// collision is a silently broken drawer rather than a build failure.
	coreIDs := []string{"shell", "left-nav", "content", "context", "page-region", "palette", "shortcuts"}

	files := []string{"character.templ", "panels.templ", "character_templ.go", "panels_templ.go"}
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		for needle, reason := range forbidden {
			if strings.Contains(text, needle) {
				t.Errorf("%s contains %q: %s", name, needle, reason)
			}
		}
		for _, id := range coreIDs {
			if strings.Contains(text, `id="`+id+`"`) {
				t.Errorf("%s renders id=%q, which the shell already owns", name, id)
			}
		}
	}
}

// TestTheSearchResolverReturnsNoHiddenContent is the resolver's real contract.
//
// The rows a resolver returns are rendered into a search result for whoever
// asked, so a resolver that could be handed a secret would be a way to search
// for hidden text. The assertion is therefore negative and it is checked against
// canaries planted in page bodies: a Summary containing one means a body was
// read, and a body is the only place a canary exists.
func TestTheSearchResolverReturnsNoHiddenContent(t *testing.T) {
	t.Parallel()
	p, _ := register(t)
	d := p.Descriptor()

	resolver := d.SearchResolvers[0]
	canaries := []string{characterBodyCanary, ruleBodyCanary, untypedBodyCanary}

	t.Run("a frontmatter match returns a row derived from frontmatter", func(t *testing.T) {
		t.Parallel()
		rows, err := resolver.Query(context.Background(), "gundren")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("Query returned %d rows, want 1: %+v", len(rows), rows)
		}
		row := rows[0]
		if row.Kind != PageTypeCharacter {
			t.Errorf("Kind = %q, want %q", row.Kind, PageTypeCharacter)
		}
		if row.Title != "Gundren Rockheart" {
			t.Errorf("Title = %q, want the frontmatter name", row.Title)
		}
		if row.Href != pluginPageHref+"Characters/Gundren.md" {
			t.Errorf("Href = %q, want the page route for the vault path", row.Href)
		}
		if row.Ref != "Characters/Gundren.md" {
			t.Errorf("Ref = %q, want the vault path", row.Ref)
		}
		// A summary that names the class, the level and the AC is provably
		// built from frontmatter, which is what makes the negative assertions
		// below mean something.
		for _, want := range []string{"Fighter (Battle Master)", "level 3", "AC 16"} {
			if !strings.Contains(row.Summary, want) {
				t.Errorf("Summary %q does not mention %q, so it is not derived from the sheet's fields", row.Summary, want)
			}
		}
	})

	t.Run("no row carries page text", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{"gundren", "fighter", "veteran", "critical", "combat", "player's handbook", "quicksilver"} {
			rows, err := resolver.Query(context.Background(), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			for _, row := range rows {
				blob := row.Kind + "\x00" + row.Title + "\x00" + row.Href + "\x00" + row.Summary + "\x00" + row.Ref
				for _, canary := range canaries {
					if strings.Contains(blob, canary) {
						t.Errorf("Query(%q) returned a row carrying page text: %+v", term, row)
					}
				}
			}
		}
	})

	t.Run("a term that only exists in a body matches nothing", func(t *testing.T) {
		t.Parallel()
		// The sharpest form of the assertion. quicksilver appears in a page
		// body and in no frontmatter, so a resolver that read bodies would
		// return a row here and this one must not.
		rows, err := resolver.Query(context.Background(), bodyOnlyTerm)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("Query(%q) returned %d rows; the term is in a page body, so matching it means the body was read", bodyOnlyTerm, len(rows))
		}
	})

	t.Run("only pages of this plugin's types are indexed", func(t *testing.T) {
		t.Parallel()
		// The untyped page and the note with no frontmatter both contain
		// canaries, and neither is a dnd5e page. A walk that returned every
		// Markdown file would hand them both to whoever searched.
		for _, term := range []string{"tavern", "no frontmatter", "not even a dnd5e page"} {
			rows, err := resolver.Query(context.Background(), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			if len(rows) != 0 {
				t.Errorf("Query(%q) returned %+v, which is not a page this plugin claims", term, rows)
			}
		}
	})

	t.Run("a title match outranks a field match", func(t *testing.T) {
		t.Parallel()
		// "veteran" is a tag on Gundren and "veteran adventurer" is in the
		// Tavern's own title, so a vault-wide test would be ambiguous; the point
		// here is only that the two levels are ordered, which the resolver's
		// score decides and the host's merge consumes.
		rows, err := resolver.Query(context.Background(), "party")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 1 || rows[0].Ref != "Characters/Gundren.md" {
			t.Fatalf("Query(%q) = %+v, want only the character page", "party", rows)
		}
		if rows[0].Score != 0.5 {
			t.Errorf("Score = %v, want 0.5: a field match is worth less than a title match", rows[0].Score)
		}
		rows, err = resolver.Query(context.Background(), "Gundren")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 1 || rows[0].Score != 1 {
			t.Errorf("a title match scored %v, want 1", rows)
		}
	})

	t.Run("an empty term asks for nothing", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{"", "   "} {
			rows, err := resolver.Query(context.Background(), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			if len(rows) != 0 {
				t.Errorf("Query(%q) returned %d rows; an empty term is not a search", term, len(rows))
			}
		}
	})
}

// TestTheCharacterSchemaHasNoRequiredFieldTheEditorCannotRender is the seam
// between the declared schema and the markup that draws it.
//
// A field in the schema that the template does not render is a field a reader
// cannot see exists, and a field the template renders that the schema does not
// declare is a field nothing indexes, nothing validates and nothing the core
// editor knows about. Both directions are checked, and the check is made against
// rendered HTML rather than against the template text, so it fails for a field
// that is present in the source and absent from the page.
func TestTheCharacterSchemaHasNoRequiredFieldTheEditorCannotRender(t *testing.T) {
	t.Parallel()

	allowedTypes := map[string]bool{
		"text": true, "textarea": true, "number": true, "bool": true, "select": true, "tags": true,
	}
	for _, pt := range pageTypes() {
		for key, field := range pt.FrontmatterSchema {
			if !allowedTypes[field.Type] {
				t.Errorf("page type %q field %q has type %q, which is not one of text, textarea, number, bool, select or tags", pt.ID, key, field.Type)
			}
			if field.Type == "select" && len(field.Options) == 0 {
				t.Errorf("page type %q field %q is a select with no options, so it renders an empty control", pt.ID, key)
			}
			if field.Key != key {
				t.Errorf("page type %q maps %q to a field whose Key is %q; the map key is the frontmatter key and the two must be the same string", pt.ID, key, field.Key)
			}
			if field.Name == "" {
				t.Errorf("page type %q field %q has no label, so the editor would render an unlabelled control", pt.ID, key)
			}
		}
	}

	sheet := Sheet{
		Path:      "Characters/Gundren.md",
		Name:      "Gundren Rockheart",
		Class:     "Fighter (Battle Master)",
		Level:     3,
		HPMax:     22,
		AC:        16,
		Speed:     30,
		Tags:      []string{"party", "veteran"},
		SpeedUnit: "ft",
	}
	body := render(t, characterEditor(sheet))

	for key := range pageTypes()[0].FrontmatterSchema {
		if !strings.Contains(body, `id="dnd5e-`+key+`"`) {
			t.Errorf("the character schema declares %q but the editor renders no input with id dnd5e-%s", key, key)
		}
		if !strings.Contains(body, `for="dnd5e-`+key+`"`) {
			t.Errorf("the editor renders an input for %q with no label bound to it", key)
		}
		if !strings.Contains(body, `name="`+key+`"`) {
			t.Errorf("the editor renders an input for %q with no name, so a save could not name the field", key)
		}
	}
	for _, want := range []string{
		`value="Gundren Rockheart"`,
		`value="Fighter (Battle Master)"`,
		`value="3"`,
		`value="22"`,
		`value="16"`,
		`value="30"`,
		`value="party, veteran"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the editor does not render %s; a sheet whose values do not appear is a sheet showing nothing", want)
		}
	}
	if !strings.Contains(body, `type="number"`) {
		t.Error("the editor renders no number input, so a level and a hit point count are edited as text")
	}
	if !strings.Contains(body, "readonly") {
		t.Error("the editor renders editable inputs with no save path behind them, which is a control with nothing behind it")
	}
	if !strings.Contains(body, sheet.Path) {
		t.Error("the editor does not name the file it read, so a reader cannot tell which page is shown")
	}
}

// TestTheRealHostBootsThisPlugin is the test that catches what a fake cannot.
//
// Everything above runs this plugin against a hand-written imitation of the
// host, and an imitation only proves that the plugin agrees with the imitation.
// The real host has opinions a fake does not have — it builds the sub-router
// itself, refuses a plugin that mounts on a router of its own, audits the
// patterns actually mounted rather than the ones a plugin said, and gates a nav
// item on there being a route for it to point at.
//
// So this test loads the plugin through plugin.Load with a PluginDeps the way a
// composition root would supply one, and asserts the boot report says ok. It is
// the test that would have caught this plugin handing the host a router of its
// own, which a fake built to accept anything would have passed.
func TestTheRealHostBootsThisPlugin(t *testing.T) {
	t.Parallel()

	mux := chi.NewRouter()
	var migrations []plugin.Migration
	reg, report := plugin.Load(context.Background(), plugin.PluginDeps{
		Now: func() time.Time { return time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC) },
		Log: func(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {},
		FS:  func() fs.FS { return newFakeFS(t) },
		Config: func(pluginID string) (plugin.Config, error) {
			return plugin.Config{Values: map[string]any{}}, nil
		},
		Migrations: func(ctx context.Context, pluginID string, migs []plugin.Migration) error {
			migrations = append(migrations, migs...)
			return nil
		},
		SubRouter: func(pluginID string) plugin.RouteMounter { return mux },
	}, New())

	for _, entry := range report.Entries {
		if entry.ID != ID {
			continue
		}
		if entry.Status != plugin.StatusOK {
			t.Fatalf("the real host reported %s: %s", entry.Status, entry.Reason)
		}
	}
	if len(report.Warnings) > 0 {
		t.Errorf("the real host warned about the only plugin offered: %v", report.Warnings)
	}
	if len(migrations) != 1 {
		t.Errorf("the host ran %d migrations, want 1", len(migrations))
	}

	// The contributions the host actually collected, read back from the registry
	// rather than from this package.
	if _, ok := reg.PageType(PageTypeCharacter); !ok {
		t.Errorf("the registry has no %q page type", PageTypeCharacter)
	}
	if _, ok := reg.PageType(PageTypeRule); !ok {
		t.Errorf("the registry has no %q page type", PageTypeRule)
	}
	if got := len(reg.PanelsFor(PageTypeCharacter)); got != 1 {
		t.Errorf("PanelsFor(%q) returned %d panels, want 1", PageTypeCharacter, got)
	}
	if got := len(reg.PanelsFor("")); got != 0 {
		t.Errorf("PanelsFor(\"\") returned %d panels; this plugin's panel is restricted to character pages", got)
	}
	nav := reg.NavItems()
	if len(nav) != 1 {
		t.Errorf("NavItems returned %d entries, want 1", len(nav))
	}
	if len(reg.SearchResolvers()) != 1 {
		t.Errorf("SearchResolvers returned %d entries, want 1", len(reg.SearchResolvers()))
	}
	if len(reg.Summaries()) != 1 {
		t.Errorf("Summaries returned %d entries, want 1", len(reg.Summaries()))
	}
	if got := reg.Extenders(); len(got) != 0 {
		t.Errorf("Extenders returned %d entries; this plugin contributes none", len(got))
	}
	routes := reg.Routes()
	if len(routes) != 1 {
		t.Fatalf("Routes returned %d sub-routers, want 1", len(routes))
	}
	if patterns := plugin.RoutePatterns(routes[0].Value); len(patterns) != len(routePatterns()) {
		t.Errorf("the host saw the patterns %v, want %v", patterns, routePatterns())
	}

	// And the router the host built serves the requests, under the prefix the
	// router installs it at.
	root := chi.NewRouter()
	for _, owned := range reg.Routes() {
		root.Mount(plugin.PluginPrefix(owned.Plugin), owned.Value)
	}
	if _, status := serve(t, root, sheetURL("Characters/Gundren.md")); status != http.StatusOK {
		t.Errorf("the character sheet route answered %d through the host's own sub-router", status)
	}
}

// TestTheRoutesAnswer renders both mounted routes, because a route that
// compiles and a route that answers are different claims.
//
// The router is mounted the way the host mounts it — under the plugin prefix —
// so the assertions cover the prefix and the wildcard parameter together.
func TestTheRoutesAnswer(t *testing.T) {
	t.Parallel()
	p, h := register(t)
	if p.routes != h.mux {
		t.Error("the plugin kept a router other than the one it handed the host")
	}

	root := chi.NewRouter()
	root.Mount("/plugin/"+ID, h.mux)

	t.Run("the index lists the page types and the characters", func(t *testing.T) {
		t.Parallel()
		body, status := serve(t, root, "/plugin/"+ID+"/")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		for _, want := range []string{"D&amp;D 5e", "character", "rule", "Gundren Rockheart", "Fighter (Battle Master)"} {
			if !strings.Contains(body, want) {
				t.Errorf("the index does not contain %q", want)
			}
		}
		if strings.Contains(body, untypedBodyCanary) {
			t.Error("the index rendered a page body; a plugin page is a frontmatter page")
		}
	})

	t.Run("a character sheet renders from the file's frontmatter", func(t *testing.T) {
		t.Parallel()
		body, status := serve(t, root, sheetURL("Characters/Gundren.md"))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		for _, want := range []string{"Gundren Rockheart", "Characters/Gundren.md", `value="22"`, `value="16"`} {
			if !strings.Contains(body, want) {
				t.Errorf("the sheet does not contain %q", want)
			}
		}
	})

	t.Run("a path that is not a character page is 404", func(t *testing.T) {
		t.Parallel()
		// One answer for "does not exist", "not a character page" and "is a
		// traversal attempt", because three answers would let a reader map the
		// vault.
		for _, path := range []string{
			"Tavern.md",
			"Notes/no%20frontmatter.md",
			"nothing/here.md",
			"../../etc/passwd",
			"Notes/sketch.png",
		} {
			_, status := serve(t, root, sheetURL(path))
			if status != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", path, status)
			}
		}
	})

	t.Run("the nav destination is the route the plugin mounted", func(t *testing.T) {
		t.Parallel()
		// A nav item whose href answers 404 is exactly the affordance with
		// nothing behind it, and the link the shell renders is the one here.
		_, status := serve(t, root, New().Descriptor().NavItems[0].Href)
		if status != http.StatusOK {
			t.Errorf("the nav item points at %q, which answers %d", IndexHref, status)
		}
	})
	t.Run("a host filesystem that honours no path rules still cannot be walked out of", func(t *testing.T) {
		t.Parallel()
		// The fs.FS contract says Open must refuse a path containing "..", and
		// the fake every other test here uses does. So a traversal test written
		// against it proves the *filesystem's* validation and not the plugin's
		// check, which is the vacuous shape this subtest exists to avoid: a
		// host that hands a plugin a hand-rolled FS is exactly the case
		// fs.ValidPath is defending, and it has to be exercised or the defence
		// is untested.
		loose := newFakeHost(t)
		loose.fsys = permissiveFS{page: []byte("---\ntype: character\nname: Gundren\n---\nbody\n")}
		registerWith(t, loose)
		hostileRoot := chi.NewRouter()
		hostileRoot.Mount("/plugin/"+ID, loose.mux)

		// The control: the same route, the same handler, the same component,
		// and the permissive filesystem serves a perfectly ordinary path. So the
		// 404s below are the plugin's own check and nothing else.
		if _, status := serve(t, hostileRoot, sheetURL("Characters/Gundren.md")); status != http.StatusOK {
			t.Errorf("a valid path answered %d against the permissive host, so the host is not permissive and this test proves nothing", status)
		}
		for _, path := range []string{"../../etc/passwd", "..%2f..%2fetc/passwd", "./../secret.md", "a/../../b.md"} {
			if _, status := serve(t, hostileRoot, sheetURL(path)); status != http.StatusNotFound {
				t.Errorf("GET %s = %d against a filesystem that opens anything, want 404: the plugin's own path check is the only thing refusing it", path, status)
			}
		}
	})
}

// permissiveFS is an fs.FS that opens any name at all, including one holding
// "..", and answers with the same character page every time.
//
// It exists only so that a traversal assertion tests the plugin. Against a
// conforming filesystem the refusal comes from the filesystem either way, and a
// test that cannot tell the two apart is a test that stops being one the moment
// somebody replaces the fake.
type permissiveFS struct{ page []byte }

// Open ignores the name, which is the whole point.
func (f permissiveFS) Open(name string) (fs.File, error) {
	return permissiveFile{Reader: bytes.NewReader(f.page)}, nil
}

// permissiveFile is an fs.File over a fixed buffer.
type permissiveFile struct{ *bytes.Reader }

// Stat satisfies fs.File. The size is the buffer's, so the plugin's own
// read-size guard is not what refuses the request either.
func (permissiveFile) Stat() (fs.FileInfo, error) { return permissiveInfo{}, nil }

// Close satisfies fs.File.
func (permissiveFile) Close() error { return nil }

// permissiveInfo is an fs.FileInfo for a fixed size.
type permissiveInfo struct{}

// permissiveInfo reports a size inside the plugin's read limit, so a refusal can
// only be the path check.
func (permissiveInfo) Name() string       { return "anything" }
func (permissiveInfo) Size() int64        { return 64 }
func (permissiveInfo) Mode() fs.FileMode  { return 0o444 }
func (permissiveInfo) ModTime() time.Time { return time.Time{} }
func (permissiveInfo) IsDir() bool        { return false }
func (permissiveInfo) Sys() any           { return nil }

// TestValidateRejectsAValueThePluginCannotUse is the settings contract.
//
// A validator that accepted everything would leave the plugin rendering a
// campaign with a level cap nobody chose, and the operator would have no way to
// find out which stored value was ignored.
func TestValidateRejectsAValueThePluginCannotUse(t *testing.T) {
	t.Parallel()
	p := New()

	tests := []struct {
		name    string
		values  map[string]any
		wantErr bool
	}{
		{name: "empty config", values: map[string]any{}},
		{name: "valid values", values: map[string]any{"new_sheet_level": 5, "new_sheet_hp": 12, "speed_unit": "m"}},
		{name: "a level below the cap", values: map[string]any{"new_sheet_level": 0}, wantErr: true},
		{name: "a level above the cap", values: map[string]any{"new_sheet_level": 21}, wantErr: true},
		{name: "a level that is text", values: map[string]any{"new_sheet_level": "three"}, wantErr: true},
		{name: "a fractional level", values: map[string]any{"new_sheet_level": 3.5}, wantErr: true},
		{name: "an unknown unit", values: map[string]any{"speed_unit": "cubits"}, wantErr: true},
		{name: "a unit that is a number", values: map[string]any{"speed_unit": 5}, wantErr: true},
		{name: "negative hit points", values: map[string]any{"new_sheet_hp": -1}, wantErr: true},
		{
			// A key from a newer version of the plugin is not an error. Refusing
			// to boot because the stored config is from the future is the
			// behaviour the API-level window in §2.5 exists to prevent.
			name: "a key this version does not know", values: map[string]any{"dice_notation": "4d6"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := p.Validate(plugin.Config{Values: tc.values})
			if tc.wantErr && err == nil {
				t.Errorf("Validate(%v) = nil, want an error", tc.values)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate(%v) = %v, want nil", tc.values, err)
			}
		})
	}

	// The defaults Validate accepts are the defaults the read path uses, so a
	// setting cannot be valid at boot and a different value at render time.
	if err := p.Validate(plugin.Config{Values: map[string]any{}}); err != nil {
		t.Fatalf("an empty config does not validate: %v", err)
	}
	if got := configInt(plugin.Config{Values: map[string]any{}}, "new_sheet_level"); got != 1 {
		t.Errorf("an absent new_sheet_level reads as %d, want the schema's default of 1", got)
	}
	if got := configString(plugin.Config{Values: map[string]any{}}, "speed_unit"); got != "ft" {
		t.Errorf("an absent speed_unit reads as %q, want the schema's default of ft", got)
	}
}

// TestTheMigrationCreatesOnlyThePrefixedTable checks the one DDL statement this
// plugin owns.
//
// The prefix is a host requirement and the SQL comment says so, but a comment is
// a promise: this reads the statement the host will run and checks that the only
// table it names is prefixed with plugin_dnd5e_.
func TestTheMigrationCreatesOnlyThePrefixedTable(t *testing.T) {
	t.Parallel()
	ms := New().Descriptor().Migrations
	if len(ms) != 1 {
		t.Fatalf("Migrations has %d entries, want 1", len(ms))
	}
	if ms[0].Version != 1 {
		t.Errorf("migration version = %d, want 1", ms[0].Version)
	}
	if !strings.Contains(ms[0].SQL, "CREATE TABLE IF NOT EXISTS plugin_"+ID+"_") {
		t.Errorf("the migration does not create a plugin_%s_ prefixed table: %s", ID, ms[0].SQL)
	}
	if !strings.Contains(strings.ToLower(ms[0].SQL), "plugin_") {
		t.Error("the migration names no plugin_ table at all")
	}
	// Nothing the host runs may be a template, so every statement has to survive
	// being handed straight to the migration runner.
	if strings.Contains(ms[0].SQL, "Sprintf(") || strings.Contains(ms[0].SQL, "fmt.") {
		t.Error("the migration SQL is not a constant string")
	}
}

// spriteSymbols reads the committed icon sprite and returns the ids it defines.
//
// It reads the embedded asset tree rather than the working tree, for the reason
// internal/web's own icon test gives: a test that read the file on disk would
// pass against a sprite the binary does not carry. The package it reaches for is
// the module-root one, which holds an embed and nothing else, because
// internal/web is not importable from here — see the note on spriteHref.
func spriteSymbols(t *testing.T) map[string]bool {
	t.Helper()
	f, err := webassets.FS().Open("icons.svg")
	if err != nil {
		t.Fatalf("the icon sprite is not in the embedded assets: %v", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read the sprite: %v", err)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`<symbol id="(i-[a-z0-9-]+)"`).FindAllStringSubmatch(string(raw), -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("the sprite defines no symbols, so this test is not looking at the sprite")
	}
	return out
}

// render returns a component's bytes.
func render(t *testing.T, c interface {
	Render(ctx context.Context, w io.Writer) error
}) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// sheetURL is a character sheet's public URL.
//
// It is written out rather than assembled from the route pattern, because the
// pattern carries a `*` wildcard and concatenating a path onto a wildcard
// produces a URL that matches nothing — which is a 404 for the wrong reason and
// a test that passes while asserting nothing.
func sheetURL(path string) string {
	return "/plugin/" + ID + "/character/" + path
}

// serve issues a GET through a router and returns the body and the status.
func serve(t *testing.T, router *chi.Mux, path string) (string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	return rec.Body.String(), rec.Code
}

// TestTheSourceFilesAreAllChecked keeps the file walkers honest.
//
// Every assertion in this file that reads the package directory skips test
// files, which is right for a boundary check and wrong for "the thing I meant to
// scan is not there". If a file is renamed out of the set, the scan quietly
// covers less and still passes, so the set is asserted explicitly.
func TestTheSourceFilesAreAllChecked(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(entry.Name(), "_test.go"):
		case strings.HasSuffix(entry.Name(), ".go"), strings.HasSuffix(entry.Name(), ".templ"):
			seen[entry.Name()] = true
		}
	}
	want := []string{"doc.go", "plugin.go", "hostcall.go", "character.templ", "panels.templ", "character_templ.go", "panels_templ.go"}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("%s is not in the package directory, so the scans over it are covering less than they claim", name)
		}
		delete(seen, name)
	}
	for name := range seen {
		t.Errorf("%s is a new source file: add it to the scans, because a file nothing scans is a file whose boundary was never checked", name)
	}
}
