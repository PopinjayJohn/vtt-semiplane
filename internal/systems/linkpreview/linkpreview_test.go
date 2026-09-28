package linkpreview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// The canaries below live in the Excerpt of a fixture page and in the body of a
// card that should never be rendered.
//
// They exist because the interesting assertion about this plugin is negative: a
// card may not show a page the viewer may not read, and may not show anything
// the page store did not hand it. A test that asserted only "the right card came
// back for a readable page" would still pass if a future edit started answering
// a DM-only page for everybody, and that edit would be the leak the whole
// feature exists to prevent.
const (
	// publicCanary is in the excerpt of the page every principal may read. It is
	// the positive control: a test that asserts the DM canary is absent is worth
	// nothing unless it also asserts the public one is present, or the absence
	// would be explained by a card that rendered nothing at all.
	publicCanary = "EXCERPT-CANARY-4a1f02-the-quiet-harbour"
	// dmCanary is in the excerpt of the page only a DM may preview. It exists
	// nowhere else, so finding it in a rendered card means a card was rendered
	// for a principal that may not have it.
	dmCanary = "EXCERPT-CANARY-9c7d55-the-cellar-key"
)

const (
	// publicPage is readable by any principal that may read public content.
	publicPage int64 = 11
	// dmPage carries a DM-only excerpt. In v1 there is no per-page ACL, so "DM
	// only" here is a property of this fixture rather than of the product; what
	// the test needs is a page the store answers ErrNoRows for, and a canary
	// sitting behind it.
	dmPage int64 = 12
	// emptyPage exists and carries no public text, which the store answers the
	// same way it answers for a page that does not exist.
	emptyPage int64 = 13
	// absentPage was never indexed at all.
	absentPage int64 = 999
)

// semverRe is a three-number version, which is the whole of what this package
// claims to ship. It is deliberately not the full semver grammar: a pre-release
// suffix is a thing a release process adds, and a test that accepted it would
// not notice a version that had quietly become something else.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// recordingHost is a plugin.Host that records every call.
//
// A fake host is not a convenience here, it is the only way to test a plugin: the
// real one needs a database, a vault lock and a boot sequence, and a test that
// boots all three to assert that a plugin returned one summary provider is a
// test that breaks for unrelated reasons. Every method is recorded so that a
// test can assert on what Register asked for and not only on what it returned.
type recordingHost struct {
	now    time.Time
	caps   plugin.Capabilities
	kind   plugin.Kind
	config plugin.Config
	fsys   fs.FS
	pages  plugin.PageStore
	// mux is the sub-router the host owns, already prefixed and already
	// wrapped. The plugin mounts on this one and never on a router of its own.
	mux *chi.Mux
	// routes is what the plugin actually mounted, read back from the router
	// rather than from anything the plugin said.
	routes []chi.Route

	// calls is the ordered list of method names the plugin made, one entry per
	// call, so that "the plugin asked for the page store" is checkable.
	calls []string
	// logs is every Log line the plugin emitted, message and key/values both.
	// The KVs are kept separately because they are where a plugin names what it
	// contributed: a boot report that showed the message but not the attributes
	// would say a plugin registered without saying what it registered.
	logs    []string
	logKeys []plugin.KV
	// faults is every way the plugin departed from the shape the host expects.
	faults []string
	// collected is what the host took from Summaries(), kept because the real
	// host takes it before Register and every request is answered by that copy
	// rather than by a later call.
	collected []plugin.SummaryProvider
}

// gather is the host's post-Register step, and the fake reproduces the real
// order exactly: the host builds itself — which is when it collects the plugin's
// summary providers — and only then calls Register. Reproducing that order is the
// point: a harness that registered first and collected afterwards would let a
// provider capture the page store by value, and a plugin that does that would
// look correct here and answer ErrNoRows to every page in a real boot.
func (h *recordingHost) gather(p *Plugin) {
	if ui, ok := any(p).(plugin.PluginUI); ok {
		h.collected = ui.Summaries()
	}
	if err := p.Register(context.Background(), h); err != nil {
		h.faults = append(h.faults, "Register: "+err.Error())
		return
	}
	ui, ok := any(p).(plugin.PluginUI)
	if !ok {
		h.faults = append(h.faults, "the plugin does not implement PluginUI, so the host reaches no summary provider for it")
		return
	}
	ui.RegisterRoutes(h.mux)
	h.routes = h.mux.Routes()
}

// The compile-time proof that a fake is a Host. It is the same assertion the
// production plugin makes about itself, and it is what makes this file a test of
// the contract rather than a test of a hand-written imitation of it: if the Host
// interface gains a method, this stops compiling.
var _ plugin.Host = (*recordingHost)(nil)

func (h *recordingHost) Log(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {
	h.calls = append(h.calls, "Log")
	h.logs = append(h.logs, msg)
	h.logKeys = append(h.logKeys, kv...)
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

func (h *recordingHost) Pages() plugin.PageStore {
	h.calls = append(h.calls, "Pages")
	if h.pages == nil {
		return &pageStore{}
	}
	return h.pages
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

// newFixtureStore returns a page store holding the three fixture pages.
//
// A store that answers from a fixed list rather than from a database is right
// here: the assertions are about which principal the plugin passes and what it
// does with the answer, and a real SQLite vault would add a dependency and a
// failure mode to neither. What the fake reproduces faithfully is the contract
// store.GetPageSummary states — ErrNoRows for a page this principal may not have,
// including for one that does not exist — because that contract is the whole of
// what the plugin relies on.
func newFixtureStore() *pageStore {
	return &pageStore{
		pages: []fixturePage{
			{
				sum: store.PageSummary{
					ID:        publicPage,
					Path:      "Places/Quiet Harbour.md",
					Title:     "The Quiet Harbour",
					Excerpt:   publicCanary + ", where the tide comes in and nobody hurries.",
					Tags:      []string{"location", "coast"},
					UpdatedAt: time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
				},
				readableBy: mayReadPublic,
			},
			{
				sum: store.PageSummary{
					ID:        dmPage,
					Path:      "Secrets/The Cellar Key.md",
					Title:     "The Cellar Key",
					Excerpt:   dmCanary + ", and what it opens.",
					Tags:      []string{"plot"},
					UpdatedAt: time.Date(2024, time.March, 2, 9, 30, 0, 0, time.UTC),
				},
				// The DM-only half. A player asking for this page gets
				// ErrNoRows, exactly as a page that does not exist would.
				readableBy: isDM,
			},
			{
				// Indexed, but with no public text at all, so the inner join
				// finds no row and the store declines it.
				sum: store.PageSummary{
					ID:    emptyPage,
					Path:  "Notes/Empty.md",
					Title: "Empty",
				},
				readableBy: mayReadPublic,
				noText:     true,
			},
		},
	}
}

// fixturePage is one page the fake store holds.
type fixturePage struct {
	sum store.PageSummary
	// readableBy decides, from the principal alone, whether this principal gets
	// a row or ErrNoRows. It is a func rather than a role so that the store
	// cannot accidentally be consulted about a page a player may not have.
	readableBy func(authz.Principal) bool
	// noText marks a page that exists but has no public text row, which the real
	// store answers ErrNoRows for because the join is an inner one.
	noText bool
}

func mayReadPublic(p authz.Principal) bool { return p.CanReadPublic() }
func isDM(p authz.Principal) bool          { return p.CanReadPublic() && p.IsDM() }

// pageStore is a plugin.PageStore over a fixed list of pages.
//
// It records every principal it was handed, which is what makes the security
// assertion mechanical: "the plugin passes the request's own principal" is a
// comparison against a recorded value rather than a reading of the code.
//
// It is guarded because a real PageStore is a database handle, and a server
// answers previews from several requests at once. A fake that was not
// concurrency-safe would fail `make test-race` in whichever test happened to run
// two subtests in parallel — and the fix there would be to stop testing two
// things at once, which is the wrong lesson to teach a fake.
type pageStore struct {
	mu sync.Mutex
	// pages is what this store holds. It is written before the store is handed
	// to the plugin and only read afterwards, so it needs no guard.
	pages []fixturePage
	// fault, when set, is returned by every read instead of a row. It models a
	// database that is there and unhappy, which is the case that must not be
	// mistaken for a page that does not exist. It is set through setFault.
	fault error
	// asked is one entry per GetPageSummary call, in order.
	asked []asked
}

// setFault makes every read fail with err.
func (s *pageStore) setFault(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = err
}

// askedFor returns a copy of the recorded calls, safe to read while other
// goroutines are calling the store.
func (s *pageStore) askedFor() []asked {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

// asked is one recorded call: which page, and under whose authority.
type asked struct {
	pageID int64
	who    authz.Principal
}

func (s *pageStore) GetPageSummary(ctx context.Context, who authz.Principal, pageID int64) (store.PageSummary, error) {
	s.mu.Lock()
	s.asked = append(s.asked, asked{pageID: pageID, who: who})
	fault := s.fault
	s.mu.Unlock()
	if fault != nil {
		return store.PageSummary{}, fault
	}
	for _, p := range s.pages {
		if p.sum.ID != pageID {
			continue
		}
		// The order is the store's order and is load-bearing: a principal that
		// may read nothing is refused before any page is considered, and a page
		// this principal may not have is refused rather than returned with
		// something removed from it.
		if !who.CanReadPublic() || !p.readableBy(who) || p.noText {
			return store.PageSummary{}, fmt.Errorf("page summary: %w", store.ErrNoRows)
		}
		return p.sum, nil
	}
	return store.PageSummary{}, fmt.Errorf("page summary: %w", store.ErrNoRows)
}

func (s *pageStore) ListPagesByType(ctx context.Context, who authz.Principal, pageType string) ([]store.Page, error) {
	return nil, nil
}

func (s *pageStore) CountPagesByType(ctx context.Context, who authz.Principal, pageType string) (int, error) {
	return 0, nil
}

func (s *pageStore) ListTags(ctx context.Context, who authz.Principal) ([]store.TagCount, error) {
	return nil, nil
}

var _ plugin.PageStore = (*pageStore)(nil)

// newFakeHost returns a host that grants everything this plugin declares, with a
// fixed clock, a fake vault and the fixture page store.
func newFakeHost(t *testing.T) *recordingHost {
	t.Helper()
	return &recordingHost{
		now:    time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
		caps:   mustCapabilities(t),
		kind:   plugin.KindFeature,
		config: plugin.Config{Values: map[string]any{}},
		fsys:   fstest.MapFS{},
		pages:  newFixtureStore(),
		mux:    chi.NewRouter(),
	}
}

// register returns a plugin booted against the plain fake host, in the order the
// real host uses: collect the providers, then Register, then mount.
func register(t *testing.T) (*Plugin, *recordingHost) {
	t.Helper()
	h := newFakeHost(t)
	p := New()
	h.gather(p)
	if len(h.faults) > 0 {
		t.Fatalf("the host recorded %v", h.faults)
	}
	return p, h
}

// theProvider returns the single provider the host collected, and fails the test
// if there is not exactly one.
//
// It is the host's copy and not a fresh Summaries() call, because that is the
// one a request would be answered by — and because the host collects before
// Register, which is the order a provider that captured the page store by value
// would get wrong.
func theProvider(t *testing.T, p *Plugin, h *recordingHost) plugin.SummaryProvider {
	t.Helper()
	if len(h.collected) != 1 {
		t.Fatalf("the host collected %d summary providers, want 1", len(h.collected))
	}
	fresh := p.Summaries()
	if len(fresh) != 1 {
		t.Fatalf("Summaries returned %d providers, want 1", len(fresh))
	}
	if fresh[0].ID() != h.collected[0].ID() {
		t.Errorf("the provider the host collected is %q and the one Summaries now returns is %q; a host that collected one and got another is a host answering requests with something nobody audited",
			h.collected[0].ID(), fresh[0].ID())
	}
	return h.collected[0]
}

// aContextFor is the context a request arrives with: the principal the session
// middleware resolved, carried by authz.
func aContextFor(who authz.Principal) context.Context {
	return authz.WithPrincipal(context.Background(), who)
}

// renderCard renders a component to the string a reader would receive.
//
// The render goes into a buffer, and a card that cannot be rendered is a test
// failure rather than an empty string: a body of "" would satisfy every "does
// not contain" assertion below, which is the failure mode a negative test has.
func renderCard(t *testing.T, c templ.Component) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render the card: %v", err)
	}
	return buf.String()
}

// TestTheDescriptorIsWellFormed checks the declaration, and ParseCapabilities
// checks it for real.
//
// ParseCapabilities is the assertion that matters. A capability name the host
// does not recognise is not an error anywhere else in the system: the plugin
// believes it holds the capability, nothing does, and the consequence is a
// preview that silently never appears rather than a boot failure.
func TestTheDescriptorIsWellFormed(t *testing.T) {
	t.Parallel()
	d := New().Descriptor()

	if err := d.ValidateID(); err != nil {
		t.Errorf("ValidateID: %v", err)
	}
	if d.ID != "linkpreview" {
		t.Errorf("ID = %q, want %q: it is the last segment of the summary URL, and a second spelling is a preview that 404s on every hover", d.ID, "linkpreview")
	}
	if !d.Kind.Valid() {
		t.Errorf("Kind %q is not valid", d.Kind)
	}
	if d.Kind != plugin.KindFeature {
		t.Errorf("Kind = %q, want %q: this is a feature, not a game system", d.Kind, plugin.KindFeature)
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
	if !granted.Has(plugin.CapPageSummaries) {
		t.Errorf("the descriptor does not claim %q, so the host discards the provider and no preview ever appears", plugin.CapPageSummaries)
	}
	// One, named above, and no more. A second would be a capability this plugin
	// has no contribution for, which the working agreement calls a control with
	// nothing behind it.
	if len(d.Capabilities) != 1 {
		t.Errorf("the descriptor claims %d capabilities, want 1: %v", len(d.Capabilities), d.Capabilities)
	}
}

// TestAFeatureDeclaresNoPageTypeNoNavAndNoSchema is the KindFeature rule, and
// every half of it.
//
// It is checked three ways because three different code paths read it: the
// descriptor is what the version gate and the kind rules run against, CoreTypes
// is what the host calls on a plugin that implements PluginCore, and NavItems is
// what a host collects after Register.
func TestAFeatureDeclaresNoPageTypeNoNavAndNoSchema(t *testing.T) {
	t.Parallel()
	p, _ := register(t)
	d := p.Descriptor()

	if len(d.PageTypes) != 0 {
		t.Errorf("the descriptor declares %d page types: a feature plugin may not register page types, and that is a boot error for the plugin", len(d.PageTypes))
	}
	if got := p.CoreTypes(); len(got) != 0 {
		t.Errorf("CoreTypes returned %d page types: the host faults a feature plugin that builds one at register time too", len(got))
	}
	if len(d.NavItems) != 0 {
		t.Errorf("the descriptor declares %d nav items: this plugin has no page of its own to link one to", len(d.NavItems))
	}
	if got := p.NavItems(); len(got) != 0 {
		t.Errorf("NavItems returned %d items", len(got))
	}
	if got := d.ConfigSchema; len(got) != 0 {
		t.Errorf("the descriptor declares %d settings, want 0: a schema is a promise that a value is read and validated", len(got))
	}
	if got := p.ConfigSchema(); len(got) != 0 {
		t.Errorf("ConfigSchema returned %d settings, want 0", len(got))
	}
	if got := d.Migrations; len(got) != 0 {
		t.Errorf("the descriptor declares %d migrations: a card is derived from the index and owns no state", len(d.Migrations))
	}
	if got := d.SearchResolvers; len(got) != 0 {
		t.Errorf("the descriptor declares %d search resolvers: a card is not a search result", len(got))
	}
	if got := p.MarkdownExtenders(); len(got) != 0 {
		t.Errorf("MarkdownExtenders returned %d extenders: the card renders a store.PageSummary, not markdown", len(got))
	}
	if got := p.Panels(); len(got) != 0 {
		t.Errorf("Panels returned %d panels: a panel renders on every page in the vault, whether or not a reader ever points at a link", len(got))
	}
}

// TestTheDescriptorIsAValueEachCallerOwns guards the one piece of shared mutable
// state this package could have introduced.
//
// A Descriptor is mutable — a caller may reorder its slices — so handing out the
// package-level capability table would let the first caller to touch it change
// what every later caller sees, and the boot report and the host's grant would
// then be describing different plugins.
func TestTheDescriptorIsAValueEachCallerOwns(t *testing.T) {
	t.Parallel()
	first := New().Descriptor()
	first.Capabilities[0] = plugin.CapMaps

	second := New().Descriptor()
	if second.Capabilities[0] != plugin.CapPageSummaries {
		t.Errorf("a caller that rewrote its own descriptor changed what the next one sees: %v", second.Capabilities)
	}
}

// TestTheProviderIsContributedAndCarriesNoStalePageStore is the collection
// contract, and the ordering in it is the part that matters.
//
// plugin.Host collects a plugin's summary providers while it is being built,
// which is before Register has run. So a provider that captured the page store
// by value would be holding whatever a host hands out at collection time — and
// the host answers that with the empty store, the one that returns ErrNoRows to
// every page. The plugin therefore hands the host a provider that resolves the
// store per request, and this test reproduces the real collection order so that
// a regression to a captured value fails here rather than in a campaign where
// every link previews as nothing.
func TestTheProviderIsContributedAndCarriesNoStalePageStore(t *testing.T) {
	t.Parallel()
	who := authz.ForUser(7, "gundren", authz.RolePlayer, false)
	p, h := register(t)

	providers := p.Summaries()
	if len(providers) != 1 {
		t.Fatalf("Summaries returned %d providers, want 1", len(providers))
	}
	if got := providers[0].ID(); got != providerID {
		t.Errorf("provider ID = %q, want %q", got, providerID)
	}
	// It is contributed exactly once, and the id is stable across calls: two
	// providers under one id would be a duplicate the host's registry has to
	// resolve, and which one won would be a decision a reader cannot see.
	if again := p.Summaries(); len(again) != 1 || again[0].ID() != providerID {
		t.Errorf("Summaries is not stable: %v", again)
	}
	// Register takes the page store, and every request is answered through it.
	if !contains(h.calls, "Pages") {
		t.Errorf("Register never asked for the page store, so the provider has nothing to read. Calls: %v", h.calls)
	}
	// The provider the host collected before Register still reads the store
	// Register captured, which is the whole point of the ordering above.
	body, ok, err := theProvider(t, p, h).Summary(aContextFor(who), publicPage)
	if err != nil || !ok || body == nil {
		t.Fatalf("the provider the host collected answered ok=%v err=%v on a page this principal may read: it captured the page store before Register gave it one", ok, err)
	}
	_ = renderCard(t, body)
}

// TestAContextWithNoPrincipalIsDeclinedForEveryPage is the fail-closed half.
//
// authz.PrincipalFrom on a context that never went through WithPrincipal yields
// the zero Principal, which is anonymous and cannot read public content, so the
// page store answers ErrNoRows and the preview declines. That is the direction
// that matters: a caller that lost the request's identity reads nothing rather
// than reading everything, and the plugin does not need a guard of its own to
// make that true.
func TestAContextWithNoPrincipalIsDeclinedForEveryPage(t *testing.T) {
	t.Parallel()
	p, h := register(t)
	provider := theProvider(t, p, h)

	// A bare context, and one that has been through some other package's key
	// machinery. Both read as the zero principal.
	contexts := map[string]context.Context{
		"a context that was never given a principal": context.Background(),
		"a cancelled context":                        cancelledContext(),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, pageID := range []int64{publicPage, dmPage, emptyPage} {
				body, ok, err := provider.Summary(ctx, pageID)
				if err != nil {
					t.Errorf("page %d: Summary returned %v, want a silent decline", pageID, err)
				}
				if ok || body != nil {
					t.Errorf("page %d: ok=%v body=%v, want a decline: a preview answered without a principal is a preview served to whoever asked for it", pageID, ok, body != nil)
				}
			}
		})
	}
}

// cancelledContext is a context that was never given a principal and is already
// done, which is the shape a request looks like after the reader navigated away.
func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestTheBootReportNamesWhatWasContributed checks the one line an operator will
// ever read about this plugin.
//
// The boot report is the only place a refusal, a missing page store or a
// capability the host withheld becomes visible, and it is read long after the
// boot that produced it. A plugin that registers silently is a plugin whose
// absence is indistinguishable from one that was never installed — so the line
// has to name the plugin and the provider it contributed.
func TestTheBootReportNamesWhatWasContributed(t *testing.T) {
	t.Parallel()
	_, h := register(t)

	var line string
	for _, l := range h.logs {
		if strings.Contains(l, "linkpreview registered") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no log line says the plugin registered, so the boot report cannot say that previews exist. Lines: %v", h.logs)
	}
	// The provider id is in an attribute rather than the message, which is where
	// a structured line belongs, and the fake records attributes separately
	// precisely so this test can insist on it.
	var named bool
	for _, kv := range h.logKeys {
		if kv.Key == "provider" && fmt.Sprint(kv.Value) == providerID {
			named = true
		}
	}
	if !named {
		t.Errorf("no log attribute names the provider %q, so the boot report cannot say what was contributed. Attributes: %v", providerID, h.logKeys)
	}
}

// TestNoRouteIsMountedBecauseCoreOwnsTheSummaryEndpoint records a conclusion
// rather than asserting a coincidence.
//
// The summary endpoint is GET /plugin/{id}/summary/{pageID} and core mounts it
// in internal/httpapi/routes.go. A plugin-owned mount of the same path would be
// chi's rule — first handler wins, the second is invisible — and would put a
// plugin in front of the byte-identical 404 that httpapi.writeError produces and
// a plugin cannot reproduce.
func TestNoRouteIsMountedBecauseCoreOwnsTheSummaryEndpoint(t *testing.T) {
	t.Parallel()
	_, h := register(t)

	if len(h.routes) != 0 {
		var patterns []string
		for _, r := range h.routes {
			patterns = append(patterns, r.Pattern)
		}
		t.Errorf("the plugin mounted %v: the summary endpoint is core's, and a second mount of the same path would shadow the byte-identical 404", patterns)
	}
}

// TestThePrincipalHandedToThePageStoreIsTheOnesTheHostResolved is the security
// property, stated as a comparison rather than as a reading of the code.
//
// Every one of these principals is offered, and the assertion is that the value
// recorded at the page store is byte-equal to the one the host resolved for that
// request. A plugin that defaulted to anonymous, or that substituted a DM, or
// that reconstructed a principal from the page id would fail here — which is the
// only reason this test exists rather than a comment.
func TestThePrincipalHandedToThePageStoreIsTheOnesTheHostResolved(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		who  authz.Principal
	}{
		{name: "a player", who: authz.ForUser(7, "gundren", authz.RolePlayer, false)},
		{name: "a dm", who: authz.ForUser(3, "mara", authz.RoleDM, false)},
		{name: "an admin", who: authz.ForUser(1, "rowan", authz.RoleAdmin, false)},
		{name: "an anonymous reader with anonymous read on", who: authz.Anonymous(true)},
		{name: "an anonymous reader with anonymous read off", who: authz.Anonymous(false)},
		{
			// A principal with a session id and an authz generation, because a
			// plugin that rebuilt one field-by-field from what it could see would
			// pass every row above and fail this one.
			name: "a principal carrying a session and a generation",
			who: authz.Principal{
				UserID: 7, Username: "gundren", Role: authz.RolePlayer,
				SessionID: "e3b0c44298fc1c14", AuthzGeneration: 42,
				AllowAnonymousRead: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, h := register(t)
			store := p.pages.(*pageStore)

			if _, _, err := theProvider(t, p, h).Summary(aContextFor(tc.who), publicPage); err != nil {
				t.Fatalf("Summary: %v", err)
			}
			calls := store.askedFor()
			if len(calls) != 1 {
				t.Fatalf("the page store was asked %d times, want 1: %v", len(calls), calls)
			}
			if calls[0].pageID != publicPage {
				t.Errorf("the page store was asked about page %d, want %d", calls[0].pageID, publicPage)
			}
			if calls[0].who != tc.who {
				t.Errorf("the page store was handed %v, want %v: a preview answered under a principal other than the request's own is the leak this plugin exists not to have", calls[0].who, tc.who)
			}
		})
	}
}

// TestAPageThePrincipalMayNotReadIsDeclined is the other half of the same
// property, from the outside.
//
// ok=false is the whole of the answer, and core turns it into a 404 that is
// byte-identical to navigating to the page. What must not happen is a card that
// shows something, or an error that says why — a 500 says "this page exists" to
// anyone who can tell the two apart, and core answers an error with 404 for
// exactly that reason.
func TestAPageThePrincipalMayNotReadIsDeclined(t *testing.T) {
	t.Parallel()
	player := authz.ForUser(7, "gundren", authz.RolePlayer, false)
	dm := authz.ForUser(3, "mara", authz.RoleDM, false)

	tests := []struct {
		name   string
		who    authz.Principal
		pageID int64
		wantOK bool
	}{
		{name: "a player asks for a public page", who: player, pageID: publicPage, wantOK: true},
		{name: "a player asks for a dm-only page", who: player, pageID: dmPage},
		{name: "a dm asks for a dm-only page", who: dm, pageID: dmPage, wantOK: true},
		{name: "a page with no public text", who: player, pageID: emptyPage},
		{name: "a page that was never indexed", who: player, pageID: absentPage},
		{name: "a page id of zero", who: dm, pageID: 0},
		{name: "a negative page id", who: dm, pageID: -4},
		{
			name:   "an anonymous reader with anonymous read off",
			who:    authz.Anonymous(false),
			pageID: publicPage,
		},
		{
			name:   "an anonymous reader with anonymous read on",
			who:    authz.Anonymous(true),
			pageID: publicPage,
			wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, h := register(t)

			body, ok, err := theProvider(t, p, h).Summary(aContextFor(tc.who), tc.pageID)
			if err != nil {
				t.Fatalf("Summary returned an error: %v. A decline is ok=false, not a failure: core answers both with the same 404.", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				if body != nil {
					t.Errorf("a declined page still returned a component; core only checks ok, and a body beside ok=false is a card nobody asked for")
				}
				return
			}
			if body == nil {
				t.Fatalf("ok = true with a nil body: core answers a nil body with a 404, so a card that never renders is a preview that never appears")
			}
			_ = renderCard(t, body)
		})
	}
}

// TestTheCardNeverShowsAThingTheViewerMayNotRead is the assertion that the
// table above only gestures at, and it is deliberately both-polarity.
//
// The DM case asserts the canary IS present. Without it, every "does not
// contain" assertion below would also pass for a card that rendered nothing, and
// a card that renders nothing is the failure mode a fake store produces when a
// plugin declines too eagerly.
func TestTheCardNeverShowsAThingTheViewerMayNotRead(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		who  authz.Principal
		// pageID is the page hovered.
		pageID int64
		// wantVisible and wantHidden are the canaries the rendered card must and
		// must not carry. An empty entry asserts nothing about that canary,
		// which is how the DM case checks the positive control without
		// restating it.
		wantVisible string
		wantHidden  string
	}{
		{
			name: "a player hovering a public page",
			who:  authz.ForUser(7, "gundren", authz.RolePlayer, false),
			// The player's own page carries the public canary, so "the card is
			// not empty" and "the card is not a DM card" are both checked by
			// one render.
			pageID:      publicPage,
			wantVisible: publicCanary,
			wantHidden:  dmCanary,
		},
		{
			name:        "a dm hovering the dm-only page",
			who:         authz.ForUser(3, "mara", authz.RoleDM, false),
			pageID:      dmPage,
			wantVisible: dmCanary,
			wantHidden:  publicCanary,
		},
		{
			name:        "an anonymous reader with anonymous read on",
			who:         authz.Anonymous(true),
			pageID:      publicPage,
			wantVisible: publicCanary,
			wantHidden:  dmCanary,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, h := register(t)

			body, ok, err := theProvider(t, p, h).Summary(aContextFor(tc.who), tc.pageID)
			if err != nil || !ok {
				t.Fatalf("Summary: ok=%v err=%v", ok, err)
			}
			html := renderCard(t, body)

			if tc.wantVisible != "" && !strings.Contains(html, tc.wantVisible) {
				t.Errorf("the card does not contain %q, so this test cannot tell a correct card from an empty one:\n%s", tc.wantVisible, html)
			}
			if tc.wantHidden != "" && strings.Contains(html, tc.wantHidden) {
				t.Errorf("the card contains %q, which this principal may not read:\n%s", tc.wantHidden, html)
			}
		})
	}
}

// TestTheStoreErrorPropagatesAndTheAbsenceOfTheRowDeclines separates the two
// non-card answers, because conflating them is the whole failure.
//
// store.ErrNoRows is the documented degradation and must be silent: core turns
// it into the same 404 a missing page gets. Every other error is a failure, and
// core logs it and answers 404 too — but a plugin that swallowed it would turn
// a broken database into "that link has no preview", which is a diagnostic an
// operator can act on being lost to a 404 nobody can act on.
func TestTheStoreErrorPropagatesAndTheAbsenceOfTheRowDeclines(t *testing.T) {
	t.Parallel()
	who := authz.ForUser(7, "gundren", authz.RolePlayer, false)

	tests := []struct {
		name    string
		fault   error
		wantErr bool
	}{
		{name: "the store has no row for this principal", fault: fmt.Errorf("page summary: %w", store.ErrNoRows)},
		{name: "the store is closed", fault: errors.New("store: database is closed"), wantErr: true},
		{name: "the store fails on a wrapped absence", fault: fmt.Errorf("linkpreview: reading: %w", store.ErrNoRows)},
		{
			// The trap: a query error that happens to wrap sql.ErrNoRows is not
			// store.ErrNoRows, and treating it as an absence would swallow a
			// failure. store.GetPageSummary translates before it returns, so a
			// plugin that matched on the sql sentinel instead would be matching
			// on a value store never hands out.
			name:    "a wrapped sql absence is not store's own",
			fault:   fmt.Errorf("store: get page summary: %w", errFakeSQLNoRows),
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, h := register(t)
			fake := p.pages.(*pageStore)
			fake.setFault(tc.fault)

			body, ok, err := theProvider(t, p, h).Summary(aContextFor(who), publicPage)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Summary swallowed %v and answered ok=%v: a failure reported as a missing page is a broken index nobody can act on", tc.fault, ok)
				}
				if !errors.Is(err, tc.fault) {
					t.Errorf("the error does not wrap its cause: got %v, want one wrapping %v", err, tc.fault)
				}
				// The message carries the page id, so an operator can find the
				// request, and never the page: an error that quoted the excerpt
				// would be a way to get vault text into a log line.
				if !strings.Contains(err.Error(), strconv.Itoa(int(publicPage))) {
					t.Errorf("the error does not name the page id: %v", err)
				}
			} else if err != nil {
				t.Fatalf("Summary returned %v, want a silent decline", err)
			}
			if ok || body != nil {
				t.Errorf("ok=%v body=%v, want ok=false and no body", ok, body != nil)
			}
		})
	}
}

// errFakeSQLNoRows stands in for database/sql's sentinel without importing
// database/sql into a plugin test for one value. store translates sql.ErrNoRows
// into store.ErrNoRows at its own boundary, which is exactly the reason a plugin
// must not match the inner one.
var errFakeSQLNoRows = errors.New("sql: no rows in result set")

// TestTheCardShowsWhatTheRowCarries is the positive content assertion, and it is
// the one that would notice a field quietly disappearing from the card.
func TestTheCardShowsWhatTheRowCarries(t *testing.T) {
	t.Parallel()
	who := authz.ForUser(7, "gundren", authz.RolePlayer, false)
	p, h := register(t)

	body, ok, err := theProvider(t, p, h).Summary(aContextFor(who), publicPage)
	if err != nil || !ok {
		t.Fatalf("Summary: ok=%v err=%v", ok, err)
	}
	html := renderCard(t, body)

	want := []string{
		"The Quiet Harbour",
		publicCanary,
		"location",
		"coast",
		"2024-03-01",
		// The machine-readable instant as well as the visible day: a reader in a
		// campaign that runs past midnight has a card that says the 2nd and no
		// way to tell which 2nd.
		`datetime="2024-03-01T12:00:00Z"`,
	}
	for _, w := range want {
		if !strings.Contains(html, w) {
			t.Errorf("the card does not carry %q:\n%s", w, html)
		}
	}
	// The page's own path is not shown. A path is a filesystem fact rather than
	// something a reader typed, and a card that shows one invites it to be
	// pasted into an edit.
	if strings.Contains(html, "Quiet Harbour.md") {
		t.Errorf("the card shows the vault-relative path:\n%s", html)
	}
}

// TestTheCardOmitsWhatTheRowDoesNotCarry is the other half: a card must not
// render an empty paragraph, an empty tag list or the year 1, because a card
// with a blank under the title is a claim that the page is blank.
func TestTheCardOmitsWhatTheRowDoesNotCarry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		card Card
		want []string
		// unwanted is a marker that must not appear at all.
		unwanted []string
	}{
		{
			name:     "a title alone",
			card:     Card{Title: "Only a title"},
			want:     []string{"Only a title"},
			unwanted: []string{"<p", "<ul", "<time", "<li"},
		},
		{
			name:     "an excerpt with nothing else",
			card:     Card{Title: "T", Excerpt: "the text"},
			unwanted: []string{"<ul", "<time"},
		},
		{
			name:     "tags with no excerpt",
			card:     Card{Title: "T", Tags: []string{"a", "b"}},
			want:     []string{"<li", "a", "b"},
			unwanted: []string{"<time"},
		},
		{
			name:     "a zero timestamp",
			card:     Card{Title: "T", UpdatedAt: time.Time{}},
			unwanted: []string{"<time", "0001-01-01"},
		},
		{
			name:     "an empty tag slice",
			card:     Card{Title: "T", Tags: []string{}},
			unwanted: []string{"<ul"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			html := renderCard(t, summaryCard(tc.card))
			for _, w := range tc.want {
				if !strings.Contains(html, w) {
					t.Errorf("the card does not carry %q:\n%s", w, html)
				}
			}
			for _, u := range tc.unwanted {
				if strings.Contains(html, u) {
					t.Errorf("the card carries %q, which this row does not justify:\n%s", u, html)
				}
			}
		})
	}
}

// TestVaultDerivedTextIsEscaped is the reason this file cannot mark a string
// raw, checked against text that would be dangerous if it were not.
//
// A preview is the one surface that shows a page's own words to somebody who has
// not opened that page, so it is also the one where an unescaped author-supplied
// string would be stored cross-site scripting against every reader in the
// campaign.
func TestVaultDerivedTextIsEscaped(t *testing.T) {
	t.Parallel()
	hostile := `<script>alert("x")</script> & "quotes" 'single'`

	html := renderCard(t, summaryCard(Card{
		Title:     hostile,
		Excerpt:   hostile,
		Tags:      []string{hostile},
		UpdatedAt: time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
	}))

	if strings.Contains(html, "<script") {
		t.Errorf("the card emitted a live script element:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("the card did not escape the title at all:\n%s", html)
	}
	// The three characters that end a value or a text node. templ writes the
	// quote as a numeric reference rather than a named one, so the expectation
	// is on the reference it actually emits: an assertion on &quot; alone would
	// pass for a card that emitted nothing at all.
	for _, want := range []string{"&amp;", "&#34;", "&#39;"} {
		if !strings.Contains(html, want) {
			t.Errorf("the card does not carry %q, so one of the three unsafe characters reached a reader unescaped:\n%s", want, html)
		}
	}
	// The escaped text is still text: a card that showed an author their
	// literal markup would be a preview that mangles the note it is previewing.
	if !strings.Contains(html, "alert(") {
		t.Errorf("the card dropped the author's words along with the markup:\n%s", html)
	}
}

// TestTheCardHasNoInteractiveElement is the rule about focus, and it is
// stronger than the token scan below because it asserts the rendered result
// rather than the source.
//
// The transient card is role="tooltip". A tooltip must not trap focus and must
// not contain a control, because a reader tabbing through a page would land
// inside a card that is about to disappear. The one interactive element a
// preview does have — the pin toggle — belongs to core, because acting on it is
// behaviour and a plugin cannot ship behaviour.
func TestTheCardHasNoInteractiveElement(t *testing.T) {
	t.Parallel()
	html := renderCard(t, summaryCard(Card{
		Title:     "The Quiet Harbour",
		Excerpt:   "Some public text.",
		Tags:      []string{"location"},
		UpdatedAt: time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
	}))

	// tagOpen matches an opening tag by name, so it catches a bare <button> as
	// readily as a button with a class on it.
	tagOpen := regexp.MustCompile(`<\s*(a|button|input|select|textarea|form|details|summary|iframe|object|embed|video|audio)\b`)
	if m := tagOpen.FindString(html); m != "" {
		t.Errorf("the card renders %q, which is an interactive or focusable element inside a role=tooltip:\n%s", m, html)
	}
	for _, needle := range []string{"tabindex", "role=\"button\"", "href=", "onclick", "onfocus", "onmouseover"} {
		if strings.Contains(html, needle) {
			t.Errorf("the card carries %q, which is focus wiring core owns:\n%s", needle, html)
		}
	}
	// One root element, because the client replaces the card's children as a
	// unit and a stray sibling text node beside the article is text nobody
	// styled.
	if !strings.HasPrefix(html, "<article") {
		t.Errorf("the card does not start at its root element:\n%s", html)
	}
	if strings.Count(html, "<article") != 1 {
		t.Errorf("the card renders %d root elements, want 1:\n%s", strings.Count(html, "<article"), html)
	}
}

// TestNoJavaScriptCSSOrDOMHandleIsShipped is the source-side twin, over the
// templ file and its generated output.
//
// The generated file is scanned because it is the artefact that is actually
// shipped, and a templ version that started emitting one of these would be
// caught here rather than in a browser. That is why the source comments in
// card.templ talk about these constructs without spelling them.
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
		"onmouseover=": "an inline event handler is JavaScript in an attribute",
		"data-on:":     "a DataStar expression is a behaviour binding; behaviours are core-owned",
		"data-bind:":   "a DataStar binding is a behaviour binding; behaviours are core-owned",
		"data-effect:": "a DataStar effect is a behaviour binding; behaviours are core-owned",
		"javascript:":  "a javascript: URL is script execution with a link's clothing on",
		"templ.Raw(":   "a plugin may not mark a string raw, so no string of its own can reach a reader unescaped",
		"unsafeHTML(":  "an unescaped render path is templ.Raw with a different spelling",
		"id=\"":        "a DOM handle: the ids core's own client binds to belong to core",
		"Continue;":    "a continue in a templ loop whose body holds markup compiles to the literal word continue",
	}
	// The ids core's own client binds to. A plugin that rendered one of them
	// would be a second owner of an element the shell already owns, and the
	// collision is a silently broken drawer rather than a build failure.
	coreIDs := []string{"shell", "left-nav", "content", "context", "page-region", "palette", "shortcuts", "preview", "preview-card"}

	files := []string{"card.templ", "card_templ.go"}
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

// TestTheCardShipsNoClassTheStylesheetHasNeverHeard is the CSS half, and it is
// the test that would notice a plugin inventing a design token.
//
// A plugin ships no CSS, so every class it writes has to be one the committed
// stylesheet already defines. A class that is not in the stylesheet is not an
// error — it is silently unstyled markup, which is a card that looks broken
// rather than absent, and that is the harder of the two to notice.
func TestTheCardShipsNoClassTheStylesheetHasNeverHeard(t *testing.T) {
	t.Parallel()
	// card, card-heading and the neutral palette are the tokens the card reuses,
	// and they are listed here rather than read out of the stylesheet because
	// the stylesheet is a generated artefact: a rebuild that dropped a rule
	// would change this list, and a list that follows the artefact cannot tell
	// a dropped rule from a class the card invented.
	known := []string{
		"card", "card-heading",
		"p-3", "text-sm", "mt-1", "mt-2", "mb-1",
		"font-semibold", "leading-snug",
		"flex", "flex-wrap", "gap-1", "text-xs", "block",
		"rounded", "border", "px-1.5", "py-0.5",
		"text-neutral-300", "text-neutral-400", "text-neutral-500", "text-neutral-700",
		"border-neutral-300", "border-neutral-700",
		"dark:border-neutral-700", "dark:text-neutral-300", "dark:text-neutral-400", "dark:text-neutral-500", "dark:text-neutral-700",
	}
	knownSet := map[string]bool{}
	for _, k := range known {
		knownSet[k] = true
	}

	html := renderCard(t, summaryCard(Card{
		Title:     "T",
		Excerpt:   "e",
		Tags:      []string{"a"},
		UpdatedAt: time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC),
	}))
	classAttr := regexp.MustCompile(`class="([^"]*)"`)
	for _, m := range classAttr.FindAllStringSubmatch(html, -1) {
		for _, c := range strings.Fields(m[1]) {
			if !knownSet[c] {
				t.Errorf("the card uses the class %q, which is not one the committed stylesheet defines: a plugin ships no CSS, so that is unstyled markup", c)
			}
		}
	}
}

// TestTheImportsAreWithinThePluginBoundary re-checks the allow-list from inside
// the plugin.
//
// internal/architecture_test.go enforces it too, and this is not a second gate —
// it is a gate that names its own evidence. The architecture test skips when it
// finds no plugin implementation file, so a package that existed only as doc.go
// would leave that gate with nothing to scan. Here, a violation fails in this
// directory with the file and the line.
func TestTheImportsAreWithinThePluginBoundary(t *testing.T) {
	t.Parallel()
	// The allow-list, restated with each entry's reason, from AGENTS.md §7. The
	// forbidden ones are the packages whose reach would bypass a redaction or a
	// session: httpapi holds the byte-identical 404 and the principal, auth
	// holds the session, obs holds the redacting log handler, sync writes the
	// index, config is core's, app is the composition root.
	allowed := map[string]string{
		"github.com/PopinjayJohn/vtt-semiplane/internal/plugin":  "the plugin contract",
		"github.com/PopinjayJohn/vtt-semiplane/internal/authz":   "Principal and the visibility vocabulary",
		"github.com/PopinjayJohn/vtt-semiplane/internal/store":   "PageSummary and ErrNoRows",
		"github.com/PopinjayJohn/vtt-semiplane/internal/md":      "frontmatter helpers",
		"github.com/PopinjayJohn/vtt-semiplane/internal/secrets": "the secret vocabulary",
		"github.com/PopinjayJohn/vtt-semiplane/internal/web":     "templ components",
		"github.com/a-h/templ":                                   "the component type",
		"github.com/yuin/goldmark":                               "markdown extenders",
		"github.com/go-chi/chi/v5":                               "the router a plugin may mount on",
	}
	forbidden := map[string]string{
		"internal/httpapi": "it holds writeError and the request's principal, and bypassing both is the boundary's whole purpose",
		"internal/auth":    "it holds session handling and the principal capture",
		"internal/obs":     "it holds the redacting log handler",
		"internal/sync":    "it writes the index behind the indexer's back",
		"internal/config":  "it is core configuration a plugin has no business reading",
		"internal/app":     "it is the composition root, not a library",
		"internal/systems": "a plugin that could import another plugin could reach whatever that one was given",
	}
	// Standard library and the three third-party roots above are always allowed;
	// anything else that is not one of ours is somebody else's module and is not
	// this test's business.
	ours := "github.com/PopinjayJohn/vtt-semiplane/"

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	var checked int
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// The generated file imports the same set as its source, and a test
		// file's imports are the test harness's business rather than the
		// plugin's. Both are excluded so the count below means what it says.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(path, ours) {
				continue
			}
			checked++
			rel := strings.TrimPrefix(path, ours)
			if why, bad := forbidden[rel]; bad {
				t.Errorf("%s imports %s: %s", name, rel, why)
			}
			if _, ok := allowed[path]; !ok {
				t.Errorf("%s imports %s, which is outside the plugin boundary", name, rel)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no internal import was found to check, so this boundary test passed without running")
	}
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
	want := []string{"doc.go", "plugin.go", "card.templ", "card_templ.go"}
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

// TestTheGeneratedCardIsCommittedAndCurrent keeps the generated artefact honest.
//
// AGENTS.md §8: *_templ.go is generated, committed, and never hand-edited. A
// generated file that is stale passes every behavioural test in this file, because
// the tests read whatever is on disk — so the check has to be that the thing on
// disk is what the source produces.
func TestTheGeneratedCardIsCommittedAndCurrent(t *testing.T) {
	t.Parallel()
	// The generated file is a build artefact of card.templ. Regenerating it needs
	// the templ tool, which is pinned in go.mod and may not be present in every
	// environment this test runs in, so the check that always runs is the one
	// that does not need it: the file exists, is not a stub, and carries the
	// component the package calls.
	src, err := os.ReadFile("card_templ.go")
	if err != nil {
		t.Fatalf("read card_templ.go: %v. It is generated and committed; run `make generate`.", err)
	}
	text := string(src)
	if !strings.Contains(text, "func summaryCard(c Card) templ.Component") {
		t.Error("card_templ.go does not define the component plugin.go calls: it is stale, or a different component was renamed without regenerating it")
	}
	if len(text) < 500 {
		t.Errorf("card_templ.go is %d bytes, which is too small to be the generated component: it is probably a stub", len(text))
	}
}

// TestNowIsTheHostsClock is the one method whose whole purpose is testability.
//
// A plugin that called time.Now directly would make every timestamp it wrote
// unfixable in a test, and "testable" is the only reason Host.Now exists.
func TestNowIsTheHostsClock(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC)
	h := newFakeHost(t)
	h.now = frozen
	p := New()
	h.gather(p)
	if len(h.faults) > 0 {
		t.Fatalf("the host recorded %v", h.faults)
	}
	if got := p.Now(); !got.Equal(frozen) {
		t.Errorf("Now() = %v, want the host's %v", got, frozen)
	}
	// The zero value answers rather than panicking, so a composition root that
	// skipped Register fails with a wrong clock instead of a crash.
	if got := New().Now(); !got.IsZero() {
		t.Errorf("an unregistered plugin answered Now() = %v, want the zero time", got)
	}
}

// TestTheDescriptorValidatorsRegisterReliesOnRejectWhatTheyShould covers the
// two boot errors Register can return.
//
// It cannot drive them through Register, and the reason is worth writing down:
// the declaration is not a parameter. A plugin builds its own Descriptor, so the
// only way to reach Register's id and kind refusals from a test is for the
// plugin to misdeclare itself — which would be a second code path in the
// production file for the sake of a test. So the checks are asserted against the
// exported validators Register calls, which is what would otherwise run only at
// boot, once, in a report an operator reads after something has already gone
// wrong.
func TestTheDescriptorValidatorsRegisterReliesOnRejectWhatTheyShould(t *testing.T) {
	t.Parallel()
	t.Run("a kind that is neither system nor feature", func(t *testing.T) {
		t.Parallel()
		for _, k := range []plugin.Kind{"game", "System", "", plugin.KindFeature} {
			if k.Valid() != (k == plugin.KindSystem || k == plugin.KindFeature) {
				t.Errorf("Kind(%q).Valid() disagrees with the rule Register applies", k)
			}
		}
		if plugin.Kind("game").Valid() {
			t.Error(`"game" is a valid kind, so Register's kind check would let a descriptor through that names no plugin kind`)
		}
	})
	t.Run("an id the host would refuse", func(t *testing.T) {
		t.Parallel()
		for _, id := range []string{"", "LinkPreview", "link preview", "link_preview", "link/preview"} {
			if err := (plugin.Descriptor{ID: id, Kind: plugin.KindFeature}).ValidateID(); err == nil {
				t.Errorf("ValidateID accepted %q, so Register's id check would let it through", id)
			}
		}
		if err := (plugin.Descriptor{ID: ID, Kind: plugin.KindFeature}).ValidateID(); err != nil {
			t.Errorf("ValidateID refused this package's own id %q: %v", ID, err)
		}
	})
}

// mustCapabilities is the grant the fake host offers, parsed through the host's
// own parser so a new capability cannot be quietly forgotten here.
func mustCapabilities(t *testing.T) plugin.Capabilities {
	t.Helper()
	caps, err := plugin.ParseCapabilities(New().Descriptor().Capabilities)
	if err != nil {
		t.Fatalf("the descriptor's own capabilities do not parse: %v", err)
	}
	return caps
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
