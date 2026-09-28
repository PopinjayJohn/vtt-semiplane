package houserules

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	webassets "github.com/PopinjayJohn/vtt-semiplane/web"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// The canaries below live in the fixture under testdata/, in the two places a
// house-rule index could plausibly leak from.
//
// bodyCanary is in the *body* of a rule and of a page of another type. The store
// row a plugin is given has no column for a body at all, so this canary is the
// assertion that the plugin cannot reach prose even by accident — and the reason
// a plugin's search row may only be built from frontmatter and a title.
//
// hiddenCanary is the *title* of a rule the fixture gives to a DM alone. A title
// is public text — it is in the file tree, the tag cloud, the command palette
// and every backlink — so the index must show it exactly to the principals whose
// store answer holds that row, and to nobody else. Every assertion about it is
// two-polarity: present for those who may open it, so that its absence for the
// rest means something.
const (
	bodyCanary   = "BODY-CANARY-4c1f02-under-the-stairs"
	hiddenCanary = "TITLE-CANARY-9ab77e-the-betrayal"
)

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
	pages  plugin.PageStore
	// mux is the sub-router the host owns, already prefixed and already wrapped.
	// The plugin mounts on this one and never on a router of its own, which is
	// what the real host's RegisterRoutes refuses.
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
// the contract rather than a test of a hand-written imitation of it: if the Host
// interface gains a method, this stops compiling.
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

func (h *recordingHost) Pages() plugin.PageStore {
	h.calls = append(h.calls, "Pages")
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

// newFakeHost returns a host that grants everything this plugin declares, which
// is what a first-party host does, plus a fixed clock, a small vault and the
// authz-filtered page store below.
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
		kind:   plugin.KindFeature,
		config: plugin.Config{Values: map[string]any{}},
		fsys:   fstest.MapFS{},
		pages:  newFakeStore(t),
		mux:    chi.NewRouter(),
	}
}

// register returns a plugin registered against the fake host, with the host's
// post-Register gather already run — so the routes are mounted, which is the
// state a real request would arrive in.
func register(t *testing.T) (*Plugin, *recordingHost) {
	t.Helper()
	return registerWith(t, newFakeHost(t))
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

// rootFor mounts a host's sub-router under the plugin prefix, the way the real
// host does, so the assertions cover the prefix and not just the handler.
func rootFor(t *testing.T, h *recordingHost) *chi.Mux {
	t.Helper()
	root := chi.NewRouter()
	root.Mount(plugin.PluginPrefix(ID), h.mux)
	return root
}

// serve issues a GET as a named principal and returns the body and the status.
//
// The principal goes on the context the way httpapi's session middleware puts it
// there, which is the only place a request's identity comes from. Everything
// this package asserts about who it is asking is asserted through this helper, so
// a plugin that stopped reading the context would answer every one of these with
// an empty list.
//
// Note the mount, not the helper: every route under a plugin prefix sits behind
// PermSession, so a real anonymous request is answered with the login redirect
// rather than with a 200. The router here is the bare sub-router the host hands
// the plugin, which is what a plugin's own test can reach.
func serveAs(t *testing.T, router *chi.Mux, path string, who authz.Principal) (string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx := authz.WithPrincipal(t.Context(), who)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	router.ServeHTTP(rec, req)
	return rec.Body.String(), rec.Code
}

// serve is serveAs for a signed-in player, which is the reader this page is for
// in every case where the choice does not matter.
func serve(t *testing.T, router *chi.Mux, path string) (string, int) {
	t.Helper()
	return serveAs(t, router, path, principalOutsider)
}

// The fixture index, and the read rule that decides it.

// fakePage is one row in the fake index.
//
// The Markdown is the fixture under testdata/, read through md rather than
// hand-written as a Go literal, so the convention is exercised as a convention.
// public and owners are the other two inputs to the read rule, and neither is in
// the file: ownership is a page_owners row and privacy would be an index column,
// so the test states which pages are private rather than inventing a frontmatter
// key nothing else in the app would read.
type fakePage struct {
	ID          int64
	Path        string
	Title       string
	Frontmatter string
	// body is the file's text after the frontmatter. The real row has no column
	// for it, and that is the property under test rather than a simplification:
	// the fake keeps it only so a test can assert it never reaches the plugin.
	body   string
	public bool
	owners []int64
}

// toRow is what the store hands a plugin. There is no body field: store.Page
// carries no page_text, so a plugin given this row has nothing to leak even by
// accident.
func (p fakePage) toRow() store.Page {
	return store.Page{ID: p.ID, Path: p.Path, Title: p.Title, Frontmatter: p.Frontmatter}
}

// privateTo is the fixture's own read rule, as a table rather than as logic, so
// that a page's visibility is a fact the test states and not a consequence.
var privateTo = map[string][]int64{
	"Rules/Fence.md":        {2, 5},
	"Rules/Old Job.md":      {1},
	"Rules/The Betrayal.md": {1},
}

// newFakePages reads the testdata vault into rows.
//
// The reader is deliberately the real one — md.SplitFrontmatter for the fences,
// md.ParseFields for the block, the first H1 for the title — because that is the
// order store's indexer uses, so a fixture the real indexer would not produce
// fails here rather than in a campaign.
func newFakePages(t *testing.T) []fakePage {
	t.Helper()
	var paths []string
	err := filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, err := filepath.Rel("testdata", path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk the fixture vault: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("the fixture vault holds no Markdown, so this test is asserting that an empty index behaves")
	}
	sort.Strings(paths)

	var out []fakePage
	for i, path := range paths {
		raw, err := os.ReadFile(filepath.Join("testdata", path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body, _, fm, _, err := md.SplitFrontmatter(raw)
		if err != nil {
			t.Fatalf("split the frontmatter of %s: %v", path, err)
		}
		title := firstHeading(string(body))
		if title == "" {
			fields, err := md.ParseFields(fm)
			if err != nil {
				t.Fatalf("parse the frontmatter of %s: %v", path, err)
			}
			title = md.FieldString(fields, "title")
		}
		if title == "" {
			title = md.Basename(path)
		}
		owners, private := privateTo[path]
		out = append(out, fakePage{
			ID:          int64(i + 1),
			Path:        path,
			Title:       title,
			Frontmatter: string(fm),
			body:        string(body),
			public:      !private,
			owners:      owners,
		})
	}
	return out
}

// firstHeading is the first level-one ATX heading, which is what store's indexer
// reads a page's title from.
func firstHeading(body string) string {
	for line := range strings.Lines(body) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "# ")
		if ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// storeCall is one recorded call of the page store.
type storeCall struct {
	Method   string
	Who      authz.Principal
	PageType string
}

// fakePageStore is a PageStore over an in-memory index, and it filters.
//
// It filters harder than the real store does, deliberately. store's
// ListPagesByType carries no secret predicate at all — a page is a file, and
// what can be hidden on a page is text inside it, filtered when it is read — so
// a fake that filtered nothing would let every assertion below pass for a
// plugin that ignored authorization entirely. A fake that hides a page from a
// reader who may not open it is the strongest thing this file can hand the
// plugin, and a plugin that renders it correctly renders the real store
// correctly too.
type fakePageStore struct {
	// pages is the index, in the order the store returns it: title order.
	pages []fakePage
	// calls is every method call, with the principal it was made under. The
	// plugin's whole safety argument is one value in this list.
	//
	// It is guarded because the subtests that share a store are parallel — a
	// recording that is not safe to write concurrently turns a test suite into a
	// race report, and a race report is how a real failure gets ignored.
	mu    sync.Mutex
	calls []storeCall
	// failing makes every read fail, for the "the store could not be read" path.
	failing bool
}

// record appends one call under the lock.
func (f *fakePageStore) record(call storeCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// recorded returns a copy of the call log, so that a test can read it while other
// subtests are still writing to it.
func (f *fakePageStore) recorded() []storeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]storeCall(nil), f.calls...)
}

func newFakeStore(t *testing.T) *fakePageStore {
	t.Helper()
	return &fakePageStore{pages: newFakePages(t)}
}

// visible is the one statement both the list and the count are derived from.
//
// That is the shape the real store has — ListPagesByType and CountPagesByType
// read the identical FROM and WHERE out of the same constant — and it is what
// makes "the number and the list cannot disagree" a property of the pair rather
// than a coincidence. A fake that computed them from two different places would
// make the test below pass for a plugin that had done the same.
func (f *fakePageStore) visible(who authz.Principal, pageType string) []store.Page {
	if pageType == "" {
		return nil
	}
	var out []store.Page
	for _, page := range f.pages {
		if pageTypeOf(page.Frontmatter) != pageType {
			continue
		}
		if expectReadable(who, page.public, page.owners) {
			out = append(out, page.toRow())
		}
	}
	return out
}

// pageTypeOf is the page's declared type, read the way the indexer reads it, so
// that "is this a house rule" is a question about the file rather than about a
// substring this file happens to contain.
func pageTypeOf(frontmatter string) string {
	fields, err := md.ParseFields([]byte(frontmatter))
	if err != nil {
		return ""
	}
	return md.FieldString(fields, "type")
}

func (f *fakePageStore) ListPagesByType(ctx context.Context, who authz.Principal, pageType string) ([]store.Page, error) {
	f.record(storeCall{Method: "ListPagesByType", Who: who, PageType: pageType})
	if f.failing {
		return nil, errStoreDown
	}
	return f.visible(who, pageType), nil
}

func (f *fakePageStore) CountPagesByType(ctx context.Context, who authz.Principal, pageType string) (int, error) {
	f.record(storeCall{Method: "CountPagesByType", Who: who, PageType: pageType})
	if f.failing {
		return 0, errStoreDown
	}
	return len(f.visible(who, pageType)), nil
}

func (f *fakePageStore) GetPageSummary(ctx context.Context, who authz.Principal, pageID int64) (store.PageSummary, error) {
	f.record(storeCall{Method: "GetPageSummary", Who: who})
	return store.PageSummary{}, store.ErrNoRows
}

// ListTags answers over the whole vault rather than over the house rules, which
// is what the real one does. It is recorded rather than filtered so that a test
// can assert the plugin never asks: a chip built from this would carry a number
// for a tag the list below never shows.
func (f *fakePageStore) ListTags(ctx context.Context, who authz.Principal) ([]store.TagCount, error) {
	f.record(storeCall{Method: "ListTags", Who: who})
	if f.failing {
		return nil, errStoreDown
	}
	counts := map[string]int{}
	for _, page := range f.pages {
		if !expectReadable(who, page.public, page.owners) {
			continue
		}
		for _, tag := range fakeTags(page.Frontmatter) {
			counts[tag]++
		}
	}
	var out []store.TagCount
	for name, count := range counts {
		out = append(out, store.TagCount{Name: name, PageCount: count})
	}
	return out, nil
}

// errStoreDown is what the fake store fails with, and it carries a path-shaped
// string so that a plugin which put an error into a response body would be caught
// by the tripwire subtest rather than by a reader.
var errStoreDown = errors.New("houserules test: the store is down")

// expectReadable is the page read rule, transcribed.
//
// A page is readable by anybody who may read public content at all, and a page
// that is not public is readable by its owners and by a DM. It is written from
// the rule rather than from authz, so a case where this function and the code
// under test disagree is a finding and not a tautology.
func expectReadable(who authz.Principal, public bool, owners []int64) bool {
	if !who.CanReadPublic() {
		return false
	}
	if public {
		return true
	}
	if !who.Authenticated() {
		return false
	}
	if who.IsDM() {
		return true
	}
	for _, owner := range owners {
		if owner == who.UserID {
			return true
		}
	}
	return false
}

// fakeTags reads the tags out of a fixture's raw frontmatter.
//
// It uses md, the same reader the code under test uses, and that is deliberate:
// the assertion this feeds is about the *count* on a chip, not about how YAML is
// parsed. A hand-rolled tag reader here would let the test's idea of a tag drift
// from the file's, and the test would then be comparing two different things and
// pass. The fixture writes its tags as a block list rather than inline, which is
// what an author actually types and what a substring reader gets wrong.
func fakeTags(frontmatter string) []string {
	fields, err := md.ParseFields([]byte(frontmatter))
	if err != nil {
		return nil
	}
	return md.FieldStrings(fields, "tags")
}

// The authorization matrix, and the expectation table it is checked against.
var (
	principalDM         = authz.ForUser(1, "dm", authz.RoleDM, false)
	principalAdmin      = authz.ForUser(3, "root", authz.RoleAdmin, false)
	principalAuthor     = authz.ForUser(2, "alice", authz.RolePlayer, false)
	principalCoOwner    = authz.ForUser(5, "carol", authz.RolePlayer, false)
	principalOutsider   = authz.ForUser(4, "bob", authz.RolePlayer, false)
	principalAnonymous  = authz.Anonymous(true)
	principalUnauthRead = authz.Anonymous(false)
)

// matrix is every principal the page is evaluated under, with the rules it must
// see. The expectations are written out rather than computed from expectVisible,
// because a computed expectation would agree with the code by construction and
// this file's whole claim is that a disagreement would be visible.
var matrix = []struct {
	name string
	who  authz.Principal
	want []string
}{
	// The ten rules of the fixture, less whatever this principal may not open.
	// privateTo is the fixture's own statement of which are which; these are
	// transcribed from the same table rather than computed from it, so a rule
	// that moved would fail here.
	{name: "a dm", who: principalDM, want: []string{
		"Apollo Diplomacy", "Fair Play", "Fence", "Old Job", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette", hiddenCanary,
	}},
	{name: "an admin", who: principalAdmin, want: []string{
		"Apollo Diplomacy", "Fair Play", "Fence", "Old Job", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette", hiddenCanary,
	}},
	{name: "an author who co-owns a rule", who: principalAuthor, want: []string{
		"Apollo Diplomacy", "Fair Play", "Fence", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette",
	}},
	{name: "a co-owner of a rule", who: principalCoOwner, want: []string{
		"Apollo Diplomacy", "Fair Play", "Fence", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette",
	}},
	{name: "a player who owns nothing", who: principalOutsider, want: []string{
		"Apollo Diplomacy", "Fair Play", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette",
	}},
	{name: "an anonymous reader", who: principalAnonymous, want: []string{
		"Apollo Diplomacy", "Fair Play", "Ritual", "Stakes", "Teeth", "Unfiled", "Zoom Call Etiquette",
	}},
	{name: "a request that may read nothing", who: principalUnauthRead, want: nil},
	{name: "a request that lost its principal", who: authz.Principal{}, want: nil},
}

// TestTheDescriptorIsWellFormed checks the declaration, and ParseCapabilities
// checks it for real.
//
// ParseCapabilities is the assertion that matters here. A capability name the
// host does not recognise is not an error anywhere else in the system: the
// plugin believes it holds the capability, nothing does, and the consequence is
// a sidebar group that silently does not appear.
func TestTheDescriptorIsWellFormed(t *testing.T) {
	t.Parallel()
	d := New().Descriptor()

	if err := d.ValidateID(); err != nil {
		t.Errorf("ValidateID: %v", err)
	}
	if !d.Kind.Valid() {
		t.Errorf("Kind %q is not valid", d.Kind)
	}
	if d.Kind != plugin.KindFeature {
		t.Errorf("Kind = %q, want %q: this package's content model is a frontmatter convention, which only a feature may use", d.Kind, plugin.KindFeature)
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
	everything, err := plugin.ParseCapabilities(plugin.AllCapabilities)
	if err != nil {
		t.Fatalf("ParseCapabilities(AllCapabilities): %v", err)
	}
	if extra := granted & ^everything; extra != 0 {
		t.Errorf("granted = %08b, which includes bits the host does not define", granted)
	}
	// The two the descriptor is required to claim, each named. A subset check
	// alone would pass for a plugin that quietly dropped CapSearchResolvers and
	// stopped contributing rows without anybody noticing.
	for _, want := range []plugin.Capability{plugin.CapSidebarNav, plugin.CapSearchResolvers} {
		if !granted.Has(want) {
			t.Errorf("the descriptor does not claim %q, so the contribution behind it is discarded", want)
		}
	}
	// Two, named above, and no more. A third would be a capability this plugin
	// has no contribution for, which §7 of the working agreement calls a control
	// with nothing behind it.
	if len(d.Capabilities) != 2 {
		t.Errorf("the descriptor claims %d capabilities, want 2: %v", len(d.Capabilities), d.Capabilities)
	}

	if len(d.SearchResolvers) != 1 {
		t.Errorf("SearchResolvers has %d entries, want 1", len(d.SearchResolvers))
	}
	if len(d.NavItems) != 1 {
		t.Fatalf("NavItems has %d entries, want 1", len(d.NavItems))
	}
	nav := d.NavItems[0]
	if nav.ID != NavID {
		t.Errorf("nav id = %q, want %q: nav ids are unique across the whole registry, so it is namespaced", nav.ID, NavID)
	}
	if nav.Label != "House Rules" {
		t.Errorf("nav label = %q, want %q", nav.Label, "House Rules")
	}
	if nav.Order != 40 {
		t.Errorf("nav order = %d, want 40", nav.Order)
	}
	if got := nav.Href; got != IndexHref {
		t.Errorf("nav href = %q, want the plugin's own prefix %q", got, IndexHref)
	}
	if got := nav.Href; !strings.HasPrefix(got, "/plugin/"+ID) {
		t.Errorf("nav href %q is outside the plugin's own prefix; that is a registration error, not a link", got)
	}
	if nav.Badge != nil {
		t.Error("the nav item carries a badge: the count is on the index page beside the list it counts, which is where a reader can check it")
	}
	if nav.MinimumRole != "" {
		t.Errorf("nav MinimumRole = %q, want empty: a role here hides the link and gates nothing", nav.MinimumRole)
	}

	if len(d.Migrations) != 0 {
		t.Errorf("Migrations has %d entries, want 0: the Markdown file is canonical and a table of derived rules would be a second source of truth", len(d.Migrations))
	}
	if len(d.ConfigSchema) != 0 {
		t.Errorf("ConfigSchema has %d entries, want 0", len(d.ConfigSchema))
	}
	// Icons are sprite tokens, and a token the sprite does not have is a silently
	// empty <use>: the affordance looks broken rather than absent.
	sprite := spriteSymbols(t)
	if !sprite[nav.Icon] {
		t.Errorf("nav item %q references icon %q, which web/static/icons.svg does not define", nav.ID, nav.Icon)
	}
}

// semverRe is a three-number version, which is the whole of what this package
// claims to ship. It is deliberately not the full semver grammar: a pre-release
// suffix is a thing a release process adds, and a test that accepted it would not
// notice a version that had quietly become something else.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// TestAFeaturePluginDeclaresNoPageTypes is the feature half of the plugin
// architecture, in the two directions it can fail.
//
// The first is this package's own: the descriptor and CoreTypes are both empty,
// and Register refuses a descriptor that grew a page type — so a future edit that
// adds one fails at a line of code rather than as a boot report entry.
//
// The second is the host's: a feature that declares a page type, and a feature
// that builds one at register time, are both refused by the real host, and the
// registry holds neither. Asserting only the first would pass for a host that
// let a feature plugin define what a character sheet is.
func TestAFeaturePluginDeclaresNoPageTypes(t *testing.T) {
	t.Parallel()

	d := New().Descriptor()
	if len(d.PageTypes) != 0 {
		t.Errorf("the descriptor declares %d page types; a feature plugin may not declare any", len(d.PageTypes))
	}
	if got := New().CoreTypes(); len(got) != 0 {
		t.Errorf("CoreTypes returned %d page types, want none: the convention needs no registration", len(got))
	}

	tests := []struct {
		name string
		load func(ctx context.Context, deps plugin.PluginDeps) (plugin.Registry, plugin.Report)
	}{
		{
			// The road the descriptor takes.
			name: "a feature that declares a page type",
			load: func(ctx context.Context, deps plugin.PluginDeps) (plugin.Registry, plugin.Report) {
				return plugin.Load(ctx, deps, declaresPageType{New()})
			},
		},
		{
			// The road that reaches the same rule without a declaration: the host
			// asks CoreTypes, so a feature that grows one there is refused as well.
			name: "a feature that builds a page type at register time",
			load: func(ctx context.Context, deps plugin.PluginDeps) (plugin.Registry, plugin.Report) {
				return plugin.Load(ctx, deps, buildsPageType{New()})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg, report := tc.load(t.Context(), bootDeps(nil))
			entry := requireEntry(t, report, ID)
			if entry.Status == plugin.StatusOK {
				t.Fatalf("the host admitted a feature plugin that registered a page type")
			}
			if entry.Reason == "" {
				t.Error("the refusal carries no reason, and a boot report line with an empty reason is a bug in the host")
			}
			if _, ok := reg.PageType(PageTypeHouseRule); ok {
				t.Errorf("the registry kept the %q page type a feature plugin registered", PageTypeHouseRule)
			}
		})
	}
}

// declaresPageType is this plugin with one page type added to its declaration.
type declaresPageType struct{ *Plugin }

func (f declaresPageType) Descriptor() plugin.Descriptor {
	d := f.Plugin.Descriptor()
	d.PageTypes = []plugin.PageType{{ID: PageTypeHouseRule, Name: "House rule", Icon: NavIcon}}
	return d
}

// buildsPageType is this plugin answering CoreTypes with a page type, which is
// the same violation reached without a declaration.
type buildsPageType struct{ *Plugin }

func (b buildsPageType) CoreTypes() []plugin.PageType {
	return []plugin.PageType{{ID: PageTypeHouseRule, Name: "House rule", Icon: NavIcon}}
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
	// plugin writes nothing: the Markdown file stays canonical.
	for _, route := range h.routes {
		for method := range route.Handlers {
			if method != http.MethodGet {
				t.Errorf("pattern %q is mounted for %s; this plugin mounts read routes only", route.Pattern, method)
			}
		}
	}

	// It asked for the page store. A plugin that rendered from the filesystem
	// instead would be a second path to vault bytes that no read rule ever saw.
	if seen["Pages"] != 1 {
		t.Errorf("Register called Host.Pages %d times, want 1: the index reads the store and nothing else", seen["Pages"])
	}

	nav := p.NavItems()
	if len(nav) != len(d.NavItems) {
		t.Errorf("NavItems has %d entries, the descriptor declares %d", len(nav), len(d.NavItems))
	}
	if len(p.Panels()) != 0 {
		t.Error("Panels returned entries: a panel renders on every page in the vault, and this plugin's only surface is its own page")
	}
	if len(p.Summaries()) != 0 {
		t.Error("Summaries returned entries: the link-preview card is core's route over the same public excerpt")
	}
	if len(p.CoreTypes()) != 0 {
		t.Error("CoreTypes returned entries: a feature plugin may not register page types")
	}
	if got := p.MarkdownExtenders(); got != nil {
		t.Errorf("MarkdownExtenders returned %d extenders; this plugin contributes none and nil is how it says so", len(got))
	}
	if got := p.ConfigSchema(); got != nil {
		t.Errorf("ConfigSchema returned %v; this plugin declares no settings", got)
	}

	// The plugin mounted on the host's sub-router and nowhere else. A router of
	// its own would be mounted outside the prefix and outside the session
	// wrapper, and the host refuses it.
	if p.routes != h.mux {
		t.Error("the plugin mounted on a router other than the one the host handed it")
	}
	// The clock is the host's. It is a method value rather than a value, so
	// asking for the clock now and again must still be the host's reading —
	// which is the property a plugin calling time.Now would lose.
	if got := p.Now(); !got.Equal(h.now) {
		t.Errorf("Now() = %v, want the host's %v", got, h.now)
	}
	if len(h.logs) == 0 {
		t.Error("Register logged nothing, so a boot report would show the plugin appearing without a line")
	}
	// Every line the plugin logged names the plugin and carries no content.
	for _, line := range h.logs {
		if strings.Contains(line, bodyCanary) || strings.Contains(line, hiddenCanary) {
			t.Errorf("a log line carries page content: %q", line)
		}
	}
}

// TestThePrincipalHandedToThePageStoreIsTheOnesTheHostResolved is this package's
// whole authorization claim, observed at the call site.
//
// Every recorded store call is compared byte for byte against the principal the
// request context carried. Three ways this could be wrong and one of them is
// invisible to every other test in the file: a constant anonymous reader would
// make the index under-report a DM while every "the page contains no canary"
// assertion still passed; a forged DM would over-report a player; and a principal
// rebuilt field by field would differ in the session id or the authz generation
// while looking identical in a hand-written comparison. Comparing the whole
// struct is what rules the third out.
func TestThePrincipalHandedToThePageStoreIsTheOnesTheHostResolved(t *testing.T) {
	t.Parallel()
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Its own store per subtest, not a shared one: the call log is a
			// shared slice, and a window into it taken by a parallel subtest
			// would contain its neighbours' calls as well as its own.
			store := newFakeStore(t)
			h := newFakeHost(t)
			h.pages = store
			registerWith(t, h)
			root := rootFor(t, h)
			if _, status := serveAs(t, root, "/plugin/"+ID+"/", tc.who); status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if _, status := serveAs(t, root, "/plugin/"+ID+rulesRoute+"?q=fair", tc.who); status != http.StatusOK {
				t.Fatalf("the fragment answered %d", status)
			}
			calls := store.recorded()
			if len(calls) == 0 {
				t.Fatal("the page made no store call, so this test is not looking at one")
			}
			for _, call := range calls {
				if call.Who != tc.who {
					t.Errorf("%s was called as %+v, want the request's own principal %+v", call.Method, call.Who, tc.who)
				}
			}
		})
	}
}

// TestTheResolverIsAskedForTheCallersOwnPrincipalToo checks the same property on
// the other surface, because the resolver is called by core's /search rather than
// by a route this plugin mounted — and a resolver that quietly used a constant
// would hand every searcher the same rows.
func TestTheResolverIsAskedForTheCallersOwnPrincipalToo(t *testing.T) {
	t.Parallel()
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Its own store, for the reason the other test has: a shared call log
			// and a parallel subtest make a window into it meaningless.
			store := newFakeStore(t)
			h := newFakeHost(t)
			h.pages = store
			p, _ := registerWith(t, h)
			resolver := p.Descriptor().SearchResolvers[0]

			if _, err := resolver.Query(authz.WithPrincipal(t.Context(), tc.who), "fair"); err != nil {
				t.Fatalf("Query: %v", err)
			}
			calls := store.recorded()
			if len(calls) == 0 {
				t.Fatal("the resolver made no store call")
			}
			for _, call := range calls {
				if call.Who != tc.who {
					t.Errorf("%s was called as %+v, want the caller's own principal", call.Method, call.Who)
				}
			}
		})
	}
}

// TestThePluginNeverAsksTheStoreForMoreThanItNeeds is the shape of the calls.
//
// A resolver that walked the vault rather than its own type would return rows
// for pages it does not claim, and ListTags would give it counts over every page
// in the campaign rather than over the rules on the page — a number for a tag the
// list below never shows. Both are refusals of a *specific* method rather than of
// the page, so a page that leaked nothing would still be wrong.
func TestThePluginNeverAsksTheStoreForMoreThanItNeeds(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	root := rootFor(t, h)

	if _, status := serve(t, root, "/plugin/"+ID+"/"); status != http.StatusOK {
		t.Fatalf("the index answered %d", status)
	}
	if _, status := serve(t, root, "/plugin/"+ID+rulesRoute+"?q=fair"); status != http.StatusOK {
		t.Fatalf("the fragment answered %d", status)
	}

	var listed, counted int
	for _, call := range store.recorded() {
		switch call.Method {
		case "ListPagesByType":
			listed++
			if call.PageType != PageTypeHouseRule {
				t.Errorf("ListPagesByType asked for %q, want %q", call.PageType, PageTypeHouseRule)
			}
		case "CountPagesByType":
			counted++
		case "ListTags":
			t.Error("ListTags was called: it counts every page in the vault, so a chip built from it would carry a number the list below never shows")
		case "GetPageSummary":
			t.Error("GetPageSummary was called: this plugin contributes no link-preview card, so it has no business asking")
		}
	}
	if listed == 0 || counted == 0 {
		t.Errorf("the plugin made %d list calls and %d count calls; both halves of the pair are what keep the number and the list from disagreeing", listed, counted)
	}
}

// TestThePageShowsTheStoreAnswerAndNothingElse is the matrix, rendered.
//
// For every principal in the matrix the page is served as that principal and the
// markup is checked three ways at once: every rule the store returned is present,
// no rule it withheld is present by title or by path, and no canary is anywhere
// unless this principal may open the page carrying it.
//
// The canary check is two-polarity on purpose. A canary that is simply absent
// proves nothing if the render was empty, so the private fixture is asserted to
// be *present* for the principals that may open it, which is what makes its
// absence for the rest an assertion rather than an artifact.
func TestThePageShowsTheStoreAnswerAndNothingElse(t *testing.T) {
	t.Parallel()
	fixture := newFakePages(t)

	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore(t)
			h := newFakeHost(t)
			h.pages = store
			registerWith(t, h)
			body, status := serveAs(t, rootFor(t, h), "/plugin/"+ID+"/", tc.who)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}

			answer := store.visible(tc.who, PageTypeHouseRule)
			if !sameTitles(answer, tc.want) {
				t.Fatalf("the store answers %v for this principal, the table expects %v", titles(answer), tc.want)
			}
			returned := map[string]bool{}
			for _, row := range answer {
				returned[row.Path] = true
				if !strings.Contains(body, row.Title) {
					t.Errorf("the index does not show %q, which the store returned", row.Title)
				}
				if !strings.Contains(body, row.Path) {
					t.Errorf("the index does not name %q, which the store returned", row.Path)
				}
			}
			for _, page := range fixture {
				if returned[page.Path] {
					continue
				}
				if strings.Contains(body, page.Title) {
					t.Errorf("the index shows %q, which the store did not return to this principal", page.Title)
				}
				if strings.Contains(body, page.Path) {
					t.Errorf("the index names %q, which the store did not return to this principal", page.Path)
				}
			}

			// A body canary is never rendered for anybody: the row has no column
			// for it.
			if strings.Contains(body, bodyCanary) {
				t.Errorf("the index carries the body canary %q", bodyCanary)
			}
			// And the title canary, which is a page the matrix gives to a DM
			// alone, is two-polarity.
			mayOpen := false
			for _, page := range fixture {
				if page.Title == hiddenCanary {
					mayOpen = expectReadable(tc.who, page.public, page.owners)
				}
			}
			switch {
			case mayOpen && !strings.Contains(body, hiddenCanary):
				t.Errorf("the index does not render %q, which this principal may open: an absent canary is not evidence of a redaction", hiddenCanary)
			case !mayOpen && strings.Contains(body, hiddenCanary):
				t.Errorf("the index carries the canary %q, which this principal may not open", hiddenCanary)
			}

			// The number on the page is the store's count, so it is printed beside
			// the list and not derived from it.
			if want := countLabel(len(answer), "house rule"); !strings.Contains(body, want) {
				t.Errorf("the index does not print %q, so its count and its list are two independent claims", want)
			}
		})
	}
}

// TestTheListAndItsCountAgreeOverTheWholeMatrix is the §2.4 property, checked
// for every principal rather than for the one the plugin happens to use.
//
// A list whose badge counts three while it shows one is an existence leak, and
// the way to be sure there is not one is to ask both halves of the pair the same
// question and compare. The plugin's contribution to that is to use both.
func TestTheListAndItsCountAgreeOverTheWholeMatrix(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)

	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			list, err := store.ListPagesByType(t.Context(), tc.who, PageTypeHouseRule)
			if err != nil {
				t.Fatalf("ListPagesByType: %v", err)
			}
			count, err := store.CountPagesByType(t.Context(), tc.who, PageTypeHouseRule)
			if err != nil {
				t.Fatalf("CountPagesByType: %v", err)
			}
			if count != len(list) {
				t.Errorf("the list holds %d rows and the count says %d", len(list), count)
			}
			if !sameTitles(list, tc.want) {
				t.Errorf("the list is %v, the table expects %v", titles(list), tc.want)
			}

			// Every chip's count is a count of *this* principal's listed rows, so a
			// chip can never advertise a rule the list does not hold.
			listed := map[string]int{}
			for _, row := range list {
				for _, tag := range fakeTags(row.Frontmatter) {
					listed[tag]++
				}
			}
			for tag, want := range listed {
				if got := chipCount(list, tag); got != want {
					t.Errorf("chip %q counts %d, and %d listed rules carry it", tag, got, want)
				}
			}
			if len(listed) == 0 && count != 0 {
				t.Errorf("no rule carries a tag, yet the count is %d", count)
			}
		})
	}
}

// chipCount is what a chip for tag would say, computed from the same rows the
// page renders.
func chipCount(rows []store.Page, tag string) int {
	var out int
	for _, row := range rows {
		for _, have := range fakeTags(row.Frontmatter) {
			if have == tag {
				out++
			}
		}
	}
	return out
}

// TestNoChipCountsARuleTheReaderMayNotOpen is the chip's half of the matrix,
// checked on the rendered page.
//
// A chip is a number, and a number is a disclosure: a chip that says 2 beside a
// list of one says the second rule exists. So for every principal the chips on
// the page are compared against the rules that principal's answer holds.
func TestNoChipCountsARuleTheReaderMayNotOpen(t *testing.T) {
	t.Parallel()

	for _, tc := range matrix {
		if len(tc.want) == 0 {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore(t)
			h := newFakeHost(t)
			h.pages = store
			registerWith(t, h)
			body, status := serveAs(t, rootFor(t, h), "/plugin/"+ID+"/", tc.who)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}

			carried := map[string]int{}
			for _, row := range store.visible(tc.who, PageTypeHouseRule) {
				for _, tag := range fakeTags(row.Frontmatter) {
					carried[tag]++
				}
			}
			// for tag := range carried, not `for _, tag := range carried`: a range
			// clause whose first variable is blank assigns the map's value to the
			// second one, and this loop wants the tag itself.
			for tag := range carried {
				at := chipAnchor(tag).FindStringIndex(body)
				if at == nil {
					t.Errorf("the index renders no chip for the tag %q that %d of this principal's rules carry", tag, carried[tag])
					continue
				}
				// The count is the chip's own number, rendered in the span beside
				// the name. Reading it back out of the markup rather than from a
				// helper is the point: a chip is what the reader counts.
				rest := body[at[1]:]
				end := strings.Index(rest, "</span>")
				if end < 0 {
					t.Errorf("the chip for %q renders no count", tag)
					continue
				}
				if text := stripTags(rest[:end]); text != itoa(carried[tag]) {
					t.Errorf("the chip for %q reads %q, and %d of this principal's rules carry it", tag, text, carried[tag])
				}
			}
			// A tag only a rule this principal may not open carries must not
			// appear at all, or the number beside it would be counting something
			// the list never shows.
			for tag := range carried {
				if chipAnchor(tag).MatchString(body) {
					continue
				}
				t.Errorf("the index renders no chip for %q even though %d rules carry it", tag, carried[tag])
			}
			for _, tag := range []string{"planning", "timing"} {
				// Both tags live only on rules the fixture gives to a DM or to two
				// players, so a principal outside that set must see no chip at all.
				if expectVisibleTag(newFakePages(t), tc.who, tag) {
					continue
				}
				if strings.Contains(body, ">"+tag+" <span") {
					t.Errorf("the index renders a chip for %q, which only rules this principal may not open carry", tag)
				}
			}
		})
	}
}

// expectVisibleTag reports whether any rule this principal may open carries tag.
func expectVisibleTag(fixture []fakePage, who authz.Principal, tag string) bool {
	for _, page := range fixture {
		if !expectReadable(who, page.public, page.owners) {
			continue
		}
		for _, have := range fakeTags(page.Frontmatter) {
			if have == tag {
				return true
			}
		}
	}
	return false
}

// chipAnchor matches a chip's own markup: the tag as the link's text, followed by
// the count in the span beside it. Matching the whole pair is what makes the
// number below the one the reader reads, rather than a number that happens to
// appear somewhere else in the document.
func chipAnchor(tag string) *regexp.Regexp {
	return regexp.MustCompile(`>` + regexp.QuoteMeta(tag) + ` <span[^>]*>`)
}

// TestTheFilterCanOnlyNarrow is the other direction of the same argument: a
// reader-chosen filter is applied after the store's answer, never before it, so
// no combination of query parameters can widen the list or move a count.
func TestTheFilterCanOnlyNarrow(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	root := rootFor(t, h)

	all := store.visible(principalOutsider, PageTypeHouseRule)
	base, status := serve(t, root, "/plugin/"+ID+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{name: "no filter", query: "", want: len(all)},
		{name: "a tag that exists", query: "?tag=table", want: chipCount(all, "table")},
		{name: "a tag in a different case", query: "?tag=TABLE", want: chipCount(all, "table")},
		{name: "a tag nobody carries", query: "?tag=nonsense", want: len(all)},
		{name: "a term matching a title", query: "?q=fair", want: 1},
		{name: "a term matching a tag on two rules", query: "?q=combat", want: chipCount(all, "combat")},
		{name: "a term matching nothing", query: "?q=zzzznotarule", want: 0},
		{name: "a term and a tag together", query: "?tag=table&q=fair", want: 1},
		{name: "a term and a tag that disagree", query: "?tag=combat&q=fair", want: 0},
		{name: "grouping changes nothing", query: "?group=system", want: len(all)},
		{name: "an unknown grouping value", query: "?group=author", want: len(all)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, status := serve(t, root, "/plugin/"+ID+"/"+tc.query)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			listed := listedTitles(body)
			if got := len(listed); got != tc.want {
				t.Errorf("the filtered index lists %d rules (%v), want %d", got, listed, tc.want)
			}
			// Every row shown is a row the unfiltered index showed. A filter that
			// added a rule would be a filter the store's count never saw.
			for _, path := range listed {
				if !strings.Contains(base, path) {
					t.Errorf("the filtered index shows %q, which the unfiltered index did not", path)
				}
			}
			// The count is the whole set's, whatever the filter did, and the page
			// says how many of them survived.
			if want := countLabel(len(all), "house rule"); !strings.Contains(body, want) {
				t.Errorf("the filtered index does not print the unfiltered count %q", want)
			}
		})
	}
}

// TestGroupingRendersOneHeadingPerSystem checks the toggle's other state, which
// is a different template branch and therefore a different way to be wrong.
func TestGroupingRendersOneHeadingPerSystem(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	root := rootFor(t, h)

	body, status := serve(t, root, "/plugin/"+ID+"/?group=system")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// apollo, dnd5e, then unassigned. Alphabetical order would be apollo, dnd5e,
	// unassigned, zend — so with no zend in the fixture the two rules look the
	// same, which is why the fixture carries a system called apollo: it is the
	// only name in the table that sorts *before* UnassignedSystem, and without it
	// "unassigned last" is indistinguishable from "sorted".
	wantOrder := []string{"apollo", "dnd5e", UnassignedSystem}
	at := -1
	for _, name := range wantOrder {
		found := strings.Index(body, ">"+name+" <span")
		if found < 0 {
			t.Fatalf("the grouped index has no group for %q", name)
		}
		if found < at {
			t.Errorf("group %q is rendered before the group above it; unassigned is meant to be last", name)
		}
		at = found
	}
	// Each group is a labelled section, so the heading and the region it names
	// are the same id rather than two strings that can drift.
	for i := range wantOrder {
		id := groupID(i)
		if !strings.Contains(body, `id="`+id+`"`) {
			t.Errorf("the grouped index has no heading with id %q", id)
		}
		if !strings.Contains(body, `aria-labelledby="`+id+`"`) {
			t.Errorf("no section is labelled by %q", id)
		}
	}
	// And every rule is still on the page exactly once.
	if got, want := len(listedTitles(body)), len(store.visible(principalOutsider, PageTypeHouseRule)); got != want {
		t.Errorf("the grouped index lists %d rules, want %d", got, want)
	}
}

// TestTheIndexShipsOneSectionAndSaysWhy is the negative test, and it is the most
// important one in this file.
//
// A house-rule index with a "rules for the table" section and a "rules only the
// DM sees" section is the obvious design, and the gate for the second one is now
// available: this plugin knows the reader's own principal, so it could branch on
// IsDM(). It does not, and the reason is the content model rather than the
// capability. A page is a file and a file has no visibility; what can be hidden
// is text inside a page, in a secret fence. So there is no such thing as a
// DM-only house-rule *page* to hold back, and a second section would have to
// filter on a frontmatter key nothing else in the app enforces — naming rules
// that a player can still open at /p/{path}, which is advertising rather than
// protecting.
//
// So the test asserts three things: one section heading, the reason the second
// one is absent stated on the page, and `visibility` not being one of the four
// frontmatter keys this package reads.
func TestTheIndexShipsOneSectionAndSaysWhy(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	body, status := serve(t, rootFor(t, h), "/plugin/"+ID+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if got := strings.Count(body, "<h3"); got != 1 {
		t.Errorf("the index renders %d section headings, want exactly 1: a second one would list pages it does not protect", got)
	}
	if !strings.Contains(body, "Shared with the table") {
		t.Error("the index does not carry the one section heading it is able to gate")
	}
	if strings.Contains(strings.ToLower(body), "dm only") {
		t.Error("the index renders a DM-only section; a page has no visibility, so there is nothing such a section could hold back")
	}
	// The absence is stated, so that a DM reading the page learns the limitation
	// instead of concluding the campaign has no private rules.
	if !strings.Contains(body, "A list kept for the DM alone is not attempted") {
		t.Error("the index does not say why there is no DM-only section, so its absence reads as an oversight rather than a decision")
	}
	// And the mechanism an author should use instead is named, because "here is
	// why not" without "here is what instead" is an unhelpful answer.
	if !strings.Contains(body, "secret fence") {
		t.Error("the index does not point at the mechanism that does hide a rule from a reader")
	}
	// Neither can be built by filtering on a frontmatter key: the convention is a
	// closed list of four keys and `visibility` is not one of them, so a rule that
	// declares one is listed like any other.
	for _, key := range conventionFields {
		if key == "visibility" {
			t.Error("conventionFields reads a visibility key, and a key nothing in the app enforces is a plugin deciding authorization on its own")
		}
	}
}

// TestTheSearchResolverReturnsNoHiddenContent is the resolver's real contract.
//
// The rows a resolver returns are rendered into a search result for whoever
// asked, so a resolver that could reach a page body would be a way to search for
// hidden text. The assertion is therefore negative, and it is checked against
// canaries in the two places a resolver could plausibly leak from: the body of a
// rule, and the title of a rule its caller may not open.
func TestTheSearchResolverReturnsNoHiddenContent(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	p, _ := registerWith(t, h)
	resolver := p.Descriptor().SearchResolvers[0]
	// The resolver is called by core's /search with the searcher's own context, so
	// every subtest carries one. A bare context is a case of its own, below.
	caller := func(who authz.Principal) context.Context {
		return authz.WithPrincipal(t.Context(), who)
	}

	t.Run("a title match returns a row built from the row's own fields", func(t *testing.T) {
		t.Parallel()
		rows, err := resolver.Query(caller(principalOutsider), "fair")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("Query returned %d rows, want 1: %+v", len(rows), rows)
		}
		row := rows[0]
		if row.Kind != ResultKind {
			t.Errorf("Kind = %q, want %q", row.Kind, ResultKind)
		}
		if row.Title != "Fair Play" {
			t.Errorf("Title = %q, want the page's own title", row.Title)
		}
		if row.Href != pluginPageHref+"Rules/Fair Play.md" {
			t.Errorf("Href = %q, want the core page route for the vault path", row.Href)
		}
		if row.Ref != "Rules/Fair Play.md" {
			t.Errorf("Ref = %q, want the vault path", row.Ref)
		}
		if row.Score != 1 {
			t.Errorf("Score = %v, want 1 for a title match", row.Score)
		}
		for _, want := range []string{ResultKind, "dnd5e", "safety", "table"} {
			if !strings.Contains(row.Summary, want) {
				t.Errorf("Summary %q does not mention %q", row.Summary, want)
			}
		}
	})

	t.Run("no row carries anything outside the four convention keys", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{"fair", "teeth", "unfiled", "combat", "timing", "safety", "dnd5e", "heist", "Rules"} {
			rows, err := resolver.Query(caller(principalOutsider), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			for _, row := range rows {
				blob := row.Kind + "\x00" + row.Title + "\x00" + row.Href + "\x00" + row.Summary + "\x00" + row.Ref
				for _, canary := range []string{bodyCanary, hiddenCanary} {
					if strings.Contains(blob, canary) {
						t.Errorf("Query(%q) returned a row carrying %q: %+v", term, canary, row)
					}
				}
			}
		}
	})

	t.Run("a term that only exists in an unread key matches nothing", func(t *testing.T) {
		t.Parallel()
		// The sharpest form of the assertion. The canary is in the prose of a rule
		// the index does list, and the store row that reaches the plugin has no
		// column for prose — so a resolver that tried to search the rule's own
		// text would find nothing to search. This one must not match.
		rows, err := resolver.Query(caller(principalOutsider), bodyCanary)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("Query(%q) returned %d rows; that term is in a rule's prose, which no store row carries", bodyCanary, len(rows))
		}
	})

	t.Run("a page the caller may not open matches nothing", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{hiddenCanary, "betrayal"} {
			rows, err := resolver.Query(caller(principalOutsider), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			if len(rows) != 0 {
				t.Errorf("Query(%q) returned %d rows for a page this caller may not open: %+v", term, len(rows), rows)
			}
		}
	})

	t.Run("the same page does match for a caller who may open it", func(t *testing.T) {
		t.Parallel()
		// The other half, and the reason the one above means anything. Without it
		// "returned no rows" could be a resolver that never returns any.
		rows, err := resolver.Query(caller(principalDM), hiddenCanary)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 1 || !strings.Contains(rows[0].Title, hiddenCanary) {
			t.Errorf("Query for a DM = %+v, want the one row the store returns for a principal who may open the page", rows)
		}
	})

	t.Run("a context with no principal returns nothing", func(t *testing.T) {
		t.Parallel()
		// authz.PrincipalFrom yields the zero Principal for a context that never
		// went through WithPrincipal, and the zero Principal cannot read public
		// content, so the store answers nothing. Losing a request's identity
		// fails closed, and this is the test that says so.
		for _, ctx := range []context.Context{t.Context(), context.Background()} {
			rows, err := resolver.Query(ctx, "fair")
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(rows) != 0 {
				t.Errorf("Query on a context with no principal returned %+v; a caller with no identity must read nothing", rows)
			}
		}
	})

	t.Run("a page of another type is not a house rule", func(t *testing.T) {
		t.Parallel()
		// "Ordinary" is type: note and shares a tag with a real rule, so a
		// resolver that walked the vault rather than the type would return it.
		rows, err := resolver.Query(caller(principalOutsider), "Session Three")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("Query returned %+v, which is a page this plugin does not claim", rows)
		}
	})

	t.Run("a title match outranks a tag match", func(t *testing.T) {
		t.Parallel()
		rows, err := resolver.Query(caller(principalOutsider), "table")
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(rows) < 2 {
			t.Fatalf("Query returned %d rows, want the readable rules carrying the tag: %+v", len(rows), rows)
		}
		if rows[0].Score != 0.5 {
			t.Errorf("the first row scored %v, want 0.5: no readable rule's title contains the tag", rows[0].Score)
		}
		for _, row := range rows {
			if row.Score > 0.5 {
				t.Errorf("a field match scored %v, which outranks a title match", row.Score)
			}
		}
	})

	t.Run("an empty term asks for nothing", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{"", "   "} {
			rows, err := resolver.Query(caller(principalOutsider), term)
			if err != nil {
				t.Fatalf("Query(%q): %v", term, err)
			}
			if len(rows) != 0 {
				t.Errorf("Query(%q) returned %d rows; an empty term is not a search", term, len(rows))
			}
		}
	})

	t.Run("a store that cannot be read reports the error rather than an empty list", func(t *testing.T) {
		t.Parallel()
		// An empty list and a failed read are the same shape to a reader, and the
		// difference is the whole claim this resolver makes.
		broken := newFakeStore(t)
		broken.failing = true
		failing := New()
		if err := failing.Register(t.Context(), &recordingHost{
			caps:   grantedFor(t),
			kind:   plugin.KindFeature,
			config: plugin.Config{Values: map[string]any{}},
			pages:  broken,
			mux:    chi.NewRouter(),
			now:    time.Time{},
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, err := failing.Descriptor().SearchResolvers[0].Query(authz.WithPrincipal(t.Context(), principalOutsider), "fair"); err == nil {
			t.Error("a failed read answered nil, so an outage and a campaign with no rules look the same")
		}
	})
}

// TestTheRoutesAnswer renders both mounted routes, because a route that compiles
// and a route that answers are different claims.
//
// The router is mounted the way the host mounts it — under the plugin prefix —
// so the assertions cover the prefix as well as the handlers.
func TestTheRoutesAnswer(t *testing.T) {
	t.Parallel()
	_, h := register(t)
	root := rootFor(t, h)

	t.Run("the index renders the document, the rules and the filter", func(t *testing.T) {
		t.Parallel()
		body, status := serve(t, root, "/plugin/"+ID+"/")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		for _, want := range []string{
			"<!doctype html>", `<html lang="en"`, `<link rel="stylesheet"`,
			`name="q"`, `id="houserules-q"`, `action="` + IndexHref + `"`,
			"Fair Play", "Teeth", "Unfiled", "Shared with the table",
			"Group by system", "Filter rules",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("the index does not contain %q", want)
			}
		}
		// The filter is a GET form with a real destination and a real control,
		// because a form whose button posts nowhere is a control with nothing
		// behind it.
		if !strings.Contains(body, `<button type="submit"`) {
			t.Error("the filter form renders no submit control")
		}
		if !strings.Contains(body, `for="houserules-q"`) {
			t.Error("the filter input has no label bound to it")
		}
	})

	t.Run("the fragment is the list and nothing else", func(t *testing.T) {
		t.Parallel()
		body, status := serve(t, root, "/plugin/"+ID+rulesRoute)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if !strings.Contains(body, "Fair Play") {
			t.Error("the fragment does not carry the list")
		}
		// A fragment that is a document would replace a reader's page with one
		// when a region swap took it, and would nest an <html> inside a body.
		for _, unwanted := range []string{"<!DOCTYPE", "<html", "<head", "<body"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("the fragment contains %q, so it is a document rather than a fragment", unwanted)
			}
		}
		// And it owns none of the shell's ids, because it is the half that could
		// be swapped into somebody else's page.
		for _, id := range coreShellIDs {
			if strings.Contains(body, `id="`+id+`"`) {
				t.Errorf("the fragment renders id=%q, which the shell owns", id)
			}
		}
	})

	t.Run("the fragment answers the same query as the index", func(t *testing.T) {
		t.Parallel()
		index, _ := serve(t, root, "/plugin/"+ID+"/?tag=combat")
		fragment, status := serve(t, root, "/plugin/"+ID+rulesRoute+"?tag=combat")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		for _, want := range listedTitles(index) {
			if !strings.Contains(fragment, want) {
				t.Errorf("the fragment does not list %q, which the index lists for the same query", want)
			}
		}
	})

	t.Run("a filter that matches nothing says so rather than rendering nothing", func(t *testing.T) {
		t.Parallel()
		body, status := serve(t, root, "/plugin/"+ID+"/?q=zzzznotarule")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if !strings.Contains(body, "No rule matches this filter") {
			t.Error("a filter matching nothing does not say so: an empty list and a campaign with no rules look the same")
		}
		if !strings.Contains(body, "clear the filter") {
			t.Error("a filter matching nothing offers no way to remove it")
		}
	})

	t.Run("a campaign with no rules says which emptiness it is", func(t *testing.T) {
		t.Parallel()
		empty := New()
		host := newFakeHost(t)
		host.pages = emptyStore{}
		if err := empty.Register(t.Context(), host); err != nil {
			t.Fatalf("Register: %v", err)
		}
		host.gather(empty)
		body, status := serve(t, rootFor(t, host), "/plugin/"+ID+"/")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if !strings.Contains(body, "No house rules yet") {
			t.Error("an index with no rules does not name the absence")
		}
		if !strings.Contains(body, "0 house rules") {
			t.Error("an index with no rules prints no count")
		}
	})

	t.Run("the nav destination is the route the plugin mounted", func(t *testing.T) {
		t.Parallel()
		// A nav item whose href answers 404 is exactly the affordance with
		// nothing behind it, and the host drops every nav item for a plugin that
		// mounted no route, so this is also the test that RegisterRoutes is
		// reached at all.
		_, status := serve(t, root, New().Descriptor().NavItems[0].Href)
		if status != http.StatusOK {
			t.Errorf("the nav item points at %q, which answers %d", IndexHref, status)
		}
	})
}

// emptyStore is a page store with nothing behind it, which is the shape the host
// hands a plugin whose composition root wired none.
type emptyStore struct{}

func (emptyStore) GetPageSummary(context.Context, authz.Principal, int64) (store.PageSummary, error) {
	return store.PageSummary{}, store.ErrNoRows
}
func (emptyStore) ListPagesByType(context.Context, authz.Principal, string) ([]store.Page, error) {
	return nil, nil
}
func (emptyStore) CountPagesByType(context.Context, authz.Principal, string) (int, error) {
	return 0, nil
}
func (emptyStore) ListTags(context.Context, authz.Principal) ([]store.TagCount, error) {
	return nil, nil
}

var _ plugin.PageStore = emptyStore{}

// TestAStoreThatCannotBeReadSaysSo is the failure path, and it is a page
// property rather than an error property: a list of nothing and a read that
// failed look identical otherwise, and the second is the page lying.
func TestAStoreThatCannotBeReadSaysSo(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	store.failing = true
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	body, status := serve(t, rootFor(t, h), "/plugin/"+ID+"/")
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", status)
	}
	if !strings.Contains(body, "The list below may be incomplete") {
		t.Error("a failed read renders no incompleteness banner")
	}
	if !strings.Contains(body, storeUnreadable) {
		t.Error("a failed read does not say that the list is not the whole set")
	}
	// And it renders no list, because a list of nothing under a heading that
	// claims completeness is the failure the banner exists to prevent.
	if strings.Contains(body, "No house rules yet") {
		t.Error("a failed read renders the empty state, which says the campaign has no rules")
	}
	// The error never reaches the reader: it is a store's own string, and a
	// response body is not a log.
	if strings.Contains(body, errStoreDown.Error()) {
		t.Error("the store's error text reached the response body")
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
func TestTheRealHostBootsThisPlugin(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	mux := chi.NewRouter()
	var migrations []plugin.Migration

	reg, report := plugin.Load(t.Context(), plugin.PluginDeps{
		Now:   func() time.Time { return time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC) },
		Log:   func(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {},
		FS:    func() fs.FS { return fstest.MapFS{} },
		Pages: store,
		Config: func(string) (plugin.Config, error) {
			return plugin.Config{Values: map[string]any{}}, nil
		},
		Migrations: func(ctx context.Context, id string, migs []plugin.Migration) error {
			migrations = append(migrations, migs...)
			return nil
		},
		SubRouter: func(string) plugin.RouteMounter { return mux },
	}, New())

	entry := requireEntry(t, report, ID)
	if entry.Status != plugin.StatusOK {
		t.Fatalf("the real host reported %s: %s", entry.Status, entry.Reason)
	}
	if len(report.Warnings) > 0 {
		t.Errorf("the real host warned about the only plugin offered: %v", report.Warnings)
	}
	if len(migrations) != 0 {
		t.Errorf("the host ran %d migrations; this plugin owns no table", len(migrations))
	}

	if got := len(reg.NavItems()); got != 1 {
		t.Errorf("NavItems returned %d entries, want 1: the host drops every nav item for a plugin that mounted no route", got)
	}
	if got := len(reg.SearchResolvers()); got != 1 {
		t.Errorf("SearchResolvers returned %d entries, want 1", got)
	}
	if _, ok := reg.PageType(PageTypeHouseRule); ok {
		t.Errorf("the registry holds a %q page type, which a feature plugin may not register", PageTypeHouseRule)
	}
	if got := len(reg.Summaries()); got != 0 {
		t.Errorf("Summaries returned %d entries, want 0", got)
	}
	if got := len(reg.PanelsFor("")); got != 0 {
		t.Errorf("PanelsFor(\"\") returned %d panels; this plugin contributes none", got)
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
	if _, status := serve(t, root, IndexHref); status != http.StatusOK {
		t.Errorf("the index answered %d through the host's own sub-router", status)
	}
	if _, status := serve(t, root, IndexHref+rulesRoute); status != http.StatusOK {
		t.Errorf("the fragment answered %d through the host's own sub-router", status)
	}
}

// TestTheHostWithoutAPageStoreStillServesAPage covers the composition root that
// wired no store. The host hands every plugin its emptyPageStore rather than a
// nil, so the question is not whether the plugin survives a nil — it is whether
// the page it serves is a working one.
func TestTheHostWithoutAPageStoreStillServesAPage(t *testing.T) {
	t.Parallel()
	mux := chi.NewRouter()
	reg, report := plugin.Load(t.Context(), plugin.PluginDeps{
		Now:       func() time.Time { return time.Time{} },
		Log:       func(context.Context, plugin.Level, string, ...plugin.KV) {},
		FS:        func() fs.FS { return fstest.MapFS{} },
		SubRouter: func(string) plugin.RouteMounter { return mux },
	}, New())
	if entry := requireEntry(t, report, ID); entry.Status != plugin.StatusOK {
		t.Fatalf("the host reported %s: %s", entry.Status, entry.Reason)
	}
	root := chi.NewRouter()
	for _, owned := range reg.Routes() {
		root.Mount(plugin.PluginPrefix(owned.Plugin), owned.Value)
	}
	body, status := serve(t, root, IndexHref)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: a plugin with no store still serves its page", status)
	}
	if !strings.Contains(body, "No house rules yet") {
		t.Error("a plugin with no store renders something other than the empty state")
	}
	if _, status := serve(t, root, IndexHref+rulesRoute+"?q=fair"); status != http.StatusOK {
		t.Errorf("the fragment answered %d with no store behind it", status)
	}
}

// TestNoJavaScriptCSSOrDOMHandleIsShipped is a security property rather than a
// style rule.
//
// §2.6 of the plan and §7 of the working agreement are explicit: a plugin cannot
// ship JavaScript, a stylesheet or a DOM handle. The Host interface has no
// method that could install one, so this test is the backstop against a future
// contributor finding a way around that anyway.
//
// Both halves are checked: the .templ source, because that is where markup is
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
		"data-drawer":  "the drawer's open state is a core signal; a plugin may not write one",
		"data-show":    "the drawer's open state is a core signal; a plugin may not write one",
		"javascript:":  "a javascript: URL is script execution with a link's clothing on",
		"templ.Raw(":   "a plugin may not mark a string raw, so no string of its own can reach a reader unescaped",
	}
	files := []string{"index.templ", "index_templ.go"}
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
	}
}

// coreShellIDs are the ids the shell owns and app.js binds to.
var coreShellIDs = []string{"shell", "left-nav", "content", "context", "page-region", "palette", "shortcuts"}

// TestTheDocumentDeliberatelyUsesTheShellsIDs is the other side of that rule,
// stated rather than left ambiguous.
//
// The committed stylesheet keys its three-column rules and its drawer
// breakpoints on #shell, #left-nav, #content and #context, and not on a class, so
// a page with different ids gets none of the shell's layout. This page uses
// core's ids, which is safe only because it is a standalone document that loads
// no script — and the fact that it loads no script is what the previous test
// checks. Both halves are asserted here so neither can be removed alone.
func TestTheDocumentDeliberatelyUsesTheShellsIDs(t *testing.T) {
	t.Parallel()
	store := newFakeStore(t)
	h := newFakeHost(t)
	h.pages = store
	registerWith(t, h)
	body, status := serve(t, rootFor(t, h), "/plugin/"+ID+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	for _, id := range []string{"shell", "left-nav", "content", "context"} {
		if got := strings.Count(body, `id="`+id+`"`); got != 1 {
			t.Errorf("the document renders id=%q %d times, want exactly 1", id, got)
		}
	}
	for _, id := range []string{"page-region", "palette", "shortcuts"} {
		if strings.Contains(body, `id="`+id+`"`) {
			t.Errorf("the document renders id=%q, which belongs to the shell rather than to a page of its own", id)
		}
	}
	// Every id this package invents is prefixed, so an id from a plugin and an id
	// from the shell can never be the same identifier by coincidence.
	for _, m := range regexp.MustCompile(`id="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		if !strings.HasPrefix(m[1], "houserules-") && !slicesContains(coreShellIDs, m[1]) {
			t.Errorf("the document renders the unprefixed id %q, which is a claim on the shell's namespace", m[1])
		}
	}
	// A plugin page references the stylesheet and nothing else it could execute.
	if !strings.Contains(body, `<link rel="stylesheet" href="`+stylesheetHref+`"`) {
		t.Error("the document does not reference the committed stylesheet, so the three columns would render unstyled")
	}
	if !strings.Contains(body, `<link rel="icon"`) {
		t.Error("the document carries no icon reference, so a bookmark shows a broken favicon")
	}
}

// sourceDirective is one @source line of the Tailwind entry point. It is
// anchored to the start of a line so that an @import or a font name is not
// mistaken for a scan surface, and it fails loudly on a directive that matches
// no file rather than skipping it.
var sourceDirective = regexp.MustCompile(`(?m)^@source\s+"([^"]+)"`)

// quotedString is every double- or back-quoted string in a Go or templ source,
// which is where a class name can hide.
var quotedString = regexp.MustCompile("\"([^\"\\n]*)\"|`([^`\\n]*)`")

// TestThePluginShipsNoClassTheStylesheetHasNeverHeardOf is the silent-failure
// gate for this package's markup.
//
// Tailwind's class names are discovered by the scanner web/src/input.css
// configures, and internal/systems/** is deliberately not on that list — the
// list is core-owned and narrowing or widening it is core's decision. So a class
// that appears only in this package's .templ is a class the committed stylesheet
// has no rule for, and the page renders unstyled with no error anywhere: the
// build succeeds, the test run succeeds, and the reader sees a wall of text.
//
// The scan surface is read from input.css rather than restated here, so a change
// to the list is picked up rather than contradicted.
func TestThePluginShipsNoClassTheStylesheetHasNeverHeardOf(t *testing.T) {
	t.Parallel()

	base := filepath.Join("..", "..", "..", "web", "src")
	raw, err := os.ReadFile(filepath.Join(base, "input.css"))
	if err != nil {
		t.Fatalf("read the Tailwind entry point: %v", err)
	}
	css := string(raw)

	// The classes core's own scan surface already knows: every token inside a
	// quoted string of every scanned file.
	known := map[string]bool{}
	scans := 0
	for _, match := range sourceDirective.FindAllStringSubmatch(css, -1) {
		matches, globErr := filepath.Glob(filepath.Join(base, match[1]))
		if globErr != nil || len(matches) == 0 {
			t.Fatalf("the Tailwind entry point scans %q, which matches no file: this test is not looking where the build looks", match[1])
		}
		scans++
		for _, file := range matches {
			body, readErr := os.ReadFile(file)
			if readErr != nil {
				t.Fatalf("read %s: %v", file, readErr)
			}
			for _, quoted := range quotedString.FindAllStringSubmatch(string(body), -1) {
				for _, part := range quoted[1:] {
					for _, tok := range strings.Fields(part) {
						known[tok] = true
					}
				}
			}
		}
	}
	if scans == 0 {
		t.Fatal("the Tailwind entry point names no @source, so this test is not looking at the build's scan surface")
	}
	// Plus the component classes the stylesheet defines itself, which are plain
	// CSS and need no scan surface to exist.
	for _, match := range regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`).FindAllStringSubmatch(css, -1) {
		known[match[1]] = true
	}
	if len(known) == 0 {
		t.Fatal("no class name was found, so this test is not looking at the stylesheet's scan surface")
	}

	src, err := os.ReadFile("index.templ")
	if err != nil {
		t.Fatalf("read index.templ: %v", err)
	}
	used := map[string]bool{}
	for _, match := range regexp.MustCompile(`class="([^"]*)"`).FindAllStringSubmatch(string(src), -1) {
		for _, tok := range strings.Fields(match[1]) {
			used[tok] = true
		}
	}
	if len(used) == 0 {
		t.Fatal("no class was found, so this test is not looking at the markup")
	}
	for tok := range used {
		if !known[tok] {
			t.Errorf("index.templ uses the class %q, which nothing in the committed stylesheet's scan surface or its own rules produces", tok)
		}
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
// The walk skips _test.go. This file necessarily reads files and the test binary
// necessarily imports os; internal/architecture_test.go skips test files for the
// same reason, and a check that trips over its own instrumentation is a check
// somebody deletes.
func TestTheHostSurfaceIsEnoughToImplementThisPlugin(t *testing.T) {
	t.Parallel()

	// The compile-time half, asserted again here so the test is self-contained
	// rather than depending on a file-level var being noticed.
	var h plugin.Host = &recordingHost{}
	if h.Capability().Has(plugin.CapSidebarNav) {
		t.Error("an empty capability set reported holding CapSidebarNav")
	}

	// The imports a plugin may not name, matched as whole quoted import paths
	// rather than as bare words. A bare word would fire on this file's own prose
	// — several of these names appear in comments explaining why they are
	// forbidden — and an assertion that trips over its own documentation is an
	// assertion somebody deletes.
	//
	// net/http is deliberately absent: serving a route is an http.HandlerFunc
	// and the router's own method takes one, so a plugin that mounts routes must
	// name the type. What is forbidden is the *client* half, and a plugin that
	// reached for http.Client would be caught by the .DefaultClient and
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
		`"github.com/PopinjayJohn/vtt-semiplane/internal/web"`:     "web is above httpapi, so importing it from a plugin closes the loop",
	}
	// os./net./exec. as a package qualifier, and the two spellings of an HTTP
	// client, which are the only ways a compiled-in plugin reaches the network.
	forbiddenUses := []*regexp.Regexp{
		regexp.MustCompile(`\bos\.[A-Z]`),
		regexp.MustCompile(`\bnet\.[A-Z]`),
		regexp.MustCompile(`\bexec\.[A-Z]`),
		regexp.MustCompile(`\bhttp\.(Client|NewRequest|DefaultClient|Get|Post)\b`),
	}
	// And the ways a plugin could reach for a role. A plugin has no principal —
	// see reader() — so every one of these is an authorization this package would
	// be inventing, and inventing one is the failure mode the whole design of
	// this plugin exists to avoid. authz.Anonymous is not on the list because
	// reader() is built from it; the count below pins it to the one call site.
	forbiddenRoles := map[string]string{
		"authz.ForUser":    "a plugin cannot assert who is asking",
		"authz.RoleDM":     "a plugin cannot decide who is a DM",
		"authz.RoleAdmin":  "a plugin cannot decide who is an admin",
		"authz.RolePlayer": "a plugin cannot decide who anyone is",
		"IsDM(":            "a plugin cannot ask a role question; it has no principal to ask about",
		"IsAdmin(":         "a plugin cannot ask a role question; it has no principal to ask about",
		"Principal{":       "a plugin cannot construct a principal",
		"MinimumRole":      "a role on a nav item hides a link and gates nothing",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	checked := 0
	anonymousUses := 0
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
		for needle, reason := range forbiddenRoles {
			// Over code and not over text: a line that is not a comment. The prose
			// in this package's own comments names these symbols, and an assertion
			// that trips over its own documentation is an assertion somebody
			// deletes.
			if found := codeLines(regexp.MustCompile(`\b` + regexp.QuoteMeta(needle))).match(text); found != "" {
				t.Errorf("%s reaches for %s: %s", name, needle, reason)
			}
		}
		anonymousUses += codeLines(regexp.MustCompile(`authz\.PrincipalFrom`)).count(text)
	}
	if checked < 4 {
		t.Errorf("only %d source files were checked, so the boundary assertion is not looking where it thinks it is", checked)
	}
	// authz.PrincipalFrom is the one place this package names a principal, and it
	// names the request's own. A second use is a second answer to "who is asking",
	// which is the question the host already answered once.
	if anonymousUses != 1 {
		t.Errorf("authz.PrincipalFrom is used %d times in the package's sources, want exactly 1: it belongs in reader() and nowhere else", anonymousUses)
	}
}

// codeLines strips comment lines out of a Go or templ source, so a check over the
// code is not a check over the documentation that explains it.
func codeLines(needle *regexp.Regexp) matcher {
	return matcher{needle: needle}
}

// matcher counts and reports non-comment lines matching a pattern.
type matcher struct{ needle *regexp.Regexp }

func (m matcher) count(text string) int {
	var n int
	for _, line := range strings.Split(text, "\n") {
		if m.matches(line) {
			n++
		}
	}
	return n
}

func (m matcher) match(text string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m.needle.MatchString(trimmed) {
			return trimmed
		}
	}
	return ""
}

func (m matcher) matches(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
		return false
	}
	return m.needle.MatchString(trimmed)
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
	want := []string{"doc.go", "plugin.go", "hostcall.go", "index.templ", "index_templ.go"}
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

// The small helpers, and the reasons they are shaped the way they are.

// grantedFor is the host's own parse of this plugin's declaration, for the
// subtests that build a host inline.
func grantedFor(t *testing.T) plugin.Capabilities {
	t.Helper()
	got, err := plugin.ParseCapabilities(New().Descriptor().Capabilities)
	if err != nil {
		t.Fatalf("ParseCapabilities: %v", err)
	}
	return got
}

// bootDeps is a composition root's PluginDeps, for the subtests that boot the
// real host without going through the fake.
func bootDeps(pages plugin.PageStore) plugin.PluginDeps {
	return plugin.PluginDeps{
		Now:       func() time.Time { return time.Time{} },
		Log:       func(context.Context, plugin.Level, string, ...plugin.KV) {},
		FS:        func() fs.FS { return fstest.MapFS{} },
		Pages:     pages,
		SubRouter: func(string) plugin.RouteMounter { return chi.NewRouter() },
	}
}

// requireEntry finds one plugin's line in a boot report, failing loudly when it
// is absent: a report with no line for the plugin under test is a report the
// test cannot read, and a test that cannot read its evidence passes vacuously.
func requireEntry(t *testing.T, report plugin.Report, id string) plugin.Entry {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.ID == id {
			return entry
		}
	}
	t.Fatalf("the boot report has no line for %q: %+v", id, report.Entries)
	return plugin.Entry{}
}

// titles is the titles of a set of rows, for the expectation comparisons.
func titles(rows []store.Page) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Title)
	}
	return out
}

// sameTitles compares two title sets as sets, so that a fixture which drifted in
// order is reported as a drift rather than as a pass.
func sameTitles(rows []store.Page, want []string) bool {
	got := map[string]int{}
	for _, row := range rows {
		got[row.Title]++
	}
	if len(got) != len(want) {
		return false
	}
	for _, title := range want {
		if got[title] != 1 {
			return false
		}
	}
	return true
}

// listedTitles reads the paths out of a rendered index.
//
// It reads the markup rather than calling a helper, because the thing under test
// is the markup: a helper would report what the view model holds while the page
// showed something else, and the whole of this package's claim is that the two
// agree.
func listedTitles(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`<code class="text-xs[^"]*">([^<]*)</code>`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// stripTags removes markup from a rendered fragment, so that a number read back
// out of the page is the number a reader reads rather than the one the source
// happened to contain.
func stripTags(s string) string {
	return strings.TrimSpace(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, ""))
}

// slicesContains reports membership, without importing slices for one call.
func slicesContains(haystack []string, needle string) bool {
	for _, have := range haystack {
		if have == needle {
			return true
		}
	}
	return false
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
func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(t.Context(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

// TestTheComponentsEscapeWhatTheyRender is the last line of defence between a
// frontmatter value and a reader's screen.
//
// Every value that reaches a template here came out of a Markdown file, and a
// Markdown file is the one artefact in this application that an untrusted person
// can put arbitrary text into. templ escapes a string expression by construction,
// and the only way to defeat that is templ.Raw — which this package may not call
// and which the token test above checks for. This test does not prove templ is
// safe; it proves that if somebody does find a way around it, the values that
// matter are the ones being checked.
func TestTheComponentsEscapeWhatTheyRender(t *testing.T) {
	t.Parallel()
	hostile := `<script>alert("x")</script> & "quoted" 'single'`
	view := indexView{
		Total: 1,
		All:   []Rule{hRule},
		Shown: []Rule{hRule},
		Chips: []tagChip{{Name: hostile, Count: 1}},
		Term:  hostile,
		// The active tag is the hostile one too, so the chip, the hidden form
		// field and the chip href all carry it.
		ActiveTag: hostile,
		Groups:    []ruleGroup{{ID: groupID(0), Name: hostile, Rules: []Rule{hRule}}},
	}
	for _, name := range []string{"a tag", "a system"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, c := range []struct {
				what string
				body templ.Component
			}{
				{"the document", houseRulesDocument(view)},
				{"the list", houseRulesList(view)},
				{"the row", ruleRow(hRule)},
				{"the chip", tagChipRow(view.Chips[0], true, view.ChipHref(hostile))},
				{"the grouped list", groupedRules(view)},
			} {
				body := render(t, c.body)
				if strings.Contains(body, "<script>alert") {
					t.Errorf("%s rendered an unescaped script element: %s", c.what, body)
				}
				if !strings.Contains(body, "&lt;script&gt;") {
					t.Errorf("%s dropped the value instead of escaping it: %s", c.what, body)
				}
			}
			// The hostile tag also travels in a URL, where an unencoded quote
			// would end the attribute and start a new one. The view used here
			// carries no active tag, because a chip whose tag is already the
			// filter links to the state *without* it — which is the toggle, and
			// which is why the tag is checked through href rather than ChipHref.
			href := indexView{Term: hostile}.href(hostile, hostile, true)
			if strings.ContainsAny(href, `"'<> `) {
				t.Errorf("a chip href is not encoded: %q", href)
			}
			for _, want := range []string{"tag=", "q=", "group="} {
				if !strings.Contains(href, want) {
					t.Errorf("a chip href lost %q: %q", want, href)
				}
			}
		})
	}
}

// hRule is one hostile rule, used by the escaping test.
var hRule = Rule{
	ID:     1,
	Path:   `Rules/O'Brien & <Sons>.md`,
	Title:  `<script>alert("x")</script> & "quoted" 'single'`,
	System: `<script>alert("x")</script> & "quoted" 'single'`,
	Tags:   []string{`<script>alert("x")</script> & "quoted" 'single'`},
}
