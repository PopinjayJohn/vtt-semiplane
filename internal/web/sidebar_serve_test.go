package web_test

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	isync "github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
)

// The sidebar's tree, end to end: a real vault, a real index, the real router
// and the real renderer, with the links read out of the rendered document and
// then *followed*.
//
// The component tests above can prove the template renders the view model it was
// given. They cannot prove anything is pointed at it, which is the failure
// AGENTS.md §11 records in this exact shape — an HTTP-level test that requests a
// route directly proves the route works, and a render test proves the component
// renders. So every link here is taken from the bytes of a real response and
// issued as a request, and the assertion is about where it lands rather than
// about whether it matched a pattern.
//
// It is a boot rather than a stub on purpose: a matrix over stubs is a matrix
// over the stubs, and the question "does the campaign's own navigation reach the
// campaign's pages" is exactly the question a stub answers wrongly.

// serveFixture is a booted application and the vault behind it.
type serveFixture struct {
	t   *testing.T
	dir string
	ts  *httptest.Server
}

// newServeFixture writes files into a temp vault, walks it, indexes it and boots
// the router over it.
//
// A directory entry written with a trailing slash is created and left empty, so
// a test can put a genuinely empty folder in the vault and ask what the tree
// does with it — which is a different question from what the template does with
// a directory node that has nothing in it.
func newServeFixture(t *testing.T, files map[string]string) *serveFixture {
	t.Helper()
	dir := t.TempDir()
	for path, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if strings.HasSuffix(path, "/") {
			if err := os.MkdirAll(full, 0o750); err != nil {
				t.Fatalf("make the empty directory %q: %v", path, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("make the parent of %q: %v", path, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}

	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = 0
	cfg.Vault = dir
	cfg.NoOpen = true
	// Anonymous read on, so the walk runs as a principal who may open every page
	// in the vault. The point of the fixture is the tree, and a tree a stranger
	// cannot see is asserted on its own in the component tests.
	cfg.AllowAnonymousRead = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the fixture's configuration is not valid: %v", err)
	}

	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if migrateErr := store.Migrate(context.Background(), db.Writer(), func(context.Context) error { return nil }); migrateErr != nil {
		t.Fatalf("migrate the index: %v", migrateErr)
	}

	ix, err := isync.New(isync.Options{DB: db, Root: dir})
	if err != nil {
		t.Fatalf("build the indexer: %v", err)
	}
	res, err := ix.Walk(context.Background())
	if err != nil {
		t.Fatalf("walk the vault: %v", err)
	}
	if _, indexErr := ix.IndexBatch(context.Background(), res.Files); indexErr != nil {
		t.Fatalf("index the vault: %v", indexErr)
	}
	if bootErr := store.MetaSet(context.Background(), db.Writer(), store.KeyBootState, store.BootStateReady); bootErr != nil {
		t.Fatalf("record the boot state: %v", bootErr)
	}

	srv, err := httpapi.New(httpapi.Options{
		Config:        cfg,
		DB:            db,
		Writer:        vault.NewWriter(dir, nil),
		Reindexer:     ix,
		AuthorRetryer: ix,
		Assets:        web.Assets(),
		Renderer:      web.NewRenderer(),
		Build:         app.Info(),
	})
	if err != nil {
		t.Fatalf("build the server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &serveFixture{t: t, dir: dir, ts: ts}
}

// get is a request, and it takes the URL as a *browser* would receive it: the
// raw attribute value, HTML-unescaped, parsed so the request line carries the
// right percent-encoding.
//
// It returns the status and the body rather than the *http.Response, because it
// has already drained and closed the body by the time it returns — and handing
// back a closed response is a trap that invites a caller to close it again, or
// to read it. Returning only what a caller may still use also removes a class of
// finding that was pure artefact: a helper that closes its body correctly still
// trips bodyclose at every call site, once per caller, with nothing to fix.
func (fx *serveFixture) get(target string) (int, string) {
	fx.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fx.ts.URL+target, nil)
	if err != nil {
		fx.t.Fatalf("build a request for %q: %v", target, err)
	}
	resp, err := fx.ts.Client().Do(req)
	if err != nil {
		fx.t.Fatalf("GET %q: %v", target, err)
	}
	// The shape is load-bearing and both linters care about a different thing
	// about it. `defer resp.Body.Close()` is what bodyclose can follow into this
	// helper, so it stops reporting every call site as an unclosed response;
	// wrapping the close in a func literal to satisfy errcheck makes it invisible
	// to bodyclose again, which is a way of trading one linter's finding for
	// seven of another's. So the close stays bare and carries the reason instead.
	defer resp.Body.Close() //nolint:errcheck // a drained read handle's close is not actionable
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if readErr != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

// sidebarTreeLinks is every page link the left column emitted, in document
// order, as the URLs a browser would request them.
//
// The href is read raw and unescaped before being parsed, because that is the
// order the browser does it in: the HTML parser decodes the attribute, and the
// URL parser percent-encodes what is left. Skipping either half would test an
// encoding the application never produced.
func sidebarTreeLinks(t *testing.T, document string) []string {
	t.Helper()
	nav := between(document, `<nav id="left-nav"`, "</nav>")
	if nav == "" {
		t.Fatal("the document has no left navigation")
	}
	var out []string
	for _, m := range regexp.MustCompile(`<li class="file-page"><a href="([^"]*)"`).FindAllStringSubmatch(nav, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// TestTheSidebarTreeIsOnEveryPageAndEveryLinkItEmitsResolves is the end-to-end
// claim: the tree is reached, and every link it prints opens the page it names.
//
// Both halves are the reason this file exists. The first — the tree is in the
// document at all — is what a render test cannot see. The second is what a
// route test cannot see: it follows the hrefs the sidebar emitted rather than
// composing paths from the fixture, so a tree that encoded a path differently
// from the router would fail here and pass a test that requested /p/{path}
// itself.
func TestTheSidebarTreeIsOnEveryPageAndEveryLinkItEmitsResolves(t *testing.T) {
	t.Parallel()
	fx := newServeFixture(t, map[string]string{
		"Index.md":                 "# Index\n",
		"Tavern.md":                "# The Drowned Lantern\n\nThe lantern is on a table.\n",
		"Area/Salt_Ruin.md":        "# The Salt Ruin\n",
		"Area/NPCs/Gundren.md":     "# Gundren\n",
		"Sessions/12.md":           "# Session 12\n",
		"Ash & Ember/Naïve.md":     "# Naive and bold\n",
		`Odd "quoted" & spaced.md`: "# Odd names\n",
		"Empty/":                   "",
	})

	cases := []struct {
		name string
		path string
	}{
		{name: "the dashboard", path: "/"},
		{name: "the file tree page", path: "/files"},
		{name: "a page view", path: "/p/Index.md"},
		{name: "a nested page view", path: "/p/Area/NPCs/Gundren.md"},
		{name: "the tag index", path: "/tags"},
		{name: "the search page", path: "/search?q=lantern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, body := fx.get(tc.path)
			if status != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200\n%.600s", tc.path, status, body)
			}
			links := sidebarTreeLinks(t, body)
			if len(links) == 0 {
				t.Fatalf("GET %s carries no vault tree, so the sidebar is not a navigation on this surface:\n%.1200s", tc.path, body)
			}
			// Every page in the vault is reachable from every surface, which is
			// the difference between a navigation and a widget that appears on
			// some pages.
			for _, want := range []string{
				"/p/Index.md", "/p/Tavern.md", "/p/Area/Salt_Ruin.md",
				"/p/Area/NPCs/Gundren.md", "/p/Sessions/12.md",
				"/p/Ash & Ember/Naïve.md", `/p/Odd "quoted" & spaced.md`,
			} {
				if !slicesContains(links, want) {
					t.Errorf("GET %s does not link %q; it links %v", tc.path, want, links)
				}
			}
		})
	}

	t.Run("every link the sidebar emitted opens the page it names", func(t *testing.T) {
		t.Parallel()
		_, dashboard := fx.get("/")
		links := sidebarTreeLinks(t, dashboard)
		if len(links) == 0 {
			t.Fatal("the dashboard's sidebar emitted no page links")
		}
		for _, link := range links {
			status, body := fx.get(link)
			if status != http.StatusOK {
				t.Errorf("the sidebar linked %q and following it answered %d, want 200", link, status)
				continue
			}
			// It is the page, not a login form: an anonymous reader with
			// --allow-anonymous-read on may open every page, and a 303 to /login
			// would be a 200 nowhere and a tree full of dead links.
			if !strings.Contains(body, `id="page-region"`) {
				t.Errorf("following %q did not reach a page region", link)
			}
			if strings.Contains(body, "name=\"q\"") && !strings.Contains(body, "<h1") {
				t.Errorf("following %q reached a form rather than a page", link)
			}
		}
	})

	t.Run("an empty folder contributes no row and breaks no link", func(t *testing.T) {
		t.Parallel()
		// The tree is built from indexed pages, so a directory holding no file
		// has no node to render. Asserting that it is *absent* is the claim; the
		// important half is that nothing else moved, because a tree that had been
		// built by walking directories would show a folder with nothing in it and
		// that is a second, disagreeing source of truth about the vault.
		_, dashboard := fx.get("/")
		if strings.Contains(dashboard, `data-dir="Empty"`) {
			t.Error("an empty folder appears in the tree, so the tree is not built from the index")
		}
		for _, link := range sidebarTreeLinks(t, dashboard) {
			if strings.HasPrefix(link, "/p/Empty/") {
				t.Errorf("the tree links a page inside an empty folder: %q", link)
			}
		}
	})
}

// TestTheSidebarTreeCarriesNoPathThatLeavesTheVault is the traversal claim, end
// to end.
//
// A hostile *file on disk* is the case that matters, because the syntactic rules
// in vault.Resolve only run when something asks for a path: a name the walk
// admits into the index is a name the tree will print, and a symlink out of the
// vault is exactly such a name. So the fixture plants one, and the claim is
// about the document rather than about the walk: whatever the walk decides, the
// sidebar prints no link whose target is not inside the vault.
func TestTheSidebarTreeCarriesNoPathThatLeavesTheVault(t *testing.T) {
	t.Parallel()
	fx := newServeFixture(t, map[string]string{
		"Index.md":          "# Index\n",
		"Area/Salt_Ruin.md": "# The Salt Ruin\n",
	})
	// A symlink named like a page, aimed at a file outside the vault. If the walk
	// admits it, the tree prints a link the router will refuse; if the walk
	// refuses it, the tree prints nothing. Either way the sidebar must not print
	// a traversal.
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("# outside the vault\n"), 0o600); err != nil {
		t.Fatalf("write the file outside the vault: %v", err)
	}
	planted := 0
	for _, name := range []string{"Escape.md", "..Escape.md", "Area/../../Escape.md"} {
		full := filepath.Join(fx.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("make the parent of %q: %v", name, err)
		}
		if err := os.Symlink(outside, full); err != nil {
			t.Logf("could not plant the symlink %q: %v", name, err)
			continue
		}
		// The plant is asserted, not assumed. A symlink this code cannot create
		// is a test that quietly stopped testing anything, and the whole fixture
		// would still pass — which is the failure AGENTS.md §11 records as "an
		// assertion is only as strong as the state its fixture built".
		if _, err := os.Lstat(full); err != nil {
			t.Fatalf("the symlink %q was not created: %v", name, err)
		}
		planted++
	}
	if planted == 0 {
		t.Fatal("no symlink could be planted, so the traversal assertions are looking at nothing")
	}

	_, dashboard := fx.get("/")
	links := sidebarTreeLinks(t, dashboard)
	for _, link := range links {
		if !strings.HasPrefix(link, "/p/") {
			t.Errorf("the sidebar emitted %q, which is not a page URL", link)
		}
		for _, elem := range strings.Split(strings.TrimPrefix(link, "/p/"), "/") {
			if elem == ".." || elem == "." {
				t.Errorf("the sidebar emitted a link with a %q element: %q", elem, link)
			}
		}
		// A link the router would refuse is a link the tree should not have
		// printed, and following it is the only way to know.
		status, _ := fx.get(link)
		if status == http.StatusNotFound {
			t.Errorf("the sidebar links %q and following it is a 404", link)
		}
	}
	// The positive control, without which the loop above could pass by printing
	// nothing at all.
	if !slicesContains(links, "/p/Index.md") {
		t.Fatalf("the tree printed no links, so the traversal assertions are looking at nothing: %v", links)
	}
}

// TestTheSidebarTreeIsTheSameTreeOnEverySurface is the "one listing" claim,
// measured rather than asserted.
//
// The sidebar's tree and the tree at /files are rendered from one view model on
// one page, and a second listing query would be a second thing that can disagree
// with the first. So the page link sets are compared: if the two ever differ, one
// of them is lying about the vault and the difference is a bug whichever way it
// goes.
func TestTheSidebarTreeIsTheSameTreeOnEverySurface(t *testing.T) {
	t.Parallel()
	var files = map[string]string{"Index.md": "# Index\n"}
	for i := range 12 {
		files[fmt.Sprintf("Campaigns/Ash/Page-%02d.md", i)] = fmt.Sprintf("# Page %d\n", i)
	}
	fx := newServeFixture(t, files)

	_, filesPage := fx.get("/files")
	nav := between(filesPage, `<nav id="left-nav"`, "</nav>")
	page := between(filesPage, `<h1 id="files-heading"`, "</section>")
	sidebarSet := sortedStrings(sidebarTreeLinks(t, filesPage))
	pageSet := sortedStrings(regexpLinks(page))
	if len(pageSet) == 0 {
		t.Fatalf("the file tree page rendered no links, so the comparison is looking at nothing:\n%.800s", filesPage)
	}
	if !slicesEqual(sidebarSet, pageSet) {
		t.Errorf("the two trees disagree about the vault\nsidebar: %v\npage:    %v", sidebarSet, pageSet)
	}
	// The sidebar carries the cap and the page does not, so on a vault larger
	// than the cap they are *meant* to differ — and the difference is declared
	// rather than silent. With thirteen pages the cap does not bite, which is
	// the state this asserts.
	if strings.Contains(nav, "more pages in this vault") {
		t.Errorf("a %d-page vault announced an omission:\n%s", len(files), nav)
	}
}

// regexpLinks is every /p/ href in a fragment, in document order.
func regexpLinks(fragment string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`href="(/p/[^"]*)"`).FindAllStringSubmatch(fragment, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
