package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/PopinjayJohn/vtt-semiplane"
const internalPath = modulePath + "/internal/"

// The canonical dependency order, lowest first. A package may import itself and
// anything earlier in this list, and nothing later.
//
//	app is exempt and may import everything; it is the composition root.
//	testutil is exempt and may import everything; it boots the app in-process.
//	sample may import nothing internal; it is an embedded filesystem.
//	systems/* and plugins/* are plugins and are held to pluginBoundary.
//
// This ordering resolves two inconsistencies in the design plan.
//
// The plan lists `secrets < authz`, which would forbid the redactor from asking
// authz.CanReadSecret — and asking it is the whole point of the redactor. The
// arrow therefore runs secrets -> authz, and authz is forbidden from importing
// secrets so that no cycle can form. authz owns the canonical visibility
// constants precisely so that both packages can name them.
//
// The plan's list does not mention authz's position relative to store, but
// store's own queries embed authz.SecretVisibleSQL verbatim, so authz sits below
// store. authz imports nothing of ours: a Resource is a plain struct handed to
// it by the service that already has the row, so authz never queries a
// database and holds no *sql.DB of its own.
var order = []string{
	"config",
	"obs",
	"authz",
	"store",
	"md",
	"plugin",
	"vault",
	"auth",
	"secrets",
	"sync",
	"search",
	"httpapi",
	"web",
}

var exempt = map[string]bool{
	"app":      true,
	"testutil": true,
}

var index = func() map[string]int {
	m := make(map[string]int, len(order))
	for i, p := range order {
		m[p] = i
	}
	return m
}()

// pluginBoundary is the import allow-list for a plugin package. A plugin is
// first-party code; the boundary exists to make a reach-through into the
// request path impossible to express by accident (§11).
var pluginBoundary = map[string]bool{
	"plugin":  true,
	"md":      true,
	"store":   true,
	"web":     true,
	"authz":   true,
	"secrets": true,
}

// forbiddenInPlugins are internal packages a plugin may never reach, each with
// the reason, so a failure explains the rule rather than printing a list diff.
var forbiddenInPlugins = map[string]string{
	"httpapi": "it would bypass the host's per-request redaction and the Perm middleware",
	"auth":    "it would bypass session handling and the Principal capture",
	"obs":     "it would bypass the redacting log handler",
	"sync":    "it would write the index behind the indexer's back",
	"config":  "it would read core configuration a plugin has no business seeing",
	"app":     "it is the composition root, not a library",
}

func rootOf(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd)
}

// shortName maps a full import path to its package name within our tree.
func shortName(imp string) (name string, ours bool) {
	if !strings.HasPrefix(imp, internalPath) {
		return "", false
	}
	return strings.TrimPrefix(imp, internalPath), true
}

func isPluginPkg(name string) bool {
	return name == "sample" ||
		strings.HasPrefix(name, "systems/") ||
		strings.HasPrefix(name, "plugins/")
}

func TestDependencyDirection(t *testing.T) {
	root := rootOf(t)
	failures := map[string][]string{}

	dirs, err := os.ReadDir(filepath.Join(root, "internal"))
	if err != nil {
		t.Fatalf("read internal: %v", err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files := goFiles(t, filepath.Join(root, "internal", d.Name()))
		if len(files) == 0 {
			continue
		}
		pkg := d.Name()
		if exempt[pkg] {
			continue
		}
		me, ordered := index[pkg]
		seen := map[string]bool{}
		for _, file := range files {
			for _, imp := range parseImports(t, file) {
				dep, ours := shortName(imp)
				if !ours || dep == pkg || seen[dep] {
					continue
				}
				seen[dep] = true
				switch {
				case isPluginPkg(pkg):
					if why, bad := forbiddenInPlugins[dep]; bad {
						failures[pkg] = append(failures[pkg], fmt.Sprintf("imports %s: %s", dep, why))
						continue
					}
					if !pluginBoundary[dep] {
						failures[pkg] = append(failures[pkg],
							fmt.Sprintf("imports %s, which is outside the plugin boundary", dep))
					}
				case ordered:
					j, ok := index[dep]
					switch {
					case ok && j > me:
						failures[pkg] = append(failures[pkg],
							fmt.Sprintf("imports %s, which is higher in the order: %s must not import %s", dep, pkg, dep))
					case !ok && !exempt[dep] && !isPluginPkg(dep):
						failures[pkg] = append(failures[pkg],
							fmt.Sprintf("imports %s, which is not in the dependency order at all", dep))
					}
				}
			}
		}
	}

	for pkg, reasons := range failures {
		t.Errorf("%s:\n  %s", pkg, strings.Join(dedupeSorted(reasons), "\n  "))
	}
}

func dedupeSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i > 0 && s == in[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// goFiles collects the non-test .go files of a directory.
func goFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out
}

var importBlock = regexp.MustCompile(`(?s)import\s*\((.*?)\n\)`)
var importLine = regexp.MustCompile(`"(?:[A-Za-z_.][A-Za-z0-9_.-]*/)?[^"]+"`)
var singleImport = regexp.MustCompile(`(?m)^import\s+(?:[A-Za-z_.][A-Za-z0-9_.]*\s+)?"([^"]+)"`)

func parseImports(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)
	var out []string
	for _, m := range importBlock.FindAllStringSubmatch(src, -1) {
		for _, l := range importLine.FindAllString(m[1], -1) {
			out = append(out, strings.Trim(l, `"`))
		}
	}
	for _, m := range singleImport.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestPluginImportsAreWithinBoundary re-checks the plugin allow-list with an
// explicit reason per forbidden package, so a failure says which rule broke.
func TestPluginImportsAreWithinBoundary(t *testing.T) {
	root := rootOf(t)
	for _, base := range []string{"systems", "plugins"} {
		dir := filepath.Join(root, "internal", base)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, imp := range parseImports(t, path) {
				dep, ours := shortName(imp)
				if !ours {
					continue
				}
				if why, bad := forbiddenInPlugins[dep]; bad {
					t.Errorf("%s: a plugin may not import %s: %s", rel, dep, why)
					continue
				}
				if !pluginBoundary[dep] {
					t.Errorf("%s: import %s is outside the plugin boundary", rel, dep)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
}

// TestNoSQLBuiltByStringFormatting enforces the first hard rule in AGENTS.md:
// never construct SQL by string formatting. A query is either a constant or
// built from a fixed set of known-safe fragments; a user value is always a bind
// parameter.
func TestNoSQLBuiltByStringFormatting(t *testing.T) {
	root := rootOf(t)
	verbs := regexp.MustCompile(`(?i)\b(select|insert into|update |delete from|create table|alter table|drop table|create index|create unique index|create virtual table)\b`)

	walkGo(t, root, func(rel, line string, num int) {
		if !strings.Contains(line, "Sprintf") {
			return
		}
		if verbs.MatchString(line) {
			t.Errorf("%s:%d: SQL built by string formatting: %s", rel, num, strings.TrimSpace(line))
		}
	})
}

// TestNoHandRolledVisibilityPredicates enforces the single canonical predicate.
// A hand-rolled `visibility = 'dm'` anywhere outside authz is an existence leak
// waiting to happen, so it fails the build.
func TestNoHandRolledVisibilityPredicates(t *testing.T) {
	root := rootOf(t)
	lit := regexp.MustCompile(`(?i)visibility\s*(=|!=|<>|in)\s*'(\w+)'`)

	walkGo(t, root, func(rel, line string, num int) {
		if strings.HasSuffix(rel, "architecture_test.go") ||
			strings.HasPrefix(rel, "internal/authz/") ||
			strings.HasSuffix(rel, "_test.go") {
			return
		}
		if m := lit.FindStringSubmatch(line); m != nil {
			t.Errorf("%s:%d: hand-rolled visibility predicate %q: use authz.SecretVisibleSQL",
				rel, num, strings.TrimSpace(m[0]))
		}
	})
}

// TestVisibilityPredicateShape pins the two properties of SecretVisibleSQL that
// make it correct: table and private are positive clauses, and dm is NOT one —
// its only route is the :is_dm branch. A future edit that adds
// `s.visibility = 'dm'` as a clause would leak every DM secret to page owners.
func TestVisibilityPredicateShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(rootOf(t), "internal", "authz", "predicate.go"))
	if err != nil {
		t.Fatalf("read predicate.go: %v", err)
	}
	src := string(b)
	for _, want := range []string{":is_dm = 1", "s.visibility = 'table'", "s.visibility = 'private'",
		"s.author_id = :uid", "FROM page_owners po"} {
		if !strings.Contains(src, want) {
			t.Errorf("SecretVisibleSQL no longer contains %q", want)
		}
	}
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "s.visibility = 'dm'") {
			t.Errorf("SecretVisibleSQL must not grant dm visibility by comparison: %s", strings.TrimSpace(line))
		}
	}
}

// TestPackageListIsComplete keeps the skeleton honest: every package the
// architecture names must exist and must carry a doc.go stating what it owns.
func TestPackageListIsComplete(t *testing.T) {
	root := rootOf(t)
	want := []string{
		"cmd/semiplane",
		"internal/app", "internal/config", "internal/obs", "internal/auth",
		"internal/authz", "internal/store", "internal/search", "internal/md",
		"internal/vault", "internal/sync", "internal/secrets", "internal/plugin",
		"internal/systems/core", "internal/systems/dnd5e", "internal/httpapi",
		"internal/web", "internal/sample", "internal/testutil",
	}
	for _, p := range want {
		dir := filepath.Join(root, p)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			t.Errorf("missing package directory %s", p)
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "doc.go")); err != nil {
			t.Errorf("%s has no doc.go: every package states what it owns and what it may import", p)
		}
	}
}

var idLiteralRE = regexp.MustCompile(`ID:\s*"([a-z0-9][a-z0-9-]*)"`)

// TestNoPluginSwitchInCore keeps the plugin architecture honest: no core
// package may branch on a plugin id. Adding a plugin must be one map entry.
func TestNoPluginSwitchInCore(t *testing.T) {
	root := rootOf(t)
	ids := registeredPluginIDs(t, root)
	if len(ids) == 0 {
		t.Skip("no plugins registered yet")
	}
	for _, pkg := range []string{"app", "httpapi", "web", "vault", "store", "md",
		"search", "sync", "authz", "secrets", "auth", "obs", "config"} {
		for _, file := range goFiles(t, filepath.Join(root, "internal", pkg)) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(root, file)
			for _, id := range ids {
				if strings.Contains(string(b), `"`+id+`"`) {
					t.Errorf("%s mentions plugin id %q: a plugin id may appear only in the plugin registry", rel, id)
				}
			}
		}
	}
}

func registeredPluginIDs(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	var ids []string
	for _, base := range []string{"plugins", "systems"} {
		dir := filepath.Join(root, "internal", base)
		for _, file := range goFiles(t, dir) {
			b, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			for _, m := range idLiteralRE.FindAllStringSubmatch(string(b), -1) {
				if !seen[m[1]] {
					seen[m[1]] = true
					ids = append(ids, m[1])
				}
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// TestEveryQueryUsesBindParameters is a cheap, high-value guard against the most
// damaging mistake this codebase could make: interpolating a value into a
// query. Sprintf is the usual vehicle, and a Sprintf that mentions SQL is
// almost always a query.
func TestEveryQueryUsesBindParameters(t *testing.T) {
	root := rootOf(t)
	verbs := regexp.MustCompile(`(?i)\b(select|insert|update|delete|from|where|join|values|pragma)\b`)
	walkGo(t, root, func(rel, line string, num int) {
		if strings.HasSuffix(rel, "architecture_test.go") {
			return
		}
		if !strings.Contains(line, "Sprintf") {
			return
		}
		if verbs.MatchString(line) {
			t.Errorf("%s:%d: query built by Sprintf: %s", rel, num, strings.TrimSpace(line))
		}
	})
}

func walkGo(t *testing.T, root string, fn func(rel, line string, num int)) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", ".tools", "dist", ".kilo", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(b), "\n") {
			fn(filepath.ToSlash(rel), line, i+1)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestNoOutboundNetwork enforces the rule that the request path never talks to
// the network: no telemetry, no analytics, no CDN fetch, no remote font or
// script, no update check. Every asset is embedded and served from
// /_/assets/.
//
// The check is on the *client* symbols rather than the `net/http` import,
// because a server legitimately imports net/http for handlers. A background
// goroutine dialling home would not appear in a rendered page, so the check that
// greps for remote URLs in HTML is not sufficient on its own; this one is.
//
// The plan named this test TestNoOutboundNetwork and it was never written, so a
// hard security rule in AGENTS.md §2 was documented as enforced when nothing
// enforced it. That is the exact failure AGENTS.md's own preamble forbids, and
// this is the remedy.
func TestNoOutboundNetwork(t *testing.T) {
	t.Parallel()
	root := rootOf(t)

	// Client-side capability. Each of these can leave the machine.
	clients := []string{
		"http.Get(", "http.Head(", "http.Post(", "http.PostForm(",
		"http.NewRequest(", "http.NewRequestWithContext(",
		"http.DefaultClient", "http.Client{",
		"net.Dial(", "net.DialTimeout(", "net.DialTCP(",
		"net.LookupHost(", "smtp.SendMail(",
		`"net/smtp"`, `"net/rpc"`, `"net/http/httputil"`,
	}

	walkGo(t, root, func(rel, line string, num int) {
		if strings.HasSuffix(rel, "_test.go") {
			// A test may open a listener, and httptest does. The rule is about
			// the shipped request path.
			return
		}
		if strings.HasPrefix(rel, "tools/") {
			return
		}
		for _, c := range clients {
			if strings.Contains(line, c) {
				t.Errorf("%s:%d: outbound network capability %q: every asset is embedded and served from /_/assets/",
					rel, num, strings.TrimSpace(c))
			}
		}
	})
}

// TestNoProcessExecution enforces the other half of the same rule set: a
// library that shells out is a library that can ignore the authorization it was
// handed. Only the composition root may execute anything.
func TestNoProcessExecution(t *testing.T) {
	t.Parallel()
	root := rootOf(t)

	walkGo(t, root, func(rel, line string, num int) {
		if strings.HasSuffix(rel, "_test.go") {
			return
		}
		if strings.HasPrefix(rel, "internal/app/") {
			return
		}
		for _, bad := range []string{`"os/exec"`, "exec.Command(", "exec.LookPath("} {
			if strings.Contains(line, bad) {
				t.Errorf("%s:%d: %q outside internal/app: only the composition root may run a process",
					rel, num, strings.TrimSpace(bad))
			}
		}
	})
}
