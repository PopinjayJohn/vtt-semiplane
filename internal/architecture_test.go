package internal

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
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

// walkGoRecursive lists every non-test .go file under root, recursively.
//
// walkGo lists one directory, which is right for a Go package and wrong for
// anything else — and getting that wrong is not hypothetical. The plugin-id
// collector used it to find plugin directories, found nothing because a plugin is
// a directory, and the gate it fed skipped silently forever. A helper that
// promises recursion has to actually recurse, so this one is named for it.
func walkGoRecursive(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base != "." && (base == ".git" || base == "dist" || base == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
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

// pluginRoots are the two directories a plugin may live in, repo-relative.
//
// A plugin is a *directory* — internal/systems/dnd5e — so every walk that looks
// for one has to recurse. The first version of registeredPluginIDs called
// goFiles, which does not, and therefore reported zero plugins no matter what
// was on disk: TestNoPluginSwitchInCore would have gone on skipping after the
// first real plugin landed, and a skip is indistinguishable from a rule that
// held. A gate that cannot tell those apart is not a gate.
var pluginRoots = []string{"internal/systems", "internal/plugins"}

// isPluginRoot reports whether a directory name directly under internal/ holds
// plugins. isPluginPkg recognises only the prefixed form, so the two bare
// container names are named here: internal/systems is a plugin root, and a walk
// that forgets that is the bug above.
func isPluginRoot(name string) bool {
	return name == "systems" || name == "plugins" || isPluginPkg(name)
}

// pluginGoFiles collects every non-test .go file under a plugin root, recursing.
func pluginGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, base := range pluginRoots {
		dir := filepath.Join(root, filepath.FromSlash(base))
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			out = append(out, path)
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	sort.Strings(out)
	return out
}

// pluginImplementationFiles is the plugin files that carry code rather than a
// package comment. doc.go files import nothing, so including them would make
// "the boundary was checked" true on an empty tree — the exact vacuity this
// file exists to close.
func pluginImplementationFiles(t *testing.T, root string) []string {
	t.Helper()
	all := pluginGoFiles(t, root)
	var out []string
	for _, f := range all {
		if strings.HasSuffix(f, "doc.go") {
			continue
		}
		out = append(out, f)
	}
	return out
}

// TestPluginImportsAreWithinBoundary re-checks the plugin allow-list with an
// explicit reason per forbidden package, so a failure says which rule broke.
func TestPluginImportsAreWithinBoundary(t *testing.T) {
	t.Parallel()
	root := rootOf(t)
	files := pluginImplementationFiles(t, root)
	if len(files) == 0 {
		t.Skipf("no plugin package has an implementation file under %s, so there is no import to check. "+
			"A non-test .go file in internal/systems/<id>/ (or internal/plugins/<id>/) declaring a plugin.Descriptor "+
			"is what un-skips this. TestTheArchitectureGatesHaveSomethingToCheck fails while it is missing, so a "+
			"green run here cannot be read as a checked boundary.",
			strings.Join(pluginRoots, " or "))
	}
	for _, file := range files {
		rel, _ := filepath.Rel(root, file)
		for _, imp := range parseImports(t, file) {
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

// registryOwner is the one file allowed to name a plugin id, because it holds
// the registry that maps an id to a plugin.
//
// It is cmd/semiplane/registry.go and not internal/plugin, and the reason is a
// cycle rather than a preference: a plugin imports the package that defines its
// interface, so internal/systems/dnd5e imports internal/plugin, and a map naming
// dnd5e.New() there would close the loop. The vocabulary cannot know the
// implementations. `app` is the other candidate and cannot either, because a
// plugin may import `web`, `web` imports `httpapi`, and `httpapi` imports `app`.
//
// The value is a path and not a package name because "which files may name a
// plugin id" is a file-level permission: the rule is one registry, and a
// package-wide exemption would let a second map appear in another file of the
// same package without anything noticing.
const registryOwner = "cmd/semiplane/registry.go"

// pluginIDsIn returns the plugin ids a package's Descriptor literals declare,
// and the id expressions it could not resolve.
//
// The id is the ID field of a plugin.Descriptor, resolved through the package's
// own string constants, because `ID: ID` with `const ID = "dnd5e"` above it is
// ordinary Go and no less a declaration than the inline form. A gate that only
// reads inline literals goes quiet on the tidier of the two spellings, which is
// the same failure as reading nothing at all.
//
// It is scoped to Descriptor on purpose. "Any `ID: \"…\"` in a plugin file" is
// not the same scan: a multi-line `plugin.PageType{{ID: "character"}}` would
// register `character` as a *plugin* id, and then every core file that had ever
// named a page type would be reported as branching on a plugin.
//
// The parser is stdlib and the AST is a tree: no byte cursor to fail to
// advance, which is the shape of both infinite loops this repository shipped.
func pluginIDsIn(srcs map[string]string) (ids, unresolved []string) {
	fset := token.NewFileSet()
	consts := map[string]string{}
	files := make(map[string]*ast.File, len(srcs))
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			unresolved = append(unresolved, fmt.Sprintf("%s does not parse: %v", name, err))
			continue
		}
		files[name] = f
		for k, v := range stringConsts(f.Decls) {
			if _, dup := consts[k]; dup {
				unresolved = append(unresolved, fmt.Sprintf("%s redeclares const %s", name, k))
				continue
			}
			consts[k] = v
		}
	}
	// fset.Position already renders the file name, so the map key is not
	// repeated in the report.
	for _, f := range files {
		for _, lit := range descriptorLiterals(f) {
			expr := descriptorIDField(lit)
			if expr == nil {
				continue
			}
			id, ok := idExpr(expr, consts)
			if !ok {
				unresolved = append(unresolved, fmt.Sprintf(
					"%s: a Descriptor declares an ID this gate cannot resolve statically, so the ban on naming a "+
						"plugin id cannot see this plugin: use a string literal or a package-level string constant",
					fset.Position(expr.Pos())))
				continue
			}
			ids = append(ids, id)
		}
	}
	return dedupeStrings(ids), unresolved
}

// stringConsts returns the file's own package-level string constants, which is
// what turns `ID: ID` into a value rather than an unresolved expression.
func stringConsts(decls []ast.Decl) map[string]string {
	out := map[string]string{}
	for _, d := range decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			// One name to one value only: a grouped `const A, B = "a", "b"`
			// is skipped rather than paired wrongly.
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			if s, ok := literalString(vs.Values[0]); ok {
				out[vs.Names[0].Name] = s
			}
		}
	}
	return out
}

// descriptorLiterals returns every plugin.Descriptor composite literal in f.
func descriptorLiterals(f *ast.File) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && typeName(lit.Type) == "plugin.Descriptor" {
			out = append(out, lit)
		}
		return true
	})
	return out
}

// descriptorIDField returns the value assigned to the ID field of a Descriptor
// literal, or nil if it has none.
func descriptorIDField(lit *ast.CompositeLit) ast.Expr {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ID" {
			return kv.Value
		}
	}
	return nil
}

// idExpr resolves a Descriptor ID field to a string: a literal, or an
// identifier naming one of the package's own string constants. Anything else —
// a concatenation, a function call — is reported as unresolved rather than
// skipped, because a plugin whose id this gate cannot read is a gate that has
// quietly stopped applying to it.
func idExpr(expr ast.Expr, consts map[string]string) (string, bool) {
	if s, ok := literalString(expr); ok {
		return s, true
	}
	if ident, ok := expr.(*ast.Ident); ok {
		s, found := consts[ident.Name]
		return s, found
	}
	return "", false
}

func literalString(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// typeName renders a type expression the way it is written, so
// `map[string]plugin.Plugin` can be recognised by the type it maps to.
func typeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case nil:
		return ""
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		pkg, ok := v.X.(*ast.Ident)
		if !ok {
			return typeName(v.Sel)
		}
		return pkg.Name + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + typeName(v.X)
	case *ast.MapType:
		return "map[" + typeName(v.Key) + "]" + typeName(v.Value)
	case *ast.ArrayType:
		return "[]" + typeName(v.Elt)
	}
	return ""
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// pluginPackageDirs is every directory under a plugin root that is itself a
// package — that is, every directory that holds at least one non-test .go file.
// The container directories are not packages, and a plugin may split itself
// across subdirectories, so the unit is the directory that holds Go files
// rather than the plugin root.
func pluginPackageDirs(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, file := range pluginGoFiles(t, root) {
		dir := filepath.Dir(file)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// registeredPluginIDs returns every plugin id declared under a plugin root, so
// the ban in TestNoPluginSwitchInCore knows what to look for.
//
// A package whose Descriptor names its id in a way this cannot read is an
// error, not an absence. Returning a short id list for a package that is really
// there would leave the ban silently inapplicable to it — the exact failure
// this whole file is about — so it is reported instead.
func registeredPluginIDs(t *testing.T, root string) []string {
	t.Helper()
	var ids []string
	for _, dir := range pluginPackageDirs(t, root) {
		srcs := map[string]string{}
		// goFiles is not recursive, which is right here: a Go package is one
		// directory, and a plugin that splits itself across subdirectories has
		// one id per subpackage.
		for _, file := range goFiles(t, dir) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			srcs[filepath.Base(file)] = string(b)
		}
		rel, _ := filepath.Rel(root, dir)
		pkgIDs, unresolved := pluginIDsIn(srcs)
		for _, u := range unresolved {
			t.Errorf("%s: %s", filepath.ToSlash(rel), u)
		}
		ids = append(ids, pkgIDs...)
	}
	return dedupeStrings(ids)
}

// corePackagesScanned is every package the ban on naming a plugin id applies
// to: the dependency order, plus the exempt packages, plus cmd/semiplane.
//
// It is derived rather than written out. A hand-written list is a rule that
// quietly narrows the day a core package is added and nobody remembers to add
// it here, and a narrowed rule is indistinguishable from a rule that held.
//
// cmd/semiplane is in the set because that is where the registry lives (see
// registryOwner) and it is the *only* place a plugin id may appear — so the set
// has to include it for the ban to mean anything, and the registry file is
// exempted separately. Scanning the package that holds the registry and then
// exempting one file in it is deliberate: it means a second registry, or a
// dispatch anywhere else in main, is caught.
//
// internal/plugin is scanned too. It holds the vocabulary rather than the
// registry, so there is no reason to spare it, and sparing it would have left a
// hole exactly where the interface a plugin implements is defined.
func corePackagesScanned() []string {
	out := make([]string, 0, len(order)+len(exempt)+1)
	out = append(out, order...)
	for p := range exempt {
		out = append(out, p)
	}
	out = append(out, "semiplane")
	sort.Strings(out)
	return out
}

// coreGoFiles is every non-test .go file of every scanned core package,
// recursing: a subdirectory of a core package is still core.
func coreGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, pkg := range corePackagesScanned() {
		dir := filepath.Join(root, "internal", pkg)
		if pkg == "semiplane" {
			// cmd/semiplane is the one scanned package outside internal/, and it
			// is where the registry lives. Resolving it by the same internal/
			// prefix would silently find nothing, and a scan that finds nothing
			// over the package that holds the registry is the exact failure this
			// test exists to prevent.
			dir = filepath.Join(root, "cmd", "semiplane")
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			out = append(out, path)
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", pkg, err)
		}
	}
	sort.Strings(out)
	return out
}

// pluginIDMention is one core file dispatching on one plugin id.
type pluginIDMention struct {
	file string
	line int
	id   string
}

// findPluginIDMentions reports every place in files that dispatches on a plugin
// id.
//
// **The decision, and the reason it is not a substring match.** A plugin id
// reaching Go is a string, so the first version of this scan looked for the
// quoted literal and it was wrong on the first real plugin: internal/md/callout.go
// has `"example": true` in a table of callout *kinds*, and the scan reported
// that file as branching on the plugin `example`. It is not, and a gate that
// reports a lie is worse than one that stays quiet, because the habit it
// teaches is to ignore it.
//
// A bare occurrence of the word proves nothing, then. `internal/md/callout.go`
// is the proof. So the scan is not over *occurrences* but over *dispatch sites* —
// the four places a core package can actually give one plugin different
// behaviour from another:
//
//	kind == "dnd5e"      a comparison
//	case "dnd5e":        a switch arm
//	byID["dnd5e"]        an index
//	map[string]plugin.Plugin{"dnd5e": p}   a second registry
//
// The fourth is included because it is the registry's own type: a map of ids to
// plugins anywhere but internal/plugin is a copy of the registry, which is
// precisely the "one map entry, no core changes" rule being enforced.
//
// The three this does *not* catch are deliberate, and each is a case where the
// word is not a switch: a bare identifier (`dnd5e.New()` — a package selector,
// which cannot branch), a plain map or slice keyed by a coincidentally equal
// word (the callout table), and a mention in prose. A core file that has to
// write a plugin's id down is a core file coupled to that plugin, but nothing
// branches on a comment, and a rule that reads comments invents failures.
//
// It is a function rather than an inline loop so that
// TestNoPluginSwitchGateFires can run the identical scan over a synthetic file:
// a grep gate that has never been observed to fire is a gate nobody knows works.
func findPluginIDMentions(t *testing.T, root string, files, ids []string) []pluginIDMention {
	t.Helper()
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	var out []pluginIDMention
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		rel, _ := filepath.Rel(root, file)
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Base(file), b, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s does not parse, so the ban on naming a plugin id cannot be applied to it: %v", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			for _, expr := range dispatchOperands(n) {
				s, ok := literalString(expr)
				if !ok || !known[s] {
					continue
				}
				out = append(out, pluginIDMention{file: rel, line: fset.Position(expr.Pos()).Line, id: s})
			}
			return true
		})
	}
	return out
}

// dispatchOperands returns the expressions at node that a value is compared
// against, keyed on, or looked up by.
func dispatchOperands(node ast.Node) []ast.Expr {
	switch v := node.(type) {
	case *ast.BinaryExpr:
		if v.Op == token.EQL || v.Op == token.NEQ {
			return []ast.Expr{v.X, v.Y}
		}
	case *ast.SwitchStmt:
		// A switch on a value is a chain of comparisons, and the tag is the
		// value; a switch on a type is a type switch and its cases are types.
		if v.Tag != nil {
			return []ast.Expr{v.Tag}
		}
	case *ast.CaseClause:
		return v.List
	case *ast.IndexExpr:
		return []ast.Expr{v.Index}
	case *ast.CompositeLit:
		m, ok := v.Type.(*ast.MapType)
		if !ok || m == nil || typeName(m.Value) != "plugin.Plugin" {
			return nil
		}
		var out []ast.Expr
		for _, elt := range v.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				out = append(out, kv.Key)
			}
		}
		return out
	}
	return nil
}

// TestNoPluginSwitchInCore keeps the plugin architecture honest: no core
// package may branch on a plugin id. Adding a plugin must be one map entry.
func TestNoPluginSwitchInCore(t *testing.T) {
	t.Parallel()
	root := rootOf(t)
	ids := registeredPluginIDs(t, root)
	if len(ids) == 0 {
		t.Skipf("no plugin id is declared under %s, so there is nothing to scan for. "+
			"A non-test .go file in internal/systems/<id>/ declaring a plugin.Descriptor is what un-skips this. "+
			"TestTheArchitectureGatesHaveSomethingToCheck fails while it is missing, so a green run here cannot be "+
			"read as a checked ban.",
			strings.Join(pluginRoots, " or "))
	}
	for _, m := range findPluginIDMentions(t, root, coreGoFiles(t, root), ids) {
		if m.file == registryOwner {
			// The registry itself. Exempting one named file rather than a package
			// is the point: a package-wide exemption would let a second map
			// appear in a sibling file without anything noticing.
			continue
		}
		t.Errorf("%s:%d names plugin id %q: a plugin id may appear only in %s, so that adding a plugin is one map entry there",
			m.file, m.line, m.id, registryOwner)
	}
	assertTheRegistryIsThere(t, root, ids)
}

// assertTheRegistryIsThere checks the thing the exemption above depends on: that
// the one file allowed to name a plugin id really is the registry, and really
// does name every registered plugin.
//
// Without it the exemption is a hole with a comment on it. A file could be
// exempted and then used for anything, and a plugin could ship without ever
// being added to the registry — which is not an error in any test, and is
// exactly how a system plugin ends up in the tree and not in the app.
func assertTheRegistryIsThere(t *testing.T, root string, ids []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(registryOwner)))
	if err != nil {
		t.Errorf("the registry is exempt from the ban on naming a plugin id, but %s does not exist: %v", registryOwner, err)
		return
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, registryOwner, b, parser.SkipObjectResolution)
	if err != nil {
		t.Errorf("%s does not parse, so the exemption cannot be justified: %v", registryOwner, err)
		return
	}
	declared := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || typeName(lit.Type) != "map[string]plugin.Plugin" {
			return true
		}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if s, ok := literalString(kv.Key); ok {
					declared[s]++
				}
			}
		}
		return true
	})
	if len(declared) == 0 {
		t.Errorf("%s holds no map[string]plugin.Plugin literal, so it is not the registry and its exemption is unjustified", registryOwner)
	}
	for _, id := range ids {
		switch declared[id] {
		case 0:
			// example is the exception, and for a stated reason: it is a plugin
			// built to be refused, and offering it to every boot would put a known
			// failure in the boot report of a running campaign. It exercises
			// plugin.Load from its own package instead.
			if id == "example" {
				continue
			}
			t.Errorf("the plugin %q is registered under %s but absent from the registry in %s: it would ship in the tree and never run",
				id, pluginRoots, registryOwner)
		case 1:
		default:
			t.Errorf("%s names %q %d times: the registry maps an id to one plugin", registryOwner, id, declared[id])
		}
	}
}

// TestNoPluginSwitchGateFires is the self-test for the ban above: the same scan,
// over synthetic files, asserting that it flags every dispatch site and leaves
// alone everything that merely shares a word. The negative cases are the
// load-bearing half — a gate that flags everything passes the positive ones, and
// the first real plugin found that out.
//
// The files live in t.TempDir(). A test that writes into the repository fails
// CI on purpose, after every job: git status --porcelain must be empty.
func TestNoPluginSwitchGateFires(t *testing.T) {
	t.Parallel()
	const id = "dnd5e"

	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"an equality comparison", `func f(kind string) bool { return kind == "dnd5e" }`, true},
		{"an inequality comparison", `func f(kind string) bool { return kind != "dnd5e" }`, true},
		{"a switch arm", "func f(k string) int {\n\tswitch k {\n\tcase \"dnd5e\":\n\t\treturn 1\n\t}\n\treturn 0\n}", true},
		{"an index expression", `func f(m map[string]int) int { return m["dnd5e"] }`, true},
		{"a second registry", `var r = map[string]plugin.Plugin{"dnd5e": dnd5e.New()}`, true},
		{"a bare package identifier", `func f() *dnd5e.Plugin { return dnd5e.New() }`, false},
		{"the plugin route prefix", `func f(mux *chi.Mux) { mux.Handle("/plugin/dnd5e/summary", h) }`, false},
		{"a different plugin id", `func f() int { switch k { case "dnd5e-rules": return 1 } }`, false},
		// The real case, copied from internal/md/callout.go, where "example" is
		// a callout kind. A quoted-literal scan reports that file as branching
		// on the plugin `example`, which is why this one exists.
		{"a data table keyed by a coincidental word", `var kinds = map[string]bool{"bug": true, "example": true}`, false},
		{"a mention in prose", `// the dnd5e system plugin owns character sheets`, false},
		{"no mention at all", `func f() error { return nil }`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "core.go")
			if err := os.WriteFile(path, []byte("package core\n\n"+tc.src+"\n"), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			got := findPluginIDMentions(t, dir, []string{path}, []string{id})
			if flagged := len(got) > 0; flagged != tc.want {
				t.Errorf("scan flagged %v, want flagged=%v (%s)", got, tc.want, tc.src)
			}
		})
	}

	// The vacuous case, stated rather than assumed: with no ids the scan
	// reports nothing at all, and reports it as a pass. This is why
	// TestTheArchitectureGatesHaveSomethingToCheck exists.
	t.Run("no ids to look for", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "core.go")
		src := "package core\n\nfunc f(kind string) bool { return kind == \"dnd5e\" }\n"
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if got := findPluginIDMentions(t, dir, []string{path}, nil); len(got) != 0 {
			t.Errorf("an empty id set flagged %v, so a test using it as evidence would pass vacuously", got)
		}
	})
}

// TestRegisteredPluginIDsReadsOnlyDescriptors guards the id extraction the ban
// depends on. Scoping it to Descriptor is what keeps a plugin's page types from
// being registered as plugin ids, and resolving `ID: ID` through the package's
// own constants is what keeps a plugin that names its id once, tidily, from
// going unregistered. A wrong id set makes the ban either useless or unbearable,
// and neither failure is visible from the test that would have caught it.
func TestRegisteredPluginIDsReadsOnlyDescriptors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		srcs map[string]string
		want []string
	}{
		{
			"a gofmt multi-line descriptor",
			map[string]string{"plugin.go": "package p\n\nfunc f() plugin.Descriptor {\n\treturn plugin.Descriptor{\n" +
				"\t\tID:           \"dnd5e\",\n\t\tKind: plugin.KindSystem,\n\t}\n}"},
			[]string{"dnd5e"},
		},
		{
			"a descriptor whose id is a package const",
			map[string]string{"plugin.go": "package p\n\nconst ID = \"dnd5e\"\n\nfunc f() plugin.Descriptor {\n" +
				"\treturn plugin.Descriptor{ID: ID, Kind: plugin.KindSystem}\n}"},
			[]string{"dnd5e"},
		},
		{
			"a descriptor with page types",
			map[string]string{"plugin.go": "package p\n\nfunc f() plugin.Descriptor {\n\treturn plugin.Descriptor{\n" +
				"\t\tID: \"dnd5e\",\n\t\tPageTypes: []plugin.PageType{{\n\t\t\tID:   \"character\",\n\t\t}}," +
				"\t}\n}"},
			[]string{"dnd5e"},
		},
		{
			"a page type outside a descriptor",
			map[string]string{"plugin.go": "package p\n\nfunc f() plugin.PageType {\n\treturn plugin.PageType{\n" +
				"\t\tID: \"character\",\n\t}\n}"},
			nil,
		},
		{
			"a page type id in a const from a sibling file",
			map[string]string{"consts.go": "package p\n\nconst reservedPageType = \"character\"\n",
				"plugin.go": "package p\n\nfunc f() plugin.Descriptor {\n\treturn plugin.Descriptor{\n" +
					"\t\tID: \"dnd5e\",\n\t\tPageTypes: []plugin.PageType{{ID: reservedPageType}},\n\t}\n}"},
			[]string{"dnd5e"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, unresolved := pluginIDsIn(tc.srcs)
			if len(unresolved) != 0 {
				t.Errorf("unresolved id expressions: %v", unresolved)
			}
			if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
				t.Errorf("pluginIDsIn = %v, want %v", got, tc.want)
			}
		})
	}

	// An id this gate cannot read is reported, not skipped. Silently returning
	// nothing for a plugin that is really there would leave the ban
	// inapplicable to it, which is the failure this file exists to prevent.
	t.Run("an unresolvable id is reported rather than dropped", func(t *testing.T) {
		t.Parallel()
		srcs := map[string]string{"plugin.go": "package p\n\nfunc f() plugin.Descriptor {\n" +
			"\treturn plugin.Descriptor{ID: strings.ToLower(\"DND5E\")}\n}"}
		got, unresolved := pluginIDsIn(srcs)
		if len(got) != 0 {
			t.Errorf("pluginIDsIn = %v, want none", got)
		}
		if len(unresolved) != 1 {
			t.Errorf("unresolved = %v, want exactly one report naming the file and line", unresolved)
		}
	})
}

// TestTheArchitectureGatesHaveSomethingToCheck is the guard against the two
// gates above going vacuous again.
//
// They skip when the tree holds no plugin, which is honest but indistinguishable
// from a rule that held: a green run proves nothing until a plugin exists. So
// the check that the tree has a plugin is itself a test, and it fails rather
// than skips while it is false. A guard that skips is the thing it was written
// to prevent.
//
// The failure names what is missing, because deleting a plugin deletes the
// evidence these gates run on — and the deletion that breaks a build is
// indistinguishable from one that is merely tidy until the message says which.
func TestTheArchitectureGatesHaveSomethingToCheck(t *testing.T) {
	t.Parallel()
	root := rootOf(t)

	if ids := registeredPluginIDs(t, root); len(ids) == 0 {
		t.Errorf("no plugin id is declared: the scan in TestNoPluginSwitchInCore has nothing to look for and skips. "+
			"It is waiting for a non-test .go file under %s that declares a plugin.Descriptor — internal/systems/dnd5e "+
			"and internal/systems/example are the two that are meant to. If you removed a plugin, this is what tells "+
			"you the gate lost its evidence, not merely that the gate is quiet.",
			strings.Join(pluginRoots, " or "))
	}

	if files := pluginImplementationFiles(t, root); len(files) == 0 {
		t.Errorf("no plugin package has an implementation file: the import walk in TestPluginImportsAreWithinBoundary "+
			"has no import to check and skips. It is waiting for a non-test .go file beyond doc.go under %s — "+
			"internal/systems/dnd5e and internal/systems/example are the two that are meant to. A doc.go imports "+
			"nothing, so a tree of doc.go files is a boundary that has never been enforced.",
			strings.Join(pluginRoots, " or "))
	}
}

// TestNoPluginSwitchScansEveryCorePackage keeps the ban total over the packages
// it applies to.
//
// corePackagesScanned is derived from `order` and `exempt`, and a derived set is
// only trustworthy while something checks the derivation: a new core package in
// neither list would sit outside the ban, silently, and the ban would look like
// it had held.
func TestNoPluginSwitchScansEveryCorePackage(t *testing.T) {
	t.Parallel()
	root := rootOf(t)
	scanned := map[string]bool{}
	for _, p := range corePackagesScanned() {
		scanned[p] = true
	}
	entries, err := os.ReadDir(filepath.Join(root, "internal"))
	if err != nil {
		t.Fatalf("read internal: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == filepath.Base(registryOwner), name == "semiplane", scanned[name], isPluginRoot(name):
		default:
			t.Errorf("internal/%s is in neither the dependency order nor the exempt list, so no architecture test "+
				"covers it and the ban on naming a plugin id does not reach it: add it to `order` or to `exempt`", name)
		}
	}
}

// withoutCapability returns every known capability except need.
//
// plugin.Capabilities has no Without method, and this file does not add one: a
// file another workstream owns is not this one's to extend. Building the set by
// omission over the exported AllCapabilities is exactly what With does, so the
// capability under test is genuinely absent rather than unset by accident.
func withoutCapability(need plugin.Capability) plugin.Capabilities {
	var s plugin.Capabilities
	for _, c := range plugin.AllCapabilities {
		if c != need {
			s = s.With(c)
		}
	}
	return s
}

// TestEveryReservedNameIsClaimableOnlyWithItsCapability is the reserved-name
// rule stated as a matrix over both tables in internal/plugin/reserved.go.
//
// The rule is the table's own; what this adds is that every row of the table is
// subject to it, and that the two halves of the rule — the kind and the
// capability — are separately load-bearing. A table entry that is never
// claimable is a name the host is holding for nobody.
func TestEveryReservedNameIsClaimableOnlyWithItsCapability(t *testing.T) {
	t.Parallel()

	types := plugin.ReservedPageTypes()
	if len(types) == 0 {
		t.Fatal("the reserved page-type table is empty: remove the table rather than leaving it dormant")
	}
	routes := plugin.ReservedRoutes()
	if len(routes) == 0 {
		t.Fatal("the reserved route table is empty: remove the table rather than leaving it dormant")
	}

	for _, r := range types {
		t.Run("page type "+r.ID, func(t *testing.T) {
			t.Parallel()
			checkReservedClaim(t, r.ID, r.Capability)
		})
	}
	for _, r := range routes {
		t.Run("route segment "+r.Segment, func(t *testing.T) {
			t.Parallel()
			checkReservedClaim(t, r.Segment, r.Capability)
		})
	}
}

// checkReservedClaim holds one reserved name to the rule: claimable by a
// KindSystem holding the matching capability, and by nothing else.
func checkReservedClaim(t *testing.T, name string, need plugin.Capability) {
	t.Helper()
	if !plugin.All().Has(need) {
		t.Errorf("%s is reserved for %q, which is not one of AllCapabilities: the grant can never be held",
			name, need)
	}
	if !plugin.Claimable(plugin.KindSystem, plugin.All(), need) {
		t.Errorf("%s: a KindSystem holding every capability cannot claim a name reserved for %q, so the reservation is unreachable",
			name, need)
	}
	if plugin.Claimable(plugin.KindFeature, plugin.All(), need) {
		t.Errorf("%s: a KindFeature claims it even holding %q. A capability says what a plugin may do; a kind says "+
			"what vocabulary it may speak, and only a %s speaks a game system's", name, need, plugin.KindSystem)
	}
	if plugin.Claimable(plugin.KindSystem, withoutCapability(need), need) {
		t.Errorf("%s: a KindSystem without %q claims it, so holding the capability is not the grant", name, need)
	}
}

// TestTheReservedTablesHaveNoDuplicates exists because a duplicate is a table
// where the second row silently wins: ReservedPageTypeFor and RouteReservation
// both return the first match, so the second row's capability is unreachable
// and the name is refused from a system that is entitled to it.
func TestTheReservedTablesHaveNoDuplicates(t *testing.T) {
	t.Parallel()

	t.Run("page types", func(t *testing.T) {
		t.Parallel()
		seen := map[string]plugin.Capability{}
		for _, r := range plugin.ReservedPageTypes() {
			if r.ID == "" {
				t.Errorf("a reserved page type has an empty id, and it would match every lookup")
			}
			if prev, dup := seen[r.ID]; dup {
				t.Errorf("page type %q is reserved twice, for %q and %q: the first row wins every lookup, so the "+
					"second capability can never claim it", r.ID, prev, r.Capability)
			}
			seen[r.ID] = r.Capability
		}
	})

	t.Run("route segments", func(t *testing.T) {
		t.Parallel()
		seen := map[string]plugin.Capability{}
		for _, r := range plugin.ReservedRoutes() {
			if r.Segment == "" {
				t.Errorf("a reserved route has an empty segment, and it would match every route")
			}
			if prev, dup := seen[r.Segment]; dup {
				t.Errorf("route segment %q is reserved twice, for %q and %q: the first row wins every lookup, so the "+
					"second capability can never claim it", r.Segment, prev, r.Capability)
			}
			seen[r.Segment] = r.Capability
		}
	})
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
// clients is every capability that can leave the machine.
//
// It is package level because three tests need it and one list is the point: a
// capability the gate checks but the guard does not know about is a capability
// the guard cannot hold a file to. Entries are `pkg.Sel(` or a quoted import
// path, and are matched against the syntax tree rather than against bytes — see
// TestNoOutboundNetwork for why.
var clients = []string{
	"http.Get(", "http.Head(", "http.Post(", "http.PostForm(",
	"http.NewRequest(", "http.NewRequestWithContext(",
	"http.DefaultClient", "http.Client{",
	"net.Dial(", "net.DialTimeout(", "net.DialTCP(",
	"net.LookupHost(", "smtp.SendMail(",
	`"net/smtp"`, `"net/rpc"`, `"net/http/httputil"`,
}

func TestNoOutboundNetwork(t *testing.T) {
	t.Parallel()
	root := rootOf(t)

	// The scan is over the syntax tree, not over the bytes.
	//
	// It was a `strings.Contains` over each line, which is the obvious
	// implementation and the wrong one twice over. It produced false positives
	// from prose: a plugin whose doc comment explains *why* it must not reach the
	// network cannot then say the words, so the rule and its explanation were
	// mutually exclusive and the only way past the failure was to delete the
	// explanation. And it could not see a real one either — `http
	// .Get(` across a line break is a call, and a line grep is not a parser.
	//
	// Matching `pkg.Sel` in the AST is strictly tighter than the byte grep on
	// both counts: comments and string literals are not expressions, so prose
	// cannot trip it, and a call split across lines still is one selector.
	//
	// The list is now expressed as package + selector, which is also what makes
	// the import half below expressible — a bare `"net/smtp"` string is a
	// comment just as easily as it is an import.
	scanTree(t, root, func(rel string, uses []capabilityUse) {
		if strings.HasSuffix(rel, "_test.go") {
			// A test may open a listener, and httptest does. The rule is about
			// the shipped request path.
			return
		}
		if strings.HasPrefix(rel, "tools/") {
			return
		}
		for _, u := range uses {
			// The carve-out is decided per file, not per use: what makes a
			// request safe is that the file never sends it, and that is a
			// property of the whole file. TestSyntheticRequestFilesAreStillOnlySynthetic
			// is what actually holds the file to it, once, instead of every line
			// of it.
			if _, ok := syntheticRequestFiles[rel]; ok && isRequestConstructor(u.Text) {
				continue
			}
			t.Errorf("%s:%d: outbound network capability %q: every asset is embedded and served from /_/assets/",
				rel, u.Line, u.Text)
		}
	})
}

// capabilityUse is one matched capability reference, with the position needed to
// report it.
type capabilityUse struct {
	// Text is the canonical form, e.g. "http.Get(" — the string the table holds,
	// not whatever the source happened to write.
	Text string
	// Line is the 1-indexed line of the reference.
	Line int
}

// scanTree walks every non-test Go file under root and hands the callback each
// file's matched capability uses, with their positions.
//
// It parses rather than greps, and a file that does not parse is a build
// failure elsewhere, so a parse error here is reported rather than swallowed: a
// gate that skips unreadable input is a gate with a hole shaped like a syntax
// error.
func scanTree(t *testing.T, root string, fn func(rel string, uses []capabilityUse)) {
	t.Helper()
	all := map[string][]string{}
	for _, p := range clients {
		all[pkgOf(p)] = append(all[pkgOf(p)], p)
	}
	for _, file := range walkGoRecursive(t, root) {
		rel, _ := filepath.Rel(root, file)
		if strings.HasPrefix(rel, "tools"+string(filepath.Separator)) {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			// A file that does not parse is reported by the compiler. Failing here
			// as well would double every typo, so the file is skipped and the
			// reason is not hidden: a gate that cannot read its input must say so.
			continue
		}
		var uses []capabilityUse
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, p := range all[ident.Name] {
				if selName(p) != sel.Sel.Name {
					continue
				}
				pos := fset.Position(sel.Pos())
				uses = append(uses, capabilityUse{Text: p, Line: pos.Line})
			}
			return true
		})
		sort.Slice(uses, func(i, j int) bool { return uses[i].Line < uses[j].Line })
		fn(filepath.ToSlash(rel), uses)
	}
}

// pkgOf is the package part of a capability string: "http.Get(" is "http",
// `net/http/httputil` is "net/http/httputil".
func pkgOf(c string) string {
	c = strings.Trim(c, `"`)
	if i := strings.IndexByte(c, '.'); i >= 0 {
		return c[:i]
	}
	return c
}

// selName is the selector part: "http.Get(" is "Get", `net/http/httputil` is
// "" because an import path has no selector and is matched on the package alone.
func selName(c string) string {
	c = strings.Trim(c, `"`)
	if i := strings.IndexByte(c, '.'); i >= 0 {
		return c[i+1 : len(c)-1]
	}
	return ""
}

// TestSyntheticRequestFilesAreStillOnlySynthetic holds the carve-out in
// TestNoOutboundNetwork to the two claims that justify it, so that the exemption
// cannot quietly become a loophole.
//
// The main test has to be line-based, because it walks line by line, and a
// per-line rule on a request constructor would be checking the wrong thing: a
// constructor call and the host it targets are usually three lines apart. So the
// exemption is granted per file and this test is what keeps it honest, by
// asserting that each exempt file still contains the reserved host and still
// contains no client symbol whatsoever.
func TestSyntheticRequestFilesAreStillOnlySynthetic(t *testing.T) {
	t.Parallel()
	root := rootOf(t)
	if len(syntheticRequestFiles) == 0 {
		t.Fatal("the carve-out table is empty: remove the machinery rather than leaving it dormant")
	}
	for rel, construct := range syntheticRequestFiles {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s is exempt from TestNoOutboundNetwork but does not exist: %v", rel, err)
			continue
		}
		src := string(b)
		if !strings.Contains(src, construct.host) {
			t.Errorf("%s is exempt from TestNoOutboundNetwork but never names %q: the request it builds must target a host that cannot resolve",
				rel, construct.host)
		}
		for _, c := range clientsExceptConstructors {
			if strings.Contains(src, c) {
				t.Errorf("%s is exempt from TestNoOutboundNetwork and contains %q: a file that may build a request may not be able to send one",
					rel, c)
			}
		}
	}
}

// requestConstructors are the two symbols that build an http.Request without
// sending it. They are capability-free on their own — the capability is the
// client that follows — and they are the one entry on the clients list a file may
// be exempted from, under the conditions TestSyntheticRequestFilesAreStillOnlySynthetic
// checks.
var requestConstructors = []string{"http.NewRequest(", "http.NewRequestWithContext("}

func isRequestConstructor(c string) bool {
	for _, r := range requestConstructors {
		if c == r {
			return true
		}
	}
	return false
}

// clientsExceptConstructors is the clients list without the request
// constructors, which is what an exempt file is held to.
var clientsExceptConstructors = func() []string {
	var out []string
	for _, c := range clients {
		if !isRequestConstructor(c) {
			out = append(out, c)
		}
	}
	return out
}()

// syntheticRequestFiles are the files allowed to *build* an http.Request without
// sending it, and the host every such request must be built against.
//
// This is the one carve-out in TestNoOutboundNetwork and it is narrow on purpose.
// The live-push path is required to deliver a subscriber's re-render by calling
// the ordinary handler with a synthetic request carrying that subscriber's
// captured principal, which is what makes the push and fetch paths literally the
// same function — the property §4.5 calls the single most important thing about
// the design. That needs a request object, and a request object is what
// http.NewRequestWithContext returns.
//
// What makes it safe is not the file name and not a comment here. It is that the
// request is never handed to a client: .invalid is the reserved TLD from RFC 2606
// and resolves nowhere, and every other symbol on the clients list — http.Client,
// http.Get, net.Dial — is still refused in this file exactly as everywhere else.
// So a reader who wants to check the claim can grep this file for a client
// symbol, and the check this test performs above refuses a request built against
// any other host.
//
// A second file needing this would be a second reason to re-examine whether the
// push path should be reaching for the handler at all.
var syntheticRequestFiles = map[string]struct{ host string }{
	"internal/httpapi/events.go": {host: "push.invalid"},
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
