package httpapi_test

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// This file holds the stage-2 shell's tests: the tag surfaces, the file tree,
// the campaign status panel, the page-context API and the command palette.
//
// The assertions here are deliberately not written against a view model's field
// names. A test that reads a field is a test that breaks when the field is
// renamed and passes when the field is rendered with the wrong value; what is
// asserted instead is the property each surface exists for — a tag the reader
// may not see is absent, a panel's number agrees with its own list, a page's
// context is the same in the HTML and in the JSON, and a refusal is
// byte-identical to the refusal for something that was never there.

// visibleText is a rendered body with every element removed.
//
// The markup around a value belongs to the view layer and is allowed to change;
// what is not allowed to change is the value. Reading the text alone is what
// makes a count assertion survive a restyle, and it also keeps a lookup from
// tripping over a digit inside a class name, an element id or a URL — all of
// which contain numbers the page is not claiming.
func visibleText(body string) string {
	return html.UnescapeString(markupTag.ReplaceAllString(body, " "))
}

var markupTag = regexp.MustCompile(`(?s)<!--.*?-->|</?[a-zA-Z][^>]*>`)

// countAfter reads the number a value is followed by.
//
// The window is small and the run must start at it, because the number this
// reads is a badge sitting immediately after its label. A window that searched
// further would find the next unrelated number on the page and pass a wrong
// count for a right one.
var countAfter = regexp.MustCompile(`[^0-9A-Za-z]{0,12}([0-9]{1,6})`)

// numberAfter returns the count rendered immediately after label.
//
// It assumes the shape the tag cloud and the backlink panel already have: the
// label, then the number. A panel that reversed the two would fail this with a
// message saying so, which is the right outcome — it would mean the two halves
// of a panel had stopped reading in the order a reader reads them.
func numberAfter(t *testing.T, body, label string) int {
	t.Helper()
	text := visibleText(body)
	i := strings.Index(text, label)
	if i < 0 {
		t.Fatalf("the page does not render %q:\n%s", label, snippet(visibleText(body)))
	}
	m := countAfter.FindStringSubmatch(text[i+len(label):])
	if m == nil {
		t.Fatalf("nothing that looks like a count follows %q:\n%s", label, snippet(text[i:]))
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n
}

// tagCountIn is numberAfter for a tag's row, which is rendered as the name and
// then the number of pages carrying it.
//
// The leading '#' is tried first and the bare name second, so a template that
// writes the name on its own is not a failure; a name that is a prefix of
// another tag's would be, which is why no fixture uses one.
func tagCountIn(t *testing.T, body, name string) int {
	t.Helper()
	text := visibleText(body)
	for _, needle := range []string{"#" + name, name} {
		if i := strings.Index(text, needle); i >= 0 {
			m := countAfter.FindStringSubmatch(text[i+len(needle):])
			if m == nil {
				t.Fatalf("the row for %q shows no count:\n%s", name, snippet(text[i:]))
			}
			n := 0
			for _, c := range m[1] {
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	t.Fatalf("the page does not show the tag %q:\n%s", name, snippet(text))
	return 0
}

// pageLink matches an href to a page, which is the only thing the file tree and
// a tag list have in common and the only thing this file counts.
var pageLink = regexp.MustCompile(`href="/p/([^"#?]+)"`)

// pageLinksIn returns the pages a body links to, in the order it links to them
// and with duplicates, because the duplicates are the finding.
func pageLinksIn(body string) []string {
	var out []string
	for _, m := range pageLink.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// The JSON shapes, re-declared here on purpose.
//
// A test that unmarshalled into the handler's own type would be asserting that
// a struct is still itself. These are the wire contract — the field names a
// client depends on — and the point of the projection in the handler is that
// this is the whole of it.
type jsonRefBody struct {
	Href  string `json:"href"`
	Title string `json:"title"`
	Path  string `json:"path"`
}

type jsonTocBody struct {
	Level int    `json:"level"`
	Text  string `json:"text"`
	Slug  string `json:"slug"`
	Href  string `json:"href"`
}

type jsonBacklinkBody struct {
	Href  string `json:"href"`
	Title string `json:"title"`
	Path  string `json:"path"`
	Line  int    `json:"line"`
}

type jsonSessionBody struct {
	Href   string `json:"href"`
	Title  string `json:"title"`
	Path   string `json:"path"`
	Number int    `json:"number"`
	Date   string `json:"date"`
}

type jsonPartyBody struct {
	Href  string `json:"href"`
	Title string `json:"title"`
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Note  string `json:"note"`
}

type jsonStatusBody struct {
	Session      *jsonSessionBody `json:"session"`
	Threads      []jsonRefBody    `json:"threads"`
	ThreadCount  int              `json:"thread_count"`
	LastActivity []jsonRefBody    `json:"last_activity"`
	Party        []jsonPartyBody  `json:"party"`
	SystemNote   string           `json:"system_note"`
}

type jsonContextBody struct {
	Href          string             `json:"href"`
	Title         string             `json:"title"`
	Path          string             `json:"path"`
	Toc           []jsonTocBody      `json:"toc"`
	Backlinks     []jsonBacklinkBody `json:"backlinks"`
	BacklinkCount int                `json:"backlink_count"`
	Related       []jsonRefBody      `json:"related"`
	Status        jsonStatusBody     `json:"status"`
}

type jsonCommandBody struct {
	Label string `json:"label"`
	Href  string `json:"href"`
	Kind  string `json:"kind"`
	Hint  string `json:"hint"`
}

type jsonCommandsBody struct {
	Query    string            `json:"query"`
	Commands []jsonCommandBody `json:"commands"`
}

// contextFor fetches and decodes a page's context.
func contextFor(t *testing.T, s *session, id int64) jsonContextBody {
	t.Helper()
	var out jsonContextBody
	decodeJSON(t, s.getOK("/api/pages/"+strconv.FormatInt(id, 10)+"/context"), &out)
	return out
}

// pageRowsOf is the palette's page rows' hrefs.
func pageRowsOf(got jsonCommandsBody) []string {
	var out []string
	for _, c := range got.Commands {
		if c.Kind == httpapi.CommandPage {
			out = append(out, c.Href)
		}
	}
	return out
}

func decodeJSON(t *testing.T, body string, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), into); err != nil {
		t.Fatalf("the response is not the JSON the contract describes: %v\n%s", err, snippet(body))
	}
}

// pageID is a page's index id, read through the store rather than scraped out
// of a rendered page, so that a test about ids does not depend on the markup.
func pageID(t *testing.T, fx *fixture, path string) int64 {
	t.Helper()
	row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), path)
	if err != nil {
		t.Fatalf("look up %s: %v", path, err)
	}
	return row.ID
}

// noSystemNote is the panel's statement that no game system is registered. It
// is written out here rather than reached for, because a test that shared the
// handler's constant could not tell a missing plugin from a missing constant.
const noSystemNote = "No game system is registered for this campaign."

// TestTagsPageListsEveryVisibleTag covers the tag cloud as a reader who may see
// most of the campaign, and the one status an outsider gets.
func TestTagsPageListsEveryVisibleTag(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, tagCloudVault())
	fx.accounts()

	player := fx.asUser(otherName, otherPass)
	// The fragment, because the cloud is the content region and the document
	// around it would let a value in the masthead answer for a value in the
	// list.
	body := player.text(player.fragment("/tags"))

	for _, want := range []struct {
		tag   string
		count int
	}{
		{"area", 3},
		{"place", 2},
		{"ruin", 1},
	} {
		if !strings.Contains(visibleText(body), want.tag) {
			t.Errorf("the tag cloud does not show %q:\n%s", want.tag, snippet(visibleText(body)))
			continue
		}
		if got := tagCountIn(t, body, want.tag); got != want.count {
			t.Errorf("the tag %q counts %d, want %d", want.tag, got, want.count)
		}
	}
	// Every row is a real link, so the cloud works with the script that enhances
	// it switched off. The href is checked rather than the words, because a row
	// that renders the right name and links nowhere is a control that goes
	// nowhere, and that is the bug a de-graded app has.
	for _, href := range []string{"/tag/area", "/tag/place", "/tag/ruin"} {
		if !strings.Contains(body, `href="`+href+`"`) {
			t.Errorf("the tag cloud does not link to %s:\n%s", href, snippet(body))
		}
	}

	t.Run("an unauthenticated reader with anonymous read off is sent to the login form", func(t *testing.T) {
		t.Parallel()
		// Its own fixture, because the setting is read at boot.
		closed := newFixtureWith(t, tagCloudVault())
		closed.accounts()
		s := closed.newSession()
		resp := s.do(s.get("/tags"))
		defer drain(resp)
		out := s.read(resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("GET /tags with no session: status %d, want 303 to the login form", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); !strings.HasPrefix(got, "/login") {
			t.Errorf("GET /tags redirected to %q, want the login form", got)
		}
		if strings.Contains(visibleText(out), "area") {
			t.Error("the redirect to the login form carried the tag cloud with it")
		}
	})

	t.Run("an unauthenticated reader with anonymous read on may see it", func(t *testing.T) {
		t.Parallel()
		open := newFixtureWith(t, tagCloudVault(), func(c *config.Config) { c.AllowAnonymousRead = true })
		open.accounts()
		s := open.newSession()
		anon := s.text(s.fragment("/tags"))
		if !strings.Contains(visibleText(anon), "area") {
			t.Errorf("an anonymous reader with anonymous read on saw no tags:\n%s", snippet(visibleText(anon)))
		}
	})
}

// tagCloudVault is a campaign whose tags carry three different counts, so that
// a count assertion can tell one row from another. A fixture where every tag
// counts one would pass a test that read the wrong number off the wrong row.
func tagCloudVault() map[string]string {
	return map[string]string{
		"Index.md": "---\ntitle: Index\n---\n\n# Index\n\n" +
			"The [[Tavern]], the [[Ruin]] and the [[Watchtower]], in that order of wetness.\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\ntags: [area, place]\n---\n\n" +
			"# The Drowned Lantern\n\nThe only dry room for miles.\n",
		"Ruin.md": "---\ntitle: The Salt Ruin\ntags: [area]\n---\n\n" +
			"# The Salt Ruin\n\nOpen to the sky, and to the [[Tavern]].\n",
		"Watchtower.md": "---\ntitle: The Watchtower\ntags: [area, place]\n---\n\n" +
			"# The Watchtower\n\nA cold look at the #ruin below.\n",
	}
}

// TestTagCountsExcludeHiddenSecrets is the P4 accept test: a tag whose only
// occurrence is inside a secret the reader may not read must be absent from that
// reader's cloud, and the tag's own page must show nothing rather than 404.
//
// The two cases a player cannot tell apart — a tag nobody can see and a tag
// that does not exist — are the same answer on purpose, and this test is what
// pins that: the player gets a page, with a count of zero and no rows.
func TestTagCountsExcludeHiddenSecrets(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, secretTagVault())
	fx.accounts()

	player := fx.asUser(otherName, otherPass)
	dm := fx.asUser(dmName, dmPass)

	t.Run("a player is shown no trace of the tag", func(t *testing.T) {
		cloud := player.text(player.fragment("/tags"))
		if strings.Contains(strings.ToLower(cloud), "conspiracy") {
			t.Errorf("the tag cloud names a tag that only exists inside a dm secret:\n%s", snippet(cloud))
		}
		page := player.text(player.fragment("/tag/conspiracy"))
		if got := tagCountIn(t, page, "conspiracy"); got != 0 {
			t.Errorf("/tag/conspiracy counts %d for a player, want 0", got)
		}
		if got := pageLinksIn(page); len(got) != 0 {
			t.Errorf("/tag/conspiracy lists pages for a player: %v", got)
		}
	})

	t.Run("the dm is shown the tag and the page", func(t *testing.T) {
		cloud := dm.text(dm.fragment("/tags"))
		if !strings.Contains(cloud, "conspiracy") {
			t.Fatalf("the dm's tag cloud has no conspiracy tag:\n%s", snippet(cloud))
		}
		if got := tagCountIn(t, cloud, "conspiracy"); got != 1 {
			t.Errorf("the conspiracy tag counts %d for the dm, want 1", got)
		}
		page := dm.text(dm.fragment("/tag/conspiracy"))
		if got := tagCountIn(t, page, "conspiracy"); got != 1 {
			t.Errorf("/tag/conspiracy counts %d for the dm, want 1", got)
		}
		if got := pageLinksIn(page); len(got) != 1 || got[0] != "Conspiracy.md" {
			t.Errorf("/tag/conspiracy lists %v for the dm, want exactly Conspiracy.md", got)
		}
	})
}

// secretTagVault's one page carries a tag only inside a dm secret. The public
// text of the page mentions no tag at all, so the only page_tags row for it is
// the one the predicate has to filter.
func secretTagVault() map[string]string {
	return map[string]string{
		"Index.md": "---\ntitle: Index\n---\n\n# Index\n\nEverything worth knowing is on the [[Conspiracy]] page.\n",
		"Conspiracy.md": "---\ntitle: The Conspiracy\n---\n\n# The Conspiracy\n\n" +
			"There is a conspiracy, and this sentence is all the public may know of it.\n\n" +
			fence("a9a9a9a9a9a9", "dm", dmName, "Who is in it", "CONSPIRACY-BODY-TOKEN-6d3f0a #conspiracy"),
	}
}

// TestTagPageCountMatchesItsList is §2.4 in the smallest form it can be stated
// in: the number a tag page shows and the rows it shows are the same fact, read
// twice, and they must not disagree — for either reader.
func TestTagPageCountMatchesItsList(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, markedTagVault())
	fx.accounts()

	for _, who := range []struct {
		name       string
		user, pass string
		want       int
		wantPages  []string
	}{
		{name: "a player", user: otherName, pass: otherPass, want: 2,
			wantPages: []string{"Alpha.md", "Beta.md"}},
		{name: "the dm", user: dmName, pass: dmPass, want: 3,
			wantPages: []string{"Alpha.md", "Beta.md", "Gamma.md"}},
	} {
		t.Run(who.name, func(t *testing.T) {
			t.Parallel()
			s := fx.asUser(who.user, who.pass)
			body := s.text(s.fragment("/tag/marked"))
			count := tagCountIn(t, body, "marked")
			links := pageLinksIn(body)
			if count != len(links) {
				t.Errorf("/tag/marked shows a count of %d and %d rows: %v", count, len(links), links)
			}
			if count != who.want {
				t.Errorf("/tag/marked counts %d, want %d", count, who.want)
			}
			sort.Strings(links)
			want := append([]string(nil), who.wantPages...)
			sort.Strings(want)
			if strings.Join(links, ",") != strings.Join(want, ",") {
				t.Errorf("/tag/marked lists %v, want %v", links, want)
			}
		})
	}
}

// markedTagVault carries the tag in public text on two pages and inside a dm
// secret on a third, which is the one arrangement where a count and a list
// computed from different queries come out different.
func markedTagVault() map[string]string {
	return map[string]string{
		"Alpha.md": "---\ntitle: Alpha\ntags: [marked]\n---\n\n# Alpha\n\nOne of the two marked pages.\n",
		"Beta.md":  "---\ntitle: Beta\ntags: [marked]\n---\n\n# Beta\n\nTwo of the two marked pages.\n",
		"Gamma.md": "---\ntitle: Gamma\n---\n\n# Gamma\n\nNothing public here is marked.\n\n" +
			fence("b8b8b8b8b8b8", "dm", dmName, "The third mark", "GAMMA-BODY-TOKEN-3c7e41 #marked"),
	}
}

// TestFileTreeMirrorsTheVault asserts the tree against the files it is built
// from, and does it structurally rather than by round-tripping a rendering.
//
// The properties are: every page appears exactly once, the set of pages is the
// vault's set, the pages under any one directory are contiguous in the rendered
// order (which is what a pre-order walk of a nested tree means, and is the only
// ordering constraint that holds however the template chooses to interleave a
// node's own files with its subdirectories), two renders agree with each other
// (a comparator that is not a total order produces a different tree per
// request), and the markup is balanced — because a document the browser repairs
// is not the document the handler assembled.
func TestFileTreeMirrorsTheVault(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, treeVault())
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	body := s.text(s.fragment("/files"))
	if problem := unbalancedMarkup(body); problem != "" {
		t.Errorf("the file tree's markup does not nest: %s\n%s", problem, snippet(body))
	}
	links := pageLinksIn(body)

	want := make([]string, 0, len(treeVault()))
	for path := range treeVault() {
		want = append(want, path)
	}
	sort.Strings(want)

	// Every page exactly once. A tree that dropped a page and a tree that showed
	// one twice are the same failure here, which is the point: this is the
	// "no page is invented and none is lost" half of the contract.
	seen := map[string]int{}
	for _, path := range links {
		seen[path]++
	}
	for _, path := range want {
		switch n := seen[path]; {
		case n == 0:
			t.Errorf("the tree does not show %s", path)
		case n > 1:
			t.Errorf("the tree shows %s %d times", path, n)
		}
	}
	for path, n := range seen {
		if n == 1 && !contains(want, path) {
			t.Errorf("the tree shows %s, which is not a page in the vault", path)
		}
	}

	// Every directory is a real path prefix, and its pages are contiguous. A
	// directory is a prefix here, so this is also the assertion that the tree
	// invented no directory: a run of pages under a prefix that is not a
	// directory would break contiguity, and a run under a prefix that does not
	// exist cannot be built from pages that do.
	for _, dir := range []string{"Guild", "Guild/Cellar", "Wilderness", "Wilderness/deep"} {
		under := 0
		for _, path := range links {
			if strings.HasPrefix(path, dir+"/") {
				under++
			}
		}
		if under == 0 {
			t.Errorf("no page appears under the directory %s", dir)
			continue
		}
		first, last := -1, -1
		for i, path := range links {
			if strings.HasPrefix(path, dir+"/") {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
		if last-first+1 != under {
			t.Errorf("the pages under %s are not contiguous: %v", dir, links)
		}
	}

	// Two renders of one state produce one tree. A sort that is not total, or a
	// map walked twice, is how a sidebar changes its own order between a
	// refresh and a reload.
	again := pageLinksIn(s.text(s.fragment("/files")))
	if strings.Join(again, ",") != strings.Join(links, ",") {
		t.Errorf("the file tree reordered between two renders:\nfirst:  %v\nsecond: %v", links, again)
	}

	// The shell's seed is the only JSON in an HTML response, and a client that
	// cannot parse it has no page to refetch into. The two keys are the ones the
	// view layer and the client agreed on, so a third key or a renamed one fails
	// here rather than in a browser console.
	doc := s.getOK("/files")
	seed := signalsSeed(t, doc)
	if len(seed) == 0 {
		t.Error("the shell carries no data-signals seed, so the client has no current page to refetch")
	}
	for _, key := range []string{"currentPageUrl", "push"} {
		if _, ok := seed[key]; !ok {
			t.Errorf("the shell's data-signals seed has no %q key: %v", key, seed)
		}
	}
}

// treeVault is nested three deep in one branch and two in the other, with two
// files sharing a directory and two pages at the root's own level, so that a
// tree that flattened everything into one list fails.
func treeVault() map[string]string {
	return map[string]string{
		"Index.md":                "---\ntitle: Index\n---\n\n# Index\n\nThe top of the vault.\n",
		"Guild/Guild Hall.md":     "---\ntitle: Guild Hall\n---\n\n# Guild Hall\n\nWhere they meet.\n",
		"Guild/Map.md":            "---\ntitle: The Guild Map\n---\n\n# The Guild Map\n\nRolled and shelved.\n",
		"Guild/Cellar/Barrels.md": "---\ntitle: Barrels\n---\n\n# Barrels\n\nA damp cellar.\n",
		"Guild/Cellar/Wine.md":    "---\ntitle: Wine\n---\n\n# Wine\n\nRacks, dust and one bottle.\n",
		"Wilderness/Ruins.md":     "---\ntitle: Ruins\n---\n\n# Ruins\n\nBroken walls in the open.\n",
		"Wilderness/deep/Cave.md": "---\ntitle: Cave\n---\n\n# Cave\n\nDamp, dark and further down.\n",
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// unbalancedMarkup reports the first element the markup closes wrongly, or "".
//
// templ emits well-formed HTML by construction, so a mismatch means a template
// hand-wrote something, and a document the browser has to repair is not the
// document the handler assembled: a browser given unbalanced markup guesses
// where the nesting went, and a file tree is entirely nesting.
func unbalancedMarkup(body string) string {
	void := map[string]bool{
		"area": true, "base": true, "br": true, "col": true, "embed": true,
		"hr": true, "img": true, "input": true, "link": true, "meta": true,
		"source": true, "track": true, "wbr": true,
	}
	var open []string
	for i := 0; i < len(body); {
		j := strings.IndexByte(body[i:], '<')
		if j < 0 {
			break
		}
		i += j + 1
		switch {
		case strings.HasPrefix(body[i:], "!--"):
			end := strings.Index(body[i:], "-->")
			if end < 0 {
				return "a comment that is never closed"
			}
			i += end + 3
			continue
		case strings.HasPrefix(body[i:], "!"):
			end := strings.IndexByte(body[i:], '>')
			if end < 0 {
				return "a declaration that is never closed"
			}
			i += end + 1
			continue
		}
		closing := body[i] == '/'
		if closing {
			i++
		}
		start := i
		for i < len(body) && (isNameByte(body[i])) {
			i++
		}
		name := strings.ToLower(body[start:i])
		if name == "" {
			continue
		}
		end := strings.IndexByte(body[i:], '>')
		if end < 0 {
			return "an element that is never closed: <" + name
		}
		selfClosing := body[i+end-1] == '/'
		i += end + 1
		if closing {
			if len(open) == 0 {
				return "</" + name + "> with nothing open"
			}
			if got := open[len(open)-1]; got != name {
				return "</" + name + "> closing <" + got + ">"
			}
			open = open[:len(open)-1]
			continue
		}
		if !void[name] && !selfClosing {
			open = append(open, name)
		}
	}
	if len(open) > 0 {
		return "an element that is never closed: <" + open[len(open)-1] + ">"
	}
	return ""
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ':'
}

// signalsSeed is the shell's data-signals payload, decoded.
//
// The attribute is found by name and its value is HTML-unescaped, because
// templ writes attribute values in double quotes and escapes the JSON's own
// quotes inside them. A payload that does not parse is a failure here rather
// than a silent skip: the client reads this and nothing else, so a payload it
// cannot parse is a page it cannot navigate away from.
func signalsSeed(t *testing.T, body string) map[string]any {
	t.Helper()
	i := strings.Index(body, "data-signals=")
	if i < 0 {
		return nil
	}
	rest := body[i+len("data-signals="):]
	if rest == "" {
		t.Fatal("the data-signals attribute has no value")
	}
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		t.Fatalf("the data-signals attribute is not quoted with %q", quote)
	}
	end := strings.IndexByte(rest[1:], quote)
	if end < 0 {
		t.Fatal("the data-signals attribute's value is never closed")
	}
	var out map[string]any
	value := html.UnescapeString(rest[1 : 1+end])
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		t.Fatalf("the shell's data-signals seed is not a JSON object: %v\n%s", err, snippet(value))
	}
	return out
}

// campaignPanelVault is a campaign with a session log, two open threads and a
// character sheet, which are the three things the panel names.
//
// It also carries five filler pages, and they are there for a reason: the panel's
// last-activity list shows five pages, and a panel page inside that window would
// make every "the panel shows this title" assertion pass for the wrong reason —
// the title would be in the window whether or not the panel had rendered. The
// indexer walks a vault in lexical path order and every page in one pass shares
// one updated_at, so a page's id is its position in that order: naming the
// fillers F… and the panel pages I/L/P/T puts the fillers at ids 1 to 5 and the
// panel pages at 6 to 9, which puts all of them outside the window. The page
// under test is the Index, and the window fills with the fillers.
func campaignPanelVault() map[string]string {
	vault := map[string]string{
		"Index.md": "---\ntitle: Index\n---\n\n# Index\n\n" +
			"Five ordinary notes, and a campaign that has not settled down.\n",
		"Logs/Session Twelve.md": "---\ntitle: Session Twelve\nsession: 12\ndate: 2026-03-14\ntags: [session]\n---\n\n" +
			"# Session Twelve\n\nThe party finds the cellar door.\n",
		"Threads/First Thread.md": "---\ntitle: First Thread\ntags: [open-thread]\n---\n\n" +
			"# First Thread\n\nWho locked the door?\n",
		"Threads/Second Thread.md": "---\ntitle: Second Thread\ntags: [open-thread]\n---\n\n" +
			"# Second Thread\n\nWho paid the guard?\n",
		"Party/Thia the Bold.md": "---\ntitle: Thia the Bold\ntype: character\n---\n\n" +
			"# Thia the Bold\n\nA fighter of some renown.\n",
	}
	for _, name := range []string{"One", "Two", "Three", "Four", "Five"} {
		vault["Filler "+name+".md"] = "---\ntitle: Filler " + name + "\n---\n\n# Filler " + name + "\n\nNothing of note.\n"
	}
	return vault
}

// hiddenSessionVault is a campaign whose only `#session` tag is written inside a
// dm secret. The log's date is the marker the assertions use: a date is
// rendered by a session entry and by nothing else, so its absence says the
// entry is gone rather than that the panel is short of room.
func hiddenSessionVault() map[string]string {
	return map[string]string{
		"Index.md": "---\ntitle: Index\n---\n\n# Index\n\n" +
			"See the [[Hidden Session Log]] for what is really going on.\n",
		"Hidden Session Log.md": "---\ntitle: The Hidden Session Log\nsession: 9\ndate: 1999-12-31\n---\n\n" +
			"# The Hidden Session Log\n\nA page with nothing in it but a secret.\n\n" +
			fence("c7c7c7c7c7c7", "dm", dmName, "The real plan", "HIDDEN-SESSION-TOKEN-8a4e02 #session"),
	}
}

// TestCampaignStatusIsFieldLevelAuthorized is the P5 accept test.
//
// The panel is not authorized all-or-nothing: a reader sees the fields they may
// see and the others are absent, rather than present and locked. Three things
// are asserted: that a player is shown the session, the threads, the party and
// the plugin's absence; that the panel carries no secret body at all, for
// anybody; and that a `#session` tag which exists only inside a dm secret
// produces no session entry for a player at all — not a blanked one, and not a
// locked one.
func TestCampaignStatusIsFieldLevelAuthorized(t *testing.T) {
	t.Parallel()

	t.Run("the panel shows the fields this reader may see", func(t *testing.T) {
		t.Parallel()
		fx := newFixtureWith(t, campaignPanelVault())
		fx.accounts()
		// The character sheet is owned, because a sheet with no owner is an
		// unowned NPC and the party list is a list of people.
		if err := fx.addOwner("Party/Thia the Bold.md", fx.userID(playerName)); err != nil {
			t.Fatal(err)
		}
		id := pageID(t, fx, "Index.md")

		for _, who := range []struct {
			name       string
			user, pass string
		}{
			{name: "a player", user: playerName, pass: playerPass},
			{name: "the dm", user: dmName, pass: dmPass},
		} {
			t.Run(who.name, func(t *testing.T) {
				t.Parallel()
				s := fx.asUser(who.user, who.pass)
				// The document, not the fragment: the right column is chrome and
				// lives outside the swappable region, so a fragment is a page
				// without a panel and would make every assertion below vacuous.
				body := s.getOK("/p/Index.md")
				text := visibleText(body)
				for _, field := range []string{"session", "threads", "party", "system", "last-activity"} {
					if !strings.Contains(body, `data-status-field="`+field+`"`) {
						t.Errorf("the panel has no %s field:\n%s", field, snippet(text))
					}
				}
				// A session entry carries the log's own date, and a date is
				// rendered by a session entry and by nothing else on the page.
				if !strings.Contains(text, "2026-03-14") {
					t.Errorf("the panel does not show the session's date:\n%s", snippet(text))
				}
				if !strings.Contains(text, noSystemNote) {
					t.Errorf("the panel does not show the system note:\n%s", snippet(text))
				}

				// The same panel, read as the API projection, so that the
				// field-level rule is asserted on the data rather than on one
				// template's rendering of it.
				status := contextFor(t, s, id).Status
				if status.Session == nil {
					t.Fatal("the context payload has no session, but the panel renders one")
				}
				if status.Session.Number != 12 {
					t.Errorf("the session number is %d, want the file's own 12", status.Session.Number)
				}
				if status.Session.Date != "2026-03-14" {
					t.Errorf("the session date is %q, want 2026-03-14", status.Session.Date)
				}
				if status.ThreadCount != 2 {
					t.Errorf("the panel counts %d open threads, want 2", status.ThreadCount)
				}
				if len(status.Threads) != status.ThreadCount {
					t.Errorf("the panel counts %d threads and lists %d", status.ThreadCount, len(status.Threads))
				}
				if len(status.Party) != 1 {
					t.Fatalf("the party list holds %d members, want 1", len(status.Party))
				}
				if status.Party[0].Owner != "Thia" {
					t.Errorf("the party's owner is %q, want the account's display name", status.Party[0].Owner)
				}
				if status.Party[0].Note != "" {
					t.Errorf("the party member carries a note %q, and no system plugin exists to write one", status.Party[0].Note)
				}
				if status.SystemNote != noSystemNote {
					t.Errorf("the panel's system note is %q, want the fixed phrase", status.SystemNote)
				}
				// Nothing a panel may not show is in it, for anybody: this
				// campaign has no secrets at all, so the check is that a panel
				// which invented one out of a page title or a tag would fail.
				for _, token := range bodyTokens {
					assertNoToken(t, body, token, "the campaign status panel as "+who.name)
				}
			})
		}
	})

	t.Run("a session that exists only in a dm secret is not in the player's panel", func(t *testing.T) {
		t.Parallel()
		fx := newFixtureWith(t, hiddenSessionVault())
		fx.accounts()
		id := pageID(t, fx, "Index.md")

		player := fx.asUser(otherName, otherPass)
		body := player.getOK("/p/Index.md")
		// Absent, not blanked and not locked. The panel's own field marker is the
		// right thing to look for: a blanked entry would still render the field,
		// and a locked one would render it with a lock in it. What must not be
		// there is the field.
		if strings.Contains(body, `data-status-field="session"`) {
			t.Errorf("the player's panel has a session field for a session that exists only in a dm secret:\n%s",
				snippet(visibleText(body)))
		}
		// And the log's own date, which a session entry is the only thing on the
		// page that renders, is not there either.
		if strings.Contains(visibleText(body), "1999-12-31") {
			t.Errorf("the player's panel names a session log that exists only in a dm secret:\n%s",
				snippet(visibleText(body)))
		}
		status := contextFor(t, player, id).Status
		if status.Session != nil {
			t.Errorf("the player's payload carries a session entry: %+v", *status.Session)
		}
		for _, token := range bodyTokens {
			assertNoToken(t, body, token, "the player's panel on a campaign with a hidden session")
		}
		assertNoToken(t, body, "HIDDEN-SESSION-TOKEN-8a4e02", "the player's panel on a campaign with a hidden session")

		// And the DM does get it, so the absence above is a decision about the
		// reader rather than a session log the index never recorded.
		dm := fx.asUser(dmName, dmPass)
		if !strings.Contains(dm.getOK("/p/Index.md"), `data-status-field="session"`) {
			t.Error("the dm's panel has no session field, but the log is visible to a dm")
		}
		if got := contextFor(t, dm, id).Status.Session; got == nil {
			t.Error("the dm's payload has no session, but the log is visible to a dm")
		} else if got.Number != 9 || got.Date != "1999-12-31" {
			t.Errorf("the dm's session is number %d on %q, want 9 on 1999-12-31", got.Number, got.Date)
		}
	})
}

// TestLastActivityExcludesTheOpenPage covers the panel's one piece of state: the
// page you are reading is not one of the five pages it tells you about.
func TestLastActivityExcludesTheOpenPage(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	index := pageID(t, fx, "Index.md")
	tavern := pageID(t, fx, "Tavern.md")

	open := contextFor(t, s, index)
	if len(open.Status.LastActivity) == 0 {
		t.Fatal("the panel lists no recent pages, so the exclusion cannot be observed")
	}
	for _, entry := range open.Status.LastActivity {
		if entry.Path == "Index.md" {
			t.Errorf("the panel lists the page that is open as recent activity: %+v", entry)
		}
	}
	// The other page's panel does list it, which is what makes the assertion
	// above a fact about this request rather than a fact about the index.
	other := contextFor(t, s, tavern)
	found := false
	for _, entry := range other.Status.LastActivity {
		if entry.Path == "Index.md" {
			found = true
		}
	}
	if !found {
		t.Errorf("the Tavern's panel does not list the Index, so nothing was excluded:\n%+v", other.Status.LastActivity)
	}

	// And the rendered page does not link to itself, which is the same fact
	// through the view layer. The Index links to the Tavern and the Ruin and
	// nothing links to the Index, so a self-link anywhere in the document can
	// only be the panel listing the page the reader is on.
	body := s.getOK("/p/Index.md")
	for _, path := range pageLinksIn(body) {
		if path == "Index.md" {
			t.Errorf("the page view links to itself from its own context column:\n%s", snippet(body))
		}
	}
}

// TestContextAPIAndPageViewAgree is the cross-check that the context API and the
// page view are one implementation. A second implementation of a page's context
// is the bug the canonical predicate exists to prevent, and it would show up
// first as a disagreement between the two, because both are rendered from the
// same index and the same predicate.
func TestContextAPIAndPageViewAgree(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	id := pageID(t, fx, "Tavern.md")
	got := contextFor(t, s, id)
	// The document, because the table of contents and the backlinks are rendered
	// into the right-hand column, which is chrome and lives outside the
	// swappable region — a fragment is a page with no context column at all.
	page := s.getOK("/p/Tavern.md")
	text := visibleText(page)

	if got.Href != "/p/Tavern.md" {
		t.Errorf("the context payload's href is %q, want /p/Tavern.md", got.Href)
	}
	if got.Path != "Tavern.md" || got.Title != "The Drowned Lantern" {
		t.Errorf("the context payload names %q at %q, want the Tavern", got.Title, got.Path)
	}
	if len(got.Toc) == 0 {
		t.Fatal("the Tavern has no table of contents, so the two cannot be compared")
	}
	for _, entry := range got.Toc {
		if !strings.Contains(text, entry.Text) {
			t.Errorf("the page view does not show the heading %q the context payload lists", entry.Text)
		}
		if !strings.Contains(page, `href="`+entry.Href+`"`) {
			t.Errorf("the page view does not link to the anchor %q the context payload lists", entry.Href)
		}
	}
	if len(got.Backlinks) == 0 {
		t.Fatal("the Tavern has no backlinks, so the two cannot be compared")
	}
	for _, chip := range got.Backlinks {
		if !strings.Contains(text, chip.Title) {
			t.Errorf("the page view does not show the referring page %q the context payload lists", chip.Title)
		}
		if !strings.Contains(page, `href="`+chip.Href+`"`) {
			t.Errorf("the page view does not link to %q the context payload lists", chip.Href)
		}
	}
	if len(got.Backlinks) != got.BacklinkCount {
		t.Errorf("the payload lists %d backlinks and counts %d", len(got.Backlinks), got.BacklinkCount)
	}
	// And the number the page renders is the number the payload carries. The
	// panel's badge is the shape a reader sees, so it is the shape the
	// comparison is made in.
	if shown := numberAfter(t, page, "Linked from"); shown != got.BacklinkCount {
		t.Errorf("the page view shows a backlink count of %d and the payload carries %d", shown, got.BacklinkCount)
	}
}

// TestContextAPIForAnUnreadablePageIsTheSameAsForAMissingPage is the rule the
// error page's doc comment states, checked on a JSON route.
//
// The class that exists in v1 is a page whose file has gone while its index row
// has not: the Markdown file is canonical, so a row with no file is not a page.
// The other two of the three ids are a number no page has and a string that is
// not a number, and all of them must answer identically — a client that could
// tell them apart could enumerate the index.
func TestContextAPIForAnUnreadablePageIsTheSameAsForAMissingPage(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	// The file goes; the row stays, because the fixture runs no watcher and no
	// reconciliation scan. That is the state the reader is actually in between a
	// file being deleted and the scan that notices.
	stale := strconv.FormatInt(pageID(t, fx, "Ruin.md"), 10)
	if err := os.Remove(filepath.Join(fx.Root, "Ruin.md")); err != nil {
		t.Fatalf("remove the vault file: %v", err)
	}

	stalePath := "/api/pages/" + stale + "/context"
	if got := s.status(s.get(stalePath)); got != http.StatusNotFound {
		t.Fatalf("the context of a page whose file is gone: status %d, want 404", got)
	}
	staleBody := s.refusedBody(t, stalePath)

	missingPath := "/api/pages/999999999/context"
	if got := s.status(s.get(missingPath)); got != http.StatusNotFound {
		t.Fatalf("the context of a page that never existed: status %d, want 404", got)
	}
	missingBody := s.refusedBody(t, missingPath)

	if staleBody != missingBody {
		t.Errorf("the two refusals are not byte-identical:\nstale:   %q\nmissing: %q", staleBody, missingBody)
	}
	// A payload that named the page, or its title, or anything else per request,
	// would be the leak. The fixed shape is the whole of the answer.
	for _, forbidden := range []string{"Ruin", "Salt", "Ruin.md", stale} {
		assertNoToken(t, staleBody, forbidden, "the refusal for a page whose file is gone")
	}
}

// refusedBody performs a request that is expected to be refused and returns its
// body, so that two refusals can be compared byte for byte.
func (s *session) refusedBody(t *testing.T, path string) string {
	t.Helper()
	resp := s.do(s.get(path))
	body := s.read(resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET %s: status %d, want 404\n%s", path, resp.StatusCode, snippet(body))
	}
	return body
}

// TestContextAPIRejectsABadID checks that every way of naming a page that is not
// one gets the same answer.
//
// A 400 would be wrong on its own terms: it would confirm that the address is
// one this route understands, which is a fact about the campaign's internals
// that an outsider has no business having.
func TestContextAPIRejectsABadID(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	// Every one of these names a page that is not there: not a number, not a
	// positive number, a number no page holds, a number that is not an integer
	// in any language the parse accepts, and one that does not fit in an int64.
	var first string
	for i, id := range []string{"abc", "0", "-1", "99999999", "1.5", "0x10", "9223372036854775808"} {
		t.Run("id="+id, func(t *testing.T) {
			path := "/api/pages/" + id + "/context"
			resp := s.do(s.get(path))
			body := s.read(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s: status %d, want 404\n%s", path, resp.StatusCode, snippet(body))
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("GET %s: content type %q, want JSON", path, ct)
			}
			if i == 0 {
				first = body
				return
			}
			if body != first {
				t.Errorf("GET %s answered differently from the first bad id:\n%s\n%s", path, first, body)
			}
		})
	}
	// And the good path still works, so the four refusals are refusals rather
	// than a route that answers 404 to everything.
	if got := contextFor(t, s, pageID(t, fx, "Index.md")); got.Path != "Index.md" {
		t.Errorf("a page that does exist answered %q", got.Path)
	}
}

// TestCommandsAreRealLinksAndRespectTheMatrix covers the palette's three
// promises: the actions are always there, a term finds the page it names, and a
// term that only a hidden secret contains finds nothing at all. Every href is
// checked to be a same-origin absolute path, because that is what makes the
// palette a list of links rather than a script.
func TestCommandsAreRealLinksAndRespectTheMatrix(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accounts()
	s := fx.asUser(otherName, otherPass)

	t.Run("with no term the actions are the answer", func(t *testing.T) {
		t.Parallel()
		got := commandsFor(t, s, "")
		if got.Query != "" {
			t.Errorf("the payload echoes %q for an empty term", got.Query)
		}
		want := map[string]string{"/": "h", "/tags": "t", "/files": "f"}
		for href, hint := range want {
			found := false
			for _, c := range got.Commands {
				if c.Href == href {
					found = true
					if c.Kind != httpapi.CommandAction {
						t.Errorf("the action %q is a %q, want an action", href, c.Kind)
					}
					if c.Hint != hint {
						t.Errorf("the action %q hints %q, want %q", href, c.Hint, hint)
					}
				}
			}
			if !found {
				t.Errorf("an empty term did not offer the action %q", href)
			}
		}
		if len(got.Commands) != len(want) {
			t.Errorf("an empty term answered %d rows, want the %d actions", len(got.Commands), len(want))
		}
	})

	t.Run("a term finds the page and the tag it names", func(t *testing.T) {
		t.Parallel()
		// A prefix, on the title or on the path, and nothing else: a substring
		// match over a path list is a way to learn that a page exists whose name
		// the reader has guessed most of, one character at a time.
		for _, term := range []string{"Tav", "The Drowned"} {
			got := commandsFor(t, s, term)
			var pages []string
			for _, c := range got.Commands {
				if c.Kind == httpapi.CommandPage {
					pages = append(pages, c.Href)
				}
			}
			if !contains(pages, "/p/Tavern.md") {
				t.Errorf("a term of %q answered the pages %v, want /p/Tavern.md among them", term, pages)
			}
		}
		// A term in the middle of a title matches nothing, which is the property
		// that keeps the palette from being a substring oracle.
		if pages := pageRowsOf(commandsFor(t, s, "Drowned")); len(pages) != 0 {
			t.Errorf("a term in the middle of a title answered the pages %v, want none", pages)
		}

		// Tags, matched by prefix on the name, linking to the tag's own page with
		// the slash in a nested name escaped: a slash left bare is the router's
		// own separator, so /tag/area/port matches no route at all and the row
		// would be a link to nothing.
		tags := commandsFor(t, s, "area")
		var hrefs []string
		for _, c := range tags.Commands {
			if c.Kind == httpapi.CommandTag {
				hrefs = append(hrefs, c.Href)
			}
		}
		sort.Strings(hrefs)
		if strings.Join(hrefs, ",") != "/tag/area%2Fport,/tag/area%2Fwild" {
			t.Errorf("a term of area answered the tags %v", hrefs)
		}
	})

	t.Run("a term that only a hidden secret contains finds nothing", func(t *testing.T) {
		t.Parallel()
		// The term is in every secret body in the fixture and in no page, and it
		// is not a secret itself — the palette echoes the term back, so a term
		// that was a body would be found in the response for that reason alone
		// and the assertion would prove nothing.
		for _, term := range []string{searchWord, "PRIVATE", "9f3a2c"} {
			got := commandsFor(t, s, term)
			for _, c := range got.Commands {
				if c.Kind != httpapi.CommandAction {
					t.Errorf("a term of %q answered a %q row: %+v", term, c.Kind, c)
				}
			}
			for _, token := range bodyTokens {
				for _, c := range got.Commands {
					assertNoToken(t, c.Label+c.Href, token, "a palette row for the term "+term)
				}
			}
		}
	})

	t.Run("every href is a same-origin absolute path", func(t *testing.T) {
		t.Parallel()
		for _, term := range []string{"", "a", "area", searchWord, "  spaced  "} {
			for _, c := range commandsFor(t, s, term).Commands {
				if !strings.HasPrefix(c.Href, "/") {
					t.Errorf("the row %q links to %q, which is not an absolute path", c.Label, c.Href)
				}
				if strings.Contains(c.Href, "://") {
					t.Errorf("the row %q links to %q, which names a scheme", c.Label, c.Href)
				}
				if strings.Contains(c.Href, "//") {
					t.Errorf("the row %q links to %q, which could be read as another origin", c.Label, c.Href)
				}
				if c.Kind == "" {
					t.Errorf("the row %q has no kind", c.Label)
				}
			}
		}
	})
}

// TestCommandsRequireASession covers the palette's own permission, which is
// stricter than the campaign's: an anonymous reader with anonymous read on can
// read every page the palette would offer them, so refusing the palette to them
// would be refusing a convenience on the grounds that it is convenient.
func TestCommandsRequireASession(t *testing.T) {
	t.Parallel()

	for _, anon := range []struct {
		name string
		read bool
	}{
		{name: "anonymous read off"},
		{name: "anonymous read on", read: true},
	} {
		t.Run(anon.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixtureWith(t, tagCloudVault(), func(c *config.Config) { c.AllowAnonymousRead = anon.read })
			fx.accounts()
			s := fx.newSession()

			// The campaign itself is readable in the read-on case, so the
			// refusal below is about the palette and not about the campaign.
			if anon.read {
				if got := s.status(s.get("/tags")); got != http.StatusOK {
					t.Fatalf("an anonymous reader with read on cannot read /tags: status %d", got)
				}
			}
			resp := s.do(s.get("/_/commands?q=Dro"))
			body := s.read(resp)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("GET /_/commands with no session: status %d, want 303 to the login form", resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); !strings.HasPrefix(got, "/login") {
				t.Errorf("GET /_/commands redirected to %q, want the login form", got)
			}
			if strings.Contains(body, "Drowned") || strings.Contains(body, `"commands"`) {
				t.Errorf("the refusal to the palette carried the palette with it:\n%s", snippet(body))
			}
		})
	}
}

// TestEveryNewRouteIsInTheAuthorizationMatrix checks the six stage-2 rows are in
// the route table with the permissions the contract names.
//
// It does not check that the matrix has a row for each of them, because
// TestTheMatrixCoversEveryRoute already derives that from this same table: it
// walks fx.Server.Routes() and fails on any route the matrix does not name, so
// a second copy of the check here would be a second thing to forget. What this
// adds is the permission column, which the matrix asserts as a status code and
// not as a name.
func TestEveryNewRouteIsInTheAuthorizationMatrix(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)

	// The permissions are named as the strings the table carries rather than as
	// the constants, because the point of the check is the table's own value:
	// PermNone is the zero value, so a row that lost its permission would look
	// exactly like a row that never had one.
	want := map[string]string{
		"GET /tags":                   string(authz.PermAnonRead),
		"GET /tag/{name}":             string(authz.PermAnonRead),
		"GET /files":                  string(authz.PermAnonRead),
		"GET /api/pages/{id}/context": string(authz.PermReadPage),
		"GET /_/commands":             string(authz.PermSession),
		"GET /_/events":               string(authz.PermSession),
	}

	perms := map[string]string{}
	for _, rt := range fx.Server.Routes() {
		perms[rt.Name()] = string(rt.Perm)
	}
	for name, perm := range want {
		got, ok := perms[name]
		if !ok {
			t.Errorf("the route table has no row for %s", name)
			continue
		}
		if got != perm {
			t.Errorf("the route %s has permission %q, want %q", name, got, perm)
		}
	}
	// The matrix itself is the gate for coverage, and it is named here so that
	// the reason this test does not duplicate it is on the record.
	t.Run("the coverage check is matrix_test.go's", func(t *testing.T) {
		t.Parallel()
		// The route table and the matrix are compared by a test in matrix_test.go
		// that this one must not shadow. Its absence is not observable from here,
		// so this is a note rather than an assertion, and the assertion above —
		// every stage-2 row present with its documented permission — is what this
		// file owns.
	})
}

// TestNoNewRouteLeaksASecret is the tripwire over the five routes this
// workstream added, as every role.
//
// The sixth new row, /_/events, belongs to the live-push workstream and is
// deliberately not walked here: its response is a stream that stays open, so
// reading its body to the end is exactly the thing a test must not do. Its
// secrets are covered by the push tests the phase lists.
func TestNoNewRouteLeaksASecret(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	tavern := pageID(t, fx, "Tavern.md")

	steps := []step{
		{name: "tags", method: http.MethodGet, path: "/tags"},
		{name: "tags as a fragment", method: http.MethodGet, path: "/tags", fragment: true},
		{name: "tag", method: http.MethodGet, path: "/tag/area%2Fport"},
		{name: "files", method: http.MethodGet, path: "/files"},
		{name: "files as a fragment", method: http.MethodGet, path: "/files", fragment: true},
		{name: "page context", method: http.MethodGet, path: "/api/pages/" + strconv.FormatInt(tavern, 10) + "/context"},
		{name: "commands", method: http.MethodGet, path: "/_/commands?q=lantern"},
		{name: "commands with no term", method: http.MethodGet, path: "/_/commands"},
	}

	cases := []leakPrincipal{
		{name: "admin", user: adminName, pass: adminPass},
		{name: "dm", user: dmName, pass: dmPass},
		{name: "page owner", user: playerName, pass: playerPass},
		{name: "player", user: otherName, pass: otherPass},
		{name: "anonymous with read off", anonymous: true},
	}
	// The same model of the rule the tripwire uses, restated rather than reached
	// for: a walk that shared the predicate it is checking cannot catch that
	// predicate being wrong.
	mayRead := func(p leakPrincipal, token string) bool {
		dmish := p.name == "admin" || p.name == "dm"
		owner := p.name == "page owner"
		switch token {
		case tableToken:
			return !p.anonymous
		case "PRIVATE-BODY-TOKEN-9f3a2c", "OWNER-BODY-TOKEN-2a6e10":
			return dmish || owner
		case "DM-BODY-TOKEN-7b1e4d", "RUIN-BODY-TOKEN-2c8f61":
			return dmish
		}
		return false
	}

	for _, p := range cases {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s := fx.newSession()
			if !p.anonymous {
				resp := s.login(p.user, p.pass)
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("sign in: status %d, want 303", resp.StatusCode)
				}
				drain(resp)
			}
			for _, st := range steps {
				t.Run(st.name, func(t *testing.T) {
					// A fragment is a different code path on the server, so the
					// walk asks for both shapes of every HTML surface.
					step := &call{method: st.method, path: st.path}
					if st.fragment {
						step = s.fragment(st.path)
					}
					resp := s.do(step)
					defer drain(resp)
					body := s.read(resp)
					assertNoLeaks(t, body, resp.Header, mayRead, p, st.name)
				})
			}
		})
	}
}
