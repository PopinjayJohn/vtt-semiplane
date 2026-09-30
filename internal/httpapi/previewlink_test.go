package httpapi_test

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/systems/linkpreview"
)

// The link preview driven the way a reader drives it: read the attribute off a
// rendered page, build the URL the shell builds from it, and follow that.
//
// Every test in preview_test.go requests /plugin/linkpreview/summary/<id> with an
// id the test chose. That proves the route answers, and it is exactly the shape
// AGENTS.md §11 records twice: the attachment route worked perfectly while every
// attachment in the app was a broken image, because the page emitted a relative
// src. The route being correct is not the same claim as the page pointing at it,
// and only one of the two is the user-visible bug. So no test in this file writes
// an id down; it reads one off a page and follows it.
//
// The provider is the real plugin over a real store, not the double
// preview_test.go uses. A test that drives core's route with a fake provider
// cannot tell a core bug from a plugin bug, and the bug in this area has been in
// both.

// previewPageStore is the composition root's pageStore, restated here so a test in
// this package can hand a real registry to a real plugin.
//
// q is filled in after the fixture boots, because the registry has to be built
// before the database it reads exists. Every method is the store's own, called
// verbatim: a query written here would be a query store's own tests cannot see.
type previewPageStore struct{ q store.Queryer }

func (p *previewPageStore) GetPageSummary(ctx context.Context, who authz.Principal, id int64) (store.PageSummary, error) {
	return store.GetPageSummary(ctx, p.q, who, id)
}

func (p *previewPageStore) ListPagesByType(ctx context.Context, who authz.Principal, pt string) ([]store.Page, error) {
	return store.ListPagesByType(ctx, p.q, who, pt)
}

func (p *previewPageStore) CountPagesByType(ctx context.Context, who authz.Principal, pt string) (int, error) {
	return store.CountPagesByType(ctx, p.q, who, pt)
}

func (p *previewPageStore) ListTags(ctx context.Context, who authz.Principal) ([]store.TagCount, error) {
	return store.ListTags(ctx, p.q, who)
}

// realPreviewRegistry loads the shipped link-preview plugin the way app does, and
// fails the test if the boot report does not say it registered: a fixture with a
// silently-skipped plugin answers every request below with a 404, and every
// assertion in this file would then be about the skip.
func realPreviewRegistry(t *testing.T, pages plugin.PageStore) plugin.Registry {
	t.Helper()
	reg, report := plugin.Load(context.Background(), plugin.PluginDeps{
		Now:    func() time.Time { return time.Time{} },
		Pages:  pages,
		Config: func(string) (plugin.Config, error) { return plugin.Config{}, nil },
		Log:    func(context.Context, plugin.Level, string, ...plugin.KV) {},
	}, linkpreview.New())
	if len(report.Entries) != 1 {
		t.Fatalf("the boot report holds %d entries, want exactly the one plugin this file loads", len(report.Entries))
	}
	e := report.Entries[0]
	if e.ID != linkpreview.ID {
		t.Fatalf("the report names %q, which is not the plugin this file loads", e.ID)
	}
	if e.Status != plugin.StatusOK {
		t.Fatalf("the linkpreview plugin did not register: %s (%s)", e.Status, e.Reason)
	}
	return reg
}

// newPreviewFixture boots a server over files with the real preview provider
// registered, its accounts populated, and the Tavern's ownership granted.
//
// The order is accounts, reindex, grant, reindex, for the reason harness_test.go
// gives on accountsFor: reindexAll drops the derived index and derives it again,
// so a grant written before it names a page row that no longer exists. A grant
// that silently failed to attach is a "player who owns nothing" reading as a
// "player who owns the tavern", and every ownership-dependent assertion below
// would pass against the wrong state.
func newPreviewFixture(t *testing.T, files map[string]string, mutate ...func(*config.Config)) *fixture {
	t.Helper()
	pages := &previewPageStore{}
	fx := newFixturePlugins(t, files, realPreviewRegistry(t, pages), mutate...)
	pages.q = fx.DB.Reader()
	fx.accountsForAccounts()
	fx.reindexAll()
	if _, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), "Tavern.md"); err == nil {
		if err := fx.addOwner("Tavern.md", fx.userID(playerName)); err != nil {
			t.Fatalf("grant the tavern to its owner: %v", err)
		}
	}
	return fx
}

// shellSummaryPath is the summary route's URL as the client assembles it, from
// the same constant the shell holds. Assembling it here rather than pasting a
// literal is what stops the test agreeing with a route that has moved.
const shellSummaryPath = "/plugin/" + linkpreview.ID + "/summary/"

// emittedLink is one anchor on a rendered page, as the shell sees it.
type emittedLink struct {
	href     string
	pageID   string
	text     string
	wikilink bool
}

var (
	// anchorExpr finds every anchor, with or without the preview attribute, so a
	// test can assert about the ones that are missing.
	anchorExpr = regexp.MustCompile(`<a [^>]*href="([^"]*)"[^>]*>(.*?)</a>`)
	pageIDExpr = regexp.MustCompile(`\bdata-wikilink="([0-9]+)"`)
	tagExpr    = regexp.MustCompile(`<[^>]*>`)
)

// readEmittedLinks parses a rendered page into the anchors it carries.
func readEmittedLinks(body string) []emittedLink {
	var out []emittedLink
	for _, m := range anchorExpr.FindAllStringSubmatch(body, -1) {
		// The attribute may sit before or after href depending on templ's
		// attribute order, so the whole anchor is searched rather than the
		// substring after it.
		id := pageIDExpr.FindStringSubmatch(m[0])
		link := emittedLink{
			href:     m[1],
			text:     strings.TrimSpace(tagExpr.ReplaceAllString(m[2], "")),
			wikilink: id != nil,
		}
		if id != nil {
			link.pageID = id[1]
		}
		out = append(out, link)
	}
	return out
}

// anchorIn returns the anchors of the one paragraph naming a case.
//
// Paragraphs rather than the whole page, because the shape under test is the
// *link* and two shapes can render the same words: `[[Tavern]]` and
// `[[Tavern#^cellar1]]` both say "Tavern", and a test that found the first when it
// asked for the second would be asserting about the wrong link while looking
// correct. Each case is its own paragraph in the fixture below, which is what
// makes the two findable.
func anchorIn(t *testing.T, body, marker string) []emittedLink {
	t.Helper()
	for _, para := range strings.Split(body, "</p>") {
		if !strings.Contains(para, marker) {
			continue
		}
		links := readEmittedLinks(para)
		var withHref []emittedLink
		for _, l := range links {
			if l.href != "" {
				withHref = append(withHref, l)
			}
		}
		if len(withHref) == 0 {
			t.Fatalf("the paragraph naming %q has no anchor in it:\n%s", marker, para)
		}
		return withHref
	}
	t.Fatalf("the page has no paragraph naming %q", marker)
	return nil
}

// theLink is the paragraph's one anchor, and a paragraph with two is a fixture
// that has stopped saying which shape it was recording.
func theLink(t *testing.T, body, marker string) emittedLink {
	t.Helper()
	links := anchorIn(t, body, marker)
	if len(links) != 1 {
		t.Fatalf("the paragraph naming %q has %d anchors, want 1", marker, len(links))
	}
	return links[0]
}

// renderedPage reads a page and answers its body, failing if the page does not
// hold the markers the test is about. A fixture that lost a file would otherwise
// make every assertion below vacuous.
func renderedPage(t *testing.T, s *session, path string, markers ...string) string {
	t.Helper()
	body := s.getBody(path)
	for _, m := range markers {
		if !strings.Contains(body, m) {
			t.Fatalf("%s does not contain %q, so this test is asserting about a fixture that is not there", path, m)
		}
	}
	return body
}

// preview follows the URL the shell builds from a link and answers the status and
// the body. It refuses to guess: a link with no attribute has no id, and a test
// that invented one would be testing the route rather than the page.
func preview(t *testing.T, s *session, link emittedLink) (int, string) {
	t.Helper()
	if !link.wikilink {
		t.Fatalf("the link to %q carries no data-wikilink, so the shell has no id to ask about it", link.text)
	}
	resp := s.do(s.get(shellSummaryPath + link.pageID))
	defer drain(resp)
	return resp.StatusCode, s.read(resp)
}

// navigate is one ordinary request, answered as the reader would get it.
type navigated struct {
	status int
	body   string
}

func navigate(t *testing.T, s *session, path string) navigated {
	t.Helper()
	resp := s.do(s.get(path))
	defer drain(resp)
	return navigated{status: resp.StatusCode, body: s.read(resp)}
}

// refusesLikeThePage is the AGENTS.md §7 comparison, as a predicate: a summary is
// acceptable when it is a card, or when it is the page's own answer in the same
// status and the same bytes.
//
// The second half is the half a status check cannot make. A reader who cannot
// read the page and a reader for whom the page does not exist have to be
// indistinguishable, and the only way to say that is to compare the bodies.
func refusesLikeThePage(t *testing.T, label string, sum, page navigated) {
	t.Helper()
	if strings.Contains(sum.body, "<article") {
		return
	}
	if sum.status != page.status {
		t.Errorf("a summary of %s answered %d and the page answered %d: the two refusals are distinguishable by status", label, sum.status, page.status)
		return
	}
	if sum.body != page.body {
		t.Errorf("a summary of %s is not the page's own answer byte for byte.\n got: %q\nwant: %q", label, sum.body, page.body)
	}
}

// previewVault is a page whose body carries one of every link shape a campaign
// actually contains, plus the four targets those shapes name.
var previewVault = map[string]string{
	"Hub.md": "---\ntitle: Hub\ntags: [hub]\n---\n\n" +
		"A paragraph naming pages in every way an author writes them.\n\n" +
		"A plain link: [[Tavern]].\n\n" +
		"A heading link: [[Tavern#The Cellar]].\n\n" +
		"A block reference: [[Tavern#^cellar1]].\n\n" +
		"An aliased link: [[Tavern|the drowned lantern]].\n\n" +
		"A page in a subdirectory: [[Party/Orrin]].\n\n" +
		"A page with no title: [[Untitled]].\n\n" +
		"A page that is not there: [[No Such Page]].\n\n" +
		"A link into this page: [[#A paragraph naming pages]].\n\n" +
		"A markdown link: [the tavern](Tavern.md).\n\n" +
		"An external link: [elsewhere](https://example.invalid/notes).\n",

	"Tavern.md": "---\ntitle: The Drowned Lantern Inn\ntags: [tavern, hub]\n---\n\n" +
		"The cellar is down two flights and the ale is worse than the stairs.\n\n" +
		"^cellar1\n\n" +
		"## The Cellar\n\n" +
		"```secret id=a1b2c3d4e5f6 visibility=dm author=dm created=2026-01-01T00:00:00Z title=\"The key\"\n" +
		"DM-BODY-TOKEN-7b1e4d the key is under the third stair\n```\n",

	"Party/Orrin.md": "---\n---\n\nOrrin has not bought a round since the road to Greyhawk.\n",

	"Untitled.md": "---\n---\n\nA page whose frontmatter carries no title at all.\n",
}

// TestALinkOnAPagePreviewsThePageItNames is the positive control for this file: a
// reader hovers a link, a card arrives, and the card says the title of the page
// the link named.
//
// It is also the only assertion here that would catch a route answering 200 with
// an empty body, which is a leak suite's ideal outcome and a reader's
// disappointment: a preview suite that asserts only the absence of a secret passes
// perfectly against a feature that shows nothing at all.
func TestALinkOnAPagePreviewsThePageItNames(t *testing.T) {
	t.Parallel()

	fx := newPreviewFixture(t, previewVault)
	s := fx.asUser(playerName, playerPass)
	body := renderedPage(t, s, "/p/Hub.md", "A plain link", "An aliased link", "A page in a subdirectory")

	for _, tc := range []struct{ marker, title, excerpt string }{
		{marker: "A plain link", title: "The Drowned Lantern Inn", excerpt: "The cellar is down two flights"},
		{marker: "An aliased link", title: "The Drowned Lantern Inn", excerpt: "The cellar is down two flights"},
		// A subdirectory page, whose title came from its basename because its
		// frontmatter declares none. A card that showed the wrong page here would
		// look plausible — it is a card, with a title and an excerpt — so this row
		// is here rather than folded into the two above.
		{marker: "A page in a subdirectory", title: "Orrin", excerpt: "Orrin has not bought a round"},
	} {
		t.Run(tc.marker, func(t *testing.T) {
			t.Parallel()
			status, card := preview(t, s, theLink(t, body, tc.marker))
			if status != http.StatusOK {
				t.Fatalf("the %q link's preview answered %d, want 200", tc.marker, status)
			}
			if !strings.Contains(card, ">"+tc.title+"<") {
				t.Errorf("the card the %q link produced does not name the page as %q: %s", tc.marker, tc.title, card)
			}
			if !strings.Contains(card, tc.excerpt) {
				t.Errorf("the card the %q link produced carries no excerpt of the page: %s", tc.marker, card)
			}
		})
	}
}

// TestTheLinkShapesThatPreviewArePinned is the record of this surface's two
// kinds of failure, and it is a test rather than a table in a document because
// AGENTS.md §0 says the code is the specification and a paragraph of prose can be
// wrong while looking authoritative.
//
// A disagreement here is silent by construction. The attribute is put on a
// rendered anchor by one place — a byte scan in internal/httpapi/page.go — and it
// is put there only when the scan's key set contains the href the renderer
// actually emitted. No attribute means an ordinary link, which is exactly what
// the absence-degrades rule wants a build with no previews to do, so a preview
// that never binds and a build that was never going to have one look identical on
// screen. That was the whole of "works unreliably": the key set was a second,
// hand-written copy of md's URL rule, and the two disagreed wherever the
// renderer's answer was not that copy's answer.
//
// Measured on this vault, with the real renderer and the real index:
//
//	[[Tavern]]                      -> /p/Tavern                        previews
//	[[Tavern|the drowned lantern]]  -> /p/Tavern                        previews
//	[[Party/Orrin]]                 -> /p/Party/Orrin                   previews
//	[[Tavern#The Cellar]]           -> /p/Tavern#The%20Cellar           previews
//	[[Tavern#^cellar1]]             -> /p/Tavern#%5Ecellar1             previews
//	[the tavern](Tavern.md)         -> /p/Hub.md/attachment/Tavern.md  previews
//	[[No Such Page]]                -> /p/No%20Such%20Page              no attribute, correctly
//	[[#A paragraph naming pages]]   -> #A%20paragraph%20naming%20pages  no attribute, correctly
//	[elsewhere](https://…)          -> https://example.invalid/notes    no attribute, correctly
//
// The three that are *supposed* to be absent are pinned here too, so a change
// that made one of them carry the attribute would have to argue for it rather
// than arrive silently. A dangling link has no page to preview; a link into the
// page it is written on is not a link to another page; an external link is not
// ours and must not be turned into a request.
//
// The fix was one function: the href is now built by md.LinkHref, which md
// exports so the rule has one owner, and the two sides are compared
// decoding-insensitively — the renderer escapes what it writes and requiring two
// encoders to agree byte for byte is requiring the second copy back.
//
// This fires in either direction, which is the point. A shape that starts
// previewing where it did not is a fix and is a failure here, so the fix has to
// come with its reasoning; a shape that stops is a regression and is also a
// failure. Both have to be looked at.
func TestTheLinkShapesThatPreviewArePinned(t *testing.T) {
	t.Parallel()

	fx := newPreviewFixture(t, previewVault)
	s := fx.asUser(playerName, playerPass)
	body := renderedPage(t, s, "/p/Hub.md", "A plain link", "A heading link", "A block reference", "A markdown link")

	for _, tc := range []struct {
		name     string
		marker   string
		previews bool
	}{
		{name: "a plain wikilink", marker: "A plain link", previews: true},
		{name: "a heading link", marker: "A heading link", previews: true},
		{name: "a block reference", marker: "A block reference", previews: true},
		{name: "an aliased link", marker: "An aliased link", previews: true},
		{name: "a subdirectory page", marker: "A page in a subdirectory", previews: true},
		{name: "a page with no title", marker: "A page with no title", previews: true},
		{name: "a markdown link", marker: "A markdown link", previews: true},
		{name: "a dangling link", marker: "A page that is not there", previews: false},
		{name: "a link into this page", marker: "A link into this page", previews: false},
		{name: "an external link", marker: "An external link", previews: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			link := theLink(t, body, tc.marker)
			if link.wikilink != tc.previews {
				t.Fatalf("the %q link renders as %q and carries the preview attribute: %v, want %v.\n"+
					"The record in the comment above names both directions: a shape that starts\n"+
					"previewing without a reason here is as much a failure as one that stops.",
					tc.marker, link.href, link.wikilink, tc.previews)
			}
		})
	}
}

// TestAPageLinkEverywhereInTheShellPreviews is the half of the feature that was
// missing outright, and the half a reader notices first.
//
// The attribute was put on a page's markdown links and on nothing else. Every
// internal page link the shell itself renders — the file tree, the dashboard's
// recent pages, a search hit, a backlink, a related page, an active thread, a
// party member, a session log, a broken-link row — carried no data-wikilink at
// all, so hovering any of them did nothing, for ever, with no error anywhere. One
// reader, on one page, got a preview from the link in the body and nothing from
// the panel beside it.
//
// The fix is web.Wikilink on each of those anchors. This test walks the panels
// rather than trusting the edit: it follows the attribute the panel emitted and
// asks the real route for the card, so an anchor that carries the attribute but
// the wrong one is a failure too.
func TestAPageLinkEverywhereInTheShellPreviews(t *testing.T) {
	t.Parallel()

	fx := newPreviewFixture(t, campaignFiles)
	s := fx.asUser(playerName, playerPass)

	for _, path := range []string{"/files", "/", "/search?q=tavern", "/p/Index.md", "/broken", "/tags"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			links := readEmittedLinks(renderedPage(t, s, path))
			var checked, followed int
			for _, l := range links {
				if !strings.HasPrefix(l.href, "/p/") {
					continue
				}
				// A sub-surface of a page is not a link to the page: /p/x/edit and
				// /p/x/raw have a page behind them and no card of their own, and a
				// preview there would answer a question the reader did not ask.
				if strings.Count(strings.TrimPrefix(l.href, "/p/"), "/") > 1 {
					continue
				}
				// A link to a page the index does not have is a dangling link, and
				// a dangling link carries no attribute for the same reason an
				// external one does: there is no page to name. campaignFiles holds
				// one on purpose, so the walk skips them rather than counting them
				// as pages it forgot to decorate.
				if _, err := store.GetPageByPath(context.Background(), fx0(s).DB.Reader(), strings.TrimPrefix(l.href, "/p/")); err != nil {
					continue
				}
				checked++
				if !l.wikilink {
					t.Errorf("%s links to %q as %q with no preview attribute: a reader hovers it and nothing happens", path, l.text, l.href)
					continue
				}
				// Three per page, and not one per link. The route budgets thirty
				// requests a minute per address by design, and a walk of every link
				// on five pages would spend the budget on the walk rather than on
				// anything being tested — the attribute is asserted for every link,
				// and following it is a spot check that the id names the page the
				// href does.
				if followed >= 3 {
					continue
				}
				followed++
				status, body := preview(t, s, l)
				if status != http.StatusOK {
					t.Errorf("%s: following the page's own link to %q answered %d, want 200", path, l.text, status)
					continue
				}
				// The card names the page the href names, not some other page the
				// id happens to resolve to.
				if name := pageNameOf(t, s, l.href); !strings.Contains(body, ">"+name+"<") {
					t.Errorf("%s: the card for the link to %q does not name %q: %s", path, l.text, name, body)
				}
			}
			if checked == 0 {
				t.Errorf("%s rendered no internal page link, so this test is asserting about nothing", path)
			}
		})
	}
}

// pageNameOf is the title the index holds for a page, read through the store
// rather than guessed from the href: a link whose attribute names a different page
// would still render a plausible card, and the point of following it is that the
// card is about the page the link went to.
// pageNameOf is the title the index holds for the page a link points at, read
// through the store rather than guessed from the href: a link whose attribute
// named some other page would still render a plausible card, and the point of
// following it is that the card is about the page the link went to.
//
// The bare/`.md` pair is the same lookup the router does, because an href names a
// page the way a URL does and the index stores the path with its extension.
func pageNameOf(t *testing.T, s *session, href string) string {
	t.Helper()
	path := strings.TrimPrefix(href, "/p/")
	for _, cand := range []string{path, path + ".md"} {
		row, err := store.GetPageByPath(context.Background(), fx0(s).DB.Reader(), cand)
		if err == nil {
			return row.Title
		}
	}
	t.Fatalf("no page row for %q, so a link to it cannot be checked", href)
	return ""
}

// fx0 is the fixture a session belongs to, for the two helpers that need the
// store rather than the client.
func fx0(s *session) *fixture { return s.fx }

// TestTheRefusalsAreTheSameBytesAsNavigatingToThePage is the requirement
// AGENTS.md §7 states, re-asserted with the real plugin rather than the double:
// a provider that is the shipped code over a real store is a different code path
// from a fixed one, and the refusal it produces is the one a reader would see.
//
// Three ways a page can be un-previewable, and each has to be the page's own 404
// byte for byte: a page that does not exist, a reader with no right to read public
// content, and a build with no provider at all.
func TestTheRefusalsAreTheSameBytesAsNavigatingToThePage(t *testing.T) {
	t.Parallel()

	t.Run("a page that does not exist", func(t *testing.T) {
		t.Parallel()
		fx := newPreviewFixture(t, previewVault)
		s := fx.asUser(playerName, playerPass)
		reference := navigate(t, s, "/p/NoSuchPage.md")
		if reference.status != http.StatusNotFound {
			t.Fatalf("the reference answered %d, want 404: this test compares a refusal against a refusal", reference.status)
		}
		for _, id := range []string{"999999", "0", "not-a-number", "-1", "1.5"} {
			sum := navigate(t, s, shellSummaryPath+id)
			if sum.body != reference.body {
				t.Errorf("a summary of %q is %d bytes and an ordinary 404 is %d: the two refusals are distinguishable", id, len(sum.body), len(reference.body))
			}
		}
	})

	t.Run("a reader with no right to read public content", func(t *testing.T) {
		t.Parallel()
		// Anonymous read off, so the principal the session middleware installs is
		// one that may read nothing. The route's own gate answers first, with the
		// redirect to the sign-in page, and the page answers with the same one —
		// which is the shape the comparison has to be able to hold: "the same
		// answer" is not the same as "a 404".
		fx := newPreviewFixture(t, previewVault, func(c *config.Config) { c.AllowAnonymousRead = false })
		anon := fx.newSession()
		row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), "Tavern.md")
		if err != nil {
			t.Fatalf("read the tavern's row: %v", err)
		}
		page := navigate(t, anon, "/p/Tavern.md")
		sum := navigate(t, anon, shellSummaryPath+strconv.FormatInt(row.ID, 10))
		if sum.body == page.body && sum.status == page.status {
			return
		}
		t.Errorf("an anonymous reader's summary of a real page is not what navigating to the page gives.\n got: %d %.80q\nwant: %d %.80q", sum.status, sum.body, page.status, page.body)
	})

	t.Run("a reader with anonymous read on", func(t *testing.T) {
		t.Parallel()
		// The one principal the demo-path tripwire cannot reach: an anonymous
		// browser with --allow-anonymous-read on, against a `table` secret. The
		// table case is the one `table` has no authentication term for, so a
		// summary here is a read of a secret-derived row by a principal that
		// never had a session.
		fx := newPreviewFixture(t, previewVault, func(c *config.Config) { c.AllowAnonymousRead = true })
		anon := fx.newSession()
		row, err := store.GetPageByPath(context.Background(), fx.DB.Reader(), "Tavern.md")
		if err != nil {
			t.Fatalf("read the tavern's row: %v", err)
		}
		sum := navigate(t, anon, shellSummaryPath+strconv.FormatInt(row.ID, 10))
		if sum.status == http.StatusOK {
			if !strings.Contains(sum.body, "The Drowned Lantern Inn") {
				t.Errorf("an anonymous reader with read on got a card without the page's title: %s", sum.body)
			}
			if strings.Contains(sum.body, "DM-BODY-TOKEN-7b1e4d") {
				t.Errorf("an anonymous reader with read on was served a dm secret's body: %s", sum.body)
			}
			return
		}
		refusesLikeThePage(t, "the tavern, to an anonymous reader with read on", sum, navigate(t, anon, "/p/Tavern.md"))
	})

	t.Run("a build with no provider registered", func(t *testing.T) {
		t.Parallel()
		fx := newFixturePlugins(t, previewVault, previewRegistry{})
		fx.accountsForAccounts()
		s := fx.asUser(playerName, playerPass)
		reference := navigate(t, s, "/p/NoSuchPage.md")
		sum := navigate(t, s, shellSummaryPath+"1")
		if sum.status != reference.status || sum.body != reference.body {
			t.Errorf("a build with no provider answers a summary with %d %.80q, and an ordinary 404 is %d %.80q", sum.status, sum.body, reference.status, reference.body)
		}
	})
}

// TestASummaryNeverCarriesASecretBody is the property the excerpt's source is
// supposed to give for free, asserted over the real plugin and the real store
// rather than over the component.
//
// page_text.body is written from md.Doc.PublicBody and nothing else, so a secret
// body is not in the table to be selected. That is a property of what is stored,
// not of a filter a caller has to remember — and the only way to know it still
// holds is to ask every principal, for pages carrying fences at each of the three
// visibilities, and look for the body token in the answer.
func TestASummaryNeverCarriesASecretBody(t *testing.T) {
	t.Parallel()

	files := map[string]string{}
	for name, body := range campaignFiles {
		files[name] = body
	}
	files["Mixed.md"] = "---\ntitle: Mixed\n---\n\nPublic lead-in.\n\n" +
		"```secret id=0f0f0f0f0f0f visibility=table author=dm created=2026-01-01T00:00:00Z title=\"Shared\"\n" +
		"TABLE-BODY-TOKEN-5d0a8f shared with the table\n```\n\nPublic tail.\n"

	tokens := []string{
		"PRIVATE-BODY-TOKEN-9f3a2c",
		"DM-BODY-TOKEN-7b1e4d",
		"OWNER-BODY-TOKEN-2a6e10",
		"TABLE-BODY-TOKEN-5d0a8f",
		"RUIN-BODY-TOKEN-2c8f61",
		"shared with the table",
	}

	// One fixture per role, because matrixRoles carries the anonymous-read
	// setting and that is a boot-time flag rather than a per-request one. Every
	// role is walked so that "no secret body" is a claim about the matrix and not
	// about the DM, who is entitled to every one of them.
	for _, role := range matrixRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			rfx := newPreviewFixture(t, files, func(c *config.Config) { c.AllowAnonymousRead = role.anonymousRead })
			s := rfx.newSession()
			if role.signIn != "" {
				resp := s.login(role.signIn, role.pass)
				defer drain(resp)
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("sign %s in: status %d, want 303", role.signIn, resp.StatusCode)
				}
			}
			var cards int
			for _, path := range []string{"Tavern.md", "Ruin.md", "Mixed.md"} {
				id, ok := rfx.pageIDByPath(path)
				if !ok {
					t.Fatalf("no page id for %s", path)
				}
				sum := navigate(t, s, shellSummaryPath+strconv.FormatInt(id, 10))
				for _, token := range tokens {
					if strings.Contains(sum.body, token) {
						t.Errorf("a summary of %s as %s carries %q", path, role.name, token)
					}
				}
				// The positive control, and the only thing that makes the sweep
				// above mean anything: a leak walk that found nothing because it
				// looked at nothing is indistinguishable from a clean one. So every
				// answer is either a card, or the page's own refusal.
				if strings.Contains(sum.body, "<article") {
					cards++
					continue
				}
				refusesLikeThePage(t, path+" as "+role.name, sum, navigate(t, s, "/p/"+path))
			}
			if role.signIn != "" && cards == 0 {
				t.Errorf("%s got no card for any of the three pages, so the token sweep proved nothing", role.name)
			}
		})
	}
}

// TestTheCardRendersSomethingForEveryPageItAccepts is the empty-state rule, over
// the four shapes a page can be in and a card still has to answer for.
//
// A page with no title of its own, a page whose body is nearly all fence, a page
// whose body is empty, and a page long enough to be clipped. Each has to come back
// as a card with a name, because a card whose heading is empty is a card that
// says nothing, and a reader who hovers a link is looking for the name of the
// thing behind it.
func TestTheCardRendersSomethingForEveryPageItAccepts(t *testing.T) {
	t.Parallel()

	fx := newPreviewFixture(t, map[string]string{
		// One target per paragraph, so the paragraph is what names the case: two
		// of these four links render the same words as each other once a title
		// falls back to a basename, and a test that found the wrong one would
		// still be green.
		"Hub.md": "---\ntitle: Hub\n---\n\nNo title of its own: [[Untitled]]\n\n" +
			"Mostly a fence: [[MostlySecret]]\n\n" +
			"Nothing at all: [[Blank]]\n\n" +
			"Long enough to clip: [[Long]]\n",
		"Untitled.md": "---\n---\n\nA page whose frontmatter carries no title at all.\n",
		"Blank.md":    "---\ntitle: Blank\n---\n",
		"MostlySecret.md": "---\ntitle: Mostly secret\n---\n\nPublic lead-in.\n\n" +
			"```secret id=bbb1bbb1bbb1 visibility=dm author=dm created=2026-01-01T00:00:00Z title=\"Kept\"\n" +
			"DM-BODY-TOKEN-7b1e4d hidden\n```\n",
		"Long.md": "---\ntitle: Long\n---\n\n" + strings.Repeat("A sentence of ordinary prose. ", 60),
	})
	s := fx.asUser(playerName, playerPass)
	page := renderedPage(t, s, "/p/Hub.md", "No title of its own", "Mostly a fence", "Nothing at all", "Long enough to clip")

	for _, marker := range []string{"No title of its own", "Mostly a fence", "Nothing at all", "Long enough to clip"} {
		t.Run(marker, func(t *testing.T) {
			t.Parallel()
			link := theLink(t, page, marker)
			status, card := preview(t, s, link)
			if status != http.StatusOK {
				t.Fatalf("the %q page's card answered %d, want 200", marker, status)
			}
			if !strings.Contains(card, "<article") {
				t.Fatalf("the %q page's answer is not a card: %s", marker, card)
			}
			if name := pageNameOf(t, s, link.href); !strings.Contains(card, ">"+name+"<") {
				t.Errorf("the card for the %q page does not name it as %q: %s", marker, name, card)
			}
			if strings.Contains(card, `card-heading font-semibold leading-snug"></h3>`) {
				t.Errorf("the card for the %q page has an empty heading: %s", marker, card)
			}
			if strings.Contains(card, "DM-BODY-TOKEN-7b1e4d") {
				t.Errorf("the card for the %q page carries a secret body: %s", marker, card)
			}
		})
	}
}

// TestTheSummaryIsAFragmentAndNotADataStarSwap settles the first hypothesis on
// the list, affirmatively and with a measurement, because "the response is not a
// valid DataStar swap payload" is the kind of thing that is true of a feature
// that works and worth ruling out explicitly rather than leaving to a reading.
//
// The shell does not ask for a fragment: it fetches the route with a plain
// Accept: text/html, parses the answer with DOMParser and puts the parsed nodes
// into the card. The route therefore has to answer a document fragment, and the
// Content-Type is what a client would branch on. Asserting both is what stops a
// future edit from turning it into a DataStar response: the swap would still
// render nothing, and a test that only inspected the body would pass.
func TestTheSummaryIsAFragmentAndNotADataStarSwap(t *testing.T) {
	t.Parallel()

	fx := newPreviewFixture(t, previewVault)
	s := fx.asUser(playerName, playerPass)
	link := theLink(t, renderedPage(t, s, "/p/Hub.md", "A plain link"), "A plain link")

	resp := s.do(s.get(shellSummaryPath + link.pageID))
	body := s.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type is %q, want text/html: the shell parses this answer with DOMParser, and a DataStar swap envelope would render nothing", ct)
	}
	for _, marker := range []string{"datastar-swap-id", "data-signals", "template-id"} {
		if strings.Contains(body, marker) {
			t.Errorf("the answer carries %q, so it is a DataStar swap rather than the fragment the shell parses", marker)
		}
	}
	if !strings.Contains(body, "<article") {
		t.Errorf("the answer is not a card body: %s", body)
	}
}
