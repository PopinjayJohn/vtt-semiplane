package httpapi_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
)

// editHrefAttr matches the attribute app.js's `e` key acts on. It is written
// out rather than shared with the client because the client is not a package
// this test can import, and the point of the assertion is the two agreeing on a
// string; a rename on either side that leaves the other matching nothing is the
// failure this catches.
var editHrefAttr = regexp.MustCompile(`data-edit-href="([^"]*)"`)

// TestTheEditLinkIsOfferedOnlyToAPrincipalWhoMayWrite is the server half of the
// `e` key.
//
// app.js navigates to whatever the page view put in a[data-edit-href] and does
// nothing at all when there is no such link, so the whole of the key's
// authorization is decided by whether that link is rendered: a link offered to a
// principal the editor would refuse is a control that lies, and a link withheld
// from one that may is a permission that exists only in a view model. Each case
// therefore asserts both halves of one fact — the link's presence, and what the
// editor answers for that same principal — so that a row cannot pass with the
// editor broken for everybody, which is the one state in which the negative
// half is true by accident.
func TestTheEditLinkIsOfferedOnlyToAPrincipalWhoMayWrite(t *testing.T) {
	t.Parallel()
	// Anonymous read is on so the anonymous row renders a page at all: a login
	// redirect carries no link because it carries no page, and that row would
	// then pass for a reason that has nothing to do with the editor.
	fx := newFixture(t, func(c *config.Config) { c.AllowAnonymousRead = true })
	fx.accountsFor()

	// The editor's URL for the page under test, written out rather than derived
	// from the same expression the handler uses: a change to that URL has to
	// fail this test rather than be agreed with by it.
	const editorHref = "/p/Tavern.md/edit"

	cases := []struct {
		name  string
		user  string
		pass  string
		anon  bool
		write bool
	}{
		{name: "admin", user: adminName, pass: adminPass, write: true},
		{name: "dm", user: dmName, pass: dmPass, write: true},
		// A page's owner is a player, and §8.9 exists so that a player may edit
		// the public parts of a page a DM has put a secret on. An edit link that
		// appeared only for a DM would be that feature unreachable from the page
		// it is about.
		{name: "page owner", user: playerName, pass: playerPass, write: true},
		{name: "player", user: otherName, pass: otherPass},
		{name: "anonymous", anon: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := fx.newSession()
			if !c.anon {
				resp := s.login(c.user, c.pass)
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("sign %s in: status %d, want 303", c.user, resp.StatusCode)
				}
				drain(resp)
			}

			page := s.getOK("/p/Tavern.md")
			links := editHrefAttr.FindAllStringSubmatch(page, -1)

			if !c.write {
				if len(links) != 0 {
					t.Errorf("a principal who may not write this page was offered %d edit links, the first to %q",
						len(links), links[0][1])
				}
				// The absence is a decision rather than a route that is broken
				// for everyone: the same URL, for the same principal, is refused.
				// The rows above are what make this meaningful — a 200 here would
				// be a working control this view model decided to hide.
				if status := s.status(s.get(editorHref)); status == http.StatusOK {
					t.Error("the editor answers 200 for a principal who may not write, so withholding the link hid a control that works")
				}
				return
			}

			if len(links) != 1 {
				t.Fatalf("a principal who may write this page was offered %d edit links, want exactly 1", len(links))
			}
			if links[0][1] != editorHref {
				t.Errorf("the edit link points at %q, want %q", links[0][1], editorHref)
			}
			// An ordinary link as well as the hook, because the affordance has to
			// work with this file blocked — the `e` key is an enhancement and
			// nothing on this page may exist only once JavaScript has run.
			if !strings.Contains(page, `href="`+editorHref+`"`) {
				t.Error("the edit affordance is a hook with no href, so it is not a link at all without JavaScript")
			}
			if status := s.status(s.get(editorHref)); status != http.StatusOK {
				t.Errorf("the offered edit link answers %d for a principal who may write this page, want 200", status)
			}
		})
	}
}
