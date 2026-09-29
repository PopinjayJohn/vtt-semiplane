package httpapi_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The broken-links panel's kind filter (§5.6's dangling-reference surface, and
// the place a rename's suggestion is offered).
//
// One SQL fact is the whole difficulty, and it is the reason this test is here:
// `links.target_page_id IS NULL` is true of every attachment reference and every
// inline tag as well as of every dangling wikilink, because an image embed
// points at a file and a tag points at a tag. A panel built on that column alone
// lists the campaign's picture library as a list of mistakes and puts the number
// of attachments on its badge.
//
// The panel therefore reads store.ListVisibleUnresolvedLinks, whose statement
// excludes the two kinds, and reads its badge from store.CountVisibleUnresolvedLinks,
// which is a COUNT over the identical statement. Neither is re-spelled in
// broken.go, because a WHERE clause written twice is two clauses that will
// diverge — and a badge that disagrees with its own list is an existence leak
// with a number on it.
//
// The secret half of the panel — that a reference written only inside a dm
// secret is absent for a principal who may not read it — is
// TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks in pageroutes_test.go,
// which also asserts the badge against the list for every role. The two halves
// are split because they are different questions: one is about the kind filter
// and belongs to the rename that reads the same table, the other is about the
// canonical predicate and belongs with the panel's own tests.

// brokenPanelFixture is a page with one reference of every kind the panel has to
// handle: a public wikilink nobody can reach, an inline tag, two image embeds
// whose files are not pages, and a wikilink inside a dm secret.
const brokenPanelFixture = "---\ntitle: Waypoints\n---\n\n# Waypoints\n\n" +
	"A public dangling link: [[Nowhere-at-all]].\n" +
	"An inline tag: #Area/Port\n" +
	"An image: ![the village map](maps/village.png)\n" +
	"Another image in angle brackets: ![the coast](<maps/coast.png>)\n\n" +
	"```secret id=b1b1b1b1b1b1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The real lair\"\n" +
	"The lair is [[Lair-Of-The-Dragon]] and nobody may know.\n```\n"

// brokenPanelPublic is a dangling wikilink in public prose: the one reference of
// the three kinds the panel exists to show.
const brokenPanelPublic = "Nowhere-at-all"

// brokenPanelNotPageReferences are the strings the panel must not contain at all:
// an image path, an angle-bracketed image path, and an inline tag. Each has a
// NULL target_page_id for the same uninteresting reason, and each would appear in
// a panel built on that column alone.
var brokenPanelNotPageReferences = []string{
	"maps/village.png",
	"maps/coast.png",
	"#Area/Port",
}

// TestTheBrokenLinksPanelExcludesAttachmentsAndTags runs for every role that can
// see the page, because the kind filter is not a visibility question and a filter
// that only held for one role would be an accident.
//
// The assertions are on absence, which is the shape of this bug: there is nothing
// in the output to point at except the thing that should not be there. The last
// assertion is on presence, so the test above is not passing because the page
// rendered nothing.
func TestTheBrokenLinksPanelExcludesAttachmentsAndTags(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, map[string]string{
		"Waypoints.md": brokenPanelFixture,
	})
	fx.accountsForAccounts() // no Tavern.md in this fixture, so not accountsFor
	// The query the panel is built on, asserted directly.
	//
	// It is a separate subtest rather than a preamble because it is a separate
	// claim: the panel's HTTP half needs internal/web to have a
	// BrokenLinksView case, and while it does not, the *data* half is still
	// assertable and is the half that would be wrong if the kind filter were
	// missing. A test that can only fail for one reason is a test that reports
	// one thing.
	t.Run("the panel's own query carries the page reference and neither the image nor the tag", func(t *testing.T) {
		for _, tc := range []struct {
			username string
			pass     string
		}{
			{playerName, playerPass},
			{dmName, dmPass},
			{adminName, adminPass},
		} {
			who := fx.renamePrincipal(t, tc.username)
			rows, err := store.ListVisibleUnresolvedLinks(context.Background(), fx.DB.Reader(), who)
			if err != nil {
				t.Fatalf("%s: list the dangling references: %v", tc.username, err)
			}
			var targets []string
			for _, l := range rows {
				targets = append(targets, l.TargetRaw)
			}
			if !slices.Contains(targets, brokenPanelPublic) {
				t.Errorf("%s: the query does not return the public dangling reference, got %v", tc.username, targets)
			}
			for _, unwanted := range brokenPanelNotPageReferences {
				for _, got := range targets {
					if strings.Contains(got, strings.TrimPrefix(unwanted, "#")) {
						t.Errorf("%s: the query returns %q, whose target is a file or a tag and not a page", tc.username, got)
					}
				}
			}
		}
		// And the badge is a count over the identical statement, so a panel that
		// shows the first and counts the second is impossible by construction.
		dmRows, err := store.CountVisibleUnresolvedLinks(context.Background(), fx.DB.Reader(), fx.renamePrincipal(t, dmName))
		if err != nil {
			t.Fatalf("count the dangling references: %v", err)
		}
		dmList, err := store.ListVisibleUnresolvedLinks(context.Background(), fx.DB.Reader(), fx.renamePrincipal(t, dmName))
		if err != nil {
			t.Fatalf("list the dangling references: %v", err)
		}
		if dmRows != len(dmList) {
			t.Errorf("the count says %d and the list holds %d, and the two come from the same statement", dmRows, len(dmList))
		}
	})

	for _, tc := range []struct {
		name     string
		username string
		pass     string
	}{
		{name: "a player", username: playerName, pass: playerPass},
		{name: "a dm", username: dmName, pass: dmPass},
		{name: "an admin", username: adminName, pass: adminPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fx.asUser(tc.username, tc.pass)
			resp := s.do(s.get("/broken"))
			body := s.read(resp)
			if resp.StatusCode != http.StatusOK {
				// A 500 here is internal/web having no BrokenLinksView case, which
				// is a missing component rather than a filtering bug. The rendered
				// error page is six kilobytes of shell, so only the status is
				// worth printing.
				t.Fatalf("%s: GET /broken: status %d, want 200 (a 500 is a missing BrokenLinksView case in internal/web, not a filter)", tc.name, resp.StatusCode)
			}
			for _, unwanted := range brokenPanelNotPageReferences {
				if strings.Contains(body, unwanted) {
					t.Errorf("the broken-links panel lists %q, whose target is a file or a tag and not a page", unwanted)
				}
			}
			// The one reference the panel is for is still there.
			if !strings.Contains(body, brokenPanelPublic) {
				t.Errorf("the panel does not list the public dangling reference %q, so it is not rendering anything", brokenPanelPublic)
			}
		})
	}
}
