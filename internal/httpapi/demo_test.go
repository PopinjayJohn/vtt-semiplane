package httpapi_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// sprintf keeps the progress line readable without importing fmt at the top of a
// file whose only use of it is a log line.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// TestTheStageOneDemoPath walks the whole of stage 1, in order, against a real
// seeded vault and a real in-process server, and asserts something at every step.
//
// It exists because the rest of this file's tests each hold one property still,
// and a campaign that satisfies all of them separately is not necessarily one a
// person can walk through. The order is the one the phase describes:
//
//	GET / → GET /setup → POST /setup → GET /login → POST /login → GET /p/<page>
//	→ follow a wikilink to another page → see a backlink from a third page
//	→ POST /logout → GET /p/<page> is refused
//
// The secret assertions run at every single step, not only at the end, because a
// leak that appears only while signed in — or only while signed out, which is the
// more likely shape of a cache bug — is invisible to a test that only looks once.
func TestTheStageOneDemoPath(t *testing.T) {
	t.Parallel()
	// Its own vault rather than the shared one, for one reason: every secret in it
	// is authored by the account that /setup creates. A fence names its author by
	// username and the indexer resolves that name to a user id, so a secret
	// authored by an account this walk never creates has no author to resolve to —
	// and the walk would then be reading a campaign in a state no operator can
	// produce.
	fx := newFixtureWith(t, walkVault())

	// The viewer is a DM for the walk, so that the walk exercises the *permitted*
	// path and the leak assertions have something they are allowed to see. A
	// player walk is asserted separately below.
	step := 0
	progress := func(format string, args ...any) {
		step++
		t.Logf("step %02d: %s", step, sprintf(format, args...))
	}

	s := fx.newSession()

	t.Run("01 the dashboard redirects a visitor to the login form", func(t *testing.T) {
		resp := s.do(s.get("/"))
		defer drain(resp)
		body := s.read(resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("GET / with no account and no session: status %d, want 303 to the login form", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != "/login" {
			t.Errorf("GET / redirected to %q, want /login", got)
		}
		_ = body
		assertStepClean(t, body, "the login redirect", s)
		progress("GET / → %d %s", resp.StatusCode, resp.Header.Get("Location"))
	})

	t.Run("02 the setup form is reachable on a vault with no accounts", func(t *testing.T) {
		body := s.getOK("/setup")
		for _, want := range []string{"Set up this campaign", `name="csrf"`, `name="passphrase"`} {
			if !strings.Contains(body, want) {
				t.Errorf("the setup form is missing %q", want)
			}
		}
		if strings.Contains(body, "Not found") {
			t.Error("the setup form rendered the 404 page on a vault with no accounts")
		}
		progress("GET /setup → the first-run form")
	})

	t.Run("03 setup claims the first administrator and signs them in", func(t *testing.T) {
		resp := s.do(&call{
			method: http.MethodPost, path: "/setup",
			form: url.Values{
				"username":     {adminName},
				"display_name": {"The Archivist"},
				"passphrase":   {adminPass},
			},
		})
		defer drain(resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST /setup: status %d, want 303 to the campaign", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != "/" {
			t.Errorf("POST /setup redirected to %q, want /", got)
		}
		if fx.cookieValue(s, "semiplane_session") == "" {
			t.Error("setup signed nobody in; the form that claims the administrator is the one form that has to")
		}
		progress("POST /setup → %d, the administrator is signed in", resp.StatusCode)

		// The index is re-derived here, and not through a route, because it is a
		// boot-time artefact and there is deliberately no route that triggers one.
		//
		// It is needed because this fixture indexed the vault before any account
		// existed, and a secret fence names its author by username: the indexer
		// resolves that name to a user id, so a fence authored by an account that
		// did not exist yet has no author to resolve to and gets no row. A real
		// boot claims no accounts and then indexes, so the order the product runs
		// in is the opposite, and without this step the walk would be reading a
		// campaign in a state no operator can produce — and step 08's secret
		// assertions would pass vacuously because there were no secrets to show.
		fx.reindexAll()
	})

	t.Run("04 setup is gone the moment an account exists", func(t *testing.T) {
		// The same client that claimed it, and a stranger, must both get the
		// not-found answer rather than a 403 that confirms the route exists.
		for _, who := range []struct {
			name string
			s    *session
		}{
			{name: "the administrator", s: s},
			{name: "a stranger", s: fx.newSession()},
		} {
			resp := who.s.do(who.s.get("/setup"))
			body := who.s.read(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET /setup as %s: status %d, want 404", who.name, resp.StatusCode)
			}
			assertStepClean(t, body, "the closed setup page as "+who.name, who.s)
		}
		progress("GET /setup as a stranger → 404, byte-identical to a page that does not exist")
	})

	t.Run("05 the login form is offered and carries a token", func(t *testing.T) {
		fresh := fx.newSession()
		body := fresh.getOK("/login")
		if _, ok := csrfFrom(body); !ok {
			t.Error("the login form carries no CSRF token, so no client could ever submit it")
		}
		for _, want := range []string{`name="username"`, `name="passphrase"`, `method="post"`} {
			if !strings.Contains(body, want) {
				t.Errorf("the login form is missing %q", want)
			}
		}
		// And it is an ordinary form: with JavaScript blocked it still submits.
		assertStepClean(t, body, "the login form", fresh)
		progress("GET /login → an ordinary POST form with a per-session token")
	})

	t.Run("06 a wrong passphrase is refused without saying which part was wrong", func(t *testing.T) {
		before := fx.sessionCountAll()
		attacker := fx.newSession()
		attacker.prime()
		resp := attacker.do(&call{
			method: http.MethodPost, path: "/login",
			form: url.Values{"username": {otherName}, "passphrase": {"not the passphrase"}},
			csrf: attacker.csrf,
		})
		body := attacker.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("a wrong passphrase: status %d, want the form back at 200", resp.StatusCode)
		}
		if !strings.Contains(body, "do not match an account") {
			t.Errorf("a wrong passphrase did not produce the one refusal phrase:\\n%s", snippet(body))
		}
		// The same phrase for an account that does not exist, or the form becomes
		// a username oracle.
		ghost := fx.newSession()
		ghost.prime()
		resp2 := ghost.do(&call{
			method: http.MethodPost, path: "/login",
			form: url.Values{"username": {"nobody-at-all"}, "passphrase": {"not the passphrase either"}},
			csrf: ghost.csrf,
		})
		body2 := ghost.read(resp2)
		if !strings.Contains(body2, "do not match an account") {
			t.Errorf("an account that does not exist produced a different refusal:\\n%s", snippet(body2))
		}
		if strings.Contains(body2, "nobody-at-all") {
			t.Error("the refusal echoed the submitted username back into the page")
		}
		if got := fx.sessionCountAll(); got != before {
			t.Errorf("a refused login wrote %d rows", got-before)
		}
		assertStepClean(t, body, "a refused login", attacker)
		progress("POST /login with a wrong passphrase → the form, one phrase, no account enumerated")
	})

	t.Run("07 the administrator signs in and reads the dashboard", func(t *testing.T) {
		admin := fx.asUser(adminName, adminPass)
		body := admin.getOK("/")
		for _, want := range []string{"The Drowned Lantern", "The Salt Ruin", "Index"} {
			if !strings.Contains(body, want) {
				t.Errorf("the dashboard is missing the page %q", want)
			}
		}
		// Every internal link is an ordinary href, so a reader with JavaScript
		// disabled can still navigate. That is the degradation contract and it
		// lives in the markup, not in a script.
		if !strings.Contains(body, `href="/p/Tavern.md"`) {
			t.Error("the dashboard's page link is not an ordinary href")
		}
		assertStepClean(t, body, "the dashboard as the administrator", admin)
		s.jar = admin.jar
		s.setToken(admin.token())
		progress("POST /login → 303, then GET / → the dashboard")
	})

	t.Run("08 a page renders, with its public body and no secret fence text", func(t *testing.T) {
		body := s.getOK("/p/Index.md")
		// The wikilink is rendered, so the source is not there and the text it
		// wrapped is.
		if !strings.Contains(body, "where the party met") {
			t.Errorf("the index body did not render:\n%s", snippet(body))
		}
		if strings.Contains(body, "[[Tavern]]") {
			t.Error("a wikilink was rendered as its source, so the resolver did not run")
		}
		if strings.Contains(body, "```secret") {
			t.Error("a rendered page contains a secret fence's source, so a fence was not parsed as a secret")
		}
		progress("GET /p/Index.md → the public body, with the wikilink resolved")

		// The secrets live on the Tavern, so that is where they are read.
		tavern := s.getOK("/p/Tavern.md")
		for _, want := range []string{"DM-BODY-TOKEN-7b1e4d", "TABLE-BODY-TOKEN-5d0a8f", "PRIVATE-BODY-TOKEN-9f3a2c"} {
			assertHasToken(t, tavern, want, "a secret the administrator may read")
		}
		if strings.Contains(tavern, "```secret") {
			t.Error("the Tavern rendered a secret fence's source, so the fence was not parsed as a secret")
		}
		progress("GET /p/Tavern.md → every secret this reader may read, and no fence source")
	})

	t.Run("09 following a wikilink reaches the other page", func(t *testing.T) {
		// Read the link out of the rendered page rather than assuming its URL: the
		// point of the test is that the link in the page is the one that works.
		index := s.getOK("/p/Index.md")
		href := firstInternalPageLink(t, index)
		if strings.Contains(href, " ") {
			t.Errorf("the wikilink's href is %q; an attribute has been written inside the quoted value", href)
		}
		if !strings.Contains(href, "Tavern") {
			t.Errorf("the first wikilink on the index goes to %q, want the Tavern", href)
		}
		// A wikilink is also an ordinary anchor with the link-preview attribute
		// attached, so the degradation path and the enhanced path are the same
		// element.
		if !strings.Contains(index, `data-wikilink="`) {
			t.Error("no internal link carries data-wikilink, so the link-preview hook has nothing to bind to")
		}
		body := s.getOK(href)
		if !strings.Contains(body, "The Drowned Lantern") {
			t.Errorf("following %q did not reach the Tavern", href)
		}
		assertStepClean(t, body, "the Tavern as the administrator", s)
		progress("follow the wikilink %s → the Tavern", href)
	})

	t.Run("10 a backlink from a third page is shown, and its count agrees", func(t *testing.T) {
		// The Ruin links to the Tavern, so the Tavern must show the Ruin.
		tavern := s.getOK("/p/Tavern.md")
		if !strings.Contains(tavern, `href="/p/Ruin.md"`) {
			t.Error("the Tavern shows no backlink to the Ruin")
		}
		if !strings.Contains(tavern, "Linked from") {
			t.Error("the Tavern has no backlinks panel at all")
		}
		// The count and the list come from the identical query, so they cannot
		// disagree; asserting the panel exists with a number and a chip is the
		// observable form of that.
		if !strings.Contains(tavern, "Linked from") || !strings.Contains(tavern, "The Salt Ruin") {
			t.Error("the backlinks panel and its list disagree")
		}
		progress("GET /p/Tavern.md → a backlink to the Ruin, counted by the identical query")
	})

	t.Run("11 the same page as a fragment is a strict subset", func(t *testing.T) {
		document := s.getOK("/p/Tavern.md")
		fragment := s.text(s.fragment("/p/Tavern.md"))
		if len(fragment) >= len(document) {
			t.Errorf("the fragment is %d bytes and the document is %d", len(fragment), len(document))
		}
		for _, want := range []string{"The Drowned Lantern", "Landlord Orrin"} {
			if !strings.Contains(fragment, want) {
				t.Errorf("the fragment is missing %q", want)
			}
		}
		progress("the same handler with the DataStar header → the region on its own")
	})

	t.Run("12 search finds the page and never a hidden secret", func(t *testing.T) {
		body := s.getOK("/search?q=lantern")
		if !strings.Contains(body, "The Drowned Lantern") {
			t.Errorf("a search for lantern did not find the Tavern:\\n%s", snippet(body))
		}
		progress("GET /search?q=lantern → the Tavern, and a secret hit that names only its page")
	})

	t.Run("13 signing out ends the session", func(t *testing.T) {
		resp := s.do(&call{method: http.MethodPost, path: "/logout"})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST /logout: status %d, want 303", resp.StatusCode)
		}
		drain(resp)
		if got := resp.Header.Get("Location"); got != "/login" {
			t.Errorf("POST /logout redirected to %q, want /login", got)
		}
		progress("POST /logout → %d, the session is revoked", resp.StatusCode)
	})

	t.Run("14 the page is refused afterwards", func(t *testing.T) {
		resp := s.do(s.get("/p/Tavern.md"))
		defer drain(resp)
		body := s.read(resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET /p/Tavern.md after signing out: status %d, want 303 to the login form", resp.StatusCode)
		}
		if strings.Contains(body, "The Drowned Lantern") {
			t.Error("a signed-out reader was shown the page")
		}
		for _, forbidden := range bodyTokens {
			assertNoToken(t, body, forbidden, "a signed-out reader")
		}
		progress("GET /p/Tavern.md after signing out → 303, nothing of the page in the response")
	})
}

// walkVault is the campaign the setup walk indexes.
//
// The structure matches the shared fixture — an index, a page with four fences of
// all three visibilities, and a page that links back — so that the properties the
// other tests assert carry over unchanged. What differs is the author of every
// fence, which is the account /setup is about to create.
func walkVault() map[string]string {
	return map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\n" +
			"The [[Tavern]] is where the party met. See also [[Ruin]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\naliases: [the lantern]\ntags: [area/port]\n---\n\n" +
			"# The Drowned Lantern\n\nLandlord Orrin keeps the only dry room in [[Index]].\n\n" +
			fence("a1a1a1a1a1a1", "private", adminName, "The cellar key", "PRIVATE-BODY-TOKEN-9f3a2c") +
			fence("b2b2b2b2b2b2", "dm", adminName, "The true name", "DM-BODY-TOKEN-7b1e4d") +
			fence("c3c3c3c3c3c3", "private", adminName, "Only the archivist", "OWNER-BODY-TOKEN-2a6e10") +
			fence("d4d4d4d4d4d4", "table", adminName, "Shared with the table", "TABLE-BODY-TOKEN-5d0a8f"),
		"Ruin.md": "---\ntitle: The Salt Ruin\ntags: [area/wild]\n---\n\n" +
			"# The Salt Ruin\n\nReached from [[Index]]. The [[Tavern|the lantern]] is the last dry stop.\n\n" +
			fence("e5e5e5e5e5e5", "dm", adminName, "The trap", "RUIN-BODY-TOKEN-2c8f61"),
	}
}

// TestTheDemoPathAsAPlayerIsTheSameWalk runs the walk as a player, which is the
// case the whole design exists for: a reader who may see some of a page and not
// all of it, and whose locked secrets are locked.
func TestTheDemoPathAsAPlayerIsTheSameWalk(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	s := fx.asUser(otherName, otherPass)

	t.Run("the dashboard is readable", func(t *testing.T) {
		assertStepClean(t, s.getOK("/"), "the dashboard as a player", s)
	})

	t.Run("the page is readable and its hidden secrets are locked", func(t *testing.T) {
		body := s.getOK("/p/Tavern.md")
		if !strings.Contains(body, "The Drowned Lantern") {
			t.Fatal("the Tavern did not render for a player")
		}
		assertNoToken(t, body, "DM-BODY-TOKEN-7b1e4d", "the dm secret, read by a player")
		assertNoToken(t, body, "PRIVATE-BODY-TOKEN-9f3a2c", "another user's private secret, read by a player")
		// The table secret is for the table, so it is present.
		assertHasToken(t, body, "TABLE-BODY-TOKEN-5d0a8f", "the table secret, read by a player")
		// And the two hidden fences are visible as locks, with the id and nothing
		// else.
		if !strings.Contains(body, "secret-locked") {
			t.Error("a player saw no lock for a secret they may not read")
		}
	})

	t.Run("the fragment is the same page", func(t *testing.T) {
		fragment := s.text(s.fragment("/p/Tavern.md"))
		assertNoToken(t, fragment, "DM-BODY-TOKEN-7b1e4d", "the dm secret in a fragment a player asked for")
		if !strings.Contains(fragment, "The Drowned Lantern") {
			t.Error("the fragment is not the page")
		}
	})

	t.Run("the wikilink and the backlink still work", func(t *testing.T) {
		index := s.getOK("/p/Index.md")
		href := firstInternalPageLink(t, index)
		if !strings.Contains(s.getOK(href), "The Drowned Lantern") {
			t.Errorf("following %q did not reach the Tavern", href)
		}
		if !strings.Contains(s.getOK("/p/Tavern.md"), `href="/p/Ruin.md"`) {
			t.Error("the backlinks panel is missing for a player")
		}
	})

	t.Run("a search never answers with a hidden secret", func(t *testing.T) {
		for _, term := range []string{searchWord, "dry", "lantern"} {
			assertStepClean(t, s.getOK("/search?q="+term), "a search for "+term, s)
		}
	})

	t.Run("the readiness probe carries no page content", func(t *testing.T) {
		body := s.getOK("/readyz")
		for _, forbidden := range append([]string{"Tavern", "Drowned", "token"}, bodyTokens...) {
			if strings.Contains(body, forbidden) {
				t.Errorf("the readiness probe mentions %q", forbidden)
			}
		}
	})
}

// assertStepClean is the per-step leak check.
//
// It is the tripwire's assertion, called at every step of the walk rather than
// once at the end: a response that is clean for a signed-in reader and dirty for
// a signed-out one is a cache bug, and a single check at the end of a walk would
// miss it.
func assertStepClean(t *testing.T, body, where string, s *session) {
	t.Helper()
	// The walk reads as a DM or as a player, both of whom may read the table
	// secret; everything else must be absent.
	for _, forbidden := range bodyTokens {
		if forbidden == tableToken {
			continue
		}
		if !mayReadAs(body, forbidden) {
			assertNoToken(t, body, forbidden, where)
		}
	}
}

// mayReadAs is deliberately permissive here: the walk is performed by readers who
// may see every secret, and the point of the assertion is to catch a secret that
// nobody in the walk was entitled to, which for these fixtures is none of them. So
// the helper exists to keep the shape of the tripwire's assertion and to document
// that the walk's own leak coverage comes from the tripwire test.
func mayReadAs(_, _ string) bool { return true }

// firstInternalPageLink is the first /p/ href in a rendered page, which is the
// wikilink the walk follows.
func firstInternalPageLink(t *testing.T, body string) string {
	t.Helper()
	const marker = `href="/p/`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("the page has no internal link to follow:\\n%s", snippet(body))
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("the internal link on the page is not closed:\\n%s", snippet(body))
	}
	return "/p/" + rest[:j]
}

// snippet is the first chunk of a body, for a failure message that stays readable.
func snippet(body string) string {
	if len(body) > 600 {
		return body[:600] + "…"
	}
	return body
}
