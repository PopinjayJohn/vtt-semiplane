package sync

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// leakToken is a word that appears in the secret body and in nothing else. Every
// assertion in this file is "this token is not in there", which is only
// meaningful because nothing else in the corpus contains it.
const leakToken = "zephyrite"

// secretPage is a page whose secret fence holds a heading, a wikilink, a tag and
// a paragraph, so every derived row that could carry a leak is exercised.
func secretPage(id, visibility string) string {
	return fmt.Sprintf("# The Safe\n\nPublic before the fence, with a #public tag.\n\n"+
		"```secret id=%s visibility=%s author=dorn created=2026-09-28T10:04:11Z title=\"The %s\"\n"+
		"## Hidden chapter\n\nThe %s is kept in the vault. See [[The Safe]] and #hidden tag.\n"+
		"```\n\n## Public chapter\n\nAfter the fence, with a #public tag again.\n",
		id, visibility, visibility, leakToken)
}

// TestNoSecretEverEntersPageText is the test this package exists for.
//
// It asserts the whole chain rather than one table: the body of a secret that is
// not table-visible appears in no page_text row, matches no page_fts query,
// produces no snippet, and has no row in secret_text or secret_fts — and the
// moment the fence is flipped to `table` by an edit to the file, it appears in
// the secret index and still not in the public one. A fence is never public text
// however open it is; that is the difference between "revealed" and "written on
// the page".
func TestNoSecretEverEntersPageText(t *testing.T) {
	t.Parallel()
	for _, visibility := range []string{"private", "dm", "table"} {
		visibility := visibility
		t.Run(visibility, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, map[string]string{
				"The Safe.md": secretPage("abcdef012345", visibility),
			})
			h.indexAll()
			pageID := h.pageID("The Safe.md")
			const id = "abcdef012345"

			// The secret row itself exists, with the body verbatim. The
			// assertion is not that the secret is missing from the index; it is
			// that the *public* half of the index has never heard of it.
			if got := h.mustQueryString(`SELECT body FROM secrets WHERE id = ?`, id); !strings.Contains(got, leakToken) {
				t.Fatalf("the secret body was not stored: %q", got)
			}

			for _, q := range []struct{ name, query string }{
				{"page_text.body", `SELECT body FROM page_text WHERE page_id = ?`},
				{"page_text.title", `SELECT title FROM page_text WHERE page_id = ?`},
				{"page_text.headings", `SELECT headings FROM page_text WHERE page_id = ?`},
			} {
				if got := h.mustQueryString(q.query, pageID); strings.Contains(got, leakToken) {
					t.Errorf("the secret body reached %s: %q", q.name, got)
				}
			}
			if got := h.mustQueryString(`SELECT title FROM pages WHERE id = ?`, pageID); strings.Contains(got, leakToken) {
				t.Errorf("the secret body reached the page title: %q", got)
			}
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM headings WHERE page_id = ? AND text LIKE ?`,
				pageID, "%"+leakToken+"%"); n != 0 {
				t.Error("the secret body reached the headings table")
			}
			if hits := h.ftsHits("page_fts", leakToken); len(hits) > 0 {
				t.Errorf("the secret body is in page_fts (rowids %v)", hits)
			}
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, leakToken); n != 0 {
				t.Error("the secret body matches a public FTS query")
			}
			// A snippet is what a search result renders, so an FTS row that
			// matched but could not be rendered would still be a leak.
			var snippet string
			err := h.db.Reader().QueryRowContext(context.Background(),
				`SELECT snippet(page_fts, 2, '[', ']', '', 12) FROM page_fts WHERE page_fts MATCH ?`,
				leakToken).Scan(&snippet)
			if err == nil {
				t.Errorf("a public snippet was produced: %q", snippet)
			}
			if n, err := store.CheckSecretIndexInvariant(context.Background(), h.db.Reader()); err != nil || n != 0 {
				t.Errorf("the secret index invariant is %d, want 0 (%v)", n, err)
			}

			hidden := visibility != "table"
			if hidden {
				if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, id); n != 0 {
					t.Error("a hidden secret has a search-index row")
				}
				if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken); n != 0 {
					t.Error("a hidden secret is findable through secret_fts")
				}
			}

			// The heading and the link inside the fence are attributed to the
			// secret, which is what store.TOC and store.ListBacklinks filter on.
			if got := h.mustQueryString(
				`SELECT COALESCE(secret_id, '') FROM headings WHERE page_id = ? AND text = ?`,
				pageID, "Hidden chapter"); got != id {
				t.Errorf("the heading inside the fence is attributed to %q, want %q", got, id)
			}
			if got := h.mustQueryString(
				`SELECT COALESCE(secret_id, '') FROM links WHERE source_page_id = ? AND target_raw = ?`,
				pageID, "The Safe"); got != id {
				t.Errorf("the link inside the fence is attributed to %q, want %q", got, id)
			}
			if got := h.mustQueryString(
				`SELECT secret_id FROM page_tags WHERE page_id = ? AND tag = ?`, pageID, "hidden"); got != id {
				t.Errorf("the tag inside the fence is attributed to %q, want %q", got, id)
			}

			// A player must not see the chapter that lives inside a secret. For a
			// table-visible one the chapter is public knowledge; for a hidden one
			// its existence is itself the secret. Both cases are the canonical
			// predicate's answer and neither is this package's.
			player := h.principal("pia")
			toc, err := store.TOC(context.Background(), h.db.Reader(), player, pageID)
			if err != nil {
				t.Fatalf("toc: %v", err)
			}
			var sawHidden int
			for _, head := range toc {
				if strings.Contains(head.Text, "Hidden") {
					sawHidden++
				}
			}
			wantHidden := 0
			if visibility == "table" {
				wantHidden = 1
			}
			if sawHidden != wantHidden {
				t.Errorf("a player's table of contents shows the hidden chapter %d times, want %d",
					sawHidden, wantHidden)
			}
			// The link inside the fence is a backlink for a player who may read the
			// secret and not for one who may not, and the count has to agree with
			// the list in both cases.
			links, err := store.ListBacklinks(context.Background(), h.db.Reader(), player, pageID)
			if err != nil {
				t.Fatalf("backlinks: %v", err)
			}
			count, err := store.BacklinkCount(context.Background(), h.db.Reader(), player, pageID)
			if err != nil {
				t.Fatalf("backlink count: %v", err)
			}
			if len(links) != count {
				t.Errorf("a panel would list %d backlinks and count %d", len(links), count)
			}
			var selfLinks int
			for _, l := range links {
				if l.Page.Path == "The Safe.md" {
					selfLinks++
				}
			}
			wantSelf := 0
			if visibility == "table" {
				wantSelf = 1
			}
			if selfLinks != wantSelf {
				t.Errorf("a player sees %d links written inside the secret, want %d", selfLinks, wantSelf)
			}

			if visibility != "table" {
				return
			}
			// A revealed secret is findable, and findable only as a secret: the
			// fence is still a fence, so the body does not become page text.
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, id); n != 1 {
				t.Error("a table-visible secret was not put in the search index")
			}
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken); n != 1 {
				t.Error("a table-visible secret is not findable through secret_fts")
			}
			if err := h.db.Reader().QueryRowContext(context.Background(),
				`SELECT snippet(secret_fts, 0, '[', ']', '', 16) FROM secret_fts WHERE secret_fts MATCH ?`,
				leakToken).Scan(&snippet); err != nil {
				t.Errorf("no snippet for a revealed secret: %v", err)
			} else if !strings.Contains(snippet, leakToken) {
				t.Errorf("the snippet does not contain the term: %q", snippet)
			}
			if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, leakToken); n != 0 {
				t.Error("revealing a secret put it in the public index")
			}
		})
	}
}

// TestSecretIsFoundByThePublicIndexOnlyWhenRevealed flips one fence in the file
// and asserts the index follows the file, with no write from the app.
func TestSecretIsFoundByThePublicIndexOnlyWhenRevealed(t *testing.T) {
	t.Parallel()
	const id = "0f0f0f0f0f0f"
	h := newHarness(t, map[string]string{"The Safe.md": secretPage(id, "dm")})
	h.indexAll()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken); n != 0 {
		t.Fatal("a dm secret is findable before it was revealed")
	}
	beforeGen, err := store.MetaGetInt(context.Background(), h.db.Reader(), store.KeyAuthzGeneration)
	if err != nil {
		t.Fatalf("authz generation: %v", err)
	}

	// The DM edits the fence in Obsidian. Nothing in the app is involved.
	h.vault.WriteFile(t, "The Safe.md", secretPage(id, "table"))
	h.reconcile()

	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken); n != 1 {
		t.Fatal("an externally revealed secret did not reach the index")
	}
	if got := h.mustQueryString(`SELECT visibility FROM secrets WHERE id = ?`, id); got != "table" {
		t.Fatalf("the indexed visibility is %q, want table", got)
	}
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, leakToken); n != 0 {
		t.Error("a revealed secret reached the public index")
	}
	// An edit that changes who may read something is an authorization change,
	// and a stream carrying the old answer has to be torn down.
	afterGen, err := store.MetaGetInt(context.Background(), h.db.Reader(), store.KeyAuthzGeneration)
	if err != nil {
		t.Fatalf("authz generation: %v", err)
	}
	if afterGen <= beforeGen {
		t.Errorf("the authorization generation did not move: %d then %d", beforeGen, afterGen)
	}

	// And back again.
	h.vault.WriteFile(t, "The Safe.md", secretPage(id, "dm"))
	h.reconcile()
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, leakToken); n != 0 {
		t.Error("an externally revoked secret is still findable")
	}
	if n, err := store.CheckSecretIndexInvariant(context.Background(), h.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d, want 0 (%v)", n, err)
	}
}

// TestSecretIndexInvariantHolds indexes a mixed corpus and asserts store's own
// invariant check is clean: no hidden secret has a body in the search index.
func TestSecretIndexInvariantHolds(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Open.md":      secretPage("a1a1a1a1a1a1", "table"),
		"Closed.md":    secretPage("b2b2b2b2b2b2", "private"),
		"DM Only.md":   secretPage("c3c3c3c3c3c3", "dm"),
		"Two.md":       "# Two\n\n" + secretFence("111111111111", "dm", "dorn", "One hidden body.") + "\n" + secretFence("222222222222", "table", "mara", "One open body.") + "\nPlain tail.\n",
		"Unauthored":   "# Unauthored\n\n" + secretFence("333333333333", "dm", "nobody", "A body with an author that does not exist.") + "\n",
		"No Author.md": "# No Author\n\n```secret id=444444444444 visibility=dm\nA body with no author at all.\n```\n",
	})
	first := h.indexAll()

	if n, err := store.CheckSecretIndexInvariant(context.Background(), h.db.Reader()); err != nil || n != 0 {
		t.Fatalf("the secret index invariant is %d, want 0 (%v)", n, err)
	}
	// Every secret whose author is a real account is indexed; the two whose
	// author is not are recorded as problems and left out of the index, which is
	// a miss and not a leak.
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets`); n != 5 {
		t.Fatalf("expected five indexed secrets, got %d", n)
	}
	for _, id := range []string{"333333333333", "444444444444"} {
		if n := h.mustQueryInt(`SELECT COUNT(*) FROM secrets WHERE id = ?`, id); n != 0 {
			t.Errorf("a secret with an unusable author was indexed: %s", id)
		}
		if n := h.mustQueryInt(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, id); n != 0 {
			t.Errorf("a secret with an unusable author reached the search index: %s", id)
		}
	}
	// And the problem is reported rather than swallowed.
	var reported, reportedLeak int
	for _, r := range first.Indexed {
		for _, p := range r.Problems {
			if p.Code == ProblemAuthorUnknown && p.SecretID == "333333333333" {
				reported++
			}
			if p.SecretID == "333333333333" && strings.Contains(p.Message, "nobody") {
				reportedLeak++
			}
		}
	}
	if reported != 1 {
		t.Errorf("expected one unknown-author problem, got %d", reported)
	}
	if reportedLeak != 0 {
		t.Error("a problem message carried the directive's own value")
	}
	// A DM sees all of them; a player sees only the open one.
	dm := h.principal("dorn")
	player := h.principal("pia")
	rows, err := store.ListVisibleSecretRowsByPage(context.Background(), h.db.Reader(), dm, h.pageID("Two.md"))
	if err != nil {
		t.Fatalf("dm rows: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("a DM should see both secrets on the page, sees %d", len(rows))
	}
	rows, err = store.ListVisibleSecretRowsByPage(context.Background(), h.db.Reader(), player, h.pageID("Two.md"))
	if err != nil {
		t.Fatalf("player rows: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "222222222222" {
		t.Errorf("a player should see only the table-visible secret, sees %+v", rows)
	}
	count, err := store.CountVisibleSecrets(context.Background(), h.db.Reader(), player, h.pageID("Two.md"))
	if err != nil {
		t.Fatalf("player count: %v", err)
	}
	if count != len(rows) {
		t.Errorf("the panel would list %d secrets and count %d", len(rows), count)
	}
}

// TestPrivateSecretIsReadableByItsAuthorAndDMOnly documents the one ownership
// rule the indexer does not implement: page_owners is populated by the app, not
// by a frontmatter key, so a private secret on a fresh vault is readable by its
// author and by DMs only — and the canonical predicate is what says so.
func TestPrivateSecretIsReadableByItsAuthorAndDMOnly(t *testing.T) {
	t.Parallel()
	const id = "999999999999"
	h := newHarness(t, map[string]string{
		"Page.md": "# Page\n\n" + secretFence(id, "private", "pia", "A player-authored body.") + "\n",
	})
	h.seedUser("pia2", "player")
	h.indexAll()
	pageID := h.pageID("Page.md")
	if n := h.mustQueryInt(`SELECT COUNT(*) FROM page_owners WHERE page_id = ?`, pageID); n != 0 {
		t.Fatal("the indexer invented a page owner")
	}
	for _, tc := range []struct {
		name  string
		who   string
		shown bool
	}{
		{"the author", "pia", true},
		{"a dm", "dorn", true},
		{"an admin", "mara", true},
		{"another player", "pia2", false},
		{"an anonymous visitor", "", false},
	} {
		who := h.principal(tc.who)
		row, err := store.GetVisibleSecret(context.Background(), h.db.Reader(), who, id)
		switch {
		case err == nil && !tc.shown:
			t.Errorf("%s can read a private secret they must not", tc.name)
		case err != nil && tc.shown:
			t.Errorf("%s cannot read a private secret they may: %v", tc.name, err)
		case err == nil && row.Body == "":
			t.Errorf("%s got an empty body for a secret they may read", tc.name)
		}
	}
}
