package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// The stage-2 fixture.
//
// Every page, tag and secret here exists to make one authorization rule
// separable from the next. A tag is written publicly on some pages and only
// inside a secret on others, at each of the three visibilities; the private
// one is authored by one player and its page co-owned by the other, so the
// rule's two routes cannot be confused for each other; one character sheet has
// a flagged primary owner, one has only an unflagged owner row, and one has no
// owner at all.

// stage2Actor is one of the principals the fixture is evaluated under.
type stage2Actor struct {
	name      string
	principal authz.Principal
}

type stage2Fixture struct {
	db *DB
	// ids keyed by a short name: cellar, gamma, partyAlice and so on.
	ids  map[string]int64
	dm   int64
	coer int64
	auth int64
	// The accounts' login names. They appear in no title, no path and no
	// display name, so a test can assert one is absent from a whole rendered
	// PartyMember without the assertion being ambiguous.
	coerLogin string
	authLogin string
	dmLogin   string
}

func newStage2Fixture(t *testing.T) *stage2Fixture {
	t.Helper()
	ctx := context.Background()
	db := newMigratedDB(t)
	tx, err := db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	f := &stage2Fixture{db: db, ids: map[string]int64{}}
	f.dm = stage2Account(t, tx, "dm_the_keeper", "The Keeper", "dm")
	f.coer = stage2Account(t, tx, "zeta_one", "Alice the Bold", "player")
	f.auth = stage2Account(t, tx, "kappa_two", "Bob the Bold", "player")
	f.dmLogin, f.coerLogin, f.authLogin = "dm_the_keeper", "zeta_one", "kappa_two"

	at := time.Unix(1750000000, 0).UTC()
	page := func(key, path, title, pageType string) int64 {
		t.Helper()
		id := stage2Page(t, tx, path, title, pageType, at)
		f.ids[key] = id
		return id
	}

	page("index", "Index.md", "Index", "note")
	page("campaign", "Campaign.md", "Campaign", "note")
	cellar := page("cellar", "Notes/Cellar.md", "Cellar", "note")
	page("alpha", "Notes/Alpha.md", "Alpha", "note")
	page("beta", "Notes/Beta.md", "Beta", "note")
	gamma := page("gamma", "Notes/Gamma.md", "Gamma", "note")
	delta := page("delta", "Notes/Delta.md", "Delta", "note")
	page("epsilon", "Notes/Epsilon.md", "Epsilon", "note")
	zeta := page("zeta", "Notes/Zeta.md", "Zeta", "note")
	page("partyAlice", "Party/Alice.md", "Alice", TypeCharacter)
	page("partyBob", "Party/Bob.md", "Bob", TypeCharacter)
	page("partyOla", "Party/Ola.md", "Ola", TypeCharacter)
	page("partyUna", "Party/Una.md", "Una", TypeCharacter)
	page("partyWren", "Party/Wren.md", "Wren", TypeCharacter)

	// Cellar's dm secret carries a tag Cellar already carries in public, so a
	// query that forgets to collapse the two rows counts one page twice.
	stage2Secret(t, tx, "s00000000dm01", cellar, 0, authz.VisibilityDM, f.dm)
	stage2Secret(t, tx, "s00000000gm01", gamma, 0, authz.VisibilityDM, f.dm)
	stage2Secret(t, tx, "s00000000dl01", delta, 0, authz.VisibilityTable, f.dm)
	stage2Secret(t, tx, "s00000000zt01", zeta, 0, authz.VisibilityPrivate, f.auth)

	// Zeta's primary owner authored its private secret; alice co-owns the page
	// without authoring it, so "authored it" and "owns the page" are
	// separable. Party/Ola has two owner rows, only one of them flagged;
	// Party/Una has an owner row and nothing else, which is what the party
	// query's fallback is for. Party/Wren has none.
	stage2Owner(t, tx, zeta, f.auth, true, at)
	stage2Owner(t, tx, zeta, f.coer, false, at)
	stage2Owner(t, tx, f.ids["partyAlice"], f.coer, true, at)
	stage2Owner(t, tx, f.ids["partyBob"], f.auth, true, at)
	stage2Owner(t, tx, f.ids["partyOla"], f.coer, false, at)
	stage2Owner(t, tx, f.ids["partyOla"], f.auth, true, at)
	stage2Owner(t, tx, f.ids["partyUna"], f.coer, false, at)

	if err := ReplacePageTags(ctx, tx, cellar, []PageTag{
		{Tag: "shared", Source: TagFromFrontmatter},
		{Tag: TagOpenThread, Source: TagFromFrontmatter},
		{Tag: "dual", Source: TagFromFrontmatter},
		{Tag: "dual", Source: TagFromInline, SecretID: "s00000000dm01"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"alpha", "beta"} {
		if err := ReplacePageTags(ctx, tx, f.ids[key], []PageTag{
			{Tag: "shared", Source: TagFromFrontmatter},
			{Tag: TagOpenThread, Source: TagFromFrontmatter},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ key, secret string }{
		{"gamma", "s00000000gm01"},
		{"delta", "s00000000dl01"},
		{"zeta", "s00000000zt01"},
	} {
		if err := ReplacePageTags(ctx, tx, f.ids[tc.key], []PageTag{
			{Tag: "shared", Source: TagFromInline, SecretID: tc.secret},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ReplacePageTags(ctx, tx, f.ids["epsilon"], []PageTag{
		{Tag: TagOpenThread, Source: TagFromFrontmatter},
	}); err != nil {
		t.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f
}

// actors is every principal the fixture is evaluated under, in a fixed order so
// the subtest names are deterministic.
func (f *stage2Fixture) actors() []stage2Actor {
	return []stage2Actor{
		{"dm", authz.ForUser(f.dm, f.dmLogin, authz.RoleDM, false)},
		{"co_owner", authz.ForUser(f.coer, f.coerLogin, authz.RolePlayer, false)},
		{"author", authz.ForUser(f.auth, f.authLogin, authz.RolePlayer, false)},
		{"anonymous", authz.Anonymous(true)},
	}
}

func (f *stage2Fixture) principal(t *testing.T, name string) authz.Principal {
	t.Helper()
	for _, a := range f.actors() {
		if a.name == name {
			return a.principal
		}
	}
	t.Fatalf("no actor named %s", name)
	return authz.Principal{}
}

func stage2Page(t *testing.T, e Execer, path, title, pageType string, at time.Time) int64 {
	t.Helper()
	id, err := UpsertPage(context.Background(), e, Page{
		Path: path, Basename: trimExt(lastSegment(path)), Title: title,
		ContentHash: []byte("hash-" + path), MTimeUnix: at.Unix(), SizeBytes: 42,
		PageType: pageType, CreatedAt: at, UpdatedAt: at,
	})
	if err != nil {
		t.Fatalf("upsert page %s: %v", path, err)
	}
	return id
}

func stage2Account(t *testing.T, e Execer, username, displayName, role string) int64 {
	t.Helper()
	id, err := InsertUser(context.Background(), e, User{
		Username: username, DisplayName: displayName, Role: role,
		PWSalt: []byte("salt"), CreatedAt: time.Unix(1750000000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("insert account %s: %v", username, err)
	}
	return id
}

func stage2Owner(t *testing.T, e Execer, pageID, userID int64, isOwner bool, at time.Time) {
	t.Helper()
	if err := AddPageOwner(context.Background(), e, PageOwner{
		PageID: pageID, UserID: userID, IsOwner: isOwner, AddedAt: at,
	}); err != nil {
		t.Fatalf("grant page %d to user %d: %v", pageID, userID, err)
	}
}

func stage2Secret(t *testing.T, e Execer, id string, pageID int64, ordinal int, vis authz.Visibility, authorID int64) {
	t.Helper()
	at := time.Unix(1750000000, 0).UTC()
	if err := InsertSecret(context.Background(), e, Secret{
		ID: id, PageID: pageID, Ordinal: ordinal, Visibility: vis, AuthorID: authorID,
		Body: "body of " + id, BodyHash: []byte(id), CreatedAt: at, UpdatedAt: at,
	}); err != nil {
		t.Fatalf("insert secret %s: %v", id, err)
	}
}

func titles(pages []Page) []string {
	out := make([]string, 0, len(pages))
	for _, p := range pages {
		out = append(out, p.Title)
	}
	return out
}

func ids(pages []Page) []int64 {
	out := make([]int64, 0, len(pages))
	for _, p := range pages {
		out = append(out, p.ID)
	}
	return out
}

func containsPage(pages []Page, id int64) bool {
	for _, p := range pages {
		if p.ID == id {
			return true
		}
	}
	return false
}

func sameStrings(got, want []string) bool { return strings.Join(got, ",") == strings.Join(want, ",") }

// allTagNames reads the tags table directly, so "every tag" means every tag the
// fixture contains and not merely the ones a principal happens to be shown —
// the tag nobody may see is exactly the one that would drift.
func allTagNames(t *testing.T, q Queryer) []string {
	t.Helper()
	rows, err := q.QueryContext(context.Background(), `SELECT name FROM tags ORDER BY name`)
	if err != nil {
		t.Fatalf("read tags: %v", err)
	}
	var out []string
	err = ForEach(rows, func(r Rows) error {
		var name string
		if scanErr := r.Scan(&name); scanErr != nil {
			return fmt.Errorf("scan tag name: %w", scanErr)
		}
		out = append(out, name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTaggedPagesExcludeSecretOnlyTags is the rule the tag page exists to
// enforce: a page whose only occurrence of a tag sits inside a secret the
// viewer may not read is in neither the list nor the count.
func TestTaggedPagesExcludeSecretOnlyTags(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()

	// shared is public on Cellar, Alpha and Beta; dm-only on Gamma; table on
	// Delta; private on Zeta, authored by bob and co-owned by alice. The
	// `hidden` set below is the pages whose only `shared` the principal may not
	// read, and is asserted to be absent as well as counted at zero.
	for _, tc := range []struct {
		actor string
		want  []string
	}{
		{"dm", []string{"Alpha", "Beta", "Cellar", "Delta", "Gamma", "Zeta"}},
		{"co_owner", []string{"Alpha", "Beta", "Cellar", "Delta", "Zeta"}},
		{"author", []string{"Alpha", "Beta", "Cellar", "Delta", "Zeta"}},
		{"anonymous", []string{"Alpha", "Beta", "Cellar"}},
	} {
		t.Run(tc.actor, func(t *testing.T) {
			// Gamma's tag is dm-only, so no player sees it however much of
			// the vault they own; the table secret and the private one are off
			// the anonymous list as well.
			hidden := []int64{f.ids["gamma"]}
			if tc.actor == "anonymous" {
				hidden = append(hidden, f.ids["delta"], f.ids["zeta"])
			}
			if tc.actor == "dm" {
				// The DM reads every visibility, so nothing is hidden — and
				// the count proving it is 6 rather than 3.
				hidden = nil
			}
			p := f.principal(t, tc.actor)
			got, err := ListTaggedPages(ctx, f.db.Writer(), p, "shared")
			if err != nil {
				t.Fatal(err)
			}
			if !sameStrings(titles(got), tc.want) {
				t.Errorf("ListTaggedPages(shared) = %v, want %v", titles(got), tc.want)
			}
			n, err := CountTaggedPages(ctx, f.db.Writer(), p, "shared")
			if err != nil {
				t.Fatal(err)
			}
			if n != len(tc.want) {
				t.Errorf("CountTaggedPages(shared) = %d, want %d", n, len(tc.want))
			}
			if n != len(got) {
				t.Errorf("the count says %d and the list has %d rows; one of them is lying", n, len(got))
			}
			for _, gone := range hidden {
				if containsPage(got, gone) {
					t.Errorf("page %d is listed although its only `shared` is in a secret this principal may not read", gone)
				}
			}
		})
	}

	// dual is public on Cellar and, again, inside Cellar's own dm secret. Two
	// page_tags rows, one page: both answers are 1, for every principal,
	// including the DM who can see both rows.
	for _, actor := range f.actors() {
		t.Run("dual_is_one_page_for_"+actor.name, func(t *testing.T) {
			got, err := ListTaggedPages(ctx, f.db.Writer(), actor.principal, "dual")
			if err != nil {
				t.Fatal(err)
			}
			n, err := CountTaggedPages(ctx, f.db.Writer(), actor.principal, "dual")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || n != 1 {
				t.Errorf("dual: %d pages listed and a count of %d, want 1 and 1", len(got), n)
			}
		})
	}
}

// TestTagPagesAgreeWithTagCloud is the AGENTS.md §2.4 cross-check for this file,
// over every tag in the fixture rather than a hand-picked few: the number the
// tag cloud shows and the list the tag page shows are one predicate.
func TestTagPagesAgreeWithTagCloud(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()

	if tags := allTagNames(t, f.db.Writer()); len(tags) != 3 {
		t.Fatalf("the fixture holds tags %v, the assertions below assume three", tags)
	}
	for _, actor := range f.actors() {
		t.Run(actor.name, func(t *testing.T) {
			cloud := map[string]int{}
			for _, tc := range mustListTags(t, ctx, f.db.Writer(), actor.principal) {
				cloud[tc.Name] = tc.PageCount
			}
			for _, tag := range allTagNames(t, f.db.Writer()) {
				list, err := ListTaggedPages(ctx, f.db.Writer(), actor.principal, tag)
				if err != nil {
					t.Fatalf("list pages carrying %s: %v", tag, err)
				}
				n, err := CountTaggedPages(ctx, f.db.Writer(), actor.principal, tag)
				if err != nil {
					t.Fatalf("count pages carrying %s: %v", tag, err)
				}
				if n != len(list) {
					t.Errorf("tag %q: CountTaggedPages = %d but the list has %d rows", tag, n, len(list))
				}
				if want, offered := cloud[tag]; offered && want != n {
					t.Errorf("tag %q: the cloud says %d pages, the tag page says %d", tag, want, n)
				}
				seen := map[int64]bool{}
				for _, p := range list {
					if seen[p.ID] {
						t.Errorf("tag %q: page %d is listed twice", tag, p.ID)
					}
					seen[p.ID] = true
				}
			}
		})
	}
}

// TestAnonymousPrincipalSeesNoTableSecrets pins the one case where the
// canonical predicate on its own is wrong. It admits a table-visible secret on
// visibility with no authentication term, so the query below says the table
// secret is visible to an anonymous principal, while authz.CanReadSecret says
// it is not because the principal is unauthenticated. The tag query has to
// answer like the Go rule, and publicOnlySQL is the only reason it does.
func TestAnonymousPrincipalSeesNoTableSecrets(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()
	anon := authz.Anonymous(true)
	uid, isDM := anon.Bind()

	// The gap, shown rather than asserted. If this ever reads 0 the gap has been
	// closed upstream and the public-only term below is redundant, not wrong.
	bare := mustQueryInt(t, f.db.Writer(),
		`SELECT COUNT(*) FROM secrets s JOIN pages p ON p.id = s.page_id
		 WHERE s.id = ? AND `+authz.SecretVisibleSQL,
		"s00000000dl01", sql.Named("uid", uid), sql.Named("is_dm", isDM))
	if bare != 1 {
		t.Fatalf("the bare predicate admits the table secret to an anonymous principal (%d rows, want 1); "+
			"if it does not, this test's subject has moved", bare)
	}
	if authz.CanReadSecret(anon, false, f.dm, authz.VisibilityTable) {
		t.Fatal("authz.CanReadSecret admits a table secret to an anonymous principal")
	}

	// The query answers like the Go rule.
	list, err := ListTaggedPages(ctx, f.db.Writer(), anon, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if containsPage(list, f.ids["delta"]) {
		t.Error("the page whose only `shared` is table-visible is listed for an anonymous principal")
	}
	n, err := CountTaggedPages(ctx, f.db.Writer(), anon, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(list) {
		t.Errorf("the count says %d and the list has %d rows for an anonymous principal", n, len(list))
	}
	if n != 3 {
		t.Errorf("anonymous count = %d, want the 3 pages whose tag is public", n)
	}

	// An authenticated principal is entitled to the same row, which is what
	// makes the anonymous answer a judgement rather than a truncation.
	player := authz.ForUser(f.coer, f.coerLogin, authz.RolePlayer, false)
	playerList, err := ListTaggedPages(ctx, f.db.Writer(), player, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if !containsPage(playerList, f.ids["delta"]) {
		t.Error("a table-revealed tag is hidden from an authenticated player")
	}
}

func TestOpenThreadCountMatchesList(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()

	for _, actor := range f.actors() {
		t.Run(actor.name, func(t *testing.T) {
			n, err := CountOpenThreads(ctx, f.db.Writer(), actor.principal)
			if err != nil {
				t.Fatal(err)
			}
			// A window far wider than the fixture, so nothing is cut: the
			// count and the list must be the same set.
			list, err := ListOpenThreads(ctx, f.db.Writer(), actor.principal, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(list) {
				t.Errorf("CountOpenThreads = %d but the list has %d rows", n, len(list))
			}
			if n != 4 {
				t.Errorf("open threads = %d, want the 4 tagged pages", n)
			}
			// Every seeded page carries the same updated_at, so the ordering
			// falls through to p.id: cellar, alpha, beta, epsilon.
			if want := []string{"Cellar", "Alpha", "Beta", "Epsilon"}; !sameStrings(titles(list), want) {
				t.Errorf("threads = %v, want %v", titles(list), want)
			}
		})
	}

	t.Run("the count is over the whole set", func(t *testing.T) {
		p := f.principal(t, "dm")
		short, err := ListOpenThreads(ctx, f.db.Writer(), p, 1)
		if err != nil {
			t.Fatal(err)
		}
		n, err := CountOpenThreads(ctx, f.db.Writer(), p)
		if err != nil {
			t.Fatal(err)
		}
		if len(short) != 1 || n != 4 {
			t.Errorf("the windowed list has %d rows and the count is %d; "+
				"the count must not be len() of the window", len(short), n)
		}
	})
}

// TestRecentPagesExcludeIsNotAPostFilter separates two implementations that look
// identical unless the window is the point: a post-filter takes the top `limit`
// and then drops the excluded page, leaving a hole; a WHERE clause fills the
// window with the pages after it.
func TestRecentPagesExcludeIsNotAPostFilter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	p := authz.ForUser(seedUser(t, db.Writer(), "dm", "dm"), "dm", authz.RoleDM, false)

	base := time.Unix(1750000000, 0).UTC()
	newest := stage2Page(t, db.Writer(), "Newest.md", "Newest", "note", base.Add(2*time.Hour))
	middle := stage2Page(t, db.Writer(), "Middle.md", "Middle", "note", base.Add(time.Hour))
	oldest := stage2Page(t, db.Writer(), "Oldest.md", "Oldest", "note", base)

	t.Run("exclude zero excludes nothing", func(t *testing.T) {
		got, err := ListRecentPagesExcluding(ctx, db.Writer(), p, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("excludeID 0 returned %d pages, want all 3", len(got))
		}
		if got[0].ID != newest {
			t.Errorf("the first page is %d, want the most recently updated %d", got[0].ID, newest)
		}
	})

	t.Run("the exclusion is a where clause", func(t *testing.T) {
		got, err := ListRecentPagesExcluding(ctx, db.Writer(), p, newest, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("excluding the newest with a limit of 2 returned %d pages, want 2; "+
				"a post-filter would have left 1", len(got))
		}
		if !sameInts(ids(got), []int64{middle, oldest}) {
			t.Errorf("pages = %v, want middle then oldest", ids(got))
		}
	})
}

func sameInts(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestPartyReturnsDisplayNamesNotUsernames holds the reason the party query
// joins users at all, and only that column: a username is an account
// identifier, and the party sidebar is the one surface every reader of the
// campaign can see.
func TestPartyReturnsDisplayNamesNotUsernames(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()
	p := f.principal(t, "dm")

	party, err := ListParty(ctx, f.db.Writer(), p, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range party {
		got[m.Page.Title] = m.OwnerDisplayName
	}
	want := map[string]string{
		"Alice": "Alice the Bold",
		"Bob":   "Bob the Bold",
		// Two owner rows, and the flagged primary is Bob's.
		"Ola": "Bob the Bold",
		// One owner row, unflagged: the fallback picks it rather than
		// deciding the page is unowned.
		"Una": "Alice the Bold",
	}
	if len(got) != len(want) {
		t.Fatalf("party = %d members %v, want %d", len(party), got, len(want))
	}
	for name, display := range want {
		if got[name] != display {
			t.Errorf("%s is shown as %q, want the display name %q", name, got[name], display)
		}
	}
	if _, ok := got["Wren"]; ok {
		t.Error("a character sheet with no owner row was listed as a party member")
	}

	rendered := fmt.Sprintf("%+v", party)
	for _, login := range []string{f.coerLogin, f.authLogin, f.dmLogin} {
		if strings.Contains(rendered, login) {
			t.Errorf("the party list contains the username %q:\n%s", login, rendered)
		}
	}

	one, err := ListParty(ctx, f.db.Writer(), p, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Page.Title != "Alice" {
		t.Errorf("a limit of 1 returned %v, want Alice first by title", one)
	}
	if one[0].Page.PageType != TypeCharacter {
		t.Errorf("a party member is a %q page, want %q", one[0].Page.PageType, TypeCharacter)
	}
}

// TestRelatedPagesShareVisibleTags: a tag both pages carry only inside a secret
// the viewer may not read makes no relationship at all, and the order is total
// so the panel does not reshuffle between two renders of one state.
func TestRelatedPagesShareVisibleTags(t *testing.T) {
	t.Parallel()
	f := newStage2Fixture(t)
	ctx := context.Background()

	// Cellar carries shared and open-thread in public text, plus dual inside
	// its own dm secret. Alpha and Beta share two tags with it; the rest share
	// one, each of a kind only some principals can see.
	for _, tc := range []struct {
		actor string
		want  []string
	}{
		{"dm", []string{"Alpha", "Beta", "Delta", "Epsilon", "Gamma", "Zeta"}},
		{"co_owner", []string{"Alpha", "Beta", "Delta", "Epsilon", "Zeta"}},
		{"author", []string{"Alpha", "Beta", "Delta", "Epsilon", "Zeta"}},
		{"anonymous", []string{"Alpha", "Beta", "Epsilon"}},
	} {
		t.Run(tc.actor, func(t *testing.T) {
			got, err := ListRelatedPages(ctx, f.db.Writer(),
				f.principal(t, tc.actor), f.ids["cellar"], 100)
			if err != nil {
				t.Fatal(err)
			}
			if !sameStrings(titles(got), tc.want) {
				t.Errorf("related to Cellar = %v, want %v", titles(got), tc.want)
			}
			for _, pg := range got {
				if pg.ID == f.ids["cellar"] {
					t.Error("a page is related to itself")
				}
			}
		})
	}

	t.Run("the shared count is a count of tags", func(t *testing.T) {
		// Cellar's `dual` exists twice, once public and once in its dm secret.
		// Counting page_tags rows rather than distinct tags would score it
		// twice and reorder the list; the top entry must be Alpha at 2.
		got, err := ListRelatedPages(ctx, f.db.Writer(), f.principal(t, "dm"), f.ids["cellar"], 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Title != "Alpha" {
			t.Errorf("the top related page is %v, want Alpha", titles(got))
		}
	})

	t.Run("no shared visible tag is an empty list", func(t *testing.T) {
		got, err := ListRelatedPages(ctx, f.db.Writer(), f.principal(t, "dm"), f.ids["index"], 100)
		if err != nil {
			t.Fatalf("a page with no tags failed: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("related to an untagged page = %v, want nothing", titles(got))
		}
	})

	t.Run("a hidden secret makes no relationship", func(t *testing.T) {
		// Gamma's only tag is in a dm secret, so for a player there is
		// nothing to relate on; for the DM there is.
		player, err := ListRelatedPages(ctx, f.db.Writer(), f.principal(t, "author"), f.ids["gamma"], 100)
		if err != nil {
			t.Fatal(err)
		}
		if containsPage(player, f.ids["cellar"]) {
			t.Error("Cellar is related to Gamma for a player, through a dm secret")
		}
		dm, err := ListRelatedPages(ctx, f.db.Writer(), f.principal(t, "dm"), f.ids["gamma"], 100)
		if err != nil {
			t.Fatal(err)
		}
		if !containsPage(dm, f.ids["cellar"]) {
			t.Error("Cellar is not related to Gamma for the DM, who can read the secret")
		}
	})
}

// TestCommandPagesMatchesPrefixNotSubstring: the palette answers a prefix and
// nothing else, and the reader's own LIKE metacharacters are literals.
func TestCommandPagesMatchesPrefixNotSubstring(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	p := authz.ForUser(seedUser(t, db.Writer(), "dm", "dm"), "dm", authz.RoleDM, false)
	at := time.Unix(1750000000, 0).UTC()

	stage2Page(t, db.Writer(), "Notes/Cellar.md", "Cellar", "note", at)
	stage2Page(t, db.Writer(), "Notes/Under-Cellar.md", "Under-Cellar", "note", at)
	stage2Page(t, db.Writer(), "cellar-vault.md", "cellar-vault", "note", at)
	stage2Page(t, db.Writer(), "Notes/100% Water.md", "100% Water", "note", at)
	stage2Page(t, db.Writer(), "Notes/100X Water.md", "100X Water", "note", at)
	stage2Page(t, db.Writer(), "Notes/a_b.md", "a_b", "note", at)
	stage2Page(t, db.Writer(), "Notes/aXb.md", "aXb", "note", at)
	stage2Page(t, db.Writer(), `Notes/back\slash.md`, `back\slash`, "note", at)
	stage2Page(t, db.Writer(), "Notes/backslash.md", "backslash", "note", at)
	stage2Page(t, db.Writer(), "Zed.md", "Zed", "note", at)

	// Expected titles are in `ORDER BY p.title COLLATE NOCASE, p.id` order:
	// ASCII case-folded, so digits first, then '_' (0x5F) before 'b' before 'x'.
	for _, tc := range []struct {
		name   string
		prefix string
		want   []string
	}{
		{"a title prefix matches", "Cell", []string{"Cellar", "cellar-vault"}},
		{"a lower case prefix matches", "cellar-v", []string{"cellar-vault"}},
		{"a mid string does not match", "nder", nil},
		{"a path prefix matches", "Zed", []string{"Zed"}},
		{"path prefixes match too", "Notes/", []string{
			"100% Water", "100X Water", "a_b", "aXb", `back\slash`, "backslash", "Cellar", "Under-Cellar"}},
		{"a narrow path prefix matches", "Notes/a", []string{"a_b", "aXb"}},
		{"percent is a literal", "100%", []string{"100% Water"}},
		{"percent is not a wildcard", "100", []string{"100% Water", "100X Water"}},
		{"underscore is a literal", "a_", []string{"a_b"}},
		{"backslash is a literal", `back\`, []string{`back\slash`}},
		{"nothing matches", "nowhere", nil},
		{"an empty prefix returns nothing", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ListCommandPages(ctx, db.Writer(), p, tc.prefix, 100)
			if err != nil {
				t.Fatal(err)
			}
			if !sameStrings(titles(got), tc.want) {
				t.Errorf("prefix %q matched %v, want %v", tc.prefix, titles(got), tc.want)
			}
		})
	}
}

// TestLimitIsClamped: a limit is a page size, and a value the caller did not
// choose must not become SQLite's own reading of `LIMIT -1`, which is every row
// in the vault. The fixture is deliberately larger than the ceiling, so an
// unclamped value would show in the result length.
func TestLimitIsClamped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	p := authz.ForUser(seedUser(t, db.Writer(), "dm", "dm"), "dm", authz.RoleDM, false)
	at := time.Unix(1750000000, 0).UTC()

	total := maxListLimit + 5
	for i := range total {
		stage2Page(t, db.Writer(), "Palette/"+itoa(i)+".md", "Palette "+itoa(i), "note", at)
	}
	first := mustQueryInt(t, db.Writer(), `SELECT id FROM pages WHERE path = ?`, "Palette/0.md")

	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"an absurd limit is capped", 1 << 30, maxListLimit},
		{"a negative limit is not every row", -1, defaultListLimit},
		{"a zero limit is not every row", 0, defaultListLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ListCommandPages(ctx, db.Writer(), p, "Palette", tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Errorf("limit %d returned %d pages, want %d; the fixture holds %d",
					tc.limit, len(got), tc.want, total)
			}
		})
	}

	t.Run("every windowed query clamps", func(t *testing.T) {
		for _, limit := range []int{-1, 0, 1 << 20} {
			if _, err := ListOpenThreads(ctx, db.Writer(), p, limit); err != nil {
				t.Errorf("ListOpenThreads with limit %d: %v", limit, err)
			}
			if _, err := ListParty(ctx, db.Writer(), p, limit); err != nil {
				t.Errorf("ListParty with limit %d: %v", limit, err)
			}
			if _, err := ListRelatedPages(ctx, db.Writer(), p, first, limit); err != nil {
				t.Errorf("ListRelatedPages with limit %d: %v", limit, err)
			}
		}
		recent, err := ListRecentPagesExcluding(ctx, db.Writer(), p, 0, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(recent) != defaultListLimit {
			t.Errorf("recent pages = %d, want the default window %d", len(recent), defaultListLimit)
		}
		related, err := ListRelatedPages(ctx, db.Writer(), p, first, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if len(related) != 0 {
			t.Errorf("related to a page with no tags = %v, want nothing", titles(related))
		}
	})
}

// TestListAllPagesIsPathOrdered is the file tree's only requirement: one forward
// pass with no sorting in the handler, and a principal accepted today so the
// filter has a home when there is one.
func TestListAllPagesIsPathOrdered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newStage2Fixture(t)

	all, err := ListAllPages(ctx, f.db.Writer(), authz.Anonymous(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(f.ids) {
		t.Fatalf("ListAllPages = %d pages, want all %d of the fixture", len(all), len(f.ids))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Path > all[i].Path {
			t.Errorf("pages are not in path order: %q before %q", all[i-1].Path, all[i].Path)
		}
	}
	if all[0].Path != "Campaign.md" {
		t.Errorf("the first page is %q, want Campaign.md; the tree needs sorted input", all[0].Path)
	}
}
