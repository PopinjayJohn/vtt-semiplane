package store

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// secretMeta is the fixture's own record of one secret, kept so the test can
// decide visibility from the §8.2 table rather than by asking the code under
// test.
type secretMeta struct {
	vis      authz.Visibility
	authorID int64
	owners   map[int64]bool
}

// expectVisible is §8.2's table, transcribed. It is written from the plan and
// not from authz or from the SQL, so a case where the two disagree is a real
// finding rather than a tautology.
func expectVisible(p authz.Principal, m secretMeta) bool {
	switch m.vis {
	case authz.VisibilityTable:
		return p.Authenticated()
	case authz.VisibilityPrivate:
		if !p.Authenticated() {
			return false
		}
		return p.IsDM() || p.UserID == m.authorID || m.owners[p.UserID]
	case authz.VisibilityDM:
		return p.IsDM()
	default:
		return false
	}
}

// matrixFixture is a small vault that exercises every route into the predicate:
// a public link, one link per visibility, a public heading and one per
// visibility, and a public tag and one per visibility.
//
// Everything hangs off sourcePage, which alice owns and carol co-owns, so the
// private rule's two routes — authored it, or own the page — are separable. A
// test that only checked authorship would pass against a rule that ignored page
// ownership, and vice versa.
type matrixFixture struct {
	db         *DB
	alice      int64
	dm         int64
	carol      int64
	bob        int64
	root       int64
	targetPage int64
	sourcePage int64
	secrets    map[authz.Visibility]secretMeta
	lines      map[authz.Visibility]int
	// otherTypedPage is a second page of the same frontmatter type, so the
	// by-type list and count have more than one row to agree about.
	otherTypedPage int64
	// summaryExcerpt is the public text every principal must see identically.
	summaryExcerpt string
	// secretTokens are the secret bodies seeded above. None of them may appear
	// in anything a principal is shown, whatever that principal may read.
	secretTokens map[string]bool
	// sharedAttachment is referenced from public text AND from a secret, which
	// is the case §8.8 says must still be served to everybody.
	sharedAttachment string
	// dmOnlyAttachment is referenced only from a dm secret, so only a dm or an
	// admin may be served it.
	dmOnlyAttachment string
	// unreferencedAttachment is recorded but referenced by nothing, and must
	// never be served: a file no link points at is a name a guesser found.
	unreferencedAttachment string
	// danglingPublic is the one dangling link written in public text.
	danglingPublic string
	// danglingInSecrets is the target of the dangling link inside each secret, so
	// a test can assert about the unfiltered read without repeating the fixture's
	// own naming.
	danglingInSecrets []string
}

func newMatrixFixture(t *testing.T) *matrixFixture {
	t.Helper()
	ctx := context.Background()
	db := newMigratedDB(t)
	tx, err := db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	f := &matrixFixture{
		db:      db,
		secrets: map[authz.Visibility]secretMeta{},
		lines:   map[authz.Visibility]int{},
	}
	f.dm = seedUser(t, tx, "dm", "dm")
	f.alice = seedUser(t, tx, "alice", "player")
	f.bob = seedUser(t, tx, "bob", "player")
	f.carol = seedUser(t, tx, "carol", "player")
	f.root = seedUser(t, tx, "root", "admin")

	f.targetPage = seedPage(t, tx, "Target.md", "Target")
	f.sourcePage = seedPage(t, tx, "Source.md", "Source")

	at := time.Unix(1750000000, 0).UTC()
	owners := map[int64]bool{f.alice: true, f.carol: true}
	for _, u := range []int64{f.alice, f.carol} {
		if err := AddPageOwner(ctx, tx, PageOwner{
			PageID: f.sourcePage, UserID: u, IsOwner: u == f.alice, AddedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}

	line := 1
	target := f.targetPage
	if _, err := InsertLink(ctx, tx, Link{
		SourcePageID: f.sourcePage, TargetPageID: &target,
		TargetRaw: "[[Target]]", Kind: LinkWikilink, Line: line,
	}); err != nil {
		t.Fatal(err)
	}
	publicLine := line

	var tags []PageTag
	tags = append(tags, PageTag{Tag: "tag-public", Source: TagFromFrontmatter})
	if err := InsertHeading(ctx, tx, Heading{
		PageID: f.sourcePage, Ordinal: 100, Level: 1, Slug: "public", Text: "public heading",
	}); err != nil {
		t.Fatal(err)
	}

	// §8.8's three attachments, seeded before the links that reference them so
	// the join in AttachmentVisibleTo has something on both sides.
	f.sharedAttachment = "assets/shared.png"
	f.dmOnlyAttachment = "assets/dm-only.png"
	f.unreferencedAttachment = "assets/unreferenced.png"
	for _, path := range []string{f.sharedAttachment, f.dmOnlyAttachment, f.unreferencedAttachment} {
		if _, err := InsertAttachment(ctx, tx, Attachment{
			PageID: &f.sourcePage, Path: path, Mime: "image/png", SizeBytes: 128,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := InsertLink(ctx, tx, Link{
		SourcePageID: f.sourcePage, TargetRaw: f.sharedAttachment,
		Kind: LinkAttachment, Line: 70,
	}); err != nil {
		t.Fatal(err)
	}

	for i, vis := range []authz.Visibility{authz.VisibilityDM, authz.VisibilityPrivate, authz.VisibilityTable} {
		id := "secret" + itoa(i)
		if err := InsertSecret(ctx, tx, Secret{
			ID: id, PageID: f.sourcePage, Ordinal: i, Visibility: vis,
			AuthorID: f.alice, Body: "needle " + string(vis),
			BodyHash: []byte(id), CreatedAt: at, UpdatedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
		f.secrets[vis] = secretMeta{vis: vis, authorID: f.alice, owners: owners}
		line++
		f.lines[vis] = line
		if _, err := InsertLink(ctx, tx, Link{
			SourcePageID: f.sourcePage, TargetPageID: &target,
			TargetRaw: "[[Target]]", Kind: LinkWikilink, SecretID: id, Line: line,
		}); err != nil {
			t.Fatal(err)
		}
		// A dangling reference per secret, on a line of its own so the panel's
		// ordering cannot be confused with the resolved links above. It carries
		// no target_page_id at all, which is what makes it a broken link rather
		// than a link to a page that is missing from the fixture.
		dangling := "[[Nowhere-" + id + "]]"
		f.danglingInSecrets = append(f.danglingInSecrets, dangling)
		if _, err := InsertLink(ctx, tx, Link{
			SourcePageID: f.sourcePage, TargetRaw: dangling,
			Kind: LinkWikilink, SecretID: id, Line: 50 + i,
		}); err != nil {
			t.Fatal(err)
		}
		// The two attachment references that decide §8.8's two halves: one file
		// referenced from public text and from a private secret, one referenced
		// only from the dm secret.
		if vis == authz.VisibilityPrivate || vis == authz.VisibilityDM {
			att := f.sharedAttachment
			if vis == authz.VisibilityDM {
				att = f.dmOnlyAttachment
			}
			if _, err := InsertLink(ctx, tx, Link{
				SourcePageID: f.sourcePage, TargetRaw: att,
				Kind: LinkAttachment, SecretID: id, Line: 60 + i,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := InsertHeading(ctx, tx, Heading{
			PageID: f.sourcePage, Ordinal: i, Level: 2, Slug: "h" + id,
			Text: "heading " + string(vis), SecretID: id,
		}); err != nil {
			t.Fatal(err)
		}
		tags = append(tags, PageTag{Tag: "tag-" + string(vis), Source: TagFromInline, SecretID: id})
	}
	if err := ReplacePageTags(ctx, tx, f.sourcePage, tags); err != nil {
		t.Fatal(err)
	}

	// The broken-links panel needs one dangling link that is not inside a secret,
	// or every principal's list would be empty and the count would agree with
	// nothing.
	f.danglingPublic = "[[Nowhere-public]]"
	if _, err := InsertLink(ctx, tx, Link{
		SourcePageID: f.sourcePage, TargetRaw: f.danglingPublic,
		Kind: LinkWikilink, Line: 40,
	}); err != nil {
		t.Fatal(err)
	}

	// The public text row, which is what a link preview's excerpt is read from.
	//
	// It is written here by hand rather than through the indexer because this
	// fixture is about predicates, not about segmentation, and the property under
	// test is precisely that this column is secret-free: the same bytes for
	// every principal, whatever that principal may read. If the indexer were
	// involved the test would be asserting that it did its job, which is a real
	// and separate property — but a fixture that could not detect a secret body
	// in this column would not be testing the thing that matters here.
	f.summaryExcerpt = "The public text of the source page."
	f.secretTokens = map[string]bool{}
	for _, vis := range []authz.Visibility{authz.VisibilityDM, authz.VisibilityPrivate, authz.VisibilityTable} {
		f.secretTokens["needle "+string(vis)] = true
	}
	if err := ReplacePageText(ctx, tx, PageText{
		PageID: f.sourcePage, Title: "Source",
		Headings: "public heading", Body: f.summaryExcerpt,
	}); err != nil {
		t.Fatal(err)
	}

	// A second page of the same type, so the by-type pair has more than one row
	// to disagree about.
	f.otherTypedPage = seedPage(t, tx, "Rule.md", "Rule")
	if err := ReplacePageText(ctx, tx, PageText{
		PageID: f.otherTypedPage, Title: "Rule", Headings: "", Body: "A house rule.",
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{f.sourcePage, f.otherTypedPage} {
		if err := setPageType(ctx, tx, id, "houserule"); err != nil {
			t.Fatal(err)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = publicLine
	return f
}

// setPageType rewrites a page's frontmatter type, which seedPage cannot take as
// an argument because the two typed pages are seeded before the type is known.
func setPageType(ctx context.Context, e Execer, pageID int64, pageType string) error {
	_, err := e.ExecContext(ctx, `UPDATE pages SET page_type = ? WHERE id = ?`, pageType, pageID)
	return err
}

func (f *matrixFixture) principal(t *testing.T) map[string]authz.Principal {
	t.Helper()
	return map[string]authz.Principal{
		"dm":        authz.ForUser(f.dm, "dm", authz.RoleDM, false),
		"admin":     authz.ForUser(f.root, "root", authz.RoleAdmin, false),
		"author":    authz.ForUser(f.alice, "alice", authz.RolePlayer, false),
		"co_owner":  authz.ForUser(f.carol, "carol", authz.RolePlayer, false),
		"outsider":  authz.ForUser(f.bob, "bob", authz.RolePlayer, false),
		"anonymous": authz.Anonymous(true),
	}
}

// TestPredicateMatrixAgrees is the heart of §6.4: every query that can return a
// secret-derived row, evaluated as every principal in the fixture, and each
// result compared against §8.2's table transcribed by the test itself.
//
// The count/list agreement is asserted per principal rather than per secret,
// because that is where the leak would be: a panel that lists one row while
// counting three.
func TestPredicateMatrixAgrees(t *testing.T) {
	t.Parallel()
	f := newMatrixFixture(t)
	ctx := context.Background()

	for name, p := range f.principal(t) {
		t.Run(name, func(t *testing.T) {
			// Per-secret visibility.
			for vis, meta := range f.secrets {
				id := meta.secretID()
				_, err := GetVisibleSecret(ctx, f.db.Writer(), p, id)
				gotVisible := err == nil
				if want := expectVisible(p, meta); gotVisible != want {
					t.Errorf("%s secret: GetVisibleSecret ok = %v, want %v (err %v)",
						vis, gotVisible, want, err)
				}
				if !expectVisible(p, meta) && !errors.Is(err, ErrNoRows) {
					t.Errorf("%s secret: invisible secret reported %v, want ErrNoRows so its existence stays hidden",
						vis, err)
				}
				// authz.CanReadSecret is the Go policy; it must agree with the SQL.
				if want := authz.CanReadSecret(p, meta.owners[p.UserID], meta.authorID, meta.vis); want != expectVisible(p, meta) {
					t.Errorf("%s secret: authz.CanReadSecret = %v, want %v", vis, want, expectVisible(p, meta))
				}
			}

			// Backlinks: one public row plus one per visible secret.
			wantLinks := 1
			wantHeadings := 1
			wantTags := map[string]bool{"tag-public": true}
			for vis, meta := range f.secrets {
				if !expectVisible(p, meta) {
					continue
				}
				wantLinks++
				wantHeadings++
				wantTags["tag-"+string(vis)] = true
			}

			bl, err := ListBacklinks(ctx, f.db.Writer(), p, f.targetPage)
			if err != nil {
				t.Fatalf("list backlinks: %v", err)
			}
			if len(bl) != wantLinks {
				t.Errorf("%d backlinks, want %d", len(bl), wantLinks)
			}
			bc, err := BacklinkCount(ctx, f.db.Writer(), p, f.targetPage)
			if err != nil {
				t.Fatalf("count backlinks: %v", err)
			}
			if bc != len(bl) {
				t.Errorf("BacklinkCount = %d but the list has %d rows; the two disagree", bc, len(bl))
			}
			for _, b := range bl {
				if b.Page.ID != f.sourcePage {
					t.Errorf("backlink points at page %d, want the source page", b.Page.ID)
				}
			}

			toc, err := TOC(ctx, f.db.Writer(), p, f.sourcePage)
			if err != nil {
				t.Fatalf("toc: %v", err)
			}
			if len(toc) != wantHeadings {
				t.Errorf("%d toc rows, want %d", len(toc), wantHeadings)
			}
			hc, err := HeadingCount(ctx, f.db.Writer(), p, f.sourcePage)
			if err != nil {
				t.Fatalf("count toc: %v", err)
			}
			if hc != len(toc) {
				t.Errorf("HeadingCount = %d but the toc has %d rows", hc, len(toc))
			}
			secretByID := map[string]secretMeta{}
			for _, m := range f.secrets {
				secretByID[m.secretID()] = m
			}
			for _, h := range toc {
				if h.SecretID == "" {
					continue
				}
				m, ok := secretByID[h.SecretID]
				if !ok {
					t.Errorf("toc row carries unknown secret %q", h.SecretID)
					continue
				}
				if !expectVisible(p, m) {
					t.Errorf("toc exposes heading %q from a secret %s may not read", h.Text, m.vis)
				}
			}
			// Every row is an owner's page, so the visible-secret list agrees.
			rows, err := ListVisibleSecretRowsByPage(ctx, f.db.Writer(), p, f.sourcePage)
			if err != nil {
				t.Fatalf("list visible secrets: %v", err)
			}
			if len(rows) != wantHeadings-1 {
				t.Errorf("%d visible secrets, want %d", len(rows), wantHeadings-1)
			}
			if len(rows) > 0 && rows[0].ID == "" {
				t.Error("a SecretRow came back without an id")
			}
			vc, err := CountVisibleSecrets(ctx, f.db.Writer(), p, f.sourcePage)
			if err != nil {
				t.Fatal(err)
			}
			if vc != len(rows) {
				t.Errorf("CountVisibleSecrets = %d but the list has %d rows", vc, len(rows))
			}

			// The broken-links panel. A dangling reference written inside a
			// secret is a fact about that secret, so it is filtered before the
			// row exists; the count has to move with the list or the badge says
			// how many secrets a player cannot read.
			wantDangling := 1
			for _, meta := range f.secrets {
				if expectVisible(p, meta) {
					wantDangling++
				}
			}
			dangling, err := ListVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
			if err != nil {
				t.Fatalf("list visible unresolved links: %v", err)
			}
			if len(dangling) != wantDangling {
				t.Errorf("%d visible dangling links, want %d", len(dangling), wantDangling)
			}
			dc, err := CountVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
			if err != nil {
				t.Fatalf("count visible unresolved links: %v", err)
			}
			if dc != len(dangling) {
				t.Errorf("CountVisibleUnresolvedLinks = %d but the list has %d rows; a badge would disagree with the list beside it",
					dc, len(dangling))
			}
			for _, l := range dangling {
				if l.SecretID == "" {
					continue
				}
				m, ok := secretByID[l.SecretID]
				if !ok {
					t.Errorf("a dangling link carries unknown secret %q", l.SecretID)
					continue
				}
				if !expectVisible(p, m) {
					t.Errorf("the broken-links panel exposes a dangling link from a %s secret this principal may not read",
						m.vis)
				}
			}

			// §8.8's attachment rule, whose two halves are different answers and
			// not one rule with a special case. A file referenced from public
			// text stays servable even though a secret also references it, and a
			// file referenced only from a dm secret is servable by exactly the
			// principals who may read that secret. The unreferenced file is the
			// third answer: nothing points at it, so guessing its name reaches
			// nothing.
			for _, tc := range []struct {
				name string
				want bool
			}{
				{f.sharedAttachment, true},
				{f.dmOnlyAttachment, expectVisible(p, f.secrets[authz.VisibilityDM])},
				{f.unreferencedAttachment, false},
			} {
				got, attachmentVisibleToErr := AttachmentVisibleTo(ctx, f.db.Writer(), p, f.sourcePage, tc.name)
				if attachmentVisibleToErr != nil {
					t.Fatalf("attachment %s: %v", tc.name, attachmentVisibleToErr)
				}
				if got != tc.want {
					t.Errorf("attachment %s visible = %v, want %v", tc.name, got, tc.want)
				}
			}
			// A name that is not on this page answers the same way as one that
			// is hidden, because a route that could tell them apart would be a
			// route that confirms the existence of a DM's portrait.
			if got, attachmentVisibleToErr := AttachmentVisibleTo(ctx, f.db.Writer(), p, f.sourcePage, "assets/guessed.png"); attachmentVisibleToErr != nil || got {
				t.Errorf("a guessed attachment name is visible = %v (attachmentVisibleToErr %v), want false", got, attachmentVisibleToErr)
			}

			// Tag counts, which §6.4 also names.
			listed := map[string]bool{}
			for _, tc := range mustListTags(t, ctx, f.db.Writer(), p) {
				listed[tc.Name] = true
				if !wantTags[tc.Name] {
					t.Errorf("tag %q is listed but only appears in a secret this principal may not read", tc.Name)
				}
				if tc.PageCount != 1 {
					t.Errorf("tag %q count = %d, want 1", tc.Name, tc.PageCount)
				}
			}
			for want := range wantTags {
				if !listed[want] {
					t.Errorf("tag %q is missing from the list; the principal may read it", want)
				}
			}

			// The link preview's summary, which is the one place a plugin reads
			// page content, so it is the one place the matrix has to say
			// something about a body rather than a row.
			//
			// Two properties, and they are different. The tags on the card must
			// agree with wantTags, because a preview showing a tag the tag page
			// hides is the same leak with more steps. And the excerpt must be the
			// same for every principal, because it comes from a column that is
			// secret-free by construction — if it varied, something had put a
			// secret body in a public column, and every assertion above would
			// still have passed.
			summary, err := GetPageSummary(ctx, f.db.Writer(), p, f.sourcePage)
			if err != nil {
				t.Fatalf("get page summary: %v", err)
			}
			gotSummaryTags := map[string]bool{}
			for _, name := range summary.Tags {
				gotSummaryTags[name] = true
			}
			for name := range gotSummaryTags {
				if !wantTags[name] {
					t.Errorf("the summary shows tag %q, which only appears in a secret this principal may not read", name)
				}
			}
			for name := range wantTags {
				if !gotSummaryTags[name] {
					t.Errorf("the summary is missing tag %q, which this principal may read", name)
				}
			}
			if f.summaryExcerpt != "" && summary.Excerpt != f.summaryExcerpt {
				t.Errorf("the excerpt differs by principal.\n %s: %q\n %s: %q",
					name, summary.Excerpt, "another principal", f.summaryExcerpt)
			}
			for token := range f.secretTokens {
				if strings.Contains(summary.Excerpt, token) {
					t.Errorf("the summary excerpt carries a secret body token: %s", token)
				}
			}

			// A page that was never written is ErrNoRows and not a zero card, so
			// a caller cannot mistake "nothing here" for "an empty page".
			if _, getPageSummaryErr := GetPageSummary(ctx, f.db.Writer(), p, 999999); !errors.Is(getPageSummaryErr, ErrNoRows) {
				t.Errorf("a summary of a page that does not exist is %v, want ErrNoRows", getPageSummaryErr)
			}

			// The by-type pair, which is what a feature plugin reads a
			// frontmatter convention with. The agreement is the assertion: a list
			// of two and a badge saying one is the leak, and it is the reason both
			// statements come out of one constant.
			typed, err := ListPagesByType(ctx, f.db.Writer(), p, "houserule")
			if err != nil {
				t.Fatalf("list pages by type: %v", err)
			}
			tc, err := CountPagesByType(ctx, f.db.Writer(), p, "houserule")
			if err != nil {
				t.Fatalf("count pages by type: %v", err)
			}
			if tc != len(typed) {
				t.Errorf("CountPagesByType = %d but the list has %d rows; a badge would disagree with the list beside it",
					tc, len(typed))
			}
			// A principal who may not read public content sees neither rows nor
			// a count. The check is on the principal rather than in SQL, and
			// asserting it here is what stops someone "optimising" the guard away
			// as redundant on the grounds that the predicate already handles it.
			if !p.CanReadPublic() && len(typed) != 0 {
				t.Errorf("%d rows for a principal who may not read public content", len(typed))
			}
			for _, tc := range mustListTags(t, ctx, f.db.Writer(), p) {
				n, err := TagCountFor(ctx, f.db.Writer(), p, tc.Name)
				if err != nil {
					t.Fatal(err)
				}
				if n != tc.PageCount {
					t.Errorf("TagCountFor(%q) = %d, the list says %d", tc.Name, n, tc.PageCount)
				}
			}
		})
	}
}

func (m secretMeta) secretID() string {
	switch m.vis {
	case authz.VisibilityDM:
		return "secret0"
	case authz.VisibilityPrivate:
		return "secret1"
	default:
		return "secret2"
	}
}

func mustListTags(t *testing.T, ctx context.Context, q Queryer, p authz.Principal) []TagCount {
	t.Helper()
	tags, err := ListTags(ctx, q, p)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	return tags
}

func TestBacklinkCountMatchesList(t *testing.T) {
	t.Parallel()
	f := newMatrixFixture(t)
	ctx := context.Background()

	for _, p := range []authz.Principal{
		authz.ForUser(f.dm, "dm", authz.RoleDM, false),
		authz.ForUser(f.alice, "alice", authz.RolePlayer, false),
		authz.Anonymous(true),
	} {
		list, err := ListBacklinks(ctx, f.db.Writer(), p, f.targetPage)
		if err != nil {
			t.Fatal(err)
		}
		count, err := BacklinkCount(ctx, f.db.Writer(), p, f.targetPage)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(list) {
			t.Errorf("%s: count %d, list %d", p, count, len(list))
		}
		// The §6.4 ordering is by title, not by rowid, so a panel is stable.
		for i := 1; i < len(list); i++ {
			if list[i-1].Page.Title > list[i].Page.Title {
				t.Errorf("backlinks are not ordered by title: %q before %q",
					list[i-1].Page.Title, list[i].Page.Title)
			}
		}
	}
}

// TestTagCountsExcludeHiddenSecrets is the §6.4 tag-count rule: a tag that
// appears only inside a secret the principal may not read must not appear in
// their tag list, and must not be counted either.
func TestUpsertPagePreservesCreatedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	second := first.Add(72 * time.Hour)

	id, err := UpsertPage(ctx, db.Writer(), Page{
		Path: "a.md", Basename: "a", Title: "First", ContentHash: []byte("h1"),
		MTimeUnix: 100, SizeBytes: 10, CreatedAt: first, UpdatedAt: first,
	})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := UpsertPage(ctx, db.Writer(), Page{
		Path: "a.md", Basename: "a", Title: "Second", ContentHash: []byte("h2"),
		MTimeUnix: 200, SizeBytes: 20, CreatedAt: second, UpdatedAt: second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != id2 {
		t.Errorf("re-indexing a page changed its id: %d then %d", id, id2)
	}
	p, err := GetPageByID(ctx, db.Writer(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CreatedAt.Equal(first) {
		t.Errorf("created_at = %v, want %v; a re-index must not re-create a page", p.CreatedAt, first)
	}
	if p.Title != "Second" {
		t.Errorf("title = %q, want the updated value", p.Title)
	}
	if !p.UpdatedAt.Equal(second) {
		t.Errorf("updated_at = %v, want %v", p.UpdatedAt, second)
	}
	if _, err := GetPageByPath(ctx, db.Writer(), "a.md"); err != nil {
		t.Errorf("get by path: %v", err)
	}
	if _, err := GetPageByID(ctx, db.Writer(), 9999); !errors.Is(err, ErrNoRows) {
		t.Errorf("missing page error = %v, want ErrNoRows", err)
	}
}

func TestPageOwnershipAndAliases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	dm := seedUser(t, db.Writer(), "dm", "dm")
	alice := seedUser(t, db.Writer(), "alice", "player")
	page := seedPage(t, db.Writer(), "NPCs/Gundren.md", "Gundren")

	if ok, err := IsPageOwner(ctx, db.Writer(), page, alice); err != nil || ok {
		t.Errorf("IsPageOwner before grant = %v (err %v), want false", ok, err)
	}
	if err := AddPageOwner(ctx, db.Writer(), PageOwner{
		PageID: page, UserID: alice, IsOwner: true, AddedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := IsPageOwner(ctx, db.Writer(), page, alice); err != nil || !ok {
		t.Errorf("IsPageOwner after grant = %v (err %v), want true", ok, err)
	}
	// Granting twice must not fail; a re-index replays the owner set.
	if err := AddPageOwner(ctx, db.Writer(), PageOwner{
		PageID: page, UserID: alice, IsOwner: true, AddedAt: time.Now().UTC(),
	}); err != nil {
		t.Errorf("re-granting ownership: %v", err)
	}
	owners, err := ListPageOwners(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 {
		t.Errorf("owners = %d rows after a duplicate grant, want 1", len(owners))
	}
	pages, err := ListPagesForUser(ctx, db.Writer(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 || pages[0] != page {
		t.Errorf("ListPagesForUser = %v, want [%d]", pages, page)
	}
	byOwner, err := ListPagesByOwner(ctx, db.Writer(), dm)
	if err != nil {
		t.Fatal(err)
	}
	if len(byOwner) != 0 {
		t.Errorf("the DM owns nothing, got %d pages", len(byOwner))
	}
	if removePageOwnerErr := RemovePageOwner(ctx, db.Writer(), page, alice); removePageOwnerErr != nil {
		t.Fatal(removePageOwnerErr)
	}
	if ok, _ := IsPageOwner(ctx, db.Writer(), page, alice); ok {
		t.Error("ownership survived removal")
	}

	if addPageAliasErr := AddPageAlias(ctx, db.Writer(), page, "NPC-Gundren"); addPageAliasErr != nil {
		t.Fatal(addPageAliasErr)
	}
	if addPageAliasErr := AddPageAlias(ctx, db.Writer(), page, "NPC-Gundren"); addPageAliasErr != nil {
		t.Errorf("duplicate alias: %v", addPageAliasErr)
	}
	aliases, err := ListPageAliases(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 1 || aliases[0] != "NPC-Gundren" {
		t.Errorf("aliases = %v", aliases)
	}
	resolved, err := ListPagesByAlias(ctx, db.Writer(), "npc-gundren")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].ID != page {
		t.Errorf("alias resolution returned %d pages; alias lookup must be case-insensitive", len(resolved))
	}
	byBase, err := ListPagesByBasename(ctx, db.Writer(), "gundren")
	if err != nil {
		t.Fatal(err)
	}
	if len(byBase) != 1 {
		t.Errorf("basename lookup returned %d pages, want 1", len(byBase))
	}
}

func TestUnresolvedLinksAreKept(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	page := seedPage(t, db.Writer(), "Source.md", "Source")

	if _, err := InsertLink(ctx, db.Writer(), Link{
		SourcePageID: page, TargetRaw: "[[Nowhere]]", Kind: LinkWikilink, Line: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := InsertLink(ctx, db.Writer(), Link{
		SourcePageID: page, TargetPageID: &page, TargetRaw: "[[Source]]",
		Kind: LinkEmbed, Alias: "self", Line: 4,
	}); err != nil {
		t.Fatal(err)
	}
	unresolved, err := ListUnresolvedLinks(ctx, db.Writer())
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 1 || unresolved[0].TargetRaw != "[[Nowhere]]" {
		t.Fatalf("unresolved = %v, want just the dangling link", unresolved)
	}
	if n, countOutgoingLinksErr := CountOutgoingLinks(ctx, db.Writer(), page); countOutgoingLinksErr != nil || n != 1 {
		t.Errorf("dangling count = %d (countOutgoingLinksErr %v), want 1", n, countOutgoingLinksErr)
	}
	all, err := ListLinksByPage(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("links = %d, want 2", len(all))
	}
	if err := DeleteLinksByPage(ctx, db.Writer(), page); err != nil {
		t.Fatal(err)
	}
	if left, err := ListLinksByPage(ctx, db.Writer(), page); err != nil || len(left) != 0 {
		t.Errorf("links after delete = %d (err %v), want 0", len(left), err)
	}
}

func TestRevisionRetention(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	page := seedPage(t, db.Writer(), "Hist.md", "Hist")

	appendRevisions(t, db, page, string(RevisionApp), 60)
	appendRevisions(t, db, page, string(RevisionExternal), 12)

	removed, err := PruneRevisions(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	// 60 - 50 app + 12 - 5 external
	if removed != 17 {
		t.Errorf("pruned %d revisions, want 17", removed)
	}
	if n := mustQueryInt(t, db.Writer(),
		`SELECT COUNT(*) FROM revisions WHERE page_id = ? AND source = ?`, page, string(RevisionApp)); n != AppRevisionRetention {
		t.Errorf("app revisions = %d, want %d", n, AppRevisionRetention)
	}
	if n := mustQueryInt(t, db.Writer(),
		`SELECT COUNT(*) FROM revisions WHERE page_id = ? AND source = ?`, page, string(RevisionExternal)); n != ExternalRevisionRetention {
		t.Errorf("external revisions = %d, want %d", n, ExternalRevisionRetention)
	}

	// The survivors must be the newest ones, which the retention relies on the
	// text ordering of `at` to decide.
	all, err := ListRevisionsByPage(ctx, db.Writer(), page, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].At.Before(all[i].At) {
			t.Errorf("revisions are not newest-first: %v before %v", all[i-1].At, all[i].At)
		}
	}
	newest, err := GetRevision(ctx, db.Writer(), all[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if newest.Content != "app-59" {
		t.Errorf("newest revision content = %q, want the last one written", newest.Content)
	}
}

// appendRevisions writes n revisions, oldest first, one second apart.
func appendRevisions(t *testing.T, db *DB, pageID int64, source string, n int) {
	t.Helper()
	ctx := context.Background()
	base := time.Unix(1750000000, 0).UTC()
	for i := range n {
		if _, err := AppendRevision(ctx, db.Writer(), Revision{
			PageID:      pageID,
			ContentHash: []byte(source),
			Content:     source + "-" + itoa(i),
			At:          base.Add(time.Duration(i) * time.Second),
			Source:      RevisionSource(source),
		}); err != nil {
			t.Fatalf("append revision %d: %v", i, err)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestSelfwriteIsHashMatched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	now := time.Unix(1750000000, 0).UTC()
	hash := []byte("our-bytes")

	if err := RecordSelfwrite(ctx, db.Writer(), "a.md", hash, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := SelfwriteMatches(ctx, db.Writer(), "a.md", hash, now.Add(2*time.Second)); err != nil || !ok {
		t.Errorf("match inside the window = %v (err %v), want true", ok, err)
	}
	// A genuine external edit inside the window differs in hash and must land.
	if ok, err := SelfwriteMatches(ctx, db.Writer(), "a.md", []byte("theirs"), now.Add(time.Second)); err != nil || ok {
		t.Errorf("match on a different hash = %v (err %v), want false", ok, err)
	}
	if ok, err := SelfwriteMatches(ctx, db.Writer(), "a.md", hash, now.Add(time.Minute)); err != nil || ok {
		t.Errorf("match past the window = %v (err %v), want false", ok, err)
	}
	if ok, err := SelfwriteMatches(ctx, db.Writer(), "other.md", hash, now); err != nil || ok {
		t.Errorf("match on an unwritten path = %v (err %v), want false", ok, err)
	}
	if n, err := PruneSelfwrites(ctx, db.Writer(), now); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Errorf("pruned %d unexpired selfwrites, want 0", n)
	}
	if n, err := PruneSelfwrites(ctx, db.Writer(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("pruned %d expired selfwrites, want 1", n)
	}
}

func TestInviteIsSingleUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	dm := seedUser(t, db.Writer(), "dm", "dm")
	now := time.Unix(1750000000, 0).UTC()

	if err := InsertInvite(ctx, db.Writer(), Invite{
		TokenHash: "hash-1", Role: "player", CreatedBy: dm,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	bob := seedUser(t, db.Writer(), "bob", "player")
	if err := RedeemInvite(ctx, db.Writer(), "hash-1", bob, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := RedeemInvite(ctx, db.Writer(), "hash-1", bob, now.Add(2*time.Minute)); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("second redemption = %v, want ErrInviteUsed", err)
	}
	got, err := GetInviteByTokenHash(ctx, db.Writer(), "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Redeemed() || got.RedeemedBy == nil || *got.RedeemedBy != bob {
		t.Errorf("invite redemption not recorded: %+v", got)
	}

	// An expired invite cannot be redeemed at all.
	if err := InsertInvite(ctx, db.Writer(), Invite{
		TokenHash: "hash-2", Role: "player", CreatedBy: dm,
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := RedeemInvite(ctx, db.Writer(), "hash-2", bob, now); !errors.Is(err, ErrInviteUsed) {
		t.Errorf("redeeming an expired invite = %v, want ErrInviteUsed", err)
	}
	if pending, err := ListPendingInvites(ctx, db.Writer(), now); err != nil {
		t.Fatal(err)
	} else if len(pending) != 0 {
		t.Errorf("pending invites = %d, want 0", len(pending))
	}
}

func TestSessionLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	dm := seedUser(t, db.Writer(), "dm", "dm")
	now := time.Unix(1750000000, 0).UTC()

	if err := InsertSession(ctx, db.Writer(), Session{
		ID: "sha256-of-token", UserID: dm, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), LastSeenAt: now, UserAgent: "curl/8",
	}); err != nil {
		t.Fatal(err)
	}
	s, err := GetSession(ctx, db.Writer(), "sha256-of-token")
	if err != nil {
		t.Fatal(err)
	}
	if s.UserID != dm || s.UserAgent != "curl/8" {
		t.Errorf("session = %+v", s)
	}
	if err := TouchSession(ctx, db.Writer(), "sha256-of-token", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s, _ = GetSession(ctx, db.Writer(), "sha256-of-token"); !s.LastSeenAt.Equal(now.Add(time.Minute)) {
		t.Errorf("last_seen_at = %v, want the touched time", s.LastSeenAt)
	}
	if _, err := DeleteExpiredSessions(ctx, db.Writer(), now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := mustQueryInt(t, db.Writer(), `SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Errorf("an unexpired session was deleted (%d remain)", n)
	}
	if n, err := DeleteUserSessions(ctx, db.Writer(), dm); err != nil || n != 1 {
		t.Errorf("DeleteUserSessions = %d (err %v), want 1", n, err)
	}
}

func TestUserDisableAndDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	alice := seedUser(t, db.Writer(), "alice", "player")
	now := time.Unix(1750000000, 0).UTC()

	if err := SetUserRole(ctx, db.Writer(), alice, "dm"); err != nil {
		t.Fatal(err)
	}
	u, err := GetUserByID(ctx, db.Writer(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "dm" {
		t.Errorf("role = %q, want dm", u.Role)
	}
	if err := SetUserDisabled(ctx, db.Writer(), alice, &now); err != nil {
		t.Fatal(err)
	}
	if u, _ = GetUserByID(ctx, db.Writer(), alice); u.Active() {
		t.Error("a disabled account reports itself active")
	}
	if err := SetUserDisabled(ctx, db.Writer(), alice, nil); err != nil {
		t.Fatal(err)
	}
	if u, _ = GetUserByID(ctx, db.Writer(), alice); !u.Active() {
		t.Error("re-enabling did not clear disabled_at")
	}
	// Usernames are unique case-insensitively.
	if _, err := InsertUser(ctx, db.Writer(), User{
		Username: "ALICE", DisplayName: "x", Role: "player", PWSalt: []byte("s"),
		CreatedAt: now,
	}); err == nil {
		t.Error("a case-variant username was accepted")
	}
	if err := DeleteUser(ctx, db.Writer(), alice); err != nil {
		t.Fatal(err)
	}
	if _, err := GetUserByID(ctx, db.Writer(), alice); !errors.Is(err, ErrNoRows) {
		t.Errorf("deleted user error = %v, want ErrNoRows", err)
	}
}

func TestAttachmentScopeIsPerPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	page := seedPage(t, db.Writer(), "Villain.md", "Villain")

	if _, err := InsertAttachment(ctx, db.Writer(), Attachment{
		PageID: &page, Path: "assets/portrait.png", Mime: "image/png", SizeBytes: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := InsertAttachment(ctx, db.Writer(), Attachment{
		Path: "assets/orphan.png", Mime: "image/png", SizeBytes: 10,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := ListAttachmentsByPage(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "assets/portrait.png" {
		t.Errorf("attachments = %v; only the page's own are listed", got)
	}
	// The vault-level file has no page, which is exactly why the serve route is
	// page-scoped and resolves against this set.
	if a, err := GetAttachmentByPath(ctx, db.Writer(), "assets/orphan.png"); err != nil || a.PageID != nil {
		t.Errorf("orphan attachment = %+v (err %v), want a nil page", a, err)
	}
}

func TestPluginMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	now := time.Unix(1750000000, 0).UTC()

	for _, v := range []int{1, 2, 3} {
		if err := RecordPluginMigration(ctx, db.Writer(), PluginMigration{
			PluginID: "dnd5e", Version: v, AppliedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordPluginMigration(ctx, db.Writer(), PluginMigration{
		PluginID: "dnd5e", Version: 3, AppliedAt: now,
	}); err != nil {
		t.Errorf("re-recording a migration: %v", err)
	}
	if v, err := AppliedPluginVersion(ctx, db.Writer(), "dnd5e"); err != nil || v != 3 {
		t.Errorf("applied version = %d (err %v), want 3", v, err)
	}
	if ok, err := HasPluginMigration(ctx, db.Writer(), "dnd5e", 2); err != nil || !ok {
		t.Errorf("HasPluginMigration(2) = %v (err %v), want true", ok, err)
	}
	if ok, err := HasPluginMigration(ctx, db.Writer(), "dnd5e", 9); err != nil || ok {
		t.Errorf("HasPluginMigration(9) = %v (err %v), want false", ok, err)
	}
	if v, err := AppliedPluginVersion(ctx, db.Writer(), "houserules"); err != nil || v != 0 {
		t.Errorf("an unapplied plugin reports v%d (err %v), want 0", v, err)
	}
	ms, err := ListPluginMigrations(ctx, db.Writer(), "dnd5e")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 {
		t.Errorf("recorded migrations = %d, want 3", len(ms))
	}
}

func TestMetaBumpIsAtomicAndMonotonic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)

	if v, err := AuthzGeneration(ctx, db.Writer()); err != nil || v != 0 {
		t.Errorf("authz generation on a fresh vault = %d (err %v), want 0", v, err)
	}
	for want := int64(1); want <= 5; want++ {
		got, err := BumpAuthzGeneration(ctx, db.Writer())
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("bump returned %d, want %d", got, want)
		}
	}
	if v, err := AuthzGeneration(ctx, db.Reader()); err != nil || v != 5 {
		t.Errorf("authz generation = %d (err %v), want 5", v, err)
	}
	// A lost increment is the whole reason the bump is one statement.
	if v, err := BumpAuthzGeneration(ctx, db.Writer()); err != nil || v != 6 {
		t.Errorf("bump = %d (err %v), want 6", v, err)
	}

	if err := MetaSet(ctx, db.Writer(), KeyBootState, BootStateIndexing); err != nil {
		t.Fatal(err)
	}
	if v, err := MetaGet(ctx, db.Writer(), KeyBootState); err != nil || v != BootStateIndexing {
		t.Errorf("boot state = %q (err %v)", v, err)
	}
	if err := MetaSet(ctx, db.Writer(), KeyBootState, BootStateReady); err != nil {
		t.Fatal(err)
	}
	if v, _ := MetaGet(ctx, db.Writer(), KeyBootState); v != BootStateReady {
		t.Errorf("boot state = %q, want ready", v)
	}
	if _, err := MetaGet(ctx, db.Writer(), "no_such_key"); !errors.Is(err, ErrNoRows) {
		t.Errorf("missing key error = %v, want ErrNoRows", err)
	}
	mustExec(t, db.Writer(), `INSERT INTO meta (key, value) VALUES ('bad', 'not-a-number')`)
	if _, err := MetaGetInt(ctx, db.Writer(), "bad"); err == nil {
		t.Error("MetaGetInt accepted a non-numeric value; the caller would get a silent 0")
	}
}

func TestNeedsFTSRebuild(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)

	// A migrated-but-never-indexed vault: the FTS generation is 0 and the
	// schema is 1, so the boot check must ask for a rebuild.
	if need, err := NeedsFTSRebuild(ctx, db.Writer()); err != nil || !need {
		t.Errorf("NeedsFTSRebuild on a fresh index = %v (err %v), want true", need, err)
	}
	if err := MarkFTSGeneration(ctx, db.Writer(), int64(SchemaVersion())); err != nil {
		t.Fatal(err)
	}
	if need, err := NeedsFTSRebuild(ctx, db.Writer()); err != nil || need {
		t.Errorf("NeedsFTSRebuild after marking = %v (err %v), want false", need, err)
	}
}

func TestExecReportsRowsAffected(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	n, err := Exec(context.Background(), db.Writer(), `DELETE FROM pages WHERE path = ?`, "nothing.md")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("delete of nothing touched %d rows", n)
	}
}

func TestRandomPagePathsRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	// A fuzz-flavoured check that path handling is not accidentally
	// case-folding or normalising: a vault may legitimately hold both
	// Gundren.md and gundren.md, and pages.path is UNIQUE with BINARY
	// collation precisely so that both survive.
	rng := rand.New(rand.NewSource(1750000000))
	paths := []string{
		"NPCs/Gundren.md", "npcs/gundren.md", "a b/c d.md", "ünïcode/Grüße.md",
		"deep/" + strings.Repeat("x/", 20) + "end.md",
	}
	for i := 0; i < 20; i++ {
		paths = append(paths, "gen/"+string(rune('a'+rng.Intn(26)))+itoa(rng.Intn(1000))+".md")
	}
	for _, p := range paths {
		if _, err := UpsertPage(ctx, db.Writer(), Page{
			Path: p, Basename: trimExt(lastSegment(p)), Title: p, ContentHash: []byte(p),
			MTimeUnix: 1, SizeBytes: 1, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			t.Fatalf("upsert %q: %v", p, err)
		}
	}
	for _, p := range paths {
		got, err := GetPageByPath(ctx, db.Writer(), p)
		if err != nil {
			t.Fatalf("get %q: %v", p, err)
		}
		if got.Path != p {
			t.Errorf("path round trip: stored %q, asked for %q", got.Path, p)
		}
	}
}

func lastSegment(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
