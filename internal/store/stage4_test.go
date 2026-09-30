package store

import (
	"context"
	"reflect"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// TestUnresolvedLinksExcludeSecretOnlyDanglingLinks is the broken-links panel's
// half of §6.4: a dangling reference written inside a secret must not be listed
// to a principal who may not read that secret, and must not be counted either.
//
// The unfiltered read is asserted alongside it on purpose. The indexer and the
// reconciliation scan need to see every dangling link in the vault, so the
// existence of an unfiltered query is correct; what is not correct is a panel
// built on it, and the two have to be distinguishable to be safe.
func TestUnresolvedLinksExcludeSecretOnlyDanglingLinks(t *testing.T) {
	t.Parallel()
	f := newMatrixFixture(t)
	ctx := context.Background()

	// The fixture seeds one public dangling link and one inside each of the
	// three secrets, so every row of the table below is a different answer and a
	// filter that ignored one of the two routes into the predicate shows up.
	for _, tc := range []struct {
		principal string
		want      int
	}{
		// Both the dm secret and the private one are readable; so is the table
		// one, and it was always readable by any signed-in principal.
		{"dm", 4},
		{"admin", 4},
		// Alice authored all three secrets and co-owns the page, so the private
		// one is readable by two independent routes and the dm one by none.
		{"author", 3},
		{"co_owner", 3},
		// An outsider reads the public link and the table secret, nothing else.
		{"outsider", 2},
		// §8.2's bottom row: an unauthenticated request sees no secret at all,
		// so the canonical predicate's table clause has to be closed off here or
		// the panel would list a revealed secret to a stranger.
		{"anonymous", 1},
	} {
		t.Run(tc.principal, func(t *testing.T) {
			t.Parallel()
			p := f.principal(t)[tc.principal]
			listed, err := ListVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(listed) != tc.want {
				t.Errorf("listed %d dangling links, want %d: %v", len(listed), tc.want, targetsOf(listed))
			}
			count, err := CountVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if count != len(listed) {
				t.Errorf("CountVisibleUnresolvedLinks = %d but the list has %d rows", count, len(listed))
			}
			// Every row is a real link, not a filtered stub, and none of them is
			// resolved: the panel is for links that do not resolve.
			for _, l := range listed {
				if l.TargetPageID != nil {
					t.Errorf("a resolved link is listed as dangling: %+v", l)
				}
				if l.SecretID != "" && !expectVisible(p, f.secrets[visOfSecret(t, f, l.SecretID)]) {
					t.Errorf("a dangling link inside a secret this principal may not read is listed: %q", l.TargetRaw)
				}
			}
			// The indexer's view is unchanged: it sees the dangling link in every
			// secret whatever the principal, and it also sees the attachment
			// references, whose target is a file and is therefore never a page.
			// That difference is why the panel's statement excludes those kinds
			// and this one does not.
			all, err := ListUnresolvedLinks(ctx, f.db.Writer())
			if err != nil {
				t.Fatalf("unfiltered list: %v", err)
			}
			seen := map[string]bool{}
			for _, l := range all {
				seen[l.TargetRaw] = true
			}
			for _, want := range append([]string{f.danglingPublic, f.sharedAttachment, f.dmOnlyAttachment}, f.danglingInSecrets...) {
				if !seen[want] {
					t.Errorf("the unfiltered read is missing %q; the indexer needs to see every dangling link", want)
				}
			}
			if want := mustQueryInt(t, f.db.Writer(),
				`SELECT COUNT(*) FROM links WHERE target_page_id IS NULL`); int(want) != len(all) {
				t.Errorf("the unfiltered read returns %d rows but the table holds %d", len(all), want)
			}
		})
	}

	// A principal that may not read public content at all is a different case
	// from an anonymous one, and it is the panel's whole output rather than only
	// its secret rows. The public dangling link is public text, so it is held
	// back by the same rule that holds back a public page.
	t.Run("anonymous_without_public_read", func(t *testing.T) {
		t.Parallel()
		p := authz.Anonymous(false)
		listed, err := ListVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(listed) != 0 {
			t.Errorf("listed %d dangling links to a principal who may not read public content: %v",
				len(listed), targetsOf(listed))
		}
		count, err := CountVisibleUnresolvedLinks(ctx, f.db.Writer(), p)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Errorf("CountVisibleUnresolvedLinks = %d, want 0 for a principal who may not read public content", count)
		}
	})
}

func targetsOf(links []Link) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, l.TargetRaw)
	}
	return out
}

// visOfSecret looks a seeded secret's visibility up by id, failing the test
// rather than defaulting: a dangling link naming a secret the fixture never
// seeded would otherwise be evaluated against a zero visibility, and the
// predicate denies an unknown one, so the check would pass for the wrong reason.
func visOfSecret(t *testing.T, f *matrixFixture, secretID string) authz.Visibility {
	t.Helper()
	for vis, m := range f.secrets {
		if m.secretID() == secretID {
			return vis
		}
	}
	t.Fatalf("the fixture has no secret %q", secretID)
	return ""
}

// TestRevisionListDoesNotCarryContent is the property that keeps a history panel
// from becoming a secret reader by accident.
//
// It is asserted on both halves: the statement must not name the content column,
// and the result type must have no field to put it in. The second half is the
// one that survives a future edit — adding a Content field back to RevisionMeta
// is a two-line change that the SQL check alone would not notice, and it would
// put a body in a context that has not re-segmented or re-authorised one.
func TestRevisionListDoesNotCarryContent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	page := seedPage(t, db.Writer(), "Hist.md", "Hist")

	const body = "the bytes of a file, secret plaintext included"
	id, err := AppendRevision(ctx, db.Writer(), Revision{
		PageID: page, ContentHash: []byte("h1"), Content: body,
		At: time.Unix(1750000000, 0).UTC(), Source: RevisionApp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The statement, checked on its own. content_hash is a digest and is wanted;
	// a word-boundary match is what keeps the two apart, since a substring check
	// would flag the column the test is relying on.
	bare := regexp.MustCompile(`\bcontent\b`)
	for _, sql := range []string{revisionMetaColumns, revisionMetaListSQL, revisionMetaCountSQL} {
		if bare.MatchString(sql) {
			t.Errorf("the metadata statement names the content column: %s", sql)
		}
	}

	// The type, checked on its own.
	if f, ok := reflect.TypeOf(RevisionMeta{}).FieldByName("Content"); ok {
		t.Errorf("RevisionMeta has a %s field of type %s; the panel read must not be able to carry a body", f.Name, f.Type)
	}

	meta, err := ListRevisionMetaByPage(ctx, db.Writer(), page, 100)
	if err != nil {
		t.Fatalf("list revision metadata: %v", err)
	}
	if len(meta) != 1 {
		t.Fatalf("revision metadata = %d rows, want 1", len(meta))
	}
	if meta[0].ID != id || meta[0].PageID != page || meta[0].Source != RevisionApp {
		t.Errorf("revision metadata = %+v, want the row that was appended", meta[0])
	}
	if string(meta[0].ContentHash) != "h1" {
		t.Errorf("content hash = %q, want h1; the digest is metadata and is wanted", meta[0].ContentHash)
	}
	if meta[0].At.IsZero() {
		t.Error("revision metadata has no timestamp, and the history panel is ordered by it")
	}

	// The count comes from the same FROM and WHERE as the list, so a badge cannot
	// disagree with the list beside it.
	if n, countRevisionsByPageErr := CountRevisionsByPage(ctx, db.Writer(), page); countRevisionsByPageErr != nil || n != len(meta) {
		t.Errorf("CountRevisionsByPage = %d (countRevisionsByPageErr %v) but the list has %d rows", n, countRevisionsByPageErr, len(meta))
	}
	// The bytes are still reachable, and only through the single-revision read.
	// This is not vacuity: a test that only proved the list carries no body would
	// also pass if the content had been dropped from the schema entirely.
	rev, err := GetRevision(ctx, db.Writer(), id)
	if err != nil {
		t.Fatalf("get revision: %v", err)
	}
	if rev.Content != body {
		t.Errorf("GetRevision content = %q, want the appended bytes", rev.Content)
	}
}

// attachmentShape is one arrangement of references to a page's attachment.
type attachmentShape struct {
	name string
	// secretVis is the visibility of the page's secret, or "" when the page has
	// no secret at all.
	secretVis authz.Visibility
	// publicRef and secretRef are whether public text and the secret each embed
	// the file.
	publicRef bool
	secretRef bool
}

// attachmentPrincipals is every identity the matrix is evaluated as, in a fixed
// order so a subtest name cannot drift from the expectation beside it.
var attachmentPrincipals = []string{
	"dm", "admin", "owner", "outsider", "table_reference", "anonymous", "anonymous_without_public_read",
}

// TestAttachmentIsServedWhenAnyReferenceIsVisible is §8.8's rule over the whole
// authorization matrix, and the three answers are different from one another:
// served on a public reference, denied on a secret-only reference, and denied on
// a file nothing references.
//
// The expectations are written out per shape rather than computed from the shape,
// because a table derived from the same rule the query implements agrees with a
// wrong query as readily as with a right one.
//
// The two-references-to-one-file case is the one a single-reference rule gets
// wrong, and it is the case the rule exists for: a DM who embeds a portrait in a
// secret and also shows it in public has not made it private.
func TestAttachmentIsServedWhenAnyReferenceIsVisible(t *testing.T) {
	t.Parallel()
	// Everyone who may read public content, which is every identity below except
	// the last: a public reference alone is enough to serve the file.
	everyone := map[string]bool{
		"dm": true, "admin": true, "owner": true, "outsider": true,
		"table_reference": true, "anonymous": true, "anonymous_without_public_read": false,
	}
	shapes := []struct {
		attachmentShape
		served map[string]bool
	}{
		{attachmentShape{name: "public_reference_only", publicRef: true}, everyone},
		{
			// A dm secret is the DM's alone, even for the page owner and even for
			// its own author.
			attachmentShape{name: "secret_only_dm", secretVis: authz.VisibilityDM, secretRef: true},
			map[string]bool{"dm": true, "admin": true},
		},
		{
			// A private secret is readable by the DM, the admin and the page
			// owner. The secret is authored by the DM, so ownership is the only
			// route open to the owner here.
			attachmentShape{name: "secret_only_private", secretVis: authz.VisibilityPrivate, secretRef: true},
			map[string]bool{"dm": true, "admin": true, "owner": true},
		},
		{
			// A revealed secret is readable by any signed-in principal and by no
			// anonymous one, whatever the secret's author or the page's owner.
			attachmentShape{name: "secret_only_table", secretVis: authz.VisibilityTable, secretRef: true},
			map[string]bool{"dm": true, "admin": true, "owner": true, "outsider": true, "table_reference": true},
		},
		{attachmentShape{name: "public_and_secret_dm", secretVis: authz.VisibilityDM, publicRef: true, secretRef: true}, everyone},
		{attachmentShape{name: "public_and_secret_private", secretVis: authz.VisibilityPrivate, publicRef: true, secretRef: true}, everyone},
		{attachmentShape: attachmentShape{name: "referenced_in_nothing"}},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			t.Parallel()
			// served is the set of principals that may be served, so an omitted
			// name means denied. That encoding fails in the safe direction: a
			// principal that should have been served and was left out of the set
			// makes the test red, while one that should be denied and was left
			// out only confirms the denial. The check below is therefore for the
			// other mistake — a name that is not a principal at all, which would
			// compare against a map that can never be read.
			for name := range shape.served {
				if !slices.Contains(attachmentPrincipals, name) {
					t.Errorf("the expectation names %q, which is not one of the principals under test", name)
				}
			}
			f := seedAttachmentShape(t, shape.attachmentShape)
			for _, name := range attachmentPrincipals {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					got, err := AttachmentVisibleTo(t.Context(), f.db.Writer(), f.principal(name), f.pageID, f.name)
					if err != nil {
						t.Fatalf("attachment visible: %v", err)
					}
					if want := shape.served[name]; got != want {
						t.Errorf("AttachmentVisibleTo = %v, want %v", got, want)
					}
				})
			}
		})
	}
}

// attachmentFixture is one seeded page with one attachment and a fixed set of
// references to it.
type attachmentFixture struct {
	db     *DB
	pageID int64
	name   string
	dm     int64
	admin  int64
	owner  int64
	out    int64
}

func (f *attachmentFixture) principal(name string) authz.Principal {
	switch name {
	case "dm":
		return authz.ForUser(f.dm, "dm", authz.RoleDM, false)
	case "admin":
		return authz.ForUser(f.admin, "root", authz.RoleAdmin, false)
	case "owner":
		return authz.ForUser(f.owner, "alice", authz.RolePlayer, false)
	case "table_reference":
		return authz.ForUser(f.out, "bob", authz.RolePlayer, false)
	case "anonymous":
		return authz.Anonymous(true)
	case "anonymous_without_public_read":
		return authz.Anonymous(false)
	default:
		return authz.ForUser(f.out, "bob", authz.RolePlayer, false)
	}
}

// seedAttachmentShape builds a page owned by alice, a file beside it, and
// whichever references the shape asks for.
//
// The secret is authored by the DM rather than by the owner, on purpose: the
// private rule then has exactly one route open to alice — page ownership — so a
// predicate that implemented authorship and dropped ownership (or the reverse)
// would answer differently here than it does in the matrix fixture.
func seedAttachmentShape(t *testing.T, shape attachmentShape) *attachmentFixture {
	t.Helper()
	ctx := context.Background()
	db := newMigratedDB(t)

	f := &attachmentFixture{db: db, name: "assets/portrait.png"}
	f.dm = seedUser(t, db.Writer(), "dm", "dm")
	f.admin = seedUser(t, db.Writer(), "root", "admin")
	f.owner = seedUser(t, db.Writer(), "alice", "player")
	f.out = seedUser(t, db.Writer(), "bob", "player")

	f.pageID = seedPage(t, db.Writer(), "Villain.md", "Villain")
	if err := AddPageOwner(ctx, db.Writer(), PageOwner{
		PageID: f.pageID, UserID: f.owner, IsOwner: true,
		AddedAt: time.Unix(1750000000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := InsertAttachment(ctx, db.Writer(), Attachment{
		PageID: &f.pageID, Path: f.name, Mime: "image/png", SizeBytes: 2048,
	}); err != nil {
		t.Fatal(err)
	}

	secretID := ""
	if shape.secretVis != "" {
		secretID = "portrait-secret"
		if err := InsertSecret(ctx, db.Writer(), Secret{
			ID: secretID, PageID: f.pageID, Ordinal: 0, Visibility: shape.secretVis,
			AuthorID: f.dm, Body: "a body nobody but a dm may read",
			BodyHash: []byte("h"), CreatedAt: time.Unix(1750000000, 0).UTC(),
			UpdatedAt: time.Unix(1750000000, 0).UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	line := 1
	if shape.publicRef {
		if _, err := InsertLink(ctx, db.Writer(), Link{
			SourcePageID: f.pageID, TargetRaw: f.name, Kind: LinkAttachment, Line: line,
		}); err != nil {
			t.Fatal(err)
		}
		line++
	}
	if shape.secretRef {
		if _, err := InsertLink(ctx, db.Writer(), Link{
			SourcePageID: f.pageID, TargetRaw: f.name, Kind: LinkAttachment,
			SecretID: secretID, Line: line,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// TestLinkByteOffsetsDefaultToUnset is the migration's own assertion, on a row
// written before the columns existed.
//
// The default has to be a value the updater can recognise as "unknown", and the
// reason it is -1 rather than 0 is the property the second half checks: 0 is a
// legitimate offset, so an unset offset written as 0 would verify an empty span
// and report every link in a migrated vault as a conflict.
func TestLinkByteOffsetsDefaultToUnset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const v1 = 1
	db := newDBAtVersion(t, v1)
	page := seedPage(t, db.Writer(), "Source.md", "Source")
	// The insert names only the v1 columns, because it stands in for a row a v1
	// binary wrote. store's own queries are written against head, so InsertLink
	// cannot be the vehicle here: it names byte_start, which this schema does not
	// have yet, and failing on that is the correct behaviour.
	mustExec(t, db.Writer(),
		`INSERT INTO links (source_page_id, target_raw, kind, line) VALUES (?, ?, ?, ?)`,
		page, "Gundren", string(LinkWikilink), 3)
	// The columns do not exist yet, which is the point: the row below is written
	// by a v1 binary and carries no span at all.
	if n := mustQueryInt(t, db.Writer(),
		`SELECT COUNT(*) FROM pragma_table_info('links') WHERE name IN ('byte_start','byte_len')`); n != 0 {
		t.Fatalf("the v1 schema already has %d offset columns", n)
	}
	if err := Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	got, err := ListLinksByPage(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("links = %d rows, want the one the v1 fixture wrote", len(got))
	}
	if got[0].ByteStart != LinkByteStartUnset || got[0].ByteLen != 0 {
		t.Errorf("a pre-migration link reads byte_start=%d byte_len=%d, want %d/0",
			got[0].ByteStart, got[0].ByteLen, LinkByteStartUnset)
	}

	// A recorded span round-trips, and the Go zero value does not become a
	// plausible offset on the way in: a caller who forgets to set it writes
	// "unrecorded", not "the top of the file".
	if _, insertLinkErr := InsertLink(ctx, db.Writer(), Link{
		SourcePageID: page, TargetRaw: "Gundren", Kind: LinkWikilink, Line: 4,
		ByteStart: 0, ByteLen: 0,
	}); insertLinkErr != nil {
		t.Fatal(insertLinkErr)
	}
	recorded := 41
	if _, insertLinkErr := InsertLink(ctx, db.Writer(), Link{
		SourcePageID: page, TargetRaw: "Sildar", Kind: LinkWikilink, Line: 5,
		ByteStart: recorded, ByteLen: 6,
	}); insertLinkErr != nil {
		t.Fatal(insertLinkErr)
	}
	byLine, err := ListLinksByPage(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(byLine) != 3 {
		t.Fatalf("links = %d rows, want 3", len(byLine))
	}
	if byLine[1].ByteStart != LinkByteStartUnset || byLine[1].ByteLen != 0 {
		t.Errorf("an unrecorded span was written as %d/%d, want %d/0",
			byLine[1].ByteStart, byLine[1].ByteLen, LinkByteStartUnset)
	}
	if byLine[2].ByteStart != recorded || byLine[2].ByteLen != 6 {
		t.Errorf("recorded span = %d/%d, want %d/6", byLine[2].ByteStart, byLine[2].ByteLen, recorded)
	}

	// The same span travels with the query the bulk updater uses to find the
	// affected pages, so it does not have to re-derive it from the file.
	target := page
	if _, insertLinkErr := InsertLink(ctx, db.Writer(), Link{
		SourcePageID: page, TargetPageID: &target, TargetRaw: "Gundren",
		Kind: LinkWikilink, Line: 6, ByteStart: 120, ByteLen: 7,
	}); insertLinkErr != nil {
		t.Fatal(insertLinkErr)
	}
	incoming, err := ListLinksToPage(ctx, db.Writer(), page)
	if err != nil {
		t.Fatal(err)
	}
	if len(incoming) != 1 {
		t.Fatalf("links to page = %d rows, want 1", len(incoming))
	}
	if incoming[0].ByteStart != 120 || incoming[0].ByteLen != 7 || incoming[0].TargetRaw != "Gundren" {
		t.Errorf("the updater's read lost the occurrence: %+v", incoming[0])
	}
}
