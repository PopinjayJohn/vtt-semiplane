package httpapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The page-scoped write gate, tested directly.
//
// Through HTTP it is unreachable, and that is the point of the test. The route
// table's PermWritePage is asked by the permit middleware with a zero Resource —
// authz.Page(0, false) — so every principal but a DM or an admin is refused
// before any handler runs, and a test that only drove the route would be testing
// the gate above this one. mayWritePage is the check whose Resource is right, and
// it is what would catch a caller that reached a write handler without the table
// in front of it — internal/secrets makes the same check, on the same rule, and
// the two answering differently would be a page that can be edited by the
// service and not by the router.
//
// A gate that is never reachable and never tested is decoration. This is the test
// that says which of the two it is.
func TestThePageScopedWriteGateIsARefusalAndNotADecoration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate the index: %v", err)
	}

	// The three fields the gate reads, and nothing else. A Server built through
	// New would need a writer, a reindexer, an asset filesystem and a renderer
	// for a function that asks one question of a policy, and a test that
	// assembles four dependencies to reach a two-line function is testing the
	// assembly.
	s := &Server{db: db, policy: authz.NewPolicy(true), log: obs.Discard()}

	owner := insertUser(t, db, 1, "thia", authz.RolePlayer)
	other := insertUser(t, db, 2, "bram", authz.RolePlayer)
	dm := insertUser(t, db, 3, "dungeonmaster", authz.RoleDM)
	admin := insertUser(t, db, 4, "archivist", authz.RoleAdmin)

	tavern := insertPage(t, db, "Tavern.md")
	index := insertPage(t, db, "Index.md")
	// Ownership is a row and not a consequence of who wrote the file, so the
	// test sets it up rather than inferring it.
	grantOwnership(t, db, tavern, owner.id)

	anon := authz.Anonymous(true)
	zero := authz.Principal{}

	for _, tc := range []struct {
		name string
		p    authz.Principal
		id   int64
		want bool
	}{
		{"a page owner may write their page", owner.principal(), tavern, true},
		{"a page owner may not write somebody else's page", owner.principal(), index, false},
		{"a player who owns nothing may not write a page", other.principal(), index, false},
		{"a dm may write any page", dm.principal(), tavern, true},
		{"an admin may write any page", admin.principal(), tavern, true},
		{"an authenticated player may not write a page they do not own", other.principal(), tavern, false},
		{"an anonymous principal may not write a page", anon, tavern, false},
		{"the zero principal may not write a page", zero, tavern, false},
		{"a page id of zero is not an ownership exemption", other.principal(), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.mayWritePage(ctx, tc.p, tc.id)
			if err != nil {
				t.Fatalf("mayWritePage: %v", err)
			}
			if got != tc.want {
				t.Errorf("mayWritePage = %v, want %v", got, tc.want)
			}
		})
	}
}

// account is one inserted user, with the role kept beside the row so the test
// hands authz.ForUser the role it was given rather than one read back out of
// the database — a read-back role would make a wrong insert pass.
type account struct {
	id       int64
	username string
	role     authz.Role
}

// principal is the account as the policy sees it, with anonymous read on, which
// is the state that makes ownership rather than authentication the deciding
// factor.
func (a account) principal() authz.Principal {
	return authz.ForUser(a.id, a.username, a.role, true)
}

// insertUser is one account row, for the gate's IsPageOwner lookup and for
// nothing else.
func insertUser(t *testing.T, db *store.DB, id int64, username string, role authz.Role) account {
	t.Helper()
	var got int64
	err := db.Writer().QueryRowContext(context.Background(),
		`INSERT INTO users (id, username, display_name, role, pw_salt, created_at)
		 VALUES (?, ?, ?, ?, x'00', ?) RETURNING id`,
		id, username, username, string(role), store.FormatTime(gateEpoch)).Scan(&got)
	if err != nil {
		t.Fatalf("insert the user %s: %v", username, err)
	}
	return account{id: got, username: username, role: role}
}

// insertPage is one page row.
func insertPage(t *testing.T, db *store.DB, path string) int64 {
	t.Helper()
	var got int64
	err := db.Writer().QueryRowContext(context.Background(),
		`INSERT INTO pages (path, basename, title, content_hash, mtime_unix, size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 0, 0, ?, ?) RETURNING id`,
		path, path, path, make([]byte, 32), store.FormatTime(gateEpoch), store.FormatTime(gateEpoch)).Scan(&got)
	if err != nil {
		t.Fatalf("insert the page %s: %v", path, err)
	}
	return got
}

// gateEpoch is the instant the inserted rows carry. The gate reads no timestamp,
// so any value would do; a constant is here so the inserts do not reach for the
// clock and so two runs insert identical rows.
var gateEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// TestTheConflictPageRedactsTheOnDiskSideForAnActorWhoCannotReadIt is the test
// that could not be written in the test package, and the reason it is here is the
// finding rather than a convenience.
//
// The conflict page's redaction is only ever non-trivial for a principal with a
// non-empty hidden set. Through HTTP, the only principals who reach a 409 are a
// DM and an admin — the route table's PermWritePage is asked with a zero
// Resource — and a DM's hidden set is empty by definition, because a DM may read
// every fence. So the handler can be driven end to end all day and never once
// with a body it had to redact, which means an HTTP test would pass against a
// conflict page that printed the file verbatim.
//
// So the derivation is called directly here, against a real service and a real
// page, with a player who may read neither fence. The assertions are the three
// that matter and the one that is easy to forget:
//
//   - neither body is in Theirs;
//   - no restore sentinel is either, because md.Redact's sentinel carries the
//     hidden body's length and a digest of it, and a 409 is not the editor;
//   - Mine is echoed, because a save that refuses must not throw the work away.
func TestTheConflictPageRedactsTheOnDiskSideForAnActorWhoCannotReadIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	const page = "Tavern.md"
	file := "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
		"```secret id=b2b2b2b2b2b2 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The true name\"\n" +
		"DM-BODY-TOKEN-7b1e4d\n```\n\n" +
		"```secret id=d4d4d4d4d4d4 visibility=table author=dungeonmaster created=2026-01-01T00:00:00Z title=\"Shared\"\n" +
		"TABLE-BODY-TOKEN-5d0a8f\n```\n\n"
	if err := os.WriteFile(filepath.Join(dir, page), []byte(file), 0o600); err != nil {
		t.Fatalf("write the page: %v", err)
	}

	db, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open the index: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if migrateErr := store.Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); migrateErr != nil {
		t.Fatalf("migrate the index: %v", migrateErr)
	}

	dm := insertUser(t, db, 1, "dungeonmaster", authz.RoleDM)
	player := insertUser(t, db, 2, "thia", authz.RolePlayer)
	pageID := insertPage(t, db, page)
	grantOwnership(t, db, pageID, dm.id)

	// A real Server, built the way the composition root builds it, so the
	// secrets service under test is the one a request would use. The reindexer is
	// a no-op because the fixture is already indexed by hand; a stub is the
	// honest thing here rather than booting an indexer to re-derive two rows.
	s, err := New(Options{
		Config:    config.Default(),
		DB:        db,
		Writer:    vault.NewWriter(dir, obs.Discard()),
		Reindexer: noReindex{},
		Assets:    os.DirFS(dir),
		Renderer:  noRenderer{},
		Log:       obs.Discard(),
	})
	if err != nil {
		t.Fatalf("build a server: %v", err)
	}
	row := store.Page{ID: pageID, Path: page, Title: "The Drowned Lantern"}

	for _, tc := range []struct {
		name     string
		p        authz.Principal
		wantHide []string
		wantShow []string
	}{
		{
			name:     "a player who may read neither fence",
			p:        player.principal(),
			wantHide: []string{"DM-BODY-TOKEN-7b1e4d"},
			// The table fence is readable by every authenticated principal, so a
			// player sees it — and a redaction that removed it would be a bug in
			// the other direction.
			wantShow: []string{"TABLE-BODY-TOKEN-5d0a8f"},
		},
		{
			name:     "a dm who may read both",
			p:        dm.principal(),
			wantShow: []string{"DM-BODY-TOKEN-7b1e4d", "TABLE-BODY-TOKEN-5d0a8f"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conflict, err := s.conflictFor(ctx, tc.p, row, "# The Drowned Lantern\n\nmy own revision\n", "save")
			if err != nil {
				t.Fatalf("derive the conflict: %v", err)
			}
			for _, hidden := range tc.wantHide {
				if strings.Contains(conflict.Theirs, hidden) {
					t.Errorf("the on-disk side of the conflict carries %q", hidden)
				}
			}
			for _, shown := range tc.wantShow {
				if !strings.Contains(conflict.Theirs, shown) {
					t.Errorf("the on-disk side of the conflict is missing %q, which this principal may read", shown)
				}
			}
			if strings.Contains(conflict.Theirs, "‹s:") {
				t.Error("the on-disk side carries a restore sentinel: a sentinel encodes the length and a digest of the body it stands in for, and a conflict page is not the editor")
			}
			if !strings.Contains(conflict.Mine, "my own revision") {
				t.Error("the submitted side does not carry the actor's own buffer: a save that refuses must not throw the work away")
			}
			if conflict.BaseHash != vault.HashHex([]byte(file)) {
				t.Error("the conflict does not carry the on-disk hash, so a resubmission has nothing to be against")
			}
			if len(conflict.Hunks) == 0 {
				t.Error("the conflict carries no diff between two documents that differ")
			}
		})
	}
}

// grantOwnership records a page's owner, which is the row the whole redacted
// editor is built on.
func grantOwnership(t *testing.T, db *store.DB, pageID, userID int64) {
	t.Helper()
	if _, err := db.Writer().ExecContext(context.Background(),
		`INSERT INTO page_owners (page_id, user_id, is_owner, added_at) VALUES (?, ?, 1, ?)`,
		pageID, userID, store.FormatTime(gateEpoch)); err != nil {
		t.Fatalf("grant ownership: %v", err)
	}
}

// noReindex is a reindexer that does nothing, for a fixture whose rows are
// already in place.
type noReindex struct{}

func (noReindex) Reindex(context.Context, string) error { return nil }

// noRenderer is a renderer that renders nothing, for a test that reads the view
// model rather than the response.
type noRenderer struct{}

func (noRenderer) Document(http.ResponseWriter, *http.Request, View) error { return nil }

func (noRenderer) Fragment(http.ResponseWriter, *http.Request, View) error { return nil }

func (noRenderer) Region(View, string) ([]byte, error) { return nil, nil }
