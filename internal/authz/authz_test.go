package authz

import (
	"testing"
)

func player(id int64) Principal { return ForUser(id, "player", RolePlayer, false) }
func dm(id int64) Principal     { return ForUser(id, "dm", RoleDM, false) }
func admin(id int64) Principal  { return ForUser(id, "admin", RoleAdmin, false) }
func anonRead() Principal       { return Anonymous(true) }
func anonNoRead() Principal     { return Anonymous(false) }

// TestCanReadSecretOverTheWholeMatrix is the Go half of the cross-check: every
// (visibility, role, author, page owner) combination, asserted against §8.2 of
// the plan. The SQL half lives in internal/store as TestPredicateMatrixAgrees,
// which runs both against one expectation — here rather than in store because
// the table this asserts is the Go one, and the pairing only holds if each half
// sits next to the implementation it checks.
func TestCanReadSecretOverTheWholeMatrix(t *testing.T) {
	t.Parallel()

	const author = int64(7)
	const other = int64(9)

	cases := []struct {
		name      string
		p         Principal
		vis       Visibility
		isAuthor  bool
		pageOwner bool
		want      bool
	}{
		{"table: player", player(3), VisibilityTable, false, false, true},
		{"table: page owner", player(3), VisibilityTable, false, true, true},
		{"table: dm", dm(3), VisibilityTable, false, false, true},
		{"table: anonymous with read", anonRead(), VisibilityTable, false, false, false},
		{"table: anonymous without read", anonNoRead(), VisibilityTable, false, false, false},

		{"private: author", player(author), VisibilityPrivate, true, false, true},
		{"private: page owner who did not author it", player(other), VisibilityPrivate, false, true, true},
		{"private: unrelated player", player(3), VisibilityPrivate, false, false, false},
		{"private: dm", dm(3), VisibilityPrivate, false, false, true},
		{"private: admin", admin(3), VisibilityPrivate, false, false, true},
		{"private: anonymous", anonRead(), VisibilityPrivate, false, false, false},

		// The row that a hand-rolled OR-chain gets wrong.
		{"dm: page owner", player(other), VisibilityDM, false, true, false},
		{"dm: author", player(author), VisibilityDM, true, false, false},
		{"dm: dm", dm(3), VisibilityDM, false, false, true},
		{"dm: admin", admin(3), VisibilityDM, false, false, true},
		{"dm: player", player(3), VisibilityDM, false, false, false},
		{"dm: anonymous", anonRead(), VisibilityDM, false, false, false},

		{"unknown visibility is denied to everyone", dm(3), Visibility("nonsense"), true, true, false},
		{"empty visibility is denied to everyone", admin(3), Visibility(""), true, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CanReadSecret(tc.p, tc.pageOwner, author, tc.vis)
			if got != tc.want {
				t.Errorf("CanReadSecret(%s, vis=%s, owner=%v) = %v, want %v",
					tc.p, tc.vis, tc.pageOwner, got, tc.want)
			}
		})
	}
}

// TestAnonymousNeverMatchesAParentID guards the bind parameters. An anonymous
// principal binds :uid to -1 rather than 0, so a page owned by user 0 — or a
// future system account — can never be reached by an unauthenticated request.
func TestAnonymousNeverMatchesAParentID(t *testing.T) {
	t.Parallel()

	uid, isDM := anonRead().Bind()
	if uid != -1 {
		t.Errorf("anonymous :uid = %d, want -1", uid)
	}
	if isDM != 0 {
		t.Errorf("anonymous :is_dm = %d, want 0", isDM)
	}
	if CanReadSecret(anonRead(), false, -1, VisibilityPrivate) {
		t.Error("an anonymous principal must never match an author id")
	}
}

func TestIsDMBindsOne(t *testing.T) {
	t.Parallel()
	for _, p := range []Principal{dm(1), admin(1)} {
		uid, isDM := p.Bind()
		if isDM != 1 {
			t.Errorf("%s bound :is_dm = %d, want 1", p, isDM)
		}
		if uid != p.UserID {
			t.Errorf("%s bound :uid = %d, want %d", p, uid, p.UserID)
		}
	}
	_, isDM := player(4).Bind()
	if isDM != 0 {
		t.Errorf("player bound :is_dm = %d, want 0", isDM)
	}
}

func TestPrincipalReadAccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		p       Principal
		public  bool
		authed  bool
		isDM    bool
		isAdmin bool
	}{
		{"anon without read", anonNoRead(), false, false, false, false},
		{"anon with read", anonRead(), true, false, false, false},
		{"player", player(1), true, true, false, false},
		{"dm", dm(1), true, true, true, false},
		{"admin", admin(1), true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.p.CanReadPublic(); got != tc.public {
				t.Errorf("CanReadPublic = %v, want %v", got, tc.public)
			}
			if got := tc.p.Authenticated(); got != tc.authed {
				t.Errorf("Authenticated = %v, want %v", got, tc.authed)
			}
			if got := tc.p.IsDM(); got != tc.isDM {
				t.Errorf("IsDM = %v, want %v", got, tc.isDM)
			}
			if got := tc.p.IsAdmin(); got != tc.isAdmin {
				t.Errorf("IsAdmin = %v, want %v", got, tc.isAdmin)
			}
		})
	}
}

func TestPrincipalStringIsSafeToLog(t *testing.T) {
	t.Parallel()
	if got := player(1).String(); got != "player(player)" {
		t.Errorf("String = %q", got)
	}
	if got := anonRead().String(); got != "anon" {
		t.Errorf("anonymous String = %q", got)
	}
	// A session id is never part of the string form.
	p := player(1)
	p.SessionID = "e3b0c44298fc1c149afbf4c8996fb924"
	if got := p.String(); got != "player(player)" {
		t.Errorf("String leaked a session id: %q", got)
	}
}

func TestRoleValid(t *testing.T) {
	t.Parallel()
	for _, r := range []Role{RoleAdmin, RoleDM, RolePlayer} {
		if !r.Valid() {
			t.Errorf("%q should be persistable", r)
		}
	}
	// anon exists as a Principal value but is never a stored role.
	if RoleAnonymous.Valid() {
		t.Error("anon must not be a persistable role")
	}
}

func TestVisibilityValid(t *testing.T) {
	t.Parallel()
	for _, v := range []Visibility{VisibilityPrivate, VisibilityDM, VisibilityTable} {
		if !v.Valid() {
			t.Errorf("%q should be valid", v)
		}
	}
	for _, v := range []Visibility{"", "owner", "public", "table "} {
		if v.Valid() {
			t.Errorf("%q should not be valid", v)
		}
	}
}

func TestResourceConstructors(t *testing.T) {
	t.Parallel()
	p := Page(42, true)
	if p.PageID != 42 || !p.IsPageOwner || p.HasSecret {
		t.Errorf("Page built %+v", p)
	}
	s := SecretOf(42, false, 7, VisibilityDM)
	if !s.HasSecret || s.AuthorID != 7 || s.Visibility != VisibilityDM {
		t.Errorf("SecretOf built %+v", s)
	}
}

func TestHashSecretIDIsStableAndOpaque(t *testing.T) {
	t.Parallel()
	a := HashSecretID("7f3a91c40d2e")
	b := HashSecretID("7f3a91c40d2e")
	if a != b {
		t.Fatal("the hash is not stable")
	}
	if a == HashSecretID("7f3a91c40d2f") {
		t.Fatal("two ids hash the same")
	}
	if len(a) != 16 {
		t.Errorf("hash length = %d, want 16 hex chars", len(a))
	}
}
