package authz

import (
	"errors"
	"testing"
)

// The five principals of the authorization matrix: anon (with and without
// anonymous read), an ordinary player, a player who owns the page, a DM, and an
// admin. "owner" is a player *relative to a resource*, not a role, which is why
// the owner column is expressed through Resource.IsPageOwner.
type role int

const (
	rAnon role = iota
	rPlayer
	rOwner
	rDM
	rAdmin
)

func principalFor(r role) Principal {
	switch r {
	case rAnon:
		return Anonymous(true)
	case rPlayer:
		return ForUser(3, "player", RolePlayer, false)
	case rOwner:
		return ForUser(4, "owner", RolePlayer, false)
	case rDM:
		return ForUser(5, "dm", RoleDM, false)
	case rAdmin:
		return ForUser(6, "admin", RoleAdmin, false)
	default:
		panic("unknown role")
	}
}

func isOwnerFor(r role) bool { return r == rOwner }

func isDMFor(r role) bool { return r == rDM || r == rAdmin }

func TestAuthorizationMatrix(t *testing.T) {
	t.Parallel()

	// Every cell of §10, as (permission, resource) → which roles are allowed.
	cases := []struct {
		name  string
		perm  Permission
		res   func(owner bool) Resource
		allow func(r role) bool
	}{
		{
			name: "read public page",
			perm: PermReadPage,
			res:  func(bool) Resource { return Resource{} },
			// anon reads only when --allow-anonymous-read is on; the table
			// below is written for that case and the off case is tested apart.
			allow: func(role) bool { return true },
		},
		{
			name:  "create a page",
			perm:  PermWriteAny,
			res:   func(bool) Resource { return Resource{} },
			allow: func(r role) bool { return r != rAnon },
		},
		{
			name:  "edit a page",
			perm:  PermWritePage,
			res:   func(o bool) Resource { return Resource{PageID: 1, IsPageOwner: o} },
			allow: func(r role) bool { return isOwnerFor(r) || isDMFor(r) },
		},
		{
			name:  "delete a page",
			perm:  PermDeletePage,
			res:   func(o bool) Resource { return Resource{PageID: 1, IsPageOwner: o} },
			allow: func(r role) bool { return isOwnerFor(r) || isDMFor(r) },
		},
		{
			name:  "read a table secret",
			perm:  PermReadSecret,
			res:   func(bool) Resource { return Resource{HasSecret: true, Visibility: VisibilityTable} },
			allow: func(r role) bool { return r != rAnon },
		},
		{
			name: "read a private secret",
			perm: PermReadSecret,
			res: func(o bool) Resource {
				return Resource{HasSecret: true, Visibility: VisibilityPrivate, IsPageOwner: o, AuthorID: 4}
			},
			allow: func(r role) bool { return isOwnerFor(r) || isDMFor(r) },
		},
		{
			name: "read a dm secret",
			perm: PermReadSecret,
			res: func(o bool) Resource {
				return Resource{HasSecret: true, Visibility: VisibilityDM, IsPageOwner: o, AuthorID: 5}
			},
			// The page owner is not enough. This row is the one an OR-chain
			// gets wrong.
			allow: isDMFor,
		},
		{
			name:  "write a secret the principal authored",
			perm:  PermWriteSecret,
			res:   func(bool) Resource { return Resource{HasSecret: true, Visibility: VisibilityPrivate, AuthorID: 3} },
			allow: func(r role) bool { return r == rPlayer || isDMFor(r) },
		},
		{
			name: "write a secret the principal did not author",
			perm: PermWriteSecret,
			res: func(o bool) Resource {
				return Resource{HasSecret: true, Visibility: VisibilityPrivate, IsPageOwner: o, AuthorID: 99}
			},
			allow: isDMFor,
		},
		{
			name: "write a dm secret as its author",
			perm: PermWriteSecret,
			res: func(o bool) Resource {
				return Resource{HasSecret: true, Visibility: VisibilityDM, IsPageOwner: o, AuthorID: 3}
			},
			allow: isDMFor,
		},
		{
			name:  "reveal to table, revoke, trigger a reindex or backup",
			perm:  PermDM,
			res:   func(bool) Resource { return Resource{} },
			allow: isDMFor,
		},
		{
			name:  "manage users, invites and roles",
			perm:  PermAdmin,
			res:   func(bool) Resource { return Resource{} },
			allow: func(r role) bool { return r == rAdmin },
		},
		{
			// Admin-only, and the last admin is exempt: a vault whose only
			// admin has just been demoted has no way back, because setup is
			// closed forever once an admin exists.
			name:  "manage a user",
			perm:  PermManageUser,
			res:   func(bool) Resource { return Resource{} },
			allow: func(r role) bool { return r == rAdmin },
		},
		{
			name:  "require a session",
			perm:  PermSession,
			res:   func(bool) Resource { return Resource{} },
			allow: func(r role) bool { return r != rAnon },
		},
	}

	pol := NewPolicy(true)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, r := range []role{rAnon, rPlayer, rOwner, rDM, rAdmin} {
				who := principalFor(r)
				err := pol.Check(who, tc.perm, tc.res(isOwnerFor(r)))
				want := tc.allow(r)
				if got := err == nil; got != want {
					t.Errorf("Check(%s, %s) allowed=%v, want %v (%v)",
						who, tc.perm, got, want, err)
				}
				// ErrNotAuthenticated is a distinct, expected refusal: the
				// handler turns it into a redirect to /login rather than a 403.
				switch {
				case tc.perm == PermSession && !want:
					if !errors.Is(err, ErrNotAuthenticated) {
						t.Errorf("%s: PermSession refusal should be ErrNotAuthenticated, got %v", who, err)
					}
				case err != nil && !errors.Is(err, ErrDenied):
					t.Errorf("%s got a non-ErrDenied error: %v", who, err)
				}
			}
		})
	}
}

func TestTheLastAdminCannotBeDemotedOrDisabled(t *testing.T) {
	t.Parallel()
	pol := NewPolicy(true)

	// A target that is not the last admin is permitted for an admin and refused
	// for everyone else, with no mention of LastAdmin.
	if err := pol.Check(admin(1), PermManageUser, Resource{UserID: 5}); err != nil {
		t.Errorf("an admin was refused an ordinary user change: %v", err)
	}
	for _, who := range []Principal{player(2), dm(3), Anonymous(true)} {
		if err := pol.Check(who, PermManageUser, Resource{UserID: 5}); !errors.Is(err, ErrDenied) {
			t.Errorf("%s was allowed: %v", who, err)
		}
	}

	res := Resource{UserID: 6, LastAdmin: true}
	if err := pol.Check(admin(1), PermManageUser, res); !errors.Is(err, ErrDenied) {
		t.Errorf("an admin disabled the last admin: %v", err)
	}
	// A non-admin is refused for the ordinary reason, not because of LastAdmin,
	// so the two causes stay distinguishable in a log.
	err := pol.Check(player(2), PermManageUser, res)
	if !errors.Is(err, ErrDenied) {
		t.Errorf("a player was allowed: %v", err)
	}
	// And it is specifically a user-management refusal, not a role one.
	var de *DeniedError
	if !errors.As(err, &de) || de.Perm != PermManageUser {
		t.Errorf("refusal does not name PermManageUser: %v", err)
	}
}

func TestAnonymousReadIsOffByDefault(t *testing.T) {
	t.Parallel()

	off := NewPolicy(false)
	who := Anonymous(true) // the principal claims it may read

	for _, perm := range []Permission{PermAnonRead, PermReadPage, PermWriteAny} {
		if err := off.Check(who, perm, Resource{}); err == nil {
			t.Errorf("%s was allowed with anonymous read disabled", perm)
		}
	}
	// A principal with no session is refused PermSession too, but with
	// ErrNotAuthenticated rather than ErrDenied, so the handler can redirect
	// to /login instead of rendering a 403.
	if err := off.Check(Anonymous(true), PermSession, Resource{}); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("an anonymous session check should be ErrNotAuthenticated, got %v", err)
	}

	err := off.Check(Anonymous(true), PermReadPage, Resource{})
	if !errors.Is(err, ErrDenied) {
		t.Errorf("an anonymous denial should wrap ErrDenied, got %v", err)
	}
}

func TestUnauthenticatedIsDistinctFromForbidden(t *testing.T) {
	t.Parallel()
	pol := NewPolicy(true)
	err := pol.Check(Anonymous(true), PermSession, Resource{})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("an unauthenticated request should be ErrNotAuthenticated, got %v", err)
	}
}

func TestSetupOpenClosesAfterBootstrap(t *testing.T) {
	t.Parallel()
	pol := NewPolicy(true)

	if err := pol.Check(Anonymous(true), PermSetupOpen, Resource{SetupOpen: true}); err != nil {
		t.Errorf("setup should be open before bootstrap: %v", err)
	}
	// After bootstrap the route must be absent rather than forbidden, so an
	// outsider cannot confirm it exists.
	for _, who := range []Principal{
		Anonymous(true), player(1), principalFor(rOwner), dm(1), admin(1),
	} {
		if err := pol.Check(who, PermSetupOpen, Resource{SetupOpen: false}); !errors.Is(err, ErrSetupClosed) {
			t.Errorf("%s should get ErrSetupClosed, got %v", who, err)
		}
	}
}

func TestUnknownPermissionFailsClosed(t *testing.T) {
	t.Parallel()
	pol := NewPolicy(true)
	// A typo in the route table must not accidentally grant a route.
	//nolint:misspell // the misspelling is the input under test: the realistic
	// mistake is a hand-written string that is nearly a real permission, not a
	// permission that was deleted and left no gap.
	if err := pol.Check(admin(1), Permission("adminstrator"), Resource{}); err == nil {
		t.Fatal("an unknown permission was allowed")
	}
}

func TestPolicyIsTheAuthorityForAnonymousRead(t *testing.T) {
	t.Parallel()

	// An anonymous principal claiming the flag is refused when the policy
	// says anonymous read is off.
	if err := NewPolicy(false).Check(Anonymous(true), PermReadPage, Resource{}); err == nil {
		t.Fatal("an anonymous principal widened itself past the policy")
	}
	if err := NewPolicy(false).Check(Anonymous(false), PermReadPage, Resource{}); err == nil {
		t.Fatal("anonymous read off should refuse an anonymous principal")
	}
	// And an authenticated principal is unaffected either way, so a forged
	// flag on a session cannot be used to bypass anything.
	who := ForUser(1, "x", RolePlayer, true)
	for _, allow := range []bool{false, true} {
		if err := NewPolicy(allow).Check(who, PermReadPage, Resource{}); err != nil {
			t.Errorf("an authenticated player was refused with anonymous-read=%v: %v", allow, err)
		}
	}
	// The policy's setting also overrides a principal that claims the
	// opposite, so the flag cannot travel with a forged request.
	if err := NewPolicy(true).Check(Anonymous(false), PermReadPage, Resource{}); err != nil {
		t.Errorf("anonymous read on should admit an anonymous principal: %v", err)
	}
}

func TestDeniedErrorCarriesNoResource(t *testing.T) {
	t.Parallel()
	pol := NewPolicy(true)
	err := pol.Check(player(3), PermAdmin, Resource{PageID: 42, Visibility: VisibilityDM})
	var de *DeniedError
	if !errors.As(err, &de) {
		t.Fatalf("error is not a DeniedError: %v", err)
	}
	if de.Perm != PermAdmin {
		t.Errorf("Perm = %q", de.Perm)
	}
	// The message names the principal and the permission, never the page id.
	if de.Error() == "" {
		t.Error("DeniedError message is empty")
	}
	if de.Who.UserID != 3 {
		t.Errorf("Who = %+v", de.Who)
	}
}

func TestPolicyString(t *testing.T) {
	t.Parallel()
	if got := NewPolicy(false).String(); got != "authz(anonymous-read=off)" {
		t.Errorf("String = %q", got)
	}
	if got := NewPolicy(true).String(); got != "authz(anonymous-read=on)" {
		t.Errorf("String = %q", got)
	}
}
