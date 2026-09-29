package authz_test

import (
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// TestPermissionForRole pins the plugin vocabulary translation in the package
// that owns the role type.
//
// It moved here from httpapi, and the move is what this test is for: while it
// lived there the httpapi suite exercised it through the nav, and the moment it
// was a function of authz with no test of its own, internal/authz lost 3.4
// points of coverage and the ratchet said so. A function is tested where it
// lives, not where its last caller happened to be.
func TestPermissionForRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		role     string
		want     authz.Permission
		wantOK   bool
		explains string
	}{
		{name: "an empty requirement is the weakest one, not none",
			role: "", want: authz.PermReadPage, wantOK: true,
			explains: "a plugin that states no minimum is claiming a read, and read is what a signed-in player already has"},
		{name: "player", role: "player", want: authz.PermReadPage, wantOK: true},
		{name: "dm", role: "dm", want: authz.PermDM, wantOK: true},
		{name: "admin", role: "admin", want: authz.PermAdmin, wantOK: true},
		// The plugin spells the role as a string, so the case and the padding are
		// whatever the author typed. Trimming is a decision: a nav item that
		// vanished for a DM because of a trailing space is a policy with a hole
		// in it.
		{name: "surrounding whitespace is trimmed", role: "  dm  ", want: authz.PermDM, wantOK: true},
		// The direction of the default is the whole argument for the function
		// living where it does. An unrecognised name is nobody's requirement
		// rather than everybody's, so a typo in a plugin's string costs its own
		// screen instead of producing a difference between two readers — and the
		// zero Permission must never be handed back as if it were a real one.
		{name: "an unknown requirement is nobody's", role: "wizard",
			want: "", wantOK: false,
			explains: "returning true with the zero Permission would make an unknown role answer to no one and look like a grant"},
		{name: "a role that is never stored is still unknown", role: "anon",
			want: "", wantOK: false,
			explains: "anon is a request, not a requirement a plugin can state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := authz.PermissionForRole(tc.role)
			if ok != tc.wantOK {
				t.Fatalf("PermissionForRole(%q) ok = %v, want %v", tc.role, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("PermissionForRole(%q) = %q, want %q", tc.role, got, tc.want)
			}
		})
	}
}

// TestPermissionForRoleAgreesWithThePolicy is the property that makes the
// translation worth having rather than a table that happens to be correct.
//
// A nav item is shown when the policy admits the permission the plugin asked
// for, so a translation that named the wrong permission would hide an item from
// a role that could have used it. Both directions are checked: the permission
// is one the policy grants to that role, and it is refused to a role below it —
// which is what a DM-only nav item depends on.
func TestPermissionForRoleAgreesWithThePolicy(t *testing.T) {
	t.Parallel()
	// A campaign that permits public reads, which is the configuration in which
	// a signed-in player's read requirement is satisfiable at all: PermReadPage
	// answers CanReadPublic, and that is the policy's setting rather than the
	// principal's. The interesting cells are the ones above a player, and they
	// are unaffected by the flag.
	pol := authz.NewPolicy(true)
	cases := []struct {
		role authz.Role
		// wantFor is the role a player is checked against for the negative
		// direction: a player must not do whatever this role asked for.
		wantFor authz.Permission
	}{
		{role: authz.RolePlayer, wantFor: authz.PermReadPage},
		{role: authz.RoleDM, wantFor: authz.PermDM},
		{role: authz.RoleAdmin, wantFor: authz.PermAdmin},
	}
	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			t.Parallel()
			// The permission the plugin asked for.
			asked, ok := authz.PermissionForRole(string(tc.role))
			if !ok {
				t.Fatalf("the policy translator does not know the role %q", tc.role)
			}
			if asked != tc.wantFor {
				t.Fatalf("PermissionForRole(%q) = %q, want %q", tc.role, asked, tc.wantFor)
			}
			// The role that asked for it may do it.
			who := authz.Principal{Role: tc.role}
			if err := pol.Check(who, asked, authz.Resource{}); err != nil {
				t.Errorf("%q asked for %q and the policy refuses its own translation: %v", tc.role, asked, err)
			}
			// A player may not do what a DM or an admin asked for, which is the
			// property a role-gated nav entry rests on. A player's own
			// requirement is the one thing a player is granted, so it is excluded
			// from this direction.
			if tc.role != authz.RolePlayer {
				player := authz.Principal{Role: authz.RolePlayer}
				if err := pol.Check(player, asked, authz.Resource{}); err == nil {
					t.Errorf("a player may do %q, which %q asked for", asked, tc.role)
				}
			}
		})
	}
}
