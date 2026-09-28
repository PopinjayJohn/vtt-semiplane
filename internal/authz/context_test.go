package authz_test

import (
	"context"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// The context carrier is a security boundary now, and these are the two
// directions it can fail in.
//
// It became one when a plugin needed it. plugin.PageStore takes a principal on
// every method, and a plugin is forbidden from importing httpapi — so before
// this existed, the value was on the context and unreachable, and the honest
// options were all bad: a plugin that reads nothing, or a plugin that fabricates
// a principal. Both were considered and both are worse than three lines here.

// TestThePrincipalRoundTrips is the ordinary case, and it is here so the
// failure direction is unambiguous: a caller that does the obvious thing gets
// their own principal back, not a zero value.
func TestThePrincipalRoundTrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   authz.Principal
	}{
		{name: "a player", in: authz.ForUser(7, "thia", authz.RolePlayer, false)},
		{name: "a dm", in: authz.ForUser(3, "gm", authz.RoleDM, false)},
		{name: "an admin", in: authz.ForUser(1, "root", authz.RoleAdmin, false)},
		{name: "an anonymous reader with the flag on", in: authz.Anonymous(true)},
		{name: "an anonymous reader with the flag off", in: authz.Anonymous(false)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := authz.PrincipalFrom(authz.WithPrincipal(context.Background(), tc.in))
			if got != tc.in {
				t.Errorf("PrincipalFrom(WithPrincipal(%v)) = %+v, want %+v", tc.in, got, tc.in)
			}
		})
	}
}

// TestAPrincipalThatWasNeverSetReadsAsAnonymous is the direction that matters.
//
// The zero Principal is not the same as authz.Anonymous(true), and the
// difference is the whole reason this is worth a test. Anonymous(true) can read
// public content; the zero value cannot. A caller holding a context nobody wrote
// a principal into — a background goroutine that forgot, a test that built the
// context by hand, a future caller that resolved the session elsewhere — must
// read as the one that sees nothing, so that the mistake is a blank page rather
// than a page it should not have had.
func TestAPrincipalThatWasNeverSetReadsAsAnonymous(t *testing.T) {
	t.Parallel()

	got := authz.PrincipalFrom(context.Background())
	if got.Authenticated() {
		t.Error("a context with no principal resolved as authenticated")
	}
	if got.CanReadPublic() {
		t.Error("a context with no principal may read public content; the zero value must be the closed one")
	}
	if got.IsDM() {
		t.Error("a context with no principal resolved as a DM")
	}
	if got != (authz.Principal{}) {
		t.Errorf("PrincipalFrom on a bare context = %+v, want the zero Principal", got)
	}
}

// TestTheZeroPrincipalIsNotAnonymousWithRead pins the distinction the test above
// depends on, as a fact about the type rather than as a consequence of it.
//
// If someone "fixes" PrincipalFrom to return authz.Anonymous(true) on a miss —
// which is a one-word change and looks like a kindness — every caller that ever
// loses its principal becomes a reader with public access. This fails first.
func TestTheZeroPrincipalIsNotAnonymousWithRead(t *testing.T) {
	t.Parallel()

	if (authz.Principal{}) == authz.Anonymous(true) {
		t.Fatal("the zero Principal and Anonymous(true) are equal, so a missing principal silently grants public read")
	}
	if authz.Anonymous(true).CanReadPublic() != true {
		t.Fatal("Anonymous(true) cannot read public content; the tripwire above is testing the wrong thing")
	}
	if (authz.Principal{}).CanReadPublic() != false {
		t.Fatal("the zero Principal can read public content")
	}
}

// TestTheLastPrincipalWins is what "exactly one writer" buys.
//
// The session middleware writes once per request, so a second write is a bug —
// but if one happens, it must be deterministic rather than order-dependent on
// which layer happened to look first. Overwrite, not first-wins: a context
// carrying the wrong principal is the dangerous state, and a second correct
// write is the only thing that can repair it.
func TestTheLastPrincipalWins(t *testing.T) {
	t.Parallel()

	first := authz.ForUser(1, "first", authz.RolePlayer, false)
	second := authz.ForUser(2, "second", authz.RoleDM, false)

	ctx := authz.WithPrincipal(context.Background(), first)
	ctx = authz.WithPrincipal(ctx, second)

	if got := authz.PrincipalFrom(ctx); got != second {
		t.Errorf("PrincipalFrom = %+v, want the last principal written (%+v)", got, second)
	}
}

// TestTheKeyIsNotGuessableFromOutside guards the other half of the contract: a
// caller must go through these two functions rather than building the key
// itself.
//
// This is a compile-time property — contextKey is unexported, so no other
// package can construct a value that compares equal to the key — and the test
// cannot assert a compile error at runtime. What it can assert is the property
// the unexported type buys: a *different* package's own key of the same name
// does not collide, which is what would happen if the key were a bare string.
func TestTheKeyIsNotGuessableFromOutside(t *testing.T) {
	t.Parallel()

	type foreignKey struct{ name string }
	foreign := context.WithValue(context.Background(), foreignKey{"authz.principal"},
		authz.ForUser(99, "impostor", authz.RoleAdmin, false))

	got := authz.PrincipalFrom(foreign)
	if got.UserID == 99 {
		t.Error("a value stored under a structurally identical foreign key was read as the principal")
	}
	if got.CanReadPublic() {
		t.Error("a foreign key granted public read")
	}
}
