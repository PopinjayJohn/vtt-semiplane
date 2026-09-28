package auth

import (
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// Signing out has to close what the sign-out opened.
//
// This is the one authorization change that does not change what anybody may
// *read* — the account still exists, the role is the same, the pages are the
// same — and it is therefore the one a generation bump gets forgotten on. But a
// live-push stream captures its principal when it connects and re-renders under
// that captured identity for as long as it is open, so a stream that survives a
// sign-out keeps delivering content to somebody the server would now answer with
// an anonymous principal. Nothing downstream re-checks: that is the design, and
// it is what makes the push path safe from the SQL side and fragile from the
// lifecycle side.
//
// So the property is pinned here rather than left to the push path's own tests,
// which would be the wrong place to change it: the push path must terminate on a
// generation change, and this is what makes sure a sign-out produces one.

func generation(t *testing.T, h *harness) int64 {
	t.Helper()
	g, err := store.AuthzGeneration(t.Context(), h.db.Reader())
	if err != nil {
		t.Fatalf("read the authorization generation: %v", err)
	}
	return g
}

// TestSigningOutBumpsTheAuthorizationGeneration is the whole claim.
func TestSigningOutBumpsTheAuthorizationGeneration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("leaving", authz.RolePlayer)
	raw := h.login("leaving")

	before := generation(t, h)
	if err := h.svc.Destroy(ctx, raw); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if after := generation(t, h); after <= before {
		t.Errorf("signing out left the authorization generation at %d, was %d: a stream captured under that account would survive the sign-out", after, before)
	}
	// Session answers an unknown token with the anonymous principal and no
	// error, so the assertion is about the principal rather than about err.
	who, err := h.svc.Session(ctx, raw)
	if err != nil {
		t.Fatalf("resolve the session after a sign-out: %v", err)
	}
	if who.Authenticated() {
		t.Errorf("the session still authenticates as %q after a sign-out", who.Username)
	}
}

// TestSigningOutRevokesTheSessionAndNothingElse is the other half: the bump is
// an addition to the sign-out, not a replacement for it.
func TestSigningOutRevokesTheSessionAndNothingElse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	userID := h.seedUser("leaving", authz.RolePlayer)
	raw := h.login("leaving")

	if err := h.svc.Destroy(ctx, raw); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if _, err := store.GetUserByID(ctx, h.db.Reader(), userID); err != nil {
		t.Errorf("the account was removed by a sign-out: %v", err)
	}

	// A malformed or unknown token is a no-op, and it must not bump the
	// generation either. Otherwise any request carrying a junk cookie would
	// close every open stream in the campaign, which turns "I signed out in one
	// tab" into "everybody's tabs reconnected" — and a per-request cost is not
	// worth paying for a session that was not there.
	before := generation(t, h)
	for _, token := range []string{"not-a-token", "", strings.Repeat("z", 64)} {
		if err := h.svc.Destroy(ctx, token); err != nil {
			t.Fatalf("sign out with %q: %v", token, err)
		}
	}
	if after := generation(t, h); after != before {
		t.Errorf("a malformed sign-out moved the authorization generation from %d to %d", before, after)
	}
}

// TestChangingPageOwnershipBumpsTheAuthorizationGeneration covers the other half
// of the same bug.
//
// Ownership is the input that decides whether a `private` secret on that page is
// readable, so a grant makes a body available to somebody who could not fetch it
// and a revoke takes away one they could. A stream captured before either is
// serving under the old answer, and the revoke is the direction that has to take
// effect immediately.
func TestChangingPageOwnershipBumpsTheAuthorizationGeneration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	userID := h.seedUser("owner", authz.RolePlayer)

	page, err := store.UpsertPage(ctx, h.db.Writer(), store.Page{
		Path: "Tavern.md", Basename: "Tavern", Title: "Tavern",
		ContentHash: []byte("x"), MTimeUnix: 1, SizeBytes: 1,
		PageType: "note", CreatedAt: clockNow, UpdatedAt: clockNow,
	})
	if err != nil {
		t.Fatalf("create the page: %v", err)
	}

	before := generation(t, h)
	if err := store.AddPageOwner(ctx, h.db.Writer(), store.PageOwner{
		PageID: page, UserID: userID, IsOwner: true, AddedAt: clockNow,
	}); err != nil {
		t.Fatalf("grant ownership: %v", err)
	}
	afterGrant := generation(t, h)
	if afterGrant <= before {
		t.Errorf("granting ownership left the authorization generation at %d, was %d", afterGrant, before)
	}

	if err := store.RemovePageOwner(ctx, h.db.Writer(), page, userID); err != nil {
		t.Fatalf("revoke ownership: %v", err)
	}
	if afterRevoke := generation(t, h); afterRevoke <= afterGrant {
		t.Errorf("revoking ownership left the authorization generation at %d, was %d: this is the direction that must take effect immediately", afterRevoke, afterGrant)
	}
}

// TestARoleChangeStillBumpsTheGeneration is the control: the paths that already
// bumped must keep bumping, so the two above are an addition rather than a
// replacement.
func TestARoleChangeStillBumpsTheGeneration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", authz.RoleAdmin)
	userID := h.seedUser("promoted", authz.RolePlayer)

	before := generation(t, h)
	if err := h.svc.SetRole(ctx, h.principal(adminID, "the-admin", authz.RoleAdmin), userID, authz.RoleDM); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if after := generation(t, h); after <= before {
		t.Errorf("a role change left the authorization generation at %d, was %d", after, before)
	}
}
