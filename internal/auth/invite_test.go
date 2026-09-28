package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// TestInviteIsSingleUse covers the whole redemption once and then again. The
// second attempt must fail, and the failure must leave nothing behind: no
// account, no half-redeemed invite, no session.
func TestInviteIsSingleUse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", "admin")
	admin := h.principal(adminID, "the-admin", "admin")

	raw, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	first, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: raw, Username: "newcomer", Passphrase: "Correct-Horse-9",
	})
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if first.Role != authz.RolePlayer {
		t.Errorf("the first redemption returned role %q, want player", first.Role)
	}
	if h.countUsers() != 2 {
		t.Fatalf("users = %d after the first redemption, want 2", h.countUsers())
	}

	second, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: raw, Username: "newcomer-two", Passphrase: "Correct-Horse-9",
	})
	if !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the second redemption returned %v, want ErrInviteInvalid", err)
	}
	if second.Authenticated() {
		t.Error("the second redemption returned a principal")
	}
	if n := h.countUsers(); n != 2 {
		t.Errorf("users = %d after the second redemption, want 2: the replay created an account", n)
	}
	if _, err := store.GetUserByUsername(ctx, h.db.Reader(), "newcomer-two"); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("the replay created the account anyway: %v", err)
	}
}

// TestInviteIsSingleUseAndUndistinguishableFromUnknown is the enumeration
// property for the redemption endpoint. A token that was already used and a
// token that never existed must produce the same *value*, not merely the same
// sentinel: the handler renders err.Error(), and two different messages on one
// form is a replay oracle.
func TestInviteIsSingleUseAndUndistinguishableFromUnknown(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", "admin")
	admin := h.principal(adminID, "the-admin", "admin")

	used, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: used, Username: "newcomer", Passphrase: "Correct-Horse-9",
	}); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	expired, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0)
	if err != nil {
		t.Fatalf("create expiring invite: %v", err)
	}
	h.advance(config.InviteTTL + time.Hour)

	neverA, neverB := mustToken(t), mustToken(t)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"a token that was already used", used},
		{"a token that never existed", neverA},
		{"another token that never existed", neverB},
		{"a token that expired", expired},
		{"a token of the wrong shape", "not-even-close"},
		{"an empty token", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			who, err := h.svc.AcceptInvite(t.Context(), RedeemRequest{
				Token: tc.token, Username: "someone", Passphrase: "Correct-Horse-9",
			})
			if err != ErrInviteInvalid { //nolint:errorlint // the point is the identical value
				t.Fatalf("err = %#v, want the bare ErrInviteInvalid value", err)
			}
			if who.Authenticated() {
				t.Error("a failed redemption returned a principal")
			}
		})
	}
	if n := h.countUsers(); n != 2 {
		t.Errorf("users = %d after five failed redemptions, want 2", n)
	}
}

func TestAnExpiredInviteIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", "admin")
	admin := h.principal(adminID, "the-admin", "admin")

	raw, err := h.svc.CreateInvite(ctx, admin, authz.RoleDM, config.InviteTTL)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	h.advance(config.InviteTTL + time.Second)
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: raw, Username: "too-late", Passphrase: "Correct-Horse-9",
	}); err != ErrInviteInvalid { //nolint:errorlint // an expiry is an unknown token
		t.Fatalf("err = %v, want ErrInviteInvalid", err)
	}
	if n := h.countUsers(); n != 1 {
		t.Errorf("users = %d after an expired redemption, want 1", n)
	}
}

// TestInviteGrantsTheInvitedRoleNotTheActors is the privilege boundary. An
// admin who invites a player has issued a player; copying the issuer's role
// across would make every invite a second admin.
//
// Every row is issued by an admin, because an admin is the only principal that
// can issue at all — TestOnlyAnAdminMayCreateAnInvite covers the refusal — and
// the point of the table is that the three invited roles all come out exactly
// as asked, including the one that matches the issuer.
func TestInviteGrantsTheInvitedRoleNotTheActors(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	for _, invited := range []authz.Role{authz.RolePlayer, authz.RoleDM, authz.RoleAdmin} {
		t.Run("an invite for a "+string(invited), func(t *testing.T) {
			// A vault per case, so the issuers do not accumulate and the
			// usernames do not collide with each other.
			h := newHarness(t)
			issuerName := "issuer-of-a-" + string(invited)
			issuerID := h.seedUser(issuerName, "admin")
			issuer := h.principal(issuerID, issuerName, "admin")

			raw, err := h.svc.CreateInvite(ctx, issuer, invited, 0)
			if err != nil {
				t.Fatalf("create invite: %v", err)
			}
			who, err := h.svc.AcceptInvite(ctx, RedeemRequest{
				Token: raw, Username: "accepting", DisplayName: "The Accepting",
				Passphrase: "Correct-Horse-9",
			})
			if err != nil {
				t.Fatalf("redeem: %v", err)
			}
			if who.Role != invited {
				t.Errorf("the new account has role %q, want the invited %q (the issuer was an admin)",
					who.Role, invited)
			}
			if who.UserID == issuerID {
				t.Error("the new principal is the issuer's")
			}
			u, err := store.GetUserByUsername(ctx, h.db.Reader(), "accepting")
			if err != nil {
				t.Fatalf("load the new account: %v", err)
			}
			if u.Role != invited.String() {
				t.Errorf("the stored role is %q, want %q", u.Role, invited)
			}
			if u.DisplayName != "The Accepting" {
				t.Errorf("display name is %q, want the one that was given", u.DisplayName)
			}
		})
	}
}

// TestOnlyAnAdminMayCreateAnInvite runs the real policy over all four
// principals, including the anonymous one, and requires that only the admin gets
// a token. It uses Policy rather than a role comparison, because that is the
// only way the answer is allowed to be produced.
func TestOnlyAnAdminMayCreateAnInvite(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()

	actors := []struct {
		name string
		who  authz.Principal
	}{
		{"an admin", h.principal(h.seedUser("an-admin", "admin"), "an-admin", "admin")},
		{"a dm", h.principal(h.seedUser("a-dm", "dm"), "a-dm", "dm")},
		{"a player", h.principal(h.seedUser("a-player", "player"), "a-player", "player")},
		{"an anonymous visitor", authz.Anonymous(true)},
	}
	for _, actor := range actors {
		t.Run(actor.name, func(t *testing.T) {
			raw, err := h.svc.CreateInvite(ctx, actor.who, authz.RolePlayer, 0)
			if actor.who.IsAdmin() {
				if err != nil {
					t.Fatalf("an admin could not create an invite: %v", err)
				}
				if !wellFormedToken(raw) {
					t.Fatalf("an admin's invite returned %q, which is not a token", raw)
				}
				return
			}
			if !errors.Is(err, authz.ErrDenied) {
				t.Fatalf("err = %v, want authz.ErrDenied", err)
			}
			if raw != "" {
				t.Errorf("a refused invite still returned a token: %q", raw)
			}
			if n := h.countUsers(); n != 3 {
				t.Errorf("users = %d, want 3; a refused invite created something", n)
			}
		})
	}
}

func TestAnInviteMayNotGrantARoleThatIsNotStorable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	admin := h.principal(h.seedUser("an-admin", "admin"), "an-admin", "admin")

	for _, role := range []authz.Role{authz.RoleAnonymous, authz.Role(""), authz.Role("root"), authz.Role("Admin")} {
		if _, err := h.svc.CreateInvite(ctx, admin, role, 0); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("an invite granting %q was accepted: err = %v", role, err)
		}
	}
	if n := h.countUsers(); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}
}

// TestListedInvitesCarryNoToken is that the admin list is not a credential
// store. It checks the returned views *and* the raw rows, because a future
// change that switches the list to return store.Invite would be invisible to a
// test that only looked at what the UI renders.
func TestListedInvitesCarryNoToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("an-admin", "admin")
	admin := h.principal(adminID, "an-admin", "admin")

	issued := make([]string, 0, 3)
	for range 3 {
		raw, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0)
		if err != nil {
			t.Fatalf("create invite: %v", err)
		}
		issued = append(issued, raw)
	}

	views, err := h.svc.ListInvites(ctx, admin)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(views) != 3 {
		t.Fatalf("the list holds %d invites, want 3", len(views))
	}
	seen := map[string]bool{}
	for _, v := range views {
		if len(v.ID) != InviteIDChars {
			t.Errorf("invite id %q is %d characters, want %d", v.ID, len(v.ID), InviteIDChars)
		}
		if seen[v.ID] {
			t.Errorf("two invites share the id %q", v.ID)
		}
		seen[v.ID] = true
		if !v.Pending {
			t.Error("a freshly issued invite is not pending")
		}
		if v.RedeemedAt != nil {
			t.Error("a freshly issued invite carries a redemption time")
		}
		if v.Role != authz.RolePlayer {
			t.Errorf("role = %q, want player", v.Role)
		}
	}

	// The identifier has to be derivable, or the list is a list of nothing.
	for _, raw := range issued {
		if !seen[InviteID(raw)] {
			t.Errorf("InviteID(%q) = %q, which is not in the list", raw, InviteID(raw))
		}
	}

	// The rows behind the list do carry the full hash, which is why the list
	// does not: a leaked admin page must not be a set of working credentials.
	for _, i := range h.inviteRows(ctx) {
		if len(i.TokenHash) == InviteIDChars {
			t.Errorf("the stored token hash is %d characters; the test's whole premise is that it is longer", len(i.TokenHash))
		}
		for _, raw := range issued {
			if i.TokenHash == raw {
				t.Error("an invite row stores the raw token")
			}
		}
	}
}

func TestOnlyAnAdminMayListInvites(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	for _, tc := range []struct {
		name string
		who  authz.Principal
	}{
		{"a dm", h.principal(h.seedUser("a-dm", "dm"), "a-dm", "dm")},
		{"a player", h.principal(h.seedUser("a-player", "player"), "a-player", "player")},
		{"an anonymous visitor", authz.Anonymous(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, err := h.svc.ListInvites(ctx, tc.who)
			if !errors.Is(err, authz.ErrDenied) {
				t.Fatalf("err = %v, want authz.ErrDenied", err)
			}
			if views != nil {
				t.Errorf("a refused list returned %d rows", len(views))
			}
		})
	}
}

func TestPruneExpiredInvitesKeepsTheLiveOnes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	admin := h.principal(h.seedUser("an-admin", "admin"), "an-admin", "admin")
	if _, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	h.advance(config.InviteTTL + time.Hour)
	if _, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0); err != nil {
		t.Fatalf("create second invite: %v", err)
	}

	n, err := h.svc.PruneExpiredInvites(ctx, h.now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("PruneExpiredInvites removed %d, want 1", n)
	}
	views, err := h.svc.ListInvites(ctx, admin)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(views) != 1 || !views[0].Pending {
		t.Errorf("the live invite is not the one that survived: %+v", views)
	}
}

// TestAnInviteTokenIsOnlyInTheRowAsItsHash closes the loop on the raw token: it
// is in the URL, and the URL is the caller's to keep.
func TestAnInviteTokenIsOnlyInTheRowAsItsHash(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	admin := h.principal(h.seedUser("an-admin", "admin"), "an-admin", "admin")
	raw, err := h.svc.CreateInvite(ctx, admin, authz.RolePlayer, 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	rows := h.inviteRows(ctx)
	if len(rows) != 1 {
		t.Fatalf("the invites table holds %d rows, want 1", len(rows))
	}
	if rows[0].TokenHash != HashToken(raw) {
		t.Errorf("token hash = %q, want the sha256 of the token", rows[0].TokenHash)
	}
	if rows[0].TokenHash == raw {
		t.Error("the invites table stores the raw token")
	}
	if rows[0].CreatedBy != admin.UserID {
		t.Errorf("created_by = %d, want the admin's id %d", rows[0].CreatedBy, admin.UserID)
	}
	if !strings.HasPrefix(InviteID(raw), rows[0].TokenHash[:InviteIDChars]) {
		t.Error("InviteID is not a prefix of the stored hash")
	}
}

// inviteRows is every invite row, read through the store.
func (h *harness) inviteRows(ctx context.Context) []store.Invite {
	h.t.Helper()
	rows, err := store.ListInvites(ctx, h.db.Reader())
	if err != nil {
		h.t.Fatalf("list invites: %v", err)
	}
	return rows
}
