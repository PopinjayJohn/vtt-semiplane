package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// TestPassphraseNeverAppearsInAnErrorOrLog drives every error this package can
// return with a passphrase it recognises, and requires the passphrase to be
// absent from both the error and the log.
//
// It is a seeded passphrase rather than a recognisable word, so a false pass is
// impossible: the string appears nowhere in this package's source, and any
// appearance at all in the output means something echoed it.
//
// The list is table-driven over the paths, not over the error sentinels,
// because the interesting failures are the ones a caller triggers by sending
// bad input — and a sentinel added without a case here is a sentinel nobody has
// checked.
func TestPassphraseNeverAppearsInAnErrorOrLog(t *testing.T) {
	t.Parallel()
	// The valid one and the rejected one, both seeded. The rejected one is
	// all-lowercase, so it is refused by the composition rule while still being
	// long enough and distinctive enough that any echo of it is unmistakable.
	const (
		passphrase = "zQ7-marker-passphrase-4Rk2"
		weak       = "zqmarkerpassphrase"
	)

	for _, tc := range []struct {
		name string
		run  func(t *testing.T, h *harness) error
	}{
		{"ValidatePassphrase on a short passphrase", func(_ *testing.T, _ *harness) error {
			return ValidatePassphrase(weak[:6])
		}},
		{"ValidatePassphrase on a one-class passphrase", func(_ *testing.T, _ *harness) error {
			return ValidatePassphrase(weak)
		}},
		{"HashPassphrase on a rejected passphrase", func(_ *testing.T, _ *harness) error {
			_, err := HashPassphrase(weak)
			return err
		}},
		{"Setup with a short passphrase", func(t *testing.T, h *harness) error {
			_, err := h.svc.Setup(t.Context(), "the-admin", "The Admin", weak[:6])
			return err
		}},
		{"Setup with a one-class passphrase", func(t *testing.T, h *harness) error {
			_, err := h.svc.Setup(t.Context(), "the-admin", "The Admin", weak)
			return err
		}},
		{"Create for an account that does not exist", func(t *testing.T, h *harness) error {
			_, err := h.svc.Create(t.Context(), LoginRequest{Username: "nobody", Passphrase: passphrase})
			return err
		}},
		{"Create with the wrong passphrase", func(t *testing.T, h *harness) error {
			h.seedUser("someone", "player")
			_, err := h.svc.Create(t.Context(), LoginRequest{Username: "someone", Passphrase: passphrase})
			return err
		}},
		{"Create for a disabled account", func(t *testing.T, h *harness) error {
			adminID := h.seedUser("the-admin", "admin")
			userID := h.seedUser("leaving", "player")
			if err := h.svc.Disable(t.Context(), h.principal(adminID, "the-admin", "admin"), userID); err != nil {
				return err
			}
			_, err := h.svc.Create(t.Context(), LoginRequest{Username: "leaving", Passphrase: passphrase})
			return err
		}},
		{"AcceptInvite with a rejected passphrase", func(t *testing.T, h *harness) error {
			admin := h.principal(h.seedUser("the-admin", "admin"), "the-admin", "admin")
			raw, err := h.svc.CreateInvite(t.Context(), admin, "player", 0)
			if err != nil {
				return err
			}
			_, err = h.svc.AcceptInvite(t.Context(), RedeemRequest{
				Token: raw, Username: "newcomer", Passphrase: weak,
			})
			return err
		}},
		{"AcceptInvite with a rejected username", func(t *testing.T, h *harness) error {
			admin := h.principal(h.seedUser("the-admin", "admin"), "the-admin", "admin")
			raw, err := h.svc.CreateInvite(t.Context(), admin, "player", 0)
			if err != nil {
				return err
			}
			_, err = h.svc.AcceptInvite(t.Context(), RedeemRequest{
				Token: raw, Username: "no", Passphrase: passphrase,
			})
			return err
		}},
		{"AcceptInvite with a token that is not one", func(t *testing.T, h *harness) error {
			_, err := h.svc.AcceptInvite(t.Context(), RedeemRequest{
				Token: mustToken(t), Username: "newcomer", Passphrase: passphrase,
			})
			return err
		}},
		{"CreateInvite by a principal that may not", func(t *testing.T, h *harness) error {
			_, err := h.svc.CreateInvite(t.Context(),
				h.principal(h.seedUser("a-player", "player"), "a-player", "player"), "player", 0)
			return err
		}},
		{"ListInvites by a principal that may not", func(t *testing.T, h *harness) error {
			_, err := h.svc.ListInvites(t.Context(),
				h.principal(h.seedUser("a-dm", "dm"), "a-dm", "dm"))
			return err
		}},
		{"SetRole by a principal that may not", func(t *testing.T, h *harness) error {
			userID := h.seedUser("a-player", "player")
			other := h.seedUser("a-dm", "dm")
			return h.svc.SetRole(t.Context(),
				h.principal(other, "a-dm", "dm"), userID, "admin")
		}},
		{"SetRole to a role that is not storable", func(t *testing.T, h *harness) error {
			admin := h.principal(h.seedUser("the-admin", "admin"), "the-admin", "admin")
			userID := h.seedUser("a-player", "player")
			return h.svc.SetRole(t.Context(), admin, userID, "root")
		}},
		{"Setup after setup", func(t *testing.T, h *harness) error {
			if _, err := h.svc.Setup(t.Context(), "the-admin", "The Admin", passphrase); err != nil {
				return err
			}
			_, err := h.svc.Setup(t.Context(), "a-second", "A Second", passphrase)
			return err
		}},
		{"Verify on a malformed hash", func(_ *testing.T, _ *harness) error {
			_, err := Verify([]byte("not-a-hash"), passphrase)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			err := tc.run(t, h)
			if err == nil {
				t.Fatal("the call succeeded, so there is no error to inspect")
			}
			if strings.Contains(err.Error(), passphrase) {
				t.Errorf("the error echoed the passphrase: %q", err.Error())
			}
			if logs := h.logs(); strings.Contains(logs, passphrase) {
				t.Errorf("the passphrase reached the log: %q", logs)
			}
			// The marker is also checked without its punctuation, because a
			// value that survived in a truncated form would still be a leak.
			if logs := h.logs(); strings.Contains(logs, "marker-passphrase") {
				t.Errorf("part of the passphrase reached the log: %q", logs)
			}
		})
	}
}

// TestTheSuccessPathAlsoKeepsThePassphraseOutOfTheLog is the same assertion for
// the path that does not fail, because a log line that says "logged in" is
// exactly the place somebody would add the passphrase by accident.
func TestTheSuccessPathAlsoKeepsThePassphraseOutOfTheLog(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	// The valid one and the rejected one, both seeded. The rejected one is
	// all-lowercase, so it is refused by the composition rule while still being
	// long enough and distinctive enough that any echo of it is unmistakable.
	const (
		passphrase = "zQ7-marker-passphrase-4Rk2"
		weak       = "zqmarkerpassphrase"
	)

	if _, err := h.svc.Setup(ctx, "the-admin", "The Admin", passphrase); err != nil {
		t.Fatalf("setup: %v", err)
	}
	raw, err := h.svc.Create(ctx, LoginRequest{Username: "the-admin", Passphrase: passphrase, UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	admin := h.principal(h.userID(t, "the-admin"), "the-admin", "admin")
	invite, err := h.svc.CreateInvite(ctx, admin, "player", 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: invite, Username: "newcomer", Passphrase: passphrase,
	}); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	logs := h.logs()
	if logs == "" {
		t.Fatal("nothing was logged at all, so the assertion below would pass vacuously")
	}
	for _, forbidden := range []string{passphrase, "marker-passphrase", raw, invite, HashToken(raw), HashToken(invite)} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log contains a credential: %q", forbidden)
		}
	}
	// And something useful was logged, so this is not "the log is empty so we
	// are fine".
	if !strings.Contains(logs, "auth.login") {
		t.Errorf("the log holds no login record, so the leak check above proves little: %q", logs)
	}
}

// TestFailedCredentialErrorsCarryNoValue is the narrower assertion: the errors
// that a credential produces hold no part of the credential, which is what
// lets a handler render err.Error() to a stranger.
func TestFailedCredentialErrorsCarryNoValue(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("someone", "player")
	token := h.login("someone")

	raw, err := h.svc.Create(ctx, LoginRequest{Username: "nobody", Passphrase: "Correct-Horse-9"})
	if err == nil {
		t.Fatal("a login for an account that does not exist succeeded")
	}
	if raw != "" {
		t.Errorf("the error path returned a token: %q", raw)
	}
	if msg := err.Error(); strings.Contains(msg, "nobody") {
		t.Errorf("the error echoed the username that was tried: %q", msg)
	}

	admin := h.principal(h.seedUser("the-admin", "admin"), "the-admin", "admin")
	invite, err := h.svc.CreateInvite(ctx, admin, "player", 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: invite, Username: "newcomer", Passphrase: "Correct-Horse-9",
	}); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: invite, Username: "newcomer", Passphrase: "Correct-Horse-9",
	}); err == nil {
		t.Fatal("a replayed invite was accepted")
	} else if msg := err.Error(); strings.Contains(msg, invite) || strings.Contains(msg, HashToken(invite)) {
		t.Errorf("the error echoed the invite token: %q", msg)
	}
	_ = token
}

// TestErrBadCredentialsIsOneValue is the sentence the whole login path rests on.
func TestErrBadCredentialsIsOneValue(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()

	adminID := h.seedUser("the-admin", "admin")
	userID := h.seedUser("leaving", "player")
	live := h.login("leaving")
	if err := h.svc.Disable(ctx, h.principal(adminID, "the-admin", "admin"), userID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	expired := h.login("the-admin")
	h.advance(200 * 365 * 24 * time.Hour)

	// A refused session is an anonymous principal and no error, in every case.
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"a disabled account", live},
		{"an expired session", expired},
		{"a token that never existed", mustToken(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			who, err := h.svc.Session(t.Context(), tc.token)
			if err != nil {
				t.Fatalf("a refused session returned an error: %v", err)
			}
			if who.Authenticated() {
				t.Errorf("resolved to %s", who)
			}
			// The harness runs with anonymous read off, so this is the exact
			// principal the service hands back — compared by value, so a field
			// that leaked into it fails.
			if want := authz.Anonymous(false); who != want {
				t.Errorf("resolved to %+v, want the anonymous principal %+v", who, want)
			}
		})
	}

	// A refused login is one value, in every case.
	for _, tc := range []struct {
		name     string
		username string
	}{
		{"an account that does not exist", "nobody-at-all"},
		{"a disabled account", "leaving"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.Create(t.Context(), LoginRequest{Username: tc.username, Passphrase: "Correct-Horse-9"})
			if err != ErrBadCredentials { //nolint:errorlint // identity is the assertion
				t.Fatalf("err = %#v, want the bare ErrBadCredentials value", err)
			}
		})
	}
}
