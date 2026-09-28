package auth

import (
	"errors"
	"strings"
	"testing"
)

// TestUsernameValidation is the whole shape rule, accepted and rejected. The
// rejected cases are the interesting half: each one is a username that would
// have caused a specific confusion somewhere downstream.
func TestUsernameValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		username string
		reason   string
	}{
		// Accepted.
		{"shortest", "abc", ""},
		{"longest", strings.Repeat("a", 32), ""},
		{"lowercase", "gundren", ""},
		{"mixed case", "Gundren", ""},
		{"digits", "player2", ""},
		{"a dash", "gundren-black", ""},
		{"dots", "gundren.black", ""},
		{"an underscore", "gundren_rocks", ""},
		{"all three punctuation marks", "a-b.c_d", ""},
		{"punctuation at both ends", "-gundren.", ""},

		// Rejected: length.
		{"two characters", "ab", "must be 3 to 32 characters"},
		{"empty", "", "must be 3 to 32 characters"},
		{"one over the maximum", strings.Repeat("a", 33), "must be 3 to 32 characters"},
		{"thirty-three multi-byte runes", strings.Repeat("é", 33), "must be 3 to 32 characters"},

		// Rejected: characters.
		{"a space", "gundren rocks", "may contain only letters"},
		{"an at sign", "gundren@home", "may contain only letters"},
		{"a slash", "gundren/rock", "may contain only letters"},
		{"a path traversal", "../etc", "may contain only letters"},
		{"an angle bracket", "<script>", "may contain only letters"},
		{"a NUL", "gun\x00dren", "may contain only letters"},
		{"a non-ASCII letter", "gundrén", "may contain only letters"},
		{"a non-ASCII digit", "gundren２", "may contain only letters"},
		{"an emoji", "gundren🎲", "may contain only letters"},

		// Rejected: nothing but punctuation. These pass a naive
		// allowed-characters check and produce a name with no letters in it at
		// all, which reads as a system artefact in every list they appear in.
		{"three dots", "...", "must contain a letter or a digit"},
		{"three dashes", "---", "must contain a letter or a digit"},
		{"a mix of dots and dashes", ".-.-", "must contain a letter or a digit"},
		{"thirty-two dashes", strings.Repeat("-", 32), "must contain a letter or a digit"},
		{"a run of punctuation", "..--..", "must contain a letter or a digit"},

		// Rejected: role names. Each of these is a string the rest of the
		// system already uses to mean something else, and a log line saying
		// `actor=dm` is then ambiguous between the role and the person.
		{"admin", "admin", "is a role name"},
		{"Admin", "Admin", "is a role name"},
		{"ADMIN", "ADMIN", "is a role name"},
		{"dm", "dm", "is a role name"},
		{"DM", "DM", "is a role name"},
		{"player", "player", "is a role name"},
		{"Player", "Player", "is a role name"},
		{"anon", "anon", "is a role name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUsername(tc.username)
			switch {
			case tc.reason == "" && err != nil:
				t.Fatalf("ValidateUsername(%q) = %v, want nil", tc.username, err)
			case tc.reason != "" && err == nil:
				t.Fatalf("ValidateUsername(%q) = nil, want %q", tc.username, tc.reason)
			case tc.reason != "" && !errors.Is(err, ErrInvalidUsername):
				t.Fatalf("err = %v, want it to match ErrInvalidUsername", err)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("reason = %q, want it to mention %q", err.Error(), tc.reason)
			}
		})
	}
}

// TestUsernameRejectionNeverEchoesTheName is the property the typed errors buy:
// a rejected username reaches a log through three layers, and the value that
// was rejected is the value a caller least wants written down.
func TestUsernameRejectionNeverEchoesTheName(t *testing.T) {
	t.Parallel()
	const name = "gundren@hacker.example"
	err := ValidateUsername(name)
	if err == nil {
		t.Fatalf("ValidateUsername(%q) = nil", name)
	}
	if strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "hacker.example") {
		t.Errorf("the error echoed the rejected name: %q", err.Error())
	}
}

// TestUniquenessIsTheIndexAndNotAQuery is the reason ValidateUsername says
// nothing about whether a name is taken: the COLLATE NOCASE unique index is the
// only authority, and it is the only one that can be right under concurrency.
// The test inserts a name, then a case variant of it, and requires the index —
// not a lookup this package performed — to refuse.
func TestUniquenessIsTheIndexAndNotAQuery(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()

	adminID := h.seedUser("collision", "admin")
	raw, err := h.svc.CreateInvite(ctx, h.principal(adminID, "collision", "admin"), "player", 0)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	_, err = h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: raw, Username: "Collision", Passphrase: "Correct-Horse-9",
	})
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("a case-variant of an existing username was accepted: err = %v", err)
	}
	if n := h.countUsers(); n != 1 {
		t.Errorf("users = %d after a refused redemption, want 1 (the admin and nothing else)", n)
	}

	// The distinguishing case is a same-case duplicate, which a NOCASE index
	// must also refuse, and which a case-sensitive one would let through.
	raw2, err := h.svc.CreateInvite(ctx, h.principal(adminID, "collision", "admin"), "player", 0)
	if err != nil {
		t.Fatalf("create second invite: %v", err)
	}
	if _, err := h.svc.AcceptInvite(ctx, RedeemRequest{
		Token: raw2, Username: "collision", Passphrase: "Correct-Horse-9",
	}); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("a duplicate username was accepted: err = %v", err)
	}
}
