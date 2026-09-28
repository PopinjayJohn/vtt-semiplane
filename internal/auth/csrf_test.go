package auth

import (
	"crypto/subtle"
	"strings"
	"testing"
)

// TestCSRFTokenIsNotDerivedFromTheSessionToken is the reason the two are
// separate values. A CSRF token built from the session token — a truncation, an
// XOR, a keyed hash without a key — means that leaking one leaks something
// about the other, so an attacker who recovers a CSRF token from a referrer
// header, a log line or a cached form has recovered a foothold on the session
// token itself.
//
// The test asserts the property structurally rather than statistically wherever
// it can: no shared prefix at any length, no shared suffix at any length, and
// no shared length relationship. A derivation of any of the three obvious kinds
// fails one of them; independent randomness passes all three.
func TestCSRFTokenIsNotDerivedFromTheSessionToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.seedUser("one", "player")
	h.seedUser("two", "player")
	h.seedUser("three", "player")

	pairs := make([][2]string, 0, 8)
	for _, username := range []string{"one", "two", "three"} {
		session := h.login(username)
		csrf, err := h.svc.CSRFToken(session)
		if err != nil {
			t.Fatalf("csrf token for %s: %v", username, err)
		}
		pairs = append(pairs, [2]string{session, csrf})
	}
	// A second round, so a value that happened to collide once does not pass.
	for _, username := range []string{"one", "two", "three"} {
		session := h.login(username)
		csrf, err := h.svc.SetCSRFToken(session)
		if err != nil {
			t.Fatalf("second csrf token for %s: %v", username, err)
		}
		pairs = append(pairs, [2]string{session, csrf})
	}

	for i, p := range pairs {
		session, csrf := p[0], p[1]
		if len(csrf) == len(session) {
			t.Errorf("pair %d: the CSRF token is %d characters, the same length as the session token: "+
				"two values that are formatted alike make a swap between them invisible", i, len(csrf))
		}
		// The comparison starts at four characters, and that is not a
		// weakening. Two independent values over a 64-character alphabet share
		// a one-character suffix about one time in sixty-four; asserting
		// against that would be asserting that random is not random, and the
		// test would fail roughly every seventh run. A four-character overlap
		// arrives with probability 64^-4, about one run in seven million, and
		// any real derivation — a truncation, a suffix, a masked XOR — shares
		// far more than four characters.
		for n := 4; n <= len(csrf) && n <= len(session); n++ {
			if strings.HasPrefix(csrf, session[:n]) {
				t.Errorf("pair %d: the CSRF token and the session token share a %d-character prefix %q",
					i, n, session[:n])
			}
			if strings.HasSuffix(csrf, session[len(session)-n:]) {
				t.Errorf("pair %d: the CSRF token and the session token share a %d-character suffix %q",
					i, n, session[len(session)-n:])
			}
			if strings.HasPrefix(session, csrf[:n]) {
				t.Errorf("pair %d: the session token starts with the first %d characters of the CSRF token",
					i, n)
			}
		}
		// And neither value contains the other at all, which is the property a
		// derivation of any length would have.
		if strings.Contains(session, csrf) || strings.Contains(csrf, session) {
			t.Errorf("pair %d: one token contains the other", i)
		}
	}
}

func TestCheckCSRF(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("one", "player")
	h.seedUser("two", "player")

	one, two := h.login("one"), h.login("two")
	csrfOne, err := h.svc.CSRFToken(one)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	csrfTwo, err := h.svc.CSRFToken(two)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	if csrfOne == csrfTwo {
		t.Fatal("two sessions were issued the same CSRF token")
	}

	if !h.svc.CheckCSRF(one, csrfOne) {
		t.Error("the session's own token was refused")
	}
	if !h.svc.CheckCSRF(two, csrfTwo) {
		t.Error("the second session's own token was refused")
	}
	for _, tc := range []struct {
		name               string
		session, presented string
	}{
		{"another session's token", one, csrfTwo},
		{"this session's token against another session", two, csrfOne},
		{"an empty value", one, ""},
		{"a session token presented as a CSRF token", one, one},
		{"a CSRF token presented as a session token", csrfOne, csrfOne},
		{"a token of the wrong length", one, csrfOne[:len(csrfOne)-2]},
		{"a token with a non-hex character", one, strings.Repeat("g", len(csrfOne))},
		{"an unknown session", mustToken(t), csrfOne},
		{"no session at all", "", csrfOne},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if h.svc.CheckCSRF(tc.session, tc.presented) {
				t.Error("CheckCSRF accepted a value it should have refused")
			}
		})
	}

	// Rotation replaces the token, so a form rendered before the rotation stops
	// working.
	rotated, err := h.svc.SetCSRFToken(one)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if h.svc.CheckCSRF(one, csrfOne) {
		t.Error("the pre-rotation CSRF token still verifies")
	}
	if !h.svc.CheckCSRF(one, rotated) {
		t.Error("the rotated CSRF token does not verify")
	}

	// Revoking the session revokes the token with it.
	if err := h.svc.Destroy(ctx, one); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if h.svc.CheckCSRF(one, rotated) {
		t.Error("a revoked session's CSRF token still verifies")
	}
}

// TestCSRFTokenIsIndependentPerSession is the companion to the derivation test:
// not merely different from the session token, but different between sessions,
// so one form's token is no use on another page.
func TestCSRFTokenIsIndependentPerSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for i := range 6 {
		h.seedUser("session-"+string(rune('a'+i)), "player")
	}
	seen := map[string]string{}
	for i := range 6 {
		username := "session-" + string(rune('a'+i))
		session := h.login(username)
		token, err := h.svc.CSRFToken(session)
		if err != nil {
			t.Fatalf("csrf for %s: %v", username, err)
		}
		if prev, dup := seen[token]; dup {
			t.Errorf("%s and %s were issued the same CSRF token", prev, username)
		}
		seen[token] = username
	}
	// And CSRFToken is stable for a session, so a page rendered twice does not
	// invalidate the form the reader already has open.
	session := h.login("session-a")
	first, err := h.svc.CSRFToken(session)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	second, err := h.svc.CSRFToken(session)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(first), []byte(second)) != 1 {
		t.Error("CSRFToken returned two different values for one session")
	}
}

// TestCSRFRefusesValuesThatAreNotTokens keeps the cheap shape filter honest: it
// is there to save a database round trip, not to be the security property, and
// it must not throw away a value that CheckCSRF would have accepted.
func TestCSRFRefusesValuesThatAreNotTokens(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, tc := range []struct{ name, session string }{
		{"empty", ""},
		{"too short", "abc"},
		{"too long", strings.Repeat("a", 44)},
		{"not base64url", strings.Repeat("!", 43)},
		{"a passphrase-shaped value", "Correct-Horse-9-xxxxxxxxxxxxxxxxx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.svc.CSRFToken(tc.session); err == nil {
				t.Error("CSRFToken accepted a value that is not a session token")
			}
			if _, err := h.svc.SetCSRFToken(tc.session); err == nil {
				t.Error("SetCSRFToken accepted a value that is not a session token")
			}
			if h.svc.CheckCSRF(tc.session, hexOf(make([]byte, CSRFTokenBytes))) {
				t.Error("CheckCSRF accepted a value against a value that is not a session token")
			}
		})
	}
}

// mustToken mints a token that belongs to no account and no session.
func mustToken(t *testing.T) string {
	t.Helper()
	raw, err := NewToken()
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return raw
}
