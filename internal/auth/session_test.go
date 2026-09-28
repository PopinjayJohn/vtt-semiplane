package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// TestTwoConcurrentSetupsProduceOneAdmin runs N callers at the same instant and
// requires exactly one admin.
//
// The usernames are deliberately all different. With one shared username the
// second insert would be refused by the unique index, the test would pass, and
// the first-run gate would still be broken — the failure would be hidden behind
// a constraint that happens to fire for a different reason.
func TestTwoConcurrentSetupsProduceOneAdmin(t *testing.T) {
	t.Parallel()
	const n = 5
	h := newHarness(t)
	ctx := t.Context()

	type outcome struct {
		principal authz.Principal
		err       error
	}
	outcomes := make([]outcome, n)

	var start, done sync.WaitGroup
	start.Add(1)
	done.Add(n)
	for i := range n {
		go func(i int) {
			defer done.Done()
			username := "admin-" + string(rune('a'+i))
			// Line the goroutines up on the barrier so they contend rather
			// than arriving in sequence; without it the first one usually
			// finishes before the second starts and the test proves nothing.
			start.Wait()
			p, err := h.svc.Setup(ctx, username, username, "Correct-Horse-9")
			outcomes[i] = outcome{principal: p, err: err}
		}(i)
	}
	start.Done()
	done.Wait()

	succeeded := 0
	for i, got := range outcomes {
		switch {
		case got.err == nil:
			succeeded++
			if got.principal.Role != authz.RoleAdmin {
				t.Errorf("caller %d: Setup returned role %q, want admin", i, got.principal.Role)
			}
			if !got.principal.Authenticated() {
				t.Errorf("caller %d: Setup returned an unauthenticated principal", i)
			}
		case errors.Is(got.err, authz.ErrSetupClosed):
			// The only acceptable loser error: setup is closed, not "this
			// username is taken" and not some database failure.
		default:
			t.Errorf("caller %d: err = %v, want nil or authz.ErrSetupClosed", i, got.err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d of %d concurrent Setups succeeded, want exactly 1", succeeded, n)
	}
	if admins := h.countAdmins(); admins != 1 {
		t.Errorf("the users table holds %d admins, want exactly 1", admins)
	}
	if total := h.countUsers(); total != 1 {
		t.Errorf("the users table holds %d accounts, want exactly 1", total)
	}
}

func TestSetupIsNotReRunnable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()

	if open, err := h.svc.SetupOpen(ctx); err != nil || !open {
		t.Fatalf("SetupOpen on an empty vault = %v, %v; want true, nil", open, err)
	}
	first, err := h.svc.Setup(ctx, "the-first", "The First", "Correct-Horse-9")
	if err != nil {
		t.Fatalf("first setup: %v", err)
	}
	if first.Role != authz.RoleAdmin {
		t.Errorf("the first admin has role %q, want admin", first.Role)
	}
	if first.UserID == 0 {
		t.Error("the first admin's principal carries no user id")
	}
	if first.SessionID != "" {
		t.Error("Setup minted a session; the handler is expected to call Create for that")
	}

	// Same username, different username, a different passphrase: none of it
	// matters, because the gate is the emptiness of the table and not the
	// arguments.
	for _, tc := range []struct {
		name                        string
		username, display, passwrod string
	}{
		{"the same account again", "the-first", "The First", "Correct-Horse-9"},
		{"a different account", "a-second", "The Second", "Correct-Horse-9"},
		{"a different passphrase", "the-first", "The First", "Another-Pass-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.Setup(t.Context(), tc.username, tc.display, tc.passwrod)
			if !errors.Is(err, authz.ErrSetupClosed) {
				t.Fatalf("err = %v, want authz.ErrSetupClosed", err)
			}
		})
	}

	if open, err := h.svc.SetupOpen(ctx); err != nil || open {
		t.Errorf("SetupOpen after setup = %v, %v; want false, nil", open, err)
	}
	if admins := h.countAdmins(); admins != 1 {
		t.Errorf("the users table holds %d admins after three refusals, want 1", admins)
	}
	if total := h.countUsers(); total != 1 {
		t.Errorf("the users table holds %d accounts after three refusals, want 1", total)
	}
}

// TestOnlyTheRawTokenIsStored reads the database file itself and requires that
// the session token appears in no form: not the base64url text, not its bytes,
// not a hex encoding of those bytes. The only thing in there should be the
// sha256, and a leaked vault is exactly the situation the hashing exists for.
func TestOnlyTheRawTokenIsStored(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	if _, err := h.svc.Setup(ctx, "the-admin", "The Admin", "Correct-Horse-9"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	raw := h.loginAs("the-admin", "Correct-Horse-9")

	rows := h.sessionRows(ctx)
	if len(rows) != 1 {
		t.Fatalf("the sessions table holds %d rows, want 1", len(rows))
	}
	if rows[0].ID != HashToken(raw) {
		t.Errorf("session id = %q, want the sha256 of the token %q", rows[0].ID, HashToken(raw))
	}
	if len(rows[0].ID) != 64 {
		t.Errorf("session id is %d characters, want 64 hex characters", len(rows[0].ID))
	}
	for _, r := range rows[0].ID {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Errorf("session id %q is not lowercase hex", rows[0].ID)
			break
		}
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("the minted token is not base64url: %v", err)
	}
	blob := h.databaseBytes(t)
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"the token as text", []byte(raw)},
		{"the token's bytes", decoded},
		{"the token's bytes as hex", []byte(hexOf(decoded))},
		{"the token's bytes uppercased as hex", []byte(strings.ToUpper(hexOf(decoded)))},
	} {
		if bytes.Contains(blob, tc.bytes) {
			t.Errorf("the raw session token is recoverable from the database as %s", tc.name)
		}
	}
}

// TestSessionRefusesAnExpiredToken moves the clock past the absolute limit and
// requires the token to stop working without the caller having to prune
// anything first.
func TestSessionRefusesAnExpiredToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("expiring", "player")
	raw := h.login("expiring")

	if _, err := h.svc.Session(ctx, raw); err != nil {
		t.Fatalf("a fresh session did not resolve: %v", err)
	}

	h.advance(config.SessionTTL + time.Minute)
	who, err := h.svc.Session(ctx, raw)
	if err != nil {
		t.Fatalf("resolving an expired session returned an error, not a decision: %v", err)
	}
	if who.Authenticated() {
		t.Fatalf("an expired session resolved to %s", who)
	}
	if who.Role != authz.RoleAnonymous {
		t.Errorf("an expired session resolved to role %q, want anon", who.Role)
	}
}

// TestAnExpiredSessionIsDeletedWhenItIsFound is the difference between a check
// and a fix. A row that is refused but kept is re-examined on every request for
// ever, and it is a standing record of a cookie that used to work.
func TestAnExpiredSessionIsDeletedWhenItIsFound(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("expiring", "player")
	raw := h.login("expiring")
	id := HashToken(raw)
	csrf, err := h.svc.CSRFToken(raw)
	if err != nil {
		t.Fatalf("csrf token: %v", err)
	}
	if !h.svc.CheckCSRF(raw, csrf) {
		t.Fatal("a fresh session's CSRF token does not verify")
	}

	h.advance(config.SessionTTL + time.Minute)
	if _, err := h.svc.Session(ctx, raw); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if rows := h.sessionRows(ctx); len(rows) != 0 {
		t.Errorf("the sessions table still holds %d rows after an expired one was found", len(rows))
	}
	if _, err := store.GetSession(ctx, h.db.Reader(), id); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("the expired session row is still there: %v", err)
	}
	// And the CSRF token that went with it is gone, so a form rendered by the
	// page the reader already has open cannot be submitted.
	if h.svc.CheckCSRF(raw, csrf) {
		t.Error("the CSRF token of an expired session still verifies")
	}
}

// TestDisabledUserGetsNoSession covers the two halves of a disable: the
// existing cookie stops working, and the account cannot be logged into again.
func TestDisabledUserGetsNoSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", "admin")
	userID := h.seedUser("leaving", "player")
	raw := h.login("leaving")

	if _, err := h.svc.Session(ctx, raw); err != nil {
		t.Fatalf("the session did not work before the disable: %v", err)
	}

	if err := h.svc.Disable(ctx, h.principal(adminID, "the-admin", "admin"), userID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	who, err := h.svc.Session(ctx, raw)
	if err != nil {
		t.Fatalf("resolving a disabled user's session returned an error: %v", err)
	}
	if who.Authenticated() {
		t.Fatalf("a disabled account's session still resolves to %s", who)
	}
	if rows := h.sessionRows(ctx); len(rows) != 0 {
		t.Errorf("%d session rows survived the disable", len(rows))
	}
	if _, err := h.svc.Create(ctx, LoginRequest{Username: "leaving", Passphrase: fixturePassphrase("leaving")}); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a disabled account logged in again: err = %v", err)
	}

	// Re-enabling brings the account back without touching anything else.
	if err := h.svc.Enable(ctx, h.principal(adminID, "the-admin", "admin"), userID); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := h.svc.Create(ctx, LoginRequest{Username: "leaving", Passphrase: fixturePassphrase("leaving")}); err != nil {
		t.Fatalf("a re-enabled account could not log in: %v", err)
	}
}

// TestRoleChangeInvalidatesOldSessions is the assertion that a role bump is a
// role bump. A session that survives it keeps the old permissions for as long
// as the cookie lives, which is fourteen days.
func TestRoleChangeInvalidatesOldSessions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	adminID := h.seedUser("the-admin", "admin")
	userID := h.seedUser("promoted", "player")
	raw := h.login("promoted")

	before, err := h.svc.Session(ctx, raw)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if before.Role != authz.RolePlayer {
		t.Fatalf("role before the change is %q, want player", before.Role)
	}
	genBefore := before.AuthzGeneration

	if err := h.svc.SetRole(ctx, h.principal(adminID, "the-admin", "admin"), userID, authz.RoleDM); err != nil {
		t.Fatalf("set role: %v", err)
	}

	who, err := h.svc.Session(ctx, raw)
	if err != nil {
		t.Fatalf("resolve after the role change: %v", err)
	}
	if who.Authenticated() {
		t.Errorf("the old cookie still authenticates as %s", who)
	}
	if rows := h.sessionRows(ctx); len(rows) != 0 {
		t.Errorf("%d session rows survived the role change", len(rows))
	}

	// A fresh login carries the new role, and the generation has moved, which is
	// what terminates a live-push stream opened under the old one.
	fresh := h.login("promoted")
	after, err := h.svc.Session(ctx, fresh)
	if err != nil {
		t.Fatalf("session after re-login: %v", err)
	}
	if after.Role != authz.RoleDM {
		t.Errorf("role after the change is %q, want dm", after.Role)
	}
	if after.AuthzGeneration <= genBefore {
		t.Errorf("authz generation is %d, want more than the %d it was before the change", after.AuthzGeneration, genBefore)
	}
}

func TestDestroyAllForUserLeavesNoValidSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("busy", "player")
	first := h.login("busy")
	second := h.login("busy")
	if rows := h.sessionRows(ctx); len(rows) != 2 {
		t.Fatalf("the account has %d sessions, want 2", len(rows))
	}

	n, err := h.svc.DestroyAllForUser(ctx, h.userID(t, "busy"))
	if err != nil {
		t.Fatalf("destroy all: %v", err)
	}
	if n != 2 {
		t.Errorf("DestroyAllForUser removed %d sessions, want 2", n)
	}
	for _, raw := range []string{first, second} {
		if who, err := h.svc.Session(ctx, raw); err != nil || who.Authenticated() {
			t.Errorf("a session survived DestroyAllForUser (who=%s err=%v)", who, err)
		}
	}
	if rows := h.sessionRows(ctx); len(rows) != 0 {
		t.Errorf("%d session rows survived DestroyAllForUser", len(rows))
	}
}

// TestSlidingRefreshNeverExtendsPastTheAbsoluteLimit is the test the moving
// clock exists for. It is written as a walk across the whole lifetime rather
// than as one jump, because the interesting states are the ones in between: a
// session that is refreshed, a session that is close to the end, and a session
// that has just passed it.
func TestSlidingRefreshNeverExtendsPastTheAbsoluteLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("sliding", "player")
	created := h.now()

	for _, tc := range []struct {
		name string
		// at is how far past creation the clock is when the session is
		// presented.
		at time.Duration
		// wantLive is whether the session may still be presented.
		wantLive bool
		// wantTouched is whether the idle marker may have moved.
		wantTouched bool
	}{
		{"immediately after login", 0, true, false},
		{"one second after login", time.Second, true, false},
		{"just under the slide threshold", config.SessionSlide - time.Minute, true, false},
		{"at the slide threshold", config.SessionSlide, true, true},
		{"late but still inside the absolute limit", config.SessionTTL - time.Hour, true, true},
		{"one second before the absolute limit", config.SessionTTL - time.Second, true, true},
		{"at the absolute limit", config.SessionTTL, false, false},
		{"a slide threshold after the absolute limit", config.SessionTTL + config.SessionSlide, false, false},
		{"twice the absolute limit", 2 * config.SessionTTL, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The clock is restored whatever happens, because a case that fails
			// on t.Fatalf would otherwise leave the next case logging in at the
			// wrong time and failing for a second, unrelated reason.
			t.Cleanup(func() { h.setClock(created) })
			h.setClock(created)

			// Each step starts from a fresh login, so the table is a set of
			// independent observations of one policy rather than a chain in
			// which an early wrong answer poisons every later one.
			token := h.login("sliding")
			h.setClock(created.Add(tc.at))

			who, err := h.svc.Session(ctx, token)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if live := who.Authenticated(); live != tc.wantLive {
				t.Fatalf("live = %v, want %v", live, tc.wantLive)
			}
			row, err := store.GetSession(ctx, h.db.Reader(), HashToken(token))
			if !tc.wantLive {
				if !errors.Is(err, store.ErrNoRows) {
					t.Fatalf("a dead session's row is still there: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a live session's row is gone: %v", err)
			}
			if want := created.Add(config.SessionTTL); !row.ExpiresAt.Equal(want) {
				t.Errorf("expires_at is %s, want %s: a refresh moved the absolute limit", row.ExpiresAt, want)
			}
			if touched := row.LastSeenAt.After(created); touched != tc.wantTouched {
				t.Errorf("last_seen_at moved = %v, want %v", touched, tc.wantTouched)
			}
		})
	}
}

// TestARotatedLoginRevokesTheOldToken is the rotation rule: a login always
// mints, and the token that was held before the login stops working.
func TestARotatedLoginRevokesTheOldToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("rotating", "player")
	old := h.login("rotating")

	newer, err := h.svc.Create(ctx, LoginRequest{
		Username:   "rotating",
		Passphrase: fixturePassphrase("rotating"),
		Replace:    old,
	})
	if err != nil {
		t.Fatalf("re-login: %v", err)
	}
	if newer == old {
		t.Fatal("a login reissued the token it was given")
	}
	if who, err := h.svc.Session(ctx, old); err != nil || who.Authenticated() {
		t.Errorf("the pre-rotation cookie still authenticates (who=%s err=%v)", who, err)
	}
	if who, err := h.svc.Session(ctx, newer); err != nil || !who.Authenticated() {
		t.Errorf("the new cookie does not authenticate (who=%s err=%v)", who, err)
	}
	if rows := h.sessionRows(ctx); len(rows) != 1 {
		t.Errorf("%d sessions after a rotation, want 1", len(rows))
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("leaving", "player")
	raw := h.login("leaving")

	if err := h.svc.Destroy(ctx, raw); err != nil {
		t.Fatalf("first destroy: %v", err)
	}
	// Logging out twice, and logging out with a cookie that was never a token,
	// are both successes: logout is not an assertion about what was there.
	for _, tc := range []struct{ name, token string }{
		{"the same token again", raw},
		{"a token that never existed", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"an empty token", ""},
		{"a token of the wrong shape", "not-a-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.svc.Destroy(t.Context(), tc.token); err != nil {
				t.Fatalf("destroy: %v", err)
			}
		})
	}
	if rows := h.sessionRows(ctx); len(rows) != 0 {
		t.Errorf("%d session rows survived the logouts", len(rows))
	}
}

func TestPruneExpiredRemovesOnlyThePast(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	h.seedUser("stale", "player")
	h.seedUser("fresh", "player")
	stale := h.login("stale")

	h.advance(config.SessionTTL + time.Hour)
	fresh := h.login("fresh")

	n, err := h.svc.PruneExpired(ctx, h.now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("PruneExpired removed %d sessions, want 1 (the stale one)", n)
	}
	if who, _ := h.svc.Session(ctx, stale); who.Authenticated() {
		t.Error("a pruned session still authenticates")
	}
	if who, err := h.svc.Session(ctx, fresh); err != nil || !who.Authenticated() {
		t.Errorf("pruning took a live session with it (who=%s err=%v)", who, err)
	}
	if rows := h.sessionRows(ctx); len(rows) != 1 {
		t.Errorf("%d session rows survive, want 1", len(rows))
	}
}

// TestSessionIsUndistinguishableAcrossFailures is the enumeration property,
// asserted on the value rather than on the clock: a caller that renders an
// error, or logs one, or measures one, has nothing to work with.
func TestSessionIsUndistinguishableAcrossFailures(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := t.Context()
	userID := h.seedUser("leaving", "player")
	adminID := h.seedUser("the-admin", "admin")
	raw := h.login("leaving")
	if err := h.svc.Disable(ctx, h.principal(adminID, "the-admin", "admin"), userID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	expired := h.login("the-admin")
	h.advance(config.SessionTTL + time.Hour)
	// Logged in *after* the advance, so it really is live and the assertion
	// below is about the failures rather than about the clock.
	live := h.login("the-admin")

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no token at all", ""},
		{"a token that never existed", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"a token of the wrong shape", "not-a-token"},
		{"a revoked token", raw},
		{"an expired token", expired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			who, err := h.svc.Session(t.Context(), tc.token)
			if err != nil {
				t.Fatalf("a failed resolution returned an error rather than a decision: %v", err)
			}
			if who.Authenticated() {
				t.Fatalf("resolved to %s", who)
			}
			if who.Role != authz.RoleAnonymous || who.UserID != 0 || who.SessionID != "" {
				t.Errorf("failed resolution returned %+v, want the anonymous principal", who)
			}
			if who.AllowAnonymousRead {
				t.Error("the anonymous principal is allowed to read, but this harness runs with anonymous read off")
			}
		})
	}

	// The live session is unaffected by the presence of the failures, which is
	// the other half: a distinguishable failure is only a problem if the
	// success is distinguishable too.
	if who, err := h.svc.Session(ctx, live); err != nil || !who.Authenticated() {
		t.Errorf("the live session stopped working (who=%s err=%v)", who, err)
	}
}

// sessionRows is every session row, read through the store rather than by
// parsing SQL, so a test cannot pass because the query it wrote happened to
// match.
func (h *harness) sessionRows(ctx context.Context) []store.Session {
	h.t.Helper()
	rows, err := h.db.Reader().QueryContext(ctx,
		`SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent
		 FROM sessions ORDER BY created_at, id`)
	if err != nil {
		h.t.Fatalf("read sessions: %v", err)
	}
	var out []store.Session
	err = store.ForEach(rows, func(r store.Rows) error {
		var (
			sess      store.Session
			created   string
			expires   string
			lastSeen  string
			userAgent sql.NullString
		)
		if err := r.Scan(&sess.ID, &sess.UserID, &created, &expires, &lastSeen, &userAgent); err != nil {
			return err
		}
		sess.UserAgent = userAgent.String
		var err error
		if sess.CreatedAt, err = store.ParseTime(created); err != nil {
			return err
		}
		if sess.ExpiresAt, err = store.ParseTime(expires); err != nil {
			return err
		}
		if sess.LastSeenAt, err = store.ParseTime(lastSeen); err != nil {
			return err
		}
		out = append(out, sess)
		return nil
	})
	if err != nil {
		h.t.Fatalf("scan sessions: %v", err)
	}
	return out
}

// databaseBytes is every byte of the database, main file and write-ahead log
// alike. A leaked token would be in the WAL if anywhere, because that is where
// a freshly committed row lives.
func (h *harness) databaseBytes(t *testing.T) []byte {
	t.Helper()
	dir := filepath.Join(h.vault.Root, store.StateDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state dir: %v", err)
	}
	var out []byte
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), store.DBName) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out = append(out, b...)
	}
	if len(out) == 0 {
		t.Fatal("the database file is empty")
	}
	return out
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
