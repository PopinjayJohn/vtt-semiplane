package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// ErrBadCredentials is the answer to every failed login.
//
// It is one sentinel, returned unchanged, for a username that does not exist, a
// passphrase that does not match, and an account that has been disabled. Three
// distinct errors would be three distinct response times and three distinct
// pages, and either one enumerates the campaign's accounts to anyone who can
// reach the login form.
var ErrBadCredentials = errors.New("invalid username or passphrase")

// LoginRequest is one authentication attempt.
type LoginRequest struct {
	// Username is the login name, compared case-insensitively by the store.
	Username string
	// Passphrase is the plaintext. It is used once and never retained: not in
	// a struct field, not in a closure, not in a log line.
	Passphrase string
	// UserAgent is the presenting client, recorded on the session row. It is
	// the only part of the request stored verbatim, and it is a header the
	// client chose, so it is not an identity.
	UserAgent string
	// Replace is the session token the client already held, if any, and it is
	// revoked. A login always rotates: a token captured before the rotation
	// must not still work after it, or "log in again" is not a way out of a
	// stolen cookie.
	Replace string
}

// Create authenticates a passphrase and mints a session, returning the raw token
// for the cookie. It is the only place a session token is produced.
//
// The Argon2id derivation happens before the write transaction opens, on
// purpose: the write pool is one connection, so holding it across 64 MiB of
// memory-hard work would turn every login into a stall in every other writer,
// the indexer included.
func (s *Service) Create(ctx context.Context, req LoginRequest) (string, error) {
	now := s.now()

	user, err := store.GetUserByUsername(ctx, s.db.Reader(), req.Username)
	switch {
	case errors.Is(err, store.ErrNoRows):
		// Spend the work a real verification would spend, then give the same
		// answer. Without this the miss is a table lookup and the hit is 64 MiB
		// of argon2, which is a username oracle made of wall clock.
		burnVerify(req.Passphrase)
		s.audit(ctx, "auth.login", "action", "auth.login", "actor_id", int64(0), "result", "denied")
		return "", ErrBadCredentials
	case err != nil:
		return "", fmt.Errorf("auth: look up account: %w", err)
	}

	if !user.Active() || len(user.PWHash) == 0 {
		burnVerify(req.Passphrase)
		s.audit(ctx, "auth.login", "action", "auth.login", "actor_id", user.ID, "result", "denied")
		return "", ErrBadCredentials
	}

	ok, err := Verify(user.PWHash, req.Passphrase)
	if err != nil {
		// A hash that will not parse is a damaged database, not a wrong
		// passphrase, and the two must not be reported alike: they have
		// different fixes, and conflating them would hide a corrupt vault for
		// ever behind a message that says "try again".
		return "", fmt.Errorf("auth: verify passphrase: %w", err)
	}
	if !ok {
		s.audit(ctx, "auth.login", "action", "auth.login", "actor_id", user.ID, "result", "denied")
		return "", ErrBadCredentials
	}

	raw, err := NewToken()
	if err != nil {
		return "", err
	}
	id := HashToken(raw)

	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("auth: begin login: %w", err)
	}
	defer tx.Rollback()

	// Re-read inside the transaction. Between the read above and this one the
	// account may have been disabled or have its role changed, and a session
	// minted from the stale row would be a live session belonging to an account
	// that no longer has the role it was issued under. The passphrase is not
	// re-verified: the row that verified is at most one argon2 old, and
	// re-deriving it here would hold the single write connection for tens of
	// milliseconds on every login.
	fresh, err := store.GetUserByUsername(ctx, tx, req.Username)
	if err != nil {
		return "", fmt.Errorf("auth: re-read account: %w", err)
	}
	if !fresh.Active() {
		s.audit(ctx, "auth.login", "action", "auth.login", "actor_id", fresh.ID, "result", "denied")
		return "", ErrBadCredentials
	}

	if req.Replace != "" && wellFormedToken(req.Replace) {
		if err := store.DeleteSession(ctx, tx, HashToken(req.Replace)); err != nil {
			return "", err
		}
	}
	sess := store.Session{
		ID:         id,
		UserID:     fresh.ID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.sessionTTL),
		LastSeenAt: now,
		UserAgent:  req.UserAgent,
	}
	if err := store.InsertSession(ctx, tx, sess); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("auth: commit login: %w", err)
	}

	// A login is where a CSRF token is born, and every login is a new one: the
	// token minted for the session being replaced is not carried over.
	s.bindCSRF(id, fresh.ID, "")
	s.audit(ctx, "auth.login", "action", "auth.login", "actor_id", fresh.ID, "result", "ok", "role", fresh.Role)
	return raw, nil
}

// Session resolves a raw session token to the principal a request is evaluated
// under, refreshing the row's idle marker and re-reading the account every time.
//
// Everything that is not a valid, unexpired, enabled session resolves to the
// same anonymous principal and no error: no such token, an expired one, a
// disabled account and a malformed cookie are one answer. A caller that needs to
// tell a visitor from a stale cookie already knows which it presented.
//
// The returned error is therefore only ever a real failure — a database error, a
// cancelled context — and never an authorization decision.
func (s *Service) Session(ctx context.Context, rawToken string) (authz.Principal, error) {
	if !wellFormedToken(rawToken) {
		return s.anon(), nil
	}
	id := HashToken(rawToken)

	sess, err := store.GetSession(ctx, s.db.Reader(), id)
	if errors.Is(err, store.ErrNoRows) {
		s.forgetCSRF(id)
		return s.anon(), nil
	}
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: load session: %w", err)
	}

	now := s.now()
	// min() rather than the stored value alone: the absolute limit is
	// created_at + sessionTTL by construction, and clamping to it here means
	// even a restored or hand-edited row cannot outlive the lifetime this
	// service was configured with.
	absolute := sess.CreatedAt.Add(s.sessionTTL)
	if !now.Before(sess.ExpiresAt) || !now.Before(absolute) {
		if err := s.expire(ctx, id, "expired"); err != nil {
			return authz.Principal{}, err
		}
		return s.anon(), nil
	}

	user, err := store.GetUserByID(ctx, s.db.Reader(), sess.UserID)
	if errors.Is(err, store.ErrNoRows) {
		if err := s.expire(ctx, id, "orphaned"); err != nil {
			return authz.Principal{}, err
		}
		return s.anon(), nil
	}
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: load account: %w", err)
	}
	if !user.Active() {
		if err := s.expire(ctx, id, "disabled"); err != nil {
			return authz.Principal{}, err
		}
		return s.anon(), nil
	}

	generation, err := store.AuthzGeneration(ctx, s.db.Reader())
	if err != nil {
		return authz.Principal{}, err
	}

	// Sliding refresh moves last_seen_at and nothing else. expires_at is written
	// once, by Create, so the absolute limit is a property of the row rather
	// than of a write that has to remember not to move it.
	if now.Sub(sess.LastSeenAt) >= s.sessionSlide {
		if err := store.TouchSession(ctx, s.db.Writer(), id, now); err != nil {
			return authz.Principal{}, err
		}
	}
	s.ensureCSRF(id, sess.UserID)
	return s.principalFor(user, id, generation), nil
}

// expire deletes a session that must not be used, so that the caller can return
// the anonymous principal with no error.
//
// The delete is not best-effort-and-ignored: a row that is refused but kept is
// re-examined on every request for ever, and the caller is owed a definitive
// answer either way.
func (s *Service) expire(ctx context.Context, id, reason string) error {
	if err := store.DeleteSession(ctx, s.db.Writer(), id); err != nil {
		return err
	}
	s.forgetCSRF(id)
	s.audit(ctx, "auth.session.expired", "action", "auth.session.expire", "result", reason)
	return nil
}

// Destroy revokes one session. It is idempotent, and an empty or misshapen
// token is a success: logging out is not an assertion about what was there.
func (s *Service) Destroy(ctx context.Context, rawToken string) error {
	if !wellFormedToken(rawToken) {
		return nil
	}
	id := HashToken(rawToken)
	if err := store.DeleteSession(ctx, s.db.Writer(), id); err != nil {
		return err
	}
	s.forgetCSRF(id)
	return nil
}

// DestroyAllForUser revokes every session an account holds and reports how many
// it removed.
//
// This is the call a privilege change has to make. A role bump or a disable
// that leaves a live cookie in place is a role bump that did not happen, and
// the live-push stream that cookie is holding has to be terminated too — which
// is the caller's job, because the generation bump that terminates it belongs
// to a service above this one.
func (s *Service) DestroyAllForUser(ctx context.Context, userID int64) (int64, error) {
	n, err := store.DeleteUserSessions(ctx, s.db.Writer(), userID)
	if err != nil {
		return 0, err
	}
	s.forgetCSRFForUser(userID)
	return n, nil
}

// PruneExpired removes sessions that expired before a cutoff. It is the boot
// step, not a periodic job: nothing here expires a session on a timer.
func (s *Service) PruneExpired(ctx context.Context, before time.Time) (int64, error) {
	return store.DeleteExpiredSessions(ctx, s.db.Writer(), before)
}

// PruneExpiredInvites removes invites that expired before a cutoff, redeemed or
// not. A redeemed invite is kept until it expires so the trail can say the
// token was used, and so this is the only thing that ever removes one.
func (s *Service) PruneExpiredInvites(ctx context.Context, before time.Time) (int64, error) {
	return store.DeleteExpiredInvites(ctx, s.db.Writer(), before)
}
