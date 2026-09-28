package auth

import (
	"context"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// SetupOpen reports whether the first-run form is still reachable, which is
// what the /setup route needs to choose between 404 and 200.
//
// It is a count rather than a permission check, and the distinction matters:
// after bootstrap the route must be *absent*, not forbidden, so that an
// outsider cannot confirm the installation exists by watching a 403.
func (s *Service) SetupOpen(ctx context.Context) (bool, error) {
	n, err := store.CountUsers(ctx, s.db.Reader())
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// Setup claims the first admin and returns its Principal.
//
// The gate is a transaction that re-counts the users table *inside* itself, and
// not a single INSERT ... SELECT ... WHERE NOT EXISTS. Both are atomic; the
// difference is where the statement lives. Hand-rolling the statement here would
// put SQL in a package whose rule is that every query lives in store, and it
// would put a second description of the users table outside the one that owns
// it. The re-check is a call to store.CountUsers, so the two cannot drift.
//
// The re-check is sound because the write pool is a single connection
// (store.Open sets MaxOpenConns(1)): between this transaction's count and its
// insert no other writer can run, so the count cannot be stale. That is a
// property of the pool rather than of SQLite alone, and it is why Setup takes
// the write pool explicitly instead of being handed a connection.
//
// The passphrase is derived before the transaction opens, because 64 MiB of
// argon2 must not be held against the one writer. That costs the losers of a
// race the work anyway, which is the price of not serialising the server behind
// a login.
//
// After the first admin exists, Setup fails with authz.ErrSetupClosed — the
// same sentinel the policy returns — so the route that guards the form needs
// one mapping for both and setup cannot be re-run to mint a second admin.
func (s *Service) Setup(ctx context.Context, username, displayName, passphrase string) (authz.Principal, error) {
	if err := ValidateUsername(username); err != nil {
		return authz.Principal{}, err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return authz.Principal{}, err
	}
	if displayName == "" {
		displayName = username
	}

	phc, err := HashPassphrase(passphrase)
	if err != nil {
		return authz.Principal{}, err
	}
	salt, err := SaltFromPHC(phc)
	if err != nil {
		return authz.Principal{}, err
	}

	now := s.now()
	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: begin setup: %w", err)
	}
	defer tx.Rollback()

	count, err := store.CountUsers(ctx, tx)
	if err != nil {
		return authz.Principal{}, err
	}
	if count != 0 {
		return authz.Principal{}, authz.ErrSetupClosed
	}

	user := store.User{
		Username:    username,
		DisplayName: displayName,
		Role:        authz.RoleAdmin.String(),
		PWHash:      []byte(phc),
		PWSalt:      salt,
		CreatedAt:   now,
	}
	userID, err := store.InsertUser(ctx, tx, user)
	if err != nil {
		if isUsernameConflict(err) {
			return authz.Principal{}, ErrUsernameTaken
		}
		return authz.Principal{}, err
	}

	// A new account is an authorization change: a stream opened before this
	// point was opened under a world with no users in it.
	generation, err := store.BumpAuthzGeneration(ctx, tx)
	if err != nil {
		return authz.Principal{}, err
	}
	if err := tx.Commit(); err != nil {
		return authz.Principal{}, fmt.Errorf("auth: commit setup: %w", err)
	}

	user.ID = userID
	s.audit(ctx, "auth.setup", "action", "auth.setup",
		"actor_id", userID, "role", user.Role, "authz_generation", generation)
	// The principal carries no SessionID: this call did not mint one. A handler
	// that wants the new admin signed in calls Create straight afterwards, which
	// is also what puts a CSRF token in front of their first form.
	return s.principalFor(user, "", generation), nil
}
