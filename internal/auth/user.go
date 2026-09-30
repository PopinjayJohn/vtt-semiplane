package auth

import (
	"context"
	"fmt"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// SetRole changes an account's role, revokes its sessions and bumps the
// authorization generation, in one transaction.
//
// All three or none. A role change that revoked nothing would leave a cookie
// minted under the old role valid, and a revocation that did not bump the
// generation would leave a live-push stream running under the old one — a
// privilege change that changed nothing anybody can observe.
func (s *Service) SetRole(ctx context.Context, actor authz.Principal, userID int64, role authz.Role) error {
	if err := s.requireAdmin(ctx, actor, "auth.user.setrole"); err != nil {
		return err
	}
	if !role.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	return s.mutateAccount(ctx, actor, userID, "auth.user.setrole", func(tx store.Execer) error {
		return store.SetUserRole(ctx, tx, userID, role.String())
	})
}

// Disable turns an account off, revokes its sessions and bumps the generation.
//
// It disables rather than deletes. A disabled account keeps its rows because
// revisions and secrets name their author, and a hard delete would rewrite the
// campaign's history to remove an author who did nothing but leave.
func (s *Service) Disable(ctx context.Context, actor authz.Principal, userID int64) error {
	if err := s.requireAdmin(ctx, actor, "auth.user.disable"); err != nil {
		return err
	}
	at := s.now()
	return s.mutateAccount(ctx, actor, userID, "auth.user.disable", func(tx store.Execer) error {
		return store.SetUserDisabled(ctx, tx, userID, &at)
	})
}

// Enable turns a disabled account back on, on the same terms.
func (s *Service) Enable(ctx context.Context, actor authz.Principal, userID int64) error {
	if err := s.requireAdmin(ctx, actor, "auth.user.enable"); err != nil {
		return err
	}
	return s.mutateAccount(ctx, actor, userID, "auth.user.enable", func(tx store.Execer) error {
		return store.SetUserDisabled(ctx, tx, userID, nil)
	})
}

// mutateAccount runs one account mutation with its session revocation and its
// generation bump inside a single transaction.
func (s *Service) mutateAccount(ctx context.Context, actor authz.Principal, userID int64, action string, apply func(store.Execer) error) error {
	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("auth: begin %s: %w", action, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, getUserByIDErr := store.GetUserByID(ctx, tx, userID); getUserByIDErr != nil {
		return fmt.Errorf("auth: load account: %w", getUserByIDErr)
	}
	if applyErr := apply(tx); applyErr != nil {
		return applyErr
	}
	if _, deleteUserSessionsErr := store.DeleteUserSessions(ctx, tx, userID); deleteUserSessionsErr != nil {
		return deleteUserSessionsErr
	}
	generation, err := store.BumpAuthzGeneration(ctx, tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: commit %s: %w", action, err)
	}

	s.forgetCSRFForUser(userID)
	s.audit(ctx, action, "action", action, "actor_id", actor.UserID,
		"target_id", userID, "result", "ok", "authz_generation", generation)
	return nil
}
