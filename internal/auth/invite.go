package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// ErrInviteInvalid is the answer to every failed invite redemption.
//
// One sentinel, returned unchanged, for a token that never existed, one that has
// already been used, one that has expired and one that was not even shaped like
// a token. Splitting them would let anyone holding a URL they were sent
// discover, by trying it twice, whether the first attempt had worked — which is
// the only thing the second attempt would have told them that the first did
// not.
var ErrInviteInvalid = errors.New("this invite is not valid")

// ErrUsernameTaken reports a username the unique index already holds.
//
// It is produced by the index rather than by a check, because a check races:
// two simultaneous signups both see the name as free and one of them is wrong.
var ErrUsernameTaken = errors.New("that username is already taken")

// ErrInvalidRole reports a role an invite may not grant. RoleAnonymous is the
// interesting one: it is a valid authz.Role, so a naive check would wave it
// through and mint an account that could never authenticate.
var ErrInvalidRole = errors.New("that role cannot be granted by an invite")

// InviteView is one row of the admin invite list.
//
// It is deliberately not store.Invite. That row carries TokenHash in full, and
// the hash is the only thing standing between a leaked database and a working
// session for every pending invite, so the list reports a prefix of it and
// nothing else. The prefix exists so an admin holding the URL they sent can
// recognise it with InviteID rather than by eye.
type InviteView struct {
	// ID is the first InviteIDChars hex characters of the token hash.
	ID string
	// Role is the role the invite grants.
	Role authz.Role
	// CreatedBy is the admin who issued it.
	CreatedBy int64
	// CreatedAt is when it was issued.
	CreatedAt time.Time
	// ExpiresAt is when it stops being redeemable.
	ExpiresAt time.Time
	// RedeemedAt is when it was used, or nil.
	RedeemedAt *time.Time
	// Pending reports whether the invite can still be redeemed.
	Pending bool
}

// InviteIDChars is how many leading hex characters of a token hash an
// InviteView carries.
//
// Eight characters is 32 bits, which separates the handful of invites a
// campaign ever issues with a collision probability nobody will meet, and it is
// far too short to be a prefix worth guessing: recovering the rest needs the
// 224 bits behind it, and the token itself is only ever in one URL.
const InviteIDChars = 8

// InviteID returns the short identifier ListInvites reports for a raw token, so
// an admin can match a token they were sent against the list without the list
// carrying the token.
func InviteID(rawToken string) string {
	sum := HashToken(rawToken)
	if len(sum) < InviteIDChars {
		return sum
	}
	return sum[:InviteIDChars]
}

// CreateInvite issues a single-use invite and returns the raw token, which the
// caller puts in exactly one URL.
//
// Only an admin may do this, and the check asks the policy rather than looking
// at the role: this package produces principals, authz decides what they may
// do, and a Role comparison here would be the second place in the codebase that
// answers that question. The check runs before the role is even validated, so a
// caller without permission learns nothing about which roles exist.
func (s *Service) CreateInvite(ctx context.Context, actor authz.Principal, role authz.Role, ttl time.Duration) (string, error) {
	if err := s.requireAdmin(ctx, actor, "auth.invite.create"); err != nil {
		return "", err
	}
	if !role.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	if ttl <= 0 {
		ttl = s.inviteTTL
	}
	if ttl > MaxInviteTTL {
		return "", fmt.Errorf("%w: ttl of %s exceeds %s", ErrInvalidRole, ttl, MaxInviteTTL)
	}

	raw, err := NewToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	inv := store.Invite{
		TokenHash: HashToken(raw),
		Role:      role.String(),
		CreatedBy: actor.UserID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := store.InsertInvite(ctx, s.db.Writer(), inv); err != nil {
		return "", err
	}
	// The audit record names the invite by the same short identifier the admin
	// list shows, so a record and a list row can be matched without either
	// carrying the token.
	s.audit(ctx, "auth.invite.created", "action", "auth.invite.create",
		"actor_id", actor.UserID, "role", role.String(), "target", InviteID(raw))
	return raw, nil
}

// RedeemRequest is one attempt to claim an invite.
type RedeemRequest struct {
	// Token is the raw invite token, straight out of the URL.
	Token string
	// Username is the login name being claimed.
	Username string
	// DisplayName is what the UI shows. Empty means the username.
	DisplayName string
	// Passphrase is the plaintext, used once and never retained.
	Passphrase string
}

// AcceptInvite redeems an invite, creating the account it grants, and returns
// the Principal for it.
//
// The order of the checks is the security property, not a style choice. The
// token is resolved and validated before the username and before the Argon2id
// derivation, for three reasons at once: a request with a bad token must cost
// the same whether its username was also acceptable, or the response code turns
// into a validity oracle for the token; and an unauthenticated caller must not
// be able to make the server spend 64 MiB of memory-hard work on a guess. So the
// token decides, and only a caller who has already proved they hold a live
// invite is told that their passphrase or their username is the problem.
//
// The account's role is the role the invite carries. It is never the issuer's:
// an admin who invites a player has issued a player, and copying the issuer's
// role across would make every invite a second admin.
func (s *Service) AcceptInvite(ctx context.Context, req RedeemRequest) (authz.Principal, error) {
	if !wellFormedToken(req.Token) {
		return authz.Principal{}, ErrInviteInvalid
	}
	tokenHash := HashToken(req.Token)

	inv, err := store.GetInviteByTokenHash(ctx, s.db.Reader(), tokenHash)
	if errors.Is(err, store.ErrNoRows) {
		return authz.Principal{}, ErrInviteInvalid
	}
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: load invite: %w", err)
	}

	now := s.now()
	if inv.Redeemed() || !now.Before(inv.ExpiresAt) {
		return authz.Principal{}, ErrInviteInvalid
	}

	if validateUsernameErr := ValidateUsername(req.Username); validateUsernameErr != nil {
		return authz.Principal{}, validateUsernameErr
	}
	if validatePassphraseErr := ValidatePassphrase(req.Passphrase); validatePassphraseErr != nil {
		return authz.Principal{}, validatePassphraseErr
	}
	phc, err := HashPassphrase(req.Passphrase)
	if err != nil {
		return authz.Principal{}, err
	}
	salt, err := SaltFromPHC(phc)
	if err != nil {
		return authz.Principal{}, err
	}
	display := req.DisplayName
	if display == "" {
		display = req.Username
	}

	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return authz.Principal{}, fmt.Errorf("auth: begin invite redemption: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Re-read the invite inside the transaction. The read above is on the
	// reader pool and a second redemption of the same token can commit between
	// it and here; the row inside the transaction is the one that decides.
	fresh, err := store.GetInviteByTokenHash(ctx, tx, tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return authz.Principal{}, ErrInviteInvalid
		}
		return authz.Principal{}, fmt.Errorf("auth: re-read invite: %w", err)
	}
	if fresh.Redeemed() || !now.Before(fresh.ExpiresAt) {
		return authz.Principal{}, ErrInviteInvalid
	}

	user := store.User{
		Username:    req.Username,
		DisplayName: display,
		Role:        fresh.Role,
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

	// Redeeming after the insert, in the same transaction, is what makes the
	// redemption single-use. If this fails the insert rolls back with it, so
	// two simultaneous redemptions of one token leave one account and not two.
	if redeemInviteErr := store.RedeemInvite(ctx, tx, tokenHash, userID, now); redeemInviteErr != nil {
		if errors.Is(redeemInviteErr, store.ErrInviteUsed) {
			return authz.Principal{}, ErrInviteInvalid
		}
		return authz.Principal{}, redeemInviteErr
	}

	generation, err := store.BumpAuthzGeneration(ctx, tx)
	if err != nil {
		return authz.Principal{}, err
	}
	if err := tx.Commit(); err != nil {
		return authz.Principal{}, fmt.Errorf("auth: commit invite redemption: %w", err)
	}

	s.audit(ctx, "auth.invite.accepted", "action", "auth.invite.accept",
		"actor_id", userID, "role", fresh.Role, "target", InviteID(req.Token),
		"authz_generation", generation)
	return s.principalFor(user, "", generation), nil
}

// ListInvites returns every invite for the admin page, newest first.
//
// The raw token is in exactly one place, the URL handed to the invitee, and it
// is not here: this list is a page, a JSON payload or a log line away from
// somebody's shoulder, and a list of working bearer credentials is not
// something a UI should be holding. The short prefix identifies a token to the
// admin who issued it and tells them nothing else.
func (s *Service) ListInvites(ctx context.Context, actor authz.Principal) ([]InviteView, error) {
	if err := s.requireAdmin(ctx, actor, "auth.invite.list"); err != nil {
		return nil, err
	}
	invites, err := store.ListInvites(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]InviteView, 0, len(invites))
	for _, i := range invites {
		out = append(out, InviteView{
			ID:         shortHash(i.TokenHash),
			Role:       authz.Role(i.Role),
			CreatedBy:  i.CreatedBy,
			CreatedAt:  i.CreatedAt,
			ExpiresAt:  i.ExpiresAt,
			RedeemedAt: i.RedeemedAt,
			Pending:    !i.Redeemed() && now.Before(i.ExpiresAt),
		})
	}
	return out, nil
}

// shortHash truncates a token hash to the identifier length, tolerating a
// shorter one rather than panicking on a database nobody wrote.
func shortHash(hash string) string {
	if len(hash) <= InviteIDChars {
		return hash
	}
	return hash[:InviteIDChars]
}

// isUsernameConflict reports a unique-index violation on users.username.
//
// It matches store.ErrUsernameTaken rather than the driver's message. The index
// is the only thing that should be answering this question, store owns the
// schema, and store is where the translation from a numeric SQLite code
// happens — so a driver upgrade cannot turn a friendly 400 into a 500 here.
func isUsernameConflict(err error) bool {
	return errors.Is(err, store.ErrUsernameTaken)
}
