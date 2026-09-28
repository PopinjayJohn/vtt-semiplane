package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// User is a row of the users table. There is no policy in this file: deciding
// what a role may do belongs to authz, and deciding who may be created belongs
// to internal/auth. This package only stores and loads.
type User struct {
	// ID is the surrogate key, and the value authz.Principal.UserID carries.
	ID int64
	// Username is the login name, unique case-insensitively.
	Username string
	// DisplayName is what the UI shows.
	DisplayName string
	// Role is 'admin', 'dm' or 'player'.
	Role string
	// PWHash is the Argon2id hash, or nil for a user that has not set one.
	PWHash []byte
	// PWSalt is the Argon2id salt.
	PWSalt []byte
	// CreatedAt is when the account was made.
	CreatedAt time.Time
	// DisabledAt is when the account was disabled, or nil.
	DisabledAt *time.Time
}

// Active reports whether the account may authenticate. A disabled account
// keeps its rows: revisions reference its author, and a hard delete would
// rewrite history.
func (u User) Active() bool { return u.DisabledAt == nil }

const userColumns = `id, username, display_name, role, pw_hash, pw_salt, created_at, disabled_at`

func scanUser(s RowScanner) (User, error) {
	var (
		u         User
		hash      []byte
		createdAt string
		disabled  sql.NullString
	)
	if err := s.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &hash, &u.PWSalt,
		&createdAt, &disabled); err != nil {
		return User{}, err
	}
	if hash != nil {
		u.PWHash = hash
	}
	var err error
	if u.CreatedAt, err = ParseTime(createdAt); err != nil {
		return User{}, err
	}
	if disabled.Valid {
		t, err := ParseTime(disabled.String)
		if err != nil {
			return User{}, err
		}
		u.DisabledAt = &t
	}
	return u, nil
}

// InsertUser creates an account and returns its id.
// ErrUsernameTaken is returned when a username collides with the case-insensitive
// unique index. It is a sentinel rather than something a caller has to recognise
// by matching the driver's message: the driver exports no typed error, and a
// wording change would turn a friendly 400 into a 500. The index is the only
// thing that should be answering this question, so the index's answer is
// translated exactly once, here, in the package that owns the schema.
var ErrUsernameTaken = errors.New("store: username is already taken")

func InsertUser(ctx context.Context, e Execer, u User) (int64, error) {
	var id int64
	err := e.QueryRowContext(ctx,
		`INSERT INTO users (username, display_name, role, pw_hash, pw_salt, created_at, disabled_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		u.Username, u.DisplayName, u.Role, u.PWHash, u.PWSalt,
		FormatTime(u.CreatedAt), nullableTime(u.DisabledAt)).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, fmt.Errorf("store: insert user %s: %w", u.Username, ErrUsernameTaken)
		}
		return 0, fmt.Errorf("store: insert user %s: %w", u.Username, err)
	}
	return id, nil
}

// isUniqueViolation reports a SQLITE_CONSTRAINT_UNIQUE or _PRIMARYKEY failure.
//
// The type is compared numerically because the driver exposes neither a typed
// error nor a documented code, and the alternative — substring matching the
// message — is the thing this function exists to stop doing. The primary-key
// case is included so a caller that inserts an explicit id gets the same
// sentinel rather than a raw constraint error.
func isUniqueViolation(err error) bool {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		switch serr.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return true
		}
	}
	return false
}

// CountEnabledAdmins returns how many enabled admin accounts exist. It is what
// makes "is this the last admin" answerable: a vault with no admin left has no
// way back, because setup is closed once an admin has been claimed.
func CountEnabledAdmins(ctx context.Context, q Queryer) (int64, error) {
	var n int64
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = ? AND disabled_at IS NULL`, "admin").Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count enabled admins: %w", err)
	}
	return n, nil
}

// GetUserByID returns an account by id.
func GetUserByID(ctx context.Context, q Queryer, id int64) (User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
	if err != nil {
		return User{}, wrapNoRows(err, fmt.Sprintf("user %d", id))
	}
	return u, nil
}

// GetUserByUsername returns an account by login name. The comparison is
// NOCASE, so a caller cannot tell "wrong case" from "no such user".
func GetUserByUsername(ctx context.Context, q Queryer, username string) (User, error) {
	u, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username))
	if err != nil {
		return User{}, wrapNoRows(err, "user "+username)
	}
	return u, nil
}

// userNameChunk is how many names one statement binds. SQLite's own default for
// SQLITE_MAX_VARIABLE_NUMBER has been far higher since 3.32, but the historical
// floor was 999 and a statement that depends on a compile-time option is a
// statement that works on one build and fails on another.
const userNameChunk = 500

// GetUserIDsByUsernames returns the id of every account whose username matches
// one of the given names, keyed by the lower-cased username as stored.
//
// A name missing from the result is a name that is not an account, which is the
// only question the caller is asking: the indexer re-checks the authors a secret
// fence named before the accounts existed, and a map lets it ask about one name
// without going back to the database. The whole set is looked up at once because
// the alternative is a query per page, and a fresh vault can have a great many of
// them.
//
// The comparison is NOCASE — the column is declared so — so a caller need not
// reproduce the folding itself, and the result is keyed the same way so a name
// written in a fence directive answers the same whatever its case.
//
// Every name is a bind parameter, and so is every placeholder: the statement is
// assembled from a constant and a count, never from a value.
func GetUserIDsByUsernames(ctx context.Context, q Queryer, usernames []string) (map[string]int64, error) {
	out := make(map[string]int64, len(usernames))
	for start := 0; start < len(usernames); start += userNameChunk {
		end := start + userNameChunk
		if end > len(usernames) {
			end = len(usernames)
		}
		// The window must move, or this loop re-asks the same question for ever.
		// A non-positive chunk is the only way it would not, and it is a
		// constant, so the case is asserted rather than trusted.
		if end <= start {
			return nil, errors.New("store: the username chunk size is not positive")
		}
		batch := usernames[start:end]
		args := make([]any, 0, len(batch))
		for _, u := range batch {
			args = append(args, u)
		}
		rows, err := q.QueryContext(ctx,
			`SELECT id, username FROM users WHERE username IN (`+bindMarkers(len(batch))+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("store: look up %d usernames: %w", len(batch), err)
		}
		err = ForEach(rows, func(r Rows) error {
			var id int64
			var username string
			if err := r.Scan(&id, &username); err != nil {
				return fmt.Errorf("store: scan user: %w", err)
			}
			out[strings.ToLower(username)] = id
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// bindMarkers returns a comma-separated run of n positional bind markers. Only
// the count is a variable, and a count is not a value.
func bindMarkers(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ListUsers returns every account, by id.
func ListUsers(ctx context.Context, q Queryer) ([]User, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	var out []User
	err = ForEach(rows, func(r Rows) error {
		u, err := scanUser(r)
		if err != nil {
			return fmt.Errorf("store: scan user: %w", err)
		}
		out = append(out, u)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountUsers returns the number of accounts. /setup is open only while this is
// zero, so the check must be inside the transaction that creates the first one.
func CountUsers(ctx context.Context, q Queryer) (int64, error) {
	var n int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// SetUserRole changes an account's role.
func SetUserRole(ctx context.Context, e Execer, id int64, role string) error {
	if _, err := e.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id); err != nil {
		return fmt.Errorf("store: set role of user %d: %w", id, err)
	}
	return nil
}

// SetUserPassword replaces an account's Argon2id hash and salt. It does not
// touch sessions; the caller revokes them, because a privilege change has to
// terminate a stream as well as a cookie (§8.11).
func SetUserPassword(ctx context.Context, e Execer, id int64, hash, salt []byte) error {
	if _, err := e.ExecContext(ctx,
		`UPDATE users SET pw_hash = ?, pw_salt = ? WHERE id = ?`, hash, salt, id); err != nil {
		return fmt.Errorf("store: set password of user %d: %w", id, err)
	}
	return nil
}

// SetUserDisabled disables or re-enables an account.
func SetUserDisabled(ctx context.Context, e Execer, id int64, at *time.Time) error {
	if _, err := e.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, nullableTime(at), id); err != nil {
		return fmt.Errorf("store: set disabled state of user %d: %w", id, err)
	}
	return nil
}

// DeleteUser removes an account. sessions and invites cascade; revisions keep
// their author_id as NULL.
func DeleteUser(ctx context.Context, e Execer, id int64) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete user %d: %w", id, err)
	}
	return nil
}

// Session is a row of the sessions table. ID is the sha256 of the cookie token:
// the raw token exists only in the cookie and is never stored, so a database
// leak does not hand out sessions.
type Session struct {
	// ID is the sha256 of the session token.
	ID string
	// UserID is the account the session authenticates.
	UserID int64
	// CreatedAt is when the session was issued.
	CreatedAt time.Time
	// ExpiresAt is when the session stops being valid.
	ExpiresAt time.Time
	// LastSeenAt is when the session was last presented, for idle expiry.
	LastSeenAt time.Time
	// UserAgent is the presenting client, or empty.
	UserAgent string
}

func scanSession(s RowScanner) (Session, error) {
	var (
		sess      Session
		created   string
		expires   string
		lastSeen  string
		userAgent sql.NullString
	)
	if err := s.Scan(&sess.ID, &sess.UserID, &created, &expires, &lastSeen, &userAgent); err != nil {
		return Session{}, err
	}
	var err error
	if sess.CreatedAt, err = ParseTime(created); err != nil {
		return Session{}, err
	}
	if sess.ExpiresAt, err = ParseTime(expires); err != nil {
		return Session{}, err
	}
	if sess.LastSeenAt, err = ParseTime(lastSeen); err != nil {
		return Session{}, err
	}
	sess.UserAgent = userAgent.String
	return sess, nil
}

// InsertSession records a new session.
func InsertSession(ctx context.Context, e Execer, s Session) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, FormatTime(s.CreatedAt), FormatTime(s.ExpiresAt),
		FormatTime(s.LastSeenAt), nullIfEmpty(s.UserAgent)); err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	return nil
}

// GetSession returns a session by its hashed id.
func GetSession(ctx context.Context, q Queryer, id string) (Session, error) {
	s, err := scanSession(q.QueryRowContext(ctx,
		`SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent
		 FROM sessions WHERE id = ?`, id))
	if err != nil {
		return Session{}, wrapNoRows(err, "session")
	}
	return s, nil
}

// TouchSession records that a session was just presented, which is what drives
// idle expiry. A caller that has re-read the session must not write back a stale
// expiry, so this takes the new time explicitly.
func TouchSession(ctx context.Context, e Execer, id string, lastSeen time.Time) error {
	if _, err := e.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, FormatTime(lastSeen), id); err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	}
	return nil
}

// DeleteSession revokes one session.
func DeleteSession(ctx context.Context, e Execer, id string) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// DeleteUserSessions revokes every session of an account. A privilege change
// must call this: a role bump that leaves a live cookie in place is a role bump
// that did not happen.
func DeleteUserSessions(ctx context.Context, e Execer, userID int64) (int64, error) {
	n, err := Exec(ctx, e, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions of user %d: %w", userID, err)
	}
	return n, nil
}

// DeleteExpiredSessions removes sessions that expired before a cutoff. It is the
// boot step in §7.5, not a periodic job.
func DeleteExpiredSessions(ctx context.Context, e Execer, before time.Time) (int64, error) {
	n, err := Exec(ctx, e, `DELETE FROM sessions WHERE expires_at < ?`, FormatTime(before))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return n, nil
}

// Invite is a row of the invites table. TokenHash is the sha256 of the token;
// the raw token exists only in the URL handed to the invitee.
type Invite struct {
	// TokenHash is the sha256 of the invite token.
	TokenHash string
	// Role is the role the invite grants.
	Role string
	// CreatedBy is the admin who issued it.
	CreatedBy int64
	// CreatedAt is when it was issued.
	CreatedAt time.Time
	// ExpiresAt is when it stops being redeemable.
	ExpiresAt time.Time
	// RedeemedAt is when it was used, or nil.
	RedeemedAt *time.Time
	// RedeemedBy is the account that used it, or nil.
	RedeemedBy *int64
}

// Redeemed reports whether the invite has already been used.
func (i Invite) Redeemed() bool { return i.RedeemedAt != nil }

func scanInvite(s RowScanner) (Invite, error) {
	var (
		i         Invite
		createdAt string
		expiresAt string
		redeemed  sql.NullString
		redeemBy  sql.NullInt64
	)
	if err := s.Scan(&i.TokenHash, &i.Role, &i.CreatedBy, &createdAt, &expiresAt,
		&redeemed, &redeemBy); err != nil {
		return Invite{}, err
	}
	var err error
	if i.CreatedAt, err = ParseTime(createdAt); err != nil {
		return Invite{}, err
	}
	if i.ExpiresAt, err = ParseTime(expiresAt); err != nil {
		return Invite{}, err
	}
	if redeemed.Valid {
		t, err := ParseTime(redeemed.String)
		if err != nil {
			return Invite{}, err
		}
		i.RedeemedAt = &t
	}
	if redeemBy.Valid {
		id := redeemBy.Int64
		i.RedeemedBy = &id
	}
	return i, nil
}

// InsertInvite records a new invite.
func InsertInvite(ctx context.Context, e Execer, i Invite) error {
	if _, err := e.ExecContext(ctx,
		`INSERT INTO invites (token_hash, role, created_by, created_at, expires_at, redeemed_at, redeemed_by)
		 VALUES (?, ?, ?, ?, ?, NULL, NULL)`,
		i.TokenHash, i.Role, i.CreatedBy, FormatTime(i.CreatedAt), FormatTime(i.ExpiresAt)); err != nil {
		return fmt.Errorf("store: insert invite: %w", err)
	}
	return nil
}

// GetInviteByTokenHash returns an invite by its hashed token.
func GetInviteByTokenHash(ctx context.Context, q Queryer, tokenHash string) (Invite, error) {
	i, err := scanInvite(q.QueryRowContext(ctx,
		`SELECT token_hash, role, created_by, created_at, expires_at, redeemed_at, redeemed_by
		 FROM invites WHERE token_hash = ?`, tokenHash))
	if err != nil {
		return Invite{}, wrapNoRows(err, "invite")
	}
	return i, nil
}

// ListInvites returns every invite, newest first.
func ListInvites(ctx context.Context, q Queryer) ([]Invite, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT token_hash, role, created_by, created_at, expires_at, redeemed_at, redeemed_by
		 FROM invites ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list invites: %w", err)
	}
	var out []Invite
	err = ForEach(rows, func(r Rows) error {
		i, err := scanInvite(r)
		if err != nil {
			return fmt.Errorf("store: scan invite: %w", err)
		}
		out = append(out, i)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListPendingInvites returns the unredeemed, unexpired invites.
func ListPendingInvites(ctx context.Context, q Queryer, now time.Time) ([]Invite, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT token_hash, role, created_by, created_at, expires_at, redeemed_at, redeemed_by
		 FROM invites WHERE redeemed_at IS NULL AND expires_at > ?
		 ORDER BY created_at DESC`, FormatTime(now))
	if err != nil {
		return nil, fmt.Errorf("store: list pending invites: %w", err)
	}
	var out []Invite
	err = ForEach(rows, func(r Rows) error {
		i, err := scanInvite(r)
		if err != nil {
			return fmt.Errorf("store: scan invite: %w", err)
		}
		out = append(out, i)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrInviteUsed is returned by RedeemInvite when the invite was already
// redeemed. It is distinct from "not found" so that a replayed invite URL is
// reported as a replay rather than as a 404 that suggests the token was never
// valid.
var ErrInviteUsed = errors.New("store: invite already redeemed")

// RedeemInvite marks an invite used, but only if it is unredeemed and
// unexpired. The condition is in the WHERE clause rather than in Go, so two
// simultaneous redemptions of one token cannot both succeed: the second
// statement matches no row and ErrInviteUsed comes back.
func RedeemInvite(ctx context.Context, e Execer, tokenHash string, userID int64, at time.Time) error {
	res, err := e.ExecContext(ctx,
		`UPDATE invites SET redeemed_at = ?, redeemed_by = ?
		 WHERE token_hash = ? AND redeemed_at IS NULL AND expires_at > ?`,
		FormatTime(at), userID, tokenHash, FormatTime(at))
	if err != nil {
		return fmt.Errorf("store: redeem invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: redeem invite: %w", err)
	}
	if n == 0 {
		return ErrInviteUsed
	}
	return nil
}

// DeleteInvite removes an invite outright.
func DeleteInvite(ctx context.Context, e Execer, tokenHash string) error {
	if _, err := e.ExecContext(ctx, `DELETE FROM invites WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete invite: %w", err)
	}
	return nil
}

// DeleteExpiredInvites removes invites that expired before a cutoff.
func DeleteExpiredInvites(ctx context.Context, e Execer, before time.Time) (int64, error) {
	n, err := Exec(ctx, e, `DELETE FROM invites WHERE expires_at < ?`, FormatTime(before))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired invites: %w", err)
	}
	return n, nil
}
