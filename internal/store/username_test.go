package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A username collision must arrive as a sentinel a caller can branch on. The
// alternative was matching the driver's message text, which turns a friendly
// 400 into a 500 the moment the driver is upgraded.
func TestInsertUserReportsATakenUsernameAsTheSentinel(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	ctx := context.Background()

	base := User{
		Username: "gundren", DisplayName: "Gundren", Role: "dm",
		PWHash: []byte("$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaA"),
		PWSalt: []byte("saltsalt"),
	}
	if _, err := InsertUser(ctx, db.Writer(), base); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Exactly the same name.
	if _, err := InsertUser(ctx, db.Writer(), base); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("a duplicate username returned %v, want ErrUsernameTaken", err)
	}

	// The index is COLLATE NOCASE, so this collides too — and a check-then-insert
	// in the caller would have missed it.
	upper := base
	upper.Username = "Gundren"
	if _, err := InsertUser(ctx, db.Writer(), upper); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("a case-differing duplicate returned %v, want ErrUsernameTaken", err)
	}

	// A different name is not a conflict, and must not be mistaken for one.
	other := base
	other.Username = "sildar"
	if _, err := InsertUser(ctx, db.Writer(), other); err != nil {
		t.Errorf("a fresh username was rejected: %v", err)
	}
}

// A constraint failure that is not a username collision must not be laundered
// into the sentinel, or a real error becomes a "try another name" message.
func TestOnlyAUniqueViolationBecomesTheSentinel(t *testing.T) {
	t.Parallel()
	db := newMigratedDB(t)
	ctx := context.Background()

	// role has a CHECK constraint in the migration, so this fails as a
	// constraint violation that is *not* a unique violation.
	bad := User{
		Username: "gundren", DisplayName: "Gundren", Role: "wizard",
		PWHash: []byte("x"), PWSalt: []byte("y"),
	}
	_, err := InsertUser(ctx, db.Writer(), bad)
	if err == nil {
		t.Fatal("a role outside the check constraint was accepted")
	}
	if errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("a check-constraint failure was reported as a taken username: %v", err)
	}
}

// A user with no disabled_at is enabled, and a disabled one is not, so that
// "is there an admin left" is answerable from the row alone.
func TestUserActiveReflectsDisabledAt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)
	if !(User{}).Active() {
		t.Error("a user with no disabled_at should be active")
	}
	if (User{DisabledAt: &now}).Active() {
		t.Error("a user with disabled_at set should not be active")
	}
}
