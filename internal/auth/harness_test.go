package auth

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
)

// clockNow is the instant every fixture's clock reports, so a stored timestamp
// in an assertion is a literal rather than a formatted now.
var clockNow = time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)

// cheapHash is the parameter set the fixtures derive with.
//
// Argon2id at 64 MiB costs about 140 ms on this machine, which is the right
// price for a real account and the wrong price for a fixture that only needs an
// account to exist. Every fixture here is a *user*, not a *test of argon2*, so
// it uses a cheap verifier — which is only possible at all because the costs
// travel inside the hash, and is itself worth an assertion in
// TestTheEncodedParametersAreWhatVerificationWillUse.
//
// The tests that are about argon2 or about login timing use the real costs, and
// the count of those is kept deliberately small.
const (
	cheapMemoryKiB = 64
	cheapPasses    = 1
	cheapThreads   = 1
)

// harness is a Service over a temp vault, with a movable clock and an
// in-memory log.
type harness struct {
	t     *testing.T
	vault *testutil.Vault
	db    *store.DB
	svc   *Service
	// main and audit are the two sinks the redacting handler writes to. They
	// are kept apart because obs keeps them apart, and a leak test that merged
	// them would pass for the wrong reason on one and fail for the wrong reason
	// on the other.
	main  *safeBuffer
	audit *safeBuffer
	// nowUnixNano is the clock. It is atomic because the concurrent-setup test
	// reads it from five goroutines and moving it must not race with them.
	nowUnixNano atomic.Int64
}

// safeBuffer is a bytes.Buffer that survives the concurrent-setup test, whose
// five goroutines all write audit records through the logger.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	v := testutil.NewVault(t)
	db, err := store.Open(v.Root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close store: %v", closeErr)
		}
	})
	if migrateErr := store.Migrate(context.Background(), db.Writer(), func(context.Context) error { return nil }); migrateErr != nil {
		t.Fatalf("migrate: %v", migrateErr)
	}

	h := &harness{t: t, vault: v, db: db, main: &safeBuffer{}, audit: &safeBuffer{}}
	h.nowUnixNano.Store(clockNow.UnixNano())

	log := obs.NewLogger(h.main, obs.Options{Level: slog.LevelDebug, Audit: h.audit})
	svc, err := New(Options{DB: db, Policy: authz.NewPolicy(false), Log: log, Clock: h.now})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	h.svc = svc
	return h
}

// now is the harness clock.
func (h *harness) now() time.Time { return time.Unix(0, h.nowUnixNano.Load()).UTC() }

// advance moves the clock forward. Nothing in this package sleeps: an expiry
// test that waited out fourteen days would be a test nobody runs, and one that
// waited out a second would be a test that fails on a loaded machine.
func (h *harness) advance(d time.Duration) { h.nowUnixNano.Add(int64(d)) }

// setClock moves the clock to an absolute instant.
func (h *harness) setClock(at time.Time) { h.nowUnixNano.Store(at.UnixNano()) }

// logs is everything both sinks have been given, for the leak suite.
func (h *harness) logs() string { return h.main.String() + h.audit.String() }

// cheapVerifier derives a fixture passphrase at the cheap parameter set.
func cheapVerifier(t *testing.T, passphrase string) (phc string, salt []byte) {
	t.Helper()
	phc, err := hashPassphraseWith(passphrase, cheapMemoryKiB, cheapPasses, cheapThreads)
	if err != nil {
		t.Fatalf("cheap hash: %v", err)
	}
	salt, err = SaltFromPHC(phc)
	if err != nil {
		t.Fatalf("salt from phc: %v", err)
	}
	return phc, salt
}

// seedUser inserts an account directly, with a cheap verifier, and returns its
// id. It bypasses the public surface on purpose: most tests need an account to
// exist, not to have been created by Setup or by an invite, and paying 140 ms
// of argon2 for each of a dozen fixtures would be paying for nothing.
func (h *harness) seedUser(username string, role authz.Role) int64 {
	h.t.Helper()
	phc, salt := cheapVerifier(h.t, fixturePassphrase(username))
	id, err := store.InsertUser(h.t.Context(), h.db.Writer(), store.User{
		Username:    username,
		DisplayName: username,
		Role:        role.String(),
		PWHash:      []byte(phc),
		PWSalt:      salt,
		CreatedAt:   h.now(),
	})
	if err != nil {
		h.t.Fatalf("seed user %s: %v", username, err)
	}
	return id
}

// seedUserAt inserts an account with a verifier the caller derived, so a test
// that is about the cost parameters can use the real ones and a test that is
// about something else does not. A nil salt is filled in from the hash, because
// users.pw_salt is NOT NULL and a fixture should not have to care.
func (h *harness) seedUserAt(username, phc string, salt []byte) int64 {
	h.t.Helper()
	if salt == nil {
		var err error
		if salt, err = SaltFromPHC(phc); err != nil {
			h.t.Fatalf("salt for %s: %v", username, err)
		}
	}
	id, err := store.InsertUser(h.t.Context(), h.db.Writer(), store.User{
		Username:    username,
		DisplayName: username,
		Role:        authz.RolePlayer.String(),
		PWHash:      []byte(phc),
		PWSalt:      salt,
		CreatedAt:   h.now(),
	})
	if err != nil {
		h.t.Fatalf("seed user %s: %v", username, err)
	}
	return id
}

// fixturePassphrase is the passphrase a seeded account actually has. It is
// deterministic per username so a test can log in without a second variable.
func fixturePassphrase(username string) string {
	return "Fixture-Pass-" + username + "1"
}

// principal builds the Principal an admin would arrive with for a seeded
// account, with the generation the store currently reports.
func (h *harness) principal(userID int64, username string, role authz.Role) authz.Principal {
	h.t.Helper()
	gen, err := store.AuthzGeneration(h.t.Context(), h.db.Reader())
	if err != nil {
		h.t.Fatalf("authz generation: %v", err)
	}
	return authz.Principal{
		UserID:             userID,
		Username:           username,
		Role:               role,
		AuthzGeneration:    gen,
		AllowAnonymousRead: false,
	}
}

// login mints a session for a seeded account and returns the raw token.
func (h *harness) login(username string) string {
	h.t.Helper()
	return h.loginAs(username, fixturePassphrase(username))
}

// loginAs mints a session with a passphrase the caller names, for the tests
// that set one up through the public surface rather than through seedUser.
func (h *harness) loginAs(username, passphrase string) string {
	h.t.Helper()
	raw, err := h.svc.Create(h.t.Context(), LoginRequest{
		Username:   username,
		Passphrase: passphrase,
		UserAgent:  "harness",
	})
	if err != nil {
		h.t.Fatalf("login %s: %v", username, err)
	}
	return raw
}

// countUsers is the assertion every "did it create an account" test wants.
func (h *harness) countUsers() int64 {
	h.t.Helper()
	n, err := store.CountUsers(h.t.Context(), h.db.Reader())
	if err != nil {
		h.t.Fatalf("count users: %v", err)
	}
	return n
}

// countAdmins counts the accounts whose role is admin, which is the only way to
// assert the first-run gate held: an extra player would be a different bug and
// an extra session is not a bug at all.
func (h *harness) countAdmins() int64 {
	h.t.Helper()
	users, err := store.ListUsers(h.t.Context(), h.db.Reader())
	if err != nil {
		h.t.Fatalf("list users: %v", err)
	}
	var n int64
	for _, u := range users {
		if u.Role == authz.RoleAdmin.String() {
			n++
		}
	}
	return n
}

// userVerifier is the stored Argon2id verifier of an account.
func (h *harness) userVerifier(username string) []byte {
	h.t.Helper()
	u, err := store.GetUserByUsername(h.t.Context(), h.db.Reader(), username)
	if err != nil {
		h.t.Fatalf("load %s: %v", username, err)
	}
	return u.PWHash
}

// userID is the id of an account.
func (h *harness) userID(t *testing.T, username string) int64 {
	t.Helper()
	u, err := store.GetUserByUsername(t.Context(), h.db.Reader(), username)
	if err != nil {
		t.Fatalf("load %s: %v", username, err)
	}
	return u.ID
}
