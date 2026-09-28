package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// MaxInviteTTL is the longest lifetime a caller may ask for. An invite is a
// bearer credential that mints an admin, so a ttl of zero is replaced by the
// default and a ttl of a century is refused rather than honoured.
const MaxInviteTTL = 30 * 24 * time.Hour

// Options configures a Service. Every field is optional except DB; the zero
// Options is the production configuration, so the composition root only has to
// name the things it actually changes.
type Options struct {
	// DB is the vault index. Required.
	DB *store.DB
	// Policy decides who may manage accounts and invites, and supplies the
	// anonymous-read setting that every principal this package hands out
	// carries. The zero Policy denies anonymous reads, which is the safe
	// default; app passes the configured one.
	Policy authz.Policy
	// Log receives the audit trail. Nil discards it.
	Log *obs.Logger
	// Clock is the time source. Nil is the system clock. Tests move it rather
	// than sleeping, which is the only reason a session expiry test is cheap.
	Clock obs.Clock
	// SessionTTL overrides config.SessionTTL when positive.
	SessionTTL time.Duration
	// SessionSlide overrides config.SessionSlide when positive.
	SessionSlide time.Duration
	// InviteTTL overrides config.InviteTTL when positive.
	InviteTTL time.Duration
}

// Service is the account system: first-run setup, logins, sessions, invites and
// the CSRF tokens that hang off a session.
//
// It holds no *sql.DB of its own beyond the one Options hands it, and it never
// opens a transaction the caller did not ask for. Everything that mutates
// therefore runs on the single write connection, which is what makes the
// first-run gate in Setup sound.
type Service struct {
	db           *store.DB
	policy       authz.Policy
	log          *obs.Logger
	clock        obs.Clock
	sessionTTL   time.Duration
	sessionSlide time.Duration
	inviteTTL    time.Duration

	// csrfMu guards csrf. The map holds one hex token per live session id.
	//
	// It is in memory and it is meant to be: a CSRF token that survived a
	// restart would have to be readable from the vault or the database, and a
	// value in either of those is one a stolen backup hands over with a valid
	// session cookie. Losing the map on restart costs one round trip, and the
	// lost tokens are the ones a form rendered before the restart was holding,
	// which is exactly the set that should stop working.
	csrfMu sync.RWMutex
	csrf   map[string]csrfEntry
}

// New returns a Service. It never returns a nil Service with a nil error, so a
// caller never has to check before it starts a clock it cannot reach.
func New(opts Options) (*Service, error) {
	if opts.DB == nil {
		return nil, errors.New("auth: a database is required")
	}
	s := &Service{
		db:           opts.DB,
		policy:       opts.Policy,
		log:          opts.Log,
		clock:        opts.Clock,
		sessionTTL:   orDuration(opts.SessionTTL, config.SessionTTL),
		sessionSlide: orDuration(opts.SessionSlide, config.SessionSlide),
		inviteTTL:    orDuration(opts.InviteTTL, config.InviteTTL),
		csrf:         make(map[string]csrfEntry),
	}
	if s.log == nil {
		s.log = obs.Discard()
	}
	if s.clock == nil {
		s.clock = obs.SystemClock
	}
	return s, nil
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// now is the clock's value, truncated to UTC so that a stored timestamp and an
// in-memory one compare.
func (s *Service) now() time.Time { return s.clock().UTC() }

// principalFor builds the Principal a request is evaluated under. The role
// comes from the row read now, not from the row read at login: a principal is
// captured per request precisely so that a role change takes effect on the next
// request rather than the next login.
func (s *Service) principalFor(u store.User, sessionID string, generation int64) authz.Principal {
	return authz.Principal{
		UserID:             u.ID,
		Username:           u.Username,
		Role:               authz.Role(u.Role),
		SessionID:          sessionID,
		AuthzGeneration:    generation,
		AllowAnonymousRead: s.policy.AllowAnonymousRead,
	}
}

// anon is the principal every failed authentication resolves to. Every failure
// path returns this same value, which is what makes a login response
// indistinguishable between "no such account", "wrong passphrase" and "the
// account was disabled".
func (s *Service) anon() authz.Principal {
	return authz.Anonymous(s.policy.AllowAnonymousRead)
}

// audit writes one record to the audit log. Every key it is given is on
// obs.Handler's allow-list, so this call cannot become a side channel by
// construction — an unrecognised key is dropped by the handler rather than
// written, which is why no caller-supplied value is ever passed as a key.
func (s *Service) audit(ctx context.Context, msg string, args ...any) {
	s.log.Audit(ctx, msg, args...)
}

// requireAdmin is the single authorization gate in this package. It asks the
// policy, never the role: auth produces principals and authz decides what they
// may do, and a Role comparison here would be the second place in the codebase
// that answers that question.
func (s *Service) requireAdmin(ctx context.Context, actor authz.Principal, action string) error {
	if err := s.policy.Require(actor, authz.PermAdmin); err != nil {
		s.audit(ctx, "auth.denied", "action", action, "actor_id", actor.UserID, "result", "denied")
		return err
	}
	return nil
}
