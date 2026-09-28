package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
)

// The cookies. Two names, because two lifetimes: a session is revoked server
// side and a pre-session CSRF secret is not, and a logout must not be able to
// leave a client in a state where the form it must re-render has no token.
const (
	// SessionCookie carries the raw session token.
	SessionCookie = "semiplane_session"
	// CSRFCookie carries the pre-session double-submit secret, for the two forms
	// a visitor reaches before they have a session: /login and /setup.
	CSRFCookie = "semiplane_csrf"
	// CSRFHeader is the header an enhanced form submission sends the token in.
	CSRFHeader = "X-CSRF-Token"
	// CSRFField is the form field an ordinary form submission sends it in.
	CSRFField = "csrf"
)

// cookieOptions are the flags both cookies carry.
//
// SameSite is Strict because nothing in this app has a reason to be submitted
// from another origin, and Strict is the setting that makes the double-submit
// comparison worth having. Secure is set whenever the request arrived over TLS,
// which is to say never on a plain-HTTP LAN — a Secure cookie on a plain-HTTP
// listener is a cookie the browser silently drops, and a form that cannot
// carry its token is an app that cannot be used.
func cookieOptions(secure bool) *http.Cookie {
	return &http.Cookie{
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// ContentSecurityPolicy is the policy every response carries.
//
// There is no unsafe-eval and no unsafe-inline, and no remote origin of any
// kind: the stylesheet, the script and the icon are all served from
// /_/assets/ out of the binary. The one concession is img-src 'self' data:,
// because a campaign note embeds images and a data: URI is not a fetch from
// anywhere — it never leaves the process that wrote it.
const ContentSecurityPolicy = "default-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'; " +
	"img-src 'self' data:; " +
	"style-src 'self'; " +
	"script-src 'self'; " +
	"connect-src 'self'"

// PermissionsPolicy refuses every capability this app never uses, so that a
// future feature cannot inherit one by default.
const PermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), " +
	"magnetometer=(), accelerometer=(), interest-cohort=()"

// chain wraps h in the middleware, outermost first.
//
// The order is the contract:
//
//	Recoverer → RequestID → RequestLogger → SecureHeaders → Session →
//	RateLimit → per-route CSRF → per-route Perm → handler
//
// Recoverer is outermost so that a panic in any later stage is caught. The
// request id comes next so that every record after it can name the request it
// belongs to, including the record the recoverer itself writes. The request
// logger is inside the recoverer so that a panicking request is still recorded.
// SecureHeaders is outside Session so that even a response produced by a
// failure to resolve a session carries the headers. Session is outside the
// route-level gates because Perm and CSRF both need the principal, and RateLimit
// is inside Session only because it is cheaper without a database round trip
// for the requests it is about to refuse.
func (s *Server) chain(h http.Handler) http.Handler {
	// The chain is assembled innermost first, because each line wraps the one
	// above it. Written the other way round — which is the obvious thing to do,
	// and which was the first version of this function — the last line named is
	// the outermost, so the recoverer ended up two layers in and a panicked
	// request took the process with it. The list in the comment is the order that
	// actually runs, and TestTheMiddlewareChainIsInOrder walks it to keep it so.
	h = s.rateLimit(h)
	h = s.session(h)
	h = s.secureHeaders(h)
	h = s.requestLogger(h)
	h = requestID(h)
	h = s.recoverer(h)
	return h
}

// recoverer turns a panic into the 500 page.
//
// The panic value is never rendered and never logged. A panic carries whatever
// the panicking code had in hand, and on this codebase that can be a fragment
// of a vault file: the page-view path reads one, and a renderer that panicked
// halfway through a page it was rendering has it on the stack. So the value is
// reduced to its type, a hash and a length, and the stack is recorded, which is
// what a person debugging this needs and nothing more.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// A panic after the response has begun cannot be turned into a 500
			// page: the status line is already on the wire. Recording it is all
			// that is left, and pretending otherwise would corrupt the response
			// body with a second document.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.log.ErrorContext(r.Context(), "a handler panicked; the response was replaced with the error page",
				"action", "http.panic",
				"request_id", obs.RequestID(r.Context()),
				"route", RouteFrom(r.Context()),
				"panic", logRecord(rec).String(),
				"stack", string(debug.Stack()))
			s.writeError(w, r, http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// requestID gives every request a correlation id and echoes it in a header.
//
// It is generated here rather than taken from a client, because a client that
// can choose the value can collide with another request's value and make two
// records look like one. The id is not a credential and grants nothing; it is
// in a response header only, never in the body, so that two error pages for the
// same failure are byte-identical.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := newToken()
		if err != nil {
			// crypto/rand failing is not a reason to refuse a request, and a
			// zero id is still a usable correlation value.
			id = "0000000000000000"
		}
		ctx := obs.WithRequestID(r.Context(), id)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestLogger records one line per request: method, path, status, duration,
// principal and request id.
//
// What is *not* recorded is the point. The query string is not, because a
// search term is vault content and a `next=` parameter can carry a path; no
// header value is, because an Authorization or Cookie header is a credential
// and a User-Agent is a client-chosen string that would let a caller write
// arbitrary bytes into the operator's log; and no body is, obviously.
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := s.now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Principal.String() never contains a session token, and obs refuses a
		// `cookie` or `token` key outright, so this line cannot become one even
		// if a future edit names the wrong field.
		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelWarn
		}
		s.log.Log(r.Context(), level, "request",
			"action", "http.request",
			"request_id", obs.RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"route", RouteFrom(r.Context()),
			"status", rec.status,
			"bytes", rec.written,
			"duration_ms", s.now().Sub(started).Milliseconds(),
			"actor", PrincipalFrom(r.Context()).String())
	})
}

// statusRecorder captures the status code and the size of a response.
//
// It implements Unwrap so that http.ResponseController can still reach Flush
// and Hijack through it, which the live-push stream of a later phase needs; a
// logger that swallowed them would break a feature it is not part of.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
	wrote   bool
}

// WriteHeader records the status the handler chose. A second call is ignored
// rather than forwarded, because forwarding it would make the log record a status
// the client never received.
func (r *statusRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Write records the size of the response as it goes, so the request record can
// report how much a request actually cost rather than how much was offered.
func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

// Flush forwards to the wrapped writer when it can flush. A writer that cannot
// is not an error: a recorder is not allowed to be the reason a stream breaks.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// secureHeaders sets the headers every response carries, whoever wrote it.
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", PermissionsPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// The bind address is the only thing that decides this. A loopback
		// listener may be reached over plain HTTP from the machine itself, where
		// HSTS would pin http://127.0.0.1 to https and break it for good.
		if !isLoopbackHost(s.cfg.Host) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// session resolves the session cookie to a principal and puts it on the
// context.
//
// Every refusal resolves to the same anonymous principal and no error: no such
// token, an expired one, a disabled account and a malformed cookie are one
// answer, and the error return is only ever a real failure such as a cancelled
// context. A handler branches on Principal.Authenticated, never on an error.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		principal := authz.Anonymous(s.cfg.AllowAnonymousRead)
		raw := ""

		if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
			raw = c.Value
			p, err := s.auth.Session(ctx, raw)
			if err != nil {
				s.log.ErrorContext(ctx, "the session could not be resolved",
					"action", "http.session", "request_id", obs.RequestID(ctx),
					"err", err.Error())
				// A failure to resolve is not a failure to read the page: the
				// request continues as anonymous, which is the safe direction
				// and is also what an expired cookie looks like.
			} else {
				principal = p
			}
		}

		ctx = withValue(ctx, principalKey, principal)
		ctx = withValue(ctx, sessionKey, raw)
		// The token is decided from the resolved principal, so it is computed
		// against the context that carries it rather than against the request's
		// original one. Passing the request and expecting to read the principal
		// off it would read a context that does not have it yet, and every
		// authenticated request would fall through to the anonymous token.
		ctx = withValue(ctx, csrfKey, s.csrfToken(w, r.WithContext(ctx), raw))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfToken returns the token this response's forms must carry, minting one if
// there is none.
//
// An authenticated request gets the session's own token from the auth service,
// which is stored server side and cannot be forged. A request with no session
// gets a stateless double-submit secret instead: the value is in a SameSite
// cookie that only this origin can read and the form carries the same value,
// so a cross-origin submission cannot produce a matching pair. The two paths
// exist because the login and setup forms are the two forms a visitor reaches
// before they have a session, and refusing them for want of a session would
// make them unusable.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request, rawSession string) string {
	// Only a session that resolved may hand out a session token. A cookie that is
	// presented but resolves to nothing — revoked, expired, or belonging to an
	// account that was just disabled — must not decide which token the form
	// carries, or the form would carry a token the gate is about to ignore and
	// every submission from that client would be refused for no reason a reader
	// could act on.
	if rawSession != "" && PrincipalFrom(r.Context()).Authenticated() {
		if token, err := s.auth.CSRFToken(rawSession); err == nil && token != "" {
			return token
		}
	}
	if c, err := r.Cookie(CSRFCookie); err == nil && wellFormedHex(c.Value) {
		return c.Value
	}
	token, err := newToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, withCookieName(cookieOptions(r.TLS != nil), CSRFCookie, token))
	return token
}

// rateLimit refuses the requests that are expensive rather than the requests
// that are numerous.
//
// The login budget is 10 a minute because an Argon2id verification costs about
// 130 ms of memory-hard work, which makes an unthrottled login form a
// denial-of-service amplifier aimed at a single-connection write pool. The
// search budget is lower than the general one because a search is the one query
// a client can make arbitrarily expensive. Everything else gets the general
// budget, which exists to stop a loop rather than to slow a reader down.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		class := limitGeneral
		switch {
		case r.Method == http.MethodPost && isAuthPath(r.URL.Path):
			// Only the *submission*. The login form itself is a cheap page render
			// that a reader may load several times while typing, and charging it to
			// a budget of ten would mean a reader who mistypes their passphrase four
			// times has to wait a minute for the page they are already looking at.
			// What the budget is for is the Argon2id derivation, and only the
			// submission does one.
			class = limitLogin
		case strings.HasPrefix(r.URL.Path, "/search") || strings.HasPrefix(r.URL.Path, "/api/search"):
			class = limitSearch
		}
		if !s.limits.allow(class, clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			s.writeError(w, r, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAuthPath reports whether a path is one of the two forms that spend an
// Argon2id derivation.
func isAuthPath(path string) bool {
	return path == "/login" || path == "/setup" || strings.HasPrefix(path, "/invite/")
}

// clientIP is the address the request came from.
//
// X-Forwarded-For is deliberately not consulted. This app is meant to be
// reached directly on a LAN and is never meant to sit behind a proxy, and
// honouring a client-supplied header would let the client choose which bucket
// it is counted in — which is to say, let it choose to never be counted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// The rate classes.
type limitClass int

const (
	limitGeneral limitClass = iota
	limitLogin
	limitSearch
)

// limiters is the per-IP token bucket table, one bucket per class.
type limiters struct {
	login   *bucket
	search  *bucket
	general *bucket
}

// newLimiters builds the three buckets from the configured per-minute budgets.
//
// Development mode disables the limiter outright, which is what config.Dev
// documents: a developer reloading a form eleven times in a minute should not
// be told to wait, and the flag is the operator's own switch.
func newLimiters(cfg config.Config, now obs.Clock) *limiters {
	if cfg.Dev {
		return &limiters{login: unlimited(), search: unlimited(), general: unlimited()}
	}
	return &limiters{
		login:   newBucket(config.RateLoginPerMinute, now),
		search:  newBucket(config.RateSearchPerMinute, now),
		general: newBucket(config.RateSessionPerMinute, now),
	}
}

// allow spends one token for ip in the given class.
func (l *limiters) allow(class limitClass, ip string) bool {
	switch class {
	case limitLogin:
		return l.login.allow(ip)
	case limitSearch:
		return l.search.allow(ip)
	default:
		return l.general.allow(ip)
	}
}

// bucket is a token bucket per address, refilled continuously.
//
// A token bucket and not a fixed window: a fixed window lets a client spend
// its whole budget at the end of one window and again at the start of the next,
// which is twice the intended rate and lands exactly on the boundary an
// attacker would choose.
type bucket struct {
	mu       sync.Mutex
	capacity float64
	perSec   float64
	now      func() time.Time
	entries  map[string]*bucketEntry
	sweptAt  time.Time
}

type bucketEntry struct {
	tokens float64
	seen   time.Time
}

// newBucket builds a bucket allowing perMinute requests a minute from one
// address.
//
// The clock is a parameter rather than a call to time.Now so that a test can move
// time instead of sleeping. That is not only cheaper: a limiter that reads the
// wall clock cannot be tested for its refill at all, so the behaviour that matters
// most — that a refusal expires — would be the one behaviour with no test.
func newBucket(perMinute int, now obs.Clock) *bucket {
	if perMinute <= 0 {
		return unlimited()
	}
	if now == nil {
		now = time.Now
	}
	return &bucket{
		capacity: float64(perMinute),
		perSec:   float64(perMinute) / 60,
		now:      now,
		entries:  make(map[string]*bucketEntry),
	}
}

// unlimited is a bucket that never refuses. It is what development mode gets.
func unlimited() *bucket {
	return &bucket{capacity: math.Inf(1), perSec: math.Inf(1), now: time.Now, entries: map[string]*bucketEntry{}}
}

// allow spends a token for ip, reporting whether one was available.
func (b *bucket) allow(ip string) bool {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)

	e, ok := b.entries[ip]
	if !ok {
		e = &bucketEntry{}
		b.entries[ip] = e
	}
	e.tokens += now.Sub(e.seen).Seconds() * b.perSec
	if e.tokens > b.capacity {
		e.tokens = b.capacity
	}
	e.seen = now
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

// sweep forgets an address that has not been seen for ten minutes, so the table
// does not grow with every address that ever asked for a page.
func (b *bucket) sweep(now time.Time) {
	if now.Sub(b.sweptAt) < time.Minute {
		return
	}
	b.sweptAt = now
	cutoff := now.Add(-10 * time.Minute)
	for ip, e := range b.entries {
		if e.seen.Before(cutoff) {
			delete(b.entries, ip)
		}
	}
}

// checkCSRF refuses a mutation whose presented token does not match.
//
// It is a gate on every method that is not GET or HEAD, and it is derived from
// the route table rather than from a list a test maintains, so a route added
// tomorrow is covered tomorrow. Two checks run, and both must pass for an
// authenticated request: the form's token must be the session's token, and it
// must also be the cookie's. The first is the authorization; the second is what
// makes a token a double-submit rather than a value a second page could have
// read.
func (s *Server) checkCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := r.Header.Get(CSRFHeader)
		if presented == "" {
			presented = r.PostFormValue(CSRFField)
		}
		// The session is consulted only when it resolved. A cookie that no longer
		// resolves — expired, revoked, or belonging to an account that was just
		// disabled — leaves the request anonymous, and an anonymous request has to
		// pass the anonymous gate. Refusing it because a stale cookie happened to
		// be present would leave a browser that had been signed out unable to use
		// the sign-in form, which is the one form it still needs.
		raw := ""
		if PrincipalFrom(r.Context()).Authenticated() {
			raw = SessionFrom(r.Context())
		}
		if raw == "" {
			// No session: this is one of the two forms a visitor reaches before
			// they have one, so the pre-session cookie is the whole check.
			c, err := r.Cookie(CSRFCookie)
			if err != nil || c.Value == "" || !wellFormedHex(presented) {
				s.refuseCSRF(w, r)
				return
			}
			if subtle.ConstantTimeCompare([]byte(c.Value), []byte(presented)) != 1 {
				s.refuseCSRF(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !s.auth.CheckCSRF(raw, presented) {
			s.refuseCSRF(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseCSRF answers 403 with the error page.
//
// It is a 403 and not a redirect to the login form: a form whose token did not
// match is a request the server is refusing, and sending the client somewhere
// else to get a new one would be a way to make a mutation succeed by
// convincing the browser to try again.
func (s *Server) refuseCSRF(w http.ResponseWriter, r *http.Request) {
	s.log.WarnContext(r.Context(), "a mutation was refused: no valid csrf token",
		"action", "http.csrf", "request_id", obs.RequestID(r.Context()),
		"method", r.Method, "path", r.URL.Path, "route", RouteFrom(r.Context()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.writeError(w, r, http.StatusForbidden)
}

// permit is the one place a role is compared.
//
// The route table's permission is a resource-free permission, so the policy is
// asked with the bare Resource except for /setup, whose answer depends on the
// database rather than on the principal: after bootstrap the route must be
// absent rather than forbidden, so that an outsider cannot confirm the
// installation exists by watching a 403.
func (s *Server) permit(rt Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.checkPerm(rt, w, r, next)
		})
	}
}

// checkPerm is the body of the Perm gate, split out so that the wrapper reads
// as one line at the call site in the router.
func (s *Server) checkPerm(rt Route, w http.ResponseWriter, r *http.Request, next http.Handler) {
	if rt.Perm == PermNone {
		next.ServeHTTP(w, r)
		return
	}
	who := PrincipalFrom(r.Context())
	res := authz.Resource{}
	if rt.Perm == authz.PermSetupOpen {
		open, err := s.auth.SetupOpen(r.Context())
		if err != nil {
			s.log.ErrorContext(r.Context(), "could not read the setup state",
				"action", "http.setup", "request_id", obs.RequestID(r.Context()),
				"err", err.Error())
			s.writeError(w, r, http.StatusInternalServerError)
			return
		}
		res.SetupOpen = open
	}
	err := s.policy.Check(who, rt.Perm, res)
	safe := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case err == nil:
		next.ServeHTTP(w, r)
	case errors.Is(err, authz.ErrSetupClosed):
		// Absent, not forbidden. The body is the not-found body, so a probe
		// cannot tell a closed setup from a route that was never there.
		s.writeError(w, r, http.StatusNotFound)
	case !who.Authenticated() && safe:
		// A denial for want of a session becomes a redirect to the login form.
		// The policy answers ErrDenied rather than ErrNotAuthenticated for a
		// content read, because "you have no session" and "anonymous read is
		// off" are the same answer to it — and the router is the layer that
		// knows it can offer a way to fix the first.
		s.redirectToLogin(w, r)
	default:
		s.log.WarnContext(r.Context(), "a request was refused by the policy",
			"action", "http.denied", "request_id", obs.RequestID(r.Context()),
			"route", rt.Name(), "perm", string(rt.Perm))
		s.writeError(w, r, http.StatusForbidden)
	}
}

// redirectToLogin sends an unauthenticated safe request to the login form.
//
// Only for GET and HEAD. A mutation is never redirected: a redirected POST
// loses its body, and a client that retried the resulting GET would be asking
// the server to do the mutation without a token.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, r, http.StatusForbidden)
		return
	}
	target := "/login"
	if r.URL.Path != "/" {
		target += "?next=" + urlQueryEscape(r.URL.Path)
	}
	w.Header().Set("Location", target)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusSeeOther)
}

// notFound is the router's answer for a URL no route claims. It is the same
// shape as the 403 and the 500, and the same body as a page the viewer may not
// read, because a URL that resolves to nothing and a page that may not be shown
// are the same answer.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusNotFound)
}

// methodNotAllowed is the router's answer for a known path and a wrong method.
// It is a 405 and not a 404 because the path exists and saying so leaks nothing
// about its content, only about the router.
func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, r, http.StatusMethodNotAllowed)
}

// newToken returns 32 bytes of crypto/rand as hex, which is 64 characters.
//
// The same shape as a session token, deliberately: the CSRF secret is a bearer
// value in a cookie, and there is no reason for the two to be distinguishable
// by length to anything reading a log.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// wellFormedHex reports whether s is 64 lowercase hex characters. It is the
// shape check the CSRF comparison runs before it compares anything, so a
// presented value of the wrong length is never a candidate.
func wellFormedHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// withCookieName returns c with its name set, so the two cookie writers above
// read as one line each.
func withCookieName(c *http.Cookie, name, value string) *http.Cookie {
	c.Name = name
	c.Value = value
	return c
}

// isLoopbackHost reports whether a bind host is a loopback address.
func isLoopbackHost(host string) bool {
	switch host {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// urlQueryEscape percent-encodes a path for one query parameter value.
func urlQueryEscape(s string) string {
	return strings.NewReplacer("&", "%26", "?", "%3F", "#", "%23", " ", "%20").Replace(s)
}
