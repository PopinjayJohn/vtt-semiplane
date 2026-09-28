package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/go-chi/chi/v5"
)

// maxFormBytes bounds a submitted form. A login body is three short fields, and
// an unbounded read is an unbounded allocation on a route an unauthenticated
// client may reach.
const maxFormBytes = 8 << 10

// sessionCookieTTL is how long the cookie asks the browser to keep the token.
// It is deliberately shorter than the server-side absolute lifetime, so a
// browser holding a token for a year is not the reason a session is still
// alive in a year.
const sessionCookieTTL = 7 * 24 * time.Hour

// timeZero is the expiry that tells a browser to delete a cookie now.
var timeZero = time.Unix(0, 0).UTC()

// readForm parses a submitted form under the byte cap.
//
// The cap is applied to the request body rather than to the parsed values, so a
// multipart upload cannot be read into memory first and trimmed afterwards.
func readForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

// loginForm is the login page.
//
// Its permission is PermNone, and that is deliberate rather than an oversight:
// a visitor who cannot sign in is precisely the person who has to be able to
// reach the form, and gating it on being able to read the campaign would lock
// out exactly the accounts that are configured not to be able to.
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	// An authenticated visitor has no use for the form, and following a stale
	// bookmark to it should land on the campaign rather than on a second way in.
	if PrincipalFrom(r.Context()).Authenticated() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	view := LoginView{Shell: s.shell(r, "Sign in"), Next: next}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the login form", err)
	}
}

// loginSubmit authenticates a passphrase and mints a session.
//
// The order is the security property. The body is read under a cap before
// anything else, the account is looked up and verified by the auth service —
// which spends the same Argon2id work whether the account exists or not — and
// only a success rotates the cookie. A failure is one answer for a username
// that does not exist, a wrong passphrase and a disabled account, because three
// answers would enumerate the campaign's accounts to anyone who can reach the
// form.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		s.loginFailed(w, r, LoginView{}, "The form could not be read. Try again.")
		return
	}
	username := r.PostFormValue("username")
	passphrase := r.PostFormValue("passphrase")
	next := safeNext(r.PostFormValue("next"))

	raw, err := s.auth.Create(r.Context(), auth.LoginRequest{
		Username:   username,
		Passphrase: passphrase,
		UserAgent:  r.UserAgent(),
		Replace:    SessionFrom(r.Context()),
	})
	if err != nil {
		// ErrBadCredentials is one sentinel for every failure, and anything else
		// is a real fault. Neither the message nor the log names the account:
		// the audit record below carries the actor id, and a failed login has
		// no actor.
		if errors.Is(err, auth.ErrBadCredentials) {
			s.log.WarnContext(r.Context(), "a login was refused",
				"action", "auth.login", "request_id", obs.RequestID(r.Context()))
			s.loginFailed(w, r, LoginView{Next: next}, "That username and passphrase do not match an account.")
			return
		}
		s.fail(w, r, "authenticate", err)
		return
	}

	s.setSessionCookie(w, r, raw)
	// A fresh session gets a fresh token; the one the previous session held
	// belongs to a session that no longer exists.
	if _, err := s.auth.SetCSRFToken(raw); err != nil {
		s.log.WarnContext(r.Context(), "a session was minted but its csrf token was not",
			"action", "auth.login", "request_id", obs.RequestID(r.Context()),
			"err", logRecord(err).String())
	}
	s.clearPreSessionCookie(w, r)
	s.log.Audit(r.Context(), "an account signed in",
		"action", "auth.login", "result", "ok", "path", "/login")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// loginFailed re-renders the form with one fixed problem phrase.
//
// The status is 200 rather than 401 deliberately: a browser that reloads a
// failed login should show the form again, and a 401 on a form post is a
// password-manager prompt in some configurations. The refusal is still complete
// — nothing was authenticated and nothing was written.
func (s *Server) loginFailed(w http.ResponseWriter, r *http.Request, view LoginView, problem string) {
	view.Shell = s.shell(r, "Sign in")
	view.Problem = problem
	w.Header().Set("Cache-Control", "no-store")
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the login form", err)
	}
}

// logout revokes the session and drops both cookies.
//
// It is idempotent: signing out of a browser that is not signed in is a
// success, and treating it as an error would make a stale bookmark look like a
// failure. It is a POST because it is a state change, and therefore
// CSRF-checked: a logout triggered from another origin is a nuisance at best
// and a way to knock a player off a shared machine at worst.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	raw := SessionFrom(r.Context())
	if raw != "" {
		if err := s.auth.Destroy(r.Context(), raw); err != nil {
			s.fail(w, r, "end the session", err)
			return
		}
	}
	s.clearSessionCookie(w, r)
	s.log.Audit(r.Context(), "an account signed out",
		"action", "auth.logout", "actor_id", PrincipalFrom(r.Context()).UserID)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// setupForm is the first-run form. Its permission is PermSetupOpen, which the
// policy answers from the database rather than from the principal, and which
// turns into a 404 the moment an account exists.
func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	view := SetupView{Shell: s.shell(r, "Set up")}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the setup form", err)
	}
}

// setupSubmit claims the first admin and signs them in.
//
// Setup mints no session of its own, so the handler calls Create straight
// afterwards with the same passphrase. That is the only reason the passphrase
// is still in hand here, and it is used once and never retained: it is not
// logged, not stored in a field of the view model, and not put in a URL.
func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		s.setupFailed(w, r, SetupView{}, "The form could not be read. Try again.", "")
		return
	}
	username := r.PostFormValue("username")
	display := strings.TrimSpace(r.PostFormValue("display_name"))
	passphrase := r.PostFormValue("passphrase")

	principal, err := s.auth.Setup(r.Context(), username, display, passphrase)
	if err != nil {
		var usernameErr *auth.UsernameError
		var passphraseErr *auth.PassphraseError
		switch {
		case errors.As(err, &usernameErr):
			// The reason is a fixed phrase for a class of failure. It never
			// echoes what was submitted: an error that quoted the input would
			// put the account's name into the response and the log.
			s.setupFailed(w, r, SetupView{}, usernameErr.Reason, "username")
		case errors.As(err, &passphraseErr):
			s.setupFailed(w, r, SetupView{}, passphraseErr.Reason, "passphrase")
		case errors.Is(err, authz.ErrSetupClosed):
			// Somebody else won the race between the form and the submit. The
			// route is gone now, and the answer is the same 404 it would give.
			s.writeError(w, r, http.StatusNotFound)
		default:
			s.fail(w, r, "claim the first account", err)
		}
		return
	}

	// The account exists now, so the secret fences that name it can finally be
	// attributed. Without this the first admin's own secrets are shown to nobody
	// until a full reindex: the vault was indexed at boot, before this account
	// existed.
	s.retryUnresolvedAuthors(r.Context())

	raw, err := s.auth.Create(r.Context(), auth.LoginRequest{
		Username:   username,
		Passphrase: passphrase,
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		// The account exists and the operator can sign in by hand; saying so
		// would be a hint, so the response is the ordinary 500 and the log
		// carries the fault.
		s.fail(w, r, "sign in the new administrator", err)
		return
	}
	s.setSessionCookie(w, r, raw)
	if _, err := s.auth.SetCSRFToken(raw); err != nil {
		s.log.WarnContext(r.Context(), "setup signed the new administrator in but minted no csrf token",
			"action", "auth.setup", "request_id", obs.RequestID(r.Context()),
			"err", logRecord(err).String())
	}
	s.clearPreSessionCookie(w, r)
	s.log.Audit(r.Context(), "the first administrator was claimed",
		"action", "auth.setup", "actor_id", principal.UserID, "result", "ok")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// setupFailed re-renders the setup form with a field-level problem.
func (s *Server) setupFailed(w http.ResponseWriter, r *http.Request, view SetupView, problem, field string) {
	view.Shell = s.shell(r, "Set up")
	view.Problem, view.Field = problem, field
	w.Header().Set("Cache-Control", "no-store")
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the setup form", err)
	}
}

// inviteForm is the invite redemption form.
//
// The token is not resolved on the way in. Resolving it here would tell the
// browser whether a token exists before anybody had done anything, and the one
// answer an unauthenticated visitor may get for a bearer credential is "submit
// it". The role is shown after a successful redemption.
func (s *Server) inviteForm(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	view := InviteView{Shell: s.shell(r, "Join the campaign"), Token: token}
	if strings.TrimSpace(token) == "" {
		view.Invalid = true
	}
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the invite form", err)
	}
}

// inviteAccept redeems an invite and signs the new account in.
//
// The token is passed as a field rather than read from the URL, so that a
// bearer credential does not end up in a Referer header if the page ever links
// anywhere. It is hidden in the form, which is where a token belonging to this
// one submission belongs.
func (s *Server) inviteAccept(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		s.inviteFailed(w, r, "", "The form could not be read. Try again.")
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		token = chi.URLParam(r, "token")
	}
	username := r.PostFormValue("username")
	display := strings.TrimSpace(r.PostFormValue("display_name"))
	passphrase := r.PostFormValue("passphrase")

	principal, err := s.auth.AcceptInvite(r.Context(), auth.RedeemRequest{
		Token:       token,
		Username:    username,
		DisplayName: display,
		Passphrase:  passphrase,
	})
	// Checked on the failure path too, and deliberately: the redeemed account
	// exists even when the handler goes on to reject the form for another
	// reason, and a secret fence naming this username is now attributable
	// whether or not this browser ends up signed in.
	s.retryUnresolvedAuthors(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInviteInvalid):
			// One answer for a token that never existed, one that was used, one
			// that expired and one that was not a token at all: trying twice
			// must not be able to tell which.
			s.inviteFailed(w, r, "", "That invite cannot be used. Ask the administrator for a new one.")
		case errors.Is(err, auth.ErrUsernameTaken):
			s.inviteFailed(w, r, "", "That username is already taken. Try another.")
		default:
			var usernameErr *auth.UsernameError
			var passphraseErr *auth.PassphraseError
			if errors.As(err, &usernameErr) {
				s.inviteFailed(w, r, "", usernameErr.Reason)
				return
			}
			if errors.As(err, &passphraseErr) {
				s.inviteFailed(w, r, "", passphraseErr.Reason)
				return
			}
			s.fail(w, r, "redeem the invite", err)
		}
		return
	}

	raw, err := s.auth.Create(r.Context(), auth.LoginRequest{
		Username:   username,
		Passphrase: passphrase,
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		s.fail(w, r, "sign in the new account", err)
		return
	}
	s.setSessionCookie(w, r, raw)
	if _, err := s.auth.SetCSRFToken(raw); err != nil {
		s.log.WarnContext(r.Context(), "an invite was redeemed but no csrf token was minted",
			"action", "auth.invite.accept", "request_id", obs.RequestID(r.Context()),
			"err", logRecord(err).String())
	}
	s.clearPreSessionCookie(w, r)
	s.log.Audit(r.Context(), "an invite was redeemed",
		"action", "auth.invite.accept", "actor_id", principal.UserID,
		"role", string(principal.Role), "result", "ok")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// inviteFailed re-renders the invite form with one problem phrase.
func (s *Server) inviteFailed(w http.ResponseWriter, r *http.Request, token, problem string) {
	view := InviteView{Shell: s.shell(r, "Join the campaign"), Problem: problem, Token: token}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.Render(w, r, view); err != nil {
		s.fail(w, r, "render the invite form", err)
	}
}

// setSessionCookie writes the session cookie.
//
// SameSite is Strict and HttpOnly is on, so a cross-origin form post carries
// neither the session nor anything derived from it. The lifetime matches the
// session's own: a cookie that outlived its server-side row would let a
// browser present a token that answers with nothing, which is exactly the
// confusing failure the server-side row is there to avoid.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	c := cookieOptions(r.TLS != nil)
	c.Name = SessionCookie
	c.Value = raw
	c.Path = "/"
	c.Expires = s.now().Add(sessionCookieTTL)
	http.SetCookie(w, c)
}

// clearSessionCookie expires the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	c := cookieOptions(r.TLS != nil)
	c.Name = SessionCookie
	c.Value = ""
	c.Expires = timeZero
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// clearPreSessionCookie expires the CSRF cookie, which the new session no
// longer needs: a session-bound token is what its forms carry now.
func (s *Server) clearPreSessionCookie(w http.ResponseWriter, r *http.Request) {
	c := cookieOptions(r.TLS != nil)
	c.Name = CSRFCookie
	c.Value = ""
	c.Expires = timeZero
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// safeNext is the path a successful sign-in returns to.
//
// A `next` parameter is attacker-controlled, so it is accepted only when it is
// an absolute path on this origin: a leading slash, no scheme, no host, and no
// second slash where a host would start. Anything else is "/" — the campaign —
// rather than an error, because a stale bookmark is not a reason to refuse a
// login.
func safeNext(next string) string {
	switch {
	case next == "", !strings.HasPrefix(next, "/"), strings.HasPrefix(next, "//"):
		return "/"
	case strings.ContainsAny(next, "\\\n\r\t"):
		return "/"
	default:
		return next
	}
}
