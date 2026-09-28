package auth

import (
	"context"
	"crypto/subtle"
)

// csrfEntry is one session's CSRF token, and the account it belongs to.
type csrfEntry struct {
	// token is the hex token handed to the client.
	token string
	// userID is recorded so a bulk revocation can find the entry without a
	// second query. The map is keyed by session id, which is a hash the client
	// never sees, so there is no other route from an account to its entries.
	userID int64
}

// bindCSRF stores token against a session, minting one when token is empty, and
// returns the token now in force. A non-zero userID replaces the one already
// recorded, so a call that knows the account enriches the entry rather than
// erasing what an earlier call worked out.
func (s *Service) bindCSRF(sessionID string, userID int64, token string) string {
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	existing, had := s.csrf[sessionID]
	if had && userID == 0 {
		userID = existing.userID
	}
	if had && token == "" {
		return existing.token
	}
	if token == "" {
		minted, err := NewCSRFToken()
		if err != nil {
			return ""
		}
		token = minted
	}
	s.csrf[sessionID] = csrfEntry{token: token, userID: userID}
	return token
}

// ensureCSRF guarantees a live session has a token, minting one if the process
// restarted and lost the map. It is what makes a restart cost one re-render
// rather than every open tab: the next authenticated request is the one that
// repopulates the entry, and it is that request's response which carries it.
func (s *Service) ensureCSRF(sessionID string, userID int64) {
	if _, ok := s.lookupCSRF(sessionID); ok {
		return
	}
	s.bindCSRF(sessionID, userID, "")
}

// lookupCSRF returns a session's entry.
func (s *Service) lookupCSRF(sessionID string) (csrfEntry, bool) {
	s.csrfMu.RLock()
	defer s.csrfMu.RUnlock()
	e, ok := s.csrf[sessionID]
	return e, ok
}

// forgetCSRF drops one session's entry.
func (s *Service) forgetCSRF(sessionID string) {
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	delete(s.csrf, sessionID)
}

// forgetCSRFForUser drops every entry belonging to an account.
func (s *Service) forgetCSRFForUser(userID int64) {
	s.csrfMu.Lock()
	defer s.csrfMu.Unlock()
	for id, e := range s.csrf {
		if e.userID == userID {
			delete(s.csrf, id)
		}
	}
}

// SetCSRFToken mints a fresh CSRF token for a session, replacing whatever that
// session had, and returns it. A login calls it, and so does anything that
// wants to be certain the token it is about to render is not one somebody else
// chose.
//
// The token is 256 bits from crypto/rand and shares no input with the session
// token: not its bytes, not a truncation of them, not an XOR against them. A
// derived token would make the two leak into each other — knowledge of one
// would be a foothold on the other — and the whole point of carrying a second
// value is that losing one does not lose the other.
func (s *Service) SetCSRFToken(rawSessionToken string) (string, error) {
	if !wellFormedToken(rawSessionToken) {
		return "", ErrNoSessionToken
	}
	token, err := NewCSRFToken()
	if err != nil {
		return "", err
	}
	if s.bindCSRF(HashToken(rawSessionToken), 0, token) == "" {
		return "", ErrNoSessionToken
	}
	return token, nil
}

// CSRFToken returns the token currently in force for a session, minting one if
// there is none. A render path calls it so every form it emits carries a value
// CheckCSRF will accept.
func (s *Service) CSRFToken(rawSessionToken string) (string, error) {
	if !wellFormedToken(rawSessionToken) {
		return "", ErrNoSessionToken
	}
	// bindCSRF returns empty only when crypto/rand failed, and the error it
	// dropped is not recoverable from here. Reporting the absence is honest;
	// inventing a token would be worse.
	if token := s.bindCSRF(HashToken(rawSessionToken), 0, ""); token != "" {
		return token, nil
	}
	return "", ErrNoSessionToken
}

// CheckCSRF reports whether presented is the token issued to this session.
//
// The comparison is crypto/subtle.ConstantTimeCompare, and the shape check runs
// first because a value of the wrong length is not a candidate at all. A caller
// must have resolved a session before asking: the token means nothing without
// one, and this function deliberately does not go and look for it, so the
// answer depends on two values rather than on the timing of a database round
// trip.
func (s *Service) CheckCSRF(rawSessionToken, presented string) bool {
	if !wellFormedToken(rawSessionToken) || !wellFormedCSRF(presented) {
		return false
	}
	entry, ok := s.lookupCSRF(HashToken(rawSessionToken))
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(entry.token), []byte(presented)) == 1
}

// ForgetCSRFForUser drops every CSRF token belonging to an account.
//
// It is exported for the caller that changes a role or disables an account
// through the store directly rather than through SetRole and Disable — a bulk
// import, a restore — and which would otherwise leave those sessions with
// tokens that still verify.
//
// The context is accepted so that it reads like the other administrative calls
// and so a future implementation that has something to log has somewhere to
// put a request id; it is deliberately not stored.
func (s *Service) ForgetCSRFForUser(_ context.Context, userID int64) {
	s.forgetCSRFForUser(userID)
}
