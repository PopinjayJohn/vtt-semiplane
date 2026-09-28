package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrNoSessionToken reports a value that is not shaped like a session token.
//
// It is distinct from ErrBadCredentials on purpose: the CSRF helpers are called
// from a render path that already knows who the reader is, and a form that
// failed to render because a cookie was malformed should not report itself as a
// failed login.
var ErrNoSessionToken = errors.New("not a session token")

// TokenBytes is the entropy of a session token and of an invite token: 256
// bits, which is the same width as the largest key anything here negotiates
// and is not negotiable downwards.
const TokenBytes = 32

// CSRFTokenBytes is the entropy of a CSRF token. It is a separate constant
// because it is a separate value with a separate lifetime, and the rule that it
// must never be a function of a session token is easier to keep when the two
// are minted by two different functions.
const CSRFTokenBytes = 32

// tokenEncodedLen is the length of a padding-free base64url token.
const tokenEncodedLen = 43

// csrfEncodedLen is the length of a hex CSRF token.
const csrfEncodedLen = 2 * CSRFTokenBytes

// NewToken mints a session or invite token from crypto/rand and returns it in
// unpadded base64url. The raw value is returned exactly once, to the caller
// that puts it in a cookie or a URL; only its sha256 is ever stored.
func NewToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: read token randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewCSRFToken mints a CSRF token from crypto/rand.
//
// It is hex rather than base64url, unlike every other token here, and the
// difference is the point. A CSRF token that was formatted exactly like a
// session token would let a mistake — a cookie written under the wrong name, a
// log line that reached for the wrong field, a handler that read one and meant
// the other — pass every review and every test, because the wrong value would
// have looked right. Hex makes that whole class of bug visible at a glance in
// a cookie jar and in a captured log.
func NewCSRFToken() (string, error) {
	b := make([]byte, CSRFTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: read csrf randomness: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the hex sha256 of a raw token. It is the only form of a
// session or invite token that reaches the database: a leaked database hands
// out a list of hashes, and a hash of 256 bits of entropy is not a credential.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// wellFormedToken reports whether raw has the shape of a token this package
// mints. It is a cheap filter and not a security check: a token of the wrong
// shape cannot be in the table, and rejecting it before the database saves a
// round trip on every stray cookie.
func wellFormedToken(raw string) bool {
	if len(raw) != tokenEncodedLen {
		return false
	}
	for i := range len(raw) {
		c := raw[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// wellFormedCSRF reports whether a presented CSRF token has the shape of one
// this package mints.
func wellFormedCSRF(token string) bool {
	if len(token) != csrfEncodedLen {
		return false
	}
	for i := range len(token) {
		c := token[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
