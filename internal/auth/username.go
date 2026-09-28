package auth

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Username length limits. The upper bound is also what keeps a username inside
// every header, cookie and log line it will eventually appear in.
const (
	// MinUsernameLen is the shortest accepted username.
	MinUsernameLen = 3
	// MaxUsernameLen is the longest accepted username.
	MaxUsernameLen = 32
)

// ErrInvalidUsername is the sentinel every username rejection matches, so a
// caller can render one message without inspecting the reason.
var ErrInvalidUsername = errors.New("username rejected")

// UsernameError is a rejected username and the rule it broke. Like
// PassphraseError it echoes a fixed phrase rather than the value: the value is
// whatever the request carried, and a rejected username is logged, rendered and
// turned into a 400 by three different layers on the way out.
type UsernameError struct {
	// Reason is a short phrase for the UI. It is safe to render.
	Reason string
}

func (e *UsernameError) Error() string { return "auth: username " + e.Reason }

// Unwrap makes errors.Is(err, ErrInvalidUsername) true.
func (e *UsernameError) Unwrap() error { return ErrInvalidUsername }

// reservedUsernames are the role names. A user called "dm" turns every mention
// of the role into an ambiguity in a log line, an audit record and a sentence
// in the UI. There are four of them, so refusing them costs nothing.
//
// It is a constant table rather than a read of the authz role list, because
// authz is below this package and re-deriving a list of role *names* from a set
// of role *constants* would couple two packages to the same vocabulary in a way
// neither of them checks.
var reservedUsernames = map[string]bool{
	"admin":  true,
	"dm":     true,
	"player": true,
	"anon":   true,
}

// ValidateUsername checks the shape of a login name. It says nothing about
// whether the name is taken: uniqueness is the unique index's job, and a
// check-then-insert here would race with a concurrent signup and be wrong
// about half the time.
//
// The character set is ASCII only, and that is not a preference. The unique
// index on users.username is COLLATE NOCASE, and SQLite's NOCASE folds ASCII
// only: a store that accepted 'Ångström' would let 'Ångström' and 'ångström'
// both in, and the second of those is a second account with the same name.
func ValidateUsername(username string) error {
	// The reserved check runs first, not as an afterthought: "dm" is two
	// characters, so a length-first order would reject it for being short and
	// leave the caller — or a user who typed the role name by mistake — with a
	// complaint about the wrong thing.
	if reservedUsernames[strings.ToLower(username)] {
		return &UsernameError{Reason: "is a role name"}
	}
	if n := utf8.RuneCountInString(username); n < MinUsernameLen || n > MaxUsernameLen {
		return &UsernameError{Reason: fmt.Sprintf("must be %d to %d characters", MinUsernameLen, MaxUsernameLen)}
	}
	var mask uint8
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			mask |= classOf(r)
		case r == '-' || r == '.' || r == '_':
			mask |= classPunct
		default:
			return &UsernameError{Reason: "may contain only letters, digits, '-', '.' and '_'"}
		}
	}
	if mask == classPunct {
		return &UsernameError{Reason: "must contain a letter or a digit"}
	}
	return nil
}
