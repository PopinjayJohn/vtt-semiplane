// Package auth owns accounts: Argon2id passphrase hashing, sessions,
// single-use expiring invites, the CSRF tokens that hang off a session, and
// the first-run flow that claims the first admin.
//
// It sits above store and below secrets in the dependency order, and it needs
// only config, obs, authz and store. It never decides authorization. A session
// yields an authz.Principal and authz decides what that principal may do; the
// one authorization question this package asks is through authz.Policy.Require,
// never by comparing a Role.
//
// Two rules are load-bearing and are stated here because nothing else in the
// package will say them again:
//
//   - A passphrase, a session token, a raw invite token and a CSRF token are
//     never logged, never rendered and never carried in an error. An error
//     message crosses three layers before it reaches a person and one of them
//     writes it to disk, so the rule is applied at construction: there is
//     nothing in a message to redact.
//   - A failure that is an authorization decision is not an error. Unknown
//     account, wrong passphrase, disabled account, expired session, unknown
//     session and already-redeemed invite each resolve to one indistinguishable
//     answer, because a login form is a place accounts get enumerated.
package auth
