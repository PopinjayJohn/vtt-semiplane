package authz

import "context"

// The principal on a request context.
//
// This is here, in the package that owns Principal, rather than in httpapi where
// the principal is actually resolved, and the reason is reachability. httpapi's
// own key is an unexported type behind an unexported variable, so a plugin —
// which is forbidden from importing httpapi — could see the value on a context
// and not be able to ask for it: ctx.Value needs a key, and there was no way to
// name that one. That left plugin.PageStore, whose every method takes a
// principal, impossible to call from a plugin, and it is a three-line gap rather
// than a design question.
//
// The alternative fixes — an optional interface a plugin asserts on, or a
// Host.Pages() that captured a principal at boot — are both worse and worth
// naming. The first makes the principal's existence depend on an interface
// assertion succeeding, so a host change silently turns a data read into no data
// at all; the second captures a principal at boot for a request that has not
// been made yet, which is the bug that would hand a DM's view to a player.
//
// A context is the right carrier because a principal is a property of one
// request, it is resolved once, and every layer that handles that request is
// downstream of the same resolution. There is exactly one key and exactly one
// writer, so two layers cannot disagree about who is asking.

// contextKey is a distinct unexported type so that no other package's key can
// collide with this one by accident, and so that the zero value is not a valid
// key.
type contextKey struct{ name string }

// principalKey carries the resolved principal.
var principalKey = contextKey{"authz.principal"}

// WithPrincipal returns a context carrying p as the resolved principal.
//
// The writer is the request path, once per request, in the session middleware.
// Every other package is a reader.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the principal the request was resolved under.
//
// A context that never went through WithPrincipal yields the zero Principal,
// which is anonymous and cannot read public content. That is the safe direction
// for a reader that has been handed a context by accident: a principal that
// reads as anonymous sees public text or nothing, and never a secret.
//
// It is deliberately not authz.Anonymous(true) — that would grant public read to
// a caller who never resolved one, and "a principal that cannot read" and "a
// principal that may read public content" must not be the same zero value.
func PrincipalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey).(Principal)
	return p
}
