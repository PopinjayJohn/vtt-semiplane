package authz

import (
	"errors"
	"fmt"
)

// ErrDenied is returned when a principal may not perform a permission. It
// carries the permission and the principal — never the resource, because a
// resource can carry a page title and a secret id.
var ErrDenied = errors.New("permission denied")

// ErrNotAuthenticated is returned to a principal with no session when one is
// required. The handler turns it into a redirect to /login; anything else
// turns it into 403.
var ErrNotAuthenticated = errors.New("authentication required")

// ErrSetupClosed is returned by PermSetupOpen once the first admin has been
// claimed. It is deliberately distinct from ErrDenied: after bootstrap, /setup
// is *absent* (404), not forbidden, so that its existence is not confirmable.
var ErrSetupClosed = errors.New("setup is already complete")

// DeniedError is the concrete type behind ErrDenied.
type DeniedError struct {
	Perm   Permission
	Who    Principal
	Reason string
}

func (e *DeniedError) Error() string {
	if e.Reason == "" {
		return "permission " + string(e.Perm) + " denied for " + e.Who.String()
	}
	return "permission " + string(e.Perm) + " denied for " + e.Who.String() + ": " + e.Reason
}

func (e *DeniedError) Unwrap() error { return ErrDenied }

// Policy is the single implementation of "may this principal do this thing to
// this resource". Every handler consults it; the Perm middleware is the only
// place it is called with a route-level permission, and no handler compares a
// Role directly (TestOnlyPermMiddlewareIsConsulted greps for exactly that).
//
// The zero Policy denies anonymous reads. Construct it with NewPolicy.
type Policy struct {
	// AllowAnonymousRead mirrors --allow-anonymous-read. When false, every
	// anonymous request is denied every content-reading permission, and an
	// unauthenticated visitor can reach /login, /setup and /invite only.
	AllowAnonymousRead bool
}

// NewPolicy returns the policy for a boot. It takes one bool because that is
// the only thing that varies at runtime; everything else is in the table below.
func NewPolicy(allowAnonymousRead bool) Policy {
	return Policy{AllowAnonymousRead: allowAnonymousRead}
}

// Allows reports whether the principal may perform the permission. It is
// Allows with the error discarded, for the places that genuinely only need a
// boolean (a nav item that should be hidden, a panel that should be dropped).
func (p Policy) Allows(who Principal, perm Permission, res Resource) bool {
	return p.Check(who, perm, res) == nil
}

// Check is the policy. It returns nil when the action is permitted, and a
// *DeniedError (wrapping ErrDenied, or ErrNotAuthenticated) when it is not.
//
// The table below is §10 of the plan, and TestAuthorizationMatrix is
// table-driven over exactly these cells.
func (p Policy) Check(who Principal, perm Permission, res Resource) error {
	// A principal always carries the boot's anonymous-read setting, so a
	// request that crossed a process boundary cannot smuggle a permissive
	// flag. The policy's own setting is the authority.
	who.AllowAnonymousRead = p.AllowAnonymousRead

	deny := func(reason string) error {
		return &DeniedError{Perm: perm, Who: who, Reason: reason}
	}

	switch perm {
	case PermSetupOpen:
		// After the first admin is claimed, /setup is a 404 rather than a 403,
		// so that its existence is not confirmable by an outsider.
		if !res.SetupOpen {
			return ErrSetupClosed
		}
		return nil

	case PermSession:
		if !who.Authenticated() {
			return ErrNotAuthenticated
		}
		return nil

	case PermAnonRead, PermReadPage:
		if !who.CanReadPublic() {
			return deny("anonymous read is disabled")
		}
		return nil

	case PermWriteAny:
		// Any authenticated principal may create a page; an anonymous one may
		// not, even when anonymous read is on. Reading the campaign and
		// contributing to it are different permissions.
		if !who.Authenticated() {
			return deny("anonymous principals never create content")
		}
		return nil

	case PermWritePage:
		if !who.CanReadPublic() {
			return deny("anonymous read is disabled")
		}
		if !who.Authenticated() {
			return deny("anonymous principals never write")
		}
		if who.IsDM() {
			return nil
		}
		if res.IsPageOwner {
			return nil
		}
		return deny("a player may only write pages they own")

	case PermDeletePage:
		if !who.Authenticated() {
			return deny("anonymous principals never delete")
		}
		if who.IsDM() {
			return nil
		}
		if res.IsPageOwner {
			return nil
		}
		return deny("a player may only delete pages they own")

	case PermReadSecret:
		if !who.Authenticated() {
			return deny("a secret is never readable by an anonymous principal")
		}
		if CanReadSecret(who, res.IsPageOwner, res.AuthorID, res.Visibility) {
			return nil
		}
		return deny("the secret is not visible to this principal")

	case PermWriteSecret:
		if !who.Authenticated() {
			return deny("anonymous principals never write a secret")
		}
		// A dm secret is the DM's alone, even for the page owner and even for
		// its own author. Spelling this out rather than relying on the author
		// check is the point: the negative case is the one that gets forgotten.
		if res.Visibility == VisibilityDM && !who.IsDM() {
			return deny("a dm secret is writable only by a dm")
		}
		if who.IsDM() {
			return nil
		}
		if res.AuthorID != 0 && res.AuthorID == who.UserID {
			return nil
		}
		return deny("a player may only write secrets they authored")

	case PermDM:
		if !who.IsDM() {
			return deny("dm or admin required")
		}
		return nil

	case PermManageUser:
		if !who.IsAdmin() {
			return deny("admin required")
		}
		// Refusing here rather than in the handler: the handler is a route, and
		// a rule that lives in a route is a rule the next route forgets.
		if res.LastAdmin {
			return deny("the last admin cannot be demoted or disabled: setup is closed once an admin exists, so this would leave the vault unadministrable")
		}
		return nil

	case PermAdmin:
		if !who.IsAdmin() {
			return deny("admin required")
		}
		return nil

	default:
		// An unknown permission is refused rather than defaulted to allow. A
		// typo in a route table must fail closed.
		return fmt.Errorf("unknown permission %q", perm)
	}
}

// Require is Check for a route-level gate with no resource behind it: the
// route table's Perm column is a permission and a handler is not involved.
func (p Policy) Require(who Principal, perm Permission) error {
	return p.Check(who, perm, Resource{})
}

// String renders the policy for the boot report, without naming a principal.
func (p Policy) String() string {
	if p.AllowAnonymousRead {
		return "authz(anonymous-read=on)"
	}
	return "authz(anonymous-read=off)"
}
