package authz

import (
	"time"
)

// Role is a campaign-scoped role. One vault is one campaign (D3), so there is
// no per-campaign role table: a user with RoleDM is a DM for the whole vault.
type Role string

const (
	// RoleAdmin manages users, invites and the vault. Admins are DMs: they
	// imply every DM permission, including reading `dm` secrets (§8.4).
	RoleAdmin Role = "admin"
	// RoleDM is a dungeon master.
	RoleDM Role = "dm"
	// RolePlayer is an ordinary player.
	RolePlayer Role = "player"
	// RoleAnonymous is an unauthenticated request. It is never stored in the
	// users table; it only ever exists as a Principal.
	RoleAnonymous Role = "anon"
)

// Valid reports whether r is a role that may be persisted.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleDM, RolePlayer:
		return true
	default:
		return false
	}
}

func (r Role) String() string { return string(r) }

// Principal is the immutable identity a request or a long-lived connection is
// evaluated under. It is captured once at request (or connect) time and is
// never re-derived mid-response.
//
// The zero value is an anonymous principal. Use Anonymous or ForUser to build
// one explicitly.
type Principal struct {
	// UserID is the users.id of the authenticated user, or 0 when anonymous.
	UserID int64
	// Username is empty when anonymous.
	Username string
	// Role is RoleAnonymous when the request is unauthenticated.
	Role Role
	// SessionID is the sha256 of the session cookie; empty when anonymous.
	SessionID string
	// AuthzGeneration is the meta['authz_generation'] value observed when this
	// principal was captured. A stream whose generation falls behind is
	// terminated (§4.5).
	AuthzGeneration int64
	// AllowAnonymousRead mirrors the --allow-anonymous-read flag.
	AllowAnonymousRead bool
}

// Anonymous returns an unauthenticated principal. allowAnonymousRead controls
// whether it may read public pages at all.
func Anonymous(allowAnonymousRead bool) Principal {
	return Principal{Role: RoleAnonymous, AllowAnonymousRead: allowAnonymousRead}
}

// ForUser returns an authenticated principal for a stored user.
func ForUser(userID int64, username string, role Role, allowAnonymousRead bool) Principal {
	return Principal{
		UserID:             userID,
		Username:           username,
		Role:               role,
		AllowAnonymousRead: allowAnonymousRead,
	}
}

// Authenticated reports whether the request carried a valid session.
func (p Principal) Authenticated() bool { return p.UserID != 0 }

// IsDM reports whether the principal is a DM or an admin. It is the value
// bound to the :is_dm parameter of SecretVisibleSQL.
func (p Principal) IsDM() bool { return p.Role == RoleDM || p.Role == RoleAdmin }

// IsAdmin reports whether the principal is an admin.
func (p Principal) IsAdmin() bool { return p.Role == RoleAdmin }

// CanReadPublic reports whether the principal may read public page content.
// Anonymous principals may only do so when anonymous read is enabled (§10).
func (p Principal) CanReadPublic() bool { return p.Authenticated() || p.AllowAnonymousRead }

// String is safe to log: it never contains a session token.
func (p Principal) String() string {
	if !p.Authenticated() {
		return "anon"
	}
	return p.Username + "(" + string(p.Role) + ")"
}

// Visibility is the visibility of a secret. It is owned by authz rather than by
// internal/secrets so that SecretVisibleSQL and the Go-level policy check
// cannot drift apart, and so that internal/secrets may depend on authz.
type Visibility string

const (
	// VisibilityPrivate is readable by DMs, admins, its author, and the owners
	// of the page it lives on.
	VisibilityPrivate Visibility = "private"
	// VisibilityDM is readable only by DMs and admins — deliberately NOT by the
	// page owner, which is the mistake the canonical predicate exists to
	// prevent (§6.4).
	VisibilityDM Visibility = "dm"
	// VisibilityTable is readable by every authenticated user.
	VisibilityTable Visibility = "table"
)

// Valid reports whether v is one of the three known visibilities.
func (v Visibility) Valid() bool {
	switch v {
	case VisibilityPrivate, VisibilityDM, VisibilityTable:
		return true
	default:
		return false
	}
}

// Permission is a named capability checked on routes and services. The route
// map in §9 of the plan names one Perm per route, and the Perm middleware is
// the only place a role comparison happens (TestOnlyPermMiddlewareIsConsulted).
type Permission string

const (
	// PermSetupOpen is only satisfiable while no user exists.
	PermSetupOpen Permission = "setupOpen"
	// PermSession requires any authenticated principal.
	PermSession Permission = "session"
	// PermAnonRead requires a principal that may read public content, which
	// includes anonymous when --allow-anonymous-read is set.
	PermAnonRead Permission = "anon-read"

	// PermReadPage requires the ability to read a page's public content.
	PermReadPage Permission = "readPage"
	// PermWritePage requires write access to a specific page.
	PermWritePage Permission = "writePage"
	// PermWriteAny requires the ability to create a page anywhere.
	PermWriteAny Permission = "writeAny"
	// PermDeletePage requires delete access to a specific page.
	PermDeletePage Permission = "deletePage"

	// PermReadSecret requires read access to one specific secret.
	PermReadSecret Permission = "readSecret"
	// PermWriteSecret requires edit access to one specific secret.
	PermWriteSecret Permission = "writeSecret"

	// PermDM is the campaign DM or admin level. Reveal and revoke use it.
	PermDM Permission = "dm"
	// PermAdmin is the admin level. It gates the administration surface, and it
	// is deliberately broader than PermManageUser: an admin may reindex or take
	// a backup without also being able to disable an account.
	PermAdmin Permission = "admin"
	// PermManageUser is changing a role, disabling an account, or granting and
	// revoking invites. Admin only, and subject to the last-admin refusal
	// below, which is the whole reason it is not just PermAdmin at the route.
	PermManageUser Permission = "manageUser"
)

// Resource is the object a permission check applies to. It is a plain struct,
// never an interface, and it is always built by the service that already has
// the row — authz never queries the database itself.
type Resource struct {
	// UserID is the account the action applies to, or 0 when not user-scoped.
	UserID int64
	// PageID is the page the action applies to, or 0 when not page-scoped.
	PageID int64
	// IsPageOwner reports whether the principal owns the page. It is set by the
	// caller from page_owners, never from pages.owner_id alone, because
	// page_owners is the single source of truth for ownership (§6.2).
	IsPageOwner bool
	// AuthorID is the author of the secret the action applies to.
	AuthorID int64
	// Visibility is the visibility of the secret the action applies to.
	Visibility Visibility
	// HasSecret marks a secret-scoped resource, so that a zero Resource is
	// never mistaken for one.
	HasSecret bool
	// LastAdmin marks a user resource that is the last enabled admin. It is set
	// by the caller from a count, because authz holds no database, and it exists
	// because the alternative is a permanent lockout: setup is closed forever
	// once an admin exists, so demoting or disabling the only admin leaves a
	// vault that nobody can administer and no way back.
	LastAdmin bool
	// SetupOpen is true only while no user exists. It is a property of the
	// database rather than of the principal, and it is why /setup returns 404
	// rather than 403 after bootstrap: the route's existence must not be
	// confirmable by an outsider.
	SetupOpen bool
}

// Page builds a page-scoped resource.
func Page(pageID int64, isPageOwner bool) Resource {
	return Resource{PageID: pageID, IsPageOwner: isPageOwner}
}

// SecretOf builds a secret-scoped resource from a page and a secret.
func SecretOf(pageID int64, isPageOwner bool, authorID int64, visibility Visibility) Resource {
	return Resource{
		PageID:      pageID,
		IsPageOwner: isPageOwner,
		AuthorID:    authorID,
		Visibility:  visibility,
		HasSecret:   true,
	}
}

// Event is an auditable action. Audit rows carry one of these plus the actor
// and the target, and never carry content.
type Event struct {
	At     time.Time
	Actor  Principal
	Action string
	Target string
}
