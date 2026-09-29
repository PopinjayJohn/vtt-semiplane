package authz

import "strings"

// PermissionForRole is the permission a declared role name asks for.
//
// The plugin vocabulary spells a requirement as a role — plugin.NavItem.MinimumRole
// is a string, because a plugin is first-party Go code held to a short import
// allow-list — and the policy speaks in permissions. This is the only translation
// between the two, and it is here rather than beside a caller because a second
// copy of it is a second answer to "what does `dm` mean here", and the two copies
// would not have to agree. It is also why it is not a comparison of a principal's
// role: nothing here is handed a principal.
//
// An unrecognised name is nobody's requirement rather than everybody's. A nav
// entry that vanished for a DM and stayed for an admin is a policy with a hole in
// it, so a typo in a plugin's string costs its own screen rather than producing a
// difference between two readers.
func PermissionForRole(name string) (Permission, bool) {
	switch Role(strings.TrimSpace(name)) {
	case "", RolePlayer:
		return PermReadPage, true
	case RoleDM:
		return PermDM, true
	case RoleAdmin:
		return PermAdmin, true
	default:
		return "", false
	}
}
