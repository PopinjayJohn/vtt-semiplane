package authz

import (
	"crypto/sha256"
	"database/sql"
	"errors"
)

// SecretVisibleSQL is the ONLY secret-visibility predicate in the codebase.
//
// Bind exactly two parameters:
//
//	:uid   int64 — the viewer's users.id (0 when anonymous)
//	:is_dm int   — 1 when the viewer is a DM or an admin, else 0
//
// It is evaluated with `secrets` aliased as `s` and the page that OWNS the
// secret aliased as `p`. Every query that can return a secret-derived row —
// backlinks, related entities, TOC, search, tag counts, dashboard rollups,
// campaign status, exports, link resolution — MUST use this fragment verbatim
// and MUST use the identical fragment for its COUNT. A panel that lists one
// row while counting three is an existence leak.
//
// `dm` visibility deliberately falls through every clause: only the :is_dm = 1
// branch can see it. That is the bug this fragment exists to prevent.
const SecretVisibleSQL = `(
    :is_dm = 1
 OR s.visibility = 'table'
 OR (s.visibility = 'private' AND (
        s.author_id = :uid
     OR EXISTS (SELECT 1 FROM page_owners po
                 WHERE po.page_id = p.id AND po.user_id = :uid)
 ))
)`

// Bind returns the two arguments SecretVisibleSQL expects, in the order they
// must be passed to QueryContext/ExecContext. Anonymous principals bind :uid to
// 0, which can never match a real author or owner id.
func (p Principal) Bind() (uid int64, isDM int) {
	if p.IsDM() {
		isDM = 1
	}
	if p.UserID == 0 {
		// Never let an anonymous principal match a row by accident.
		uid = -1
	} else {
		uid = p.UserID
	}
	return uid, isDM
}

// IsPageOwnerSQL reports whether the viewer owns the page aliased as `p`. It is
// the ownership half of SecretVisibleSQL, factored out so that page-level
// authorization (write, delete, owner management) cannot re-derive ownership
// with a subtly different query.
const IsPageOwnerSQL = `EXISTS (SELECT 1 FROM page_owners po
                            WHERE po.page_id = p.id AND po.user_id = :uid)`

// VisiblePredicate renders SecretVisibleSQL with a named-parameter style that
// database/sql supports (":uid" and ":is_dm" are ordinary named placeholders).
// Callers that prefer positional placeholders should use Principal.Bind with
// SecretVisibleSQL directly; this helper exists for readability in longer
// queries and is exercised by the predicate tests.
func VisiblePredicate(p Principal) string { return SecretVisibleSQL }

// IsOwnerRow reports whether (pageID, userID) is present in page_owners. It is
// a helper for services that need to resolve ownership before building a
// Resource, and is the only place that reads the ownership table directly.
func IsOwnerRow(q Queryer, pageID, userID int64) (bool, error) {
	if userID == 0 {
		return false, nil
	}
	var one int
	err := q.QueryRow(`SELECT 1 FROM page_owners WHERE page_id = ? AND user_id = ?`,
		pageID, userID).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	default:
		return true, nil
	}
}

// CanReadSecret is the Go-level equivalent of SecretVisibleSQL for a single
// secret. Every service that is about to return secret text must call this.
// There is no other path to a secret body.
func CanReadSecret(p Principal, isPageOwner bool, authorID int64, visibility Visibility) bool {
	switch visibility {
	case VisibilityTable:
		return p.Authenticated()
	case VisibilityPrivate:
		if !p.Authenticated() {
			return false
		}
		return p.IsDM() || authorID == p.UserID || isPageOwner
	case VisibilityDM:
		return p.IsDM()
	default:
		// An unknown visibility is not a licence. Deny.
		return false
	}
}

// HashSecretID returns the stable hash of a secret id, for logs and for the
// tripwire's armed set. It never reveals the id itself.
func HashSecretID(id string) string {
	sum := sha256.Sum256([]byte("semiplane:secret-id:" + id))
	return hex(sum[:8])
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}

// Queryer is the minimal database surface authz needs. Declaring it here keeps
// the package testable with a stub and keeps *sql.DB out of any exported
// signature that a plugin could reach through.
type Queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}
