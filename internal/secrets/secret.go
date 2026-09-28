package secrets

import (
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Visibility is an alias of the canonical visibility type, which lives in
// authz so that the SQL predicate and the Go policy check cannot drift.
type Visibility = authz.Visibility

const (
	// VisibilityPrivate is readable by DMs, admins, its author, and the owners
	// of the page it lives on.
	VisibilityPrivate = authz.VisibilityPrivate
	// VisibilityDM is readable only by DMs and admins, never by a page owner.
	VisibilityDM = authz.VisibilityDM
	// VisibilityTable is readable by every authenticated user.
	VisibilityTable = authz.VisibilityTable
)

// Secret is one ```secret fence, parsed.
//
// Body is plaintext and is the only field that must never reach a principal
// who failed authz.CanReadSecret. Every API that fills it does so only after
// that check.
type Secret struct {
	// ID is 12 lowercase hex characters, stable across edits and reveals.
	ID string
	// PageID is the page the secret lives on.
	PageID int64
	// Ordinal is the position of the fence in the file, from 0.
	Ordinal int
	// Visibility is who may read the body. Never empty; defaults to private.
	Visibility Visibility
	// AuthorID is the user who created the secret, and the implied owner of a
	// private secret.
	AuthorID int64
	// Author is the author's username, as written in the fence directive.
	Author string
	// Title is the optional label from the fence directive.
	Title string
	// Body is the plaintext between the fence lines, without the fences.
	Body string
	// BodyHash is the sha256 of Body, for the tripwire and for change
	// detection. It is not a substitute for authorization.
	BodyHash []byte
	// CreatedAt is the creation timestamp from the directive, if present.
	CreatedAt time.Time
	// UpdatedAt is when the row was last written.
	UpdatedAt time.Time
	// Directive is the raw fence opening line, without the leading backticks.
	// It is stored so that a reveal or revoke rewrites only the visibility
	// token and leaves every other byte of the line alone (§8.3).
	Directive string
	// StartByte and EndByte locate the whole fence, opening line through
	// closing line, as absolute offsets into the file.
	StartByte int
	EndByte   int
	// BodyStartByte and BodyEndByte locate the body alone.
	BodyStartByte int
	BodyEndByte   int
}

// CanRead reports whether p may read this secret's body. It delegates to the
// single policy implementation in authz and is the ONLY way a Secret's Body
// should be exposed to a caller.
func (s Secret) CanRead(p authz.Principal, isPageOwner bool) bool {
	return authz.CanReadSecret(p, isPageOwner, s.AuthorID, s.Visibility)
}

// IsOpen reports whether the secret is currently visible to every
// authenticated user.
func (s Secret) IsOpen() bool { return s.Visibility == VisibilityTable }

// Redacted returns a copy with the body removed, suitable for a ViewModel that
// is rendered to a principal who failed CanRead. The body string is dropped,
// not replaced with a placeholder of the same length, so that response size
// cannot be used to infer a hidden secret's length (§8.8). The identity,
// visibility, byte offsets and hash-free metadata survive, so a redacted view
// can still be authorised, displayed and audited.
func (s Secret) Redacted() Secret {
	out := s
	out.Body = ""
	out.BodyHash = nil
	return out
}

// LockPlaceholder returns the label shown in place of a secret body the reader
// may not see. It carries the secret id and a generic word and nothing else —
// never the length, the author, the title, or any excerpt.
func LockPlaceholder(id string) string { return "⟨secret:" + id + " hidden⟩" }
