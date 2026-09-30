package secrets

import (
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

func secret(vis Visibility, author int64) Secret {
	return Secret{
		ID:         "7f3a91c40d2e",
		PageID:     42,
		Ordinal:    0,
		Visibility: vis,
		AuthorID:   author,
		Author:     "johan",
		Title:      "the warded door",
		Body:       "The vault door is warded. Opening it deals 3d6 necrotic damage.",
		BodyHash:   []byte{1, 2, 3, 4},
		CreatedAt:  time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC),
	}
}

func TestCanReadDelegatesToTheOnePolicy(t *testing.T) {
	t.Parallel()

	// Secret.CanRead must be a thin call into authz.CanReadSecret, not a second
	// implementation. If these two ever disagree, one of them is a leak.
	const author = int64(7)
	cases := []struct {
		name  string
		vis   Visibility
		who   authz.Principal
		owner bool
		want  bool
	}{
		{"dm reads anything", VisibilityDM, authz.ForUser(1, "dm", authz.RoleDM, false), false, true},
		{"owner reads own private", VisibilityPrivate, authz.ForUser(author, "j", authz.RolePlayer, false), false, true},
		{"page owner reads a private", VisibilityPrivate, authz.ForUser(9, "p", authz.RolePlayer, false), true, true},
		{"player cannot read a private", VisibilityPrivate, authz.ForUser(3, "p", authz.RolePlayer, false), false, false},
		{"page owner cannot read a dm", VisibilityDM, authz.ForUser(9, "p", authz.RolePlayer, false), true, false},
		{"anonymous never reads", VisibilityTable, authz.Anonymous(true), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := secret(tc.vis, author)
			if got := s.CanRead(tc.who, tc.owner); got != tc.want {
				t.Errorf("CanRead = %v, want %v", got, tc.want)
			}
			if got := authz.CanReadSecret(tc.who, tc.owner, author, tc.vis); got != tc.want {
				t.Errorf("authz.CanReadSecret = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRedactedDropsTheBodyRatherThanBlankingIt is the length-oracle defence: a
// placeholder of the same length would let a response size reveal how much text
// a hidden secret holds.
func TestRedactedDropsTheBodyRatherThanBlankingIt(t *testing.T) {
	t.Parallel()

	s := secret(VisibilityDM, 7)
	before := len(s.Body)
	r := s.Redacted()

	if r.Body != "" {
		t.Errorf("a redacted secret still carries %d bytes of body", len(r.Body))
	}
	if r.BodyHash != nil {
		t.Error("a redacted secret still carries its body hash")
	}
	// The identity survives, so a redacted view can still be authorised,
	// displayed and audited.
	if r.ID != s.ID || r.PageID != s.PageID || r.Visibility != s.Visibility {
		t.Errorf("redaction dropped identity: %+v", r)
	}
	if before == 0 {
		t.Fatal("the fixture has no body, so this test proves nothing")
	}
}

func TestRedactedLeavesTheOriginalAlone(t *testing.T) {
	t.Parallel()
	s := secret(VisibilityPrivate, 7)
	_ = s.Redacted()
	if s.Body == "" || s.BodyHash == nil {
		t.Fatal("Redacted mutated the receiver's secret")
	}
}

func TestLockPlaceholderCarriesOnlyTheID(t *testing.T) {
	t.Parallel()

	got := LockPlaceholder("7f3a91c40d2e")
	if !strings.Contains(got, "7f3a91c40d2e") {
		t.Errorf("the placeholder should carry the id: %q", got)
	}
	if !strings.Contains(got, "hidden") {
		t.Errorf("the placeholder should say hidden: %q", got)
	}
	// No length, no author, no title, no excerpt: the same information a
	// rendered page lock marker may show and nothing more.
	for _, forbidden := range []string{
		"johan", "warded", "3d6", "necrotic", "53", "private",
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the placeholder leaks %q: %q", forbidden, got)
		}
	}
}

func TestIsOpen(t *testing.T) {
	t.Parallel()
	if !secret(VisibilityTable, 7).IsOpen() {
		t.Error("a table secret is not open")
	}
	if secret(VisibilityPrivate, 7).IsOpen() || secret(VisibilityDM, 7).IsOpen() {
		t.Error("a non-table secret reports itself open")
	}
}

func TestVisibilityAliasesTheCanonicalType(t *testing.T) {
	t.Parallel()
	// The alias is the mechanism that keeps the SQL predicate and the Go policy
	// naming the same three values. A distinct type would break both.
	//
	// Declared with the named type and then assigned, rather than `var v =` or
	// `Visibility(...)`: Visibility is an alias, so a conversion is a no-op that
	// unconvert rightly reports, and inferring the type would stop naming it —
	// which is the only thing this test is about. staticcheck wants both forms
	// collapsed, so the two that would collapse it are suppressed rather than
	// applied; the alternative is a test that cannot fail.
	var v Visibility       //nolint:staticcheck // the named type is the subject; see above
	v = authz.VisibilityDM //nolint:staticcheck // ditto
	if v != authz.VisibilityDM {
		t.Fatal("secrets.Visibility is not the authz type")
	}
	if VisibilityPrivate != authz.VisibilityPrivate ||
		VisibilityDM != authz.VisibilityDM ||
		VisibilityTable != authz.VisibilityTable {
		t.Fatal("the visibility constants have drifted from authz")
	}
}
