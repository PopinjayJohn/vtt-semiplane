package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// revealedPage is the fixture §8.10 needs: a page whose secret was revealed, so
// the revision taken of it holds plaintext that a player may read TODAY and must
// not be able to read after the revoke.
func revealedPage(fixture string) string {
	return strings.Replace(fixture, "visibility=dm", "visibility=table", 1)
}

// revisionIDs returns a page's revision ids, newest first, as the history panel
// would see them.
func revisionIDs(t *testing.T, h *harness, id int64) []int64 {
	t.Helper()
	metas, err := store.ListRevisionMetaByPage(context.Background(), h.db.Reader(), id, 50)
	if err != nil {
		t.Fatalf("revision metadata: %v", err)
	}
	out := make([]int64, 0, len(metas))
	for _, m := range metas {
		out = append(out, m.ID)
	}
	return out
}

// TestRevisionRevocationIsAuthorised is §8.10's whole point. revisions.content is
// the whole file, so a revision taken while a secret was `table` is a time-frozen
// copy of its plaintext; the decision therefore has to be made against the bytes
// being served, and not against the fence's current state — which says nothing
// about what that copy contains.
func TestRevisionRevocationIsAuthorised(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": revealedPage(pageWithFence)})
	id := pageID(t, h, "Page.md")
	ids := revisionIDs(t, h, id)
	if len(ids) == 0 {
		t.Fatal("the fixture produced no revision to read")
	}
	revID := ids[len(ids)-1]

	// Before the revoke the player may read it, because the bytes say `table`.
	before, err := h.svc.Revision(ctx, h.player(), id, revID)
	if err != nil {
		t.Fatalf("a player could not read a revealed revision: %v", err)
	}
	if !strings.Contains(before.Content, secretBody) {
		t.Fatal("the revision did not hold the body it was taken with")
	}
	if !before.Visible {
		t.Error("a readable revision is not marked visible")
	}

	if revokeErr := h.svc.Revoke(ctx, h.dm(), secretID); revokeErr != nil {
		t.Fatalf("revoke: %v", revokeErr)
	}

	// After the revoke it is gone, and the file has to be consulted to know why.
	after, err := h.svc.Revision(ctx, h.player(), id, revID)
	if err == nil {
		t.Fatalf("a player read a revision taken before the revoke: %+v", after)
	}
	if !errors.Is(err, store.ErrNoRows) {
		t.Fatalf("the error is %v, want store.ErrNoRows", err)
	}
	assertNoFileContent(t, err.Error(), secretBody, secretID)

	// A DM may still read it, so the refusal was about the principal and not about
	// a broken fixture.
	if _, err := h.svc.Revision(ctx, h.dm(), id, revID); err != nil {
		t.Fatalf("a dm could not read the revision: %v", err)
	}
	// And it was refused on a read, so nothing was written about the attempt.
	if n := h.count(`SELECT COUNT(*) FROM secret_events WHERE action = ?`,
		store.SecretActionViewDenied); n != 0 {
		t.Errorf("a refused read wrote %d view_denied rows", n)
	}
}

// TestRevisionAndNonexistentRevisionAreIndistinguishable compares a refusal with
// the same id genuinely gone from the table, so the two answers are the same
// value rather than merely the same shape.
func TestRevisionAndNonexistentRevisionAreIndistinguishable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": revealedPage(pageWithFence)})
	id := pageID(t, h, "Page.md")
	revID := revisionIDs(t, h, id)[0]

	if err := h.svc.Revoke(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, forbidden := h.svc.Revision(ctx, h.player(), id, revID)
	if !errors.Is(forbidden, store.ErrNoRows) {
		t.Fatalf("the error is %v, want store.ErrNoRows", forbidden)
	}

	// Same id, no row. The only thing that changed is the reason, and the reason
	// must not be in the answer.
	if _, err := h.db.Writer().ExecContext(ctx, `DELETE FROM revisions WHERE id = ?`, revID); err != nil {
		t.Fatalf("delete the revision row: %v", err)
	}
	_, missing := h.svc.Revision(ctx, h.player(), id, revID)

	if !errors.Is(missing, store.ErrNoRows) {
		t.Fatalf("the missing error is %v, want store.ErrNoRows", missing)
	}
	if forbidden.Error() != missing.Error() {
		t.Fatalf("the two answers differ:\n  forbidden: %q\n  missing:   %q",
			forbidden.Error(), missing.Error())
	}
	if forbidden.Error() != fmt.Sprintf("revision %d: %v", revID, store.ErrNoRows) {
		t.Errorf("the answer is %q, want this package's own not-found spelling", forbidden)
	}

	// A revision belonging to another page is the same answer too, because it is a
	// revision of this page that does not exist.
	h.vault.WriteFile(t, "Other.md", "# Other\n\nNo secrets here.\n")
	h.indexAll()
	other := pageID(t, h, "Other.md")
	otherRev := revisionIDs(t, h, other)[0]
	if _, err := h.svc.Revision(ctx, h.player(), id, otherRev); !errors.Is(err, store.ErrNoRows) {
		t.Fatalf("a revision of another page returned %v, want ErrNoRows", err)
	}
}

// TestRevertIsAuthorisedAsAnEdit is §8.10's "revert is authz'd as an edit, not as
// a read", and the smuggle it exists to stop: a revert that was authorized as a
// read would hand an old secret state back to a principal who lost the right to
// see it.
func TestRevertIsAuthorisedAsAnEdit(t *testing.T) {
	t.Parallel()
	t.Run("a principal who may read a revision but not write the page cannot revert it", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": revealedPage(pageWithFence)})
		id := pageID(t, h, "Page.md")
		revID := revisionIDs(t, h, id)[0]

		// The read is fine. A revealed secret is readable by every authenticated
		// user, so the failure below cannot be a read failure.
		if _, err := h.svc.Revision(ctx, h.player(), id, revID); err != nil {
			t.Fatalf("the player could not read the revision: %v", err)
		}

		before := h.vault.ReadFile(t, "Page.md")
		err := h.svc.Revise(ctx, h.player(), id, revID)
		if !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("the error is %v, want authz.ErrDenied", err)
		}
		if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
			t.Fatal("a refused revert changed the file")
		}
		if h.reindexes.Load() != 0 {
			t.Error("a refused revert re-indexed")
		}

		// The same principal, with the write permission, may.
		giveOwnership(t, h, id, h.player().UserID)
		if err := h.svc.Revise(ctx, h.player(), id, revID); err != nil {
			t.Fatalf("the page owner could not revert: %v", err)
		}
		if !bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte(secretBody)) {
			t.Error("the revert did not restore the file")
		}
	})

	t.Run("a revert cannot carry an old secret state past a change in the fence", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": revealedPage(pageWithFence)})
		id := pageID(t, h, "Page.md")
		giveOwnership(t, h, id, h.player().UserID)
		revID := revisionIDs(t, h, id)[0]

		// The player may read the revision while the secret is `table`...
		if _, err := h.svc.Revision(ctx, h.player(), id, revID); err != nil {
			t.Fatalf("the player could not read the revealed revision: %v", err)
		}
		// ...and owns the page, so every write permission she has is in place.

		// The secret becomes `dm`. That is the one visibility a page owner can
		// never read, and it is the case a revert-as-a-read would walk straight
		// into: the revision still says `table` and still holds the plaintext.
		if err := h.svc.SetVisibility(ctx, h.dm(), secretID, authz.VisibilityDM); err != nil {
			t.Fatalf("set dm: %v", err)
		}
		before := h.vault.ReadFile(t, "Page.md")

		err := h.svc.Revise(ctx, h.player(), id, revID)
		if !errors.Is(err, store.ErrNoRows) {
			t.Fatalf("the error is %v, want store.ErrNoRows", err)
		}
		if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
			t.Fatal("a refused revert changed the file")
		}

		// And the refusal is not about the fence being unreadable to a DM: a DM
		// reverts it, which is the whole point of the exception.
		if err := h.svc.Revise(ctx, h.dm(), id, revID); err != nil {
			t.Fatalf("a dm could not revert: %v", err)
		}
		if !bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte("visibility=table")) {
			t.Error("the revert did not restore the revealed token")
		}
	})

	t.Run("a revision holding a dm secret cannot be reverted by a player at all", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": pageWithFence})
		id := pageID(t, h, "Page.md")
		giveOwnership(t, h, id, h.player().UserID)
		revID := revisionIDs(t, h, id)[0]

		before := h.vault.ReadFile(t, "Page.md")
		err := h.svc.Revise(ctx, h.player(), id, revID)
		if !errors.Is(err, store.ErrNoRows) {
			t.Fatalf("the error is %v, want store.ErrNoRows", err)
		}
		if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
			t.Fatal("a refused revert changed the file")
		}
	})
}

// TestHistoryDoesNotCarryContent asserts the property the history panel's whole
// safety rests on: its query never reaches revisions.content.
//
// It is checked three ways, because each alone is satisfiable by accident. The
// rows are inspected for empty content; the whole result is rendered and searched
// for the fixture's plaintext; and the revision is then read with the
// with-content getter to prove the row really did hold a body — a History that
// returned nothing at all would pass the first two.
func TestHistoryDoesNotCarryContent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	id := pageID(t, h, "Page.md")

	total, err := store.CountRevisionsByPage(ctx, h.db.Reader(), id)
	if err != nil {
		t.Fatalf("count revisions: %v", err)
	}
	if total == 0 {
		t.Fatal("the fixture produced no revision")
	}

	for _, who := range []struct {
		name    string
		p       authz.Principal
		visible bool
	}{
		{"a player", h.player(), false},
		{"a dm", h.dm(), true},
	} {
		rows, historyErr := h.svc.History(ctx, who.p, id)
		if historyErr != nil {
			t.Fatalf("%s: history: %v", who.name, historyErr)
		}
		if len(rows) != total {
			t.Errorf("%s: %d rows, want %d", who.name, len(rows), total)
		}
		for i, row := range rows {
			if row.Content != "" {
				t.Errorf("%s: row %d carries %d bytes of content", who.name, i, len(row.Content))
			}
			if len(row.Diff) != 0 {
				t.Errorf("%s: row %d carries a diff, which needs bytes it must not have", who.name, i)
			}
			if row.Visible != who.visible {
				t.Errorf("%s: row %d is visible=%v, want %v", who.name, i, row.Visible, who.visible)
			}
			if row.At.IsZero() || row.Source == "" {
				t.Errorf("%s: row %d is missing its metadata: %+v", who.name, i, row)
			}
		}
		rendered := fmt.Sprint(rows)
		for _, f := range []string{secretBody, "oak", "mayor"} {
			if strings.Contains(rendered, f) {
				t.Fatalf("%s: the history panel rendered %q", who.name, f)
			}
		}
	}

	// The row does hold a body, so the emptiness above is a property of History
	// and not of the fixture.
	rev, err := store.GetRevision(ctx, h.db.Reader(), revisionIDs(t, h, id)[0])
	if err != nil {
		t.Fatalf("get revision: %v", err)
	}
	if !strings.Contains(rev.Content, secretBody) {
		t.Fatal("the stored revision does not hold the body, so the assertions above are vacuous")
	}

	t.Run("the history path never asks for content", func(t *testing.T) {
		t.Parallel()
		src, err := os.ReadFile("revision.go")
		if err != nil {
			t.Fatalf("read revision.go: %v", err)
		}
		body := functionBody(t, string(src), "func (s *Service) History(")
		for _, forbidden := range []string{"GetRevision", "ListRevisionsByPage", "Content:", "Diff:"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("History mentions %q:\n%s", forbidden, body)
			}
		}
	})
}

// TestTheRevisionDiffIsAnEnvelopeOverTwoAuthorisedSides covers what the diff is
// allowed to be and where its numbers come from. HunkSummary carries four
// integers and no text, so it cannot render a body; what it must not do is be
// computed against a side that was never authorised, and the way that shows is a
// hunk that spans lines the reader has no business seeing counted.
func TestTheRevisionDiffIsAnEnvelopeOverTwoAuthorisedSides(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const pub = "# The Page\n\nPublic before the fence.\n"
	const priv = "\n```secret id=" + openSecretID +
		" visibility=private author=pia created=2026-09-28T10:04:11Z\n" +
		"The party owes the ferryman two crowns.\n```\n"
	h := newHarness(t, map[string]string{"Page.md": pub + priv + "\nPublic after the fence.\n"})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)
	revID := revisionIDs(t, h, id)[0]

	// The DM changes the public text and adds a secret the player may never read.
	h.vault.WriteFile(t, "Page.md", pub+priv+"\nA brand new public line.\n"+
		fenceBlock(closedSecretID, "dm", "dorn", secretBody))
	h.indexAll()

	view, err := h.svc.Revision(ctx, h.player(), id, revID)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if len(view.Diff) == 0 {
		t.Fatal("a changed page reported no hunks")
	}
	if strings.Contains(fmt.Sprint(view), secretBody) {
		t.Fatal("the revision view rendered a body the principal may not read")
	}
	lines := strings.Count(view.Content, "\n")
	current := bytes.Count(h.vault.ReadFile(t, "Page.md"), []byte("\n"))
	for _, hunk := range view.Diff {
		if hunk.FromA < 1 || hunk.FromB < 1 {
			t.Errorf("a hunk has a non-positive origin: %+v", hunk)
		}
		if hunk.FromA-1+hunk.CountA > lines {
			t.Errorf("the a-range is outside the revision's %d lines: %+v", lines, hunk)
		}
		if hunk.FromB-1+hunk.CountB > current {
			t.Errorf("the b-range is outside the page's %d lines: %+v", current, hunk)
		}
	}

	// An unchanged page has no hunks at all, which is the answer a panel wants
	// rather than one hunk of "no changes". The newest revision is the current
	// file, and only a DM may read it — the player cannot see the dm secret it now
	// holds, which is the redaction the diff is computed over.
	h.indexAll()
	newest := revisionIDs(t, h, id)[0]
	same, err := h.svc.Revision(ctx, h.dm(), id, newest)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if len(same.Diff) != 0 {
		t.Errorf("an unchanged page reported hunks: %+v", same.Diff)
	}
	if !bytes.Equal([]byte(same.Content), h.vault.ReadFile(t, "Page.md")) {
		t.Error("the newest revision does not match the file it was taken from")
	}
}

// TestRevisionModeStrings keeps EditMode's rendering from drifting from the two
// values it has, since a template prints it into a form field.
func TestEditModeStrings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode     secrets.EditMode
		name     string
		redacted bool
	}{
		{secrets.EditModeFull, "full", false},
		{secrets.EditModeRedacted, "redacted", true},
	} {
		if got := tc.mode.String(); got != tc.name {
			t.Errorf("mode %d is %q, want %q", tc.mode, got, tc.name)
		}
		if got := tc.mode.Redacted(); got != tc.redacted {
			t.Errorf("mode %d Redacted() is %v, want %v", tc.mode, got, tc.redacted)
		}
	}
}

// functionBody returns the source of one top-level function, so a test can assert
// on what it does and does not mention. A source-reading gate is coarse, and that
// is the point: it fails loudly and names the string it objected to, where a
// behavioural assertion would pass on an empty result.
//
// The end of the body is found by line rather than by searching for the byte
// sequence "\n}\n", because the source is a checked-in file read at test time
// and a checkout may rewrite its terminators: git's core.autocrlf is true by
// default on Git for Windows and actions/checkout does not override it, so on a
// Windows runner every Go source file in the tree is CRLF. A byte sequence that
// only occurs in an LF file would report "could not find the end" there — a
// failure with nothing wrong with the function, and no way to tell a real
// regression from a runner setting.
func functionBody(t *testing.T, src, signature string) string {
	t.Helper()
	i := strings.Index(src, signature)
	if i < 0 {
		t.Fatalf("no %q in the source", signature)
	}
	// A top-level function's closing brace is the only one in column zero, so
	// the first line that is exactly "}" ends it.
	rest := src[i+len(signature):]
	for off := 0; off < len(rest); {
		nl := strings.IndexByte(rest[off:], '\n')
		if nl < 0 {
			break
		}
		if strings.TrimSuffix(rest[off:off+nl], "\r") == "}" {
			return src[i : i+len(signature)+off+nl+1]
		}
		off += nl + 1
	}
	t.Fatalf("could not find the end of %q", signature)
	return ""
}

// TestARevisionNamingAnAuthorShowsThemInThePanel covers the metadata half of
// Revision and History: an `app` revision records who wrote it, and a panel that
// cannot show that is a panel that shows a wall of timestamps.
func TestARevisionNamingAnAuthorShowsThemInThePanel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	id := pageID(t, h, "Page.md")
	author := h.dmID
	if _, err := store.AppendRevision(ctx, h.db.Writer(), store.Revision{
		PageID:      id,
		ContentHash: vault.Hash([]byte(pageWithFence)),
		Content:     pageWithFence,
		At:          clockNow,
		Source:      store.RevisionApp,
		AuthorID:    &author,
	}); err != nil {
		t.Fatalf("append a revision: %v", err)
	}

	rows, err := h.svc.History(ctx, h.dm(), id)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	found := false
	for _, row := range rows {
		if row.Author == nil {
			continue
		}
		found = true
		if *row.Author != "dorn" {
			t.Errorf("the author is %q, want dorn", *row.Author)
		}
	}
	if !found {
		t.Fatal("the history panel named nobody")
	}

	revID := revisionIDs(t, h, id)[0]
	view, err := h.svc.Revision(ctx, h.dm(), id, revID)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if view.Author == nil || *view.Author != "dorn" {
		t.Fatalf("the revision view names %v, want dorn", view.Author)
	}
	if view.Source != string(store.RevisionApp) {
		t.Errorf("the source is %q, want app", view.Source)
	}
}

// TestARevisionHoldingASecretTheFileNoLongerHasStillReads is the deleted-fence
// half of the read-time decision. The file cannot say anything about a fence it
// has dropped, so the revision's own directive answers — and the two directions
// are deliberately different, because deletion is not a revocation.
func TestARevisionHoldingASecretTheFileNoLongerHasStillReads(t *testing.T) {
	t.Parallel()
	const stripped = "# The Page\n\nPublic before the fence.\n\nPublic after the fence.\n"
	cases := []struct {
		name     string
		fixture  string
		readable bool
	}{
		// A dm fence is readable by a DM and by nobody else, now and while it
		// existed, so a player cannot reach its body through the revision.
		{"a dm fence deleted from the file", pageWithFence, false},
		// A table fence was readable by every authenticated user while it existed,
		// and removing the fence revokes nothing — the same answer the live page
		// gives. Pinning it stops a later reader "hardening" this into a rule that
		// would refuse a body the principal was always entitled to.
		{"a table fence deleted from the file", revealedPage(pageWithFence), true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			h := newHarness(t, map[string]string{"Page.md": tc.fixture})
			id := pageID(t, h, "Page.md")
			revID := revisionIDs(t, h, id)[0]

			// The fence leaves the file entirely, not merely its visibility.
			h.vault.WriteFile(t, "Page.md", stripped)
			h.indexAll()

			_, err := h.svc.Revision(ctx, h.player(), id, revID)
			if tc.readable && err != nil {
				t.Fatalf("a player could not read a revealed, since-deleted secret: %v", err)
			}
			if !tc.readable && !errors.Is(err, store.ErrNoRows) {
				t.Fatalf("a player read a deleted dm secret's revision: %v", err)
			}
			if _, revisionErr := h.svc.Revision(ctx, h.dm(), id, revID); revisionErr != nil {
				t.Fatalf("a dm could not read the revision: %v", revisionErr)
			}
			// The body is in the revision and nowhere else, which is the whole
			// reason the fence's own directive is the answer here.
			rev, err := store.GetRevision(ctx, h.db.Reader(), revID)
			if err != nil {
				t.Fatalf("get revision: %v", err)
			}
			if !strings.Contains(rev.Content, secretBody) {
				t.Fatal("the revision does not hold the body the decision was made about")
			}
			if bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte(secretBody)) {
				t.Fatal("the body is still in the file")
			}
		})
	}
}
