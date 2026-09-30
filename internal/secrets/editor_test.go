package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The second secret of the fixture pair, so a test can tell two fences apart and
// so a page holds more than one.
const (
	openSecretID   = "111111111111"
	closedSecretID = "abcdef012345"
)

// bodyWithSentinel is a secret whose body is literally sentinel-shaped prose. It
// is the case a regex-based sentinel detector gets wrong: the text is not a
// restore token, it is a secret that happens to look like one.
const bodyWithSentinel = "The password is ‹s:abcdef012345:3:deadbeef› and nobody may know."

// pageWithTwoSecrets is a page a player may edit (she owns it) and may not fully
// read (one fence is dm), which is the state every §8.9 round trip needs.
const pageWithTwoSecrets = "# The Page\n\nPublic before the fences.\n\n" +
	"```secret id=" + closedSecretID + " visibility=dm author=dorn created=2026-09-28T10:04:11Z title=\"The Mayor's Door\"\n" +
	secretBody + "\n```\n\n" +
	"Public between the fences.\n\n" +
	"```secret id=" + openSecretID + " visibility=private author=pia created=2026-09-28T10:04:11Z title=\"A Player Note\"\n" +
	"The party owes the ferryman two crowns.\n```\n\n" +
	"Public after the fences.\n"

// pageWithSentinelBody is pageWithTwoSecrets with a dm body that is literally
// sentinel-shaped prose. It is the fixture that a regex-based restore would get
// wrong in both directions: it would either refuse the page forever or restore
// the wrong bytes into the wrong fence.
const pageWithSentinelBody = "# The Page\n\nPublic before the fences.\n\n" +
	"```secret id=" + closedSecretID + " visibility=dm author=dorn created=2026-09-28T10:04:11Z title=\"The Mayor's Door\"\n" +
	bodyWithSentinel + "\n```\n\n" +
	"Public after the fences.\n"

// fenceBlock renders one on-disk secret fence, terminator included.
func fenceBlock(id, visibility, author, body string) string {
	return "```secret id=" + id + " visibility=" + visibility +
		" author=" + author + " created=2026-09-28T10:04:11Z\n" + body + "\n```\n"
}

// pageID looks a page up by path, so a test never hard-codes an id.
func pageID(t *testing.T, h *harness, path string) int64 {
	t.Helper()
	return h.count(`SELECT id FROM pages WHERE path = ?`, path)
}

// giveOwnership makes userID a page owner. page_owners is the single source of
// truth for ownership (§6.2), so a test that wants a player to be able to write a
// page has to say so here rather than in the frontmatter.
func giveOwnership(t *testing.T, h *harness, id, userID int64) {
	t.Helper()
	if err := store.AddPageOwner(context.Background(), h.db.Writer(), store.PageOwner{
		PageID: id, UserID: userID, IsOwner: true, AddedAt: clockNow,
	}); err != nil {
		t.Fatalf("add owner %d of page %d: %v", userID, id, err)
	}
}

// TestEditorRedactedRoundTrip is §8.9's six cases. Each is a named subtest
// because each is a different failure this path has to have, not a variation on
// one: the no-op proves byte fidelity, the edit proves the public text survives,
// the modified sentinel proves a refusal leaves the file alone, the deleted block
// proves deletion is separately authorised, the sentinel-shaped body proves the
// restore is positional rather than textual, and CRLF proves line terminators are
// not normalised by a browser or by this package.
func TestEditorRedactedRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// files is the vault the subtest starts from.
		files map[string]string
		// as names the principal the edit happens under.
		as func(h *harness) authz.Principal
		// hiddenBody is the body of the dm secret, and is what must never reach a
		// redacted buffer and must always survive a write. Empty means the shared
		// fixture's.
		hiddenBody string
		// submit maps the editor buffer to the buffer to save.
		submit func(buf []byte) []byte
		// wantContent is a substring the saved file must hold.
		wantContent string
		// wantUnchanged asserts the save wrote nothing at all.
		wantUnchanged bool
		// wantRefused asserts the save was refused.
		wantRefused bool
	}{
		{
			name:  "a no-op save in redacted mode is byte-identical",
			files: map[string]string{"Page.md": pageWithTwoSecrets},
			as:    (*harness).player,
			submit: func(buf []byte) []byte {
				return buf
			},
			wantUnchanged: true,
		},
		{
			name:  "an edit above a hidden secret is kept and the body is restored",
			files: map[string]string{"Page.md": pageWithTwoSecrets},
			as:    (*harness).player,
			submit: func(buf []byte) []byte {
				return bytes.Replace(buf, []byte("Public before the fences."),
					[]byte("Public before the fences, with an edit."), 1)
			},
			wantContent: "Public before the fences, with an edit.",
		},
		{
			name:  "a modified sentinel is refused and the file is untouched",
			files: map[string]string{"Page.md": pageWithTwoSecrets},
			as:    (*harness).player,
			submit: func(buf []byte) []byte {
				// The fence as the file has it, with a sentinel that no longer
				// matches the body: the whole of what a player can type there.
				return replaceSentinel(buf, closedSecretID, secretBody+"\n",
					"‹s:"+closedSecretID+":0:00000000›\n")
			},
			wantRefused:   true,
			wantUnchanged: true,
		},
		{
			name:       "a body containing literal sentinel-shaped text is handled",
			files:      map[string]string{"Page.md": pageWithSentinelBody},
			as:         (*harness).player,
			hiddenBody: bodyWithSentinel,
			submit: func(buf []byte) []byte {
				// The edit is in the public text above the fence. The restore is
				// positional, so the sentinel-shaped prose inside the hidden body is
				// never looked at — which is the whole difference between matching
				// against the fence list and scanning the buffer for ‹s:.
				return bytes.Replace(buf, []byte("Public before the fences."),
					[]byte("Public before the fences, edited."), 1)
			},
			wantContent: "Public before the fences, edited.",
		},
		{
			name:       "a sentinel-shaped body survives a full-mode save too",
			files:      map[string]string{"Page.md": pageWithSentinelBody},
			as:         (*harness).dm,
			hiddenBody: bodyWithSentinel,
			submit: func(buf []byte) []byte {
				return bytes.Replace(buf, []byte("Public after the fences."),
					[]byte("Public after the fences, edited."), 1)
			},
			wantContent: "Public after the fences, edited.",
		},
		{
			name:  "a no-op save in full mode is byte-identical",
			files: map[string]string{"Page.md": pageWithTwoSecrets},
			as:    (*harness).dm,
			submit: func(buf []byte) []byte {
				return buf
			},
			wantUnchanged: true,
		},
		{
			name:  "CRLF round-trips in redacted mode",
			files: map[string]string{"Page.md": crlf(pageWithTwoSecrets)},
			as:    (*harness).player,
			submit: func(buf []byte) []byte {
				return buf
			},
			wantUnchanged: true,
		},
		{
			name:  "CRLF round-trips in full mode",
			files: map[string]string{"Page.md": crlf(pageWithTwoSecrets)},
			as:    (*harness).dm,
			submit: func(buf []byte) []byte {
				return buf
			},
			wantUnchanged: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			hidden := tc.hiddenBody
			if hidden == "" {
				hidden = secretBody
			}
			h := newHarness(t, tc.files)
			id := pageID(t, h, "Page.md")
			giveOwnership(t, h, id, h.player().UserID)

			view, err := h.svc.EditView(ctx, tc.as(h), id)
			if err != nil {
				t.Fatalf("edit view: %v", err)
			}
			if tc.as(h).IsDM() {
				if view.Mode != secrets.EditModeFull || len(view.HiddenIDs) != 0 {
					t.Fatalf("a DM got mode %v with hidden %v", view.Mode, view.HiddenIDs)
				}
			} else if view.Mode != secrets.EditModeRedacted {
				t.Fatalf("a player got mode %v, want redacted", view.Mode)
			}
			// The buffer never carries the body of a secret the principal may not
			// read. This is the property every other assertion here rests on, so it
			// is checked first and on the actual bytes. A full-mode buffer is
			// exempt: it is the mode that means the principal may read all of them.
			if view.Mode == secrets.EditModeRedacted && bytes.Contains(view.Content, []byte(hidden)) {
				t.Fatal("the editor buffer carried a secret body")
			}
			if view.Mode == secrets.EditModeRedacted {
				if len(view.HiddenIDs) != 1 {
					t.Fatalf("hidden ids are %v, want one", view.HiddenIDs)
				}
				if view.HiddenIDs[0] != closedSecretID {
					t.Errorf("the hidden id is %v, want [%s]", view.HiddenIDs, closedSecretID)
				}
			}
			if view.Mode == secrets.EditModeFull && len(view.HiddenIDs) != 0 {
				t.Errorf("full mode reported hidden ids %v", view.HiddenIDs)
			}

			before := h.vault.ReadFile(t, "Page.md")
			submitted := tc.submit(view.Content)
			err = h.svc.Save(ctx, tc.as(h), id, submitted, view.BaseHash)
			switch {
			case tc.wantRefused && err == nil:
				t.Fatal("the save was accepted")
			case tc.wantRefused && !errors.Is(err, secrets.ErrRefusedSave):
				t.Fatalf("the error is %v, want ErrRefusedSave", err)
			case !tc.wantRefused && err != nil:
				t.Fatalf("the save was refused: %v", err)
			}

			after := h.vault.ReadFile(t, "Page.md")
			if tc.wantUnchanged && !bytes.Equal(before, after) {
				t.Fatalf("the file changed\n--- before ---\n%q\n--- after ---\n%q", before, after)
			}
			if tc.wantRefused && !bytes.Equal(before, after) {
				t.Fatal("a refused save changed the file")
			}
			if tc.wantContent != "" && !bytes.Contains(after, []byte(tc.wantContent)) {
				t.Fatalf("the saved file does not hold %q\n%s", tc.wantContent, after)
			}
			// The hidden body is on disk in every case that wrote at all, byte for
			// byte: the restore is a byte restore, not a re-render.
			if !tc.wantRefused && !bytes.Contains(after, []byte(hidden)) {
				t.Fatalf("the secret body did not survive the save\n%s", after)
			}
		})
	}
}

// crlf rewrites a fixture's line terminators.
func crlf(src string) string {
	return strings.ReplaceAll(src, "\n", "\r\n")
}

// removeFence cuts one secret's whole block out of a buffer, which is what a
// user who selects the fence and presses delete produces.
func removeFence(buf []byte, id string) []byte {
	d := md.Parse("Page.md", buf)
	for _, s := range d.SecretSpans() {
		if s.SecretID != id {
			continue
		}
		out := make([]byte, 0, len(buf)-s.Len())
		out = append(out, buf[:s.StartByte]...)
		return append(out, buf[s.EndByte:]...)
	}
	return buf
}

// moveFenceToEnd lifts one secret's whole block and puts it at the end of the
// buffer, which is what a user dragging a paragraph produces.
func moveFenceToEnd(buf []byte, id string) []byte {
	d := md.Parse("Page.md", buf)
	for _, s := range d.SecretSpans() {
		if s.SecretID != id {
			continue
		}
		block := append([]byte(nil), buf[s.StartByte:s.EndByte]...)
		out := append([]byte(nil), buf[:s.StartByte]...)
		out = append(out, buf[s.EndByte:]...)
		return append(out, block...)
	}
	return buf
}

// replaceSentinel overwrites one hidden secret's sentinel with real text, which
// is the only way a principal who cannot read the body can say anything about
// what is inside it.
func replaceSentinel(buf []byte, id, body string, with string) []byte {
	token := md.Sentinel(id, []byte(body))
	if token == "" {
		return buf
	}
	return bytes.Replace(buf, []byte(token), []byte(with), 1)
}

// TestDeletingAWholeSecretBlockIsSeparatelyAuthorised is the fourth §8.9 case on
// its own, because it is the one with an authorization answer rather than a
// refusal: a block the reader cannot see is gone from the buffer, and md.Splice
// deliberately does not perform that deletion — it reports it, and the report is
// a separate operation with its own gate.
func TestDeletingAWholeSecretBlockIsSeparatelyAuthorised(t *testing.T) {
	t.Parallel()
	t.Run("a player may not delete a secret they cannot read", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
		id := pageID(t, h, "Page.md")
		giveOwnership(t, h, id, h.player().UserID)

		view, err := h.svc.EditView(ctx, h.player(), id)
		if err != nil {
			t.Fatalf("edit view: %v", err)
		}
		stripped := removeFence(view.Content, closedSecretID)
		if bytes.Equal(stripped, view.Content) {
			t.Fatal("the fence was not removed from the buffer")
		}
		before := h.vault.ReadFile(t, "Page.md")
		err = h.svc.Save(ctx, h.player(), id, stripped, view.BaseHash)
		// A refusal, not a denial: there is no permission that would let a player
		// delete this fence, so the answer names the problem and not a policy. The
		// two are the same outcome for the caller and the distinction is
		// deliberate — a denial here would suggest a gate somebody could pass.
		if !errors.Is(err, secrets.ErrRefusedSave) {
			t.Fatalf("the error is %v, want ErrRefusedSave", err)
		}
		var refused *secrets.SaveRefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("the error is %T, want *SaveRefusedError", err)
		}
		if len(refused.Problems) != 1 || refused.Problems[0].Code != md.ProblemSecretBlockRemoved {
			t.Fatalf("the refusal is %+v, want one block_removed", refused.Problems)
		}
		assertNoFileContent(t, err.Error(), secretBody)
		if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
			t.Fatal("a refused deletion changed the file")
		}
	})

	t.Run("a dm may, and the deletion is on the audit trail", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
		id := pageID(t, h, "Page.md")

		view, err := h.svc.EditView(ctx, h.dm(), id)
		if err != nil {
			t.Fatalf("edit view: %v", err)
		}
		stripped := removeFence(view.Content, closedSecretID)
		if saveErr := h.svc.Save(ctx, h.dm(), id, stripped, view.BaseHash); saveErr != nil {
			t.Fatalf("a dm could not delete a secret: %v", saveErr)
		}
		after := h.vault.ReadFile(t, "Page.md")
		if bytes.Contains(after, []byte(secretBody)) {
			t.Error("the body is still in the file")
		}
		if bytes.Contains(after, []byte("```secret id="+closedSecretID)) {
			t.Error("the fence survived the deletion")
		}
		// The rest of the file is untouched, and the other secret is intact.
		if !bytes.Contains(after, []byte("The party owes the ferryman two crowns.")) {
			t.Error("the deletion disturbed the page's other secret")
		}
		if n := h.count(`SELECT COUNT(*) FROM secrets WHERE id = ?`, closedSecretID); n != 0 {
			t.Error("the deleted secret is still indexed")
		}
		events, err := h.svc.EventsFor(ctx, h.dm(), closedSecretID)
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		if len(events) != 1 || events[0].Action != store.SecretActionDelete {
			t.Fatalf("the audit trail is %+v, want one delete", events)
		}
		if events[0].FromVis != "dm" {
			t.Errorf("the delete event says from %q, want dm", events[0].FromVis)
		}
	})

	t.Run("a player may delete a secret they can read and authored", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
		id := pageID(t, h, "Page.md")
		giveOwnership(t, h, id, h.player().UserID)

		view, err := h.svc.EditView(ctx, h.player(), id)
		if err != nil {
			t.Fatalf("edit view: %v", err)
		}
		// Her own private secret is readable, so this deletion never reaches the
		// hidden branch and never needs the DM gate. That is the point: the strict
		// rule costs a player nothing they were entitled to do.
		stripped := removeFence(view.Content, openSecretID)
		if err := h.svc.Save(ctx, h.player(), id, stripped, view.BaseHash); err != nil {
			t.Fatalf("a player could not delete her own secret: %v", err)
		}
		if bytes.Contains(h.vault.ReadFile(t, "Page.md"), []byte("ferryman")) {
			t.Error("the secret survived")
		}
	})

	t.Run("a player may not delete a visible secret somebody else authored", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		h := newHarness(t, map[string]string{
			"Page.md": "# The Page\n\n" +
				fenceBlock(openSecretID, "table", "dorn", "The mayor's ledger is forged.") +
				"\nPublic after.\n",
		})
		id := pageID(t, h, "Page.md")
		giveOwnership(t, h, id, h.player().UserID)

		view, err := h.svc.EditView(ctx, h.player(), id)
		if err != nil {
			t.Fatalf("edit view: %v", err)
		}
		if view.Mode != secrets.EditModeFull {
			t.Fatalf("a table secret is not redacted from the author of the page: mode %v", view.Mode)
		}
		before := h.vault.ReadFile(t, "Page.md")
		stripped := removeFence(view.Content, openSecretID)
		if err := h.svc.Save(ctx, h.player(), id, stripped, view.BaseHash); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("the error is %v, want authz.ErrDenied", err)
		}
		if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
			t.Fatal("a refused deletion changed the file")
		}
	})
}

// TestMovingAHiddenSecretIsNotAnEditToIt is the fourth §8.9 case that resolves
// the other way. A fence that moves keeps its id, its body and its directive, so
// the restore is byte-exact wherever it lands, and a DM reordering a page while a
// player edits the text around it is the ordinary case this must not break.
func TestMovingAHiddenSecretIsNotAnEditToIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)

	view, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	moved := moveFenceToEnd(view.Content, closedSecretID)
	if bytes.Equal(moved, view.Content) {
		t.Fatal("the fence did not move")
	}
	if saveErr := h.svc.Save(ctx, h.player(), id, moved, view.BaseHash); saveErr != nil {
		t.Fatalf("moving a hidden block was refused: %v", saveErr)
	}
	after := h.vault.ReadFile(t, "Page.md")
	if !bytes.Contains(after, []byte(secretBody)) {
		t.Fatal("the body did not survive the move")
	}
	if !bytes.HasSuffix(after, []byte("```\n")) {
		t.Fatalf("the fence is not last:\n%s", after)
	}
	// Nothing was invented and nothing was dropped: the same bytes in a new place.
	if got := bytes.Count(after, []byte(secretBody)); got != 1 {
		t.Errorf("the body appears %d times, want once", got)
	}
	// And a move is not an edit, so it is not on the audit trail as one.
	events, err := h.svc.EventsFor(ctx, h.dm(), closedSecretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, ev := range events {
		if ev.Action == store.SecretActionEdit || ev.Action == store.SecretActionDelete {
			t.Errorf("a move was recorded as %q", ev.Action)
		}
	}
}

// TestSaveRefusesToWriteThroughAHiddenSecret is the security core of the whole
// path: a player who cannot read a body types over it, and the file on disk is
// bit-for-bit what it was.
//
// It reads the bytes back off disk rather than trusting the returned error,
// because an error is what a caller believes and the disk is what a DM opens in
// Obsidian an hour later.
func TestSaveRefusesToWriteThroughAHiddenSecret(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// forge produces the buffer a principal who cannot read the body might
		// submit. It receives the redacted buffer.
		forge func(buf []byte) []byte
	}{
		{
			name: "prose typed over a sentinel",
			forge: func(buf []byte) []byte {
				return replaceSentinel(buf, closedSecretID, secretBody+"\n", "The mayor is the villain.\n")
			},
		},
		{
			name: "a sentinel with a matching shape but a wrong digest",
			forge: func(buf []byte) []byte {
				return replaceSentinel(buf, closedSecretID, secretBody+"\n", "‹s:"+closedSecretID+":42:00000000›\n")
			},
		},
		{
			name: "a sentinel naming a secret the page does not hold",
			forge: func(buf []byte) []byte {
				return replaceSentinel(buf, closedSecretID, secretBody+"\n", "‹s:999999999999:3:00000000›\n")
			},
		},
		{
			name: "a sentinel forged into another fence",
			forge: func(buf []byte) []byte {
				return bytes.Replace(buf,
					[]byte("The party owes the ferryman two crowns."),
					[]byte("‹s:"+closedSecretID+":3:00000000›"), 1)
			},
		},
		{
			name: "a second fence claiming the hidden secret's id",
			forge: func(buf []byte) []byte {
				return bytes.Replace(buf,
					[]byte("Public after the fences.\n"),
					[]byte("Public after the fences.\n\n```secret id="+closedSecretID+
						" visibility=table author=pia\nA second body.\n```\n"), 1)
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			h := newHarness(t, map[string]string{"Page.md": pageWithTwoSecrets})
			id := pageID(t, h, "Page.md")
			giveOwnership(t, h, id, h.player().UserID)

			view, err := h.svc.EditView(ctx, h.player(), id)
			if err != nil {
				t.Fatalf("edit view: %v", err)
			}
			before := h.vault.ReadFile(t, "Page.md")

			err = h.svc.Save(ctx, h.player(), id, tc.forge(view.Content), view.BaseHash)
			if err == nil {
				t.Fatal("the save was accepted")
			}
			// The bytes, read back from the vault, are the assertion.
			after := h.vault.ReadFile(t, "Page.md")
			if !bytes.Equal(before, after) {
				t.Fatalf("the file changed\n--- before ---\n%q\n--- after ---\n%q", before, after)
			}
			// And the index did not move either: a refused save that re-indexed
			// would make the next reconciliation derive from a file that is fine
			// and a generation that is not.
			if h.reindexes.Load() != 0 {
				t.Errorf("a refused save re-indexed %d times", h.reindexes.Load())
			}
			if n := h.count(`SELECT COUNT(*) FROM secret_events WHERE actor_id = ?`,
				h.player().UserID); n != 0 {
				t.Errorf("a refused save wrote %d audit rows", n)
			}
			// A refusal names ids and reasons, never bytes.
			assertNoFileContent(t, err.Error(), secretBody)
		})
	}
}

// TestAuthoringANewSecretNeedsWritePermission is §6's rule — ownership grants
// authoring rights, not broadcast rights — over the whole role table.
func TestAuthoringANewSecretNeedsWritePermission(t *testing.T) {
	t.Parallel()
	const authored = "\n```secret id=222222222222 visibility=%s author=%s\nA newly authored body.\n```\n"
	cases := []struct {
		name    string
		who     func(h *harness) authz.Principal
		owner   bool
		vis     string
		author  string
		allowed bool
	}{
		{"a page owner may author a private secret as herself", (*harness).player, true, "private", "pia", true},
		{"a page owner may not author a secret as somebody else", (*harness).player, true, "private", "dorn", false},
		{"a page owner may not author a dm secret", (*harness).player, true, "dm", "pia", false},
		{"a page owner may not author a table secret", (*harness).player, true, "table", "pia", false},
		{"a player who does not own the page may not author at all", (*harness).player, false, "private", "pia", false},
		{"a dm may author a table secret", (*harness).dm, false, "table", "dorn", true},
		{"an admin may author a private secret as herself", (*harness).admin, false, "private", "mara", true},
		{"an anonymous principal may not author at all", nil, false, "private", "pia", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			h := newHarness(t, map[string]string{"Page.md": "# The Page\n\nPublic text.\n"})
			id := pageID(t, h, "Page.md")
			var who authz.Principal
			if tc.who == nil {
				who = authz.Anonymous(false)
			} else {
				who = tc.who(h)
			}
			if tc.owner {
				giveOwnership(t, h, id, h.player().UserID)
			}
			before := h.vault.ReadFile(t, "Page.md")

			view, err := h.svc.EditView(ctx, who, id)
			if err != nil {
				if tc.allowed {
					t.Fatalf("edit view was refused: %v", err)
				}
				return
			}
			submitted := append(append([]byte(nil), view.Content...),
				[]byte(strings.Replace(strings.Replace(authored, "%s", tc.vis, 1), "%s", tc.author, 1))...)
			err = h.svc.Save(ctx, who, id, submitted, view.BaseHash)
			switch {
			case tc.allowed && err != nil:
				t.Fatalf("the save was refused: %v", err)
			case !tc.allowed && err == nil:
				t.Fatal("the save was accepted")
			case !tc.allowed && !errors.Is(err, authz.ErrDenied):
				t.Fatalf("the error is %v, want authz.ErrDenied", err)
			}
			after := h.vault.ReadFile(t, "Page.md")
			if tc.allowed {
				if !bytes.Contains(after, []byte("id=222222222222")) {
					t.Fatal("the fence was not written")
				}
				if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, "222222222222"); got != tc.vis {
					t.Errorf("the indexed visibility is %q, want %q", got, tc.vis)
				}
				if n := h.count(`SELECT COUNT(*) FROM secret_events WHERE secret_id = ? AND action = ?`,
					"222222222222", store.SecretActionCreate); n != 1 {
					t.Errorf("the create was recorded %d times, want once", n)
				}
				return
			}
			if !bytes.Equal(before, after) {
				t.Fatal("a refused authoring changed the file")
			}
			if h.reindexes.Load() != 0 {
				t.Error("a refused authoring re-indexed")
			}
		})
	}
}

// TestAVisibilityChangeThroughASaveIsADMOnly closes the other way into a reveal.
// SetVisibility is not the only thing that moves a fence's visibility token: an
// editor buffer can, and if that path did not take the same gate then the author
// of a private secret could reach the table with nothing but the permission to
// edit their own words.
func TestAVisibilityChangeThroughASaveIsADMOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{
		"Page.md": "# The Page\n\n" +
			fenceBlock(openSecretID, "private", "pia", "The mayor is the villain.") +
			"\nPublic after.\n",
	})
	id := pageID(t, h, "Page.md")
	giveOwnership(t, h, id, h.player().UserID)

	view, err := h.svc.EditView(ctx, h.player(), id)
	if err != nil {
		t.Fatalf("edit view: %v", err)
	}
	revealed := bytes.Replace(view.Content, []byte("visibility=private"), []byte("visibility=table"), 1)
	before := h.vault.ReadFile(t, "Page.md")

	if saveErr := h.svc.Save(ctx, h.player(), id, revealed, view.BaseHash); !errors.Is(saveErr, authz.ErrDenied) {
		t.Fatalf("a player reached visibility=table through a save: %v", saveErr)
	}
	if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
		t.Fatal("the refused reveal changed the file")
	}

	// The DM may, and the event records the move the way SetVisibility's does.
	if saveErr := h.svc.Save(ctx, h.dm(), id, revealed, view.BaseHash); saveErr != nil {
		t.Fatalf("a dm could not reveal through a save: %v", saveErr)
	}
	if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, openSecretID); got != "table" {
		t.Errorf("the indexed visibility is %q, want table", got)
	}
	events, err := h.svc.EventsFor(ctx, h.dm(), openSecretID)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 1 || events[0].Action != store.SecretActionEdit ||
		events[0].FromVis != "private" || events[0].ToVis != "table" {
		t.Fatalf("the audit trail is %+v, want one private -> table edit", events)
	}
}

// TestSaveRefusesTheAppsOwnState asserts the refusal that keeps the vault's
// single-instance lock intact.
//
// The index is derived, so a page row naming the app's own lock file is not
// supposed to exist. It is checked anyway, because the consequence is not a wrong
// answer but a second process opening the same vault: vault.Resolve establishes
// containment and nothing else, and this is the boundary that takes a path from
// the index.
func TestSaveRefusesTheAppsOwnState(t *testing.T) {
	t.Parallel()
	const lockPath = ".semiplane/semiplane.lock"
	cases := []struct {
		name string
		call func(ctx context.Context, h *harness, id int64) error
	}{
		{"save", func(ctx context.Context, h *harness, id int64) error {
			_, err := h.svc.EditView(ctx, h.dm(), id)
			if err != nil {
				return err
			}
			return h.svc.Save(ctx, h.dm(), id, []byte("# replaced\n"), vault.Hash([]byte("held\n")))
		}},
		{"revert", func(ctx context.Context, h *harness, id int64) error {
			return h.svc.Revise(ctx, h.dm(), id, 1)
		}},
		{"edit view", func(ctx context.Context, h *harness, id int64) error {
			_, err := h.svc.EditView(ctx, h.dm(), id)
			return err
		}},
		{"history", func(ctx context.Context, h *harness, id int64) error {
			_, err := h.svc.History(ctx, h.dm(), id)
			return err
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			h := newHarness(t, map[string]string{"Page.md": "# The Page\n\nText.\n"})
			abs := h.vault.WriteFile(t, lockPath, "held\n")
			id, err := store.UpsertPage(ctx, h.db.Writer(), store.Page{
				Path: lockPath, Basename: "semiplane.lock", Title: "lock",
				ContentHash: vault.Hash([]byte("held\n")), MTimeUnix: clockNow.Unix(),
				SizeBytes: 5, PageType: "note", CreatedAt: clockNow, UpdatedAt: clockNow,
			})
			if err != nil {
				t.Fatalf("seed a page row naming the lock: %v", err)
			}

			if callErr := tc.call(ctx, h, id); !errors.Is(callErr, secrets.ErrAppState) {
				t.Fatalf("the error is %v, want ErrAppState", callErr)
			}
			got, err := os.ReadFile(abs)
			if err != nil {
				t.Fatalf("the lock file is gone: %v", err)
			}
			if string(got) != "held\n" {
				t.Fatalf("the lock file now holds %q", got)
			}
		})
	}
}

// TestEventsRequiresPermission is §6a's gap, closed: the audit trail has a gate,
// the gate is asked before the lookup, and a refused principal cannot tell "not
// permitted" from "no such secret".
func TestEventsRequiresPermission(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	if err := h.svc.Reveal(ctx, h.dm(), secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}

	t.Run("a dm reads the trail", func(t *testing.T) {
		t.Parallel()
		events, err := h.svc.EventsFor(ctx, h.dm(), secretID)
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		if len(events) != 1 || events[0].Action != store.SecretActionReveal {
			t.Fatalf("the trail is %+v, want one reveal", events)
		}
	})
	t.Run("an admin reads the trail", func(t *testing.T) {
		t.Parallel()
		if _, err := h.svc.EventsFor(ctx, h.admin(), secretID); err != nil {
			t.Fatalf("an admin was refused: %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		who  func(h *harness) authz.Principal
	}{
		{"a player is refused", (*harness).player},
		{"an anonymous principal is refused", nil},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var who authz.Principal
			if tc.who == nil {
				who = authz.Anonymous(true)
			} else {
				who = tc.who(h)
			}
			real, errReal := h.svc.EventsFor(ctx, who, secretID)
			if !errors.Is(errReal, authz.ErrDenied) {
				t.Fatalf("the error is %v, want authz.ErrDenied", errReal)
			}
			if real != nil {
				t.Errorf("a refusal returned rows: %+v", real)
			}
			// The refusal is not an existence oracle: an id that does not exist
			// gives the same error, from the same place.
			_, errMissing := h.svc.EventsFor(ctx, who, "000000000000")
			if !errors.Is(errMissing, authz.ErrDenied) {
				t.Fatalf("the missing-id error is %v, want authz.ErrDenied", errMissing)
			}
			if errReal.Error() != errMissing.Error() {
				t.Fatalf("the two refusals differ: %q vs %q", errReal, errMissing)
			}
		})
	}
}

// TestTheRedactedEditorIsNotTheOnlyEditor asserts the mode decision is
// CanReadSecret and not a re-derivation of it: the same principal on the same
// page gets the same answer every time, and a page with no hidden secret is full
// mode even for a principal who cannot read anything else.
func TestTheRedactedEditorIsNotTheOnlyEditor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := []struct {
		name    string
		files   map[string]string
		as      func(h *harness) authz.Principal
		anon    bool
		want    secrets.EditMode
		hidden  int
		carries string
	}{
		{
			name:   "a page with no secret is full mode for a player",
			files:  map[string]string{"Page.md": "# The Page\n\nNothing hidden here.\n"},
			as:     (*harness).player,
			want:   secrets.EditModeFull,
			hidden: 0,
		},
		{
			name:   "a dm is full mode on a page full of dm fences",
			files:  map[string]string{"Page.md": pageWithTwoSecrets},
			as:     (*harness).dm,
			want:   secrets.EditModeFull,
			hidden: 0,
		},
		{
			name:    "a player is redacted on the same page",
			files:   map[string]string{"Page.md": pageWithTwoSecrets},
			as:      (*harness).player,
			want:    secrets.EditModeRedacted,
			hidden:  1,
			carries: "ferryman",
		},
		{
			// §2's anonymous row: authz.SecretVisibleSQL admits a table secret on
			// visibility alone with no authentication term, and CanReadSecret does
			// not. The editor asks CanReadSecret, so an anonymous principal reading
			// a table secret gets a sentinel and not the body.
			name:   "an anonymous principal is redacted even when anonymous read is on",
			files:  map[string]string{"Page.md": pageWithTwoSecrets},
			anon:   true,
			want:   secrets.EditModeRedacted,
			hidden: 2,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarnessAs(t, tc.files, tc.anon)
			id := pageID(t, h, "Page.md")
			var who authz.Principal
			if tc.anon {
				who = authz.Anonymous(true)
			} else {
				who = tc.as(h)
			}
			view, err := h.svc.EditView(ctx, who, id)
			if err != nil {
				t.Fatalf("edit view: %v", err)
			}
			if view.Mode != tc.want {
				t.Errorf("mode is %v, want %v", view.Mode, tc.want)
			}
			if len(view.HiddenIDs) != tc.hidden {
				t.Errorf("hidden ids are %v, want %d of them", view.HiddenIDs, tc.hidden)
			}
			if tc.carries != "" && !bytes.Contains(view.Content, []byte(tc.carries)) {
				t.Errorf("a readable body is missing from the buffer")
			}
			// Full mode means the file verbatim, and the hash is of the same bytes.
			if tc.want == secrets.EditModeFull && !bytes.Equal(view.Content, h.vault.ReadFile(t, "Page.md")) {
				t.Error("full mode did not return the file verbatim")
			}
			if !bytes.Equal(view.BaseHash, vault.Hash(h.vault.ReadFile(t, "Page.md"))) {
				t.Error("the base hash is not the hash of the file")
			}
			if tc.want == secrets.EditModeRedacted && bytes.Contains(view.Content, []byte(secretBody)) {
				t.Error("the buffer carried a secret body")
			}
		})
	}
}

// assertNoFileContent fails when an error or a rendered string carries any of the
// fragments. AGENTS.md §4: error messages carry ids, paths and reasons.
func assertNoFileContent(t *testing.T, where string, fragments ...string) {
	t.Helper()
	for _, f := range fragments {
		if f == "" {
			continue
		}
		if strings.Contains(where, f) {
			t.Fatalf("a message carries file content %q: %s", f, where)
		}
	}
}
