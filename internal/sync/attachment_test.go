package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// pngBytes is the content of a fixture image. It is not a PNG — nothing decodes
// it, the serve route never sniffs — so what matters is only that its length is
// knowable and that a change to it is a change to the file.
const pngBytes = "not a real png"

// attachmentsOf returns the files recorded for one page, in path order.
func (h *harness) attachmentsOf(pageID int64) []store.Attachment {
	h.t.Helper()
	rows, err := store.ListAttachmentsByPage(context.Background(), h.db.Reader(), pageID)
	if err != nil {
		h.t.Fatalf("list the attachments of page %d: %v", pageID, err)
	}
	return rows
}

// attachmentPaths returns the recorded paths of one page's files.
func (h *harness) attachmentPaths(pageID int64) []string {
	h.t.Helper()
	rows := h.attachmentsOf(pageID)
	out := make([]string, 0, len(rows))
	for _, a := range rows {
		out = append(out, a.Path)
	}
	return out
}

// TestTheIndexerRecordsAnAttachment is the half that did not exist: an md
// reference is a name, a store row is a file, and nothing turned one into the
// other. Without it the §8.8 serve route authorizes a request correctly and then
// answers 404, because it resolves the name against a table no pass had ever
// written to — a control that authorizes and then does nothing.
func TestTheIndexerRecordsAnAttachment(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Tavern.md":           "# Tavern\n\n![the barmaid](assets/portrait.png)\n",
		"assets/portrait.png": pngBytes,
	})
	res := h.indexAll()
	if problems := allProblems(res); len(problems) != 0 {
		t.Fatalf("a page with one image reported problems: %+v", problems)
	}
	pageID := h.pageID("Tavern.md")

	rows := h.attachmentsOf(pageID)
	if len(rows) != 1 {
		t.Fatalf("recorded %d files for a page with one image: %v", len(rows), h.attachmentPaths(pageID))
	}
	got := rows[0]
	if got.Path != "assets/portrait.png" {
		t.Errorf("path = %q, want %q", got.Path, "assets/portrait.png")
	}
	if got.PageID == nil {
		t.Fatal("page_id is NULL: the serve route reads this table through the page")
	} else if *got.PageID != pageID {
		t.Errorf("page_id = %d, want %d", *got.PageID, pageID)
	}
	if want := int64(len(pngBytes)); got.SizeBytes != want {
		t.Errorf("size_bytes = %d, want %d", got.SizeBytes, want)
	}
	if got.Mime != "image/png" {
		t.Errorf("mime = %q, want %q", got.Mime, "image/png")
	}

	// A player may be served the file, which is the whole reason the row exists
	// and the reason §8.8 evaluates it per referencing links row.
	visible, err := store.AttachmentVisibleTo(context.Background(), h.db.Reader(),
		h.principal("pia"), pageID, "assets/portrait.png")
	if err != nil {
		t.Fatalf("check the attachment: %v", err)
	}
	if !visible {
		t.Error("a publicly referenced image is not visible to a player")
	}
}

// TestTheStoredMimeComesFromTheExtension is the mime decision stated as a table:
// the extension, and application/octet-stream for one Go's table does not know.
// The last case is the point — it must not depend on whatever /etc/mime.types
// the machine running the test happens to have.
func TestTheStoredMimeComesFromTheExtension(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		file string
		want string
	}{
		{name: "png", file: "a.png", want: "image/png"},
		{name: "jpeg_with_the_other_extension", file: "a.jpeg", want: "image/jpeg"},
		{name: "svg", file: "a.svg", want: "image/svg+xml"},
		{name: "pdf", file: "a.pdf", want: "application/pdf"},
		{name: "html", file: "a.html", want: "text/html; charset=utf-8"},
		{name: "no_extension", file: "LICENSE", want: "application/octet-stream"},
		{name: "extension_no_one_registers", file: "map.semiplane", want: "application/octet-stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, map[string]string{
				"Tavern.md":         "# Tavern\n\n![x](assets/" + tc.file + ")\n",
				"assets/" + tc.file: pngBytes,
			})
			h.indexAll()
			rows := h.attachmentsOf(h.pageID("Tavern.md"))
			if len(rows) != 1 {
				t.Fatalf("recorded %d files, want 1: %v", len(rows), h.attachmentPaths(h.pageID("Tavern.md")))
			}
			if rows[0].Mime != tc.want {
				t.Errorf("mime for %s = %q, want %q", tc.file, rows[0].Mime, tc.want)
			}
		})
	}
}

// TestAnAttachmentReferencedFromTwoPagesIsServedFromBoth is the schema bug, as a
// test.
//
// §6.2 declared attachments.path UNIQUE, which makes the table a claim about the
// file: one row, one path, for the whole campaign. The second page to reference
// an image the first page already recorded could not have a row of its own, so
// the serve route authorized the request against that page's links and then
// found nothing to serve it from — an image a reader can plainly see on page two
// is a 404 on page two. Nothing in the schema or in the route said so; only this
// does.
//
// The fix is migration 0003's UNIQUE(path, page_id): one row per referencing
// page, one shared path.
func TestAnAttachmentReferencedFromTwoPagesIsServedFromBoth(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Tavern.md":      "# Tavern\n\n![the map](assets/map.png)\n",
		"Notes.md":       "# Notes\n\n![the same map](assets/map.png)\n",
		"assets/map.png": pngBytes,
	})
	h.indexAll()

	pages := []struct {
		name   string
		pageID int64
	}{
		{name: "first_page_to_reference_it", pageID: h.pageID("Tavern.md")},
		{name: "second_page_to_reference_it", pageID: h.pageID("Notes.md")},
	}
	ids := map[int64]bool{}
	for _, p := range pages {
		rows := h.attachmentsOf(p.pageID)
		if len(rows) != 1 {
			t.Fatalf("%s has %d recorded files, want 1: %v", p.name, len(rows), h.attachmentPaths(p.pageID))
		}
		if rows[0].Path != "assets/map.png" {
			t.Errorf("%s recorded %q, want the shared path", p.name, rows[0].Path)
		}
		if ids[rows[0].ID] {
			t.Errorf("%s reads the same row id as another page: one file, one row per page", p.name)
		}
		ids[rows[0].ID] = true
	}
	if got := h.mustQueryInt(`SELECT COUNT(*) FROM attachments`); got != 2 {
		t.Fatalf("attachments = %d, want one row per referencing page", got)
	}

	// And the row is worth something: §8.8 answers yes for a player from either
	// page, which is the question the serve route asks before it reads a byte.
	for _, p := range pages {
		for _, who := range []string{"pia", "dorn", ""} {
			visible, err := store.AttachmentVisibleTo(context.Background(), h.db.Reader(),
				h.principal(who), p.pageID, "assets/map.png")
			if err != nil {
				t.Fatalf("%s: check the attachment: %v", p.name, err)
			}
			if !visible {
				t.Errorf("the map is not visible to %q from %s", who, p.name)
			}
		}
	}
}

// TestAttachmentScopeIsPerPage pins the constraint the two-page test depends on,
// through behaviour rather than through sqlite_schema.
//
// It is asserted from this package rather than from store because the indexer is
// what the constraint is for: a migration that tightened or dropped it would
// still build, boot and serve, and the only thing that notices is the second
// page of a campaign with a shared image.
func TestAttachmentScopeIsPerPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{
		"Tavern.md":      "# Tavern\n\n![m](assets/map.png)\n\n![m again](assets/map.png)\n",
		"Notes.md":       "# Notes\n\n![m](assets/map.png)\n",
		"Other.md":       "# Other\n\nNo image here yet.\n",
		"assets/map.png": pngBytes,
	})
	h.indexAll()
	tavern, notes, other := h.pageID("Tavern.md"), h.pageID("Notes.md"), h.pageID("Other.md")

	// A page that embeds one image twice is one row, not a constraint failure.
	if rows := h.attachmentsOf(tavern); len(rows) != 1 {
		t.Fatalf("one image referenced twice recorded %d rows, want 1: %v", len(rows), h.attachmentPaths(tavern))
	}
	if got := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND kind = 'attachment'`, tavern); got != 2 {
		t.Fatalf("links rows for the image = %d, want 2: the two references are what the rule is about", got)
	}
	// The pass itself already needed the per-page scope: a second page embedding
	// the same file is a second row, and with UNIQUE(path) this is where the
	// index would have failed.
	if rows := h.attachmentsOf(notes); len(rows) != 1 || rows[0].Path != "assets/map.png" {
		t.Fatalf("the second page records %v, want the shared file", h.attachmentPaths(notes))
	}

	tx, err := h.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The same path on the same page is refused: the row is a per-page fact.
	if _, err := store.InsertAttachment(ctx, tx, store.Attachment{
		PageID: &tavern, Path: "assets/map.png", Mime: "image/png", SizeBytes: 1,
	}); err == nil {
		t.Error("a second row for one page and one path was accepted; the constraint is UNIQUE(path) again")
	}
	// The same path on another page is not, which is the whole of the migration.
	// Other.md does not reference the file, so this is a caller asking for a row
	// its page has no claim to — which the constraint must allow, because the
	// per-page scope is what the second half of the two-page test relies on.
	if _, err := store.InsertAttachment(ctx, tx, store.Attachment{
		PageID: &other, Path: "assets/map.png", Mime: "image/png", SizeBytes: 1,
	}); err != nil {
		t.Errorf("a second page could not record the shared file: %v", err)
	}
}

// TestAnAttachmentReferenceThatEscapesTheVaultIsNotRecorded is the traversal
// table.
//
// An attachment name is author-controlled text, and a recorded row is a row the
// serve route will hand bytes from, so the input matters exactly as much as it
// would on the wire. The sharp cases are the ones where the target file really
// exists and really is readable: a name that a filepath.Join onto the vault root
// would reach is a name a recorded row would leak, and each of those is created
// here. Resolve, never join, is what makes the difference.
//
// One case is recorded on purpose. A test whose every case is a refusal cannot
// tell a working gate from a broken one, and the positive control is what makes
// the refusals mean something.
func TestAnAttachmentReferenceThatEscapesTheVaultIsNotRecorded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// ref is the destination as it is written in the page.
		ref string
		// escape names a file to create outside the vault, in its parent
		// directory, so that a join-based implementation would find it. Empty
		// creates nothing.
		escape string
		// inside names a file to create inside the vault.
		inside string
		// recorded is the expectation: whether the name gets a row.
		recorded bool
		why      string
	}{
		{
			name: "a_positive_control", ref: "assets/portrait.png", inside: "assets/portrait.png",
			recorded: true, why: "an ordinary reference is recorded, or the refusals below prove nothing",
		},
		{
			name: "parent_traversal", ref: "../escaped-parent.png", escape: "escaped-parent.png",
			recorded: false, why: "the file is there and a join would reach it",
		},
		{
			name: "traversal_through_a_real_directory", ref: "assets/../../escaped-nested.png", escape: "escaped-nested.png",
			inside: "assets/.keep", recorded: false, why: "assets/ exists, so the name is not rejected for being absurd",
		},
		{
			name: "backslashes_folded_before_the_check", ref: "..\\..\\escaped-backslash.png", escape: "escaped-backslash.png",
			recorded: false, why: "a Windows-authored path is a Linux-authored one after folding",
		},
		{
			name: "homoglyph_separator", ref: "assets/∕../∕../escaped-homoglyph.png", escape: "escaped-homoglyph.png",
			inside: "assets/.keep", recorded: false, why: "the separator a human reads is not the one the OS does",
		},
		{
			name: "unc_path", ref: "//host/share/secret.png",
			recorded: false, why: "a UNC path names a host, not a vault file",
		},
		{
			name: "drive_letter", ref: "C:/Windows/System32/config/SAM",
			recorded: false, why: "refused before the filesystem is touched, so no fixture is needed",
		},
		{
			name: "absolute_path_naming_a_vault_file", ref: "/etc/passwd", inside: "etc/passwd",
			recorded: false,
			why: "the file is inside the vault and readable, and it is still not recorded: " +
				"Resolve strips the leading slash, so the recorded name would differ from the " +
				"links row's, and the serve route refuses a leading slash in a URL anyway",
		},
		{
			name: "backslash_separator_naming_a_vault_file", ref: "assets\\portrait.png", inside: "assets/portrait.png",
			recorded: false,
			why: "same reason: Resolve folds the separator, so the name is not the file's own path " +
				"and no URL can carry it",
		},
		{
			name: "the_apps_own_state", ref: ".semiplane/semiplane.db",
			recorded: false, why: "the index is not campaign content, and a page may not serve the vault's database",
		},
		{
			name: "a_dot_segment", ref: "assets/./portrait.png", inside: "assets/portrait.png",
			recorded: false, why: "cleaned into a different name, which the exact match would miss",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]string{"Tavern.md": "# Tavern\n\n![x](" + tc.ref + ")\n"}
			if tc.inside != "" {
				files[tc.inside] = pngBytes
			}
			h := newHarness(t, files)
			if tc.escape != "" {
				// Outside the vault, in the temp directory that holds it, and
				// therefore cleaned up with it.
				outside := filepath.Join(filepath.Dir(h.vault.Root), tc.escape)
				if err := os.WriteFile(outside, []byte(pngBytes), 0o600); err != nil {
					t.Fatalf("create the escape target %s: %v", tc.escape, err)
				}
				if _, err := os.Stat(outside); err != nil {
					t.Fatalf("the escape target is not readable, so the case proves nothing: %v", err)
				}
			}
			res := h.indexAll()

			// The page itself indexed: an attachment reference is never a reason
			// for a page to fail, and a fixture that could not tell a skip from a
			// failed pass would hide that.
			pageID := h.pageID("Tavern.md")
			if problems := allProblems(res); len(problems) != 0 {
				t.Fatalf("indexing a page with the reference %q reported problems: %+v", tc.ref, problems)
			}
			if got := h.mustQueryInt(
				`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND kind = 'attachment'`, pageID); got != 1 {
				t.Fatalf("the reference %q produced %d links rows, want 1: %s",
					tc.ref, got, tc.why)
			}

			paths := h.attachmentPaths(pageID)
			if tc.recorded {
				if len(paths) != 1 {
					t.Fatalf("recorded %v, want the one reference %q", paths, tc.ref)
				}
				return
			}
			if len(paths) != 0 {
				t.Fatalf("the reference %q was recorded as %v: %s", tc.ref, paths, tc.why)
			}
		})
	}
}

// TestAnAttachmentWhoseFileIsMissingDoesNotFailTheIndex is the missing-file
// decision.
//
// The decision is no row and no error, and the argument is that a missing file
// is a normal authoring state: a DM writes `![the barmaid](portrait.png)` before
// drawing it, in a note that is otherwise finished. Failing the page would make
// that note unindexable — no text, no links, no search — over a file the page does
// not own, and it would do so on every reindex until the DM noticed. Reporting it
// as a problem would be the other half of the same mistake: the broken-links
// panel already lists the reference, because the links row is written either way,
// and a second copy per reindex is noise that teaches the reader to ignore the
// panel that matters.
//
// So the file that is there is recorded and the one that is not is skipped, the
// page indexes, and nothing is reported.
func TestAnAttachmentWhoseFileIsMissingDoesNotFailTheIndex(t *testing.T) {
	t.Parallel()
	h := newHarness(t, map[string]string{
		"Tavern.md": "# Tavern\n\n![the barmaid](assets/portrait.png)\n\n" +
			"![not drawn yet](assets/missing.png)\n",
		"assets/portrait.png": pngBytes,
	})
	res := h.indexAll()
	if problems := allProblems(res); len(problems) != 0 {
		t.Fatalf("a page referencing a file that does not exist reported problems: %+v", problems)
	}
	pageID := h.pageID("Tavern.md")

	// Both references are links rows, so the broken-links panel still sees the
	// missing one. That is where a DM is told, and it costs nothing to be told
	// about a file nobody has drawn.
	if got := h.mustQueryInt(
		`SELECT COUNT(*) FROM links WHERE source_page_id = ? AND kind = 'attachment'`, pageID); got != 2 {
		t.Errorf("attachment links rows = %d, want 2: the reference is recorded even with no file", got)
	}
	paths := h.attachmentPaths(pageID)
	if len(paths) != 1 || paths[0] != "assets/portrait.png" {
		t.Fatalf("recorded files = %v, want only the one that exists", paths)
	}
	if visible, err := store.AttachmentVisibleTo(context.Background(), h.db.Reader(),
		h.principal("pia"), pageID, "assets/missing.png"); err != nil || visible {
		t.Errorf("a file with no row is visible=%v (err %v); a route would then look for bytes", visible, err)
	}
}

// TestAReindexRemovesAnAttachmentThatIsNoLongerReferenced is the one that leaves
// a lie in the database.
//
// Every other derived row of a page is replaced wholesale on a reindex, and an
// attachment row that survived would be worse than a stale link: the serve route
// authorizes on the links rows, so a page that stopped embedding an image would
// still answer a request for it — and a DM's image, deleted from the text and
// still downloadable, is a secret that was never revoked.
func TestAReindexRemovesAnAttachmentThatIsNoLongerReferenced(t *testing.T) {
	t.Parallel()
	const id = "abcdef012345"
	h := newHarness(t, map[string]string{
		"Tavern.md": "# Tavern\n\n![the barmaid](assets/portrait.png)\n\n" +
			secretFence(id, "dm", "dorn", "The key is under the third stave.") + "\n",
		"assets/portrait.png": pngBytes,
		"assets/key.png":      pngBytes,
	})
	// The secret-only image is the interesting one, so the file is seeded and
	// the page is rewritten to stop embedding it.
	h.vault.WriteFile(t, "Tavern.md",
		"# Tavern\n\n![the barmaid](assets/portrait.png)\n\n"+
			secretFence(id, "dm", "dorn", "![the key](assets/key.png)")+"\n")
	h.indexAll()
	pageID := h.pageID("Tavern.md")
	if got := len(h.attachmentsOf(pageID)); got != 2 {
		t.Fatalf("recorded %d files, want 2: %v", got, h.attachmentPaths(pageID))
	}

	// The DM deletes the image from the secret and saves the note.
	h.vault.WriteFile(t, "Tavern.md",
		"# Tavern\n\n![the barmaid](assets/portrait.png)\n\n"+
			secretFence(id, "dm", "dorn", "The key is under the third stave.")+"\n")
	if err := h.ix.Reindex(context.Background(), "Tavern.md"); err != nil {
		t.Fatalf("reindex: %v", err)
	}

	paths := h.attachmentPaths(pageID)
	if len(paths) != 1 || paths[0] != "assets/portrait.png" {
		t.Fatalf("after the reindex the page records %v, want only the image it still embeds", paths)
	}
	// The file is still on disk, so this is not a "the file went away" answer:
	// the row is gone because the reference is.
	if !h.vault.Exists("assets/key.png") {
		t.Fatal("the fixture removed the file, so this is not testing a stale row")
	}
	visible, err := store.AttachmentVisibleTo(context.Background(), h.db.Reader(),
		h.principal("dorn"), pageID, "assets/key.png")
	if err != nil {
		t.Fatalf("check the removed attachment: %v", err)
	}
	if visible {
		t.Error("an image no longer referenced by the page is still visible; a DM cannot delete one")
	}
}
