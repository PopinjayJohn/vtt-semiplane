package httpapi_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The page-scoped surfaces of §9.2–§9.4, and the one rendering decision that
// carries the most weight in them: what a lost save is allowed to show.

// asDM signs in as the DM, the only principal the coarse write gate admits today.
//
// The admin would do as well. The DM is used because the fixture's secrets are
// authored by the DM, so a DM is the principal for whom "the editor is redacted"
// and "the editor is full" are both reachable, and both halves of every assertion
// below are about a redaction actually happening.
func asDM(t *testing.T, fx *fixture) *session {
	t.Helper()
	fx.accountsFor()
	return fx.asUser(dmName, dmPass)
}

// baseHashOf is the hex hash of a vault file, which is what a submission must
// carry back.
func baseHashOf(t *testing.T, fx *fixture, name string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(fx.Root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return vault.HashHex(src)
}

// TestSaveRejectsStaleHash is the optimistic-concurrency check, and the
// assertion that matters inside it is the second one.
//
// A stale base hash is a save that was composed against bytes that are no longer
// on disk. It must not be written — that is what the check is for. And the 409
// that says so must not carry a single byte the actor was not already entitled
// to read, which is the property this asserts and the reason the conflict page
// re-derives both sides through the authorized read path rather than through
// vault.ConflictError, whose Ours() and Theirs() are the raw file on a page whose
// bytes are, in part, secret plaintext.
func TestSaveRejectsStaleHash(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := asDM(t, fx)
	before := baseHashOf(t, fx, "Tavern.md")

	// A save composed against a hash that is not the file's. The base hash is a
	// run of zeroes, which is well-formed and wrong — the case the check exists
	// for, as distinct from a malformed one, which the handler refuses earlier
	// and for a different reason.
	resp := s.do(&call{
		method: http.MethodPost,
		path:   "/p/Tavern.md/edit",
		form: url.Values{
			"content":   {"# The Drowned Lantern\n\nrewritten by somebody in a hurry\n"},
			"base_hash": {strings.Repeat("00", 32)},
		},
		csrf: s.csrf,
	})
	body := s.read(resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409; the save was composed against bytes that are not on disk", resp.StatusCode)
	}
	// Nothing was written. The page's hash is the one the actor's editor was
	// built against, which is the whole point of the check: a save composed
	// against other bytes is not applied to these.
	if got := baseHashOf(t, fx, "Tavern.md"); got != before {
		t.Errorf("the file's hash is %s after a refused save, want the %s it had before", got, before)
	}
	// The submitted buffer is echoed, because a save that refuses must not throw
	// the work away.
	if !strings.Contains(body, "rewritten by somebody in a hurry") {
		t.Error("the 409 does not echo the submitted buffer: a save that refuses must not throw the work away")
	}
	// A player cannot reach this page at all — the table's coarse gate refuses
	// them first — and that is the reason the redaction of the "theirs" side is
	// tested in pageedit_internal_test.go rather than here. Worth asserting as a
	// fact, because it is the property that makes the internal test necessary:
	// TestTheConflictPageRedactsTheOnDiskSideForAnActorWhoCannotReadIt.
	player := fx.asUser(otherName, otherPass)
	refused := player.do(&call{
		method: http.MethodPost,
		path:   "/p/Tavern.md/edit",
		form: url.Values{
			"content":   {"# The Drowned Lantern\n\nrewritten by somebody in a hurry\n"},
			"base_hash": {strings.Repeat("00", 32)},
		},
		csrf: player.csrf,
	})
	refusedBody := player.read(refused)
	if refused.StatusCode != http.StatusForbidden {
		t.Errorf("a player saving a page: status %d, want 403", refused.StatusCode)
	}
	if strings.Contains(refusedBody, "rewritten by somebody in a hurry") {
		t.Error("the refusal echoed the submission, so a 403 is answering a request with the request in it")
	}
}

// TestConflictResolutionProducesExpectedBytes closes the loop: taking the
// "theirs" side of a conflict and submitting it writes those exact bytes, and
// taking the "mine" side and submitting it writes those.
//
// The round trip is the only evidence that the conflict page did not quietly
// normalise, re-encode or re-splice either side on the way to the screen. A
// redacted buffer that came back with a different hash would be a save that
// silently discards whatever the author did not retype.
func TestConflictResolutionProducesExpectedBytes(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := asDM(t, fx)

	// A real, byte-distinct edit by somebody else, so "theirs" is not the buffer
	// the actor started from. The hash the actor's editor was built against is
	// the one of the bytes *before* that, which is what makes the save stale.
	before := mustReadFile(t, fx, "Index.md")
	edited := strings.Replace(string(before), "# Index", "# Index (revised)", 1)
	if err := os.WriteFile(filepath.Join(fx.Root, "Index.md"), []byte(edited), 0o600); err != nil {
		t.Fatalf("write the external edit: %v", err)
	}
	fx.reindexAll()

	mine := "# Index\n\nmy own revision of the opening line\n"
	form := url.Values{
		"content":   {mine},
		"base_hash": {vault.HashHex(before)},
	}
	resp := s.do(&call{method: http.MethodPost, path: "/p/Index.md/edit", form: form, csrf: s.csrf})
	body := s.read(resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d, want 409", resp.StatusCode)
	}
	// Both sides, and they are the two the page was between: the file as it is
	// on disk now, and the buffer that lost. Neither is decoration.
	if !strings.Contains(body, "Index (revised)") {
		t.Error("the conflict page does not show the file as it is on disk now")
	}
	if !strings.Contains(body, "my own revision of the opening line") {
		t.Error("the conflict page does not show the buffer that lost the race")
	}
	// Take the "theirs" side: the page as it is on disk now, which is what the
	// conflict page says to copy from.
	theirs := edited
	stale := mustReadFile(t, fx, "Index.md")
	resp2 := s.do(&call{
		method: http.MethodPost,
		path:   "/p/Index.md/edit",
		form:   url.Values{"content": {theirs}, "base_hash": {vault.HashHex(stale)}},
		csrf:   s.csrf,
	})
	s.read(resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-submitting the conflict page's own \"theirs\" text: status %d, want 200; the page and the buffer disagree", resp2.StatusCode)
	}
	if got := string(mustReadFile(t, fx, "Index.md")); got != theirs {
		t.Errorf("the file after resolving the conflict is not the bytes that were resolved:\n got %q\nwant %q", got, theirs)
	}

	// And the other side: a buffer the actor composed survives a conflict
	// unchanged, byte for byte.
	resp3 := s.do(&call{
		method: http.MethodPost,
		path:   "/p/Index.md/edit",
		form:   url.Values{"content": {mine}, "base_hash": {vault.HashHex([]byte(theirs))}},
		csrf:   s.csrf,
	})
	s.read(resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("saving the conflict page's own \"mine\" text: status %d, want 200", resp3.StatusCode)
	}
	if got := string(mustReadFile(t, fx, "Index.md")); got != mine {
		t.Errorf("the file after resolving the conflict the other way is not the bytes that were resolved:\n got %q\nwant %q", got, mine)
	}
}

// TestFrontmatterPatchPreservesRestOfFile is §1's "the app never reflows user
// Markdown", asserted on a write that changes exactly one line of the
// frontmatter and nothing else.
//
// The bytes of the rest of the file are compared, not the parse: a save that
// re-serialised the frontmatter would still produce a document that parses to the
// same thing, and only a byte comparison notices.
func TestFrontmatterPatchPreservesRestOfFile(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := asDM(t, fx)

	before := mustReadFile(t, fx, "Ruin.md")
	// One key changed, one key added, the body untouched, the line endings of a
	// CRLF file preserved, and no trailing-newline normalisation.
	after := strings.Replace(string(before), "tags: [area/wild]", "tags: [area/wild, area/ruined]\nstatus: collapsed", 1)
	if after == string(before) {
		t.Fatal("the patch did not change the file, so the test would pass vacuously")
	}
	resp := s.do(&call{
		method: http.MethodPost,
		path:   "/p/Ruin.md/edit",
		form:   url.Values{"content": {after}, "base_hash": {baseHashOf(t, fx, "Ruin.md")}},
		csrf:   s.csrf,
	})
	s.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	got := mustReadFile(t, fx, "Ruin.md")
	if string(got) != after {
		t.Errorf("the file is not the bytes that were submitted:\n got %q\nwant %q", got, after)
	}
	// The body, in particular, is not re-rendered: the secret fence inside it is
	// still there with the same directive and the same body.
	if !strings.Contains(string(got), "RUIN-BODY-TOKEN-2c8f61") {
		t.Error("the DM's own body was not written back: a full-buffer save must not redacted-read what the author just typed")
	}
}

// TestRevisionHistoryAndRevert walks the three revision routes together, because
// each of them is only meaningful next to the others: a history that lists what
// cannot be opened, or a revert that writes something other than what it
// promised, is a panel that lies.
func TestRevisionHistoryAndRevert(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := asDM(t, fx)

	// Two writes, so there is something to revert *to*: a revert to the only
	// revision would pass with a handler that did nothing.
	//
	// A revision records the bytes as they were *before* the write, so the
	// oldest revision of the page is the file as it was at boot and each save
	// adds one above it. That is worth stating because it is the opposite of
	// what the name suggests, and a test that assumed otherwise would be testing
	// the wrong revision.
	original := string(mustReadFile(t, fx, "Index.md"))
	saveOK(t, s, "/p/Index.md/edit", "v1: "+original)
	saveOK(t, s, "/p/Index.md/edit", "v2: "+string(mustReadFile(t, fx, "Index.md")))

	t.Run("the history lists what was written and links to each", func(t *testing.T) {
		resp := s.do(s.get("/p/Index.md/history"))
		body := s.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		for _, want := range []string{"/p/Index.md/revisions/", "/p/Index.md/revert/"} {
			if !strings.Contains(body, want) {
				t.Errorf("the history page contains no %q, so a revision is listed but cannot be opened", want)
			}
		}
	})

	t.Run("one revision is readable and names what it recorded", func(t *testing.T) {
		// The newest, because it is the one whose content differs from the page
		// as it is now, so the page has to be showing the revision's bytes and
		// not the file's.
		id := newestRevisionIDOf(t, fx, "Index.md")
		resp := s.do(s.get("/p/Index.md/revisions/" + strconv.FormatInt(id, 10)))
		body := s.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET a revision: status %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(body, "v1: ") {
			t.Error("the revision page does not contain the content that revision recorded")
		}
	})

	t.Run("a revert restores the bytes that revision recorded", func(t *testing.T) {
		id := oldestRevisionID(t, fx)
		resp := s.do(&call{
			method: http.MethodPost,
			path:   "/p/Index.md/revert/" + strconv.FormatInt(id, 10),
			csrf:   s.csrf,
		})
		s.read(resp)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status %d, want 303: a revert is a mutation and answers with the page it put back", resp.StatusCode)
		}
		want := original
		if got := string(mustReadFile(t, fx, "Index.md")); got != want {
			t.Errorf("the page after a revert is not the revision's bytes:\n got %q\nwant %q", got, want)
		}
	})

	t.Run("a revert to a revision that does not exist is a 404", func(t *testing.T) {
		resp := s.do(&call{
			method: http.MethodPost,
			path:   "/p/Index.md/revert/999999",
			csrf:   s.csrf,
		})
		s.read(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status %d, want 404", resp.StatusCode)
		}
	})

	t.Run("a player may not revert, and the refusal is the policy's", func(t *testing.T) {
		p := fx.asUser(otherName, otherPass)
		resp := p.do(&call{
			method: http.MethodPost,
			path:   "/p/Index.md/revert/" + strconv.FormatInt(oldestRevisionID(t, fx), 10),
			csrf:   p.csrf,
		})
		s.read(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("a player reverting a page: status %d, want 403", resp.StatusCode)
		}
	})
}

// TestRevisionRevocationIsAuthorised: a revision taken while a secret was
// readable by everybody stops being readable when it is not.
//
// This is the reason revisions store the whole file rather than a pointer, and
// it is the one test in this file that is about a disclosure rather than about a
// feature. The revoke is done through internal/secrets, because that is the only
// thing permitted to rewrite a fence's visibility, and the read is the ordinary
// HTTP read.
func TestRevisionRevocationIsAuthorised(t *testing.T) {
	t.Parallel()
	// A vault whose Tavern page holds exactly one secret, table-visible. The
	// fixture's own Tavern page will not do: it also holds DM and private
	// fences, so a player could never read a revision of it in the first place
	// and the "before" half of this test would be a 404 for the wrong reason.
	fx := newFixtureWith(t, map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
			fence("d4d4d4d4d4d4", "table", "dungeonmaster", "Shared with the table", "TABLE-BODY-TOKEN-5d0a8f"),
	})
	fx.accountsFor()
	s := fx.asUser(dmName, dmPass)
	player := fx.asUser(otherName, otherPass)

	// A revision of the page with the table-visible secret intact. The player can
	// read it, so the revision is servable to them.
	before := mustReadFile(t, fx, "Tavern.md")
	saveOK(t, s, "/p/Tavern.md/edit", string(before))
	id := newestRevisionIDOf(t, fx, "Tavern.md")
	revPath := "/p/Tavern.md/revisions/" + strconv.FormatInt(id, 10)

	resp := player.do(player.get(revPath))
	body := player.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the player reading a revision of a page whose only secret is table-visible: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, tableToken) {
		t.Error("the table secret is missing from a revision an authenticated player may read")
	}

	// Revoke it. internal/secrets is the only writer of a visibility token, and
	// the DM is one of the principals who may do it.
	admin := fx.tryAdminPrincipal()
	if err := fx.Secrets.SetVisibility(context.Background(), admin, "d4d4d4d4d4d4", authz.VisibilityDM); err != nil {
		t.Fatalf("revoke the table secret: %v", err)
	}
	fx.reindexAll()

	// The same revision, the same player, the same URL. A revision is
	// re-authorized at read time, so the revoke reaches backwards.
	resp2 := player.do(player.get(revPath))
	after := player.read(resp2)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("after the revoke the same revision answers %d, want 404: a revision is re-authorized at read time", resp2.StatusCode)
	}
	if strings.Contains(after, tableToken) {
		t.Error("the refused revision's body carries the revoked secret")
	}
	// And it is the router's 404, byte for byte, so the refusal is
	// indistinguishable from a revision that never existed.
	missing := player.do(player.get("/p/Tavern.md/revisions/999999"))
	if got := player.read(missing); got != after {
		t.Errorf("a revoked revision and a revision that never existed answer differently:\n revoked: %q\n missing: %q", after, got)
	}

	// And the DM, who may read the fence, still gets it — otherwise "reauthorized
	// at read time" would be a route that serves nobody.
	resp3 := s.do(s.get(revPath))
	dmBody := s.read(resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("the DM reading the same revision: status %d, want 200", resp3.StatusCode)
	}
	if !strings.Contains(dmBody, tableToken) {
		t.Error("the DM's own body is missing from a revision the DM may read")
	}
}

// TestTheRawViewLocksWhatTheReaderMayNotRead: the raw view is a text/plain
// response, so there is no template to audit — the tripwire in nav_test.go covers
// it in passing, and this asserts the two properties the tripwire cannot see: the
// label is the fixed one, and the whole fence goes rather than only its body.
func TestTheRawViewLocksWhatTheReaderMayNotRead(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	fx.accountsFor()
	player := fx.asUser(otherName, otherPass)
	dm := fx.asUser(dmName, dmPass)

	resp := player.do(player.get("/p/Tavern.md/raw"))
	body := player.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != rawContentType {
		t.Errorf("Content-Type is %q, want %q: a raw view served as text/html is a stored-XSS vector", ct, rawContentType)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options is %q, want nosniff", got)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control is %q; an authorization-dependent response must not be stored", cc)
	}

	// Everything the player may not read is a fixed label, and the label carries
	// nothing but the id.
	for _, secret := range []string{"PRIVATE-BODY-TOKEN-9f3a2c", "DM-BODY-TOKEN-7b1e4d", "OWNER-BODY-TOKEN-2a6e10"} {
		if strings.Contains(body, secret) {
			t.Errorf("the raw view carries %q", secret)
		}
	}
	// And the one he may read is in it, so the redaction is a decision rather
	// than a blanket removal.
	if !strings.Contains(body, tableToken) {
		t.Error("the raw view omits a table secret from an authenticated reader, who may read it")
	}
	// The label, for a fence this reader may not read. It is a DM fence and not
	// the table one, because authz.CanReadSecret lets every *authenticated*
	// principal read a table secret — Bram is one, so the table fence is in his
	// raw view in full and that is correct.
	if !strings.Contains(body, "⟨secret:b2b2b2b2b2b2 hidden⟩") {
		t.Error("the raw view does not carry the fixed label for a fence the reader may not read")
	}
	// The whole fence goes, not only the body: the directive line carries the
	// author, the title and the creation time, and each of those is a fact about
	// a secret this reader was refused.
	if strings.Contains(body, "visibility=dm author=") {
		t.Error("the raw view still carries a secret's directive line: the author, the title and the timestamp are all about the secret")
	}

	// A DM gets the file, because a DM may read every fence on it.
	resp2 := dm.do(dm.get("/p/Tavern.md/raw"))
	dmBody := dm.read(resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("the DM's raw view: status %d, want 200", resp2.StatusCode)
	}
	for _, secret := range []string{"PRIVATE-BODY-TOKEN-9f3a2c", "DM-BODY-TOKEN-7b1e4d", "OWNER-BODY-TOKEN-2a6e10", tableToken} {
		if !strings.Contains(dmBody, secret) {
			t.Errorf("the DM's raw view is missing %q, so a redaction is being applied to a principal that passed CanReadSecret", secret)
		}
	}
}

// TestAttachmentInSecretIsNotServed is §8.8's first half, end to end over HTTP.
//
// A file referenced only from inside a DM secret is served to a DM and to nobody
// else, and a name that was never indexed is not served at all — the same answer,
// because a route that could tell them apart confirms the existence of a DM's
// portrait to anybody who can guess a filename.
func TestAttachmentInSecretIsNotServed(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
			"A portrait of the landlord hangs in the common room.\n\n" +
			"```secret id=e1e1e1e1e1e1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The portrait\"\n" +
			"![portrait](portrait.png) " + searchWord + "\n```\n\n",
		"portrait.png": "\x89PNG\r\n\x1a\nnot-really-a-png",
	})
	fx.accountsFor()

	dm := fx.asUser(dmName, dmPass)
	player := fx.asUser(otherName, otherPass)
	// An anonymous reader with anonymous read *on*, which is the case
	// authz.SecretVisibleSQL alone does not close: its table clause says nothing
	// about a session, so an anonymous principal asking for a table secret is
	// answered by store.publicOnlySQL and by the CanReadPublic check at the top
	// of AttachmentVisibleTo. Both of those are inside the store, so this row is
	// the only thing that would notice if either were removed.
	anon := newFixtureWith(t, map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
			"```secret id=e1e1e1e1e1e1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"The portrait\"\n" +
			"![portrait](portrait.png) " + searchWord + "\n```\n\n",
		"portrait.png": "\x89PNG\r\n\x1a\nnot-really-a-png",
	}, func(c *config.Config) { c.AllowAnonymousRead = true })
	anon.accountsFor()
	anonS := anon.newSession()

	for _, tc := range []struct {
		name string
		s    *session
		want int
	}{
		{"the dm", dm, http.StatusOK},
		{"a player", player, http.StatusNotFound},
		{"an anonymous reader with read on", anonS, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.s.do(tc.s.get("/p/Tavern.md/attachment/portrait.png"))
			body := tc.s.read(resp)
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want != http.StatusOK {
				// A 404 with a body of its own is a probe, so the two refusals
				// are compared as bytes and not as statuses: "you may not have
				// this file" and "there is no such file" have to be the same
				// document.
				missing := tc.s.do(tc.s.get("/p/Nowhere at all.md/raw"))
				if got := tc.s.read(missing); got != body {
					t.Errorf("a refused attachment and a page that does not exist answer differently:\n attachment: %q\n page:      %q", body, got)
				}
				return
			}
			if csp := resp.Header.Get("Content-Security-Policy"); csp != attachmentCSP {
				t.Errorf("Content-Security-Policy is %q, want %q", csp, attachmentCSP)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options is %q, want nosniff", got)
			}
			if !strings.Contains(body, "not-really-a-png") {
				t.Error("the served bytes are not the file's")
			}
		})
	}
}

// TestPathTraversalRejected: the attachment name arrives from a URL, so the whole
// table of shapes somebody might put in one is a test case.
//
// Every case must be the same answer as a name that was never indexed, because
// store.AttachmentVisibleTo matches exactly and no recorded path is any of these.
//
// Tavern.md embeds portrait.png, so the boot index records it and there is a real
// row one request away: the table is refused against a name the index really
// holds, not against an empty table that would refuse anything.
func TestPathTraversalRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"parent directory", "../../semiplane.lock"},
		{"a single parent", "../Index.md"},
		{"absolute", "/etc/passwd"},
		{"a windows drive", "C:/Windows/win.ini"},
		{"backslash separator", `..\..\semiplane.lock`},
		// Percent-encoded, because net/url refuses to build a request with a raw
		// control character in it — so a literal NUL never reaches a server from a
		// browser, and the decoded one is the case worth testing.
		{"a nul byte", "portrait.png%00.txt"},
		{"a trailing slash", "portrait.png/"},
		{"a doubled separator", "portrait.png//x"},
		{"a dot segment", "./portrait.png"},
		{"percent-encoded parent", "..%2f..%2findex.md"},
		{"the app's own directory", ".semiplane/semiplane.lock"},
		{"an obsidian directory", ".obsidian/workspace.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixtureWith(t, map[string]string{
				"Index.md":     "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Tavern]].\n",
				"Tavern.md":    "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n![portrait](portrait.png)\n\nA portrait hangs here.\n",
				"portrait.png": "not-really-a-png",
			})
			fx.accountsFor()
			if got := len(mustPageAttachments(t, fx, "Tavern.md")); got != 1 {
				t.Fatalf("the boot index recorded %d files for Tavern.md, want 1: every case below would be refused by an empty table", got)
			}
			dm := fx.asUser(dmName, dmPass)

			resp := dm.do(dm.get("/p/Tavern.md/attachment/" + tc.raw))
			dm.read(resp)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET /p/Tavern.md/attachment/%s: status %d, want 404", tc.raw, resp.StatusCode)
			}
		})
	}
}

// TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks: the panel's whole
// difficulty is that a dangling reference inside a secret is a fact about that
// secret, so both the list and the count have to be filtered by the same
// predicate — and the count is where the leak would be, because a badge that
// counts what the list hides says how many secrets the reader cannot read.
func TestTheBrokenLinksPanelHidesSecretOnlyDanglingLinks(t *testing.T) {
	t.Parallel()
	// Two dangling links in public text, and one inside a DM secret, and one
	// inside a table secret: one panel, three answers, and the last two are the
	// same answer to a player.
	fx := newFixtureWith(t, map[string]string{
		"Index.md": "---\ntitle: Index\ntype: note\n---\n\n# Index\n\n[[No Such Page]] and [[Also Missing]].\n",
		"Tavern.md": "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\n" +
			"```secret id=e1e1e1e1e1e1 visibility=dm author=dungeonmaster created=2026-01-01T00:00:00Z title=\"Hidden\"\n" +
			"[[The Trap]] " + searchWord + "\n```\n\n" +
			"```secret id=e2e2e2e2e2e2 visibility=table author=dungeonmaster created=2026-01-01T00:00:00Z title=\"Shared\"\n" +
			"[[The Pact]] " + searchWord + "\n```\n\n",
	})
	fx.accountsFor()

	t.Run("the list and the badge agree for every role", func(t *testing.T) {
		for _, role := range []struct {
			name string
			s    *session
			as   string
			want []string
			not  []string
		}{
			{
				name: "the dm reads all three",
				s:    fx.asUser(dmName, dmPass),
				as:   dmName,
				want: []string{"No Such Page", "Also Missing", "The Trap", "The Pact"},
			},
			{
				// A player sees the two public ones and the table one, and the
				// count beside them says three. A badge of four would be the
				// leak: it is the number of DM secrets the reader cannot read.
				name: "a player reads three",
				s:    fx.asUser(otherName, otherPass),
				as:   otherName,
				want: []string{"No Such Page", "Also Missing", "The Pact"},
				not:  []string{"The Trap"},
			},
		} {
			resp := role.s.do(role.s.get("/broken"))
			body := role.s.read(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d, want 200", role.name, resp.StatusCode)
			}
			for _, want := range role.want {
				if !strings.Contains(body, want) {
					t.Errorf("%s: the panel does not list %q", role.name, want)
				}
			}
			for _, hidden := range role.not {
				if strings.Contains(body, hidden) {
					t.Errorf("%s: the panel lists %q, which only appears inside a secret this reader may not read", role.name, hidden)
				}
			}
			// The count and the list are the same question: the store returns
			// both from one constant, and this asserts the pair the template is
			// handed agrees with what the store would say.
			ctx := context.Background()
			total, err := store.CountVisibleUnresolvedLinks(ctx, fx.DB.Reader(), fx.principalFor(role.as))
			if err != nil {
				t.Fatalf("%s: count: %v", role.name, err)
			}
			rows, err := store.ListVisibleUnresolvedLinks(ctx, fx.DB.Reader(), fx.principalFor(role.as))
			if err != nil {
				t.Fatalf("%s: list: %v", role.name, err)
			}
			if total != len(rows) {
				t.Errorf("%s: the badge says %d and the list has %d rows; a panel whose badge disagrees with its own list is the leak", role.name, total, len(rows))
			}
			if total != len(role.want) {
				t.Errorf("%s: the count is %d, want %d", role.name, total, len(role.want))
			}
		}
	})
}

// TestTheDispatchLetsAPageNamedForASuffixStayAPage is the tie-break in
// pagedispatch.go, asserted end to end rather than on the routing table.
//
// "Guild/edit" is either a page at that path or the editor for "Guild", and the
// dispatcher resolves it in favour of the page — so a vault holding a page called
// edit.md inside a folder called Guild keeps that page openable, which is the
// whole reason the rule is "the page wins" and not "the action wins".
func TestTheDispatchLetsAPageNamedForASuffixStayAPage(t *testing.T) {
	t.Parallel()
	fx := newFixtureWith(t, map[string]string{
		"Index.md":      "---\ntitle: Index\ntype: note\n---\n\n# Index\n\nThe [[Guild/edit]] and the [[Tavern]].\n",
		"Tavern.md":     "---\ntitle: The Drowned Lantern\n---\n\n# The Drowned Lantern\n\nA dry room.\n",
		"Guild/edit.md": "---\ntitle: The Guild Ledger\n---\n\n# The Guild Ledger\n\nledger body\n",
	})
	fx.accountsFor()
	s := fx.asUser(dmName, dmPass)

	t.Run("a page whose path ends in a suffix is the page", func(t *testing.T) {
		resp := s.do(s.get("/p/Guild/edit.md"))
		body := s.read(resp)
		// The page is served, not the editor for a page called "Guild".
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if strings.Contains(body, `"Mode"`) {
			t.Error("a page named edit.md inside a folder named Guild is being served the editor for Guild")
		}
		if !strings.Contains(body, "ledger body") {
			t.Error("the page at Guild/edit.md is not being served its own body")
		}
	})

	t.Run("and the same suffix is the editor when no page answers to it", func(t *testing.T) {
		resp := s.do(s.get("/p/Tavern.md/edit"))
		body := s.read(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200: the editor is shadowed by a page that does not exist", resp.StatusCode)
		}
		// The editor's own hook, not a fragment of its text. This asserts that
		// the dispatcher chose the editor and nothing about what the editor
		// contains, which is the web package's business; a prose marker would
		// break the day the page is reworded, and the previous marker here was a
		// JSON key no response ever emitted, so the row asserted nothing.
		if !strings.Contains(body, "data-editor-form") {
			t.Error("GET /p/Tavern.md/edit did not reach the editor")
		}
	})
}

// TestTheEditorCapsTheSubmittedBuffer: a page is written through a body, so the
// cap on that body is the one number standing between an authenticated writer and
// an unbounded allocation. It is vault.MaxFileBytes, the same ceiling the
// indexer and vault.Read apply, and a submission above it is refused rather than
// trimmed — a trimmed body would write a page the author did not write.
func TestTheEditorCapsTheSubmittedBuffer(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	s := asDM(t, fx)

	over := strings.Repeat("x", int(vault.MaxFileBytes)+1)
	resp := s.do(&call{
		method: http.MethodPost,
		path:   "/p/Index.md/edit",
		form:   url.Values{"content": {over}, "base_hash": {baseHashOf(t, fx, "Index.md")}},
		csrf:   s.csrf,
	})
	s.read(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an editor submission of %d bytes: status %d, want 400", len(over), resp.StatusCode)
	}
	// And nothing was written: a cap that trimmed would have written a page of
	// x's.
	if got := string(mustReadFile(t, fx, "Index.md")); strings.Contains(got, "xxxx") {
		t.Error("a refused oversized submission still changed the file")
	}
}

// saveOK performs a save and fails the test unless it was accepted.
func saveOK(t *testing.T, s *session, path, content string) {
	t.Helper()
	fx := s.fx
	rel := strings.TrimPrefix(path, "/p/")
	rel = strings.TrimSuffix(rel, "/edit")
	resp := s.do(&call{
		method: http.MethodPost,
		path:   path,
		form:   url.Values{"content": {content}, "base_hash": {baseHashOf(t, fx, rel)}},
		csrf:   s.csrf,
	})
	s.read(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d, want 200", path, resp.StatusCode)
	}
}

// mustReadFile reads a vault file and fails the test if it cannot.
func mustReadFile(t *testing.T, fx *fixture, name string) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(fx.Root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return src
}

// mustPageID is a fixture page's index id.
func mustPageID(t *testing.T, fx *fixture, name string) int64 {
	t.Helper()
	id, ok := fx.pageIDByPath(name)
	if !ok {
		t.Fatalf("the index has no page for %s", name)
	}
	return id
}

// oldestRevisionID is the smallest revision id recorded for the index page,
// which is the first one anybody wrote.
func oldestRevisionID(t *testing.T, fx *fixture) int64 {
	t.Helper()
	rows, err := store.ListRevisionMetaByPage(context.Background(), fx.DB.Reader(), mustPageID(t, fx, "Index.md"), 50)
	if err != nil {
		t.Fatalf("read the revisions of Index.md: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Index.md has no revisions, so a history and a revert have nothing to act on")
	}
	out := rows[0].ID
	for _, r := range rows[1:] {
		if r.ID < out {
			out = r.ID
		}
	}
	return out
}

// mustPageAttachments returns the files the boot index recorded for one page.
//
// It replaces a helper that inserted the row by hand. That helper existed because
// nothing recorded an attachment at all, so every test here had to write the row
// the indexer should have written — and once the indexer does, a hand-written row
// for a page the index already covered violates the per-page constraint and fails
// the test for the wrong reason. Asserting the row is there is the same
// precondition stated honestly, and the *decision* is still entirely
// store.AttachmentVisibleTo's, over the links row the indexer really did record
// from the Markdown.
func mustPageAttachments(t *testing.T, fx *fixture, page string) []store.Attachment {
	t.Helper()
	rows, err := store.ListAttachmentsByPage(context.Background(), fx.DB.Reader(), mustPageID(t, fx, page))
	if err != nil {
		t.Fatalf("list the attachments of %s: %v", page, err)
	}
	return rows
}

// the raw view's content type, restated from the handler so a test can assert it
// without importing the package under test for one string.
const rawContentType = "text/plain; charset=utf-8"

// attachmentCSP, restated for the same reason.
const attachmentCSP = "default-src 'none'; sandbox"

// saveThroughTheEditor writes a page through the editor route as the DM, adding
// one line to it.
//
// It exists so that a test which needs a revision to walk can have one: the
// indexer records no revision at boot, so the only way a page acquires a
// revision is a real write, and a test that inserted a row would be walking a
// document no writer ever produced.
func saveThroughTheEditor(t *testing.T, fx *fixture, path string) {
	t.Helper()
	s := fx.asUser(dmName, dmPass)
	rel := strings.TrimSuffix(strings.TrimPrefix(path, "/p/"), "/edit")
	body := string(mustReadFile(t, fx, rel)) + "\nA line added through the editor.\n"
	resp := s.do(&call{
		method: http.MethodPost,
		path:   path,
		form:   url.Values{"content": {body}, "base_hash": {baseHashOf(t, fx, rel)}},
		csrf:   s.csrf,
	})
	defer drain(resp)
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s to produce a revision: status %d, want 200", path, resp.StatusCode)
	}
}

// newestRevisionIDOf is the largest revision id a page has, which is the one a
// walk should ask for: a route handed a stale id answers 404 and a 404 proves
// nothing about what it would serve.
func newestRevisionIDOf(t *testing.T, fx *fixture, name string) int64 {
	t.Helper()
	rows, err := store.ListRevisionMetaByPage(context.Background(), fx.DB.Reader(), mustPageID(t, fx, name), 50)
	if err != nil {
		t.Fatalf("read the revisions of %s: %v", name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no revisions, so there is nothing for the revision route to serve", name)
	}
	return rows[0].ID
}
