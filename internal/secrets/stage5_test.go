package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/search"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sync"
)

// The two words these tests search for.
//
// cycleProbe is the only word in the fixture's secret body that appears nowhere
// else in the corpus, so "this token is in no index" is a real assertion rather
// than a term the public prose happens to carry as well. cycleBrazier is the
// control: it is in the page's PUBLIC text and in no secret, so a search that
// answers nothing at all is distinguishable from a search that is working.
//
// Both are probes rather than secret bodies. Nothing in this file prints either
// one, and every assertion is on ids, paths, counts and lengths.
const (
	cycleProbe   = "verdigrisite"
	cycleBrazier = "brazier"
)

// cyclePage is the fixture behind both of the first two tests. Its one fence
// carries, inside a single secret, everything a page can derive from a hidden
// body: a heading, a link to a page that exists, a link to one that does not,
// and two tags. A test that pinned only the search index would be blind to four
// of the surfaces a revoke has to reach.
const cyclePage = "# The Safe\n\n" +
	"Public before the fence. The " + cycleBrazier + " stands by the door. See [[Target]].\n\n" +
	"```secret id=" + secretID + " visibility=dm author=dorn created=2026-09-28T10:04:11Z title=\"The Mayor's Door\"\n" +
	"## Hidden chapter\n\n" +
	"The " + cycleProbe + " is behind the cellar wall. See [[Target]] and [[Nowhere]], " +
	"and it carries #buriedprobe and #open-thread.\n" +
	"```\n\n" +
	"Public after the fence.\n"

// cycleNeighbour carries its shared tag inside a fence of its own. That is what
// makes the tag a measurement rather than a constant: a tag that is public
// anywhere in the vault is never absent from the cloud, so a cloud assertion
// built on one would read 1 at every step and prove nothing. Hidden on both
// sides, the tag goes 0, 2, 0 — and the related panel, which intersects the two
// pages' VISIBLE tags, goes 0, 1, 0 with it.
const cycleNeighbour = "# Neighbour\n\n" +
	"Shares only what a fence holds.\n\n" +
	"```secret id=" + cycleNeighbourSecret + " visibility=dm author=dorn created=2026-09-28T10:04:11Z\n" +
	"Tagged #buriedprobe from inside a fence of its own.\n```\n"

const cycleTarget = "# Target\n\nA page the safe's fence points at.\n"

// cycleNeighbourSecret is the second fence's id. It is named because the steps
// above open and close both fences, and a test that wrote the literal twice
// would be one edit away from revealing the same secret twice and proving
// nothing.
const cycleNeighbourSecret = "bbbbbbbbbbbb"

func cycleVault() map[string]string {
	return map[string]string{
		"Page.md":      cyclePage,
		"Target.md":    cycleTarget,
		"Neighbour.md": cycleNeighbour,
	}
}

// assertNoProbe fails when a surface carries a probe word. The message names the
// surface and never the word or the body it came from: a failure here is printed
// to a CI log, and this whole file exists because a body reached one.
func assertNoProbe(t *testing.T, where, haystack string, probes ...string) {
	t.Helper()
	for _, p := range probes {
		if p != "" && strings.Contains(haystack, p) {
			t.Errorf("%s carries a body that was never meant to be there", where)
		}
	}
}

// secretFTSHits and pageFTSHits count what a MATCH on a probe finds, which is the
// question the index is actually asked. A row that exists is not a row that is
// found, and a purge that deleted the row but left the FTS entry behind would
// pass a row-count assertion.
func secretFTSHits(t *testing.T, h *harness, term string) int64 {
	t.Helper()
	if term == "" {
		t.Fatal("a FTS assertion was given an empty term, so it would match everything")
	}
	return h.count(`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, term)
}

func pageFTSHits(t *testing.T, h *harness, term string) int64 {
	t.Helper()
	if term == "" {
		t.Fatal("a FTS assertion was given an empty term, so it would match everything")
	}
	return h.count(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, term)
}

// playerSearch runs the REAL search path — the package that answers "what can
// this reader find" — rather than querying a table. A purge that left a row
// behind in some table the search path does not read would be invisible to a
// direct query and very visible to a player, so the claim is made where the
// claim lives. It is reachable from the external test package because search
// sits above secrets in the dependency order and imports nothing of ours but
// authz.
//
// Both halves of the result are returned rather than just the rows: Total is a
// sum of two separately filtered counts, so a leak that only the count shows
// would be missed by an assertion on the rows alone.
func playerSearch(t *testing.T, h *harness, p authz.Principal, term string) search.Result {
	t.Helper()
	res, err := search.Query(context.Background(), h.db.Reader(), p, term, search.Options{})
	if err != nil {
		t.Fatalf("search over %d bytes of input: %v", len(term), err)
	}
	return res
}

// TestRevealRevokeCycle is the end-to-end claim, over the real service: a reveal
// puts the body where a player can find it and nowhere else, a revoke takes it
// away again before the call returns, and both write an audit row that says which
// way the change went.
//
// Four things are asserted that a table-count test would not catch, and they are
// the reason this is not a store test:
//
//   - page_text is byte-identical across the reveal. A reveal is a file mutation
//     (§8.3) and a database reindex; a reveal that also re-derived the public text
//     would put the body into a table with no visibility column to filter it in.
//   - The term is searched through internal/search, so the claim is what a player
//     finds rather than what a table holds. search is above secrets in the
//     dependency order, which is why the assertion is reachable from the external
//     test package and not from inside it.
//   - The purge is not the reindex's work. A revoke that only purged because the
//     indexer caught up a moment later would be correct by accident and would
//     still be serving the body to a player in between.
//   - An idempotent reveal writes nothing at all, which is why the audit trail can
//     be read as a record of changes.
func TestRevealRevokeCycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, cycleVault())
	id := pageID(t, h, "Page.md")
	player, dm := h.player(), h.dm()

	// ---- the fixture really is what the assertions assume.
	//
	// Without these the whole test is satisfiable by a fixture that had nothing
	// to change: a page with no fence, or a fence the indexer skipped, would
	// answer "the body is in no index" no matter what the reveal did.
	if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "dm" {
		t.Fatalf("the fixture indexed the secret at %q, want dm", got)
	}
	if got := h.count(`SELECT COUNT(*) FROM secrets WHERE id = ? AND body LIKE ?`,
		secretID, "%"+cycleProbe+"%"); got != 1 {
		t.Fatal("the fixture's secret body does not hold the probe, so the assertions below would pass for the wrong reason")
	}
	before := h.vault.ReadFile(t, "Page.md")
	publicBefore := h.text(`SELECT body FROM page_text WHERE page_id = ?`, id)
	if !strings.Contains(publicBefore, cycleBrazier) {
		t.Fatal("the fixture's public text does not hold the control word, so a search that found nothing would look correct")
	}
	gen0 := mustGen(t, h)
	if got := playerSearch(t, h, player, cycleBrazier); len(got.Hits) == 0 || got.Total == 0 {
		t.Fatal("the public page is not findable before the reveal, so the search path is not answering")
	}
	if got := playerSearch(t, h, player, cycleProbe); len(got.Hits) != 0 || got.Total != 0 {
		t.Fatalf("a hidden secret is findable before its reveal: %d hits, total %d", len(got.Hits), got.Total)
	}

	// ---- the reveal.
	if err := h.svc.Reveal(ctx, dm, secretID); err != nil {
		t.Fatalf("reveal: %v", err)
	}

	// It is a file mutation and only a file mutation: the visibility token moved,
	// the bytes around it did not. A reveal that re-indented or re-serialised
	// would be a rewrite of the DM's Markdown by the app (§5.3).
	after := h.vault.ReadFile(t, "Page.md")
	if bytes.Equal(before, after) {
		t.Fatal("the reveal did not change the file, so the index that followed came from nothing")
	}
	if want := withVisibility(before, "dm", "table"); !bytes.Equal(want, after) {
		t.Error("the reveal changed more than the visibility token")
	}

	// The body is findable now, and findable as a SECRET: a hit that came back as
	// a page hit would mean the fence had stopped being a fence, and the
	// paragraph below is the assertion that it did not.
	found := playerSearch(t, h, player, cycleProbe)
	hits := found.Hits
	if len(hits) != 1 {
		t.Fatalf("a player finds %d hits for a revealed secret, want 1", len(hits))
	}
	if hits[0].Kind != search.KindSecret {
		t.Errorf("the hit is a %s hit, want a secret hit", hits[0].Kind)
	}
	if hits[0].SecretID != secretID {
		t.Errorf("the hit names secret %q, want %q", hits[0].SecretID, secretID)
	}
	if hits[0].Path != "Page.md" {
		t.Errorf("the hit is attributed to %q, want Page.md", hits[0].Path)
	}
	// A secret hit renders the fence, not the body, so the snippet is empty by
	// construction. A non-empty one would be the body in a search result.
	if hits[0].Snippet != "" {
		t.Errorf("a secret hit carries a %d-byte snippet", len(hits[0].Snippet))
	}
	if hits[0].Title != "The Safe" {
		t.Errorf("the hit is titled %q, want the public title", hits[0].Title)
	}

	// And the public half never heard of it. Asserted on the bytes, not on "it
	// looks the same": a reindex that rewrote page_text with the same length and
	// different content would pass a length check.
	publicAfter := h.text(`SELECT body FROM page_text WHERE page_id = ?`, id)
	if publicAfter != publicBefore {
		t.Error("the reveal rewrote page_text; the public body must be byte-identical across a visibility change")
	}
	for _, col := range []string{"title", "headings", "body"} {
		assertNoProbe(t, "page_text."+col, pageTextColumn(t, h, id, col), cycleProbe)
	}
	if got := pageFTSHits(t, h, cycleProbe); got != 0 {
		t.Errorf("a revealed secret is in the public index in %d rows", got)
	}
	if got := secretFTSHits(t, h, cycleProbe); got != 1 {
		t.Errorf("a revealed secret is findable in %d secret index rows, want 1", got)
	}

	// An anonymous request with public read on finds the page and not the secret.
	// The canonical predicate says `s.visibility = 'table'` and says nothing about
	// a session, so this compensation is the only thing closing the gap and it is
	// asserted here rather than in a table.
	anon := authz.Anonymous(true)
	if got := playerSearch(t, h, anon, cycleProbe); len(got.Hits) != 0 || got.Total != 0 {
		t.Errorf("an anonymous reader finds %d hits for a revealed secret", len(got.Hits))
	}
	if got := playerSearch(t, h, anon, cycleBrazier); len(got.Hits) == 0 || got.Total == 0 {
		t.Error("an anonymous reader with public read on cannot find the public page")
	}
	// And a principal that never went through the session middleware at all is
	// anonymous with read OFF, which is a different principal and a different
	// answer.
	if got := playerSearch(t, h, authz.Anonymous(false), cycleBrazier); len(got.Hits) != 0 || got.Total != 0 {
		t.Errorf("a principal with public read off found %d public hits", len(got.Hits))
	}

	// The audit row says which way the change went, and says nothing else.
	events := mustSecretEvents(t, h, secretID)
	if len(events) != 1 {
		t.Fatalf("the trail has %d rows after one reveal, want 1", len(events))
	}
	assertEvent(t, events[0], store.SecretActionReveal, "dm", "table", h.dmID)
	// The trail is a log of decisions, not of text: a row that carried the body
	// would be a copy of every secret in a table with no visibility column, and
	// the audit panel would be the one surface with no predicate on it.
	assertNoProbe(t, "the audit trail", fmtEvents(events), cycleProbe)

	// The counter moved. The exact step is not pinned here, and deliberately:
	// SetVisibility bumps the counter for its own audit write, and the reindex
	// that follows bumps it again because the fence's visibility changed on
	// disk. So one logical reveal moves it by two, which is harmless — the
	// counter is a monotonic epoch and a stream only compares it for equality —
	// but a test that asserted "+1" over a service call would be pinning that
	// redundancy rather than a contract. The exact one-step pairing IS pinned, in
	// internal/store's TestAuthzGenerationBumped, over a transaction with no
	// reindex behind it. The durable claim on this side is the trail: one event.
	genAfterReveal := mustGen(t, h)
	if genAfterReveal <= gen0 {
		t.Errorf("the reveal moved the generation from %d to %d, which is not a move", gen0, genAfterReveal)
	}

	// ---- an idempotent reveal writes nothing at all.
	//
	// This is what makes the trail readable: a reader who sees two reveals knows
	// two things changed, because a reveal that changed nothing left no mark.
	// The file bytes, the generation and the trail are all asserted, and the
	// reindex counter is asserted because a no-op that still reindexed would be a
	// no-op that could not be cheap.
	reindexes := h.reindexes.Load()
	if err := h.svc.Reveal(ctx, dm, secretID); err != nil {
		t.Fatalf("second reveal: %v", err)
	}
	if !bytes.Equal(after, h.vault.ReadFile(t, "Page.md")) {
		t.Error("an idempotent reveal changed the file")
	}
	if got := mustGen(t, h); got != genAfterReveal {
		t.Errorf("an idempotent reveal moved the generation from %d to %d", genAfterReveal, got)
	}
	if got := len(mustSecretEvents(t, h, secretID)); got != 1 {
		t.Errorf("an idempotent reveal left %d audit rows, want 1", got)
	}
	if got := h.reindexes.Load(); got != reindexes {
		t.Error("an idempotent reveal re-indexed the page")
	}

	// ---- the revoke.
	if err := h.svc.Revoke(ctx, dm, secretID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := secretFTSHits(t, h, cycleProbe); got != 0 {
		t.Errorf("a revoked secret is still findable in %d secret index rows", got)
	}
	if got := h.count(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, secretID); got != 0 {
		t.Errorf("a revoke left %d search-index rows behind", got)
	}
	if got := pageFTSHits(t, h, cycleProbe); got != 0 {
		t.Errorf("a revoked secret reached the public index in %d rows", got)
	}
	if n, err := store.CheckSecretIndexInvariant(ctx, h.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d after a revoke (err %v), want 0", n, err)
	}
	// The body is still in the file and still in the secrets table: a revoke is a
	// change of audience, not a deletion, and a test that asserted otherwise
	// would be asserting a bug. So the file must STILL hold the body — asserted
	// positively, because a negative assertion here cannot tell a revoke from a
	// deletion.
	if !strings.Contains(string(h.vault.ReadFile(t, "Page.md")), cycleProbe) {
		t.Error("the revoke removed the body from the file; a revoke changes the audience, not the text")
	}
	if got := h.count(`SELECT COUNT(*) FROM secrets WHERE id = ? AND visibility = ?`,
		secretID, string(secrets.VisibilityPrivate)); got != 1 {
		t.Error("the revoke did not take; the secret is not private afterwards")
	}
	// The DM may still read it, and the player still may not. A revoke that
	// revoked the body's existence would fail this, and one that only hid the
	// search copy would fail the player's read.
	if _, err := h.svc.Load(ctx, dm, secretID); err != nil {
		t.Errorf("the DM cannot read a secret after a revoke: %v", err)
	}
	if _, err := h.svc.Load(ctx, player, secretID); !errors.Is(err, store.ErrNoRows) {
		t.Errorf("a player loaded a revoked secret: %v", err)
	}

	// The body is gone from the SEARCH for everybody, the DM included. A purge
	// that only removed the players' view — by filtering rather than by deleting
	// the row — would pass the player's assertion above and leave the body in a
	// table the next feature reads without a predicate.
	if got := playerSearch(t, h, dm, cycleProbe); len(got.Hits) != 0 || got.Total != 0 {
		t.Errorf("a revoked secret is still findable by the DM: %d hits", len(got.Hits))
	}

	events = mustSecretEvents(t, h, secretID)
	if len(events) != 2 {
		t.Fatalf("the trail has %d rows after a reveal and a revoke, want 2", len(events))
	}
	assertEvent(t, events[0], store.SecretActionRevoke, "table", "private", h.dmID)
	if got := mustGen(t, h); got <= genAfterReveal {
		t.Errorf("the revoke moved the generation to %d, which is not a move from %d", got, genAfterReveal)
	}
	// And the public text is still byte-identical after the round trip, which is
	// the "unchanged by a reveal" claim taken through the whole cycle rather
	// than to the midpoint.
	if got := h.text(`SELECT body FROM page_text WHERE page_id = ?`, id); got != publicBefore {
		t.Error("page_text is not the same after a reveal and a revoke as it was before both")
	}

	// The purge is the revoke's own work, not the reindex's. A service whose
	// reindexer refuses still has to have purged, because the reindex is the
	// step that is allowed to fail and a body served in the window between the
	// revoke returning and the reconciliation scan is a body served.
	t.Run("the purge does not wait for the reindex", func(t *testing.T) {
		t.Parallel()
		g := newHarness(t, cycleVault())
		if err := g.svc.Reveal(ctx, g.dm(), secretID); err != nil {
			t.Fatalf("reveal: %v", err)
		}
		if got := playerSearch(t, g, g.player(), cycleProbe); len(got.Hits) != 1 {
			t.Fatalf("the fixture is not revealed: %d hits", len(got.Hits))
		}
		genBefore := mustGen(t, g)

		// A second service over the same vault, the same database and the same
		// writer, wired to a reindexer that refuses. Nothing is rebuilt: the
		// harness is not used a second time, only its components.
		broken, err := secrets.NewService(secrets.Options{
			DB: g.db, Writer: g.writer, Policy: authz.NewPolicy(false),
			Reindexer: failingReindexer{}, Log: g.log, Clock: func() time.Time { return clockNow },
		})
		if err != nil {
			t.Fatalf("build a service with a refusing reindexer: %v", err)
		}
		if err := broken.Revoke(ctx, g.dm(), secretID); err == nil {
			t.Fatal("a revoke whose reindex failed reported success")
		}

		if got := playerSearch(t, g, g.player(), cycleProbe); len(got.Hits) != 0 || got.Total != 0 {
			t.Errorf("the body is still findable after a revoke whose reindex failed: %d hits", len(got.Hits))
		}
		if got := secretFTSHits(t, g, cycleProbe); got != 0 {
			t.Errorf("a revoke whose reindex failed left %d search-index rows", got)
		}
		evs := mustSecretEvents(t, g, secretID)
		if len(evs) != 2 {
			t.Fatalf("the trail has %d rows after a reveal and a failing revoke, want 2", len(evs))
		}
		assertEvent(t, evs[0], store.SecretActionRevoke, "table", "private", g.dmID)
		if got := mustGen(t, g); got <= genBefore {
			t.Errorf("a revoke whose reindex failed moved the generation from %d to %d, which is not a move",
				genBefore, got)
		}
	})
}

// TestRevokePurgesAllIndexes is the claim the plan separates into "the backlink
// list" and "the backlink count", because they are two constants and a filter
// added to one and not the other is invisible from Go.
//
// The asymmetry that makes it worth writing: a page has no visibility at all
// (AGENTS.md §7), so a `table` secret's body is in secret_fts and is still in no
// page_text row and in no public MATCH — while its heading, its two links and its
// two tags ARE indexed, attributed to the secret, and are held back by a
// predicate rather than by their absence. A revoke therefore has to take out
// something that is present, and a test that only checked the search index would
// pass on an implementation that left every panel in place.
//
// Nine surfaces, each measured at three points (before, while revealed, after the
// revoke) and each compared against the value from before the reveal rather than
// against zero.
func TestRevokePurgesAllIndexes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarnessAs(t, cycleVault(), true)
	page := pageID(t, h, "Page.md")
	target := pageID(t, h, "Target.md")
	player := h.player()
	anon := authz.Anonymous(true)

	// The unfiltered reads, taken once. These are what the reveal is NOT allowed
	// to change; if one of them moved, every filtered number below would be
	// proved by a change in the data rather than by the predicate.
	linksUnfiltered := h.count(`SELECT COUNT(*) FROM links WHERE target_page_id = ?`, target)
	headingsUnfiltered := h.count(`SELECT COUNT(*) FROM headings WHERE page_id = ?`, page)
	tagsUnfiltered := h.count(`SELECT COUNT(*) FROM page_tags WHERE page_id = ?`, page)
	if linksUnfiltered != 2 || headingsUnfiltered != 2 || tagsUnfiltered != 2 {
		t.Fatalf("the fixture holds %d links, %d headings and %d tags, want 2 of each",
			linksUnfiltered, headingsUnfiltered, tagsUnfiltered)
	}
	// The neighbour's fence is a second secret, and the steps open and close it
	// alongside the first. Without it there is nothing to intersect, so its
	// presence is part of the fixture rather than of the test.
	if got := h.count(`SELECT COUNT(*) FROM page_tags WHERE secret_id = ?`,
		cycleNeighbourSecret); got != 1 {
		t.Fatalf("the neighbour's fence holds %d tags, want 1", got)
	}

	// Each derived row must be attributed to the secret it came from, or the
	// predicates below have nothing to filter on and would pass by default.
	if got := h.count(`SELECT COUNT(*) FROM links WHERE target_page_id = ? AND secret_id = ?`,
		target, secretID); got != 1 {
		t.Fatalf("%d of the fixture's links are attributed to the secret, want 1", got)
	}
	if got := h.count(`SELECT COUNT(*) FROM page_tags WHERE page_id = ? AND secret_id = ?`,
		page, secretID); got != 2 {
		t.Fatalf("%d of the fixture's tags are attributed to the secret, want 2", got)
	}

	// Deliberately sequential: each step starts from where the previous one left
	// off, and the sequence — hidden, revealed, hidden again — is the claim. The
	// last step must return to the first step's numbers, so a predicate that only
	// ever widened the result set would fail it.
	for _, step := range []struct {
		name string
		// ops are the service calls this step makes before it measures, in
		// order; an empty list measures the state the previous step left. Both
		// fences are opened and closed together, because the related panel
		// intersects the two pages' VISIBLE tags and a tag open on one page and
		// hidden on the other intersects to nothing — which is the predicate
		// working, and is why opening only Page.md's fence would measure nothing
		// there.
		ops []string
		// revealed is whether this step's snapshot is taken with the secret open
		// to the table.
		revealed bool
		// headings is the length of a player's table of contents at this point.
		headings int
		// links is the number of backlinks to the linked page.
		links int
		// dangling is the number of unresolved references anywhere.
		dangling int
		// sharedTag is the page count the tag cloud and the tag page report for
		// the tag both fences carry: two pages while revealed, none otherwise.
		sharedTag int
		// related is the length of the related panel for the page.
		related int
		// threadTag is the page count for the tag only Page.md's fence carries,
		// and the number of open threads the campaign status reports.
		threadTag int
		// secrets is the number of secret rows the player may see.
		secrets int
	}{
		{"before the reveal", nil, false, 1, 1, 0, 0, 0, 0, 0},
		{"while both fences are revealed", []string{"reveal", "reveal"}, true, 2, 2, 1, 2, 1, 1, 1},
		{"after both are revoked", []string{"revoke", "revoke"}, false, 1, 1, 0, 0, 0, 0, 0},
	} {
		step := step
		t.Run(step.name, func(t *testing.T) {
			for i, op := range step.ops {
				id := secretID
				if i > 0 {
					id = cycleNeighbourSecret
				}
				switch op {
				case "reveal":
					if err := h.svc.Reveal(ctx, h.dm(), id); err != nil {
						t.Fatalf("reveal %s: %v", op, err)
					}
				case "revoke":
					if err := h.svc.Revoke(ctx, h.dm(), id); err != nil {
						t.Fatalf("revoke %s: %v", op, err)
					}
				default:
					t.Fatalf("the step asked for %q, which is not a call this test makes", op)
				}
			}

			// 1. The search index, in both halves.
			wantSecretHits := int64(0)
			if step.revealed {
				wantSecretHits = 1
			}
			if got := secretFTSHits(t, h, cycleProbe); got != wantSecretHits {
				t.Errorf("the secret index holds %d matching rows, want %d", got, wantSecretHits)
			}
			if got := h.count(`SELECT COUNT(*) FROM secret_text WHERE secret_id = ?`, secretID); got != wantSecretHits {
				t.Errorf("secret_text holds %d rows for the secret, want %d", got, wantSecretHits)
			}
			if got := pageFTSHits(t, h, cycleProbe); got != 0 {
				t.Errorf("the secret reached the public index in %d rows", got)
			}
			if got := h.count(`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, cycleBrazier); got != 1 {
				t.Errorf("the public page is findable in %d rows, want 1: the control word is missing", got)
			}
			if n, err := store.CheckSecretIndexInvariant(ctx, h.db.Reader()); err != nil || n != 0 {
				t.Errorf("the secret index invariant is %d (err %v), want 0", n, err)
			}

			// 2. The public text, which a reveal may not touch in either
			// direction. The byte-identity of the whole row is
			// TestRevealRevokeCycle's claim; here it is enough that no column of
			// it ever carries the body, which is the half that is a leak.
			for _, col := range []string{"title", "headings", "body"} {
				if got := pageTextColumn(t, h, page, col); strings.Contains(got, cycleProbe) {
					t.Errorf("page_text.%s carries the secret's body", col)
				}
			}

			// 3. The table of contents, list and count.
			toc, err := store.TOC(ctx, h.db.Reader(), player, page)
			if err != nil {
				t.Fatalf("table of contents: %v", err)
			}
			if len(toc) != step.headings {
				t.Errorf("a player's table of contents has %d entries, want %d", len(toc), step.headings)
			}
			tocCount, err := store.HeadingCount(ctx, h.db.Reader(), player, page)
			if err != nil {
				t.Fatalf("heading count: %v", err)
			}
			if tocCount != len(toc) {
				t.Errorf("HeadingCount = %d but the list has %d rows", tocCount, len(toc))
			}
			if tocCount != step.headings {
				t.Errorf("HeadingCount = %d, want %d", tocCount, step.headings)
			}

			// 4. The backlink panel. The count is a separate statement from the
			// list and is asserted against the plan's number, not against the
			// list's length: a count that agreed with an over-broad list would
			// satisfy count-equals-list and leak in the same assertion.
			assertBacklinkPair(t, h, player, target, step.links)
			// 5. The broken-links panel, which is a different constant built
			// from the same predicate.
			dangling, err := store.ListVisibleUnresolvedLinks(ctx, h.db.Reader(), player)
			if err != nil {
				t.Fatalf("dangling links: %v", err)
			}
			if len(dangling) != step.dangling {
				t.Errorf("a player sees %d dangling links, want %d", len(dangling), step.dangling)
			}
			dnCount, err := store.CountVisibleUnresolvedLinks(ctx, h.db.Reader(), player)
			if err != nil {
				t.Fatalf("dangling count: %v", err)
			}
			if dnCount != step.dangling {
				t.Errorf("CountVisibleUnresolvedLinks = %d, want %d", dnCount, step.dangling)
			}

			// 6. The tag cloud and the tag page, which are two more list-and-count
			// pairs built from their own copy of the predicate over page_tags.
			assertTagCloud(t, h, player, "buriedprobe", step.sharedTag)
			assertTagPages(t, h, player, "buriedprobe", step.sharedTag)
			assertTagCloud(t, h, player, store.TagOpenThread, step.threadTag)
			assertTagPages(t, h, player, store.TagOpenThread, step.threadTag)

			// 7. The related panel and the campaign-status rollups.
			related, err := store.ListRelatedPages(ctx, h.db.Reader(), player, page, 10)
			if err != nil {
				t.Fatalf("related pages: %v", err)
			}
			if len(related) != step.related {
				t.Errorf("a player sees %d related pages, want %d", len(related), step.related)
			}
			assertOpenThreads(t, h, player, step.threadTag)

			// 8. The secret panel itself: the rows and their count.
			rows, err := store.ListVisibleSecretRowsByPage(ctx, h.db.Reader(), player, page)
			if err != nil {
				t.Fatalf("visible secret rows: %v", err)
			}
			if len(rows) != step.secrets {
				t.Errorf("a player sees %d secret rows, want %d", len(rows), step.secrets)
			}
			sCount, err := store.CountVisibleSecrets(ctx, h.db.Reader(), player, page)
			if err != nil {
				t.Fatalf("count visible secrets: %v", err)
			}
			if sCount != len(rows) || sCount != step.secrets {
				t.Errorf("CountVisibleSecrets = %d, the list has %d rows, the plan says %d",
					sCount, len(rows), step.secrets)
			}

			// 9. An anonymous reader. The canonical predicate has no
			// authentication term, so publicOnlySQL is the only thing holding
			// this line, and it has to hold it WHILE the secret is open: that is
			// the step where a `table` row is actually present to be served.
			assertBacklinkPair(t, h, anon, target, 1)
			anonTOC, err := store.TOC(ctx, h.db.Reader(), anon, page)
			if err != nil {
				t.Fatalf("anonymous table of contents: %v", err)
			}
			if len(anonTOC) != 1 {
				t.Errorf("an anonymous reader sees %d headings, want 1", len(anonTOC))
			}
			for _, tag := range []string{store.TagOpenThread, "buriedprobe"} {
				assertTagCloud(t, h, anon, tag, 0)
				assertTagPages(t, h, anon, tag, 0)
			}
			anonRelated, err := store.ListRelatedPages(ctx, h.db.Reader(), anon, page, 10)
			if err != nil {
				t.Fatalf("anonymous related pages: %v", err)
			}
			if len(anonRelated) != 0 {
				t.Errorf("an anonymous reader sees %d related pages, want 0", len(anonRelated))
			}
			if got := playerSearch(t, h, anon, cycleProbe); len(got.Hits) != 0 || got.Total != 0 {
				t.Errorf("an anonymous reader finds %d hits for the secret's term", len(got.Hits))
			}
			if got := playerSearch(t, h, anon, cycleBrazier); len(got.Hits) == 0 || got.Total == 0 {
				t.Error("an anonymous reader with public read on cannot find the public page")
			}

			// The unfiltered reads have not moved. Nothing in this test is
			// allowed to have deleted a row.
			if got := h.count(`SELECT COUNT(*) FROM links WHERE target_page_id = ?`, target); got != linksUnfiltered {
				t.Errorf("the links table holds %d rows, want a constant %d", got, linksUnfiltered)
			}
			if got := h.count(`SELECT COUNT(*) FROM headings WHERE page_id = ?`, page); got != headingsUnfiltered {
				t.Errorf("the headings table holds %d rows, want a constant %d", got, headingsUnfiltered)
			}
			if got := h.count(`SELECT COUNT(*) FROM page_tags WHERE page_id = ?`, page); got != tagsUnfiltered {
				t.Errorf("the page_tags table holds %d rows, want a constant %d", got, tagsUnfiltered)
			}
		})
	}

	// The DM sees the secret at every one of the three points and the trail says
	// why, which is the other half of the audit view: a revoke that hid the
	// decision from the only principal who made it would make the trail
	// unreadable to the person who needs it.
	dmRows, err := store.ListVisibleSecretRowsByPage(ctx, h.db.Reader(), h.dm(), page)
	if err != nil {
		t.Fatalf("dm rows: %v", err)
	}
	if len(dmRows) != 1 {
		t.Errorf("a DM sees %d secret rows after the round trip, want 1", len(dmRows))
	}
}

// TestOnlyDMMayReveal asserts that the refusal is a REFUSAL.
//
// A non-nil error is the easy half. The halves that matter are the ones a
// "denied" path that still did the work would pass: a file rewritten, an audit
// row appended, a generation bumped. Any of those on a refused reveal is a
// disclosure of its own — the trail says who asked to open what, and a
// generation that moves on a refusal tears down every live stream in the
// campaign.
//
// The fixture ordering is load-bearing and is the bug AGENTS.md §11 records: the
// ownership grant has to come AFTER the accounts exist and AFTER the index pass,
// because a reindex drops the derived index and a grant that names a page row
// which no longer exists names nothing. `ownerEstablished` below proves the
// ownership is real at the moment the assertion runs, which is the assertion the
// ordering bug would have disarmed.
func TestOnlyDMMayReveal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t, map[string]string{"Page.md": pageWithFence})
	page := pageID(t, h, "Page.md")
	pia, err := store.GetUserByUsername(ctx, h.db.Reader(), "pia")
	if err != nil {
		t.Fatalf("read the player account: %v", err)
	}

	// Reindex first, then grant. The other order is the trap: `pageWithFence`
	// names `dorn` as the author, and resolving that name to a user id is what
	// the index pass does, so a grant made before it names a page row that the
	// pass is about to drop.
	giveOwnership(t, h, page, pia.ID)
	ownerEstablished(t, h, page, pia.ID)

	player, dm, anon := h.player(), h.dm(), authz.Anonymous(true)
	policy := authz.NewPolicy(false)

	// The policy still refuses with the page in the resource, so the refusal
	// below is about the permission and not about a missing page id. This is the
	// gate a zero-resource check would not have asked, and it is why
	// secrets.Service passes PermDM rather than a page-scoped permission.
	res := authz.SecretOf(page, true, h.dmID, secrets.VisibilityDM)
	if err := policy.Check(player, authz.PermDM, res); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("the policy lets a page owner reach the DM permission: %v", err)
	}
	if err := policy.Check(dm, authz.PermDM, res); err != nil {
		t.Fatalf("the fixture's DM is refused by the policy, so the test is broken: %v", err)
	}

	for _, tc := range []struct {
		name string
		who  authz.Principal
		// call is the surface under test. Both are named, because a gate applied
		// to reveal and forgotten on revoke would leave a page owner able to
		// close a secret that a DM opened.
		call func(secretID string) error
		// wantErr is the sentinel the refusal must carry. Every row is
		// ErrDenied, including the anonymous ones: PermDM is a role question and
		// a signed-out caller has no role. ErrNotAuthenticated belongs to the
		// permissions that ask for a session first, and a gate that answered
		// 401 here would be telling a signed-out caller something about the
		// campaign it has no business learning.
		wantErr error
	}{
		{"a page owner may not reveal", player, func(id string) error { return h.svc.Reveal(ctx, player, id) }, authz.ErrDenied},
		{"a page owner may not revoke", player, func(id string) error { return h.svc.Revoke(ctx, player, id) }, authz.ErrDenied},
		{"an anonymous reader may not reveal", anon, func(id string) error { return h.svc.Reveal(ctx, anon, id) }, authz.ErrDenied},
		{"an anonymous reader may not revoke", anon, func(id string) error { return h.svc.Revoke(ctx, anon, id) }, authz.ErrDenied},
		// An id that is not in the vault. The refusal must be the SAME refusal:
		// if a missing secret produced ErrNoRows, the endpoint is an existence
		// oracle for secret ids and the policy gate is doing nothing.
		{"a missing secret is refused, not reported as missing", player, func(string) error {
			return h.svc.Reveal(ctx, player, "000000000000")
		}, authz.ErrDenied},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before := h.vault.ReadFile(t, "Page.md")
			gen := mustGen(t, h)
			reindexes := h.reindexes.Load()
			events := len(mustSecretEvents(t, h, secretID))

			err := tc.call(secretID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("the call returned %v, want %v from the policy", err, tc.wantErr)
			}
			// Whatever the sentinel, it has to be a refusal from the gate and not
			// an error from somewhere further in: a missing id that answered
			// ErrNoRows would be a different answer for a different caller.
			if !errors.Is(err, authz.ErrDenied) {
				t.Errorf("the refusal is %v, which does not unwrap to authz.ErrDenied", err)
			}
			if !bytes.Equal(before, h.vault.ReadFile(t, "Page.md")) {
				t.Fatal("a refused call changed the file")
			}
			if got := mustGen(t, h); got != gen {
				t.Errorf("a refused call moved the generation from %d to %d", gen, got)
			}
			if got := len(mustSecretEvents(t, h, secretID)); got != events {
				t.Errorf("a refused call left %d audit rows where there were %d", got, events)
			}
			if got := h.reindexes.Load(); got != reindexes {
				t.Error("a refused call re-indexed the page")
			}
			if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "dm" {
				t.Errorf("a refused call by %s left the secret at %q", tc.who, got)
			}
			if got := secretFTSHits(t, h, cycleProbe); got != 0 {
				t.Errorf("a refused call put the body in the search index in %d rows", got)
			}
		})
	}

	// The control. A refusal on its own would be satisfied by a fixture in which
	// nobody may reveal, and the point of the test is that the DM may and the
	// three principals before may not.
	t.Run("the same call by a dm does work", func(t *testing.T) {
		if err := h.svc.Reveal(ctx, dm, secretID); err != nil {
			t.Fatalf("the DM was refused: %v", err)
		}
		if got := h.text(`SELECT visibility FROM secrets WHERE id = ?`, secretID); got != "table" {
			t.Errorf("after the DM's reveal the secret is at %q, want table", got)
		}
	})
}

// ownerEstablished fails the test unless the principal really does own the page
// and the policy really does grant that ownership its private secrets. Without
// it, every refusal below would be indistinguishable from a fixture in which the
// page had no owner at all — which is the vacuous pass AGENTS.md §11 calls the
// more dangerous one, because the assertion is never exercised.
func ownerEstablished(t *testing.T, h *harness, page, userID int64) {
	t.Helper()
	ctx := context.Background()
	owner, err := store.IsPageOwner(ctx, h.db.Writer(), page, userID)
	if err != nil {
		t.Fatalf("is page owner: %v", err)
	}
	if !owner {
		t.Fatalf("user %d does not own page %d, so the refusals below would be testing an unowned page", userID, page)
	}
	// The ownership arm is not merely present but consequential: it must grant
	// something, or the two negatives it separates are the same case.
	if err := authz.NewPolicy(false).Check(
		authz.ForUser(userID, "pia", authz.RolePlayer, false),
		authz.PermReadSecret,
		authz.SecretOf(page, true, h.dmID, secrets.VisibilityPrivate)); err != nil {
		t.Errorf("an owner cannot read a private secret on their own page: %v", err)
	}
	if err := authz.NewPolicy(false).Check(
		authz.ForUser(userID, "pia", authz.RolePlayer, false),
		authz.PermReadSecret,
		authz.SecretOf(page, true, h.dmID, secrets.VisibilityDM)); !errors.Is(err, authz.ErrDenied) {
		t.Error("an owner can read a dm secret on their own page, so the two negatives are not separate cases")
	}
}

// TestSecretSyntaxEdgeCases is the fail-closed table. Every row asserts what the
// SYNTAX does to confidentiality, not that it parsed.
//
// The rule underneath all seven is AGENTS.md §6's: a fence that claims secrecy
// gets it, whatever its directive says. A fence this code cannot understand is
// HIDDEN, not demoted — and the alternative is the worst failure this project
// has, so four of these rows are about a fence whose own words the indexer could
// not read or could not agree on, and one is about a fence that claims on its
// face to be public.
//
// The `wantIndexed` column is the sharpness of the table: for a well-formed CRLF
// or BOM file the body is expected to be in secret_fts, so a mis-parse that moved
// the fence's boundaries would show up as public text as well as as a missing row.
// Asserting only that nothing leaked would be satisfied by a parser that treated
// every file as one huge secret.
func TestSecretSyntaxEdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A second probe, for the row that has to show two bodies held by one span.
	const innerProbe = "cymatine"

	for _, tc := range []struct {
		name string
		// page is the whole file, written to Page.md and nothing else.
		page string
		// probes are words that appear only inside a fence in this file.
		probes []string
		// wantProblems are problem codes the index pass must report. Empty means
		// the row is expected to be clean, which is an assertion and not an
		// omission: a case that started reporting problems would be caught.
		wantProblems []string
		// wantIndexError reports whether the index pass must fail outright.
		wantIndexError bool
		// wantSecrets is how many rows the secrets table must hold afterwards.
		wantSecrets int64
		// wantPageText is how many page_text rows must exist afterwards. It is
		// one everywhere except where the index pass must fail, and there it is
		// zero: the rollback takes the page's own public text with it, which is
		// what makes the failure atomic rather than partial.
		wantPageText int64
		// wantIndexed reports whether the probe may be findable through
		// secret_fts. It is true only where the fence is well formed.
		wantIndexed bool
	}{
		{
			name: "an unterminated fence runs to the end of the file and stays secret",
			page: "# Safe\n\n```secret id=" + secretID + " visibility=dm author=dorn\n" +
				"## Never closed\n\nThe " + cycleProbe + " is on the last line of the file.\n",
			probes:       []string{cycleProbe},
			wantProblems: []string{md.ProblemSecretUnterminated},
			wantSecrets:  1,
			wantPageText: 1,
		},
		{
			name: "a fence nested in a fence cannot let the inner body out",
			page: "# Safe\n\n```secret id=" + secretID + " visibility=dm author=dorn\n" +
				"The outer body holds the " + cycleProbe + ".\n" +
				"```secret id=bbbbbbbbbbbb visibility=dm author=dorn\n" +
				"The inner body holds the " + innerProbe + ".\n```\n",
			probes:       []string{cycleProbe, innerProbe},
			wantProblems: []string{md.ProblemSecretNested},
			// One row, not two: the inner fence is a literal line inside the
			// outer body, and giving it its own identity would mean indexing a
			// span that the outer span also claims.
			wantSecrets:  1,
			wantPageText: 1,
		},
		{
			name: "two fences claiming one id are a loud index failure, not a half-indexed page",
			page: "# Safe\n\n```secret id=" + secretID + " visibility=dm author=dorn\n" +
				"The first body holds the " + cycleProbe + ".\n```\n\n" +
				"```secret id=" + secretID + " visibility=dm author=dorn\n" +
				"The second body holds the same " + cycleProbe + ".\n```\n",
			probes:         []string{cycleProbe},
			wantIndexError: true,
			// The whole transaction rolls back, so neither body reaches the
			// index at all. A half-indexed page is worse than an unindexed one:
			// it is a page whose second fence is served from nothing.
			wantSecrets:  0,
			wantPageText: 0,
		},
		{
			name: "an unknown directive key is hidden, not demoted",
			// The recorded failure, verbatim in shape: an unquoted title with a
			// space scans as a title plus two unknown keys, and a fence whose
			// directive cannot be read has to be hidden rather than served.
			page: "# Safe\n\n```secret id=" + secretID + " visibility=dm author=dorn title=The cellar key\n" +
				"The " + cycleProbe + " is behind a title the parser cannot read.\n```\n",
			probes: []string{cycleProbe},
			wantProblems: []string{
				md.ProblemSecretUnknownKey,
				// The indexer reports an author it cannot resolve, and here the
				// author is empty rather than wrong: an unreadable directive
				// yields a fence with no author, and a fence with no author is
				// not indexed. So the cost is that the fence is invisible to
				// EVERYONE, the DM included — which is the direction §6 says to
				// err in, and the opposite of the failure the plan recorded.
				sync.ProblemAuthorUnknown,
			},
			wantSecrets:  0,
			wantPageText: 1,
		},
		{
			name: "a table fence with no id is not broadcast",
			page: "# Safe\n\n```secret visibility=table author=dorn\n" +
				"The " + cycleProbe + " says table and carries no identity.\n```\n",
			probes:       []string{cycleProbe},
			wantProblems: []string{sync.ProblemUnusableFence},
			// The file says table, so the fence is public knowledge on its face.
			// It is indexed as nothing: no secrets row, no search row, and the
			// page's own public text is the only thing a reader is served. The
			// cost is that a DM cannot see it either, which is the cost §6
			// records for a malformed fence and the right side to err on.
			wantSecrets:  0,
			wantPageText: 1,
			wantIndexed:  false,
		},
		{
			name: "a CRLF file keeps the fence's boundaries",
			page: crlf("# Safe\n\n```secret id=" + secretID +
				" visibility=table author=dorn created=2026-09-28T10:04:11Z\n" +
				"The " + cycleProbe + " is inside a fence on a DOS file.\n```\n"),
			probes: []string{cycleProbe},
			// True, deliberately: with a well-formed fence the body belongs in
			// the secret index, so a line-terminator bug that swallowed the fence
			// would fail here on the index as well as on the public text.
			wantIndexed:  true,
			wantSecrets:  1,
			wantPageText: 1,
		},
		{
			name: "a byte order mark does not move the fence",
			page: "\ufeff# Safe\n\n```secret id=" + secretID +
				" visibility=table author=dorn created=2026-09-28T10:04:11Z\n" +
				"The " + cycleProbe + " is inside a fence after a mark.\n```\n",
			wantIndexed:  true,
			wantSecrets:  1,
			wantPageText: 1,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, p := range tc.probes {
				if !strings.Contains(tc.page, p) {
					t.Fatalf("the fixture does not write its own probe, so this row asserts nothing")
				}
			}
			h := newHarness(t, nil)
			raw := []byte(tc.page)
			h.vault.WriteFile(t, "Page.md", string(raw))

			// What the renderer would be given. Asserted on the parsed document
			// rather than on the database, because a fence that parsed as
			// public would be served as public text long before anything reached
			// SQLite.
			doc := md.Parse("Page.md", raw)
			assertNoProbe(t, "the document's public body", string(doc.PublicBody()), tc.probes...)
			spans := doc.SecretSpans()
			if len(spans) == 0 {
				t.Fatalf("the file produced no secret span at all, so a whole page is public")
			}
			for _, p := range tc.probes {
				off := strings.Index(tc.page, p)
				covered := false
				for _, s := range spans {
					if s.Secret() && s.Contains(off) {
						covered = true
					}
				}
				if !covered {
					t.Errorf("a fence body is not inside any secret span: the span list does not cover it")
				}
			}

			res, err := h.ix.IndexBatch(ctx, []string{"Page.md"})
			switch {
			case tc.wantIndexError && err == nil:
				t.Fatal("the index pass accepted a file it must not accept")
			case !tc.wantIndexError && err != nil:
				t.Fatalf("the index pass failed: %v", err)
			}
			if len(tc.wantProblems) == 0 {
				for _, r := range res.Indexed {
					for _, p := range r.Problems {
						t.Errorf("the index pass reported %s for a file it should have read cleanly: %s",
							p.Code, p.Message)
					}
				}
			} else {
				for _, code := range tc.wantProblems {
					if !reportedProblem(res, code) {
						t.Errorf("the index pass did not report %s; a problem nobody reports is a problem nobody fixes",
							code)
					}
				}
			}
			// A problem message carries ids, paths and reasons, never content.
			// A row that printed the directive would print a body's first line.
			for _, r := range res.Indexed {
				for _, p := range r.Problems {
					assertNoProbe(t, "a problem message", p.Message, tc.probes...)
				}
			}

			if got := h.count(`SELECT COUNT(*) FROM secrets`); got != tc.wantSecrets {
				t.Errorf("the secrets table holds %d rows, want %d", got, tc.wantSecrets)
			}
			if got := h.count(`SELECT COUNT(*) FROM page_text`); got != tc.wantPageText {
				t.Errorf("page_text holds %d rows, want %d: the pass is either half applied or has invented a row",
					got, tc.wantPageText)
			}
			wantHits := int64(0)
			if tc.wantIndexed {
				wantHits = int64(len(tc.probes))
			}
			for _, p := range tc.probes {
				if got := secretFTSHits(t, h, p); got != wantHits {
					t.Errorf("the secret index holds %d rows for a probe, want %d", got, wantHits)
				}
				if got := pageFTSHits(t, h, p); got != 0 {
					t.Errorf("a fence body reached the PUBLIC index in %d rows", got)
				}
			}
			if n, err := store.CheckSecretIndexInvariant(ctx, h.db.Reader()); err != nil || n != 0 {
				t.Errorf("the secret index invariant is %d (err %v), want 0", n, err)
			}
			// And in the index's own words, over the whole table rather than one
			// page: a body that reached a page_text row would be served as public
			// prose by every read that does not filter.
			for _, col := range []string{"title", "headings", "body"} {
				assertNoProbe(t, "page_text."+col, allTextIn(t, h, col), tc.probes...)
			}
			// The index pass must not have touched the file. It is derived and
			// disposable; a file it rewrote would be a file the app reflowed
			// (§5.3).
			if got := h.vault.ReadFile(t, "Page.md"); !bytes.Equal(raw, got) {
				t.Error("the index pass rewrote the file")
			}
		})
	}
}

// TestTheUnterminatedFenceIsTheLastSpanAndTheLastLine is the byte-level half of
// the unterminated row above, kept separate because it is a claim about a
// boundary rather than about confidentiality: the span has to reach the last
// byte of the file, or a fence is a span and whatever follows it is public.
//
// It is also the shape a later write must respect. An editor saving a buffer
// whose last line sits outside every secret span would write it as public text,
// and a body would become a paragraph.
func TestTheUnterminatedFenceIsTheLastSpanAndTheLastLine(t *testing.T) {
	t.Parallel()
	raw := []byte("# Safe\n\n```secret id=" + secretID + " visibility=dm author=dorn\nThe " + cycleProbe + " is last.\n")
	doc := md.Parse("Page.md", raw)
	spans := doc.SecretSpans()
	if len(spans) != 1 {
		t.Fatalf("the file produced %d secret spans, want 1", len(spans))
	}
	if spans[0].EndByte != len(raw) {
		t.Errorf("the span ends at %d in a %d-byte file: %d bytes sit outside it as public text",
			spans[0].EndByte, len(raw), len(raw)-spans[0].EndByte)
	}
	if !spans[0].Contains(strings.Index(string(raw), cycleProbe)) {
		t.Error("the body is not inside the span")
	}
	// The fence's own id is the stated one, so a later reveal addresses the
	// right bytes rather than a placeholder.
	if spans[0].SecretID != secretID {
		t.Errorf("the span is attributed to %q, want %q", spans[0].SecretID, secretID)
	}
}

// withVisibility renders the bytes a reveal of a `dm` fence to `table` produces:
// the directive line with the visibility token replaced and every other byte
// untouched. It is written out rather than delegated to md.SetVisibility so that
// the assertion is against the change, not against the function that made it.
func withVisibility(before []byte, from, to string) []byte {
	needle := []byte("visibility=" + from)
	at := bytes.Index(before, needle)
	if at < 0 {
		return before
	}
	out := make([]byte, 0, len(before))
	out = append(out, before[:at]...)
	out = append(out, "visibility="+to...)
	out = append(out, before[at+len(needle):]...)
	return out
}

// mustSecretEvents reads a secret's whole trail, newest first, and fails the test
// if the read failed rather than returning an empty trail — an empty trail and an
// unreadable one look identical to a caller that ignores the error, and that is
// exactly the shape of a vacuous assertion.
func mustSecretEvents(t *testing.T, h *harness, id string) []store.SecretEvent {
	t.Helper()
	rows, err := store.ListSecretEventsBySecret(context.Background(), h.db.Reader(), id)
	if err != nil {
		t.Fatalf("read the audit trail for %s: %v", id, err)
	}
	return rows
}

// assertEvent checks the four fields that make a trail row say something: what
// was done, which way, by whom, and when. It deliberately takes the expected
// actor as a value rather than comparing to h.dmID itself, so a test that meant
// to name a different actor cannot pass by reading the same field twice.
func assertEvent(t *testing.T, ev store.SecretEvent, action, from, to string, actor int64) {
	t.Helper()
	if ev.Action != action {
		t.Errorf("the event is %q, want %q", ev.Action, action)
	}
	if ev.FromVis != from || ev.ToVis != to {
		t.Errorf("the event says %q->%q, want %q->%q", ev.FromVis, ev.ToVis, from, to)
	}
	if ev.ActorID != actor {
		t.Errorf("the event names actor %d, want %d", ev.ActorID, actor)
	}
	if ev.SecretID == "" {
		t.Error("the event names no secret")
	}
}

// fmtEvents renders the trail for a content check. The row has no content field
// to render, so this is the row's own metadata as text, and the assertion is that
// no probe is in it.
func fmtEvents(events []store.SecretEvent) string {
	var b strings.Builder
	for _, ev := range events {
		b.WriteString(ev.Action)
		b.WriteString(ev.FromVis)
		b.WriteString(ev.ToVis)
		b.WriteString(ev.SecretID)
	}
	return b.String()
}

// pageTextColumn reads one column of a page's public text. An absent row reads as
// the empty string, so a test that forgets to index first fails on the emptiness
// assertions rather than passing on them.
func pageTextColumn(t *testing.T, h *harness, page int64, column string) string {
	t.Helper()
	// The column name is a literal at every call site and never a value, so the
	// statement is assembled from constants and the id is the only parameter.
	var query string
	switch column {
	case "title":
		query = `SELECT title FROM page_text WHERE page_id = ?`
	case "headings":
		query = `SELECT headings FROM page_text WHERE page_id = ?`
	case "body":
		query = `SELECT body FROM page_text WHERE page_id = ?`
	default:
		t.Fatalf("pageTextColumn was asked for %q, which is not a column", column)
	}
	return h.text(query, page)
}

// allTextIn concatenates one page_text column across every page. It is the
// whole-table form of pageTextColumn, used where the question is "did this body
// reach the table at all", which a per-page read would answer "no" for when the
// page was never indexed.
func allTextIn(t *testing.T, h *harness, column string) string {
	t.Helper()
	// The column name is a literal at every call site and is never a value, so the
	// statement is assembled from constants and there is nothing in it to bind.
	// COALESCE, because group_concat over no rows is NULL and the harness's
	// single-string scan reports a read error for NULL rather than an empty
	// string — which is the right behaviour, because a test that indexed nothing
	// should not read as "nothing leaked".
	var query string
	switch column {
	case "title":
		query = `SELECT COALESCE(group_concat(title, ''), '') FROM page_text`
	case "headings":
		query = `SELECT COALESCE(group_concat(headings, ''), '') FROM page_text`
	case "body":
		query = `SELECT COALESCE(group_concat(body, ''), '') FROM page_text`
	default:
		t.Fatalf("allTextIn was asked for %q, which is not a column", column)
	}
	return h.text(query)
}

// reportedProblem reports whether any index result named a problem code. Problems
// are reported once by the markdown parse and once by the fence parse, so the
// test is "at least one" and not "exactly one": a count of one would fail on a
// correct implementation and pass on one that lost a problem.
func reportedProblem(res sync.BatchResult, code string) bool {
	for _, r := range res.Indexed {
		for _, p := range r.Problems {
			if p.Code == code {
				return true
			}
		}
	}
	return false
}

// assertBacklinkPair is the list-and-count pair a panel is built from. Both are
// asserted against the expected number rather than against each other, so a count
// that agreed with an over-broad list fails here.
func assertBacklinkPair(t *testing.T, h *harness, p authz.Principal, page int64, want int) {
	t.Helper()
	ctx := context.Background()
	list, err := store.ListBacklinks(ctx, h.db.Reader(), p, page)
	if err != nil {
		t.Fatalf("list backlinks: %v", err)
	}
	if len(list) != want {
		t.Errorf("%s sees %d backlinks, want %d", p, len(list), want)
	}
	count, err := store.BacklinkCount(ctx, h.db.Reader(), p, page)
	if err != nil {
		t.Fatalf("count backlinks: %v", err)
	}
	if count != want {
		t.Errorf("BacklinkCount = %d, want %d", count, want)
	}
	if count != len(list) {
		t.Errorf("BacklinkCount = %d but the list has %d rows", count, len(list))
	}
}

func assertTagCloud(t *testing.T, h *harness, p authz.Principal, tag string, want int) {
	t.Helper()
	var count int
	for _, tc := range mustTagCloud(t, h, p) {
		if tc.Name == tag {
			count = tc.PageCount
		}
	}
	if count != want {
		t.Errorf("the tag cloud reports %d pages for %q, want %d", count, tag, want)
	}
	// TagCountFor is the number behind one tag rather than a row in the cloud, so
	// a cloud that filtered and a lookup that did not would disagree here.
	got, err := store.TagCountFor(context.Background(), h.db.Reader(), p, tag)
	if err != nil {
		t.Fatalf("tag count for %q: %v", tag, err)
	}
	if got != want {
		t.Errorf("TagCountFor(%q) = %d, want %d", tag, got, want)
	}
}

func mustTagCloud(t *testing.T, h *harness, p authz.Principal) []store.TagCount {
	t.Helper()
	tags, err := store.ListTags(context.Background(), h.db.Reader(), p)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	return tags
}

func assertTagPages(t *testing.T, h *harness, p authz.Principal, tag string, want int) {
	t.Helper()
	ctx := context.Background()
	pages, err := store.ListTaggedPages(ctx, h.db.Reader(), p, tag)
	if err != nil {
		t.Fatalf("list tagged pages: %v", err)
	}
	if len(pages) != want {
		t.Errorf("%s sees %d pages tagged %q, want %d", p, len(pages), tag, want)
	}
	count, err := store.CountTaggedPages(ctx, h.db.Reader(), p, tag)
	if err != nil {
		t.Fatalf("count tagged pages: %v", err)
	}
	if count != want {
		t.Errorf("CountTaggedPages(%q) = %d, want %d", tag, count, want)
	}
	if count != len(pages) {
		t.Errorf("CountTaggedPages(%q) = %d but the list has %d rows", tag, count, len(pages))
	}
}

func assertOpenThreads(t *testing.T, h *harness, p authz.Principal, want int) {
	t.Helper()
	ctx := context.Background()
	threads, err := store.ListOpenThreads(ctx, h.db.Reader(), p, 20)
	if err != nil {
		t.Fatalf("list open threads: %v", err)
	}
	if len(threads) != want {
		t.Errorf("%s sees %d open threads, want %d", p, len(threads), want)
	}
	count, err := store.CountOpenThreads(ctx, h.db.Reader(), p)
	if err != nil {
		t.Fatalf("count open threads: %v", err)
	}
	if count != want {
		t.Errorf("CountOpenThreads = %d, want %d", count, want)
	}
	if count != len(threads) {
		t.Errorf("CountOpenThreads = %d but the list has %d rows", count, len(threads))
	}
}
