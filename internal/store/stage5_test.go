package store

import (
	"context"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// stage5Probe is a word that appears in the fixtures below and nowhere else in
// the corpus, so "this token is in no index" is a real assertion rather than a
// term that happens to be in the public prose too.
//
// It is a probe rather than a secret body: nothing in this file prints it, and a
// fixture body is never quoted into a failure message.
const stage5Probe = "quillonite"

// stage5ProbeBody is what the fixture's secret says. Named so that the two
// places that need it agree on the bytes, and so that a term searched for is
// visibly a term that was written.
var stage5ProbeBody = "The " + stage5Probe + " is behind the cellar wall."

// stage5At is the instant every seeded row claims, so a stored timestamp is a
// literal rather than a formatted "now".
var stage5At = time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)

// gen reads the authorization generation, failing the test rather than
// defaulting: a counter that reads as zero because the read failed would make
// every "it did not move" assertion in this file pass for the wrong reason.
func gen(t *testing.T, q Queryer) int64 {
	t.Helper()
	n, err := AuthzGeneration(context.Background(), q)
	if err != nil {
		t.Fatalf("authz generation: %v", err)
	}
	return n
}

// eventCount is the number of rows in the whole audit table, so a test asking
// whether a write added one is not reading a filtered subset.
func eventCount(t *testing.T, q Queryer) int64 {
	t.Helper()
	return mustQueryInt(t, q, `SELECT COUNT(*) FROM secret_events`)
}

// probeHits is how many secret_text rows a MATCH on the probe token finds. It
// goes through the index rather than through a row count, because the claim is
// about findability and a row that exists is not a row that is found.
func probeHits(t *testing.T, q Queryer) int64 {
	t.Helper()
	return mustQueryInt(t, q,
		`SELECT COUNT(*) FROM secret_fts WHERE secret_fts MATCH ?`, stage5Probe)
}

// TestAuthzGenerationBumped is the half of the reveal/revoke contract that lives
// here: the audit row and the authorization generation are ONE unit of work, so a
// crash cannot leave one without the other.
//
// The pairing is the caller's to make — secrets.Service.SetVisibility opens the
// transaction — but the two things it puts into it are this package's, and so is
// the guarantee that they survive or vanish together. It matters in both
// directions: a generation that moved with no event is a counter that changed for
// a reason nobody recorded, and an event with no generation is a revocation that
// every live stream kept serving.
//
// The two failure directions are separate subtests because "they commit together"
// is two claims, and an implementation that got one of them right would satisfy
// a single-case version of this test.
//
// What this file does NOT claim: that an idempotent reveal writes nothing. That
// decision belongs to the caller, and it is made by comparing the file's bytes —
// md.SetVisibility returns the input unchanged when the fence already reads that
// way. The store half of it is the last two subtests: the counter is moved by a
// committed pair, once per pair, and by nothing else.
func TestAuthzGenerationBumped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// from and to are the visibilities the seeded secret starts and ends at,
		// so each row is a different transition rather than one repeated.
		from, to authz.Visibility
		action   string
	}{
		{"a reveal", authz.VisibilityDM, authz.VisibilityTable, SecretActionReveal},
		{"a revoke", authz.VisibilityTable, authz.VisibilityPrivate, SecretActionRevoke},
	} {
		tc := tc
		t.Run(tc.name+" moves the counter exactly one step", func(t *testing.T) {
			t.Parallel()
			f := newStage5Secret(t, tc.from)
			before := gen(t, f.db.Writer())
			// The control for the whole subtest: the fixture really does hold the
			// secret at the stated visibility and the probe really is findable
			// when the secret is open. Without it, "the counter moved" and "the
			// counter did not" would both be satisfiable by a fixture that had
			// nothing to change.
			if got := visibilityOf(t, f.db.Reader(), f.secretID); got != tc.from {
				t.Fatalf("the fixture seeded the secret at %q, want %q", got, tc.from)
			}
			if want := tc.from == authz.VisibilityTable; (probeHits(t, f.db.Reader()) == 1) != want {
				t.Fatalf("the probe is findable=%v before the change, want %v", !want, want)
			}

			commitVisibilityChange(t, f, tc.to)

			if got := gen(t, f.db.Reader()); got != before+1 {
				t.Errorf("the generation moved from %d to %d, want exactly one step", before, got)
			}
			if got := eventCount(t, f.db.Reader()); got != 1 {
				t.Errorf("the audit table holds %d rows, want 1", got)
			}
			rows, err := ListSecretEventsBySecret(ctx, f.db.Reader(), f.secretID)
			if err != nil {
				t.Fatalf("events: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("the trail has %d rows, want 1", len(rows))
			}
			ev := rows[0]
			if ev.Action != tc.action || ev.FromVis != string(tc.from) || ev.ToVis != string(tc.to) {
				t.Errorf("the event says %s %s->%s, want %s %s->%s",
					ev.Action, ev.FromVis, ev.ToVis, tc.action, tc.from, tc.to)
			}
			if ev.ActorID != f.actorID {
				t.Errorf("the event names actor %d, want %d", ev.ActorID, f.actorID)
			}
			if !ev.At.Equal(stage5At) {
				t.Errorf("the event is timestamped %s, want %s", ev.At, stage5At)
			}
			// The index move belongs to the same change, and it is what makes the
			// terms stop being findable. Asserted as findability rather than as a
			// row count, because a row that exists is not a row that is found.
			want := int64(0)
			if tc.to == authz.VisibilityTable {
				want = 1
			}
			if got := probeHits(t, f.db.Reader()); got != want {
				t.Errorf("the probe is findable in %d rows after the change, want %d", got, want)
			}
		})
	}

	t.Run("a failure to write the event rolls the generation back with it", func(t *testing.T) {
		t.Parallel()
		f := newStage5Secret(t, authz.VisibilityDM)
		before := gen(t, f.db.Writer())

		// The trigger stands in for a crash between the two statements. If they
		// were separate transactions this is exactly the state that would
		// survive, and it is the worse of the two: a counter that moved with
		// nothing to explain it.
		mustExec(t, f.db.Writer(), `CREATE TRIGGER block_events BEFORE INSERT ON secret_events
			BEGIN SELECT RAISE(ABORT, 'the audit table is unavailable'); END`)

		if _, err := bumpThenAppend(t, f); err == nil {
			t.Fatal("the audit append succeeded against a table that refuses inserts")
		}
		// "Rolled back" has to mean the transaction is finished, not merely that
		// the caller wants it to be. A transaction still open would leave the
		// counter unmoved for a reason that has nothing to do with atomicity, and
		// every assertion below would be proving the harness instead.
		assertTransactionClosed(t, f.db.Writer())
		if got := gen(t, f.db.Reader()); got != before {
			t.Errorf("the generation moved from %d to %d with no event to explain it", before, got)
		}
		if got := eventCount(t, f.db.Reader()); got != 0 {
			t.Errorf("%d audit rows exist, want none", got)
		}
	})

	t.Run("a failure to bump rolls the event back with it", func(t *testing.T) {
		t.Parallel()
		f := newStage5Secret(t, authz.VisibilityDM)
		before := gen(t, f.db.Writer())

		// The other direction, and a different failure: the audit row is written
		// and the counter does not move. Every stream carrying the old answer
		// keeps serving it, and the trail says the change happened.
		mustExec(t, f.db.Writer(), `CREATE TRIGGER block_generation BEFORE INSERT ON meta
			WHEN NEW.key = 'authz_generation'
			BEGIN SELECT RAISE(ABORT, 'the counter is unavailable'); END`)

		if _, err := bumpThenAppend(t, f); err == nil {
			t.Fatal("the generation bump succeeded against a counter that refuses writes")
		}
		assertTransactionClosed(t, f.db.Writer())
		if got := gen(t, f.db.Reader()); got != before {
			t.Errorf("the generation moved from %d to %d although the change was rolled back", before, got)
		}
		if got := eventCount(t, f.db.Reader()); got != 0 {
			t.Errorf("%d audit rows exist although the change was rolled back", got)
		}
		// And the fixture is not wedged: the trigger refuses writes, so the
		// counter is still at zero, and the only way to tell that from "the
		// counter is stuck" is to remove the trigger and write.
		mustExec(t, f.db.Writer(), `DROP TRIGGER block_generation`)
		if got, err := BumpAuthzGeneration(context.Background(), f.db.Writer()); err != nil || got != before+1 {
			t.Errorf("after the trigger was dropped the counter read %d (err %v), want %d",
				got, err, before+1)
		}
	})

	t.Run("reads never move the counter", func(t *testing.T) {
		t.Parallel()
		f := newStage5Secret(t, authz.VisibilityTable)
		before := gen(t, f.db.Reader())

		// Every read the service and the panels perform while answering a
		// request. A counter that moved on a read would tear down every live
		// stream on every poll, which fails exactly as badly as one that never
		// moves: neither tells a stale stream that its answer is wrong.
		if _, err := GetSecretByID(ctx, f.db.Reader(), f.secretID); err != nil {
			t.Fatalf("get by id: %v", err)
		}
		if _, err := GetVisibleSecret(ctx, f.db.Reader(), f.player(), f.secretID); err != nil {
			t.Fatalf("get visible: %v", err)
		}
		if _, err := ListSecretRowsByPage(ctx, f.db.Reader(), f.pageID); err != nil {
			t.Fatalf("list rows: %v", err)
		}
		if _, err := ListVisibleSecretRowsByPage(ctx, f.db.Reader(), f.player(), f.pageID); err != nil {
			t.Fatalf("list visible: %v", err)
		}
		if _, err := CountVisibleSecrets(ctx, f.db.Reader(), f.player(), f.pageID); err != nil {
			t.Fatalf("count visible: %v", err)
		}
		if _, err := ListSecretEventsBySecret(ctx, f.db.Reader(), f.secretID); err != nil {
			t.Fatalf("list events: %v", err)
		}
		if _, err := ListSecretEventsByActor(ctx, f.db.Reader(), f.actorID); err != nil {
			t.Fatalf("list events by actor: %v", err)
		}
		if _, err := CheckSecretIndexInvariant(ctx, f.db.Reader()); err != nil {
			t.Fatalf("check invariant: %v", err)
		}
		if got := gen(t, f.db.Reader()); got != before {
			t.Errorf("eight reads moved the generation from %d to %d", before, got)
		}

		// The control. Without it, "the counter did not move" is also satisfied
		// by a counter that is simply broken.
		commitVisibilityChange(t, f, authz.VisibilityPrivate)
		if got := gen(t, f.db.Reader()); got != before+1 {
			t.Errorf("a committed change did not move the generation: %d then %d", before, got)
		}
	})

	t.Run("each committed change moves it once and the trail once", func(t *testing.T) {
		t.Parallel()
		f := newStage5Secret(t, authz.VisibilityPrivate)
		before := gen(t, f.db.Writer())

		commitVisibilityChange(t, f, authz.VisibilityTable)
		commitVisibilityChange(t, f, authz.VisibilityDM)
		commitVisibilityChange(t, f, authz.VisibilityTable)

		if got := gen(t, f.db.Reader()); got != before+3 {
			t.Errorf("three committed changes moved the generation from %d to %d, want three steps", before, got)
		}
		if got := eventCount(t, f.db.Reader()); got != 3 {
			t.Errorf("%d audit rows for three changes, want 3", got)
		}
		// A lost increment is invisible to every other assertion here: the
		// counter would still be non-zero and still be monotonic. Naming the
		// expected trail is the only assertion that can tell 3 from 2.
		rows, err := ListSecretEventsBySecret(ctx, f.db.Reader(), f.secretID)
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		// Newest first. All three changes carry the same instant, so the ordering
		// falls to the row id tie-break rather than to the timestamp — which is
		// the case a trail that only ever held one row at a time would never
		// exercise.
		want := [][3]string{
			{SecretActionReveal, "dm", "table"},
			{SecretActionRevoke, "table", "dm"},
			{SecretActionReveal, "private", "table"},
		}
		if len(rows) != len(want) {
			t.Fatalf("the trail has %d rows, want %d", len(rows), len(want))
		}
		for i, w := range want {
			got := rows[i]
			if got.Action != w[0] || got.FromVis != w[1] || got.ToVis != w[2] {
				t.Errorf("trail row %d says %s %s->%s, want %s %s->%s",
					i, got.Action, got.FromVis, got.ToVis, w[0], w[1], w[2])
			}
		}
		if got := visibilityOf(t, f.db.Reader(), f.secretID); got != authz.VisibilityTable {
			t.Errorf("the indexed visibility is %q, want table", got)
		}
	})
}

// stage5Secret is one page with one secret at a stated visibility: the smallest
// fixture the generation test needs — an actor to name, a page to hang the
// secret off, and a player to prove the read paths are still answering.
type stage5Secret struct {
	db       *DB
	pageID   int64
	secretID string
	actorID  int64
	playerID int64
}

func (f *stage5Secret) player() authz.Principal {
	return authz.ForUser(f.playerID, "pia", authz.RolePlayer, false)
}

func newStage5Secret(t *testing.T, vis authz.Visibility) *stage5Secret {
	t.Helper()
	ctx := context.Background()
	db := newMigratedDB(t)
	actor := seedUser(t, db.Writer(), "dorn", "dm")
	player := seedUser(t, db.Writer(), "pia", "player")
	page := seedPage(t, db.Writer(), "Page.md", "Page")

	const id = "abcdef012345"
	if err := InsertSecret(ctx, db.Writer(), Secret{
		ID: id, PageID: page, Ordinal: 0, Visibility: vis, AuthorID: actor,
		Title: "The Mayor's Door", Body: stage5ProbeBody,
		BodyHash: []byte(id), CreatedAt: stage5At, UpdatedAt: stage5At,
	}); err != nil {
		t.Fatal(err)
	}
	if vis == authz.VisibilityTable {
		if err := IndexSecretText(ctx, db.Writer(), id, vis, stage5ProbeBody); err != nil {
			t.Fatal(err)
		}
	}
	return &stage5Secret{db: db, pageID: page, secretID: id, actorID: actor, playerID: player}
}

// commitVisibilityChange performs the database half of a reveal or a revoke, in
// the order and inside the transaction secrets.Service.SetVisibility uses it: the
// index row moves, the secret row moves, the audit row is appended and the
// generation is bumped, and all four commit together or not at all.
//
// Whether the file would change at all is the caller's decision and is not
// mirrored here — see the comment on the test. What is under test is that
// everything done once that decision is made is a single transaction.
func commitVisibilityChange(t *testing.T, f *stage5Secret, to authz.Visibility) {
	t.Helper()
	ctx := context.Background()
	sec, err := GetSecretByID(ctx, f.db.Reader(), f.secretID)
	if err != nil {
		t.Fatalf("read the secret before the change: %v", err)
	}
	from := sec.Visibility
	action := SecretActionReveal
	if to != authz.VisibilityTable {
		action = SecretActionRevoke
	}

	tx, err := f.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if to == authz.VisibilityTable {
		if indexSecretTextErr := IndexSecretText(ctx, tx, f.secretID, to, sec.Body); indexSecretTextErr != nil {
			t.Fatalf("index the revealed body: %v", indexSecretTextErr)
		}
	} else if deleteSecretTextErr := DeleteSecretText(ctx, tx, f.secretID); deleteSecretTextErr != nil {
		t.Fatalf("purge the revoked body: %v", deleteSecretTextErr)
	}
	sec.Visibility = to
	if updateSecretErr := UpdateSecret(ctx, tx, sec); updateSecretErr != nil {
		t.Fatalf("update the secret row: %v", updateSecretErr)
	}
	if _, appendSecretEventErr := AppendSecretEvent(ctx, tx, SecretEvent{
		SecretID: f.secretID, ActorID: f.actorID, Action: action,
		FromVis: string(from), ToVis: string(to), At: stage5At,
	}); appendSecretEventErr != nil {
		t.Fatalf("append the audit row: %v", appendSecretEventErr)
	}
	if _, bumpAuthzGenerationErr := BumpAuthzGeneration(ctx, tx); bumpAuthzGenerationErr != nil {
		t.Fatalf("bump the generation: %v", bumpAuthzGenerationErr)
	}
	if commitErr := tx.Commit(); commitErr != nil {
		t.Fatalf("commit: %v", commitErr)
	}

	// The audit row's from-visibility is read from the row the service read,
	// not from a literal, so a change that reported the wrong origin would be
	// caught rather than agreeing with the expectation written beside it. Only
	// the newest row is inspected: this helper may be called several times over
	// one secret, and the trail is append-only by design.
	rows, err := ListSecretEventsBySecret(ctx, f.db.Reader(), f.secretID)
	if err != nil || len(rows) == 0 {
		t.Fatalf("the committed change left %d audit rows (err %v), want at least one", len(rows), err)
	}
	newest := rows[0]
	if newest.FromVis != string(from) || newest.ToVis != string(to) {
		t.Errorf("the newest audit row says %s %s->%s, and the row said %q before the change to %q",
			newest.Action, newest.FromVis, newest.ToVis, from, to)
	}
}

// bumpThenAppend opens the transaction, bumps the generation and then tries to
// append the audit row, returning whatever the second statement produced. The
// order is bump-then-append so that the trigger on the audit table fires after
// the counter has already moved inside the transaction; the trigger on the
// counter fires at the first statement. Either way the assertions are about the
// state after the rollback.
func bumpThenAppend(t *testing.T, f *stage5Secret) (int64, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	n, err := BumpAuthzGeneration(ctx, tx)
	if err != nil {
		return 0, err
	}
	if _, err := AppendSecretEvent(ctx, tx, SecretEvent{
		SecretID: f.secretID, ActorID: f.actorID, Action: SecretActionReveal,
		FromVis: "dm", ToVis: "table", At: stage5At,
	}); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// assertTransactionClosed fails if the write pool is still inside the transaction
// the helper rolled back. A rollback that was only requested would leave the
// counter unmoved for a reason that has nothing to do with atomicity.
func assertTransactionClosed(t *testing.T, q Queryer) {
	t.Helper()
	var one int
	if err := q.QueryRowContext(context.Background(), `SELECT 1`).Scan(&one); err != nil {
		t.Fatalf("the write pool is still inside the rolled-back transaction: %v", err)
	}
}

// visibilityOf reads one secret's indexed visibility. It goes through the row
// rather than through a Go literal, so an assertion that says "the row says dm"
// is reading what the index actually holds.
func visibilityOf(t *testing.T, q Queryer, secretID string) authz.Visibility {
	t.Helper()
	sec, err := GetSecretByID(context.Background(), q, secretID)
	if err != nil {
		t.Fatalf("read secret %s: %v", secretID, err)
	}
	return sec.Visibility
}

// TestRevealUpdatesBacklinkCounts is §6.4's count-equals-list rule in the
// direction that is easy to get wrong.
//
// A reveal does not add a link. The row is written by the indexer when the fence
// is parsed, carrying the secret's id, and it is there whether the secret is
// hidden or revealed. What a reveal changes is the ANSWER: the row starts being
// inside the set a player is shown. That asymmetry is why a trailing count is
// easy to write here — the row count is constant and only the predicate moves —
// and it is the leak §2.4 names, because a badge that says three beside a list
// of one is a statement about a secret the reader was refused.
//
// Both time directions are asserted, and the unfiltered read is asserted constant
// throughout. That last one is the control: if the links table itself were
// changing, "the player's list moved" would be proved by nothing at all.
func TestRevealUpdatesBacklinkCounts(t *testing.T) {
	t.Parallel()
	f := newMatrixFixture(t)
	who := f.principal(t)

	// The fixture holds one public reference and one reference inside each of
	// the three secrets, all aimed at targetPage. A player sees the public one
	// and the one inside the table-visible secret; a DM sees all four; an
	// anonymous visitor sees one, because publicOnlySQL is the only thing
	// closing the case the canonical predicate cannot.
	player, dm := who["outsider"], who["dm"]
	hidden := f.secrets[authz.VisibilityDM].secretID()
	const allRows = 4
	if got := backlinkRows(t, f); got != allRows {
		t.Fatalf("the fixture holds %d reference rows, want %d", got, allRows)
	}

	// Deliberately not parallel: each step starts from where the previous one
	// left off, and that ordering is the claim. The last step returns to the
	// revealed state on purpose — without it, a predicate that only ever shrank
	// the result set would satisfy every step above.
	for _, step := range []struct {
		name string
		// to is the visibility the hidden secret is moved to, or "" to leave it
		// where it is.
		to   authz.Visibility
		want int
	}{
		{"before the reveal", "", 2},
		{"revealed to the table", authz.VisibilityTable, 3},
		// Private is not a consolation: the secret is authored by alice, who is
		// not this player, so a revoke takes the reference away again. This is
		// the step that makes "revealed to private = 3" a wrong expectation
		// rather than a plausible one.
		{"revoked to private", authz.VisibilityPrivate, 2},
		{"revealed to the table again", authz.VisibilityTable, 3},
	} {
		t.Run(step.name, func(t *testing.T) {
			if step.to != "" {
				moveVisibility(t, f, hidden, step.to)
			}
			assertBacklinks(t, f, player, step.want)
			// The DM's answer does not depend on the reveal: a DM reads every
			// secret, so the reference is in front of them either way. Checking
			// only the player would not notice a predicate that leaked on the DM
			// side.
			assertBacklinks(t, f, dm, allRows)
			assertBacklinks(t, f, authz.Anonymous(true), 1)

			if got := backlinkRows(t, f); got != allRows {
				t.Errorf("the unfiltered read holds %d rows, want a constant %d: the reveal changed a row, not a filter",
					got, allRows)
			}
		})
	}

	// The broken-links half, because a reference that does not resolve is a
	// different panel built from a different constant, and a filter added to
	// backlinksSQL and forgotten in unresolvedLinksSQL is the exact shape of the
	// bug. It gets its own fixture because it declares itself parallel, and a
	// parallel subtest must not share state with the ordered steps above.
	t.Run("a dangling reference inside the secret moves the broken-links panel too", func(t *testing.T) {
		t.Parallel()
		g := newMatrixFixture(t)
		bob := g.principal(t)["outsider"]
		secret := g.secrets[authz.VisibilityDM].secretID()

		assertDangling(t, g, bob, 2)
		moveVisibility(t, g, secret, authz.VisibilityTable)
		assertDangling(t, g, bob, 3)
		moveVisibility(t, g, secret, authz.VisibilityDM)
		assertDangling(t, g, bob, 2)
	})
}

// backlinkRows is the unfiltered number of references pointing at the fixture's
// target page. It is what a reveal must not change.
func backlinkRows(t *testing.T, f *matrixFixture) int64 {
	t.Helper()
	return mustQueryInt(t, f.db.Writer(),
		`SELECT COUNT(*) FROM links WHERE target_page_id = ?`, f.targetPage)
}

// assertBacklinks is the count-equals-list assertion plus the requirement that
// the count MOVED to the value the step expects, rather than merely agreeing with
// whatever the list happens to hold. A count that agreed with an empty list would
// satisfy the first half on its own.
func assertBacklinks(t *testing.T, f *matrixFixture, p authz.Principal, want int) {
	t.Helper()
	ctx := context.Background()
	list, err := ListBacklinks(ctx, f.db.Reader(), p, f.targetPage)
	if err != nil {
		t.Fatalf("list backlinks: %v", err)
	}
	if len(list) != want {
		t.Errorf("%s sees %d backlinks, want %d", p, len(list), want)
	}
	count, err := BacklinkCount(ctx, f.db.Reader(), p, f.targetPage)
	if err != nil {
		t.Fatalf("count backlinks: %v", err)
	}
	if count != len(list) {
		t.Errorf("BacklinkCount = %d but the list has %d rows", count, len(list))
	}
	if count != want {
		t.Errorf("BacklinkCount = %d, want %d", count, want)
	}
	// Every listed row points at the fixture's one referring page, so a
	// predicate that filtered the wrong column shows up as a missing row rather
	// than as a row from somewhere else.
	for _, b := range list {
		if b.Page.ID != f.sourcePage {
			t.Errorf("a backlink points at page %d, want the fixture's referring page", b.Page.ID)
		}
	}
}

func assertDangling(t *testing.T, f *matrixFixture, p authz.Principal, want int) {
	t.Helper()
	ctx := context.Background()
	list, err := ListVisibleUnresolvedLinks(ctx, f.db.Reader(), p)
	if err != nil {
		t.Fatalf("list dangling: %v", err)
	}
	if len(list) != want {
		t.Errorf("%s sees %d dangling links, want %d", p, len(list), want)
	}
	count, err := CountVisibleUnresolvedLinks(ctx, f.db.Reader(), p)
	if err != nil {
		t.Fatalf("count dangling: %v", err)
	}
	if count != want {
		t.Errorf("CountVisibleUnresolvedLinks = %d, want %d", count, want)
	}
}

// moveVisibility performs the row and index writes a reveal or a revoke makes, so
// the fixture is in the state a real reveal leaves rather than one only the
// predicate was told about. The audit row and the generation belong to
// TestAuthzGenerationBumped and are not repeated here.
func moveVisibility(t *testing.T, f *matrixFixture, secretID string, to authz.Visibility) {
	t.Helper()
	ctx := context.Background()
	sec, err := GetSecretByID(ctx, f.db.Writer(), secretID)
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if sec.Visibility == to {
		t.Fatalf("the fixture is already at %s, so this step would assert nothing", to)
	}
	tx, err := f.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if to == authz.VisibilityTable {
		if err := IndexSecretText(ctx, tx, secretID, to, sec.Body); err != nil {
			t.Fatal(err)
		}
	} else if err := DeleteSecretText(ctx, tx, secretID); err != nil {
		t.Fatal(err)
	}
	sec.Visibility = to
	if err := UpdateSecret(ctx, tx, sec); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n, err := CheckSecretIndexInvariant(ctx, f.db.Reader()); err != nil || n != 0 {
		t.Errorf("the secret index invariant is %d after the move (err %v), want 0", n, err)
	}
}

// The count-equals-list rule above is only a rule if a broken count is a failure,
// and a count that agreed with an over-broad list would satisfy it. This is the
// predicate's own negative case, on a fixture that holds three secret-only
// references beside the public one: a rule that treated page ownership or
// authorship as sufficient would hand a DM's reference to a player here, and the
// positive controls beside it are what show the assertions can fail.
func TestTheBacklinkPredicateRefusesWhatTheCanonicalPredicateRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newMatrixFixture(t)
	who := f.principal(t)

	for _, tc := range []struct {
		name string
		p    authz.Principal
		want int
	}{
		{"an anonymous visitor", who["anonymous"], 1},
		{"a player", who["outsider"], 2},
		// The rule with two routes and a negative case, which is the one an
		// OR-chain gets wrong: this owner may read the private secret on their
		// own page and not the dm one.
		{"a page owner", who["co_owner"], 3},
		{"the dm", who["dm"], 4},
		{"an admin", who["admin"], 4},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertBacklinks(t, f, tc.p, tc.want)
			// The count is read over the identical statement; agreeing with a
			// wrong list is the failure this file exists to catch, so the count is
			// checked against the plan's number and not against the list.
			n, err := BacklinkCount(ctx, f.db.Writer(), tc.p, f.targetPage)
			if err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != tc.want {
				t.Errorf("BacklinkCount = %d, want %d", n, tc.want)
			}
		})
	}
}

// The expectations above are only load-bearing if the fixture really is shaped
// the way they assume, so the shape is stated from the fixture rather than from
// the test's own bookkeeping: one public row and one per secret, each attributed
// to its own secret except the public one.
//
// Without this, a fixture that accidentally wrote four public rows would satisfy
// every count assertion in TestRevealUpdatesBacklinkCounts for the wrong reason:
// the counts would agree with each other and say nothing about the secret.
func TestTheBacklinkFixtureAttributesOneRowPerSecret(t *testing.T) {
	t.Parallel()
	f := newMatrixFixture(t)
	who := f.principal(t)

	if got := mustQueryInt(t, f.db.Writer(),
		`SELECT COUNT(*) FROM links WHERE target_page_id = ? AND secret_id IS NULL`, f.targetPage); got != 1 {
		t.Errorf("the fixture holds %d public references to the target, want 1", got)
	}
	for vis, meta := range f.secrets {
		got := mustQueryInt(t, f.db.Writer(),
			`SELECT COUNT(*) FROM links WHERE target_page_id = ? AND secret_id = ?`,
			f.targetPage, meta.secretID())
		if got != 1 {
			t.Errorf("the fixture holds %d references from the %s secret, want 1", got, vis)
		}
	}
	// And each secret is reachable only through its own routes, so a predicate
	// that tested authorship but dropped ownership — or the reverse — would answer
	// differently here than the counts above expect.
	for _, tc := range []struct {
		name string
		p    authz.Principal
		vis  authz.Visibility
		want bool
	}{
		{"the co-owner may read the private secret", who["co_owner"], authz.VisibilityPrivate, true},
		{"the co-owner may not read the dm secret", who["co_owner"], authz.VisibilityDM, false},
		{"an outsider may not read the private secret", who["outsider"], authz.VisibilityPrivate, false},
		{"the dm may read the dm secret", who["dm"], authz.VisibilityDM, true},
	} {
		if got := expectVisible(tc.p, f.secrets[tc.vis]); got != tc.want {
			t.Errorf("%s = %v, want %v; the rule the counts above rely on is not the one in the table",
				tc.name, got, tc.want)
		}
	}
}
