package diff

import (
	"fmt"
	"strings"
	"testing"
)

// numbered builds a page of n one-word lines and applies the edits in changes,
// which is keyed by 1-based line number. Handing a test a page whose lines are
// "line 7" rather than prose means an assertion can name the line it means.
func numbered(n int, changes map[int]string) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i+1)
	}
	for at, text := range changes {
		lines[at-1] = strings.TrimSuffix(text, "\n")
	}
	return strings.Join(lines, "\n") + "\n"
}

// changedIn counts the non-equal edits in a hunk.
func changedIn(h Hunk) (del, ins int) {
	for _, e := range h.Edits {
		switch e.Op {
		case OpDelete:
			del++
		case OpInsert:
			ins++
		}
	}
	return del, ins
}

func TestHunksGroupWithContext(t *testing.T) {
	t.Parallel()
	const lines = 40
	page := numbered(lines, nil)
	// Two changes 30 lines apart: with 3 lines of context they cannot share a
	// hunk without their contexts overlapping, which is what "per-hunk
	// keep-mine / keep-theirs" depends on.
	edited := numbered(lines, map[int]string{5: "CHANGED 5\n", 35: "CHANGED 35\n"})
	edits := Lines([]byte(page), []byte(edited))

	for _, tc := range []struct {
		name     string
		context  int
		wantHunk int
	}{
		{name: "no-context-separates-everything", context: 0, wantHunk: 2},
		{name: "three-context-separates-distant-changes", context: 3, wantHunk: 2},
		{name: "wide-context-merges", context: 20, wantHunk: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hunks := Hunks(Split([]byte(page)), Split([]byte(edited)), edits, tc.context)
			if len(hunks) != tc.wantHunk {
				t.Fatalf("context %d: %d hunks, want %d: %+v", tc.context, len(hunks), tc.wantHunk, hunks)
			}
			var del, ins int
			for i, h := range hunks {
				del, ins = changedIn(h)
				// Every hunk carries at most context lines of context on each
				// side, unless the file runs out.
				lead, trail := 0, 0
				for lead < len(h.Edits) && h.Edits[lead].Op == OpEqual {
					lead++
				}
				for trail < len(h.Edits) && h.Edits[len(h.Edits)-1-trail].Op == OpEqual {
					trail++
				}
				if lead > tc.context || trail > tc.context {
					t.Errorf("hunk %d has %d/%d context lines, want at most %d each",
						i, lead, trail, tc.context)
				}
				if del == 0 && ins == 0 {
					t.Errorf("hunk %d carries no change at all", i)
				}
			}
			// Whatever the grouping, the hunks between them carry both
			// changes and nothing else.
			var gotDel, gotIns int
			for _, h := range hunks {
				d, in := changedIn(h)
				gotDel += d
				gotIns += in
			}
			if gotDel != 2 || gotIns != 2 {
				t.Errorf("hunks carry %d deletes and %d inserts, want 2 and 2", gotDel, gotIns)
			}
		})
	}
}

// TestHunksMergeAdjacentChanges is the other side of the same rule: two
// changes a line apart are one hunk, because splitting them would show the
// line between them twice.
func TestHunksMergeAdjacentChanges(t *testing.T) {
	t.Parallel()
	const lines = 40
	tests := []struct {
		name     string
		changes  map[int]string
		context  int
		wantHunk int
	}{
		{
			name:     "two-changes-with-one-line-between-them",
			changes:  map[int]string{10: "A\n", 12: "B\n"},
			context:  3,
			wantHunk: 1,
		},
		{
			name:     "the-same-pair-with-no-context",
			changes:  map[int]string{10: "A\n", 12: "B\n"},
			context:  0,
			wantHunk: 2,
		},
		{
			name:     "exactly-2-context-lines-apart-merges",
			changes:  map[int]string{10: "A\n", 13: "B\n"},
			context:  1,
			wantHunk: 1,
		},
		{
			name:     "two-lines-apart-does-not-merge-at-one-context",
			changes:  map[int]string{10: "A\n", 13: "B\n"},
			context:  0,
			wantHunk: 2,
		},
		{
			name:     "contiguous-changes",
			changes:  map[int]string{10: "A\n", 11: "B\n", 12: "C\n"},
			context:  0,
			wantHunk: 1,
		},
		{
			name:     "a-block-replacement-is-one-hunk",
			changes:  map[int]string{10: "A\n", 11: "B\n", 12: "C\n", 13: "D\n"},
			context:  0,
			wantHunk: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			page := numbered(lines, nil)
			edited := numbered(lines, tc.changes)
			hunks := Hunks(Split([]byte(page)), Split([]byte(edited)), Lines([]byte(page), []byte(edited)), tc.context)
			if len(hunks) != tc.wantHunk {
				t.Fatalf("context %d: %d hunks, want %d: %+v", tc.context, len(hunks), tc.wantHunk, hunks)
			}
			var got int
			for _, h := range hunks {
				d, i := changedIn(h)
				got += d + i
			}
			if want := 2 * len(tc.changes); got != want {
				t.Errorf("hunks carry %d changes, want %d", got, want)
			}
		})
	}
}

// TestHunkEditsIndexTheInputs is the invariant a renderer needs: every entry of
// Hunk.Edits names a real line of the right side, the equal entries are the
// lines between the changes in order, and the counts agree with the edits.
func TestHunkEditsIndexTheInputs(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			la, lb := Split([]byte(tc.a)), Split([]byte(tc.b))
			edits := Lines([]byte(tc.a), []byte(tc.b))
			for _, ctx := range []int{0, 1, 3, 7} {
				for i, h := range Hunks(la, lb, edits, ctx) {
					assertHunkIsWellFormed(t, ctx, i, h, la, lb)
				}
			}
		})
	}
}

func assertHunkIsWellFormed(t *testing.T, ctx, idx int, h Hunk, la, lb []Line) {
	t.Helper()
	if h.FromA < 1 || h.FromB < 1 {
		t.Errorf("context %d hunk %d: FromA=%d FromB=%d, want both 1 or more", ctx, idx, h.FromA, h.FromB)
		return
	}
	if h.CountA < 0 || h.CountB < 0 {
		t.Errorf("context %d hunk %d: negative count %d/%d", ctx, idx, h.CountA, h.CountB)
		return
	}
	if h.FromA-1+h.CountA > len(la) || h.FromB-1+h.CountB > len(lb) {
		t.Errorf("context %d hunk %d: range %d+%d/%d+%d runs past %d/%d lines",
			ctx, idx, h.FromA, h.CountA, h.FromB, h.CountB, len(la), len(lb))
		return
	}
	if len(h.Edits) == 0 {
		t.Errorf("context %d hunk %d: no edits, so it renders nothing", ctx, idx)
		return
	}
	// The hunk opens and closes on context unless it reaches the end of the
	// file, and a zero-width context has none to open or close on.
	if ctx > 0 && h.Edits[0].Op != OpEqual && (h.FromA > 1 || h.FromB > 1) {
		t.Errorf("context %d hunk %d: opens on a change, not on context", ctx, idx)
	}
	reachesA := h.FromA-1+h.CountA >= len(la)
	reachesB := h.FromB-1+h.CountB >= len(lb)
	if ctx > 0 {
		if last := h.Edits[len(h.Edits)-1]; last.Op != OpEqual && !reachesA && !reachesB {
			t.Errorf("context %d hunk %d: closes on a change, not on context", ctx, idx)
		}
	}
	// Replaying just the hunk, against the lines its range names, has to
	// reproduce that range of b. This is the property the conflict page's
	// per-hunk keep-mine / keep-theirs decision rests on.
	gotA := la[h.FromA-1 : h.FromA-1+h.CountA]
	gotB := lb[h.FromB-1 : h.FromB-1+h.CountB]
	fromA, fromB, bad := replayHunk(h, gotA, gotB)
	if bad != "" {
		t.Errorf("context %d hunk %d: %s", ctx, idx, bad)
		return
	}
	if !sameStrings(fromA, texts(gotA)) {
		t.Errorf("context %d hunk %d: its own edits do not reproduce its range of a", ctx, idx)
	}
	if !sameStrings(fromB, texts(gotB)) {
		t.Errorf("context %d hunk %d: its own edits do not reproduce its range of b", ctx, idx)
	}
}

// replayHunk rebases a hunk's absolute line numbers onto the two ranges the
// hunk names, and replays it there. A hunk is a slice of a diff, and replaying
// it in isolation is only meaningful once its numbering is relative to itself.
func replayHunk(h Hunk, a, b []Line) (fromA, fromB []string, bad string) {
	rebased := make([]Edit, len(h.Edits))
	for i, e := range h.Edits {
		switch e.Op {
		case OpEqual, OpDelete:
			e.Line -= h.FromA - 1
		case OpInsert:
			e.Line -= h.FromB - 1
		}
		rebased[i] = e
	}
	return replay(rebased, a, b)
}

// TestHunksCoverEveryChangeExactlyOnce: a change no hunk shows is a change the
// page silently keeps, which is the worst outcome a conflict page can have.
func TestHunksCoverEveryChangeExactlyOnce(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			la, lb := Split([]byte(tc.a)), Split([]byte(tc.b))
			edits := Lines([]byte(tc.a), []byte(tc.b))
			for _, ctx := range []int{0, 2, 3} {
				seen := make(map[Edit]int)
				order := 0
				for _, h := range Hunks(la, lb, edits, ctx) {
					for _, e := range h.Edits {
						if e.Op == OpEqual {
							continue
						}
						seen[e]++
						order++
					}
				}
				if order != len(edits) {
					t.Errorf("context %d: hunks carry %d changes, the script has %d", ctx, order, len(edits))
				}
				for e, n := range seen {
					if n != 1 {
						t.Errorf("context %d: change %v appears in %d hunks, want 1", ctx, e, n)
					}
				}
			}
		})
	}
}

// TestHunksAtTheEndsOfTheFile covers the offsets a conflict page has to render
// correctly: a change on the first line has no leading context, and one on the
// last line has no trailing context, and neither may index below 1.
func TestHunksAtTheEndsOfTheFile(t *testing.T) {
	t.Parallel()
	const lines = 12
	tests := []struct {
		name       string
		changes    map[int]string
		wantFromA  int
		wantCountA int
	}{
		// A change on the first line has no leading context to show and one on
		// the last line has no trailing context, so the range collapses at
		// the edges rather than indexing below 1 or past the end.
		{name: "first-line", changes: map[int]string{1: "CHANGED\n"}, wantFromA: 1, wantCountA: 4},
		{name: "second-line", changes: map[int]string{2: "CHANGED\n"}, wantFromA: 1, wantCountA: 5},
		{name: "penultimate-line", changes: map[int]string{lines - 1: "CHANGED\n"}, wantFromA: lines - 4, wantCountA: 5},
		{name: "last-line", changes: map[int]string{lines: "CHANGED\n"}, wantFromA: lines - 3, wantCountA: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			page := numbered(lines, nil)
			edited := numbered(lines, tc.changes)
			la, lb := Split([]byte(page)), Split([]byte(edited))
			hunks := Hunks(la, lb, Lines([]byte(page), []byte(edited)), 3)
			if len(hunks) != 1 {
				t.Fatalf("got %d hunks, want 1", len(hunks))
			}
			h := hunks[0]
			if h.FromA != tc.wantFromA || h.CountA != tc.wantCountA {
				t.Errorf("hunk = FromA %d CountA %d, want %d and %d", h.FromA, h.CountA, tc.wantFromA, tc.wantCountA)
			}
			assertHunkIsWellFormed(t, 3, 0, h, la, lb)
		})
	}
}

// TestHunkForAnEmptyFileHasAUsableRange pins the offset convention at the
// edges: a hunk that only inserts reports FromA as the point it happens at
// with CountA 0, rather than FromA 0, so a caller can slice a's lines with
// FromA-1 : FromA-1+CountA and get the empty slice it expects.
func TestHunkForAnEmptyFileHasAUsableRange(t *testing.T) {
	t.Parallel()
	la, lb := Split(nil), Split([]byte("one\ntwo\n"))
	hunks := Hunks(la, lb, Lines(nil, []byte("one\ntwo\n")), 3)
	if len(hunks) != 1 {
		t.Fatalf("got %d hunks, want 1", len(hunks))
	}
	h := hunks[0]
	if h.CountA != 0 || h.CountB != 2 {
		t.Errorf("hunk = CountA %d CountB %d, want 0 and 2", h.CountA, h.CountB)
	}
	if got := la[h.FromA-1 : h.FromA-1+h.CountA]; len(got) != 0 {
		t.Errorf("a hunk with no a-lines does not slice to empty: FromA=%d", h.FromA)
	}
	if got := lb[h.FromB-1 : h.FromB-1+h.CountB]; len(got) != 2 {
		t.Errorf("a hunk does not slice to its b-lines: FromB=%d", h.FromB)
	}
}
