package web

import (
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
)

// The side-by-side fold is the one piece of real logic on these six surfaces,
// and it is the piece a reader cannot check by looking at the code: what they
// see is a table, and the table is right when the pairing underneath it is
// right. So it is table-driven here, over the shapes a change script actually
// takes, and the cases are named for the shape rather than numbered.
func TestDiffRowsPairsEachChangeWithItsOwn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hunk httpapi.DiffHunk
		want []diffRow
	}{
		{
			// The two common shapes, both of which put one line on each side of
			// a row rather than two rows.
			name: "one line replaced by one line is one row",
			hunk: httpapi.DiffHunk{FromA: 3, CountA: 1, FromB: 3, CountB: 1, Lines: []httpapi.DiffLine{
				{Op: "-", No: 3, Text: "the room was dry"},
				{Op: "+", No: 3, Text: "the room is wet"},
			}},
			want: []diffRow{
				{LeftNo: 3, Left: "the room was dry", RightNo: 3, Right: "the room is wet", Op: diffOpChanged},
			},
		},
		{
			// The shape that proves the padding: three removals against one
			// insertion is three rows, and the two rows with nothing on one side
			// carry no number for the side that has no line.
			name: "an uneven replacement pads without inventing a line",
			hunk: httpapi.DiffHunk{FromA: 2, CountA: 3, FromB: 2, CountB: 1, Lines: []httpapi.DiffLine{
				{Op: "-", No: 2, Text: "one"},
				{Op: "-", No: 3, Text: "two"},
				{Op: "-", No: 4, Text: "three"},
				{Op: "+", No: 2, Text: "one, rewritten"},
			}},
			want: []diffRow{
				{LeftNo: 2, Left: "one", RightNo: 2, Right: "one, rewritten", Op: diffOpChanged},
				{LeftNo: 3, Left: "two", Op: diffOpRemoved},
				{LeftNo: 4, Left: "three", Op: diffOpRemoved},
			},
		},
		{
			name: "a pure insertion has no left-hand line",
			hunk: httpapi.DiffHunk{FromA: 2, CountA: 0, FromB: 2, CountB: 2, Lines: []httpapi.DiffLine{
				{Op: "+", No: 2, Text: "inserted"},
				{Op: "+", No: 3, Text: "also inserted"},
			}},
			want: []diffRow{
				{RightNo: 2, Right: "inserted", Op: diffOpAdded},
				{RightNo: 3, Right: "also inserted", Op: diffOpAdded},
			},
		},
		{
			name: "a pure deletion has no right-hand line",
			hunk: httpapi.DiffHunk{FromA: 2, CountA: 1, FromB: 2, CountB: 0, Lines: []httpapi.DiffLine{
				{Op: "-", No: 2, Text: "gone"},
			}},
			want: []diffRow{
				{LeftNo: 2, Left: "gone", Op: diffOpRemoved},
			},
		},
		{
			// The arithmetic the whole fold exists for. A change script numbers
			// an equal line into the left side, so after two inserted lines the
			// same context line is number 5 on disk and number 7 on the other
			// side. Printing the left number on both sides is a diff that says
			// the file is longer than it is.
			name: "context after an insertion is numbered on both sides",
			hunk: httpapi.DiffHunk{FromA: 3, CountA: 3, FromB: 3, CountB: 5, Lines: []httpapi.DiffLine{
				{Op: " ", No: 3, Text: "before"},
				{Op: "+", No: 4, Text: "new one"},
				{Op: "+", No: 5, Text: "new two"},
				{Op: " ", No: 4, Text: "after"},
			}},
			want: []diffRow{
				{LeftNo: 3, Left: "before", RightNo: 3, Right: "before", Op: diffOpContext},
				{RightNo: 4, Right: "new one", Op: diffOpAdded},
				{RightNo: 5, Right: "new two", Op: diffOpAdded},
				{LeftNo: 4, Left: "after", RightNo: 6, Right: "after", Op: diffOpContext},
			},
		},
		{
			// The other direction, and the one a hunk header's own FromB-FromA
			// would get wrong on its own: a hunk that begins after two deletions
			// starts the right side two lines behind the left.
			name: "a hunk that begins behind the left side stays behind it",
			hunk: httpapi.DiffHunk{FromA: 9, CountA: 3, FromB: 7, CountB: 3, Lines: []httpapi.DiffLine{
				{Op: " ", No: 9, Text: "context"},
				{Op: "-", No: 10, Text: "old"},
				{Op: "+", No: 8, Text: "new"},
				{Op: " ", No: 11, Text: "more context"},
			}},
			want: []diffRow{
				{LeftNo: 9, Left: "context", RightNo: 7, Right: "context", Op: diffOpContext},
				{LeftNo: 10, Left: "old", RightNo: 8, Right: "new", Op: diffOpChanged},
				{LeftNo: 11, Left: "more context", RightNo: 9, Right: "more context", Op: diffOpContext},
			},
		},
		{
			name: "a hunk with no lines is no rows",
			hunk: httpapi.DiffHunk{FromA: 1, CountA: 0, FromB: 1, CountB: 0},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := diffRows(tc.hunk)
			if len(got) != len(tc.want) {
				t.Fatalf("%d rows, want %d:\n%+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("row %d is %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// hunkHeading is what a reader uses to find a change in the file, so the two
// degenerate shapes get their own cases: a hunk that only inserts has no
// left-hand lines, and "lines 2–1" is not a range anybody can look up.
func TestHunkHeadingNamesAnEmptySideAsAPosition(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		index, total int
		hunk         httpapi.DiffHunk
		want         string
	}{
		{
			name: "both sides have lines",
			hunk: httpapi.DiffHunk{FromA: 4, CountA: 2, FromB: 4, CountB: 3},
			want: "Change 1 — lines 4–5 in the file on disk, lines 4–6 in your version",
		},
		{
			name: "the left side is empty",
			hunk: httpapi.DiffHunk{FromA: 12, CountA: 0, FromB: 12, CountB: 1},
			want: "Change 1 — after line 12 in the file on disk, lines 12–12 in your version",
		},
		{
			name: "the right side is empty",
			hunk: httpapi.DiffHunk{FromA: 1, CountA: 3, FromB: 1, CountB: 0},
			want: "Change 1 — lines 1–3 in the file on disk, after line 1 in your version",
		},
		{
			name:  "the total is only said when there is more than one",
			index: 2,
			total: 5,
			hunk:  httpapi.DiffHunk{FromA: 1, CountA: 1, FromB: 1, CountB: 1},
			want:  "Change 3 of 5 — lines 1–1 in the file on disk, lines 1–1 in your version",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			total := tc.total
			if total == 0 {
				total = 1
			}
			if got := hunkHeading(tc.index, total, tc.hunk, onDiskProse, mineProse); got != tc.want {
				t.Errorf("the heading is %q, want %q", got, tc.want)
			}
		})
	}
}

// The attribution sentence is the one place the history panel names who is
// responsible, so the two shapes that look alike — an empty author and a flag
// saying the row is external — are asserted to be the same sentence, and the
// four sources are asserted to be four different ones.
//
// "nobody" is on the list of refusals because it is the tempting rendering: an
// empty author is the absence of an account, and a panel that fills the
// absence in with a person-shaped word is making a claim about a file.
func TestRevisionCauseNamesWhoAndNeverNobody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, source, author string
		external             bool
		want                 string
	}{
		{name: "an empty author is an external change", source: "external", want: "changed outside the app"},
		{name: "the flag says so too", source: "external", external: true, want: "changed outside the app"},
		{name: "a save names its author", source: "app", author: "thia", want: "changed by thia"},
		{name: "a creation says created", source: "create", author: "thia", want: "created by thia"},
		{name: "a deletion says deleted", source: "delete", author: "thia", want: "deleted by thia"},
		{name: "the flag beats a name", source: "app", author: "thia", external: true, want: "changed outside the app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := revisionCause(tc.source, tc.author, tc.external)
			if got != tc.want {
				t.Errorf("the cause is %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "nobody") {
				t.Errorf("the cause is %q, which names nobody rather than what happened", got)
			}
		})
	}
}
