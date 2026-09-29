package secrets

import (
	"bytes"
	"testing"
)

// TestHunksBetweenIsTheChangeEnvelope pins the arithmetic of HunkSummary.
//
// It is an in-package test because hunksBetween is unexported and the numbers it
// produces are indices into slices the caller never showed this package. A
// caller rendering FromA-1 as an offset needs those numbers to be exactly the
// line numbers they are documented as, and that is not reachable from outside.
func TestHunksBetweenIsTheChangeEnvelope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		a, b   string
		hunks  int
		fromA  int
		countA int
		fromB  int
		countB int
	}{
		{
			name: "identical documents have no hunks",
			a:    "one\ntwo\n", b: "one\ntwo\n",
		},
		{
			name:  "an insertion in the middle",
			a:     "one\ntwo\n",
			b:     "one\none-and-a-half\ntwo\n",
			hunks: 1, fromA: 2, countA: 0, fromB: 2, countB: 1,
		},
		{
			name:  "a deletion in the middle",
			a:     "one\ntwo\nthree\n",
			b:     "one\nthree\n",
			hunks: 1, fromA: 2, countA: 1, fromB: 2, countB: 0,
		},
		{
			name: "an empty document against itself",
			a:    "", b: "",
		},
		{
			name:  "everything replaced",
			a:     "a\n",
			b:     "b\n",
			hunks: 1, fromA: 1, countA: 1, fromB: 1, countB: 1,
		},
		{
			name:  "a change at the very start",
			a:     "one\ntwo\n",
			b:     "zero\none\ntwo\n",
			hunks: 1, fromA: 1, countA: 0, fromB: 1, countB: 1,
		},
		{
			name:  "a change at the very end",
			a:     "one\ntwo\n",
			b:     "one\ntwo\nthree\n",
			hunks: 1, fromA: 3, countA: 0, fromB: 3, countB: 1,
		},
		{
			name:  "a CRLF difference is a difference",
			a:     "one\ntwo\n",
			b:     "one\r\ntwo\r\n",
			hunks: 1, fromA: 1, countA: 2, fromB: 1, countB: 2,
		},
		{
			name:  "a document with no trailing newline",
			a:     "one",
			b:     "two",
			hunks: 1, fromA: 1, countA: 1, fromB: 1, countB: 1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hunksBetween([]byte(tc.a), []byte(tc.b))
			if len(got) != tc.hunks {
				t.Fatalf("got %d hunks, want %d: %+v", len(got), tc.hunks, got)
			}
			if tc.hunks == 0 {
				return
			}
			want := HunkSummary{
				FromA: tc.fromA, CountA: tc.countA,
				FromB: tc.fromB, CountB: tc.countB,
			}
			if got[0] != want {
				t.Errorf("got %+v, want %+v", got[0], want)
			}
			// The numbers are usable as indices, which is what the caller needs.
			la, lb := splitLines([]byte(tc.a)), splitLines([]byte(tc.b))
			if want.FromA-1+want.CountA > len(la) {
				t.Errorf("the a-range %d..%d is outside %d lines", want.FromA, want.CountA, len(la))
			}
			if want.FromB-1+want.CountB > len(lb) {
				t.Errorf("the b-range %d..%d is outside %d lines", want.FromB, want.CountB, len(lb))
			}
		})
	}
}

// TestSplitLinesTerminates is the progress assertion AGENTS.md §11 asks for
// anywhere a cursor walks a byte range: every line taken is strictly shorter
// than the input it was taken from, so the loop cannot spin. The property is
// asserted by reconstruction — the lines must rejoin to the input exactly —
// because a splitter that drops or repeats a byte would pass a count check and
// corrupt every envelope computed from it.
func TestSplitLinesTerminates(t *testing.T) {
	t.Parallel()
	for _, src := range []string{
		"", "\n", "\n\n\n", "one", "one\n", "one\ntwo", "one\r\ntwo\r\n",
		"‹s:abcdef012345:3:00000000›\n",
	} {
		lines := splitLines([]byte(src))
		if got := bytes.Join(lines, nil); !bytes.Equal(got, []byte(src)) {
			t.Errorf("%q: the lines rejoin to %q", src, got)
		}
		// A line never runs past its own terminator, and only the last may lack one.
		for i, line := range lines {
			if i < len(lines)-1 && !bytes.HasSuffix(line, []byte{'\n'}) {
				t.Errorf("%q: line %d does not end in a terminator: %q", src, i, line)
			}
		}
	}
}
