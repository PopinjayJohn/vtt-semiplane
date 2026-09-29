package diff

// Test helpers. None of this is in the package: a round-trip test that called
// the implementation's own replay would prove only that the replay agrees with
// itself, and the spike's property suite found five real bugs precisely because
// its check was written independently of the search.

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// checkProjections asserts both halves of the round trip for a whole script:
// it describes a real alignment of a onto b, and replaying it onto a's lines
// yields b and onto b's lines yields a.
func checkProjections(t *testing.T, iter int, sa, sb string, edits []Edit) {
	t.Helper()
	a, b := Split([]byte(sa)), Split([]byte(sb))
	fromA, fromB, bad := replay(edits, a, b)
	switch {
	case bad != "":
		t.Fatalf("iter %d: %s\n a=%q\n b=%q\n edits=%v", iter, bad, sa, sb, edits)
	case !sameStrings(fromA, texts(a)):
		t.Fatalf("iter %d: the script's projection is not a\n a=%q\n got=%q", iter, sa, fromA)
	case !sameStrings(fromB, texts(b)):
		t.Fatalf("iter %d: the script's projection is not b\n b=%q\n got=%q", iter, sb, fromB)
	}
}

// replay walks a change script the way a merge would and returns the two sides
// it implies. It reads the line numbers and the two inputs and nothing else,
// and it checks the alignment rather than assuming it: the lines the script
// calls equal really have to be equal, so a script that pairs up two different
// lines fails here even though both of its projections would come out the
// right length.
//
// The returned fromA must equal a's lines and fromB must equal b's, both in
// order. A script that reordered a line, emitted it twice, or dropped it
// satisfies at most one of them, which is why both are checked. bad is empty
// when the script is a real alignment; it is a message when it is not.
func replay(edits []Edit, a, b []Line) (fromA, fromB []string, bad string) {
	ai, bi := 1, 1
	// equal consumes one line from each side and checks that they are the
	// same line. It never panics, so a fuzz seed that produces a malformed
	// script reports rather than crashes.
	equal := func() bool {
		switch {
		case ai > len(a) || bi > len(b):
			bad = fmt.Sprintf("the script pairs a-line %d with b-line %d, past the end of a (%d lines) or b (%d lines)",
				ai, bi, len(a), len(b))
			return false
		case !bytes.Equal(a[ai-1].Text, b[bi-1].Text):
			bad = fmt.Sprintf("the script pairs a-line %d %q with b-line %d %q as the same line",
				ai, a[ai-1].Text, bi, b[bi-1].Text)
			return false
		}
		fromA = append(fromA, string(a[ai-1].Text))
		fromB = append(fromB, string(b[bi-1].Text))
		ai++
		bi++
		return true
	}
	for _, e := range edits {
		switch e.Op {
		case OpEqual:
			for ai < e.Line {
				if !equal() {
					return fromA, fromB, bad
				}
			}
			if !equal() {
				return fromA, fromB, bad
			}
		case OpDelete:
			for ai < e.Line {
				if !equal() {
					return fromA, fromB, bad
				}
			}
			if ai > len(a) {
				bad = fmt.Sprintf("the script deletes a-line %d, past the end of a (%d lines)", e.Line, len(a))
				return fromA, fromB, bad
			}
			fromA = append(fromA, string(a[ai-1].Text))
			ai++
		case OpInsert:
			for bi < e.Line {
				if !equal() {
					return fromA, fromB, bad
				}
			}
			if bi > len(b) {
				bad = fmt.Sprintf("the script inserts at b-line %d, past the end of b (%d lines)", e.Line, len(b))
				return fromA, fromB, bad
			}
			fromB = append(fromB, string(b[bi-1].Text))
			bi++
		default:
			bad = fmt.Sprintf("the script contains the unknown op %v", e.Op)
			return fromA, fromB, bad
		}
	}
	for ai <= len(a) {
		if !equal() {
			return fromA, fromB, bad
		}
	}
	for bi <= len(b) {
		if !equal() {
			return fromA, fromB, bad
		}
	}
	return fromA, fromB, ""
}

// texts is a side's lines as strings, for comparison with replay's output.
func texts(l []Line) []string {
	out := make([]string, len(l))
	for i := range l {
		out[i] = string(l[i].Text)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// editDistance is D: how many lines the script inserts or deletes.
func editDistance(edits []Edit) int {
	d := 0
	for _, e := range edits {
		if e.Op != OpEqual {
			d++
		}
	}
	return d
}

// lcsLen is a brute-force longest common subsequence, used only as the
// reference for minimality. D for a minimal script is len(a) + len(b) - 2*LCS.
func lcsLen(a, b []string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			switch {
			case a[i-1] == b[j-1]:
				cur[j] = prev[j-1] + 1
			case prev[j] >= cur[j-1]:
				cur[j] = prev[j]
			default:
				cur[j] = cur[j-1]
			}
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// randLines builds a random line script over alphabet.
//
// A quarter of the entries come back without a terminator, because two
// adjacent unterminated entries merge into one line on the way in — and
// whether the generator's mental line count and Split's agree is exactly the
// sort of thing a reference cross-check has to be immune to.
func randLines(rng *rand.Rand, alphabet []string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, alphabet[rng.Intn(len(alphabet))])
	}
	if n > 0 && rng.Intn(4) == 0 {
		out[n-1] = strings.TrimSuffix(out[n-1], "\n")
	}
	return out
}

// countOps counts the edits of each op in a script.
func countOps(edits []Edit) (eq, del, ins int) {
	for _, e := range edits {
		switch e.Op {
		case OpEqual:
			eq++
		case OpDelete:
			del++
		case OpInsert:
			ins++
		}
	}
	return eq, del, ins
}
