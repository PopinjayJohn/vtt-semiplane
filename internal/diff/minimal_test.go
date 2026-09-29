package diff

// The property suite. The spike that chose this algorithm ran the same
// generator over 30,000 short and 3,000 long random pairs and found five real
// bugs, two of them scripts that were valid-looking but non-diagonal — they
// render correctly and silently lose lines, which is the same shape as the two
// hangs AGENTS.md §11 records. These are the tests that find that class.

import (
	"math/rand"
	"strings"
	"testing"
)

// propertyIterations is the bound on the exhaustive random cross-check.
//
// It is a fixed count rather than a time budget so the suite is reproducible,
// and it is sized to run in CI: the whole suite is seconds, not minutes. In
// short mode it drops to a tenth, which still covers every code path.
func propertyIterations() int {
	if testing.Short() {
		return 2000
	}
	return 20000
}

// TestHandRolledIsMinimal cross-checks the middle-snake search against a
// brute-force LCS on small inputs.
//
// It separates two failures that a round trip alone cannot: a *minimal but
// wrong* script and a *correct but long* one. Both round-trip; only the second
// one shows up here. The alphabet deliberately includes entries with no
// terminator and repeated entries, so the generated file's real line count is
// often not the count the generator thought it wrote — which is precisely the
// mismatch that makes a cross-check worth having.
func TestHandRolledIsMinimal(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(20260929))
	alphabet := []string{"a", "b", "c", "d", "\n", "x\n", "y\n", "aa", "bb", ""}
	for iter := 0; iter < propertyIterations(); iter++ {
		a := randLines(rng, alphabet, rng.Intn(9))
		b := randLines(rng, alphabet, rng.Intn(9))
		sa, sb := strings.Join(a, ""), strings.Join(b, "")

		edits := Lines([]byte(sa), []byte(sb))
		checkProjections(t, iter, sa, sb, edits)

		// The reference is computed over the same lines the diff sees, which
		// is not always what the generator built.
		la, lb := texts(Split([]byte(sa))), texts(Split([]byte(sb)))
		want := len(la) + len(lb) - 2*lcsLen(la, lb)
		if got := editDistance(edits); got != want {
			t.Fatalf("iter %d: not minimal, D=%d want D=%d (n=%d m=%d lcs=%d)\n a=%q\n b=%q",
				iter, got, want, len(la), len(lb), lcsLen(la, lb), sa, sb)
		}
	}
}

// TestMinimalOnGeneratedPairs is the same cross-check over the shapes a vault
// actually contains rather than over a two-letter alphabet: empty lines, lines
// that repeat, and pages that share a long prefix.
func TestMinimalOnGeneratedPairs(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(4242))
	alphabet := []string{"", "\n", "## a heading\n", "- item\n", "> [!note] x\n", "same line\n", "| a | b |\n"}
	n := propertyIterations() / 20
	if n < 100 {
		n = 100
	}
	for iter := 0; iter < n; iter++ {
		base := randLines(rng, alphabet, 1+rng.Intn(25))
		a := append([]string(nil), base...)
		// Change a few lines in place, so most of the page is shared and the
		// search has a real prefix to trim.
		for k := 0; k < 1+rng.Intn(4); k++ {
			if len(a) == 0 {
				break
			}
			a[rng.Intn(len(a))] = alphabet[rng.Intn(len(alphabet))]
		}
		sa, sb := strings.Join(a, ""), strings.Join(b0(rng, base, alphabet), "")
		edits := Lines([]byte(sa), []byte(sb))
		checkProjections(t, iter, sa, sb, edits)
		la, lb := texts(Split([]byte(sa))), texts(Split([]byte(sb)))
		if got, want := editDistance(edits), len(la)+len(lb)-2*lcsLen(la, lb); got != want {
			t.Fatalf("iter %d: not minimal, D=%d want D=%d\n a=%q\n b=%q", iter, got, want, sa, sb)
		}
	}
}

// b0 derives the right-hand side of a generated pair from the left one, so the
// two share most of their lines and the diff is a patch rather than a rewrite.
func b0(rng *rand.Rand, base, alphabet []string) []string {
	b := append([]string(nil), base...)
	if len(b) > 0 && rng.Intn(2) == 0 {
		b[rng.Intn(len(b))] = alphabet[rng.Intn(len(alphabet))]
	}
	if rng.Intn(2) == 0 {
		b = append(b, alphabet[rng.Intn(len(alphabet))])
	}
	return b
}

// TestRoundTripProjectionOnLongRandomInputs runs the round-trip property on
// longer, heavily repetitive inputs, which is where the middle-snake bounds
// and the recursion depth actually bite. Half the pairs are a block move,
// because a block move is the case a prefix/suffix trim cannot help with and a
// single-line search would get wrong.
func TestRoundTripProjectionOnLongRandomInputs(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(7))
	alphabet := []string{"alpha\n", "beta\n", "gamma\n", "delta\n", "epsilon\n", "\n", "alpha\n", "beta\n"}
	iterations := propertyIterations() / 5
	for iter := 0; iter < iterations; iter++ {
		a := randLines(rng, alphabet, rng.Intn(60))
		b := append([]string(nil), a...)
		switch rng.Intn(3) {
		case 0:
			if len(a) > 3 {
				from := rng.Intn(len(a) - 3)
				size := 1 + rng.Intn(3)
				blk := append([]string(nil), a[from:from+size]...)
				rest := append(append([]string(nil), a[:from]...), a[from+size:]...)
				at := rng.Intn(len(rest) + 1)
				b = append(append(append([]string(nil), rest[:at]...), blk...), rest[at:]...)
			}
		case 1:
			if len(a) > 0 {
				a[rng.Intn(len(a))] = alphabet[rng.Intn(len(alphabet))]
			}
		case 2:
			b = append(b, alphabet[rng.Intn(len(alphabet))])
		}
		sa, sb := strings.Join(a, ""), strings.Join(b, "")
		checkProjections(t, iter, sa, sb, Lines([]byte(sa), []byte(sb)))
	}
}

// TestDocumentedShapesAreHandled walks the shapes the conflict page has to
// render. Each is a behaviour this package promises, not a fixture.
func TestDocumentedShapesAreHandled(t *testing.T) {
	t.Parallel()
	med := wikiPage("world/neverwinter-faction-web", 30)
	// med ends in a blank line, so an append has to be measured from a file
	// whose last line is a real line or the diff counts the blank one too.
	appended := strings.TrimRight(med, "\n") + "\n"
	tests := []struct {
		name             string
		a, b             string
		wantDel, wantIns int
		wantHunks        int // -1 means "not asserted"
	}{
		{name: "no-change", a: med, b: med, wantDel: 0, wantIns: 0, wantHunks: 0},
		{name: "one-line-change", a: med, b: smallEdit(med), wantDel: 1, wantIns: 1, wantHunks: 1},
		{name: "append-only", a: appended, b: appended + "One more line.\n", wantDel: 0, wantIns: 1, wantHunks: 1},
		{
			name:      "truncate-only",
			a:         med,
			b:         firstLines(med, 5),
			wantDel:   len(Split([]byte(med))) - 5,
			wantIns:   0,
			wantHunks: 1,
		},
		{name: "create-from-empty", a: "", b: "one\ntwo\n", wantDel: 0, wantIns: 2, wantHunks: 1},
		{name: "empty-from-content", a: "one\ntwo\n", b: "", wantDel: 2, wantIns: 0, wantHunks: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			edits := Lines([]byte(tc.a), []byte(tc.b))
			_, del, ins := countOps(edits)
			if del != tc.wantDel || ins != tc.wantIns {
				t.Errorf("delete/insert = %d/%d, want %d/%d", del, ins, tc.wantDel, tc.wantIns)
			}
			checkProjections(t, 0, tc.a, tc.b, edits)
			hunks := Hunks(Split([]byte(tc.a)), Split([]byte(tc.b)), edits, 3)
			if tc.wantHunks >= 0 && len(hunks) != tc.wantHunks {
				t.Errorf("hunks = %d, want %d", len(hunks), tc.wantHunks)
			}
		})
	}
	t.Run("block-move", func(t *testing.T) {
		t.Parallel()
		// A moved block is a delete and an insert of the same lines, not a
		// reorder: the projections are the only thing that distinguishes the
		// two, and this is the shape where getting it wrong is easiest.
		a, b := med, blockMove(med)
		edits := Lines([]byte(a), []byte(b))
		checkProjections(t, 0, a, b, edits)
		_, del, ins := countOps(edits)
		if del != ins || del == 0 {
			t.Errorf("a block move is %d deletes and %d inserts, want the same non-zero count of each", del, ins)
		}
	})
	t.Run("whole-file-replace", func(t *testing.T) {
		t.Parallel()
		a, b := med, different()
		edits := Lines([]byte(a), []byte(b))
		checkProjections(t, 0, a, b, edits)
		hunks := Hunks(Split([]byte(a)), Split([]byte(b)), edits, 3)
		if len(hunks) != 1 {
			t.Fatalf("two unrelated pages produced %d hunks, want 1", len(hunks))
		}
		if hunks[0].CountA != len(Split([]byte(a))) || hunks[0].CountB != len(Split([]byte(b))) {
			t.Errorf("a whole-file replace hunk spans %d/%d lines, want the whole file %d/%d",
				hunks[0].CountA, hunks[0].CountB, len(Split([]byte(a))), len(Split([]byte(b))))
		}
	})
}

// TestScriptLineNumbersIndexTheInputs is the cheap invariant a caller depends
// on: every Edit names a real line of the side it applies to, and the lines of
// one kind are strictly increasing. A script whose numbers drift by one, or
// which names the same line twice, renders a whole page shifted — or deletes
// one line and keeps its twin.
func TestScriptLineNumbersIndexTheInputs(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			la, lb := len(Split([]byte(tc.a))), len(Split([]byte(tc.b)))
			prevDel, prevIns := 0, 0
			for i, e := range Lines([]byte(tc.a), []byte(tc.b)) {
				switch e.Op {
				case OpDelete:
					if e.Line < 1 || e.Line > la || e.Line <= prevDel {
						t.Fatalf("edit %d: delete at a-line %d, want 1..%d and greater than the previous delete's %d",
							i, e.Line, la, prevDel)
					}
					prevDel = e.Line
				case OpInsert:
					if e.Line < 1 || e.Line > lb || e.Line <= prevIns {
						t.Fatalf("edit %d: insert at b-line %d, want 1..%d and greater than the previous insert's %d",
							i, e.Line, lb, prevIns)
					}
					prevIns = e.Line
				default:
					t.Fatalf("edit %d: Lines emitted an %v, which is a change script and must not", i, e.Op)
				}
			}
		})
	}
}
