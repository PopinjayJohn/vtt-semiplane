package diff

// The bound tests. Everything here is about what happens when the diff stops
// being a diff: past MaxEditDistance the search gives up, and a 8 MiB file —
// vault.MaxFileBytes, the largest the indexer will read — must be a bounded
// amount of work rather than an outage.

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"
)

// searchWith builds one descent's bounds. Lines builds a search per call, so
// nothing here is global state and a test can drive every boundary at once.
func searchWith(maxD, maxDepth int, prefilter bool) search {
	return search{maxD: maxD, maxDepth: maxDepth, prefilter: prefilter}
}

// diffWith runs one descent with the bounds a test wants to drive.
func diffWith(la, lb []Line, maxD, maxDepth int, prefilter bool) []Edit {
	return searchWith(maxD, maxDepth, prefilter).diff(nil, la, lb, 0, 0)
}

// whollyDifferent builds n lines of two versions that share nothing, which is
// the shape every bail-out test needs: the lower bound on D is 2n, so only the
// budget can produce a small answer.
func whollyDifferent(n int) (a, b []Line) {
	for i := 0; i < n; i++ {
		a = append(a, Line{Text: []byte(fmt.Sprintf("line %d of the left version\n", i))})
		b = append(b, Line{Text: []byte(fmt.Sprintf("line %d of the right version\n", i))})
	}
	return a, b
}

// TestBailOutAtTheBoundary drives the search budget to the values either side
// of the decision, so the threshold is a stated number rather than a surprise
// found in production.
//
// The region is four lines in which only the middle two match, which is the
// smallest shape where replacing the region costs strictly more than the
// minimal script: a replacement is 8 and the minimum is 4, and the search
// only reaches the middle snake at dd = 2. The identical first and last lines
// are trimmed away, so the region the search actually sees is exactly the four
// middle lines and the two expected answers cannot drift.
func TestBailOutAtTheBoundary(t *testing.T) {
	t.Parallel()
	a := []Line{
		{Text: []byte("head\n")},
		{Text: []byte("x\n")}, {Text: []byte("p\n")}, {Text: []byte("y\n")}, {Text: []byte("q\n")},
		{Text: []byte("tail\n")},
	}
	b := []Line{
		{Text: []byte("head\n")},
		{Text: []byte("q\n")}, {Text: []byte("p\n")}, {Text: []byte("y\n")}, {Text: []byte("x\n")},
		{Text: []byte("tail\n")},
	}

	tests := []struct {
		name   string
		budget int
		wantD  int
	}{
		{name: "zero-replaces-the-region", budget: 0, wantD: 8},
		{name: "one-is-not-enough-to-find-the-snake", budget: 1, wantD: 8},
		{name: "two-finds-it", budget: 2, wantD: 4},
		{name: "the-exported-budget-finds-it", budget: MaxEditDistance, wantD: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			edits := diffWith(a, b, tc.budget, maxRecursionDepth, false)
			if got := editDistance(edits); got != tc.wantD {
				t.Errorf("D = %d, want %d", got, tc.wantD)
			}
			checkProjections(t, 0, join(a), join(b), edits)
		})
	}
}

// TestMaxEditDistanceIsInForce is the test that the exported constant is the
// number the package actually uses, rather than a documented number beside a
// different one.
//
// The region is 10,000 lines of which 3,000 differ, so the minimal D is 6,000
// and replacing the region is twice whatever survives the trim. The search
// only reaches the middle snake at dd = D/2 = 3,000 and its sweep is capped at
// the budget, so the exported constant makes it give up where a budget of 6,000
// would not.
func TestMaxEditDistanceIsInForce(t *testing.T) {
	t.Parallel()
	const lines, changed = 10000, 3000
	a, b := interiorEdits(lines, changed)
	core := trimmedLen(a, b)

	withCap := diffWith(a, b, MaxEditDistance, maxRecursionDepth, false)
	if got := editDistance(withCap); got != 2*core {
		t.Errorf("D = %d with the exported budget, want a whole-region replace of %d", got, 2*core)
	}
	checkProjections(t, 0, join(a), join(b), withCap)

	withoutCap := diffWith(a, b, 2*changed+1, maxRecursionDepth, false)
	if got := editDistance(withoutCap); got != 2*changed {
		t.Errorf("D = %d with a budget above it, want the minimal %d", got, 2*changed)
	}
	checkProjections(t, 0, join(a), join(b), withoutCap)
}

// interiorEdits builds n lines whose first and last match on both sides and
// every third line of the interior differs, so the minimal D is exactly
// 2*changed and the trim can only remove the two matching ends.
func interiorEdits(n, changed int) (a, b []Line) {
	a = make([]Line, n)
	b = make([]Line, n)
	for i := range a {
		text := fmt.Sprintf("line %d\n", i)
		a[i] = Line{Text: []byte(text)}
		b[i] = Line{Text: []byte(text)}
	}
	step := (n - 2) / changed
	if step < 1 {
		step = 1
	}
	for k := 0; k < changed; k++ {
		at := 1 + k*step
		if at >= n-1 {
			break
		}
		b[at] = Line{Text: []byte(fmt.Sprintf("edited line %d\n", at))}
	}
	return a, b
}

// trimmedLen is how many lines of a the prefix and suffix trim leave for the
// search. The expected answers depend on it, so a test computes it rather than
// hard-coding a number that a one-line trim change would silently invalidate.
func trimmedLen(a, b []Line) int {
	pre := 0
	for pre < len(a) && pre < len(b) && lineEq(a[pre], b[pre]) {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && lineEq(a[len(a)-1-suf], b[len(b)-1-suf]) {
		suf++
	}
	return len(a) - pre - suf
}

// TestBailOutIsStillCorrect says what a bail-out is allowed to be: a valid
// script that is not a minimal one. Both projections still have to hold, or the
// conflict page would offer a "keep theirs" that loses the user's text.
func TestBailOutIsStillCorrect(t *testing.T) {
	t.Parallel()
	a, b := whollyDifferent(4000)
	edits := diffWith(a, b, MaxEditDistance, maxRecursionDepth, true)
	if got := editDistance(edits); got != 8000 {
		t.Errorf("D = %d, want a whole-region replace of 8000", got)
	}
	checkProjections(t, 0, join(a), join(b), edits)

	// And the same through the exported entry point, on the 400 KiB page
	// rather than a synthetic one.
	page, other := pathological(), different()+different()
	edits = Lines([]byte(page), []byte(other))
	checkProjections(t, 0, page, other, edits)
	if hunks := Hunks(Split([]byte(page)), Split([]byte(other)), edits, 3); len(hunks) != 1 {
		t.Errorf("two unrelated 400 KiB pages produced %d hunks, want 1", len(hunks))
	}
}

// TestPrefilterDoesNotChangeTheAnswer is the test the prefilter has to pass to
// be worth its twenty lines. Where it does not fire it must produce identical
// scripts to the search without it, over every generated pair — including the
// duplicated and empty lines where a count could go wrong.
func TestPrefilterDoesNotChangeTheAnswer(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(99))
	alphabet := []string{"a\n", "b\n", "\n", "a\n", "c\n", "d\n", "e\n"}
	for iter := 0; iter < propertyIterations()/4; iter++ {
		a := randLines(rng, alphabet, rng.Intn(50))
		b := randLines(rng, alphabet, rng.Intn(50))
		sa, sb := strings.Join(a, ""), strings.Join(b, "")
		la, lb := Split([]byte(sa)), Split([]byte(sb))
		with := diffWith(la, lb, MaxEditDistance, maxRecursionDepth, true)
		without := diffWith(la, lb, MaxEditDistance, maxRecursionDepth, false)
		if !sameEdits(with, without) {
			t.Fatalf("iter %d: the prefilter changed the answer\n a=%q\n b=%q\n with=%v\n without=%v",
				iter, sa, sb, with, without)
		}
	}
}

// TestPrefilterBoundsThePathologicalCase is the other half: the prefilter has
// to fire on the case it was written for, and firing has to be what makes that
// case cheap. A prefilter that never triggers is twenty lines of nothing and
// the comment on it is a lie.
func TestPrefilterBoundsThePathologicalCase(t *testing.T) {
	t.Parallel()
	const n, changed = 10000, 6666
	a, b := interiorEdits(n, changed)
	core := trimmedLen(a, b)

	if !tooExpensive(a, b, MaxEditDistance) {
		t.Fatal("the prefilter did not fire on a region with more unmatched lines than the budget")
	}
	if tooExpensive(a, a, MaxEditDistance) {
		t.Fatal("the prefilter fired on a region against itself")
	}
	// A page with 500 changed lines is well under the budget and must not
	// bail, so the two cases are distinguishable rather than both "expensive".
	near := append([]Line(nil), a...)
	for i := 0; i < 500; i++ {
		near[i] = Line{Text: []byte(fmt.Sprintf("changed line %d\n", i))}
	}
	if tooExpensive(near, a, MaxEditDistance) {
		t.Error("the prefilter fired on 500 changed lines, under the 2000 budget")
	}

	// The answer is the same either way; only the cost is different. With the
	// prefilter the region is replaced wholesale, and without it the search
	// finds the minimal script — which is the whole point of the twenty lines.
	with := diffWith(a, b, MaxEditDistance, maxRecursionDepth, true)
	without := diffWith(a, b, MaxEditDistance, maxRecursionDepth, false)
	if got := editDistance(with); got != 2*core {
		t.Errorf("with the prefilter D = %d, want a whole-region replace of %d", got, 2*core)
	}
	if got := editDistance(without); got != 2*changed {
		t.Errorf("without the prefilter D = %d, want the minimal %d", got, 2*changed)
	}
	checkProjections(t, 0, join(a), join(b), with)
	checkProjections(t, 0, join(a), join(b), without)
}

// TestHugeFileIsBounded is requirement 5: a vault file at the 8 MiB the
// indexer accepts, paired with a file sharing nothing with it, in bounded time
// and bounded memory. The ceilings are generous on purpose — they exist to
// catch a quadratic or an unbounded allocation, not to measure a machine.
//
// It is not t.Parallel: the memory figure is a TotalAlloc delta, and a
// parallel subtest running the property suite would land inside it.
func TestHugeFileIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("8 MiB fixtures: too slow for -short")
	}
	const maxFileBytes = 8 << 20
	a := bigPage(maxFileBytes, "left")
	b := bigPage(maxFileBytes, "right")
	if len(a) < maxFileBytes || len(b) < maxFileBytes {
		t.Fatalf("fixture is %d/%d bytes, want at least %d", len(a), len(b), maxFileBytes)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	t0 := time.Now()
	edits := Lines(a, b)
	elapsed := time.Since(t0)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	t.Logf("8 MiB against 8 MiB, nothing in common: %v, %d edits over %d lines, %.1f MiB allocated",
		elapsed.Round(time.Microsecond), len(edits), len(Split(a)), float64(allocated)/(1<<20))
	if elapsed > 10*time.Second {
		t.Errorf("8 MiB against 8 MiB took %v, want well under the 180s the runner allows", elapsed)
	}
	// Three things scale with the input here and nothing else does: the two
	// []Line header slices, the edit script, and the prefilter's two sets of
	// line contents. The search itself is O(min(maxD, N+M)) per level. Four
	// times the pair is a wide margin over the measured figure and four orders
	// of magnitude below the trace-storing search this replaces, which was
	// 2.18 GB on a quarter of this size.
	if limit := uint64(4 * 2 * maxFileBytes); allocated > limit {
		t.Errorf("8 MiB against 8 MiB allocated %d bytes, want under %d", allocated, limit)
	}
	checkProjections(t, 0, string(a), string(b), edits)
}

// bigPage builds a page of at least size bytes whose lines never repeat, which
// is the worst case for both the search and the prefilter's map.
func bigPage(size int, tag string) []byte {
	var b strings.Builder
	b.Grow(size + 128)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "%s section %d heading\n%s\n", tag, i, strings.Repeat(tag, 40))
	}
	return []byte(b.String())
}

// TestMaxRecursionDepthIsABackstopNotAKnob: at a depth of 0 the split is
// abandoned immediately and the script is still valid. A depth bound that
// produced a wrong answer would be worse than no bound at all.
func TestMaxRecursionDepthIsABackstopNotAKnob(t *testing.T) {
	t.Parallel()
	a, b := whollyDifferent(200)
	edits := diffWith(a, b, MaxEditDistance, 0, false)
	checkProjections(t, 0, join(a), join(b), edits)
	if got := editDistance(edits); got == 0 {
		t.Error("a depth of 0 produced an empty script for two unrelated regions")
	}
}

// TestBoundedPathologiesNeverPanic is a guard over the shapes that make the
// search work hardest, run through the exported entry points rather than the
// internals, because a caller can only ever reach those.
func TestBoundedPathologiesNeverPanic(t *testing.T) {
	t.Parallel()
	med := wikiPage("world/neverwinter-faction-web", 30)
	cases := []struct{ name, a, b string }{
		{"wholly-different-400KiB", pathological(), different() + different()},
		{"block-move-400KiB", pathological(), blockMove(pathological())},
		{"half-rewritten-400KiB", pathological(), halfRewritten(pathological())},
		{"every-line-shuffled", med, strings.Join(shuffled(med), "\n")},
		{"whole-file-repeated", med, strings.Repeat(med, 3)},
		{"one-line-repeated", "x\n", strings.Repeat("x\n", 50000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			la, lb := Split([]byte(tc.a)), Split([]byte(tc.b))
			edits := Lines([]byte(tc.a), []byte(tc.b))
			checkProjections(t, 0, tc.a, tc.b, edits)
			for _, ctx := range []int{0, 1, 3, 10} {
				for _, h := range Hunks(la, lb, edits, ctx) {
					if h.FromA < 1 || h.FromB < 1 || h.CountA < 0 || h.CountB < 0 {
						t.Fatalf("context %d: impossible hunk %+v", ctx, h)
					}
					if h.FromA-1+h.CountA > len(la) || h.FromB-1+h.CountB > len(lb) {
						t.Fatalf("context %d: hunk runs past the end: %+v over %d/%d lines", ctx, h, len(la), len(lb))
					}
				}
			}
		})
	}
}

// TestOpStringNamesTheOpsTheWayAUnifiedDiffDoes: the marker is what a test
// failure and a renderer both read, and "Op(2)" is neither.
func TestOpStringNamesTheOpsTheWayAUnifiedDiffDoes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		op   Op
		want string
	}{
		{op: OpEqual, want: " "},
		{op: OpDelete, want: "-"},
		{op: OpInsert, want: "+"},
		{op: Op(99), want: "?"},
	} {
		if got := tc.op.String(); got != tc.want {
			t.Errorf("Op(%d).String() = %q, want %q", int(tc.op), got, tc.want)
		}
	}
}

// TestHunksAcceptsAScriptItDidNotProduce covers the two inputs Hunks has to
// survive because it is exported: a script that carries its own OpEqual
// entries, which is what its own output looks like, and one carrying an op it
// has never heard of. Both have to produce a hunk rather than an index out of
// range.
func TestHunksAcceptsAScriptItDidNotProduce(t *testing.T) {
	t.Parallel()
	la := Split([]byte(numbered(12, nil)))
	lb := Split([]byte(numbered(12, map[int]string{6: "CHANGED\n"})))

	t.Run("with-its-own-op-equal-entries", func(t *testing.T) {
		t.Parallel()
		// A script that names its shared lines is a legal input even though
		// Lines never produces one, and it has to group the same way.
		script := []Edit{
			{Op: OpEqual, Line: 1},
			{Op: OpDelete, Line: 6},
			{Op: OpInsert, Line: 6},
			{Op: OpEqual, Line: 7},
		}
		hunks := Hunks(la, lb, script, 3)
		if len(hunks) != 1 {
			t.Fatalf("got %d hunks, want 1: %+v", len(hunks), hunks)
		}
		if del, ins := changedIn(hunks[0]); del != 1 || ins != 1 {
			t.Errorf("hunk carries %d deletes and %d inserts, want 1 and 1", del, ins)
		}
		assertHunkIsWellFormed(t, 3, 0, hunks[0], la, lb)
	})
	t.Run("an-unknown-op", func(t *testing.T) {
		t.Parallel()
		hunks := Hunks(la, lb, []Edit{{Op: Op(42), Line: 6}}, 3)
		if len(hunks) != 1 {
			t.Fatalf("got %d hunks, want 1", len(hunks))
		}
		if h := hunks[0]; h.CountA < 0 || h.CountB < 0 || h.FromA < 1 || h.FromB < 1 {
			t.Errorf("impossible hunk %+v", h)
		}
	})
	t.Run("a-malformed-script", func(t *testing.T) {
		t.Parallel()
		// Line numbers past the end of both files, before the start of them,
		// and an op from nowhere. Hunks is exported, so the answer has to be
		// a hunk clipped to what is there rather than a slice out of range.
		for _, script := range [][]Edit{
			{{Op: OpDelete, Line: 1000}, {Op: OpInsert, Line: 1000}},
			{{Op: OpDelete, Line: -5}, {Op: OpInsert, Line: -5}},
			{{Op: OpInsert, Line: 0}},
			{{Op: Op(7), Line: 1}, {Op: Op(9), Line: 2}},
			{{Op: OpEqual, Line: 99}, {Op: OpDelete, Line: 99}},
		} {
			for _, h := range Hunks(la, lb, script, 3) {
				if h.FromA < 1 || h.FromB < 1 || h.CountA < 0 || h.CountB < 0 {
					t.Errorf("%v: impossible hunk %+v", script, h)
					continue
				}
				if h.FromA-1+h.CountA > len(la) || h.FromB-1+h.CountB > len(lb) {
					t.Errorf("%v: hunk %+v runs past %d/%d lines", script, h, len(la), len(lb))
				}
			}
		}
	})
	t.Run("a-negative-context", func(t *testing.T) {
		t.Parallel()
		produced := Lines([]byte(numbered(12, nil)), []byte(numbered(12, map[int]string{6: "CHANGED\n"})))
		if got, want := Hunks(la, lb, produced, -1), Hunks(la, lb, produced, 0); !sameHunks(got, want) {
			t.Errorf("a negative context gave %+v, want the zero-context answer %+v", got, want)
		}
	})
}

// TestSplitAndMiddleAgreeOnASingleSharedLine covers the one branch the
// recursion needs that the trim hides: two one-line regions that are the same
// line produce no edits at all, not a delete and an insert of it. The trim in
// diff guarantees the top-level core never looks like that; a recursive call
// can, and the answer has to be the same either way.
func TestSplitAndMiddleAgreeOnASingleSharedLine(t *testing.T) {
	t.Parallel()
	a := []Line{{Text: []byte("same\n")}}
	s := searchWith(MaxEditDistance, maxRecursionDepth, true)
	if got := s.middle(nil, a, a, 0, 0, 0); len(got) != 0 {
		t.Errorf("two identical one-line regions produced %v, want no edits", got)
	}
	// The same for a region of any length, where the search reports D == 0 by
	// returning the whole region as the middle snake. Answering that with a
	// replace would report "every line changed" for a file that did not.
	shared := make([]Line, 8)
	for i := range shared {
		shared[i] = Line{Text: []byte(fmt.Sprintf("line %d\n", i))}
	}
	if got := s.middle(nil, shared, shared, 0, 0, 0); len(got) != 0 {
		t.Errorf("two identical 8-line regions produced %v, want no edits", got)
	}
	b := []Line{{Text: []byte("other\n")}}
	if got := searchWith(MaxEditDistance, maxRecursionDepth, true).middle(nil, a, b, 0, 0, 0); editDistance(got) != 2 {
		t.Errorf("two different one-line regions produced D=%d, want 2", editDistance(got))
	}
	// A negative depth is past any bound, and the answer must still be valid.
	wl, wr := whollyDifferent(50)
	got := searchWith(MaxEditDistance, -1, true).middle(nil, wl, wr, 0, 0, 0)
	checkProjections(t, 0, join(wl), join(wr), got)
	// A length gap over the budget is a bail-out with no search at all.
	long := make([]Line, 100)
	for i := range long {
		long[i] = Line{Text: []byte(fmt.Sprintf("line %d\n", i))}
	}
	if _, _, _, _, _, ok := middleSnake(long, long[:1], 10); ok {
		t.Error("middleSnake found a snake across a length gap 99 times its budget")
	}
}

// TestMiddleSnakeReturnsARealDiagonal pins middleSnake's contract directly,
// because its two frontiers are seeded on different diagonals and getting that
// wrong is silent: the split still looks like a split and the script still
// round-trips for the wrong reason. The trim in diff means the shared head and
// tail of every real call are already gone, so only a direct call reaches the
// step-0 seeding, and a test that never called it directly would leave the
// claim in its comment unchecked.
func TestMiddleSnakeReturnsARealDiagonal(t *testing.T) {
	t.Parallel()
	lines := func(ss ...string) []Line {
		out := make([]Line, len(ss))
		for i, s := range ss {
			out[i] = Line{Text: []byte(s + "\n")}
		}
		return out
	}
	tests := []struct {
		name string
		a, b []Line
	}{
		{name: "identical", a: lines("a", "b", "c"), b: lines("a", "b", "c")},
		{name: "shared-head-unequal-lengths", a: lines("a", "b", "c", "d"), b: lines("a", "b", "c")},
		{name: "no-shared-head", a: lines("a", "b", "c"), b: lines("x", "y", "z")},
		{name: "one-sided", a: lines("a", "b"), b: lines("x")},
		{name: "reverse-shared-tail", a: lines("x", "y", "z"), b: lines("p", "q", "z")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, x0, y0, u, v, ok := middleSnake(tc.a, tc.b, MaxEditDistance)
			if !ok {
				t.Fatal("the search gave up on a region far inside the budget")
			}
			if x0 > u || y0 > v || x0 < 0 || y0 < 0 {
				t.Fatalf("snake endpoints are inverted: a[%d:%d] b[%d:%d]", x0, u, y0, v)
			}
			if u > len(tc.a) || v > len(tc.b) {
				t.Fatalf("snake runs past the end: a[%d:%d] b[%d:%d] over %d/%d lines",
					x0, u, y0, v, len(tc.a), len(tc.b))
			}
			if x0 == 0 && y0 == 0 && u == len(tc.a) && v == len(tc.b) {
				// A split that consumed nothing is the D == 0 answer, and it
				// is only valid when the two regions really are the same
				// lines. Anything else would leave the caller with nothing to
				// recurse on.
				if len(tc.a) != len(tc.b) {
					t.Fatalf("the split consumed nothing across regions of %d and %d lines", len(tc.a), len(tc.b))
				}
				for i := range tc.a {
					if !lineEq(tc.a[i], tc.b[i]) {
						t.Fatalf("the split consumed nothing, but a-line %d %q differs from b-line %d %q",
							i, tc.a[i].Text, i, tc.b[i].Text)
					}
				}
			}
			for i := x0; i < u; i++ {
				if !lineEq(tc.a[i], tc.b[y0+i-x0]) {
					t.Fatalf("the snake is not a diagonal: a[%d] %q != b[%d] %q",
						i, tc.a[i].Text, y0+i-x0, tc.b[y0+i-x0].Text)
				}
			}
		})
	}
}

func sameHunks(a, b []Hunk) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].FromA != b[i].FromA || a[i].CountA != b[i].CountA ||
			a[i].FromB != b[i].FromB || a[i].CountB != b[i].CountB ||
			!sameEdits(a[i].Edits, b[i].Edits) {
			return false
		}
	}
	return true
}

func sameEdits(a, b []Edit) bool {
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

func join(l []Line) string {
	var b strings.Builder
	for _, x := range l {
		b.Write(x.Text)
	}
	return b.String()
}

// shuffled reorders a page's lines. A line-based diff has to report that as
// deletes and inserts in the original order; a script that permutes the equal
// lines instead would render plausibly and lose the page.
func shuffled(s string) []string {
	lines := strings.Split(s, "\n")
	rng := rand.New(rand.NewSource(20260929))
	rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	return lines
}
