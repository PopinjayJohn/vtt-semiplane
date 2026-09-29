package diff

// MaxEditDistance is the edit distance at which the search stops looking for a
// minimal script and replaces the whole region instead.
//
// It is a rendering decision as much as a performance one. D counts an insert
// and a delete, so this is a region of more than a thousand replaced lines
// shown as one hunk — which is what a conflict page should show, because
// nobody resolves that many by hand. A caller that wants a finer answer on a
// small region gets one: the bound applies to each region the search recurses
// into, not to the file as a whole. The script emitted past the bound is still
// valid — it replaces everything, so both projections still hold — it is just
// not minimal, and TestBailOutIsStillCorrect says so.
//
// It is also what makes the worst case a request rather than a denial of
// service. The linear-space search is O((N+M)*D), so D is the only thing
// standing between a logged-in user and a two-sided 8 MiB file.
const MaxEditDistance = 2000

// maxRecursionDepth bounds the middle-snake split.
//
// The split provably reduces the problem, so this is a termination backstop
// rather than a tuning knob. It is here because the argument for hand-rolling
// this at all is that it cannot hang, and a hang in a request path is a
// failure mode this repository has already shipped twice (AGENTS.md §11). A
// bound nothing reaches is the cheapest insurance there is.
const maxRecursionDepth = 4096

// unreach is the value the reverse frontier holds for a diagonal the search has
// not reached. Zero is a legitimate y there, so "not reached yet" needs its own
// sentinel: left at zero, the first step reads an unwritten slot as a real
// position and the split it produces is not a diagonal — a script that renders
// correctly and silently loses lines.
const unreach = 1 << 30

// search carries the bounds one recursive descent is allowed to use. They are
// fields rather than package vars, so a test can drive each boundary without
// mutating global state and so the same input can be run through the search
// with and without the prefilter to prove the prefilter changes nothing.
type search struct {
	maxD      int
	maxDepth  int
	prefilter bool
}

// diff appends the changes that turn a into b. baseA and baseB are the 0-based
// offsets of a and b within their original inputs, so the line numbers in the
// result are absolute and a caller can index them straight into Split's output.
func (s search) diff(dst []Edit, a, b []Line, baseA, baseB int) []Edit {
	n, m := len(a), len(b)
	pre := 0
	for pre < n && pre < m && lineEq(a[pre], b[pre]) {
		pre++
	}
	suf := 0
	for suf < n-pre && suf < m-pre && lineEq(a[n-1-suf], b[m-1-suf]) {
		suf++
	}
	// The shared head and tail produce no edits at all — they are exactly the
	// lines a change script omits — so only the middle is searched.
	coreA, coreB := a[pre:n-suf], b[pre:m-suf]
	coreA0, coreB0 := baseA+pre, baseB+pre

	if s.prefilter && tooExpensive(coreA, coreB, s.maxD) {
		return replaceAll(dst, coreA, coreB, coreA0, coreB0)
	}
	return s.middle(dst, coreA, coreB, coreA0, coreB0, 0)
}

// middle is the middle-snake recursion proper: find the middle snake of a
// shortest edit sequence and recurse on what is on either side of it.
//
// This is Myers 1986 §4b rather than the trace-storing version most small
// implementations use. Both are O(ND) in time and produce the same answer; only
// this one is O(N+M) in space, and the other one is what took 2.18 GB on a
// 400 KiB CRLF-versus-LF page in the spike that chose this algorithm.
//
// The snake a[x0:u] equals b[y0:v] is shared content and contributes no edits,
// so the two recursive calls are the only work.
func (s search) middle(dst []Edit, a, b []Line, baseA, baseB, depth int) []Edit {
	n, m := len(a), len(b)
	if n == 0 || m == 0 || (n == 1 && m == 1) {
		if n == 1 && m == 1 && lineEq(a[0], b[0]) {
			return dst
		}
		return replaceAll(dst, a, b, baseA, baseB)
	}
	if depth > s.maxDepth {
		return replaceAll(dst, a, b, baseA, baseB)
	}

	_, x0, y0, u, v, ok := middleSnake(a, b, s.maxD)
	if !ok {
		return replaceAll(dst, a, b, baseA, baseB)
	}
	// A split that consumed nothing means the middle snake *is* the whole
	// region, which the search only reports when D is 0. The trim in diff
	// normally removes that case before the search runs, so it arrives here
	// for a recursive call at most — and the answer is no edits at all, not a
	// replace: turning "nothing changed" into "everything changed" is the
	// failure this line exists to prevent.
	if x0 == 0 && y0 == 0 && u == n && v == m {
		return dst
	}
	dst = s.middle(dst, a[:x0], b[:y0], baseA, baseB, depth+1)
	return s.middle(dst, a[u:], b[v:], baseA+u, baseB+v, depth+1)
}

// replaceAll emits a whole-region replace: every line of a deleted, then every
// line of b inserted. Deletes first is the unified-diff convention, and the
// order is what makes the emitted region a single readable hunk rather than an
// interleaving.
//
// This is the script past MaxEditDistance, and it is the base case for any
// region the search declines to split. It is a valid script — a caller that
// applies it gets from a to b — and it is not minimal.
func replaceAll(dst []Edit, a, b []Line, baseA, baseB int) []Edit {
	for i := range a {
		dst = append(dst, Edit{Op: OpDelete, Line: baseA + i + 1})
	}
	for i := range b {
		dst = append(dst, Edit{Op: OpInsert, Line: baseB + i + 1})
	}
	return dst
}

// tooExpensive reports whether a cheap lower bound on the edit distance is
// already over the search budget.
//
// Every line of a that occurs nowhere in b has to be deleted, and every line of
// b that occurs nowhere in a has to be inserted, so the number of lines with no
// counterpart on the other side is a floor on D. One map and two passes,
// O(N+M).
//
// It is the difference between bounded and slow rather than between correct
// and incorrect: the search below would reach the same conclusion by sweeping
// maxD diagonals, and the bound is only ever used to stop early. On the case
// the spike measured — a 400 KiB page whose every line differs — it turned
// 20 ms into 386 µs.
func tooExpensive(a, b []Line, budget int) bool {
	seen := make(map[string]struct{}, len(b))
	for i := range b {
		seen[string(b[i].Text)] = struct{}{}
	}
	n := 0
	for i := range a {
		if _, ok := seen[string(a[i].Text)]; !ok {
			if n++; n > budget {
				return true
			}
		}
	}
	// The second pass is only worth its map if the first has not bailed.
	seen = make(map[string]struct{}, len(a))
	for i := range a {
		seen[string(a[i].Text)] = struct{}{}
	}
	for i := range b {
		if _, ok := seen[string(b[i].Text)]; !ok {
			if n++; n > budget {
				return true
			}
		}
	}
	return false
}

// middleSnake returns the endpoints of a middle snake of a shortest edit
// sequence for a -> b, where a[x0:u] equals b[y0:v]. ok is false when the
// search exceeded maxD, which is the too-expensive bail-out and means the
// caller should replace the region instead.
//
// Space is O(min(maxD, N+M)) and time is O((N+M) * D_found).
func middleSnake(a, b []Line, maxD int) (d, x0, y0, u, v int, ok bool) {
	n, m := len(a), len(b)
	delta := n - m
	// The middle snake is found by D/2, so there is never any point searching
	// past (n+m+1)/2. maxD caps it from above; past that, give up.
	dmax := (n + m + 1) / 2
	if dmax > maxD {
		dmax = maxD
	}
	if dmax < 1 {
		return 0, 0, 0, 0, 0, false
	}
	// D is at least |n-m|, so a length gap over the budget is a bail-out with
	// no search at all — two integer comparisons instead of a sweep. This is
	// the common shape of the pathological case.
	if delta > maxD || delta < -maxD {
		return 0, 0, 0, 0, 0, false
	}
	// Diagonal indices span [min(0,delta)-dmax, max(0,delta)+dmax]: the
	// forward frontier is centred on 0 and the reverse one on delta, and the
	// reverse one keeps walking outward as the step count grows. A window of
	// 2*dmax around 0 is not wide enough for unequal-length inputs.
	lo := min(0, delta) - dmax
	hi := max(0, delta) + dmax
	off := -lo
	vf := make([]int, hi-lo+1)
	vb := make([]int, hi-lo+1)
	snakes := make([]int, hi-lo+1)
	for i := range vb {
		vb[i] = unreach
	}

	// Step 0. The two searches do not share a starting diagonal: the forward
	// path begins at (0,0), which is diagonal 0, and the reverse path at
	// (n,m), which is diagonal n-m. Seeding both at index 0 is only correct
	// when n == m, and gets it wrong for every unequal-length input.
	fx := 0
	for fx < n && fx < m && lineEq(a[fx], b[fx]) {
		fx++
	}
	vf[off] = fx
	rx, ry := n, m
	for rx > 0 && ry > 0 && lineEq(a[rx-1], b[ry-1]) {
		rx--
		ry--
	}
	// The window always contains index delta: with delta >= 0 it lands exactly
	// on hi, and with delta < 0 it lands at dmax. Guarding it here looked
	// defensive and silently disabled the whole search for any input whose
	// length gap exceeded the step budget.
	vb[off+delta] = ry
	if delta == 0 && fx >= rx {
		// D == 0: a and b agree across the whole origin diagonal. Splitting
		// at its end always makes progress, because n and m are both above 0.
		return 0, 0, 0, fx, fx, true
	}

	for dd := 1; dd <= dmax; dd++ {
		// Forward. vf[off+k] is the furthest x reachable on diagonal k, and
		// snakes[off+k] the x where that step's diagonal run began. The run
		// a[sx:x] equals b[sx-k:x-k] is what the caller splits on, so sx has
		// to be the run's own start and not merely the furthest the reverse
		// search happens to have reached.
		for k := -dd; k <= dd; k += 2 {
			var x int
			if k == -dd || (k != dd && vf[off+k-1] < vf[off+k+1]) {
				x = vf[off+k+1]
			} else {
				x = vf[off+k-1] + 1
			}
			y := x - k
			sx := x
			for x < n && y < m && lineEq(a[x], b[y]) {
				x++
				y++
			}
			vf[off+k] = x
			snakes[off+k] = sx
		}
		// Reverse. vb[off+k] is the least y reachable on diagonal k walking
		// down from (n, m). An x-1 edit lands on diagonal k+1 and leaves y
		// alone; a y-1 edit lands on k-1 and lowers y by one. This frontier
		// is centred on delta, not on 0, which is why the two sweeps below do
		// not share loop bounds.
		rLo, rHi := delta-dd, delta+dd
		for k := rLo; k <= rHi; k += 2 {
			var y int
			if k == rLo || (k != rHi && vb[off+k+1] < vb[off+k-1]-1) {
				y = vb[off+k+1]
			} else {
				y = vb[off+k-1] - 1
			}
			x := y + k
			if x > n || y > m || x < 0 || y < 0 {
				vb[off+k] = unreach
				continue
			}
			for x > 0 && y > 0 && lineEq(a[x-1], b[y-1]) {
				x--
				y--
			}
			vb[off+k] = y
		}
		// Overlap: on some diagonal the forward point has reached at least as
		// far along as the reverse point. D is 2*dd when n-m is even and
		// 2*dd-1 when it is odd, which is why an odd delta only looks one
		// diagonal in. Scan the diagonals both frontiers reach, at the parity
		// of dd, which is the whole of the reverse range minus its outermost
		// pair for an odd delta.
		lo, hi := -dd, dd
		revLo, revHi := delta-dd, delta+dd
		if delta%2 != 0 {
			revLo, revHi = delta-dd+1, delta+dd-1
		}
		lo = max(lo, revLo)
		hi = min(hi, revHi)
		for k := lo; k <= hi; k += 2 {
			rv := vb[off+k]
			if rv == unreach || vf[off+k] < rv+k {
				continue
			}
			sx := snakes[off+k]
			return dd, sx, sx - k, vf[off+k], vf[off+k] - k, true
		}
	}
	return 0, 0, 0, 0, 0, false
}
