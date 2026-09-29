package diff

// Hunk is a run of changes with context on both ends, carrying the four
// numbers a unified diff header has.
//
// CountA and CountB span the whole hunk, context included, and either may be
// zero: a hunk that only inserts has CountA 0 and one that only deletes has
// CountB 0. FromA and FromB are 1-based and always in range, so when CountA is
// 0 FromA is the point the insert happens at, and lines[FromA-1:FromA-1+CountA]
// is the empty slice it should be. A hunk that begins before the first line of
// a file is the case this pins down: FromA 1 with CountA 0, not FromA 0.
type Hunk struct {
	FromA  int
	CountA int
	FromB  int
	CountB int
	// Edits is the hunk's own script in order, context included, with
	// OpEqual entries for the context lines. Every line in the hunk's range
	// that is not in Edits is a context line, and a hunk is renderable from
	// Edits alone.
	Edits []Edit
}

// Hunks groups a change script into hunks with context lines on both sides.
//
// Two changes join the same hunk when at most 2*context shared lines separate
// them, which is what lets a pair of hunks each show context without their
// contexts overlapping. A context below 1 is treated as 0.
//
// The result is nil when the script is empty: a page nobody changed has no
// hunks to render, and that is the answer a conflict page wants rather than
// one hunk of "no changes".
//
// a and b are the Split outputs the script was made from. They are read for
// their lengths and nothing else: the shared lines after the final change are
// not in the script, and no property of a change script alone says how many
// there are.
//
// A script that Lines did not produce for these same inputs is not rejected.
// Every count and offset is clamped to the lines that are actually there, so a
// malformed script yields a hunk whose range still slices rather than a slice
// out of range. The edits inside Hunk.Edits are echoed exactly as they were
// given, including a line number past the end of the file, because deciding
// what a clamped one means is the caller's.
func Hunks(a, b []Line, edits []Edit, context int) []Hunk {
	if context < 0 {
		context = 0
	}
	if len(edits) == 0 {
		return nil
	}
	// gap[i] is how many lines the two sides share immediately before edits[i],
	// and aStart[i]/bStart[i] is the line that run starts at. Walking both
	// sides in lockstep is the only thing a change script says about the lines
	// it does not mention, and every hunk below is built from these two arrays
	// plus the script.
	//
	// A run is consumed as it is measured: a delete at a-line L leaves a on
	// the far side of the run and b on the near side of it, which is why the
	// run is added to the *other* cursor. Leaving both cursors where the
	// previous change put them makes the next gap count the previous run a
	// second time, and a hunk's b-range then runs off the end of the file.
	gap := make([]int, len(edits))
	aStart := make([]int, len(edits))
	bStart := make([]int, len(edits))
	aPos, bPos := 1, 1
	for i, e := range edits {
		aStart[i], bStart[i] = aPos, bPos
		switch e.Op {
		case OpEqual:
			gap[i] = e.Line - aPos
			aPos, bPos = e.Line+1, e.Line+1
		case OpDelete:
			gap[i] = e.Line - aPos
			aPos = e.Line + 1
			bPos += gap[i]
		case OpInsert:
			gap[i] = e.Line - bPos
			aPos += gap[i]
			bPos = e.Line + 1
		default:
			gap[i] = 0
		}
	}

	var hunks []Hunk
	first := 0
	// The scan starts at 1 so that the first group always holds edit 0: a
	// change whose leading run is longer than the context is its own group,
	// and starting at 0 would emit that group twice, once empty.
	for i := 1; i <= len(edits); i++ {
		if i < len(edits) && gap[i] <= 2*context {
			continue
		}
		hunks = append(hunks, hunkOf(a, b, edits, gap, aStart, bStart, first, i-1, context))
		first = i
	}
	return hunks
}

// hunkOf builds the hunk covering edits[first..last]. Every index is
// non-empty: the grouping above never calls it with last < first.
//
// The lead context is the *tail* of the shared run before the first change,
// not its head, because a hunk has to be contiguous around its changes: the
// lines between the last context line and the first change are shared, and
// leaving them out while still counting from the run's start produces a hunk
// whose range spans lines its edits never mention.
func hunkOf(a, b []Line, edits []Edit, gap, aStart, bStart []int, first, last, context int) Hunk {
	// Where the first change sits, on each side: an insert is at its line on
	// the side it is inserted into and at the run's far end on the other.
	//
	// Everything here is clamped to the lines the inputs actually have,
	// because the script is not trusted. A caller that hands Hunks a line
	// number past the end of a file gets a hunk whose range still slices, not
	// a slice out of range. The edits themselves are echoed exactly as they
	// were given, because a caller that wants them clipped has to decide what
	// a clipped line number means.
	ac := clamp(aStart[first]+gap[first], 1, len(a)+1)
	bc := clamp(bStart[first]+gap[first], 1, len(b)+1)
	// The lead is context *before* the first change, so it is bounded by what
	// precedes it, not by what follows it.
	lead := clamp(min(context, gap[first]), 0, min(ac-1, bc-1))
	ac -= lead
	bc -= lead
	h := Hunk{FromA: ac, FromB: bc}

	eds := make([]Edit, 0, 2*context+4)
	for k := 0; k < lead; k++ {
		eds = append(eds, Edit{Op: OpEqual, Line: ac})
		ac++
		bc++
	}
	for i := first; i <= last; i++ {
		eds = append(eds, edits[i])
		switch edits[i].Op {
		case OpEqual:
			// Lines never emits one, but a script that names its shared lines
			// is a legal input, and the two sides advance together across one.
			ac = clamp(edits[i].Line+1, 1, len(a)+1)
			bc = clamp(bc+1, 1, len(b)+1)
		case OpDelete:
			ac = clamp(edits[i].Line+1, 1, len(a)+1)
		case OpInsert:
			bc = clamp(edits[i].Line+1, 1, len(b)+1)
		}
		if i == last {
			// No shared run follows the last change in the hunk; the one
			// after it belongs to whatever comes next, or to the end of the
			// file.
			break
		}
		// The whole shared run between two changes in one hunk is context:
		// the grouping above only put them together when it fits on both
		// sides, which is 2*context lines.
		run := clamp(gap[i+1], 0, min(len(a)-ac+1, len(b)-bc+1))
		for k := 0; k < run; k++ {
			eds = append(eds, Edit{Op: OpEqual, Line: ac})
			ac++
			bc++
		}
	}
	// Trailing context, clipped the same way: a hunk at the end of a file has
	// fewer than context lines after it, and a hunk with nothing left on one
	// side has none at all.
	trail := clamp(context, 0, min(len(a)-ac+1, len(b)-bc+1))
	for k := 0; k < trail; k++ {
		eds = append(eds, Edit{Op: OpEqual, Line: ac})
		ac++
		bc++
	}
	h.CountA = max(ac-h.FromA, 0)
	h.CountB = max(bc-h.FromB, 0)
	h.Edits = eds
	return h
}

// clamp is max(lo, min(v, hi)) in one place, because every count in hunkOf is
// clipped to the lines the inputs actually have and doing it inline four times
// is where one of them would be missed.
//
// It assumes lo <= hi, which every caller here guarantees by construction: lo
// is always 0 or 1, and hi is derived from a cursor that has itself been
// clamped into range. A guard for the other case would be a branch nothing can
// reach, which is the failure mode AGENTS.md §11 is about.
func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}
