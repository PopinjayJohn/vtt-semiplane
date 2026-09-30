package diff

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// benchInput is built once: the generator is not what is being measured.
type benchInput struct {
	name string
	a, b string
}

func benchInputs() []benchInput {
	big := pathological()
	med := wikiPage("world/neverwinter-faction-web", 30)
	return []benchInput{
		{"400KiB/no-change", big, big},
		{"400KiB/small-edit", big, smallEdit(big)},
		{"400KiB/block-move", big, blockMove(big)},
		{"400KiB/whole-file-replace", big, different() + different()},
		{"400KiB/lf-vs-crlf", big, toCRLF(big)},
		{"400KiB/many-small-edits", big, manySmallEdits(big, 20)},
		{"400KiB/half-rewritten", big, halfRewritten(big)},
		{"60KiB/no-change", med, med},
		{"60KiB/small-edit", med, smallEdit(med)},
		{"60KiB/block-move", med, blockMove(med)},
		{"60KiB/whole-file-replace", med, different()},
		{"60KiB/lf-vs-crlf", med, toCRLF(med)},
	}
}

// BenchmarkLines prices the seven 400 KiB cases the spike measured. The number
// that matters is the worst one: this runs inside a save that has already lost
// a race, on a page a user is waiting to see resolved.
func BenchmarkLines(b *testing.B) {
	for _, in := range benchInputs() {
		b.Run(in.name, func(b *testing.B) {
			a, bb := []byte(in.a), []byte(in.b)
			b.ReportAllocs()
			b.SetBytes(int64(len(in.a)))
			// Held in a local rather than a package sink: a benchmark is not
			// parallel today, and a shared global is a data race the moment one
			// is, or the moment a test shares the symbol. KeepAlive is as
			// un-elidable as writing to package state and is not shared.
			var kept []Edit
			for i := 0; i < b.N; i++ {
				kept = Lines(a, bb)
			}
			runtime.KeepAlive(kept)
		})
	}
}

// BenchmarkHunks prices the grouping, which is what the conflict page actually
// iterates over rather than the whole script.
func BenchmarkHunks(b *testing.B) {
	for _, in := range benchInputs() {
		if in.name == "400KiB/whole-file-replace" || in.name == "400KiB/no-change" {
			continue
		}
		b.Run(in.name, func(b *testing.B) {
			la, lb := Split([]byte(in.a)), Split([]byte(in.b))
			edits := Lines([]byte(in.a), []byte(in.b))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Hunks(la, lb, edits, 3)
			}
		})
	}
}

// TestWallClockAt400KiB puts the benchmark next to a number that means
// something: the time a request is allowed to take. The budget is loose, and
// the point is to catch a case that has become quadratic rather than to measure
// this machine. The timing is the best of five rather than
// testing.Benchmark's one-second minimum per case, because this runs in CI on
// every save-path change and seven cases at a second each is not a test.
func TestWallClockAt400KiB(t *testing.T) {
	t.Parallel()
	const budget = 100 * time.Millisecond
	for _, in := range benchInputs() {
		if !strings.HasPrefix(in.name, "400KiB") {
			continue
		}
		t.Run(in.name, func(t *testing.T) {
			t.Parallel()
			a, b := []byte(in.a), []byte(in.b)
			edits := Lines(a, b) // warm-up: the first call pays for a 400 KiB allocation
			// Per subtest, so parallel subtests do not share it. See the note on
			// the same pattern in BenchmarkLines.
			var kept []Edit
			best := time.Hour
			for i := 0; i < 5; i++ {
				t0 := time.Now()
				kept = Lines(a, b)
				if el := time.Since(t0); el < best {
					best = el
				}
			}
			runtime.KeepAlive(kept)
			t.Logf("%-30s %7d bytes, %5d lines, %5d edits: %v",
				in.name, len(in.a), len(Split(a)), len(edits), best.Round(time.Microsecond))
			if best > budget {
				t.Errorf("best of five took %v, over the %v budget for a 400 KiB page", best, budget)
			}
		})
	}
}
