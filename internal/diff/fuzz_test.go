package diff

import (
	"bytes"
	"testing"
)

// FuzzDiffNeverPanics feeds arbitrary bytes to every exported entry point.
// This package sits in a request path a logged-in user can reach with whatever
// their editor has in the buffer, so "does not panic" is a real requirement
// rather than a formality.
func FuzzDiffNeverPanics(f *testing.F) {
	f.Add([]byte("a\nb\nc\n"), []byte("a\nB\nc\n"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("x"), []byte("x\n"))
	f.Add([]byte("a\r\nb\r\n"), []byte("a\nb\n"))
	f.Add([]byte{0xff, 0xfe, '\n'}, []byte{0xff})
	f.Add([]byte("```secret id=x visibility=dm\nbody\n```\n"), []byte("```secret id=y\n"))

	f.Fuzz(func(t *testing.T, a, b []byte) {
		edits := Lines(a, b)
		la, lb := Split(a), Split(b)
		checkProjections(t, 0, string(a), string(b), edits)
		// Hunks is exported, so it gets the same treatment: whatever a caller
		// hands it, it clamps rather than indexing out of range.
		for _, ctx := range []int{0, 1, 3, 64} {
			for i, h := range Hunks(la, lb, edits, ctx) {
				if h.FromA < 1 || h.FromB < 1 || h.CountA < 0 || h.CountB < 0 {
					t.Fatalf("context %d hunk %d: %+v", ctx, i, h)
				}
				if h.FromA-1+h.CountA > len(la) || h.FromB-1+h.CountB > len(lb) {
					t.Fatalf("context %d hunk %d: %+v over %d/%d lines", ctx, i, h, len(la), len(lb))
				}
			}
		}
	})
}

// FuzzRoundTripProjection is the same property as its own target, so a failure
// is reproducible without re-running the panic target's seed corpus. The two
// are separated because the interesting regression is a script that is
// well-formed and wrong, and that one deserves a corpus of its own.
func FuzzRoundTripProjection(f *testing.F) {
	f.Add("## a heading\nsome prose\n", "## a heading\nother prose\n")
	f.Add("a\nb\nc\nd\n", "a\nc\nd\nb\n")
	f.Add("x", "x\n")
	f.Add("a\na\na\n", "a\n")
	f.Add("\r\n\r\n", "\n\n")

	f.Fuzz(func(t *testing.T, a, b string) {
		checkProjections(t, 0, a, b, Lines([]byte(a), []byte(b)))
	})
}

// FuzzSplitNeverLosesBytes states the one invariant the fuzzer can check about
// a line splitter: the lines, with their terminators reattached, are the input.
// A lost byte here is a lost byte in somebody's Markdown.
func FuzzSplitNeverLosesBytes(f *testing.F) {
	f.Add([]byte("a\nb\n"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("no terminator"))
	f.Add([]byte("\r"))

	f.Fuzz(func(t *testing.T, b []byte) {
		lines := Split(b)
		// A file that ends in a terminator has one on its last line too; only
		// the final line of a file with no trailing terminator lacks it.
		trailing := len(b) > 0 && b[len(b)-1] == '\n'
		var out bytes.Buffer
		for i, l := range lines {
			out.Write(l.Text)
			if i == len(lines)-1 && !trailing {
				break
			}
			if l.CRLF {
				out.WriteString("\r\n")
			} else {
				out.WriteByte('\n')
			}
		}
		if !bytes.Equal(out.Bytes(), b) {
			t.Fatalf("Split lost bytes: %q became %q", b, out.Bytes())
		}
	})
}
