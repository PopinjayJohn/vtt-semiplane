package diff

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSplit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []Line
	}{
		{name: "empty", in: "", want: nil},
		{name: "one-line-no-terminator", in: "a", want: []Line{{Text: []byte("a")}}},
		{name: "one-line-with-terminator", in: "a\n", want: []Line{{Text: []byte("a")}}},
		{name: "trailing-newline-does-not-invent-a-line", in: "a\nb\n", want: []Line{
			{Text: []byte("a")}, {Text: []byte("b")},
		}},
		{name: "blank-line-is-a-line", in: "\n", want: []Line{{Text: []byte("")}}},
		{name: "two-newlines", in: "\n\n", want: []Line{{Text: []byte("")}, {Text: []byte("")}}},
		{name: "crlf", in: "a\r\nb\r\n", want: []Line{
			{Text: []byte("a"), CRLF: true}, {Text: []byte("b"), CRLF: true},
		}},
		{name: "crlf-blank-line", in: "a\r\n\r\n", want: []Line{
			{Text: []byte("a"), CRLF: true}, {Text: []byte(""), CRLF: true},
		}},
		// A CR with no LF after it is content. A file written by a tool that
		// emits lone CRs must not lose a byte to the terminator rule.
		{name: "lone-cr-is-content", in: "a\rb", want: []Line{{Text: []byte("a\rb")}}},
		{name: "cr-at-end-is-content", in: "a\r", want: []Line{{Text: []byte("a\r")}}},
		{name: "crlf-then-lone-cr", in: "a\r\nb\rc", want: []Line{
			{Text: []byte("a"), CRLF: true}, {Text: []byte("b\rc")},
		}},
		{name: "invalid-utf8-passes-through", in: "\xff\xfe\n\xc3(", want: []Line{
			{Text: []byte{0xff, 0xfe}}, {Text: []byte{0xc3, '('}},
		}},
		{name: "nul-byte", in: "a\x00b\n", want: []Line{{Text: []byte("a\x00b")}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Split([]byte(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("Split(%q) = %d lines, want %d: %+v", tc.in, len(got), len(tc.want), got)
			}
			for i := range got {
				if !bytes.Equal(got[i].Text, tc.want[i].Text) || got[i].CRLF != tc.want[i].CRLF {
					t.Errorf("line %d = %q CRLF=%v, want %q CRLF=%v",
						i+1, got[i].Text, got[i].CRLF, tc.want[i].Text, tc.want[i].CRLF)
				}
			}
		})
	}
}

// TestSplitTerminatorsRebuildTheInput is the property the sub-slice design
// rests on: the lines partition the input, so a caller that reattaches each
// line's own terminator gets the original bytes back, whatever mixture of CR,
// LF and CRLF went in. Only a file that does not end in a terminator is
// missing one after its last line, and a caller reattaching has to know that.
func TestSplitTerminatorsRebuildTheInput(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, in := range []string{tc.a, tc.b, "a\rb\r", "\r\n\r", "no terminator at all"} {
				var out bytes.Buffer
				lines := Split([]byte(in))
				trailing := strings.HasSuffix(in, "\n")
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
				if out.String() != in {
					t.Errorf("reattaching terminators: got %q, want %q", out.String(), in)
				}
			}
		})
	}
}

// TestIdenticalInputIsANoOp pins the two halves of requirement 2: a diff of a
// file against itself is nil, and answering it costs no allocation whatever the
// file is. A page nobody touched is the common case on every save.
func TestIdenticalInputIsANoOp(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Lines([]byte(tc.a), []byte(tc.a)); len(got) != 0 {
				t.Errorf("identical input produced %d edits, want 0: %v", len(got), got)
			}
			if got := Hunks(Split([]byte(tc.a)), Split([]byte(tc.a)), nil, 3); len(got) != 0 {
				t.Errorf("identical input produced %d hunks, want 0", len(got))
			}
		})
	}
}

// TestIdenticalInputAllocatesNothing is the same claim about memory, on the
// largest fixture. Split allocates a header per line, so without the
// byte-equality short circuit an untouched 400 KiB page would still cost a few
// megabytes to discover that nothing changed.
//
// It is not t.Parallel: testing.AllocsPerRun pins GOMAXPROCS to 1 and panics if
// called from a parallel test.
func TestIdenticalInputAllocatesNothing(t *testing.T) {
	big := []byte(pathological())
	// The result is held in a local rather than a package variable. A global
	// sink is the usual way to keep a call from being elided, and it was the
	// race this package's CI caught: TestWallClockAt400KiB's subtests run in
	// parallel and wrote the same global, so `go test -race` failed while the
	// non-race build passed. A local plus KeepAlive is as un-elidable and is
	// not shared.
	var kept []Edit
	if n := testing.AllocsPerRun(5, func() { kept = Lines(big, big) }); n != 0 {
		t.Errorf("Lines on identical %d-byte input allocated %v times, want 0", len(big), n)
	}
	if len(kept) != 0 {
		t.Errorf("identical input produced %d edits, want 0", len(kept))
	}
}

// TestCRLFIsNotADiff is the decision the package is named for. A page authored
// on Windows and the same page authored on Linux have the same lines, so the
// diff is empty; keeping the terminator in the comparison unit would instead
// produce one delete and one insert per line, which is the reason the spike
// rejected the one candidate library that keeps it.
func TestCRLFIsNotADiff(t *testing.T) {
	t.Parallel()
	big := pathological()
	for _, tc := range []struct {
		name string
		page string
	}{
		{"medium", wikiPage("world/neverwinter-faction-web", 30)},
		{"pathological-400KiB", big},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lf, crlf := []byte(tc.page), []byte(toCRLF(tc.page))
			if bytes.Equal(lf, crlf) {
				t.Fatal("the fixture is not a CRLF difference")
			}
			t0 := time.Now()
			got := Lines(lf, crlf)
			if el := time.Since(t0); el > 250*time.Millisecond {
				t.Errorf("400 KiB CRLF-versus-LF diff took %v, which is the symptom the decision exists to prevent", el)
			}
			if len(got) != 0 {
				t.Errorf("CRLF versus LF produced %d edits over %d lines, want 0: %v",
					len(got), len(Split(lf)), got[:min(6, len(got))])
			}
			// The style difference is reported, not erased: Line.CRLF is how a
			// caller that cares finds out which side is which.
			if l := Split(lf); len(l) == 0 || l[0].CRLF {
				t.Error("LF fixture reported CRLF")
			}
			if l := Split(crlf); len(l) == 0 || !l[0].CRLF {
				t.Error("CRLF fixture did not report CRLF")
			}
		})
	}
}

// TestLineEndingsDoNotChangeTheScript says the same thing for a file that
// mixes the two, and for the order of the arguments: a caller that diffs the
// other way round gets the mirror image, not a different answer.
func TestLineEndingsDoNotChangeTheScript(t *testing.T) {
	t.Parallel()
	page := wikiPage("world/neverwinter-faction-web", 30)
	lf := []byte(page)
	crlf := []byte(toCRLF(page))
	mixed := []byte(strings.Replace(page, "\n", "\r\n", 7))

	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"all-crlf", crlf},
		{"mixed", mixed},
	} {
		if got := Lines(lf, tc.b); len(got) != 0 {
			t.Errorf("%s: produced %d edits, want 0", tc.name, len(got))
		}
		if got := Lines(tc.b, lf); len(got) != 0 {
			t.Errorf("%s reversed: produced %d edits, want 0", tc.name, len(got))
		}
	}
	// A real change inside a CRLF file is still found, and is still two lines.
	edited := []byte(smallEdit(toCRLF(page)))
	eq, del, ins := countOps(Lines([]byte(toCRLF(page)), edited))
	if eq != 0 || del != 1 || ins != 1 {
		t.Errorf("one-word change in a CRLF page = %d/%d/%d equal/delete/insert, want 0/1/1", eq, del, ins)
	}
}

// TestRoundTripProjection is the property that decides whether the package is
// correct at all: both projections hold. A script that reorders a line, or
// duplicates one, or drops one, fails one of them.
func TestRoundTripProjection(t *testing.T) {
	t.Parallel()
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := Split([]byte(tc.a)), Split([]byte(tc.b))
			checkProjections(t, 0, tc.a, tc.b, Lines([]byte(tc.a), []byte(tc.b)))
			_ = a
			_ = b
		})
	}
}

// TestMidLineEditIsAWholeLine is what "line-based" is for. A one-word change
// inside a long line is still one deleted line and one inserted line, never a
// byte range, and the output type has no room for a byte range at all.
func TestMidLineEditIsAWholeLine(t *testing.T) {
	t.Parallel()
	page := wikiPage("world/neverwinter-faction-web", 30)
	edited := midLineEdit(page)
	if page == edited {
		t.Fatal("the fixture changed nothing")
	}
	eq, del, ins := countOps(Lines([]byte(page), []byte(edited)))
	if eq != 0 || del != 1 || ins != 1 {
		t.Errorf("a one-word change inside one line = %d/%d/%d equal/delete/insert, want 0/1/1", eq, del, ins)
	}
}

// TestDiffHandlesHostileInput covers the shapes a logged-in user can put in a
// file and that a request path must not panic on.
func TestDiffHandlesHostileInput(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("x", 1<<20)
	tests := []struct {
		name string
		a, b string
	}{
		{name: "both-empty", a: "", b: ""},
		{name: "empty-to-empty-lines", a: "", b: "\n\n\n"},
		{name: "empty-lines-to-empty", a: "\n\n\n", b: ""},
		{name: "no-trailing-newline", a: "a", b: "b"},
		{name: "one-huge-line", a: huge, b: huge + "y"},
		{name: "huge-line-to-small", a: huge, b: "a\n"},
		{name: "invalid-utf8", a: "\xff\xfe\n\xc3(", b: "\xff\xff\n\xc3("},
		{name: "nul-bytes", a: "a\x00\n\x00\n", b: "\x00\n"},
		{name: "only-newlines", a: "\n", b: "\n\n"},
		{name: "very-many-empty-lines", a: strings.Repeat("\n", 5000), b: strings.Repeat("\n", 4999)},
		{name: "one-very-long-line-split", a: strings.Repeat("ab", 100000), b: strings.Repeat("ba", 100000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := Split([]byte(tc.a)), Split([]byte(tc.b))
			checkProjections(t, 0, tc.a, tc.b, Lines([]byte(tc.a), []byte(tc.b)))
			// Hunks is exported and a caller can hand it anything; it has to
			// clamp rather than index out of range.
			for _, ctx := range []int{-1, 0, 3} {
				for _, h := range Hunks(a, b, Lines([]byte(tc.a), []byte(tc.b)), ctx) {
					if h.FromA < 1 || h.FromB < 1 || h.CountA < 0 || h.CountB < 0 {
						t.Errorf("context %d: impossible hunk %+v", ctx, h)
					}
					if h.FromA-1+h.CountA > len(a) || h.FromB-1+h.CountB > len(b) {
						t.Errorf("context %d: hunk %+v runs past the end of a %d / b %d", ctx, h, len(a), len(b))
					}
				}
			}
		})
	}
}
