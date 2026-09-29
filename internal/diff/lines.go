package diff

import "bytes"

// Op is what an Edit does to one side of a diff.
type Op int

const (
	// OpEqual marks a line that both sides share. Lines never emits one — it
	// returns a change script, so an unchanged line is the absence of an
	// edit — but Hunk.Edits does, because a hunk that carries its own context
	// is renderable from a single slice.
	OpEqual Op = iota
	// OpDelete marks a line that is in a and not in b.
	OpDelete
	// OpInsert marks a line that is in b and not in a.
	OpInsert
)

// String names the op the way a unified diff marker does.
func (o Op) String() string {
	switch o {
	case OpEqual:
		return " "
	case OpDelete:
		return "-"
	case OpInsert:
		return "+"
	}
	return "?"
}

// Edit is one line's disposition in a change script.
//
// Line is the 1-based line number in the side the edit applies to: in a for
// OpEqual and OpDelete, in b for OpInsert. It indexes the []Line that Split
// returned for that input.
type Edit struct {
	Op   Op
	Line int
}

// Line is one line of an input: its content with the terminator removed, and
// the terminator's style.
//
// Text aliases the input rather than copying it, so Split costs one slice of
// headers and no per-line bytes. A Line therefore reads garbage once whatever
// it came from is written to, which for this package's caller means it must
// not outlive the buffer vault.Read handed it.
type Line struct {
	Text []byte
	// CRLF records that the terminator on disk was "\r\n" rather than "\n".
	// It never takes part in a comparison; see the package comment for why.
	CRLF bool
}

// Split cuts b into lines.
//
// A line ends at every "\n". One "\r" immediately before the "\n" belongs to
// the terminator and is recorded in Line.CRLF; a "\r" with no "\n" after it is
// ordinary content. The empty input has no lines, and a trailing "\n" does not
// invent one, so len(Split(b)) is the line count a text editor would report.
//
// Bytes that are not valid UTF-8 pass through untouched. This package compares
// bytes and never decodes, so a page that is not text at all costs no more
// than one that is.
func Split(b []byte) []Line {
	if len(b) == 0 {
		return nil
	}
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	out := make([]Line, 0, n+1)
	for i := 0; i < len(b); {
		// The cursor only ever moves to the byte after a delimiter or out of
		// the buffer, which is the progress assertion AGENTS.md §11 asks for:
		// the two hangs that shipped in the markdown pipeline were both a
		// branch that recognised a token and then read it again.
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			out = append(out, Line{Text: b[i:]})
			break
		}
		end := i + j
		if end > i && b[end-1] == '\r' {
			out = append(out, Line{Text: b[i : end-1], CRLF: true})
		} else {
			out = append(out, Line{Text: b[i:end]})
		}
		i = end + 1
	}
	return out
}

// Lines returns the changes that turn a into b, as a change script.
//
// The script is deletes and inserts in order, and it says nothing about the
// lines it does not mention: each of those is shared by both sides. Both
// projections follow from that, and both hold for every input — take Split(a)
// and drop the lines the script deletes and what is left is b; take Split(b)
// and drop the lines it inserts and what is left is a. A script that moved a
// line instead of deleting and reinserting it would satisfy neither, which is
// what the round-trip test is for.
//
// A nil script means the two inputs have the same lines. It is nil rather than
// a run of equalities so that a page nobody touched costs a comparison and
// nothing else, whatever its size.
func Lines(a, b []byte) []Edit {
	// Byte equality is the common case — a save whose hash still matches the
	// file on disk — and answering it before splitting is what lets that case
	// allocate nothing at all. It is not a substitute for the line comparison:
	// two files that differ only in line endings are byte-different and line-
	// equal, and they take the path below and come back nil.
	if bytes.Equal(a, b) {
		return nil
	}
	s := search{maxD: MaxEditDistance, maxDepth: maxRecursionDepth, prefilter: true}
	return s.diff(nil, Split(a), Split(b), 0, 0)
}

// lineEq compares two lines by content. Line.CRLF is deliberately not read.
func lineEq(a, b Line) bool { return bytes.Equal(a.Text, b.Text) }
