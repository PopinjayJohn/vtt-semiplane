package md

import (
	"bytes"
	"strings"
	"testing"
)

// seedSizeLimit bounds what a fuzz target will hand goldmark. A megabyte of
// `[` makes the third-party wikilink parser quadratic, so a fuzz target that
// grew into one would spend its whole budget in one input. The full-size case
// is covered by the committed 1 MiB fixture in the golden test, which is the
// right place for it: a fixture is a fact, a fuzz seed is a starting point.
const seedSizeLimit = 8 << 10

// seedCorpus adds the committed fixtures to a fuzz target, truncated so that
// the seed corpus stays small. The fixtures are the shapes a vault actually
// contains, and a fuzzer starting from nothing takes a long time to rediscover
// that a secret fence is interesting.
func seedCorpus(f *testing.F) {
	f.Helper()
	for _, name := range fixtureNames(f) {
		src := loadFixture(f, name)
		if len(src) > seedSizeLimit {
			src = src[:seedSizeLimit]
		}
		f.Add(src)
	}
}

// FuzzNeverCorrupt asserts the package's central invariant: a parse of any
// bytes at all produces a span list that partitions the body exactly once, and
// a re-parse of the same bytes produces the same one.
//
// It is called never-corrupt because the failure it catches is silent. A span
// list that is short by one byte, or that runs backwards, or that disagrees
// between two reads of the same file, produces a Doc whose facts are all
// plausible and whose secret attribution is wrong. Nothing crashes; somebody
// just sees a paragraph they were not supposed to see.
func FuzzNeverCorrupt(f *testing.F) {
	seedCorpus(f)
	f.Add([]byte(""))
	f.Add([]byte("```secret id=abc\nbody\n```\n"))
	f.Add([]byte("\xef\xbb\xbf---\ntitle: x\n---\n\n# t\n"))
	f.Add([]byte("# a\x00b\n"))

	f.Fuzz(func(t *testing.T, src []byte) {
		d := Parse("fuzz.md", src)
		assertSpansPartitionBody(t, d)

		// Re-reading the same bytes must give the same answer. A parser whose
		// output depends on anything but the input is not a parser this design
		// can rest on: the indexer reads a file, and the indexer has no state.
		again := Parse("fuzz.md", src)
		if len(again.Spans) != len(d.Spans) {
			t.Fatalf("two parses of the same bytes disagree on the span count: %d then %d",
				len(d.Spans), len(again.Spans))
		}
		for i := range d.Spans {
			if d.Spans[i] != again.Spans[i] {
				t.Fatalf("two parses of the same bytes disagree on span %d: %+v then %+v",
					i, d.Spans[i], again.Spans[i])
			}
		}

		// Segment is the constructor without a path; it must agree with Parse
		// so that the two entry points cannot drift.
		seg, err := Segment(src)
		if err != nil {
			t.Fatalf("Segment: %v", err)
		}
		if len(seg.Spans) != len(d.Spans) {
			t.Fatalf("Segment and Parse disagree on the span count: %d then %d",
				len(seg.Spans), len(d.Spans))
		}

		// The translated public body must be the public body, byte for byte.
		// An offset translation that is off by the size of a removed secret
		// would attribute every fact after it to the wrong span.
		text, spans := d.PublicBodyOffsets()
		if !bytes.Equal(text, d.PublicBody()) || len(spans) != len(d.PublicSpans()) {
			t.Fatal("PublicBodyOffsets does not agree with PublicBody")
		}
	})
}

// assertSpansPartitionBody requires the span list to cover the body exactly
// once: ascending, non-overlapping, starting at the body's first byte, ending
// at its last, and reassembling into the body when the pieces are concatenated.
func assertSpansPartitionBody(t *testing.T, d *Doc) {
	if !d.BodyRange.Valid() {
		if len(d.Spans) != 0 {
			t.Fatalf("an empty body has %d spans", len(d.Spans))
		}
		return
	}
	prev := d.BodyRange.Start
	var rebuilt []byte
	for i, s := range d.Spans {
		if s.StartByte != prev {
			t.Fatalf("span %d starts at %d, expected %d (gap or overlap): %+v",
				i, s.StartByte, prev, d.Spans)
		}
		if s.EndByte < s.StartByte {
			t.Fatalf("span %d runs backwards: %+v", i, s)
		}
		if s.EndByte > d.BodyRange.End {
			t.Fatalf("span %d ends past the body: %+v", i, s)
		}
		if s.Secret() && s.SecretID == "" {
			t.Fatalf("span %d is secret with no id: %+v", i, s)
		}
		if !s.Secret() && s.SecretID != "" {
			t.Fatalf("span %d is public with a secret id: %+v", i, s)
		}
		rebuilt = append(rebuilt, d.Bytes[s.StartByte:s.EndByte]...)
		prev = s.EndByte
	}
	if prev != d.BodyRange.End {
		t.Fatalf("the spans end at %d, expected the body's %d", prev, d.BodyRange.End)
	}
	if !bytes.Equal(rebuilt, d.Body) {
		t.Fatalf("the spans reassemble into %d bytes, the body is %d", len(rebuilt), len(d.Body))
	}
}

// FuzzMalformedMarkdown drives the whole pipeline — segment, render, extract —
// over bytes no author would type, and requires only that it does not panic and
// does not hang.
//
// It is a liveness target, not a correctness one. A panic here is a 500 for
// whoever saved the file; a hang is worse, because a watcher parked on a
// spinning parse stops indexing the rest of the vault.
func FuzzMalformedMarkdown(f *testing.F) {
	r := New(Options{})
	seedCorpus(f)
	for _, seed := range malformedSeeds() {
		if len(seed) > seedSizeLimit {
			seed = seed[:seedSizeLimit]
		}
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > seedSizeLimit {
			t.Skip("larger than the size this target renders")
		}
		d := Parse("fuzz.md", src)
		if _, err := r.Render(d.PublicBody()); err != nil {
			t.Fatalf("render: %v", err)
		}
		if _, problems := Extract(d, r); len(problems) > len(d.Problems)+1 {
			t.Fatalf("extract reported %d problems for a document parsed with %d",
				len(problems), len(d.Problems))
		}
	})
}

// malformedSeeds are the shapes a fuzzer starting from well-formed files takes
// a long time to find: a fence that never closes, a fence closed by the wrong
// delimiter, a file whose line endings change halfway through, a byte order
// mark in front of frontmatter, a NUL in the middle of a word, and a run of a
// single token long enough to make a naive scanner quadratic.
func malformedSeeds() [][]byte {
	nested := &strings.Builder{}
	for i := 0; i < 100; i++ {
		nested.WriteString(strings.Repeat("  ", i))
		nested.WriteString("- level\n")
	}
	return [][]byte{
		// A truncated secret fence: the span must run to end of file rather
		// than being dropped.
		[]byte("```secret id=abc\nbody with no closing fence\n"),
		// A fence closed by the other delimiter.
		[]byte("```js\nconst a = 1;\n~~~\nstill inside\n"),
		// A fence whose run is longer than its opener.
		[]byte("```\n````\n"),
		// CRLF and LF in the same file, including inside a secret fence.
		[]byte("---\r\ntitle: mixed\r\n---\n\n# H\n\n```secret id=a\r\nbody\n```\n"),
		// A byte order mark in front of frontmatter, and one on its own.
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("---\ntitle: x\n---\n\n# t\n")...),
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("no frontmatter\n")...),
		// NUL bytes in a heading, in frontmatter and in a fence directive.
		[]byte("# he\x00ading\n\n---\ntitle: \x00\n---\n\n```secret id=\x00\nbody\n```\n"),
		// A byte-level scanner must move its cursor on every one of these.
		[]byte(strings.Repeat("[[", 4096)),
		[]byte(strings.Repeat("!", 4096) + "[[" + strings.Repeat("]", 4096)),
		[]byte(strings.Repeat("%", 4096)),
		[]byte(strings.Repeat("%%", 2048)),
		[]byte(strings.Repeat("=", 4096)),
		[]byte(strings.Repeat("==", 2048)),
		[]byte(strings.Repeat(">", 4096) + " [!note]"),
		[]byte(strings.Repeat("```secret id=", 512)),
		[]byte(strings.Repeat("\n", 4096) + "```secret id=a\n"),
		// Block structures that nest without end.
		[]byte(nested.String()),
		[]byte(strings.Repeat("> ", 512) + "deep\n"),
		[]byte(strings.Repeat("- ", 512) + "deep\n"),
		// A closing fence of a run that is not the opener's.
		[]byte("````\n```\n````\n"),
		// Backticks inside a fence info string, which may not close it.
		[]byte("```js `x`\nbody\n"),
	}
}
