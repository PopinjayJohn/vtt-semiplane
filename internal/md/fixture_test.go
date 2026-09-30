package md

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// testdataDir is the committed corpus. Nothing in this package may write to
// it: a test that regenerates a fixture has stopped testing anything.
const testdataDir = "testdata"

// renderSizeLimit is the size above which a fixture is not handed to goldmark.
// The third-party wikilink parser rescans the current line for a closing `]]`
// at every `[`, which is quadratic, so the 1 MiB `[[` fixture would take
// longer than the universe. Every byte-level guarantee still applies to it; only
// the AST-level ones are skipped, and this is the one place that is visible.
const renderSizeLimit = 64 << 10

// corpusTB is the part of *testing.T and *testing.F the corpus helpers need.
// A fuzz target seeds itself from the same corpus the golden test sweeps, and
// *testing.F does not satisfy *testing.T, so the helpers take this instead.
type corpusTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// fixtureNames returns the committed corpus in a stable order.
func fixtureNames(t corpusTB) []string {
	t.Helper()
	entries, err := os.ReadDir(testdataDir)
	if err != nil {
		t.Fatalf("read %s: %v", testdataDir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatalf("the fixture corpus is empty")
	}
	return names
}

func loadFixture(t corpusTB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdataDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// fixtureEOL reports the line terminator a fixture's bytes currently carry.
//
// A fixture is a committed file read at test time, and a checkout is free to
// rewrite its line endings: git's core.autocrlf is true by default on Git for
// Windows, and actions/checkout does not override it, so every LF-only fixture
// arrives as CRLF on a Windows runner. An expectation written with a literal
// "\n" is then a comparison against the runner's git configuration rather than
// against this package, and it fails on a tree where nothing changed.
//
// The answer is measured from the fixture rather than from runtime.GOOS,
// because a checkout setting is not the platform: an LF checkout on Windows and
// a CRLF checkout on Linux both exist, and hard-coding either one would make a
// test that cannot fail.
func fixtureEOL(b []byte) string {
	if bytes.Contains(b, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// inEOL renders an expectation written in LF into the terminator a fixture
// uses, so a test states its expected bytes once and in one convention.
//
// It is a translation and not a normalisation: only the terminator the fixture
// already carried is accepted, so a rewrite that added a carriage return, or
// dropped one, or reflowed a line, still differs from the expected bytes and
// still fails. The alternative — normalising both sides before comparing —
// would discard exactly the class of defect this package exists to catch.
func inEOL(literal, eol string) string {
	if eol == "\n" {
		return literal
	}
	return strings.ReplaceAll(literal, "\n", eol)
}

// loadCorpus reads every fixture. It is the golden round trip's input, so it
// is read once and shared by every subtest rather than re-read per operation.
func loadCorpus(t corpusTB) map[string][]byte {
	t.Helper()
	corpus := make(map[string][]byte)
	for _, name := range fixtureNames(t) {
		corpus[name] = loadFixture(t, name)
	}
	return corpus
}
