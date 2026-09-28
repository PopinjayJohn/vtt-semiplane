package md

import (
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
