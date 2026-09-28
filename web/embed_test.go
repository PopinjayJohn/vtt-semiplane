package web_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/web"
)

// TestTheEmbedIsTheCommittedTree is the drift guard, and the successor to
// TestEmbeddedAssetsAreTheCommittedOnes, which policed a hand-synced mirror of
// this directory under internal/web.
//
// With no mirror there is nothing that can fall out of step, because the bytes
// in the binary are the committed bytes. This asserts that in both directions
// anyway: a narrowed embed pattern, a transform in an accessor, or a file that
// reached the binary without being committed fails here rather than in a
// browser.
func TestTheEmbedIsTheCommittedTree(t *testing.T) {
	t.Parallel()
	fsys := web.FS()

	onDisk := map[string][]byte{}
	walk(t, "static", func(name string, body []byte) {
		onDisk[name] = body
	})
	if len(onDisk) == 0 {
		t.Fatal("static/ holds no files, so the comparison below is vacuous")
	}

	inBinary := map[string][]byte{}
	walkFS(t, fsys, func(name string, body []byte) {
		inBinary[name] = body
	})

	for _, name := range sortedKeys(onDisk) {
		got, ok := inBinary[name]
		if !ok {
			t.Errorf("static/%s is committed but not in the embedded tree: the embed pattern must cover the whole directory", name)
			continue
		}
		if !bytes.Equal(got, onDisk[name]) {
			t.Errorf("static/%s is embedded as %d bytes against %d on disk: rebuild the binary", name, len(got), len(onDisk[name]))
		}
	}
	for _, name := range sortedKeys(inBinary) {
		if _, ok := onDisk[name]; !ok {
			t.Errorf("the embedded tree has %s, which is not committed under static/: a binary was built from a tree this checkout does not have", name)
		}
	}
}

// TestTheEmbedIsRootedAtTheStaticDirectory pins the path a caller asks for, so
// the accessor cannot drift into returning a tree whose paths all carry a
// "static/" prefix and quietly 404s every asset.
func TestTheEmbedIsRootedAtTheStaticDirectory(t *testing.T) {
	t.Parallel()
	fsys := web.FS()

	body, err := fs.ReadFile(fsys, "app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	if len(body) == 0 {
		t.Error("app.css is empty, so the byte comparisons above are vacuous")
	}
	for _, name := range []string{"static/app.css", "../static/app.css", "assets/app.css"} {
		if _, err := fs.ReadFile(fsys, name); err == nil {
			t.Errorf("%s resolves, so the tree is not rooted at the static directory", name)
		}
	}
}

func walk(t *testing.T, dir string, fn func(name string, body []byte)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(rel), body)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func walkFS(t *testing.T, fsys fs.FS, fn func(name string, body []byte)) {
	t.Helper()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		fn(path, body)
		return nil
	})
	if err != nil {
		t.Fatalf("walk the embedded tree: %v", err)
	}
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
