package web_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/web"
	webassets "github.com/PopinjayJohn/vtt-semiplane/web"
)

// TestAssetsAreTheCommittedFiles is the drift guard on this side of the
// accessor: the tree the asset route serves is the tree at the module root is
// the tree committed in web/static/.
//
// It used to compare a mirror against the committed files. A mirror was needed
// only because an embed pattern may not contain "..", and the guard is still
// needed because everything above FS() is a hand-off that could grow a copy or
// a transform. Byte-identity, not equality of names, is the property: a stylesheet
// that is rewritten on the way out is a stylesheet this binary never contained.
func TestAssetsAreTheCommittedFiles(t *testing.T) {
	t.Parallel()

	served := map[string][]byte{}
	walkAssets(t, web.Assets(), served)
	if len(served) == 0 {
		t.Fatal("the asset tree is empty, so the comparison below is vacuous")
	}

	for _, name := range sortedKeys(served) {
		fromRoot, err := fs.ReadFile(webassets.FS(), name)
		if err != nil {
			t.Errorf("the embedded tree has %s but the module-root embed does not", name)
			continue
		}
		if !bytes.Equal(served[name], fromRoot) {
			t.Errorf("%s: the tree Assets() hands out differs from the embedded one", name)
		}

		committed, err := os.ReadFile(filepath.Join("..", "..", "web", "static", filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("read the committed asset: %v", err)
			continue
		}
		if !bytes.Equal(served[name], committed) {
			t.Errorf("%s: served %d bytes against %d committed in web/static/", name, len(served[name]), len(committed))
		}
	}
}

// TestThereIsNoAssetMirror fails if a second copy of the asset tree reappears
// beside this package's code.
//
// The mirror is gone, and this is the tripwire that keeps it gone: a directory
// here that looks like an asset tree is a copy nothing has to update, and the
// binary would serve whichever of the two a build happened to embed.
func TestThereIsNoAssetMirror(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("assets"); err == nil {
		t.Error("internal/web/assets exists: the embed reaches web/static/ directly, so a copy here can only be a stale one")
	} else if !os.IsNotExist(err) {
		t.Errorf("stat internal/web/assets: %v", err)
	}
}

func walkAssets(t *testing.T, fsys fs.FS, into map[string][]byte) {
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
		into[path] = body
		return nil
	})
	if err != nil {
		t.Fatalf("walk the asset tree: %v", err)
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
