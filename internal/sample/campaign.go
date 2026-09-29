package sample

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

// The campaign ships in the binary. There is no second copy to install, no
// download step, and no way for the two to disagree: what the operator reads on
// first boot is the same bytes a reviewer read in the repository.
//
// The pattern names the directory, which means every file in it must be
// embeddable: //go:embed validates each name against x/mod's fileNameOK, which
// refuses the shell metacharacters " ' * < > ? ` |, and a walk of the directory
// refuses the first entry that fails. So a page cannot carry an apostrophe in
// its *file name* — the same character is perfectly fine in its title, in its
// aliases and in its prose, and one page here did carry one until a hand-carried
// copy of the file had to be maintained beside the real one. TestTheEmbeddedCampaignMatchesTheSourceTree
// still compares every embedded file with the source tree byte for byte, so a
// new top-level folder or a renamed page is a test failure rather than a file
// that quietly stopped shipping.
//
//go:embed campaign
var campaignFS embed.FS

// campaignDir is the directory the embed patterns name. It is a constant rather
// than a second argument to embed because the patterns and the sub-path must be
// the same string, and two copies of it are two things that can drift.
const campaignDir = "campaign"

// Root is the vault-relative directory the campaign is written to.
//
// It is a property of the campaign rather than of the boot: the content's two
// image references are written as full vault-relative paths on the assumption
// that the campaign lands here, and those references resolve against the vault
// root and not against the page's own directory. Changing this constant means
// changing those two lines of Markdown with it, which is why it lives beside
// the bytes rather than in the code that writes them.
const Root = "Campaigns/Ashes of the Hollow Crown"

// Name is the campaign's name, for the boot report. It is the last element of
// Root, carried separately so a log line does not have to split a path to say
// what it is saying.
const Name = "Ashes of the Hollow Crown"

// File is one file of the campaign: its name within the campaign and its bytes.
//
// It is a pair rather than an fs.FS because the campaign is not wholly carried
// by the embed, and an fs.FS handed to a caller would silently omit the one file
// that is not. A list has one way to be wrong — a missing entry — and the drift
// test fails on it. It is also what the caller wants: the walk in internal/app
// reads each file once, to decide whether it is already in the vault.
type File struct {
	// Name is the campaign-relative path, slash separated, with no leading
	// "./". Joining one onto Root yields the vault-relative path the file
	// belongs at.
	Name string
	// Content is the file's bytes, exactly as authored. The app never
	// normalises, reflows or reformats them, and neither does this.
	Content []byte
}

// Files returns every file of the campaign, sorted by name.
//
// The order is lexical and it is a promise rather than an accident of the
// walker's implementation, because the extraction's log line reports a count and
// a caller that wants to stop early wants the same files in the same order every
// time. Reading the whole campaign into memory costs a few hundred kilobytes on
// a boot that is about to read every one of these files again to index it.
func Files() ([]File, error) {
	var out []File
	err := fs.WalkDir(FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, err := fs.ReadFile(FS(), name)
		if err != nil {
			return err
		}
		out = append(out, File{Name: name, Content: content})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sample: walking the embedded campaign: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// FS returns the embedded campaign, rooted at the campaign directory.
//
// It is the whole campaign, and it is the same set of files Files walks: a
// caller that wanted a subdirectory should say so rather than receive a tree
// it has to know the shape of.
func FS() fs.FS {
	sub, err := fs.Sub(campaignFS, campaignDir)
	if err != nil {
		// Unreachable: the embed patterns above all name a path under a
		// directory the compiler verified exists, and fs.Sub fails only on a
		// name that is not a valid fs path. A panic here is a build defect, and
		// a silent empty campaign would be a boot that reports success and
		// writes nothing.
		panic("sample: the embedded campaign directory is not addressable: " + err.Error())
	}
	return sub
}
