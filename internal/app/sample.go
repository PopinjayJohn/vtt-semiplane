package app

import (
	"context"
	"errors"
	"os"
	"path"

	"github.com/PopinjayJohn/vtt-semiplane/internal/sample"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// sampleDestination maps a campaign-relative name to the vault-relative path the
// file belongs at, and reports false for a name the vault would refuse to hold.
//
// The refusal is vault.Ignored, and it is asked even though the name came from a
// walk of a filesystem compiled into the binary rather than off the wire. The
// rule it enforces is not about trust, it is about agreement: a file the vault
// declines to index is a file the operator has and the app cannot show, so
// writing one would put a page on disk that nothing can find. The campaign
// carries no such name today; asking costs one map lookup and makes that a
// property of the walk rather than of the content.
func sampleDestination(name string) (string, bool) {
	rel := path.Join(sample.Root, name)
	if vault.Ignored(rel) {
		return "", false
	}
	return rel, true
}

// extractSample writes the bundled campaign into the vault, and never over a
// file that is already there.
//
// The non-clobber rule is the whole design, so it is worth being exact about
// what enforces it: one vault.Read per file, and only ErrNotFound means absent.
// A nil error means the file is there. So does every other error — a file over
// the read cap, a path that is a directory, a permission the process does not
// have — because none of those is evidence of absence, and treating one as
// absence is exactly the overwrite this refuses to perform. The read is also the
// size check, so "does it exist" and "is it under the cap" are one question
// rather than two that could disagree.
//
// The destination is built with vault.Resolve rather than vault.New, and the
// reason is that the path is ours while the tree it lands in is not. New
// performs no containment check and no name validation, and its own comment
// licenses it for a path that came from a walk of the vault; these came from a
// walk of a filesystem compiled into the binary, so that is not the case New
// documents. What Resolve buys is concrete rather than theoretical: it refuses
// a ".." element, a control character, a drive letter, a UNC path, a trailing
// dot, and — the one that is easy to assume and easy to be wrong about — a
// campaign root that is a symlink pointing outside the vault. A DM who links
// Campaigns/ at a shared drive is doing something entirely ordinary, and with
// New the walk would follow the link and write thirty-eight files outside a
// vault that would then report itself empty. TestThatTheExtractionRefusesToWrite
// ThroughASymlinkedCampaignRoot is that case, and it is why the constructor is
// this one.
//
// This runs on every boot, not on a first boot. The walk costs one Resolve and
// one Read per file and changes nothing when the campaign is already there, so
// gating it on a marker would buy no work and would add a state file whose loss
// — a restored backup, a vault copied off a machine that had already extracted,
// a marker deleted with the directory it described — silently skips the campaign
// for ever. Being wrong in that direction is worse than re-checking. It also
// means a later binary that ships an extra campaign page puts it into an
// operator's existing vault on the next restart, which is the behaviour a
// living sample document wants and which a first-boot gate could not have.
//
// A file that cannot be written is a warning and not a boot failure. The
// operator gets an app with a missing page and a banner that names it, which is
// the same bargain the vault walk makes for a file it cannot read, and the right
// one: refusing to start because a convenience write failed would take the
// campaign the operator already had away from them.
func (a *App) extractSample(ctx context.Context) {
	files, err := sample.Files()
	if err != nil {
		// Unreachable in practice — the campaign is in the binary and the
		// enumeration is a walk of it — but a boot that silently skipped the
		// campaign would report success and leave an empty vault, so it is
		// reported rather than swallowed.
		a.addWarning("the bundled sample campaign could not be read and was not written: " + err.Error())
		return
	}

	var written, kept int
	for _, f := range files {
		rel, ok := sampleDestination(f.Name)
		if !ok {
			a.addWarning("the bundled sample campaign's " + f.Name +
				" was not written: the vault treats that path as its own state and would not index it")
			continue
		}
		p, err := vault.Resolve(a.root, rel)
		if err != nil {
			a.addWarning("the bundled sample campaign's " + rel + " was not written: " + err.Error())
			continue
		}
		if _, err := vault.Read(ctx, p); !errors.Is(err, vault.ErrNotFound) {
			kept++
			a.warnIfNotAFile(p, rel)
			continue
		}
		if err := vault.Write(ctx, p, f.Content); err != nil {
			a.addWarning("the bundled sample campaign's " + rel + " was not written: " + err.Error())
			continue
		}
		written++
	}

	// Names and counts. The counts are the evidence that the non-clobber walk
	// ran: a second boot reports zero written and every file kept, which is the
	// claim that re-running a downloaded binary in place cannot damage a vault.
	a.log.InfoContext(ctx, "the bundled sample campaign was written into the vault",
		"action", "boot.sample", "campaign", sample.Name, "root", sample.Root,
		"written", written, "kept", kept)
}

// warnIfNotAFile names the one kind of "already there" that is a problem.
//
// A file the operator has written where the campaign wants one is the whole
// point of the non-clobber rule and needs no comment. Something that is not a
// file is a different fact: a directory at a page's path is a page the DM
// believes is in their campaign and is not, which is the same class of silence
// walkWarnings exists to break. The path and the kind, never the content.
func (a *App) warnIfNotAFile(p vault.Path, rel string) {
	st, err := os.Stat(p.Abs())
	if err != nil || st.Mode().IsRegular() {
		return
	}
	a.addWarning("the bundled sample campaign's " + rel +
		" was not written: something that is not a file is already at that path, and it was left alone")
}
