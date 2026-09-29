package httpapi

// The wire shapes for renaming a page and for the opt-in bulk link updater
// (§5.6).
//
// They live in this file rather than in views.go for one reason: Go does not
// require a type to live beside the others that belong to the same feature, and
// keeping the rename family's shapes together means the web layer has one file
// to read and one place a new field has to be added. views.go still owns View,
// Shell and every model a template renders as a page.
//
// Two of the rules these types exist to uphold are worth stating before the
// fields, because several of the fields look redundant without them:
//
//   - **A view model is a security boundary.** Nothing here is a store row or a
//     md.Doc, so a template cannot reach a file's bytes or a secret body except
//     through a field that was put there on purpose. In particular Found holds
//     a *link target* — a short token an author typed between brackets — and
//     never a line, never a body and never anything a secret contains. An
//     occurrence the caller may not see is absent from the model entirely; it
//     is not present with a blank Found, because a row-shaped hole says the
//     row exists.
//   - **Nothing rendered here is a role.** CanWrite is a decision the handler
//     already made through the policy. A template that branched on it again
//     would be the second place in the codebase answering that question, which
//     AGENTS.md §2.7 is against.

// RenameResult is the answer to a successful POST /api/pages/{id}/rename.
//
// It is a JSON body rather than a view model: the rename is performed by a
// dialog the reader opened over a page, and a page navigation in the middle of
// it would lose the form's state. The updater pointer is here because the
// rename's whole purpose is to hand the reader the two calls that finish the
// job, and a client that had to build those URLs from the id would be a second
// place that knew the updater's shape.
type RenameResult struct {
	// OldPath is where the page's file was, before the move.
	OldPath string `json:"old_path"`
	// NewPath is where it is now.
	NewPath string `json:"new_path"`
	// OldName is the name the page answered to, and the alias that was recorded
	// so a link written against it keeps resolving. It is the bare basename
	// without the .md extension, which is the spelling a wikilink uses.
	OldName string `json:"old_name"`
	// NewName is the name the page answers to now, as the caller spelled it.
	NewName string `json:"new_name"`
	// PageID is the renamed page's index id. It is a *different* row from the
	// one the request named: a rename creates a new page row and the old one is
	// removed, which is exactly why the two updater calls below are addressed
	// to this id and not the one the rename was requested on.
	PageID int64 `json:"page_id"`
	// Aliases are the names that now resolve to this page because of the
	// rename: the departed basename plus every alias the departed row carried.
	// It is a list rather than a single field because the indexer carries the
	// whole set across a rename, and a client told about one of them would
	// under-report what the rename did.
	Aliases []string `json:"aliases"`
	// Updater points at the two calls that finish the rename. They are absolute
	// paths rather than a template for a client to fill in, so the URL of a
	// rename is a property of the server rather than of whoever is calling it.
	Updater LinkUpdaterPointer `json:"updater"`
}

// LinkUpdaterPointer names the two calls that finish a rename. The preview is
// a GET and needs the new name; the update is a POST and needs the new name and
// the word "confirmed", which the reader supplies by pressing the button the
// diff is drawn above.
type LinkUpdaterPointer struct {
	// Preview is the URL that answers what the update would change.
	Preview string `json:"preview"`
	// Update is the URL that performs it.
	Update string `json:"update"`
}

// LinkUpdatePlan is what the bulk link updater would do, computed from the
// state of the vault at the moment of the request.
//
// It is a plan and never a stored preview: §5.6's step 1 is "re-run resolution
// for the old name to get the current affected set; never trust the preview",
// and a type that could hold a preview would be one more thing a caller could
// be tempted to trust. The plan is also what both of the two handlers return,
// so the number a reader is shown before pressing the button and the number
// the server acts on come from one implementation of one question.
type LinkUpdatePlan struct {
	// OldName is the name the affected links were written against, and the name
	// the rewrite replaces. Before the move it is the page's own basename; after
	// the move the page answers to the new name and the old one survives only
	// as an alias, so the name is read off the affected set instead. It is empty
	// when the page answers to the new name and nothing refers to it any more,
	// which is a page nobody links to.
	OldName string `json:"oldName"`
	// NewName is the name the references are rewritten to, as the caller spelled
	// it. It is what was asked for and never what the page ended up called:
	// md.LinkEdits appends a .md to a token that carried one and leaves a token
	// that did not, and the per-occurrence Found field below is what a reader
	// compares to see that.
	NewName string `json:"newName"`
	// Affected is one row per page that refers to this one, in the order the
	// index returned them.
	Affected []LinkUpdatePage `json:"affected"`
	// Conflicts are the occurrences the updater will not touch, each with the
	// reason. They are listed rather than dropped because a rename that quietly
	// rewrote three of five links is a rename the reader did not agree to.
	Conflicts []LinkConflict `json:"conflicts"`
	// Summary is the plan in four numbers, and each of them is counted over the
	// same rows the slice above holds.
	Summary LinkUpdateSummary `json:"summary"`
}

// LinkUpdatePage is one affected page: where the references are, whether this
// reader may rewrite them, and which ones.
type LinkUpdatePage struct {
	// PageID is the referring page's index id.
	PageID int64 `json:"page_id"`
	// Path is its vault-relative path.
	Path string `json:"path"`
	// CanWrite is whether this reader holds writePage on *this* page. It is
	// false for a page somebody else owns, and the page is still listed: hiding
	// it would tell the reader that a page exists which refers to this one, and
	// that is the one thing the panel must not do.
	CanWrite bool `json:"canWrite"`
	// Count is how many occurrences the page holds.
	Count int `json:"count"`
	// Occurrences are the references themselves, in file order.
	Occurrences []LinkOccurrence `json:"occurrences"`
}

// LinkOccurrence is one recorded reference to the renamed page.
type LinkOccurrence struct {
	// Line is the 1-based line the reference is written on.
	Line int `json:"line"`
	// ByteStart is where the target token begins in the referring file. It is
	// store.LinkByteStartUnset when the index recorded no offset, and it is
	// never reported as 0 for "unknown": 0 is the first byte of a file, and a
	// preview that reported it there would be a preview pointing at the top of
	// the document.
	ByteStart int `json:"byteStart"`
	// ByteLen is how many bytes the token occupies, and 0 when no offset was
	// recorded. Zero means "not rewritable", never "at the start of the file":
	// a destination written escaped, in angle brackets or percent-encoded has
	// no locatable range, and this package will not decide what the author
	// meant by the escaping.
	ByteLen int `json:"byteLen"`
	// Found is the target exactly as the author wrote it, which is the token the
	// rewrite verifies against the file before it replaces anything. It is
	// always a short link target and never a line of prose.
	Found string `json:"found"`
}

// LinkConflict is one occurrence the updater will not rewrite, and why.
//
// The reason is a fixed phrase, never a snippet of the file: an occurrence that
// does not verify may sit anywhere, and the failure must not become a way to
// read a byte range of somebody else's page.
type LinkConflict struct {
	// PageID is the referring page.
	PageID int64 `json:"page_id"`
	// Path is its vault-relative path.
	Path string `json:"path"`
	// Line is the line the reference is written on, 0 when the index recorded
	// no line for it.
	Line int `json:"line"`
	// Found is the target as the author wrote it.
	Found string `json:"found"`
	// Reason is one of the constants in rename.go: ConflictStale,
	// ConflictUnrecorded, ConflictOutOfRange, ConflictInsideSecret,
	// ConflictOverlapping or ConflictHidden.
	Reason string `json:"reason"`
	// Message is the human-readable form of Reason. It carries no content: no
	// line of the file, no byte, no path outside this vault.
	Message string `json:"message"`
}

// LinkUpdateSummary is the plan in four numbers.
//
// Every one of them is counted over the rows the slices above hold. There is no
// window and no page limit, so a count and a list cannot disagree the way a
// panel's badge and a windowed list do — and a disagreement here would say
// something about pages the reader may not write.
type LinkUpdateSummary struct {
	// Pages is how many pages refer to this one.
	Pages int `json:"pages"`
	// Links is how many occurrences those pages hold in total.
	Links int `json:"links"`
	// Unwritable is how many of those pages this reader may not rewrite. It is
	// non-zero on a preview precisely so the reader is never told "12 links will
	// update" when only four can.
	Unwritable int `json:"unwritable"`
	// Conflicts is how many occurrences will be reported and left alone.
	Conflicts int `json:"conflicts"`
}

// LinkUpdateResult is the answer to a confirmed POST /api/pages/{id}/update-links.
type LinkUpdateResult struct {
	// Updated is how many pages were rewritten.
	Updated int `json:"updated"`
	// Skipped is how many were left alone, whatever the reason.
	Skipped int `json:"skipped"`
	// Details is one row per page that was not rewritten and one row per
	// occurrence that was not, so a reader who asked for twelve updates and got
	// nine can tell which three and why. A page with several skipped occurrences
	// contributes several rows, and the reason says which line each is about.
	Details []LinkUpdateDetail `json:"details"`
}

// LinkUpdateDetail is one page or one occurrence the updater left alone.
type LinkUpdateDetail struct {
	// Path is the vault-relative path of the referring file.
	Path string `json:"path"`
	// Reason is a fixed phrase naming why. It never contains content.
	Reason string `json:"reason"`
	// Message is the human-readable form. It names a line number and nothing
	// else about the file.
	Message string `json:"message"`
}

// The broken-links panel's view model is NOT here.
//
// BrokenLinksView, BrokenLinkRow, ShownLimit and the /broken page belong to
// views.go and to broken.go's neighbour, and the shape of the panel is the
// editor stage's decision: it caps the list at ShownLimit and carries Total
// beside it so the badge and the rows can never disagree. This file holds only
// the rename family's models, and the panel's two handler-side requirements —
// that the store's visible query is the one used, and that the panel's rows
// carry a target and a line and nothing else — are written down in broken.go
// next to the query they are about.
//
// The types the rename routes put on the wire are below, and they are JSON
// rather than views: the rename is performed by a dialog opened over a page, and
// navigating away from the page in the middle of it would lose the form's state.
