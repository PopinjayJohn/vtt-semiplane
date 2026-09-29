// Package diff computes line-based diffs between two byte slices.
//
// It exists for one caller: the conflict page a save shows when it loses an
// optimistic-concurrency race. That page renders lines and resolves them one
// hunk at a time, so the unit of comparison is a whole line and a mid-line
// offset cannot even be represented. Nothing here knows about Markdown,
// secrets, sessions or HTTP, and the package imports nothing of ours.
//
// Three decisions are worth stating before the code, because each of them is a
// choice rather than a consequence.
//
// A line is its content with the terminator removed, so "\r\n" and "\n" are
// the same line. A page authored on Windows therefore diffs against a page
// authored on Linux as no change at all, and Line.CRLF carries the style for a
// caller that needs to know it. Keeping the terminator in the comparison unit
// instead would turn a 400 KiB CRLF file into an 800 KiB edit script — the
// whole reason this is hand-rolled rather than a library that splits on the
// terminator. The save is byte-surgical everywhere else (§1), so line-ending
// style is somebody's business and not the conflict page's.
//
// Lines returns a change script: deletes and inserts, and nothing for a line
// the two sides share. The cost of a diff is therefore what changed rather
// than how large the files are, a no-op diff is nil instead of a script of
// equalities as long as the file, and the two projections a conflict page
// needs — the script's deletes dropped from a leaves b, its inserts dropped
// from b leaves a — are total over every input.
//
// The edit distance is bounded. Past MaxEditDistance the search stops looking
// for a minimal script and emits one whole-region replace. That is a rendering
// decision as much as a performance one: a page with two thousand changed
// lines is shown as one hunk, because nobody resolves two thousand of them by
// hand, and the script is still valid — it is just not minimal.
package diff
