package search

import (
	"errors"
	"strings"
	"unicode"
)

// MaxQueryBytes is the longest raw input BuildMatchQuery will look at. Past it
// the input is refused rather than truncated: a query long enough to be a
// denial-of-service attempt is not one whose first kilobyte deserves an answer.
const MaxQueryBytes = 1024

// MaxTokens is the most tokens one query is turned into. The FTS5 planner cost
// grows with the number of OR-ed terms, so a megabyte of single letters would
// otherwise become a megabyte-long MATCH expression.
const MaxTokens = 32

// ErrQueryTooLong is returned by BuildMatchQuery for input over MaxQueryBytes.
var ErrQueryTooLong = errors.New("search: query is too long")

// BuildMatchQuery turns raw user input into an FTS5 MATCH expression that
// contains nothing but quoted string literals joined by OR.
//
// This is the security boundary of search. The FTS5 query language is a small
// programming language — NEAR(...), ^, *, column filters, and the AND/OR/NOT
// keywords — and handing it a user's raw keystrokes is handing it a program.
// The probes in §12's S4 are not hypothetical: an input of `a:b` makes SQLite
// fail with "no such column: a", and `NEAR(...)` is a query-planner lever.
//
// So the input is tokenised, not escaped. Everything that is not a token
// character under the index's own tokenizer is a separator and simply vanishes,
// which is why a phrase like `NEAR(a b)` searches for the three words near, a
// and b, and why `"unterminated` searches for the word unterminated. A token
// the FTS5 phrase syntax could not hold is dropped rather than escaped, because
// every escape route is another parser to get wrong.
//
// The tokens are the ones unicode61 with `remove_diacritics 2 tokenchars '_-'`
// produces from the index side, so SQLite folds a query token exactly as it
// folded the indexed text: the expression needs no folding of its own. The
// deliberate difference is that this tokeniser is a subset of the index's — a
// codepoint it does not recognise is dropped rather than guessed at, which costs
// recall and never widens a result.
//
// An input with no tokens yields an empty expression, and an empty expression
// is a caller's cue to return no rows rather than to run `MATCH ”`, which is a
// syntax error.
func BuildMatchQuery(q string) (string, error) {
	if len(q) > MaxQueryBytes {
		return "", ErrQueryTooLong
	}
	tokens := tokenise(q)
	if len(tokens) > MaxTokens {
		tokens = tokens[:MaxTokens]
	}
	if len(tokens) == 0 {
		return "", nil
	}
	quoted := make([]string, 0, len(tokens))
	// Deduplicate case-sensitively, keeping first-occurrence order. Repeating a
	// word adds nothing to recall and does add to the FTS5 planner's work, and
	// a user who types the same word three times is not asking three questions.
	seen := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		if seen[t] {
			continue
		}
		seen[t] = true
		quoted = append(quoted, `"`+t+`"`)
	}
	return strings.Join(quoted, " OR "), nil
}

// tokenise splits s into the tokens the index tokenizer would produce, using a
// deliberately narrower character class.
//
// unicode61 treats every Unicode letter and digit as a token character, plus
// whatever tokenchars adds. Matching that exactly would mean trusting
// unicode.IsLetter to agree with SQLite's own tables for every codepoint, and
// the failure mode is a query token that the index splits differently. A subset
// has the opposite failure mode: a dropped character, so a narrower query. A
// missed hit is a bug report; a widened result is a leak.
func tokenise(s string) []string {
	var (
		out []string
		cur strings.Builder
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		if isTokenRune(r) {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// isTokenRune reports whether r can appear inside one token. The '_' and '-'
// entries are the schema's `tokenchars '_-'`, which is what keeps
// "goblin_scouts" and "Red-Dragon" whole instead of splitting them into four
// fragments.
func isTokenRune(r rune) bool {
	if r == '_' || r == '-' {
		return true
	}
	// RuneError is what range over a string yields for an invalid byte, so a
	// binary blob is treated as a separator rather than as a letter. That is
	// what lets the fuzz target take random bytes without a validity check.
	if r == unicode.ReplacementChar {
		return false
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}
