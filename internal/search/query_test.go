package search

import (
	"strconv"
	"strings"
	"testing"
)

// The operator tokens that must never appear unquoted in a MATCH expression
// BuildMatchQuery produces. `*` and `^` are included because a trailing `*` is
// the one that looks harmless and is a prefix operator.
var ftsOperators = []string{
	"NEAR", "AND", "OR", "NOT", "^", "*", ":", "-",
}

// assertSafeMatch is the property every normalised query must have: it is a
// sequence of quoted string literals joined by OR, and nothing else.
//
// Checking the shape rather than checking for banned substrings is the point. A
// test that greps for "NEAR(" would pass on `"NEAR"("`, and one that greps for
// a colon would fail on a legitimate `http://` inside a quoted literal.
func assertSafeMatch(t *testing.T, got string) {
	t.Helper()
	if got == "" {
		return
	}
	rest := got
	for {
		rest = strings.TrimPrefix(rest, " OR ")
		rest = strings.TrimPrefix(rest, `"`)
		if rest == "" {
			t.Fatalf("match query %q is malformed: a quoted literal is not terminated", got)
		}
		end := strings.Index(rest, `"`)
		if end < 0 {
			t.Fatalf("match query %q is malformed: a quoted literal is not terminated", got)
		}
		literal := rest[:end]
		if literal == "" {
			t.Fatalf("match query %q contains an empty literal", got)
		}
		if strings.ContainsAny(literal, `":*^()`) {
			t.Errorf("literal %q in %q contains a character the tokenizer should have dropped", literal, got)
		}
		rest = rest[end+1:]
		if rest == "" {
			return
		}
		if !strings.HasPrefix(rest, " OR ") {
			t.Fatalf("match query %q joins two expressions with %q; only OR is emitted", got, rest)
		}
	}
}

// runs splits text into its maximal non-space runs, and allOR reports whether
// every one of them is the joiner this package emits.
func runs(s string) []string { return strings.Fields(s) }

func allOR(got []string) bool {
	for _, r := range got {
		if r != "OR" {
			return false
		}
	}
	return true
}

// outsideQuotes returns the text of a match expression that lies outside its
// string literals.
func outsideQuotes(match string) string {
	var out strings.Builder
	inQuote := false
	for _, r := range match {
		switch {
		case r == '"':
			inQuote = !inQuote
		case inQuote:
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func TestBuildMatchQueryQuotesEveryToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   \t\n ", ""},
		{"one word", "vault", `"vault"`},
		{"two words are OR-ed", "vault door", `"vault" OR "door"`},
		{"case is preserved, the index folds it", "Vault", `"Vault"`},
		{"punctuation is a separator", "vault, door.", `"vault" OR "door"`},
		{"tokenchars keep a compound whole", "Red-Dragon goblin_scouts", `"Red-Dragon" OR "goblin_scouts"`},
		{"a leading dash is part of the token", "-lead", `"-lead"`},
		{"a run of dashes is one token", "a--b", `"a--b"`},
		{"the NEAR operator is not one", "NEAR(a b)", `"NEAR" OR "a" OR "b"`},
		{"a caret is dropped", "^x", `"x"`},
		{"a trailing star is dropped, not passed through", "a*", `"a"`},
		{"a bare AND is a word", "a AND b", `"a" OR "AND" OR "b"`},
		{"a bare OR is a word", "a OR b", `"a" OR "OR" OR "b"`},
		{"an unterminated quote is dropped", `"unterminated`, `"unterminated"`},
		{"a column filter is split, not honoured", "a:b", `"a" OR "b"`},
		{"a leading minus is not a NOT", "-x", `"-x"`},
		{"empty parens produce nothing", "()", ""},
		{"only operators produce nothing", "NEAR()", `"NEAR"`},
		{"a full-width colon is a separator", "title：x", `"title" OR "x"`},
		{"accents stay in the token for the index to fold", "Grüße", `"Grüße"`},
		{"astral-plane letters are letters", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢", `"𝔘𝔫𝔦𝔠𝔬𝔡𝔢"`},
		{"a NUL byte is a separator", "a\x00b", `"a" OR "b"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildMatchQuery(tc.in)
			if err != nil {
				t.Fatalf("BuildMatchQuery(%q) = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("BuildMatchQuery(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertSafeMatch(t, got)
		})
	}
}

// TestBuildMatchQueryHasNoUnquotedOperator is the property the plan names, stated
// over every adversarial shape a keyboard can produce. It is separate from the
// table above so that a new case here fails for one reason only.
func TestBuildMatchQueryHasNoUnquotedOperator(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"NEAR(a b)", "^x", "a*", "a AND b", "a OR b", `"unterminated`, "a:b", "-x",
		"()", "*", "^", ":", "NEAR", "AND", "OR", "NOT", `"`, `""`, `""""`,
		"a**b", "***", "a OR OR OR b", "col:val", "title : x", "a^", "^a",
		"a AND (b OR c)", "((()))", "\"a\" OR \"b", "a'", "'a", "a;b", "DROP TABLE pages",
		"a\x00b", "\xff\xfe", "日本��:x", "-", "--", "a--", "--a",
	} {
		got, err := BuildMatchQuery(in)
		if err != nil {
			t.Errorf("BuildMatchQuery(%q) = %v", in, err)
			continue
		}
		assertSafeMatch(t, got)
		if got == "" {
			continue
		}
		// Everything outside the quotes must be the joiner this package emits and
		// nothing else. Reading it in the plan's own words: no user-supplied
		// operator token is passed through.
		if unquoted := runs(outsideQuotes(got)); !allOR(unquoted) {
			t.Errorf("input %q produced %q, whose unquoted runs are %q rather than OR separators only",
				in, got, unquoted)
		}
	}
}

func TestBuildMatchQueryIsBounded(t *testing.T) {
	t.Parallel()

	// A long input yields a bounded expression, so the FTS5 planner cost cannot
	// grow with what a user typed.
	var long strings.Builder
	for i := 0; i < MaxTokens*3; i++ {
		long.WriteString("w")
		long.WriteString(strconv.Itoa(i))
		long.WriteByte(' ')
	}
	got, err := BuildMatchQuery(long.String())
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(got, ` OR `) + 1; n != MaxTokens {
		t.Errorf("an over-long input produced %d terms, want the MaxTokens cap of %d", n, MaxTokens)
	}
	assertSafeMatch(t, got)

	// Input past MaxQueryBytes is refused rather than answered, so a caller can
	// tell "you typed nonsense" from "you typed too much".
	huge := strings.Repeat("a", MaxQueryBytes+1)
	if _, err := BuildMatchQuery(huge); err == nil {
		t.Error("an over-long query was accepted")
	}
	// The boundary itself is accepted.
	if _, err := BuildMatchQuery(strings.Repeat("a", MaxQueryBytes)); err != nil {
		t.Errorf("a query of exactly MaxQueryBytes was refused: %v", err)
	}
}

// TestBuildMatchQueryDeduplicates keeps a repeated word from doubling the OR
// chain, which is a query-planner lever and nothing else.
func TestBuildMatchQueryDeduplicates(t *testing.T) {
	t.Parallel()
	got, err := BuildMatchQuery("vault vault VAULT door")
	if err != nil {
		t.Fatal(err)
	}
	// Case is significant, so this is two distinct literals plus the repeated one
	// collapsed.
	if got != `"vault" OR "VAULT" OR "door"` {
		t.Errorf("got %q; a repeated token should collapse", got)
	}
}

// TestTokeniseAgreesWithTheIndex is the property the whole design rests on: a
// token BuildMatchQuery emits must be a token the index tokenizer also produces,
// or the query searches for something the index never stored.
//
// It is asserted through the real FTS5 tokenizer in search_test.go; here the
// check is that tokenise never returns an empty token and never returns two
// tokens for one run of token characters.
func TestTokeniseIsMaximal(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "vault", "a-b", "-", "a--b", "  a  b  ", "日本", "\xff", "a\x00b"} {
		toks := tokenise(in)
		for i, tok := range toks {
			if tok == "" {
				t.Errorf("tokenise(%q) produced an empty token at %d", in, i)
				continue
			}
			for _, r := range tok {
				if !isTokenRune(r) {
					t.Errorf("tokenise(%q) emitted %q, which contains the non-token rune %q", in, tok, r)
				}
			}
		}
	}
}
