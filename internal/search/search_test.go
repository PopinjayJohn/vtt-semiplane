package search

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// dmSecretBody is the string that must never appear in any result, snippet or
// count for a principal who may not read it. It is a real sentence rather than
// a marker, so a leak is a leak and not an artefact of the fixture.
const dmSecretBody = "The vault door opens only for the bearer of the brass key"

const tableSecretBody = "The lantern gutters when the tide turns"

func newVault(t *testing.T) (*store.DB, int64, map[string]int64) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	users := map[string]int64{}
	for name, role := range map[string]string{
		"dm": "dm", "admin": "admin", "alice": "player", "bob": "player",
	} {
		id, err := store.InsertUser(ctx, db.Writer(), store.User{
			Username: name, DisplayName: name, Role: role, PWSalt: []byte("s"),
			CreatedAt: time.Unix(1750000000, 0).UTC(),
		})
		if err != nil {
			t.Fatalf("insert user %s: %v", name, err)
		}
		users[name] = id
	}
	return db, users["dm"], users
}

func principal(id int64, name, role string) authz.Principal {
	return authz.ForUser(id, name, authz.Role(role), false)
}

// indexPage writes a page and its public search text.
func indexPage(t *testing.T, db *store.DB, path, title, body string) int64 {
	t.Helper()
	ctx := context.Background()
	at := time.Unix(1750000000, 0).UTC()
	id, err := store.UpsertPage(ctx, db.Writer(), store.Page{
		Path: path, Basename: strings.TrimSuffix(path, ".md"), Title: title,
		Frontmatter: "", ContentHash: []byte(path), MTimeUnix: 1750000000,
		SizeBytes: int64(len(body)), PageType: "note", CreatedAt: at, UpdatedAt: at,
	})
	if err != nil {
		t.Fatalf("upsert %s: %v", path, err)
	}
	if err := store.ReplacePageText(ctx, db.Writer(), store.PageText{
		PageID: id, Title: title, Headings: "Traps", Body: body,
	}); err != nil {
		t.Fatalf("index %s: %v", path, err)
	}
	return id
}

// addSecret writes a secret on a page and, when it is table-visible, indexes it
// exactly the way the indexer will.
func addSecret(t *testing.T, db *store.DB, pageID int64, id string, vis authz.Visibility, author int64, body string) {
	t.Helper()
	ctx := context.Background()
	at := time.Unix(1750000000, 0).UTC()
	if err := store.InsertSecret(ctx, db.Writer(), store.Secret{
		ID: id, PageID: pageID, Ordinal: len(id), Visibility: vis, AuthorID: author,
		Body: body, BodyHash: []byte(id), CreatedAt: at, UpdatedAt: at,
	}); err != nil {
		t.Fatalf("insert secret %s: %v", id, err)
	}
	if vis == authz.VisibilityTable {
		if err := store.IndexSecretText(ctx, db.Writer(), id, vis, body); err != nil {
			t.Fatalf("index secret %s: %v", id, err)
		}
	}
}

func TestFTSBasicSearch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, users := newVault(t)

	indexPage(t, db, "Vault.md", "The Sunken Vault",
		"The vault door is warded. Opening it deals 3d6 necrotic damage.")
	indexPage(t, db, "Gundren.md", "Gundren", "A cheerful dwarf with a red beard.")
	indexPage(t, db, "Traps.md", "Traps", "Pressure plates, dart holes, and a warding glyph.")

	dm := principal(dmID, "dm", "dm")
	bob := principal(users["bob"], "bob", "player")

	t.Run("title match", func(t *testing.T) {
		res, err := Query(ctx, db.Reader(), dm, "Gundren", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 1 || len(res.Hits) != 1 {
			t.Fatalf("total %d hits %d, want 1", res.Total, len(res.Hits))
		}
		h := res.Hits[0]
		if h.Kind != KindPage || h.Path != "Gundren.md" || h.Title != "Gundren" {
			t.Errorf("hit = %+v", h)
		}
		if h.Href() != "/p/Gundren.md" {
			t.Errorf("href = %q", h.Href())
		}
	})

	t.Run("body match", func(t *testing.T) {
		res, err := Query(ctx, db.Reader(), dm, "dwarf", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 1 {
			t.Fatalf("total = %d, want 1", res.Total)
		}
	})

	t.Run("OR semantics", func(t *testing.T) {
		res, err := Query(ctx, db.Reader(), dm, "dwarf warded", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 2 {
			t.Errorf("total = %d, want 2 (the words are OR-ed, not AND-ed)", res.Total)
		}
	})

	t.Run("no match", func(t *testing.T) {
		res, err := Query(ctx, db.Reader(), dm, "dragon", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 0 || len(res.Hits) != 0 {
			t.Errorf("total %d hits %d, want none", res.Total, len(res.Hits))
		}
	})

	t.Run("every principal sees the same public content", func(t *testing.T) {
		for name, p := range map[string]authz.Principal{
			"dm": dm, "bob": bob, "admin": principal(users["admin"], "admin", "admin"),
		} {
			res, err := Query(ctx, db.Reader(), p, "warded", Options{})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if res.Total != 1 {
				t.Errorf("%s: total = %d, want 1", name, res.Total)
			}
		}
	})

	t.Run("title outranks body", func(t *testing.T) {
		// bm25 weights the title at 10, so a page whose title matches must come
		// before one that merely mentions the word.
		indexPage(t, db, "Warded.md", "Warded", "nothing relevant here")
		indexPage(t, db, "Mention.md", "Mention", "this page is warded somehow")
		res, err := Query(ctx, db.Reader(), dm, "warded", Options{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Total != 3 {
			t.Fatalf("total = %d, want 3", res.Total)
		}
		if res.Hits[0].Path != "Warded.md" {
			t.Errorf("first hit = %q, want the title match %q", res.Hits[0].Path, "Warded.md")
		}
	})

	t.Run("paging agrees with the total", func(t *testing.T) {
		first, err := Query(ctx, db.Reader(), dm, "warded", Options{Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		second, err := Query(ctx, db.Reader(), dm, "warded", Options{Limit: 1, Offset: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Hits) != 1 || len(second.Hits) != 1 {
			t.Fatalf("page sizes %d and %d", len(first.Hits), len(second.Hits))
		}
		if first.Hits[0].Path == second.Hits[0].Path {
			t.Error("paging returned the same row twice")
		}
		if first.Total != second.Total || first.Total != 3 {
			t.Errorf("totals %d and %d, want 3 for both", first.Total, second.Total)
		}
	})

	t.Run("limit is clamped", func(t *testing.T) {
		res, err := Query(ctx, db.Reader(), dm, "warded", Options{Limit: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Hits) > MaxLimit {
			t.Errorf("%d hits returned, want at most MaxLimit=%d", len(res.Hits), MaxLimit)
		}
	})

	t.Run("empty query is an empty result, not an error", func(t *testing.T) {
		for _, q := range []string{"", "   ", "()", "\x00"} {
			res, err := Query(ctx, db.Reader(), dm, q, Options{})
			if err != nil {
				t.Errorf("Query(%q) = %v, want no error", q, err)
				continue
			}
			if res.Total != 0 || len(res.Hits) != 0 {
				t.Errorf("Query(%q) = %+v, want empty", q, res)
			}
		}
	})
}

// TestAnonymousReadIsOffByDefault covers §8.2's bottom row from the other
// direction: with anonymous read disabled there is no query to run at all.
func TestAnonymousReadIsOffByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, _ := newVault(t)
	indexPage(t, db, "Public.md", "Public", "a public page")
	dm := principal(dmID, "dm", "dm")

	res, err := Query(ctx, db.Reader(), authz.Anonymous(false), "public", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 0 || len(res.Hits) != 0 {
		t.Errorf("an anonymous principal with read disabled got %+v", res)
	}
	// The same query as a DM finds it, so the zero is the authz decision and not
	// an empty index.
	if res, err := Query(ctx, db.Reader(), dm, "public", Options{}); err != nil || res.Total != 1 {
		t.Errorf("DM total = %d (err %v), want 1", res.Total, err)
	}
}

// TestFTSSnippetIsHTMLSafe is the §5.1/§12 rule that vault text never reaches
// the response as markup. A page whose body contains a script tag is indexed
// like any other; the snippet comes back escaped.
func TestFTSSnippetIsHTMLSafe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, _ := newVault(t)
	dm := principal(dmID, "dm", "dm")

	indexPage(t, db, "Trap.md", "Warding Glyph",
		`The warding glyph reads <script>alert('warded')</script> and "quotes" & ampersands.`)

	res, err := Query(ctx, db.Reader(), dm, "warded", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Hits) != 1 {
		t.Fatalf("total %d hits %d, want 1", res.Total, len(res.Hits))
	}
	snip := res.Hits[0].Snippet
	if snip == "" {
		t.Fatal("no snippet was produced; the assertion below would pass vacuously")
	}
	for _, forbidden := range []string{"<script>", "</script>", "<", ">"} {
		if strings.Contains(snip, forbidden) {
			t.Errorf("snippet %q contains %q; vault text must be escaped on the way out", snip, forbidden)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "&amp;", "warded"} {
		if !strings.Contains(snip, want) {
			t.Errorf("snippet %q does not contain the escaped %q", snip, want)
		}
	}
	// An attribute context is the one that matters most, so quote and apostrophe
	// are escaped too.
	if strings.Contains(snip, `'`) {
		t.Errorf("snippet %q leaves an apostrophe unescaped", snip)
	}
}

// TestSnippetIsBounded stops one enormous paragraph from becoming the response.
func TestSnippetIsBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, _ := newVault(t)
	dm := principal(dmID, "dm", "dm")

	indexPage(t, db, "Long.md", "Long", "needle "+strings.Repeat("filler ", 2000))
	res, err := Query(ctx, db.Reader(), dm, "needle", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 {
		t.Fatalf("hits = %d", len(res.Hits))
	}
	if len(res.Hits[0].Snippet) > SnippetMaxChars+8 {
		t.Errorf("snippet is %d bytes, want at most about %d", len(res.Hits[0].Snippet), SnippetMaxChars)
	}
}

// TestSearchNeverReturnsAHiddenSecret is the P1 half of the P4 leak suite, and
// the assertion the phase's own accept list names: a term that appears only in a
// secret a principal may not read returns nothing at all — not a hit, not a
// snippet, not a count.
func TestSearchNeverReturnsAHiddenSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, users := newVault(t)

	pageID := indexPage(t, db, "Vault.md", "The Sunken Vault",
		"The vault door is warded.")
	addSecret(t, db, pageID, "sdm00000001", authz.VisibilityDM, users["alice"], dmSecretBody)
	addSecret(t, db, pageID, "sprv0000001", authz.VisibilityPrivate, users["alice"], "A private ledger of debts")
	addSecret(t, db, pageID, "stbl0000001", authz.VisibilityTable, users["alice"], tableSecretBody)

	principals := map[string]authz.Principal{
		"dm":        principal(dmID, "dm", "dm"),
		"admin":     principal(users["admin"], "admin", "admin"),
		"author":    principal(users["alice"], "alice", "player"),
		"outsider":  principal(users["bob"], "bob", "player"),
		"anonymous": authz.Anonymous(true),
	}

	// "bearer" occurs only in the dm secret, "ledger" only in the private one,
	// "lantern" only in the table one.
	//
	// The first two are the structural property, and it is stronger than a
	// per-principal filter: a body whose visibility is not `table` is never in
	// secret_fts at all, so no predicate can return it — not even the DM's. The
	// plan's §6.3 calls this "structural, not a filter", and this is the test
	// that says so out loud.
	for name, p := range principals {
		t.Run("hidden_never_indexed/"+name, func(t *testing.T) {
			for _, tc := range []struct{ query, body string }{
				{"bearer", dmSecretBody},
				{"ledger", "A private ledger of debts"},
			} {
				res, err := Query(ctx, db.Reader(), p, tc.query, Options{})
				if err != nil {
					t.Fatal(err)
				}
				if res.Total != 0 || len(res.Hits) != 0 {
					t.Errorf("%s: %q returned total %d and %d hits; a hidden secret body is not in any index",
						name, tc.query, res.Total, len(res.Hits))
				}
				assertNoBodyLeak(t, name, res, tc.body)
			}
		})

		t.Run("table_secret/"+name, func(t *testing.T) {
			res, err := Query(ctx, db.Reader(), p, "lantern", Options{})
			if err != nil {
				t.Fatal(err)
			}
			// §8.2: table is visible to every authenticated user, never anonymous.
			wantTotal := 0
			if p.Authenticated() {
				wantTotal = 1
			}
			if res.Total != wantTotal {
				t.Errorf("%s: total = %d, want %d", name, res.Total, wantTotal)
			}
			if !p.Authenticated() {
				assertNoBodyLeak(t, name, res, tableSecretBody)
			}
		})
	}
}

// assertNoBodyLeak is the tripwire: the body must not appear anywhere in the
// result, including the fields a UI would render and the count.
func assertNoBodyLeak(t *testing.T, who string, res Result, body string) {
	t.Helper()
	for _, h := range res.Hits {
		for field, value := range map[string]string{
			"title": h.Title, "path": h.Path, "snippet": h.Snippet, "secretID": h.SecretID,
		} {
			if value != "" && strings.Contains(value, body) {
				t.Errorf("%s: %s contains the secret body: %q", who, field, value)
			}
		}
	}
	if strings.Contains(res.Query, body) {
		t.Errorf("%s: the executed query contains the body", who)
	}
	// A fragment of the body is enough to be a leak; check the distinctive words.
	for _, word := range []string{"bearer", "brass", "ledger", "debts", "lantern"} {
		if !strings.Contains(body, word) {
			continue
		}
		for _, h := range res.Hits {
			if strings.Contains(strings.ToLower(h.Snippet), word) {
				t.Errorf("%s: a snippet leaks the secret word %q: %q", who, word, h.Snippet)
			}
		}
	}
}

// TestSecretHitCarriesNoSnippet pins the §8.5 decision that snippet() is only
// ever called on page_fts.
func TestSecretHitCarriesNoSnippet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _, users := newVault(t)
	pageID := indexPage(t, db, "Vault.md", "The Sunken Vault", "The vault door is warded.")
	addSecret(t, db, pageID, "stbl0000001", authz.VisibilityTable, users["alice"], tableSecretBody)

	res, err := Query(ctx, db.Reader(), principal(users["bob"], "bob", "player"), "lantern", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Hits) != 1 {
		t.Fatalf("total %d hits %d, want 1", res.Total, len(res.Hits))
	}
	h := res.Hits[0]
	if h.Kind != KindSecret {
		t.Fatalf("kind = %q, want %q", h.Kind, KindSecret)
	}
	if h.SecretID != "stbl0000001" {
		t.Errorf("secret id = %q", h.SecretID)
	}
	if h.Snippet != "" {
		t.Errorf("a secret hit carries a snippet %q; snippet() is only for page_fts", h.Snippet)
	}
	if h.Path != "Vault.md" {
		t.Errorf("path = %q, want the owning page", h.Path)
	}
}

// TestSecretIndexInvariantIsAsserted proves the assertion in Query has teeth, by
// putting a hidden body in the index behind store's back.
func TestSecretIndexInvariantIsAsserted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, dmID, users := newVault(t)
	pageID := indexPage(t, db, "Vault.md", "The Sunken Vault", "The vault door is warded.")
	addSecret(t, db, pageID, "sdm00000001", authz.VisibilityDM, users["alice"], dmSecretBody)

	if _, err := db.Writer().ExecContext(ctx,
		`INSERT INTO secret_text (secret_id, body)
		 SELECT id, ? FROM secrets WHERE visibility = ?
		 ON CONFLICT(secret_id) DO UPDATE SET body = excluded.body`,
		dmSecretBody, string(authz.VisibilityDM)); err != nil {
		t.Fatal(err)
	}
	_, err := Query(ctx, db.Reader(), principal(dmID, "dm", "dm"), "bearer", Options{})
	if !errors.Is(err, ErrSecretIndexInvariant) {
		t.Fatalf("Query returned %v, want ErrSecretIndexInvariant; a hidden body is in the index", err)
	}
}

// TestTokeniseRoundTripsThroughTheRealTokenizer is the property the query
// builder depends on: a token it emits is a token the index also produced.
//
// Asserting this against the real FTS5 tokenizer is the only way to know the
// two tokenisers agree, since SQLite's notion of a token character is its own
// table rather than Go's.
func TestTokeniseRoundTripsThroughTheRealTokenizer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, _, _ := newVault(t)

	for _, text := range []string{
		"Red-Dragon and goblin_scouts patrol the Grüße district",
		"日本語のテキスト with ascii mixed in",
		"a-b-c -- x--y 123 ½ Ⅻ",
		"MiXeD CaSe WoRdS",
		"naïve café über Ångström",
	} {
		indexPage(t, db, text[:min(len(text), 6)]+".md", text[:min(len(text), 6)], text)
		match, err := BuildMatchQuery(text)
		if err != nil {
			t.Fatalf("BuildMatchQuery(%q): %v", text, err)
		}
		if match == "" {
			t.Fatalf("BuildMatchQuery(%q) produced nothing", text)
		}
		var n int
		if err := db.Reader().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, match).Scan(&n); err != nil {
			t.Errorf("the expression for %q does not execute: %v", text, err)
		}
		// The individual tokens must be findable too, which is the real claim:
		// no token BuildMatchQuery emits is a term the index lacks.
		for _, tok := range tokenise(text) {
			var found int
			if err := db.Reader().QueryRowContext(ctx,
				`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, `"`+tok+`"`).Scan(&found); err != nil {
				t.Errorf("token %q of %q does not execute: %v", tok, text, err)
				continue
			}
			if found == 0 {
				t.Errorf("token %q from %q matches no indexed row; the two tokenisers disagree", tok, text)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestFTSSearchInjectionFuzz runs the adversarial corpus deterministically, so
// CI executes it on every run rather than only under -fuzz.
//
// The corpus is the plan's list plus every shape of malformed quoting and
// operator stacking, plus 10k pseudo-random byte strings from a fixed seed so
// the run is reproducible. The invariants are: no panic, a safe expression, and
// an expression SQLite actually accepts.
func TestFTSSearchInjectionFuzz(t *testing.T) {
	t.Parallel()
	corpus := injectionCorpus(10000)

	db, dmID, _ := newVault(t)
	dm := principal(dmID, "dm", "dm")
	ctx := context.Background()
	indexPage(t, db, "Probe.md", "Probe", "a page of ordinary text for the fuzzer to search")

	for i, in := range corpus {
		got, err := BuildMatchQuery(in)
		if err != nil {
			// Only an over-long input may be refused, and it must say so.
			if len(in) > MaxQueryBytes {
				continue
			}
			t.Fatalf("corpus[%d] %q: unexpected error %v", i, in, err)
		}
		assertSafeMatch(t, got)
		if got == "" {
			continue
		}
		// The decisive check: whatever we emit, SQLite parses it as a list of
		// literals. A syntax error here means an operator escaped.
		var n int
		if err := db.Reader().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM page_fts WHERE page_fts MATCH ?`, got).Scan(&n); err != nil {
			t.Fatalf("corpus[%d] %q produced %q, which SQLite rejected: %v", i, in, got, err)
		}
		// And the same through the real entry point, as a player and as a DM.
		for _, p := range []authz.Principal{dm, authz.Anonymous(true)} {
			if _, err := Query(ctx, db.Reader(), p, in, Options{Limit: 5}); err != nil {
				if len(in) > MaxQueryBytes {
					continue
				}
				t.Fatalf("corpus[%d] %q: Query returned %v", i, in, err)
			}
		}
	}
}

// injectionCorpus is the fixed seed list followed by deterministic pseudo-random
// byte strings. The seed is fixed so a failure is reproducible.
func injectionCorpus(random int) []string {
	corpus := []string{
		"NEAR(a b)", "^x", "a*", "a AND b", "a OR b", `"unterminated`, "a:b", "-x", "()",
		"", " ", "\t\n", "*", "^", ":", "-", "+", "(", ")", `"`, "'", ";", "--", "/*",
		"NEAR", "AND", "OR", "NOT", "x:body", "title:x", "a**b", "***", "a OR OR b",
		"a AND (b OR c)", `""`, `"""`, `""""`, `"""""""`, `a" OR "b`, `"a"b"`,
		"DROP TABLE pages", "'; DELETE FROM secrets; --", "1=1", "a OR 1=1",
		"a\x00b", "\x00", "\xff", "\xff\xfe\xfd", "a\u202eb", "a\U0001F600b",
		"日本語", "𝔘𝔫𝔦", "café", "cafe", "½", "Ⅻ", "\u202e", "",
		"-" + strings.Repeat("a", 300), strings.Repeat("-", 64),
		strings.Repeat("a ", 2000), strings.Repeat("\"", 200),
		"a OR " + strings.Repeat("b OR ", 100) + "c",
		"^" + strings.Repeat("x", 100), "NEAR(" + strings.Repeat("a ", 100) + ")",
		"a:" + strings.Repeat("b", 100), "a* OR b*",
		"\x01\x02\x03\x04\x05", "�", "a�b",
	}
	rng := rand.New(rand.NewSource(1750000000))
	alphabet := []byte("abcXYZ019 \t\n\"'*^:(){}[]-+.,;|\\&%$#@!?/=<>~`\x00\x01\xff\xc3\xa9")
	for i := 0; i < random; i++ {
		n := rng.Intn(24) + 1
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		corpus = append(corpus, string(b))
	}
	return corpus
}

// FuzzBuildMatchQuery is the same invariants under -fuzz, for inputs no corpus
// thought of. The seed corpus is the adversarial list.
func FuzzBuildMatchQuery(f *testing.F) {
	for _, seed := range injectionCorpus(0) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := BuildMatchQuery(in)
		if err != nil {
			if len(in) > MaxQueryBytes {
				return
			}
			t.Fatalf("BuildMatchQuery(%q) = %v, want no error", in, err)
		}
		if got == "" {
			return
		}
		if strings.Contains(got, `" "`) {
			t.Errorf("BuildMatchQuery(%q) = %q contains a whitespace-only literal", in, got)
		}
		assertSafeMatch(t, got)
	})
}
