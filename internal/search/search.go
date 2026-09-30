package search

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
)

// Queryer is the read surface Query needs. Pass db.Reader(): every search
// statement is a read, and routing it through the writer pool would put a page
// view behind a reindex.
//
// Declared here rather than imported from store so this package can be driven
// by a stub in a test, and so nothing in it forces a connection-pool decision on
// a caller.
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Kind labels a hit so a caller can render it distinctly. It is part of the
// result rather than a presentation detail, because "this is a revealed secret"
// and "this is a page" are different trust levels and the UI must not blur them.
type Kind string

const (
	// KindPage is a hit in a page's public content.
	KindPage Kind = "page"
	// KindSecret is a hit in a revealed, table-visible secret. A secret hit
	// never carries a snippet: see Query.
	KindSecret Kind = "secret"
)

// Defaults and bounds for Options.
const (
	// DefaultLimit is the page size when Options.Limit is unset.
	DefaultLimit = 20
	// MaxLimit is the hard ceiling. A search response is a page render, and a
	// page render has a size; an unbounded LIMIT is an unbounded allocation.
	MaxLimit = 200
)

// Options controls one Query.
type Options struct {
	// Limit is the number of hits to return. Zero means DefaultLimit, and
	// anything above MaxLimit is clamped to it.
	Limit int
	// Offset is how many hits to skip, for paging.
	Offset int
}

func (o Options) limit() int {
	switch {
	case o.Limit <= 0:
		return DefaultLimit
	case o.Limit > MaxLimit:
		return MaxLimit
	default:
		return o.Limit
	}
}

// Hit is one result row.
type Hit struct {
	// Kind is page or secret.
	Kind Kind
	// Title is the display title. For a secret hit it is the owning page's
	// title, because the secret's own title is optional and a secret's identity
	// is not something a list needs to expose.
	Title string
	// Path is the owning page's vault-relative path.
	Path string
	// PageID is the owning page.
	PageID int64
	// SecretID is the matching secret, for a secret hit, and empty otherwise.
	SecretID string
	// Snippet is the matching excerpt for a page hit, HTML-escaped, and always
	// empty for a secret hit.
	Snippet string
	// Score is the bm25 rank. Lower is better, which is bm25's own convention;
	// it is not normalised, because the two sources are ranked separately and
	// merged in fixed source order.
	Score float64
	// UpdatedAt is the owning page's last index time.
	UpdatedAt time.Time
}

// Href is where the hit navigates to.
func (h Hit) Href() string { return "/p/" + h.Path }

// Result is the merged, ordered result set of one query.
type Result struct {
	// Hits are the rows for the requested window, pages before secrets.
	Hits []Hit
	// Total is how many hits exist across both sources, ignoring the window. It
	// is the sum of two separately filtered counts, so it can never disagree
	// with the rows a further page would return.
	Total int
	// Query is the MATCH expression that was executed. It is returned so a test
	// can assert on the normalisation, and so an operator reading a bug report
	// can see what the user's keystrokes became.
	Query string
}

// The page-hit statement and the page-count statement are the same FROM and
// WHERE, assembled from one constant. §6.4's rule that a list and its count
// must not diverge is only enforceable if there is nothing to diverge: there is
// no second copy of the predicate, the join, or the filter to fall out of step.
const pageFTSFrom = `FROM page_fts
JOIN pages p ON p.id = page_fts.rowid
WHERE page_fts MATCH ?`

// snippetTextTokens is how many tokens of context snippet() keeps on each side
// of a match, and SnippetMaxChars caps the result so one enormous paragraph
// cannot become the response.
const (
	snippetTextTokens = 12
	SnippetMaxChars   = 400
)

const pageHitsSQL = `SELECT p.id, p.title, p.path, p.updated_at,
	snippet(page_fts, 2, '', '', ' … ', ?),
	bm25(page_fts, 10.0, 5.0, 1.0)
` + pageFTSFrom + `
ORDER BY rank, p.updated_at DESC
LIMIT ? OFFSET ?`

const pageCountSQL = `SELECT COUNT(*) ` + pageFTSFrom

// The secret-hit statement joins secret_text (for the rowid) and secrets (for
// the row the predicate filters), and carries the canonical predicate: a
// revealed secret is a secret-derived row and gets exactly the treatment every
// other such row gets.
const secretFTSFrom = `FROM secret_fts
JOIN secret_text st ON st.fts_rowid = secret_fts.rowid
JOIN secrets s ON s.id = st.secret_id
JOIN pages p ON p.id = s.page_id
WHERE secret_fts MATCH ?`

const secretHitsSQL = `SELECT s.id, p.id, p.title, p.path, p.updated_at,
	bm25(secret_fts, 1.0)
` + secretFTSFrom + ` AND ` + authz.SecretVisibleSQL + `
ORDER BY rank, p.updated_at DESC
LIMIT ? OFFSET ?`

const secretCountSQL = `SELECT COUNT(*) ` + secretFTSFrom + ` AND ` + authz.SecretVisibleSQL

// secretIndexInvariantSQL asserts the structural property §6.3 relies on: a
// secret body is in the search index only while its visibility is table.
//
// It is an assertion, not a filter. Nothing is removed from the result set
// because of it — a row that violated the invariant would be a bug, and hiding
// the bug behind a working query would leave the leak in place. The visibility
// value is bound from authz.VisibilityTable rather than written as a literal, so
// it cannot drift from the constant the read path uses, and no principal is
// involved: this runs at query time against the index, not against a user.
const secretIndexInvariantSQL = `SELECT COUNT(*)
FROM secret_text st
JOIN secrets s ON s.id = st.secret_id
WHERE NOT (s.visibility = ?)`

// ErrSecretIndexInvariant reports a secret body in the search index that should
// not be there. It is an error rather than a filtered-out row because the only
// two possible causes are a write-side bug and a corrupted database, and both
// deserve to stop the request.
var ErrSecretIndexInvariant = errors.New("search: a hidden secret is present in the search index")

// Query runs a search for a principal.
//
// The two sources are queried separately and merged here, each already filtered
// in SQL:
//
//   - page_fts holds public content only, so a page hit needs no secret
//     predicate. Whether the principal may read public content at all is
//     decided before any statement runs, and an anonymous principal with
//     anonymous read disabled gets nothing without touching the database.
//   - secret_fts holds a body only while that secret is table-visible, and the
//     statement carries authz.SecretVisibleSQL anyway, because a table secret is
//     still subject to the authenticated-user rule in §8.2.
//
// The merge is pages-then-secrets rather than a global sort. The two bm25
// scores are not comparable — one is a three-column weighted score and the
// other a single-column one — so interleaving them by number would be a claim
// about relevance that the ranking does not support.
//
// A secret hit carries no snippet. §8.5 says snippet() is only ever called on
// page_fts, and any excerpt of a secret body risks carrying text the author did
// not intend to publish even when the body itself is revealed. The hit names
// the page, and the page is where the reader goes.
func Query(ctx context.Context, db Queryer, p authz.Principal, q string, opts Options) (Result, error) {
	if !p.CanReadPublic() {
		return Result{}, nil
	}
	match, err := BuildMatchQuery(q)
	if err != nil {
		return Result{}, err
	}
	if match == "" {
		return Result{}, nil
	}
	limit, offset := opts.limit(), opts.Offset
	if offset < 0 {
		offset = 0
	}

	if assertSecretIndexInvariantErr := assertSecretIndexInvariant(ctx, db); assertSecretIndexInvariantErr != nil {
		return Result{}, assertSecretIndexInvariantErr
	}

	pageHits, err := queryPageHits(ctx, db, match, limit, offset)
	if err != nil {
		return Result{}, err
	}
	pageTotal, err := queryPageTotal(ctx, db, match)
	if err != nil {
		return Result{}, err
	}

	// §8.2's bottom row: an unauthenticated request sees no secret, under any
	// visibility, so the two secret statements are not merely filtered for it —
	// they are never sent. The canonical predicate cannot enforce this on its
	// own; its table-visibility clause has no authentication guard, while
	// authz.CanReadSecret requires an authenticated principal for the same
	// visibility. The check is on the principal, not on a visibility value, so
	// it can only remove rows.
	var secretHits []Hit
	var secretTotal int
	if p.Authenticated() {
		secretHits, err = querySecretHits(ctx, db, p, match, limit, offset)
		if err != nil {
			return Result{}, err
		}
		secretTotal, err = querySecretTotal(ctx, db, p, match)
		if err != nil {
			return Result{}, err
		}
	}

	hits := make([]Hit, 0, len(pageHits)+len(secretHits))
	hits = append(hits, pageHits...)
	hits = append(hits, secretHits...)
	return Result{Hits: hits, Total: pageTotal + secretTotal, Query: match}, nil
}

func assertSecretIndexInvariant(ctx context.Context, db Queryer) error {
	var n int64
	if err := db.QueryRowContext(ctx, secretIndexInvariantSQL, string(authz.VisibilityTable)).Scan(&n); err != nil {
		return fmt.Errorf("search: check secret index invariant: %w", err)
	}
	if n != 0 {
		return fmt.Errorf("%w: %d row(s)", ErrSecretIndexInvariant, n)
	}
	return nil
}

func queryPageHits(ctx context.Context, db Queryer, match string, limit, offset int) ([]Hit, error) {
	rows, err := db.QueryContext(ctx, pageHitsSQL,
		snippetTextTokens, match, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search: page query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Hit
	for rows.Next() {
		var (
			h         Hit
			updatedAt string
			snippet   string
		)
		if scanErr := rows.Scan(&h.PageID, &h.Title, &h.Path, &updatedAt, &snippet, &h.Score); scanErr != nil {
			return nil, fmt.Errorf("search: scan page hit: %w", scanErr)
		}
		if h.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
			return nil, fmt.Errorf("search: page %d updated_at: %w", h.PageID, err)
		}
		h.Kind = KindPage
		// The snippet is vault text on its way to HTML. Escaping it here rather
		// than at the render site means there is one place that can get it
		// wrong, and it is this.
		h.Snippet = escapeSnippet(snippet)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search: iterate page hits: %w", err)
	}
	return out, nil
}

func queryPageTotal(ctx context.Context, db Queryer, match string) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx, pageCountSQL, match).Scan(&n); err != nil {
		return 0, fmt.Errorf("search: count page hits: %w", err)
	}
	return n, nil
}

func querySecretHits(ctx context.Context, db Queryer, p authz.Principal, match string, limit, offset int) ([]Hit, error) {
	uid, isDM := p.Bind()
	rows, err := db.QueryContext(ctx, secretHitsSQL, match,
		sql.Named("uid", uid), sql.Named("is_dm", isDM), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search: secret query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Hit
	for rows.Next() {
		var (
			h         Hit
			secretID  string
			updatedAt string
		)
		if scanErr := rows.Scan(&secretID, &h.PageID, &h.Title, &h.Path, &updatedAt, &h.Score); scanErr != nil {
			return nil, fmt.Errorf("search: scan secret hit: %w", scanErr)
		}
		if h.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
			return nil, fmt.Errorf("search: secret %s updated_at: %w", secretID, err)
		}
		h.Kind = KindSecret
		h.SecretID = secretID
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search: iterate secret hits: %w", err)
	}
	return out, nil
}

func querySecretTotal(ctx context.Context, db Queryer, p authz.Principal, match string) (int, error) {
	uid, isDM := p.Bind()
	var n int
	if err := db.QueryRowContext(ctx, secretCountSQL, match,
		sql.Named("uid", uid), sql.Named("is_dm", isDM)).Scan(&n); err != nil {
		return 0, fmt.Errorf("search: count secret hits: %w", err)
	}
	return n, nil
}

// escapeSnippet makes a snippet safe to put inside an element's text content.
//
// html.EscapeString is not redundant here even though the snippet is fetched as
// a plain string: it is assembled from vault text, vault text may contain
// anything an author pasted, and the render site is templ, where the safe
// default is escaping but the first thing a future contributor does when they
// want the match highlighted is to stop escaping. Escaping at the boundary makes
// that mistake harmless. Truncation is by rune so a cut cannot land mid-rune
// and produce invalid UTF-8 in the response.
func escapeSnippet(s string) string {
	s = html.EscapeString(s)
	if len(s) <= SnippetMaxChars {
		return s
	}
	cut := SnippetMaxChars
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + "…"
}

// isRuneStart reports whether b can begin a UTF-8 sequence.
func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
