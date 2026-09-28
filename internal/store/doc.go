// Package store owns the SQLite database: opening it, the pragmas, the
// embedded migration series, the typed queries, and the two FTS tables.
//
// It is the bottom of the dependency graph. Every other package may import it;
// it imports nothing of ours.
//
// Two rules that are structural rather than advisory:
//
//   - page_fts holds public content only, and secret_fts holds a secret body
//     only while its visibility is `table`. No code path writes a non-table
//     secret into any index.
//   - Every query that can return a row derived from a secret carries
//     authz.SecretVisibleSQL, and uses the identical predicate for its count.

package store
