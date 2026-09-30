// Package search owns FTS5 queries: normalising user input into a safe MATCH
// expression, ranking, snippet rendering, and merging public page hits with
// revealed-secret hits.
//
// A raw user string never reaches the MATCH operator. Results are filtered in
// SQL with authz.SecretVisibleSQL, not in Go, so a bug in post-processing cannot
// widen the result set.
package search
