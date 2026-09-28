// Package sync owns the indexer and the invalidation bus: Markdown file to SQLite
// in one transaction per changed file, and a publish of PageInvalidated
// afterwards.
//
// The vault is canonical. This package never writes content to the vault; the
// only write path is vault.Writer, and the only way content enters the index is
// by reading a file.

package sync
