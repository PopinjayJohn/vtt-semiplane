// Package md is the Markdown and frontmatter pipeline.
//
// It is the one place where a byte range of a vault file becomes classified as
// public or secret (§5.4). Every fact extracted from a document carries the
// md.Span it came from, and therefore a secret_id or the empty string. That
// single classification point is what makes "a secret never enters a derived
// index" implementable rather than aspirational.

package md
