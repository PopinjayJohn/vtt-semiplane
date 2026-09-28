// Package secrets owns the on-disk secret fence syntax, secret state, and the
// redactor that decides what a given principal may read.
//
// It depends on authz and never the other way round, so that a redactor can
// consult authz.CanReadSecret without a cycle. The canonical SQL predicate for
// a secret is authz.SecretVisibleSQL and is used verbatim for every query,
// including counts.
//
// Secrets are plaintext on disk (D4, ADR-0004). The protection is filesystem
// permissions plus server-side authorization, not encryption. See docs.

package secrets
