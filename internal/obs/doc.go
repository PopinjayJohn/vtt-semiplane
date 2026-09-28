// Package obs is the observability boundary: a slog wrapper that cannot log
// vault content, a redacting handler, request logging, and the append-only
// audit log.
//
// The redaction is not advisory. A handler refuses to emit a value whose key is
// content, body, snippet or raw, or whose value is longer than MaxValueBytes, so
// a future contributor cannot leak a secret by adding a log line. The audit
// log is a separate handler with an allow-list of keys, because an audit entry
// is a security record and must be structured and free-form values must not
// reach it.

package obs
