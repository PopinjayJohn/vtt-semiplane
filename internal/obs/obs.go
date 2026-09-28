package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// MaxValueBytes is the longest value the redacting handler will emit. Anything
// longer is replaced with a marker recording only its length. A vault sentence
// is longer than this; a page id, path, count, duration or status code is not.
const MaxValueBytes = 256

// Redacted is the replacement for a refused value.
const Redacted = "[redacted]"

// sensitiveMarkers are substrings that make a key's value content rather than
// metadata. Any key containing one of these is refused outright, whatever its
// shape.
var sensitiveMarkers = []string{"content", "body", "snippet", "raw", "passphrase", "password"}

// sensitiveExact are keys that are secrets in their own right.
var sensitiveExact = map[string]bool{
	"secret": true, "token": true, "auth": true, "cookie": true,
	"authorization": true, "private_key": true, "pw_hash": true, "pw_salt": true,
}

// sensitiveSuffixes catch the namespaced variants that are not a substring
// match: a session token is still a session token.
var sensitiveSuffixes = []string{"_token", "_secret", "_password", "_hash", "_salt", "_cookie"}

// isSensitive reports whether a key names a value that must never be logged.
// A secret *id* is not sensitive: it is an opaque handle that appears in a lock
// placeholder, and logging it is how a secret is traced without ever logging
// its body.
func isSensitive(key string) bool {
	k := strings.ToLower(key)
	if sensitiveExact[k] {
		return true
	}
	for _, m := range sensitiveMarkers {
		if strings.Contains(k, m) {
			return true
		}
	}
	for _, s := range sensitiveSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// auditKeys is the allow-list for audit records. An attribute outside this set
// is dropped, because an audit record is a security artefact with a schema, not
// a debugging dump.
var auditKeys = map[string]bool{
	"action": true, "actor": true, "actor_id": true, "target": true,
	"target_id": true, "page_id": true, "page_path": true, "secret_id": true,
	"from_vis": true, "to_vis": true, "result": true, "reason": true,
	"role": true, "path": true, "at": true, "request_id": true,
	"route": true, "method": true, "status": true, "authz_generation": true,
}

// Handler is a slog.Handler that refuses to emit vault content.
//
// It wraps another handler. The wrapped handler decides where records go;
// Handler decides what may go into them.
type Handler struct {
	inner slog.Handler
	attrs []slog.Attr
	group string
	// audit switches the handler into allow-list mode, where an unrecognised
	// attribute key is dropped instead of merely length-checked.
	audit bool
}

// New returns a redacting handler writing to w at the given level.
func New(w io.Writer, level slog.Level) *Handler {
	return &Handler{inner: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})}
}

// NewText returns a redacting handler with human-readable output, for a
// terminal.
func NewText(w io.Writer, level slog.Level) *Handler {
	return &Handler{inner: slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})}
}

// NewAudit returns the allow-list handler used for the audit log. Records
// carrying an attribute outside the allow-list lose that attribute; a record
// with no surviving attribute is still emitted with its message, so the audit
// trail never silently loses the fact that something happened.
func NewAudit(w io.Writer) *Handler {
	return &Handler{
		inner: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}),
		audit: true,
	}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// WithAttrs implements slog.Handler. Attributes are filtered as they are
// attached, not when they are finally written, so a caller cannot smuggle a
// refused value through WithAttrs.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := h.clone()
	for _, a := range attrs {
		if _, v, ok := filter(h.audit, a); ok {
			a.Value = v
			out.attrs = append(out.attrs, a)
		}
	}
	return out
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	out := h.clone()
	if out.group == "" {
		out.group = name
	} else {
		out.group = out.group + "." + name
	}
	return out
}

func (h *Handler) clone() *Handler {
	out := *h
	out.attrs = append([]slog.Attr(nil), h.attrs...)
	return &out
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if _, v, ok := filter(h.audit, a); ok {
			a.Value = v
			out.AddAttrs(a)
		}
		return true
	})
	return h.inner.Handle(ctx, out)
}

// filter decides whether an attribute may be emitted, and returns the value to
// emit in its place.
func filter(audit bool, a slog.Attr) (slog.Attr, slog.Value, bool) {
	key := strings.ToLower(a.Key)
	if audit {
		if !auditKeys[key] {
			return slog.Attr{}, slog.Value{}, false
		}
		return a, truncateValue(key, a.Value), true
	}
	if isSensitive(key) {
		return slog.Attr{}, slog.Value{}, false
	}
	return a, truncateValue(key, a.Value), true
}

// truncateValue refuses a long value, replacing it with a marker that keeps
// the length and nothing else.
func truncateValue(key string, v slog.Value) slog.Value {
	if v.Kind() != slog.KindString {
		return v
	}
	s := v.String()
	if len(s) <= MaxValueBytes {
		return v
	}
	// The id and generation keys are exempt: they are opaque, not content.
	switch key {
	case "id", "page_id", "secret_id", "authz_generation", "request_id":
		return v
	}
	return slog.StringValue(fmt.Sprintf("%s(%d bytes)", Redacted, len(s)))
}

// Logger is the application's logger. It is safe for concurrent use.
type Logger struct {
	*slog.Logger
	audit *slog.Logger
}

// Options configures NewLogger.
type Options struct {
	// Level is the minimum level for the main log.
	Level slog.Level
	// Audit receives audit records. When nil, audit records are dropped.
	Audit io.Writer
	// Text selects human-readable output for the main log.
	Text bool
}

// NewLogger returns the application logger. The two handlers are always
// distinct: audit records are never mixed into the request log, so a bug in
// one cannot expose the other.
func NewLogger(w io.Writer, opts Options) *Logger {
	var main *Handler
	if opts.Text {
		main = NewText(w, opts.Level)
	} else {
		main = New(w, opts.Level)
	}
	l := &Logger{Logger: slog.New(main)}
	if opts.Audit != nil {
		l.audit = slog.New(NewAudit(opts.Audit))
	}
	return l
}

// Audit writes one audit record. The keys are an allow-list, so this method
// cannot become a side channel: an unrecognised key is dropped by the handler.
func (l *Logger) Audit(ctx context.Context, msg string, args ...any) {
	if l.audit == nil {
		return
	}
	l.audit.Log(ctx, slog.LevelInfo, msg, args...)
}

// AuditEnabled reports whether an audit sink is attached, so callers can skip
// building an audit payload when nothing will read it.
func (l *Logger) AuditEnabled() bool { return l.audit != nil }

// Discard returns a logger that drops everything. Tests use it to keep output
// quiet without changing call sites.
func Discard() *Logger {
	return &Logger{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// Level parses a configured log level name.
func Level(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// RequestIDKey is the context key for the per-request correlation id.
type RequestIDKey struct{}

// WithRequestID stores a request id on the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, RequestIDKey{}, id)
}

// RequestID returns the request id, or "" when absent.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// Clock is the injectable time source, so that tests never depend on wall time.
type Clock func() time.Time

// SystemClock is the production clock.
func SystemClock() time.Time { return time.Now() }

// FixedClock returns a clock that always reports t.
func FixedClock(t time.Time) Clock { return func() time.Time { return t } }
