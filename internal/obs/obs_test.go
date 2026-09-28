package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestHandlerRefusesContentAttributes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		attr     slog.Attr
		wantGone bool
	}{
		{"content", slog.String("content", "the vault door is warded"), true},
		{"body", slog.String("body", "the vault door is warded"), true},
		{"snippet", slog.String("snippet", "the vault door is warded"), true},
		{"raw", slog.String("raw", "the vault door is warded"), true},
		{"dotted content", slog.String("page_content", "the vault door is warded"), true},
		{"camel body", slog.String("PageBody", "the vault door is warded"), true},
		{"secret", slog.String("secret", "7f3a91c40d2e"), true},
		{"token", slog.String("session_token", "abc"), true},
		{"path is allowed", slog.String("page_path", "Campaigns/Ash/Gundren.md"), false},
		{"title length is refused, path length is not", slog.String("title", strings.Repeat("x", MaxValueBytes+1)), false},
		{"count is allowed", slog.Int("page_count", 412), false},
		{"opaque ids are never truncated", slog.String("secret_id", strings.Repeat("a", 64)), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			log := slog.New(New(&buf, slog.LevelDebug))
			log.Info("page rendered", tc.attr)

			out := buf.String()
			if strings.Contains(out, "the vault door is warded") {
				t.Fatalf("a secret body reached the log: %s", out)
			}
			if strings.Contains(out, "abc") {
				t.Fatalf("a token reached the log: %s", out)
			}
			if tc.wantGone && strings.Contains(out, tc.attr.Key+"=") {
				t.Fatalf("attribute %q should have been dropped: %s", tc.attr.Key, out)
			}
			if !tc.wantGone && !strings.Contains(out, tc.attr.Key) {
				t.Fatalf("attribute %q should have survived: %s", tc.attr.Key, out)
			}
		})
	}
}

func TestHandlerTruncatesLongValues(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("A", 4096)
	var buf bytes.Buffer
	slog.New(New(&buf, slog.LevelDebug)).Info("synced", slog.String("diff", long))

	out := buf.String()
	if strings.Contains(out, long) {
		t.Fatal("a 4 KiB value was emitted in full")
	}
	if !strings.Contains(out, "4096 bytes") {
		t.Fatalf("the truncation marker should record the length: %s", out)
	}
}

func TestAuditHandlerIsAnAllowList(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := NewLogger(&buf, Options{Level: slog.LevelDebug, Audit: &buf})

	l.Audit(t.Context(), "secret revealed",
		"action", "reveal",
		"secret_id", "7f3a91c40d2e",
		"from_vis", "private",
		"to_vis", "table",
		"actor", "johan",
		// Not on the allow-list: the body of the secret, a value that must
		// never reach an audit record.
		"body", "the vault door is warded",
		"page_body", "the vault door is warded",
	)

	out := buf.String()
	if strings.Contains(out, "the vault door is warded") {
		t.Fatalf("a secret body reached the audit log: %s", out)
	}
	for _, want := range []string{`"action":"reveal"`, `"secret_id":"7f3a91c40d2e"`, `"to_vis":"table"`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit record lost %s: %s", want, out)
		}
	}
}

func TestWithAttrsFiltersAtAttachTime(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := slog.New(New(&buf, slog.LevelDebug)).With(slog.String("body", "the vault door is warded"))
	log.Info("page rendered", slog.String("page_path", "Ash/Gundren.md"))

	if strings.Contains(buf.String(), "the vault door is warded") {
		t.Fatalf("WithAttrs smuggled a value past the filter: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Ash/Gundren.md") {
		t.Fatalf("an allowed attribute was lost: %s", buf.String())
	}
}

func TestDiscardLoggerWritesNothing(t *testing.T) {
	t.Parallel()
	l := Discard()
	if l.AuditEnabled() {
		t.Fatal("Discard must not report an audit sink")
	}
	l.Audit(t.Context(), "nothing happens", "action", "noop")
}

func TestLevelParsing(t *testing.T) {
	t.Parallel()
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"info":     slog.LevelInfo,
		"warn":     slog.LevelWarn,
		"error":    slog.LevelError,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := Level(in); got != want {
			t.Errorf("Level(%q) = %v, want %v", in, got, want)
		}
	}
}
