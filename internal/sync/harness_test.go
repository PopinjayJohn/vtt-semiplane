package sync

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/testutil"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// clockNow is the instant every fixture's clock reports. It is a literal so that
// a stored timestamp in an assertion is a constant rather than a formatted now.
var clockNow = time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC)

// harness is an indexer over a temp vault, with the database, the bus and a
// settable clock.
//
// t is a testing.TB rather than a *testing.T so that bench_test.go measures the
// same indexer over the same fixture rather than a second copy of it: a
// benchmark that builds its own harness is one more thing to keep correct and
// one more number nobody can compare against a test.
type harness struct {
	t     testing.TB
	vault *testutil.Vault
	db    *store.DB
	ix    *Indexer
	bus   *Bus
	log   *obs.Logger
	// events collects everything the bus published, in delivery order.
	events chan PageInvalidated
	// nowUnixNano is the clock's value. It is atomic because the indexer reads it
	// from whichever goroutine is doing a pass, and a test that moves the clock
	// between passes must not race with one.
	nowUnixNano atomic.Int64
}

// now reports the harness clock.
func (h *harness) now() time.Time { return time.Unix(0, h.nowUnixNano.Load()).UTC() }

// setClock moves the clock, which is how a test exercises the rename window
// without sleeping through it.
func (h *harness) setClock(at time.Time) { h.nowUnixNano.Store(at.UnixNano()) }

// advance moves the clock forward.
func (h *harness) advance(d time.Duration) { h.setClock(h.now().Add(d)) }

// newHarness opens a migrated index over a temp vault seeded with files and
// three accounts: an admin, a DM and a player.
//
// The accounts exist because a fence directive names its author by username and
// secrets.author_id is a foreign key: a corpus with a secret fence and no users
// would exercise the unknown-author path and nothing else.
//
// A benchmark can call this, and does: the accounts are inserted with a stub
// password hash rather than through auth.Setup, so a 2000-page run spends zero
// argon2id derivations. That is the whole reason this harness is the cheap one
// to reuse — internal/httpapi's costs four full derivations per fixture, which
// at ~140ms each is most of a second before the first iteration runs.
func newHarness(t testing.TB, files map[string]string) *harness {
	t.Helper()
	v := newTBVault(t, files)
	db, err := store.Open(v.Root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	if err := store.Migrate(context.Background(), db.Writer(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := &harness{
		t:      t,
		vault:  v,
		db:     db,
		log:    obs.Discard(),
		events: make(chan PageInvalidated, 256),
	}
	h.nowUnixNano.Store(clockNow.UnixNano())
	h.seedUsers()
	bus := NewBus(h.log)
	bus.Subscribe(func(ev PageInvalidated) { h.events <- ev })
	h.bus = bus
	h.ix = h.newIndexer()
	return h
}

func (h *harness) newIndexer() *Indexer {
	h.t.Helper()
	ix, err := New(Options{
		DB:           h.db,
		Root:         h.vault.Root,
		Bus:          h.bus,
		Log:          h.log,
		Clock:        h.now,
		RenameWindow: DefaultRenameWindow,
	})
	if err != nil {
		h.t.Fatalf("new indexer: %v", err)
	}
	return ix
}

// newTBVault is testutil.WithVault for a testing.TB.
//
// It exists because testutil's own constructors take a *testing.T, and a
// benchmark cannot supply one — which is the only reason the harness could not
// be reused by bench_test.go as written. The behaviour is the same: a temp
// directory, files in sorted order so a page id is a function of the corpus
// rather than of the map's iteration order, 0700 directories and 0600 files, and
// the fixed clock. The Vault's fields are exported precisely so that a caller
// outside testutil can build one; only the writers are not.
func newTBVault(t testing.TB, files map[string]string) *testutil.Vault {
	t.Helper()
	v := &testutil.Vault{
		Root:  t.TempDir(),
		Clock: testutil.FixedClock(2026, 9, 28, 10, 4, 11),
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		abs := filepath.Join(v.Root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(abs, []byte(files[name]), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return v
}

func (h *harness) seedUsers() {
	h.t.Helper()
	h.seedUser("mara", "admin")
	h.seedUser("dorn", "dm")
	h.seedUser("pia", "player")
}

// seedUser adds one more account after the standard three.
func (h *harness) seedUser(name, role string) {
	h.t.Helper()
	if _, err := store.InsertUser(context.Background(), h.db.Writer(), store.User{
		Username:    name,
		DisplayName: name,
		Role:        role,
		PWSalt:      []byte("salt"),
		CreatedAt:   clockNow,
	}); err != nil {
		h.t.Fatalf("seed user %s: %v", name, err)
	}
}

// indexAll walks the vault and indexes everything it finds, then removes what is
// no longer there. It is the boot pass.
func (h *harness) indexAll() BatchResult {
	h.t.Helper()
	ctx := context.Background()
	walk, err := h.ix.Walk(ctx)
	if err != nil {
		h.t.Fatalf("walk: %v", err)
	}
	res, err := h.ix.IndexBatch(ctx, walk.Files)
	if err != nil {
		h.t.Fatalf("index batch: %v", err)
	}
	if _, err := h.ix.RemoveMissing(ctx, walk.Files); err != nil {
		h.t.Fatalf("remove missing: %v", err)
	}
	return res
}

// reconcile runs one reconciliation scan, which is the 60 s pass.
func (h *harness) reconcile() BatchResult {
	h.t.Helper()
	res, err := h.ix.Reconcile(context.Background())
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (h *harness) userID(name string) int64 {
	h.t.Helper()
	u, err := store.GetUserByUsername(context.Background(), h.db.Reader(), name)
	if err != nil {
		h.t.Fatalf("user %s: %v", name, err)
	}
	return u.ID
}

func (h *harness) pageID(path string) int64 {
	h.t.Helper()
	p, err := store.GetPageByPath(context.Background(), h.db.Reader(), path)
	if err != nil {
		h.t.Fatalf("page %s: %v", path, err)
	}
	return p.ID
}

func (h *harness) mustQueryInt(query string, args ...any) int64 {
	h.t.Helper()
	var n int64
	if err := h.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		h.t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func (h *harness) mustQueryString(query string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.db.Reader().QueryRowContext(context.Background(), query, args...).Scan(&s); err != nil {
		h.t.Fatalf("query %q: %v", query, err)
	}
	return s
}

// drainEvents returns everything the bus has published so far.
func (h *harness) drainEvents() []PageInvalidated {
	h.t.Helper()
	var out []PageInvalidated
	for {
		select {
		case ev := <-h.events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// awaitEvent waits for one invalidation, failing the test if none arrives.
func (h *harness) awaitEvent(within time.Duration) PageInvalidated {
	h.t.Helper()
	select {
	case ev := <-h.events:
		return ev
	case <-time.After(within):
		h.t.Fatal("no invalidation was published")
		return PageInvalidated{}
	}
}

// expectNoEvent asserts nothing is published within a window.
func (h *harness) expectNoEvent(within time.Duration) {
	h.t.Helper()
	select {
	case ev := <-h.events:
		h.t.Fatalf("an invalidation was published for %s (%s)", ev.Path, ev.Kind)
	case <-time.After(within):
	}
}

// settle waits for the bus to go quiet after a synchronous pass.
//
// drainEvents is not enough: a pass publishes into the subscription's pending map
// and a worker goroutine delivers it, so a drain that runs first sees nothing and
// the next await collects an event from the pass that already finished.
func (h *harness) settle() []PageInvalidated {
	h.t.Helper()
	return h.awaitQuiet(300*time.Millisecond, 10*time.Second)
}

// awaitQuiet waits until nothing has been published for a window, and returns
// everything it saw on the way. That is how a test knows an asynchronous pass is
// finished rather than merely started.
//
// A pass that created pages may re-point references and publish a second event
// for a page it has already announced, so counting events is not a way to know
// when the pass is over. Silence is.
func (h *harness) awaitQuiet(quiet, overall time.Duration) []PageInvalidated {
	h.t.Helper()
	var seen []PageInvalidated
	deadline := time.After(overall)
	for {
		select {
		case ev := <-h.events:
			seen = append(seen, ev)
		case <-time.After(quiet):
			return seen
		case <-deadline:
			h.t.Fatal("the pass never went quiet")
			return seen
		}
	}
}

// snapshotQueries is one table's contribution to a snapshot. Every one of them is
// keyed by a vault path rather than a row id, so two index states built in a
// different order compare equal when they are equal.
//
// pages.mtime_unix and meta['last_change_at'] are deliberately absent: both hold
// wall-clock filesystem times, and a snapshot is compared across two temp vaults
// in more than one test. TestLastChangeAtIsAdvanced covers the timestamp on its
// own.
var snapshotQueries = []struct{ name, query string }{
	{"page", `SELECT p.path, p.basename, p.title, p.page_type, COALESCE(p.system_id, ''),
		hex(p.content_hash), p.size_bytes, p.frontmatter, p.updated_at FROM pages p`},
	{"owner", `SELECT pg.path, po.user_id, po.is_owner FROM page_owners po
		JOIN pages pg ON pg.id = po.page_id`},
	{"alias", `SELECT pg.path, a.alias FROM page_aliases a JOIN pages pg ON pg.id = a.page_id`},
	{"tag", `SELECT t.name FROM tags t`},
	{"page_tag", `SELECT pg.path, pt.tag, pt.source, pt.secret_id FROM page_tags pt
		JOIN pages pg ON pg.id = pt.page_id`},
	{"link", `SELECT pg.path, COALESCE(tg.path, ''), l.target_raw, l.kind, l.alias, l.heading,
		l.block_ref, COALESCE(l.secret_id, ''), l.line FROM links l
		JOIN pages pg ON pg.id = l.source_page_id
		LEFT JOIN pages tg ON tg.id = l.target_page_id`},
	{"heading", `SELECT pg.path, h.ordinal, h.level, h.slug, h.text, COALESCE(h.secret_id, '')
		FROM headings h JOIN pages pg ON pg.id = h.page_id`},
	{"secret", `SELECT pg.path, s.id, s.ordinal, s.visibility, s.author_id, COALESCE(s.title, ''),
		s.body, hex(s.body_hash), s.created_at FROM secrets s JOIN pages pg ON pg.id = s.page_id`},
	{"revision", `SELECT pg.path, r.source, hex(r.content_hash), length(r.content)
		FROM revisions r JOIN pages pg ON pg.id = r.page_id`},
	{"page_text", `SELECT pg.path, t.title, t.headings, t.body FROM page_text t
		JOIN pages pg ON pg.id = t.page_id`},
	{"secret_text", `SELECT st.secret_id, st.body FROM secret_text st`},
	{"attachment", `SELECT pg.path, a.path, a.mime, a.size_bytes FROM attachments a
		JOIN pages pg ON pg.id = a.page_id`},
	{"page_fts", `SELECT rowid, title, headings, body FROM page_fts`},
	{"secret_fts", `SELECT rowid, body FROM secret_fts`},
}

// snapshot renders every index table deterministically, so two index states can
// be compared exactly rather than by counting rows. A row count cannot tell a
// reindex that rewrote identical values from one that left the index alone, and
// the whole point of the idempotence property is that the second is what happens.
func (h *harness) snapshot() string {
	h.t.Helper()
	var b strings.Builder
	for _, q := range snapshotQueries {
		b.WriteString("== " + q.name + "\n")
		b.WriteString(h.dump(q.query))
		b.WriteString("\n")
	}
	return b.String()
}

func (h *harness) dump(query string) string {
	h.t.Helper()
	rows, err := h.db.Reader().QueryContext(context.Background(), query)
	if err != nil {
		h.t.Fatalf("query %q: %v", query, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		h.t.Fatalf("columns %q: %v", query, err)
	}
	var lines []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			h.t.Fatalf("scan %q: %v", query, err)
		}
		var line strings.Builder
		for i, v := range vals {
			if i > 0 {
				line.WriteByte('|')
			}
			line.WriteString(cols[i])
			line.WriteByte('=')
			line.WriteString(renderValue(v))
		}
		lines = append(lines, line.String())
	}
	if err := rows.Err(); err != nil {
		h.t.Fatalf("rows %q: %v", query, err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func renderValue(v any) string {
	switch value := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return hex.EncodeToString(value)
	case string:
		return value
	case int64:
		return fmt.Sprintf("%d", value)
	case float64:
		return fmt.Sprintf("%v", value)
	case bool:
		return fmt.Sprintf("%t", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}

// ftsHits returns the rowids a MATCH finds in an FTS table. The query is a
// constant with a bind parameter: FTS5's own query syntax is an injection
// surface, so the term never reaches the statement as text.
func (h *harness) ftsHits(table, term string) []int64 {
	h.t.Helper()
	// table is one of two constants named by this file's callers, never a
	// request value.
	rows, err := h.db.Reader().QueryContext(context.Background(),
		`SELECT rowid FROM `+table+` WHERE `+table+` MATCH ?`, term)
	if err != nil {
		h.t.Fatalf("fts match on %s: %v", table, err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			h.t.Fatalf("scan fts rowid: %v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatalf("fts rows: %v", err)
	}
	return out
}

// secretEventRows returns a secret's audit trail.
func (h *harness) secretEventRows(secretID string) []store.SecretEvent {
	h.t.Helper()
	events, err := store.ListSecretEventsBySecret(context.Background(), h.db.Reader(), secretID)
	if err != nil {
		h.t.Fatalf("list events for %s: %v", secretID, err)
	}
	return events
}

var _ = sql.ErrNoRows

// principal builds a principal for a username, or an anonymous one for "".
func (h *harness) principal(name string) authz.Principal {
	h.t.Helper()
	if name == "" {
		return authz.Anonymous(true)
	}
	u, err := store.GetUserByUsername(context.Background(), h.db.Reader(), name)
	if err != nil {
		h.t.Fatalf("user %s: %v", name, err)
	}
	return authz.ForUser(u.ID, u.Username, authz.Role(u.Role), true)
}

// secretFence builds a fence in the on-disk syntax.
func secretFence(id, visibility, author, body string) string {
	return "```secret id=" + id + " visibility=" + visibility +
		" author=" + author + " created=2026-09-28T10:04:11Z\n" + body + "\n```\n"
}

// writer returns a vault.Writer wired to the same self-write store the indexer
// would use, which is what makes a save suppressable.
func (h *harness) writer() *vault.Writer {
	w := vault.NewWriter(h.vault.Root, h.log)
	w.Store = NewSelfwrites(h.db, h.log)
	w.Clock = h.now
	return w
}
