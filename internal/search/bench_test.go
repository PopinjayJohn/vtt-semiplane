package search

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// BenchmarkSearch1kPages measures search latency on a 1000-page vault, which is
// the size the plan's U22 note calls out as the risk case for pure-Go SQLite.
//
// It reports a p99 rather than only the mean, because the thing that matters
// for a page render is the tail: a search box is typed into, and a single 200 ms
// response is felt where a 4 ms median is not. The per-iteration timings are
// collected alongside the b.N loop so the percentile is measured on the same
// work the ns/op figure describes.
func BenchmarkSearch1kPages(b *testing.B) {
	benchPages := 1000
	db := benchVault(b, benchPages)
	queries := []string{
		"vault", "gundren", "warded door", "traps pressure", "dnd5e",
		"goblin scouts raid", "necrotic damage", "tiamat baphomet lolth",
		"portrait", "session zero notes",
	}
	dm := authz.ForUser(1, "dm", authz.RoleDM, false)
	ctx := context.Background()

	// Warm the page cache and the statement cache, so the first iteration is not
	// paying for a cold database and the percentile measures search.
	for _, q := range queries {
		if _, err := Query(ctx, db.Reader(), dm, q, Options{Limit: 20}); err != nil {
			b.Fatalf("warm up %q: %v", q, err)
		}
	}

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		start := time.Now()
		res, err := Query(ctx, db.Reader(), dm, q, Options{Limit: 20})
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatalf("query %q: %v", q, err)
		}
		if res.Total == 0 && i < len(queries) {
			b.Fatalf("query %q found nothing in a %d-page vault; the fixture is broken", q, benchPages)
		}
	}
	b.StopTimer()
	reportPercentiles(b, lat)
}

// BenchmarkSearch2kPages is the search half of the P12 budget at the scale the
// budget names: "p99 page render under 50 ms and search under 20 ms on a
// 2000-page vault", out of docs/ADR-0002-pure-go-sqlite.md. The page half is
// measured in internal/httpapi/bench_test.go, through the real router; this is
// the query under the index it reads.
//
// It is the same benchmark as BenchmarkSearch1kPages at twice the corpus, not a
// second kind of measurement: same benchVault, same ten queries, same principal,
// same reporting. The 1k row exists because the plan's U22 note names 1000 pages
// as the risk case for pure-Go SQLite; the 2k row exists because the budget says
// 2000. The ratio between the two rows is the only thing this file claims that
// the 1k row does not, and it is the honest one: the FTS5 tables are external
// content over page_text rather than a copy, so a doubling of the corpus doubles
// the posting lists every MATCH walks.
//
// The two ratios are worth reading together, because they do not agree. The read
// path is roughly linear in corpus size and costs single-digit milliseconds; the
// write path (internal/sync/bench_test.go) is where the pure-Go driver's cost
// actually lands, at a reindex of a few seconds per thousand pages.
func BenchmarkSearch2kPages(b *testing.B) {
	benchPages := 2000
	db := benchVault(b, benchPages)
	queries := []string{
		"vault", "gundren", "warded door", "traps pressure", "dnd5e",
		"goblin scouts raid", "necrotic damage", "tiamat baphomet lolth",
		"portrait", "session zero notes",
	}
	dm := authz.ForUser(1, "dm", authz.RoleDM, false)
	ctx := context.Background()

	for _, q := range queries {
		if _, err := Query(ctx, db.Reader(), dm, q, Options{Limit: 20}); err != nil {
			b.Fatalf("warm up %q: %v", q, err)
		}
	}

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		start := time.Now()
		res, err := Query(ctx, db.Reader(), dm, q, Options{Limit: 20})
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatalf("query %q: %v", q, err)
		}
		if res.Total == 0 && i < len(queries) {
			b.Fatalf("query %q found nothing in a %d-page vault; the fixture is broken", q, benchPages)
		}
	}
	b.StopTimer()
	reportPercentiles(b, lat)
}

// BenchmarkSearch1kPagesSecretMiss is the cost of a term that matches nothing,
// which is what a player typing a secret word they cannot see produces. It must
// be fast and it must be empty.
func BenchmarkSearch1kPagesSecretMiss(b *testing.B) {
	db := benchVault(b, 1000)
	bob := authz.ForUser(2, "bob", authz.RolePlayer, false)
	ctx := context.Background()

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		res, err := Query(ctx, db.Reader(), bob, "brass key", Options{Limit: 20})
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatalf("query: %v", err)
		}
		if res.Total != 0 {
			b.Fatalf("a hidden secret was searchable: %+v", res)
		}
	}
	b.StopTimer()
	reportPercentiles(b, lat)
}

// reportPercentiles adds p50/p95/p99 to the benchmark's own output. Go's testing
// package reports only a mean, and a mean is the wrong statistic for a latency
// budget.
func reportPercentiles(b *testing.B, lat []time.Duration) {
	if len(lat) == 0 {
		return
	}
	sorted := make([]time.Duration, len(lat))
	copy(sorted, lat)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	b.ReportMetric(float64(percentile(sorted, 0.50).Microseconds())/1000, "p50ms")
	b.ReportMetric(float64(percentile(sorted, 0.95).Microseconds())/1000, "p95ms")
	b.ReportMetric(float64(percentile(sorted, 0.99).Microseconds())/1000, "p99ms")
	b.ReportMetric(float64(sorted[len(sorted)-1].Microseconds())/1000, "maxms")
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

// benchVault builds a 1000-page vault with public text indexed, plus one hidden
// secret, and returns a migrated handle. It is deterministic: a benchmark whose
// corpus changes run to run cannot be compared to the run before it.
func benchVault(b *testing.B, pages int) *store.DB {
	b.Helper()
	ctx := context.Background()
	db, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })
	if migrateErr := store.Migrate(ctx, db.Writer(), func(context.Context) error { return nil }); migrateErr != nil {
		b.Fatalf("migrate: %v", migrateErr)
	}

	now := time.Unix(1750000000, 0).UTC()
	ids := make([]int64, 0, 3)
	for _, u := range []struct {
		name, role string
	}{{"dm", "dm"}, {"alice", "player"}, {"bob", "player"}} {
		id, insertUserErr := store.InsertUser(ctx, db.Writer(), store.User{
			Username: u.name, DisplayName: u.name, Role: u.role, PWSalt: []byte("s"),
			CreatedAt: now,
		})
		if insertUserErr != nil {
			b.Fatalf("user: %v", insertUserErr)
		}
		ids = append(ids, id)
	}

	rng := rand.New(rand.NewSource(1750000000))
	words := []string{
		"vault", "door", "warded", "necrotic", "damage", "gundren", "dwarf",
		"goblin", "scouts", "raid", "traps", "pressure", "plate", "darts",
		"tiamat", "baphomet", "lolth", "portrait", "session", "zero", "notes",
		"obsidian", "cloak", "cloakwork", "kobold", "ambush", "bridge", "dnd5e", "ash", "gundren",
	}
	title := func(i int) string {
		return fmt.Sprintf("%s %d", words[rng.Intn(len(words))], i)
	}
	body := func(i int) string {
		var s string
		for j := 0; j < 40; j++ {
			s += words[rng.Intn(len(words))] + " "
		}
		return fmt.Sprintf("%s page %d: %s", title(i), i, s)
	}

	tx, err := db.Writer().BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < pages; i++ {
		path := fmt.Sprintf("Campaigns/Ash/Page-%04d.md", i)
		id, err := store.UpsertPage(ctx, tx, store.Page{
			Path: path, Basename: fmt.Sprintf("Page-%04d", i), Title: title(i),
			ContentHash: []byte(path), MTimeUnix: now.Unix(), SizeBytes: 1024,
			PageType: "note", CreatedAt: now, UpdatedAt: now.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			b.Fatalf("upsert %s: %v", path, err)
		}
		if err := store.ReplacePageText(ctx, tx, store.PageText{
			PageID: id, Title: title(i), Headings: "Traps And Consequences", Body: body(i),
		}); err != nil {
			b.Fatalf("index %s: %v", path, err)
		}
	}
	// One hidden secret, so the secret half of the merge has a table to walk
	// and the miss benchmark has something to miss.
	if err := store.InsertSecret(ctx, tx, store.Secret{
		ID: "sdm00000001", PageID: 1, Ordinal: 0, Visibility: authz.VisibilityDM,
		AuthorID: ids[1], Body: "the brass key opens the Sunken Vault for the bearer alone",
		BodyHash: []byte("h"), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		b.Fatalf("secret: %v", err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return db
}
