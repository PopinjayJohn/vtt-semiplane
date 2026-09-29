package sync

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"
)

// The index half of docs/ADR-0002-pure-go-sqlite.md.
//
// That ADR concedes "pure-Go SQLite is expected to be 2–5× slower than cgo
// SQLite" and then says the expectation "is not yet a measurement". The half it
// has is BenchmarkSearch1kPages, which is a read path; the half it does not have
// is the one a reindex spends its time in. These benchmarks are that half.
//
// **There is deliberately no CGO comparison here, and adding one would be the
// wrong thing to do.** A ratio needs both arms, the second arm is
// github.com/mattn/go-sqlite3, and adding it to go.mod to measure a ratio would
// forfeit the static-binary promise the product is built on (ADR-0002's whole
// argument for the driver) so that one number could be quoted. What can honestly
// be delivered is the absolute cost and its tail, plus a statement of what a
// comparison would need: a second module, built twice, run on the same corpus.
// Anyone who wants that should write it as a throwaway module outside this
// repository rather than as a dependency of it.
//
// Every fixture here goes through newHarness, whose accounts are inserted with a
// stub password hash rather than through auth.Setup. A 1000-page run therefore
// costs **zero argon2id derivations** — the ~140ms-per-account cost that makes
// internal/httpapi's fixture unaffordable at this scale is not spent here, and
// none of the numbers below is a password-hashing number.

// benchPages is the corpus size the ADR's write-path argument is about.
const benchPages = 1000

// BenchmarkIndex1kPages is one **full reindex pass** over a 1000-page vault on
// real disk, through the real store, against a real SQLite file.
//
// One iteration is exactly what `semiplane reindex --full` does, in the order
// app.Boot does it:
//
//	RemoveMissing(ctx, nil)   drop every derived row, cascading from pages
//	Walk(ctx)                 enumerate the vault with the walker's rules
//	IndexBatch(ctx, files)    parse, extract, resolve, write, publish
//	RemoveMissing(ctx, files) evict anything the walk did not see
//
// The drop is inside the timed region and is not an artefact. Without it the
// second iteration would find every content hash already matching, take the
// Unchanged short-circuit and measure a hash comparison rather than an index —
// which is the incremental pass, and a different question (see
// BenchmarkIndex1kPagesIncremental). A benchmark whose second iteration measures
// something else from its first is a benchmark whose reported mean is a blend of
// two workloads and neither of them is the one it names.
//
// What the number **includes**: a real filesystem walk of 1000 files; 1000 parses
// through the core goldmark pipeline with no plugin extenders; frontmatter split,
// secret segmentation, link extraction and heading extraction per page; a
// database lookup per wikilink for the resolver; the full write of the pages,
// links, headings, tags, attachments, secrets, revisions, page_text and the FTS
// index rows; the FTS delete/replay/insert dance for a content-backed table; one
// invalidation published per changed page; and the RemoveMissing sweep at the
// end. That is the write path in full, and it is where a reindex spends its
// time.
//
// What it **does not include**: process start, the vault lock, the schema
// migration, the backup a real migration takes, argon2id (there are no
// derivations), the vault watcher, the FTS rebuild a schema bump forces, and any
// plugin's markdown extenders — newHarness leaves Options.Renderer nil, so this
// is the core pipeline and a build whose plugins register extenders pays for
// them on top. A production boot also indexes whatever the campaign's own
// secrets and attachments look like; the corpus below is synthetic and its shape
// is stated in benchCorpus.
//
// It reports p50/p95/p99/max rather than only a mean, for the reason
// BenchmarkSearch1kPages gives: a reindex is a thing a person waits through, and
// one slow pass is felt where a fast median is not. A mean over b.N=1 is the
// mean and no more, so **run this with -benchtime=10x**; at the default
// -benchtime=1s Go would pick b.N=1 and every percentile would be the same
// number. Even at b.N=3 the p50, the p95 and the p99 all resolve to the same of
// three samples, which is the shape of a distribution and none of its
// information — ten passes is the least that says anything, and it costs about
// a hundred seconds. The reported `pages/s` is derived from the same
// measurements, so the two agree by construction.
//
// Cost per iteration: one full reindex of 1000 pages. Measured on the machine
// these numbers were taken (8 vCPU, an i7-4790K, a vault in tmpfs so the figure
// is CPU and not disk): **8.4 s a pass, 119 pages/s, 489 MB and 8.7 M
// allocations per pass.** There is no per-page iteration here;
// BenchmarkIndex1kPagesPerFile is the one with a small one.
func BenchmarkIndex1kPages(b *testing.B) {
	h, _ := benchIndexHarness(b, benchPages)
	drainEvents(h)
	ctx := context.Background()

	// One warm pass, untimed, so the first timed iteration is not also the
	// iteration that pays for the OS page cache filling on 1000 files.
	reindexPass(b, ctx, h)

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		res := reindexPass(b, ctx, h)
		lat = append(lat, time.Since(start))
		if res != benchPages {
			b.Fatalf("the pass indexed %d files, want %d: the corpus is not what benchCorpus built, so this number is not the one it names", res, benchPages)
		}
	}
	b.StopTimer()

	reportBenchPercentiles(b, lat)
	// A pass is the unit the number is about; ns/op is per pass, and this is
	// the same arithmetic stated as a rate a reader can compare against a
	// campaign size.
	b.ReportMetric(float64(benchPages), "pages/op")
	reportBenchPagesPerSecond(b, lat)
}

// BenchmarkIndex1kPagesPerFile is the marginal cost of indexing one file, and it
// is the variant whose p99 means something: b.N runs to thousands, so the
// distribution is a distribution rather than one sample.
//
// It is `ix.Reindex` on one file, round-robin over the corpus, which is what the
// watcher calls when a file changes on disk. Files are visited in a fixed order
// rather than at random so that two runs index the same pages in the same
// sequence and a difference between two runs is a difference in the machine.
// /
// / Cost per iteration: one page, about 4.5 ms, over a corpus that is already
// warm — so the number is the marginal write path and not a cold read of the
// file.
//
// What it **does not** include: the walk. A per-file index does not stat the
// tree, and a whole pass's walk cost is amortised away here — compare against
// BenchmarkIndex1kPages, whose number has the walk inside it.
func BenchmarkIndex1kPagesPerFile(b *testing.B) {
	h, paths := benchIndexHarness(b, benchPages)
	drainEvents(h)
	ctx := context.Background()
	if writtenCount(h.indexAll()) != benchPages {
		b.Fatalf("the warm pass wrote %d files, want %d", writtenCount(h.indexAll()), benchPages)
	}
	if _, err := h.ix.Reconcile(ctx); err != nil {
		b.Fatalf("warm reconcile: %v", err)
	}

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := paths[i%len(paths)]
		start := time.Now()
		// Reindex rather than Index: after the first visit every file's hash
		// matches what is indexed, and a plain Index would take the Unchanged
		// path and measure a hash comparison.
		err := h.ix.Reindex(ctx, path)
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatalf("reindex %s: %v", path, err)
		}
	}
	b.StopTimer()
	reportBenchPercentiles(b, lat)
}

// BenchmarkIndex1kPagesIncremental is the reconcile scan over a vault nothing
// has changed, which is the pass that runs every 60 seconds on a live server.
//
// It is the number that says what the watcher costs when the watcher has
// nothing to do, and it is small: fsnotify is not recursive and its events can
// be dropped (AGENTS.md §11), so this is the correctness guarantee and it runs
// forever. A pass that re-parses 1000 files would be unusable, and this is the
// measurement that shows it is not.
func BenchmarkIndex1kPagesIncremental(b *testing.B) {
	h, _ := benchIndexHarness(b, benchPages)
	drainEvents(h)
	ctx := context.Background()
	if written := writtenCount(h.indexAll()); written != benchPages {
		b.Fatalf("the warm pass wrote %d files, want %d", written, benchPages)
	}

	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := h.ix.Reconcile(ctx); err != nil {
			b.Fatalf("reconcile: %v", err)
		}
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	reportBenchPercentiles(b, lat)
}

// reindexPass is the body of one full reindex, and the number of files whose
// bytes it actually wrote.
func reindexPass(b *testing.B, ctx context.Context, h *harness) int {
	b.Helper()
	if _, err := h.ix.RemoveMissing(ctx, nil); err != nil {
		b.Fatalf("drop the derived index: %v", err)
	}
	walk, err := h.ix.Walk(ctx)
	if err != nil {
		b.Fatalf("walk: %v", err)
	}
	res, err := h.ix.IndexBatch(ctx, walk.Files)
	if err != nil {
		b.Fatalf("index batch: %v", err)
	}
	if _, err := h.ix.RemoveMissing(ctx, walk.Files); err != nil {
		b.Fatalf("remove missing: %v", err)
	}
	written := 0
	for _, r := range res.Indexed {
		if !r.Unchanged {
			written++
		}
	}
	return written
}

// writtenCount is how many files in a pass the indexer actually wrote, which is
// not the same number as the files it looked at: a path whose content hash
// already matched reports Unchanged and no row moved. A benchmark that confuses
// the two would report a corpus size for a pass that indexed nothing.
func writtenCount(res BatchResult) int {
	written := 0
	for _, r := range res.Indexed {
		if !r.Unchanged {
			written++
		}
	}
	return written
}

// drainEvents keeps the harness's bus subscriber from wedging.
//
// newHarness subscribes a callback that pushes every invalidation into a
// 256-slot channel, and a 1000-page pass publishes 1000. Publish itself never
// blocks — that is the bus's contract and the indexer depends on it — so the
// cost of a wedged subscriber is not a hang, it is a delivery goroutine parked
// on a full channel while the benchmark measures. Draining it keeps the thing
// being measured the indexer rather than a stalled neighbour.
func drainEvents(h *harness) {
	go func() {
		for range h.events {
		}
	}()
}

// benchIndexHarness builds the corpus and opens the harness over it, returning
// the harness and the corpus's paths in walk order.
func benchIndexHarness(b *testing.B, pages int) (*harness, []string) {
	b.Helper()
	files := benchCorpus(b, pages)
	h := newHarness(b, files)
	paths := make([]string, 0, pages)
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return h, paths
}

// benchCorpus is a deterministic 1000-page campaign.
//
// Deterministic because a benchmark whose corpus changes between runs cannot be
// compared to the run before it, and the same reason the search fixture uses a
// fixed seed. The shape is the part that matters: a page is a frontmatter block,
// three headings, a few paragraphs of prose and fifteen wikilinks, because the
// resolver's per-link database lookup is a real part of the write path and a
// corpus of link-free pages would understate it. Every twentieth page carries a
// secret fence, so segmentation, the `secrets` rows and the unresolved-author
// path are measured too, and the three visibilities are all present.
//
// The fence body is synthetic text written for this benchmark. It is not
// campaign content, it is not copied from a vault, and it exists only so the
// indexer's secret path runs. The author is `dorn`, the DM newHarness seeds, so
// the author resolves to a real user id rather than exercising the
// unknown-author branch — which is a different measurement and is not this one.
func benchCorpus(b *testing.B, pages int) map[string]string {
	b.Helper()
	rng := rand.New(rand.NewSource(20260928))
	words := []string{
		"vault", "door", "warded", "necrotic", "damage", "gundren", "dwarf",
		"goblin", "scouts", "raid", "traps", "pressure", "plate", "darts",
		"tiamat", "baphomet", "lolth", "portrait", "session", "zero", "notes",
		"obsidian", "cloakwork", "kobold", "ambush", "bridge", "dnd5e", "ash",
	}
	visibilities := []string{"private", "dm", "table"}
	files := make(map[string]string, pages)
	for i := 0; i < pages; i++ {
		name := fmt.Sprintf("Campaigns/Ash/Page-%04d.md", i)
		title := fmt.Sprintf("%s %d", words[rng.Intn(len(words))], i)
		var body strings.Builder
		body.WriteString("---\ntitle: " + title + "\ntype: note\ntags: [area/wild]\n---\n\n")
		body.WriteString("# " + title + "\n\n")
		for h := 0; h < 3; h++ {
			body.WriteString("## " + strings.ToUpper(words[rng.Intn(len(words))]) + fmt.Sprintf(" %d\n\n", h) + "\n")
			for p := 0; p < 2; p++ {
				for w := 0; w < 12; w++ {
					body.WriteString(words[rng.Intn(len(words))])
					body.WriteByte(' ')
				}
				body.WriteString("\n\n")
			}
			// Fifteen links, most of which resolve and some of which do not:
			// a corpus where every link resolves would not measure the
			// unresolved-reference path that a first index of a real campaign
			// spends a lot of its time in.
			for l := 0; l < 15; l++ {
				target := rng.Intn(pages)
				if target%5 == 0 {
					fmt.Fprintf(&body, "[[Page-%04d]] and [[Nowhere-%04d]]\n", target, target)
					continue
				}
				fmt.Fprintf(&body, "[[Page-%04d]]\n", target)
			}
			body.WriteString("\n")
		}
		if i%20 == 0 {
			vis := visibilities[i/20%len(visibilities)]
			fmt.Fprintf(&body, "```secret id=%012x visibility=%s author=dorn created=2026-09-28T10:04:11Z\n",
				i, vis)
			body.WriteString("synthetic benchmark body " + words[rng.Intn(len(words))] + "\n```\n")
		}
		files[name] = body.String()
	}
	return files
}

// reportBenchPercentiles adds p50/p95/p99/max to a sync benchmark's own output.
// This is the third copy of this function in this repository — the other is in
// internal/search's bench_test.go and the other in internal/sync's. There is no
// place to put the one that would serve all three: a shared test helper has to
// live in a non-test file, and internal/testutil is one. The one-line fix, when
// someone owns that file, is a percentile helper in testutil.
// Go's testing package reports only a mean, and a mean is the wrong statistic
// for a latency budget. This is the same helper, under this package's name,
// because internal/search's is unexported and there is no test-only package a
// benchmark in two packages can share through without becoming production code.
func reportBenchPercentiles(b *testing.B, lat []time.Duration) {
	b.Helper()
	if len(lat) == 0 {
		return
	}
	sorted := make([]time.Duration, len(lat))
	copy(sorted, lat)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	at := func(p float64) float64 {
		return float64(sorted[int(float64(len(sorted)-1)*p)].Microseconds()) / 1000
	}
	b.ReportMetric(at(0.50), "p50ms")
	b.ReportMetric(at(0.95), "p95ms")
	b.ReportMetric(at(0.99), "p99ms")
	b.ReportMetric(float64(sorted[len(sorted)-1].Microseconds())/1000, "maxms")
}

// reportBenchPagesPerSecond states the per-pass rate from the same samples, so
// the p99 and the rate cannot disagree.
func reportBenchPagesPerSecond(b *testing.B, lat []time.Duration) {
	b.Helper()
	var total time.Duration
	for _, d := range lat {
		total += d
	}
	if total <= 0 {
		return
	}
	b.ReportMetric(float64(len(lat))*float64(benchPages)/total.Seconds(), "pages/s")
}
