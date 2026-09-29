package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// The P12 latency budget, measured.
//
// docs/ADR-0002-pure-go-sqlite.md states the budget: "p99 page render under
// 50 ms and search under 20 ms on a 2000-page vault", and records that nothing
// put a number on the page half of it. internal/search/bench_test.go answers the
// search half. This file answers the page half, at the same 2000-page scale.
//
// **Why the real router and not the handler.** A page render is three costs: the
// router and its middleware chain, the templ render, and the SQL under both. A
// benchmark that called `s.page` directly would measure the second and third and
// call the result a page render. Every iteration here is an HTTP GET over a
// loopback socket to the whole chain the product mounts — Recoverer, RequestID,
// requestLogger, secureHeaders, session, rateLimit, the per-route CSRF and Perm
// gates, the catch-all dispatcher, the handler, the render and the response —
// which is the only way the number means what "page render" means.
//
// **No account helper is called anywhere in this file.** `onePlayer`, `accounts`
// and `accountsFor` each spend full-cost argon2id derivations, and at ~140 ms a
// derivation a four-account fixture is most of a second of pure setup. The DM
// below is inserted with `store.InsertUser` and a stub password hash, and its
// session is a `store.InsertSession` row addressed by a token this benchmark
// generated — so a signed-in render costs zero derivations. A benchmark that
// spent 500 ms of argon2 per iteration would be measuring argon2.
//
// **No pass/fail threshold.** A latency gate written from a number measured on
// one machine is a gate that fails on a busier one and proves nothing on a
// quieter one; it would be reporting a machine's load as a regression. These
// report and do not assert, and the budget stays a number a reader compares by
// hand. That is a deliberate choice, not an unfinished one.

// benchPages2k is the corpus size the budget names.
const benchPages2k = 2000

// BenchmarkPageRender2kPages is `GET /p/…` on a 2000-page vault, as a DM.
//
// The DM is the principal worth measuring: a page render for a DM resolves each
// secret fence on the page, runs authz.CanReadSecret per fence, decides which
// bodies enter the HTML, and builds the campaign-status panel with the
// field-level authorization that panel needs. An anonymous render is strictly
// cheaper and BenchmarkPageRender2kPagesAnonymous is that number; quoting the
// cheaper one as the page-render budget would be quoting the easiest case.
//
// It reports p50/p95/p99/max rather than a mean, because a page is something a
// person waits for and one slow render is felt where a fast median is not —
// which is exactly why the budget is stated as a p99. Go's testing package
// reports a mean and nothing else.
func BenchmarkPageRender2kPages(b *testing.B) {
	fx, pages := benchPageFixture(b)

	// The DM's own client carries the session cookie and nothing else. It is a
	// plain http.Client rather than the harness's *session because that one
	// re-reads a CSRF token out of every response body: a browser reads the
	// token off a form once, not on every navigation, and leaving that in would
	// put a regexp over a whole page of HTML into every iteration.
	benchPageLoop(b, benchClient(fx, benchDMSession(b, fx)), pages)
}

// BenchmarkPageRender2kPagesAnonymous is the same page as an unauthenticated
// reader with --allow-anonymous-read on.
//
// It is a lower bound on the same work and it is the shape a public campaign
// actually serves: every fence on the page is refused, so the render carries
// placeholders rather than bodies. It is a separate benchmark rather than a
// sub-benchmark because it needs the fixture built with anonymous read on, and
// a fixture is a 2000-page index.
func BenchmarkPageRender2kPagesAnonymous(b *testing.B) {
	fx, pages := benchPageFixture(b)
	benchPageLoop(b, benchClient(fx, ""), pages)
}

// benchPageLoop drives one GET per iteration over a rotating set of pages and
// reports the distribution.
//
// The rotation is the whole reason this is not a single-page loop: a browser
// reads many pages, and hammering one would keep one page row, one file and one
// FTS-adjacent structure hot in the cache, which is a number about a hot row
// rather than about a 2000-page vault.
//
// The response is read and closed every iteration. Not doing so would leave the
// connection unread and the timing would measure a head of the render rather
// than all of it.
func benchPageLoop(b *testing.B, client *http.Client, pages []string) {
	b.Helper()
	if len(pages) == 0 {
		b.Fatalf("the corpus has no pages, so this is not a benchmark of a page render")
	}
	lat := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		page := pages[i%len(pages)]
		start := time.Now()
		resp, err := client.Get(page)
		if err != nil {
			b.Fatalf("GET %s: %v", page, err)
		}
		// A body is read for its bytes and for the connection: a response whose
		// body is not drained is a connection the client cannot reuse, and a
		// benchmark that opened a new TCP connection per iteration would be
		// measuring the loopback stack.
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatalf("read %s: %v", page, err)
		}
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("GET %s: status %d, want 200", page, resp.StatusCode)
		}
		if n < 512 {
			b.Fatalf("GET %s: %d bytes, which is not a page: the fixture is not serving the corpus", page, n)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(pages)), "pages")
	b.ReportMetric(float64(len(lat)), "samples")
	reportBenchPercentiles(b, lat)
}

// benchPageFixture boots the whole application over a 2000-page vault and
// returns it with the corpus's page paths, already URL-escaped.
//
// Two flags are set on the configuration and both are load-bearing, so they are
// named here rather than left as a mutate in the caller's argument list:
//
//   - AllowAnonymousRead, because with it off an unauthenticated GET /p/… is
//     answered 303 to the login form, and a benchmark measuring a redirect
//     while calling it a page render is worse than no benchmark. It changes
//     nothing for the DM, who is authenticated either way.
//   - Dev, because the general rate-limit budget is 300 requests a minute per
//     address (config.RateSessionPerMinute) and the fixture's clock is frozen,
//     so a bucket with no refill drains after 300 iterations and every
//     iteration past that measures a 429. Dev is the operator's documented switch
//     for exactly this ("development mode: … no rate limiting"), and its only
//     other effect on a response is one extra paragraph in the footer.
//
// The setup cost is real and it is untimed: 2000 files are written, walked,
// parsed and indexed, which is where the index-side benchmark in
// internal/sync lives. On the machine these numbers were taken that is roughly
// 20 seconds before the first iteration runs.
func benchPageFixture(b *testing.B) (*fixture, []string) {
	b.Helper()
	files := benchPageCorpus(b, benchPages2k)
	fx := newFixtureWith(b, files, func(c *config.Config) {
		c.AllowAnonymousRead = true
		c.Dev = true
	})
	seedBenchDM(b, fx)

	pages := make([]string, 0, len(files))
	for name := range files {
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		// url.URL{Path: …}.String() escapes each segment and leaves the
		// separators alone. url.PathEscape would turn every "/" into "%2F", and
		// the catch-all reads its value as a path — so a page in a subdirectory
		// would 404 and the benchmark would report a number for a URL no reader
		// ever types.
		pages = append(pages, fx.HTTP.URL+(&url.URL{Path: "/p/" + name}).String())
	}
	sort.Strings(pages)
	return fx, pages
}

// benchDMSession is the raw session token for a DM that exists without a single
// argon2id derivation.
func benchDMSession(b *testing.B, fx *fixture) string {
	b.Helper()
	raw, err := auth.NewToken()
	if err != nil {
		b.Fatalf("mint a session token: %v", err)
	}
	now := fx.Clock.now
	if err := store.InsertSession(context.Background(), fx.DB.Writer(), store.Session{
		ID: auth.HashToken(raw), UserID: fx.userID(benchDMName), CreatedAt: now,
		ExpiresAt: now.Add(config.SessionTTL), LastSeenAt: now,
	}); err != nil {
		b.Fatalf("insert the session: %v", err)
	}
	return raw
}

// seedBenchDM inserts the one account the corpus's fences are authored by and
// resolves the fences' author names.
//
// The retry is the production call and not a full reindex: a fence names its
// author by username and secrets.author_id is a foreign key, so a vault indexed
// before the account exists has fences with no author and every authorization
// question about them answered wrongly. A DM would then be shown a lock
// placeholder where a revealed body belongs, and the benchmark would be
// measuring a render that is not the one anybody performs. Re-indexing all 2000
// pages to fix 100 of them would cost the same 20 seconds the setup already
// costs; RetryUnresolvedAuthors costs one query and 100 page reads.
func seedBenchDM(b *testing.B, fx *fixture) {
	b.Helper()
	if _, err := store.InsertUser(context.Background(), fx.DB.Writer(), store.User{
		Username: benchDMName, DisplayName: "The Dungeon Master",
		Role: string(authz.RoleDM), PWSalt: []byte("bench-salt"), CreatedAt: fx.Clock.now,
	}); err != nil {
		b.Fatalf("insert the DM: %v", err)
	}
	if _, err := fx.Indexer.RetryUnresolvedAuthors(context.Background()); err != nil {
		b.Fatalf("resolve the fences' authors: %v", err)
	}
}

// benchDMName is the account the corpus's fences name.
const benchDMName = "benchmaster"

// benchClient is an HTTP client for one principal: the session cookie when a
// token is given, and no cookie at all when it is not.
func benchClient(fx *fixture, raw string) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic("cookiejar: " + err.Error())
	}
	if raw != "" {
		base, err := url.Parse(fx.HTTP.URL + "/")
		if err != nil {
			panic("server url: " + err.Error())
		}
		jar.SetCookies(base, []*http.Cookie{{Name: httpapi.SessionCookie, Value: raw, Path: "/"}})
	}
	return &http.Client{
		Jar: jar,
		// Redirects are not followed, for the same reason the harness's client
		// does not follow them: a benchmark asserting a status has to assert the
		// status the server sent, or it is asserting the second request.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       30 * time.Second,
	}
}

// benchPageCorpus is a deterministic 2000-page campaign, shaped like the one
// internal/sync measures so that the two benchmarks describe the same vault.
//
// Every twentieth page carries a secret fence, because the render a budget cares
// about is a render that has something to authorize: a corpus of pages with no
// fences would leave the secret-visibility queries out of the number entirely.
// The bodies are synthetic text written for this benchmark, not campaign content,
// and the author is the account seedBenchDM inserts.
//
// A page is a frontmatter block, three headings and fifteen wikilinks, so the
// aside column (table of contents, backlinks, related pages) has real work to do
// — that column is one query per page view, not a constant.
func benchPageCorpus(b *testing.B, pages int) map[string]string {
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
			fmt.Fprintf(&body, "## %s %d\n\n", strings.ToUpper(words[rng.Intn(len(words))]), h)
			for p := 0; p < 2; p++ {
				for w := 0; w < 12; w++ {
					body.WriteString(words[rng.Intn(len(words))])
					body.WriteByte(' ')
				}
				body.WriteString("\n\n")
			}
			for l := 0; l < 15; l++ {
				fmt.Fprintf(&body, "[[Page-%04d]]\n", rng.Intn(pages))
			}
			body.WriteString("\n")
		}
		if i%20 == 0 {
			fmt.Fprintf(&body, "```secret id=%012x visibility=%s author=%s created=2026-09-28T10:04:11Z\n",
				i, visibilities[i/20%len(visibilities)], benchDMName)
			body.WriteString("synthetic benchmark body " + words[rng.Intn(len(words))] + "\n```\n")
		}
		files[name] = body.String()
	}
	return files
}

// reportBenchPercentiles adds p50/p95/p99/max to the benchmark's own output.
// This is the third copy of this function in this repository — the other is in
// internal/search's bench_test.go and the other in internal/sync's. There is no
// place to put the one that would serve all three: a shared test helper has to
// live in a non-test file, and internal/testutil is one. The one-line fix, when
// someone owns that file, is a percentile helper in testutil.
// Go's testing package reports only a mean, and a mean is the wrong statistic
// for a latency budget: it is the number that stays the same while the thing
// the budget is about gets worse for one reader in a hundred.
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
