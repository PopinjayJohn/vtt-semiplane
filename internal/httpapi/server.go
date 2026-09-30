package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/auth"
	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/md"
	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/secrets"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/PopinjayJohn/vtt-semiplane/internal/sync"
	"github.com/PopinjayJohn/vtt-semiplane/internal/vault"
)

// The render budget.
//
// goldmark's inline loop rescans the rest of a line at every character that
// could open an inline construct, so the cost of one line is quadratic in its
// length: 64 KiB of `[` on a single line renders in about 140 ms, and the same
// line at 1 MiB extrapolates to about twelve seconds. A player who can save a
// note can therefore save a note that pins a request, and the page-view path
// is the one that has to render it.
//
// So the budget is on the input, not on a timer. A deadline around the render
// would bound the request but not the CPU: goldmark takes no context, so a
// timed-out render would have to be abandoned mid-parse, leaving a goroutine
// spinning on bytes it will never finish reading. Capping the two things that
// make the parser quadratic bounds the work itself, costs nothing when the page
// is a normal size, and is a property of the code rather than of the machine's
// mood.
const (
	// MaxRenderBytes is the largest public body handed to the renderer. Beyond it
	// the view is a prefix and the response says so.
	//
	// Two megabytes, and the size is chosen to be *invisible* for a real page
	// rather than merely safe. A total cap low enough to catch the quadratic case
	// would also clip ordinary long notes, and a clipped note is a page a reader
	// cannot read — a worse outcome than a slow one, and one they would have no
	// way to diagnose. Ordinary prose is linear in goldmark, so two megabytes of
	// it costs milliseconds; the hazard is entirely in the per-line bound below.
	// The cap still exists to bound a file at the indexer's own eight-megabyte
	// ceiling, which is 256 KiB of *response* in the worst case rather than 8 MiB.
	MaxRenderBytes = 2 << 20
	// MaxRenderLineBytes is the longest run of bytes allowed on one line, and it
	// is the bound that matters: this is the quadratic term. 16 KiB costs about
	// 9 ms of rescan, so even a body that is entirely over-long lines spends
	// around a second in the parser rather than the twelve seconds the same bytes
	// would cost unclipped.
	MaxRenderLineBytes = 16 << 10
)

// Options configures a Server.
type Options struct {
	// Config is the validated configuration. Its Addr decides whether HSTS is
	// sent, and its Dev flag whether the rate limiter runs.
	Config config.Config
	// DB is the vault index. Required.
	DB *store.DB
	// Writer is the only way a vault file changes. Required, and passed rather
	// than reached for, so that the secrets service and the page view cannot
	// end up pointed at different roots.
	Writer *vault.Writer
	// Reindexer re-derives a page's index rows after a file mutation. Required:
	// it is the same indexer the application booted, so a secret reveal updates
	// the index that is already serving every other request.
	Reindexer secrets.Reindexer
	// AuthorRetryer re-checks secret fences whose named author was not an
	// account when the page was first indexed. Optional: without it a newly
	// created account's own secrets stay invisible until a full reindex, which
	// is stale rather than wrong. It is declared here rather than in secrets
	// because the method returns a sync.BatchResult and sync sits above secrets.
	AuthorRetryer AuthorRetryer
	// Bus is the invalidation bus. May be nil, which is what a test that never
	// subscribes wants.
	Bus *sync.Bus
	// Log receives the request records. Nil discards.
	Log *obs.Logger
	// Clock is the time source. Nil is the system clock.
	Clock obs.Clock
	// Assets is the embedded file system served under /_/assets/. Required: a
	// binary with no assets would render a page whose stylesheet is a 404, and
	// a page that cannot be styled is a broken app rather than a degraded one.
	Assets fs.FS
	// Build is the build metadata the readiness probe reports.
	Build app.BuildInfo
	// Renderer renders the view models. Required.
	Renderer Renderer
	// Plugins is what the plugin lifecycle collected at boot, read by
	// /admin/plugins. Optional, and nil is a real state rather than an unset
	// one: it means this process ran no plugin lifecycle, and the report says so
	// instead of rendering an empty table that would read as "this build offers
	// no plugins". The interface is the seam on purpose, so a test can hand the
	// router a registry containing one plugin without booting one.
	Plugins plugin.Registry
}

// The account and secret services are built here rather than handed in.
//
// Both are thin, stateless wrappers over the same database, the same policy and
// the same writer the application already holds, and building them in the
// package that owns the request path means the composition root has four fields
// to pass instead of seven — and, more to the point, that there is exactly one
// place in this codebase where the request path's dependencies are declared. A
// handler that wanted a second auth service would have to invent one, and the
// place it would invent it is visible.

// Server is the HTTP surface: the route table, the middleware chain and the
// handlers.
//
// It holds no state that a request mutates and no cache of a rendered page. A
// rendered-page cache keyed wrongly is a whole class of secret leak for no
// measurable gain on a local SQLite vault, and §2.8 is explicit that v1 has
// none; a second request with a different principal re-renders from the file.
type Server struct {
	cfg     config.Config
	db      *store.DB
	auth    *auth.Service
	secrets *secrets.Service
	// writer is the only way a vault file changes, and it is held rather than
	// reached for through the secrets service so that the editor, the rename and
	// the link updater are all pointed at the same root by construction. Options
	// already required one — it is what the secrets service was built with — and
	// keeping it as a field is what turns "the only way out of the app" from a
	// rule about one package into a property of the composition root.
	writer   *vault.Writer
	bus      *sync.Bus
	log      *obs.Logger
	clock    obs.Clock
	assets   fs.FS
	policy   authz.Policy
	view     Renderer
	markdown *md.Renderer
	limits   *limiters
	build    app.BuildInfo
	// summaries is the link preview's own rate budget, separate from the three
	// general buckets in limits. Hovering a link is a request, and charging it
	// against the general budget would let a reader who previews a lot spend the
	// budget their page loads draw on.
	summaries *summaryLimiter
	// plugins is the boot report's source, held as the interface rather than
	// reached for through the application, so this package depends on what it
	// reads and not on the lifecycle that fills it. Nil is a distinct state and
	// every reader of it checks; see adminPluginsPage.
	plugins plugin.Registry
	// reindexer re-derives a page's index rows after a file mutation, so a
	// secret reveal updates the index that is already serving every request.
	reindexer secrets.Reindexer
	// authorRetryer re-checks secret fences whose named author was not an
	// account when the page was first indexed. Nil means the gap stands: the
	// index is stale, never wrong.
	authorRetryer AuthorRetryer
	// root is the absolute vault root, taken from the database so that the
	// server and the index can never disagree about which vault they mean.
	root string
	// campaign is the vault directory's name.
	campaign string

	// streams is the live-update registry, and it is a field rather than a
	// package-level map keyed by *Server.
	//
	// It was a map for a while, and the map was a workaround for this file not
	// being writable at the time, not a design: AGENTS.md §4 says no global
	// mutable state, and a map keyed by a pointer to a Server is a global that
	// happens to be tidy. It is a field now.
	//
	// It is built eagerly in New rather than lazily on the first stream,
	// because a registry that appears the first time somebody opens a stream
	// means a boot report cannot count what is open, and counting what is open
	// before the first request is the only version of the question worth asking.
	// The bus subscription it makes is one closure, and Shutdown releases it.
	streams *Events
}

// New builds a Server. It returns an error rather than a Server with a nil
// field in it, so no handler has to check before it dereferences something the
// composition root forgot.
func New(opts Options) (*Server, error) {
	switch {
	case opts.DB == nil:
		return nil, errors.New("httpapi: an index database is required")
	case opts.Writer == nil:
		return nil, errors.New("httpapi: a vault writer is required")
	case opts.Reindexer == nil:
		return nil, errors.New("httpapi: a reindexer is required")
	case opts.Assets == nil:
		return nil, errors.New("httpapi: an embedded asset filesystem is required")
	case opts.Renderer == nil:
		return nil, errors.New("httpapi: a renderer is required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = obs.SystemClock
	}
	log := opts.Log
	if log == nil {
		log = obs.Discard()
	}
	policy := authz.NewPolicy(opts.Config.AllowAnonymousRead)
	accounts, err := auth.New(auth.Options{DB: opts.DB, Policy: policy, Log: log, Clock: clock})
	if err != nil {
		return nil, fmt.Errorf("httpapi: the account service: %w", err)
	}
	secretSvc, err := secrets.NewService(secrets.Options{
		DB:        opts.DB,
		Writer:    opts.Writer,
		Policy:    policy,
		Reindexer: opts.Reindexer,
		Log:       log,
		Clock:     clock,
	})
	if err != nil {
		return nil, fmt.Errorf("httpapi: the secrets service: %w", err)
	}
	srv := &Server{
		cfg:      opts.Config,
		db:       opts.DB,
		auth:     accounts,
		secrets:  secretSvc,
		writer:   opts.Writer,
		bus:      opts.Bus,
		log:      log,
		clock:    clock,
		assets:   opts.Assets,
		view:     opts.Renderer,
		policy:   policy,
		markdown: md.New(md.Options{}),
		limits:   newLimiters(opts.Config, clock),
		build:    opts.Build,
		// The same indexer in both roles: one object re-derives a single page's
		// rows after a file mutation, and re-checks the fences whose author was
		// not an account at index time. Two seams onto one object, because the
		// two are called from different places and mean different things.
		reindexer:     opts.Reindexer,
		authorRetryer: opts.AuthorRetryer,
		plugins:       opts.Plugins,
		root:          opts.DB.Vault(),
		campaign:      campaignName(opts.DB.Vault()),
	}
	// Built here rather than on the first stream, so that the boot report can
	// count open streams on a server that has served none yet.
	srv.streams = newEvents(srv)
	// Built eagerly, like the event registry: a limiter that appears on the
	// first hover is a limiter that has not counted the hover before it, and the
	// point of one is to have counted them.
	srv.summaries = &summaryLimiter{bucket: newBucket(summaryRateBurst, clock)}
	return srv, nil
}

// Shutdown releases everything this server owns that outlives a request.
//
// The one thing that needs it is the live-update registry, and the reason is
// that http.Server.Shutdown does not know about it: an SSE stream is a request
// that has not finished, so Shutdown waits for it, and a stream that waits for a
// shutdown is a shutdown that waits for ever. Closing the registry first tells
// every subscriber to finish, which is what lets the HTTP shutdown reach its
// deadline instead of hitting it.
//
// The bus subscription the registry made is released here too, so a server that
// is stopped and then dropped leaves nothing running.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.streams == nil {
		return nil
	}
	return s.streams.Shutdown(ctx)
}

// Handler returns the fully wrapped handler: the route table behind the
// middleware chain. It is what Options.Handler is given at boot, and what a
// test mounts on an httptest server.
func (s *Server) Handler() http.Handler {
	return s.chain(s.router())
}

// Render writes v in the shape the request asked for.
//
// Every handler in this package ends by calling this, and nothing else writes a
// view model. That is what makes the negotiation a property of the request
// rather than a decision a handler might forget, and it is what lets a later
// phase's live-push path call a handler verbatim: the bytes it sends are the
// bytes the ordinary handler would have sent under the subscriber's own
// principal, in whichever shape that subscriber asked for.
func (s *Server) Render(w http.ResponseWriter, r *http.Request, v View) error {
	if Negotiate(r) == ShapeFragment {
		return s.view.Fragment(w, r, v)
	}
	return s.view.Document(w, r, v)
}

// now is the clock's value in UTC, so that every timestamp in a response and
// in a log line has one shape.
func (s *Server) now() time.Time { return s.clock().UTC() }

// clipRenderable bounds the bytes handed to the renderer.
//
// It returns the clipped body and whether anything was actually dropped. The two
// bounds are the two the quadratic term needs: a total byte cap, and a per-line
// cap. A line over the cap is *broken* with a newline rather than truncated,
// because truncating inside a UTF-8 sequence would put a replacement character in
// the middle of a word and a half-written inline construct at the end of the page.
//
// The walk is line by line, and that is the second version of this function. The
// first one stepped a fixed 16 KiB at a time through the whole buffer and inserted
// a newline every 16 KiB regardless of where the newlines already were, so every
// page with more than sixteen kilobytes of body announced itself as clipped — a
// 1.5 MB note of ordinary prose was served with a truncation notice on it. The
// control case in TestTheRenderPathIsBounded is the fixture that found it.
func clipRenderable(src []byte) ([]byte, bool) {
	truncated := false
	if len(src) > MaxRenderBytes {
		src = src[:MaxRenderBytes]
		truncated = true
	}
	// Trim to a rune boundary so the clip never splits a character.
	if cut := len(src); cut > 0 && !isRuneStart(src[cut-1]) {
		for cut > 0 && !isRuneStart(src[cut-1]) {
			cut--
		}
		src = src[:cut]
	}
	out := make([]byte, 0, len(src)+64)
	for rest := src; len(rest) > 0; {
		nl := bytes.IndexByte(rest, '\n')
		var line []byte
		if nl < 0 {
			line, rest = rest, nil
		} else {
			// The line keeps its own terminator, so that a body which was not
			// clipped comes out byte for byte identical. An earlier version
			// appended the newlines back itself and dropped the last one, which
			// made every page ending in a newline lose a byte and therefore look
			// clipped.
			line, rest = rest[:nl+1], rest[nl+1:]
		}
		out = appendClippedLine(out, line)
	}
	if len(out) != len(src) {
		truncated = true
	}
	return out, truncated
}

// appendClippedLine appends one line, terminator included, broken into cap-sized
// pieces if it is over the cap.
//
// Every cursor here moves. The rune-boundary walk can pull the end of a piece back
// to the start of the line — a line of nothing but continuation bytes — and the
// fallback takes the whole line rather than looping for ever, which is the failure
// §11 is about.
func appendClippedLine(out, line []byte) []byte {
	body, term := line, byte(0)
	if n := len(line); n > 0 && line[n-1] == '\n' {
		body, term = line[:n-1], '\n'
	}
	for len(body) > MaxRenderLineBytes {
		end := MaxRenderLineBytes
		for end > 0 && !isRuneStart(body[end]) {
			end--
		}
		if end == 0 {
			return append(out, line...)
		}
		out = append(out, body[:end]...)
		out = append(out, '\n')
		body = body[end:]
	}
	out = append(out, body...)
	if term != 0 {
		out = append(out, term)
	}
	return out
}

// isRuneStart reports whether b can begin a UTF-8 sequence.
func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// campaignName is the vault's directory name. Nothing inside a vault names the
// campaign, and a page title is vault content, so the one name the banner can
// show without leaking anything is the name of the directory holding it.
func campaignName(root string) string {
	if root == "" {
		return "campaign"
	}
	trimmed := strings.TrimRight(root, `/\`)
	if i := strings.LastIndexAny(trimmed, `/\`); i >= 0 {
		return trimmed[i+1:]
	}
	return trimmed
}

// contextKey is this package's private context key type. It is a distinct type
// so that no other package's value can collide with one of ours by accident.
type contextKey struct{ name string }

var (
	// sessionKey carries the raw session token, which the CSRF check and the
	// cookie helpers need and which must never be logged or rendered.
	sessionKey = contextKey{"session"}
	// csrfKey carries the token the response's forms must carry.
	csrfKey = contextKey{"csrf"}
	// routeKey carries the matched route, for the request log.
	routeKey = contextKey{"route"}
)

// PrincipalFrom returns the principal the Session middleware resolved. A
// request that reached a handler always went through Session, so the value is
// never the zero Principal here.
//
// It is a thin pass-through to authz rather than a read of a key of this
// package's own. The key belongs to authz because authz owns Principal, and a
// second key here would be a second answer to "who is asking" for any layer that
// could reach either — including a plugin, which may import authz and must not
// import this package.
func PrincipalFrom(ctx context.Context) authz.Principal {
	return authz.PrincipalFrom(ctx)
}

// SessionFrom returns the raw session token on the context, or "" when the
// request is unauthenticated. It is the one place a raw token is reachable
// from, and the only callers are the cookie writers and the CSRF check.
func SessionFrom(ctx context.Context) string {
	s, _ := ctx.Value(sessionKey).(string)
	return s
}

// CSRFFrom returns the token this response's forms must carry.
func CSRFFrom(ctx context.Context) string {
	s, _ := ctx.Value(csrfKey).(string)
	return s
}

// RouteFrom returns the route the router matched, for the request record.
func RouteFrom(ctx context.Context) string {
	s, _ := ctx.Value(routeKey).(string)
	return s
}

// withValue returns a context carrying one of this package's keys.
func withValue(ctx context.Context, key contextKey, value any) context.Context {
	return context.WithValue(ctx, key, value)
}

// logRecord is the redacted form of a panic value. A panic message can carry
// anything the panicking code had in hand, including a fragment of a vault
// file, so only its type, its length and a hash of it are recorded.
func logRecord(v any) slog.Value {
	var msg string
	switch t := v.(type) {
	case error:
		msg = t.Error()
	case string:
		msg = t
	default:
		msg = "non-string panic value"
	}
	return slog.StringValue(vault.HashHex([]byte(msg))[:16] + "(" + strconv.Itoa(len(msg)) + " bytes)")
}

// AuthorRetryer re-checks the secret fences whose named author did not resolve
// when their page was indexed.
//
// It is a separate seam from secrets.Reindexer because the call site is account
// creation, not page mutation, and because the two live at different times: a
// brand-new vault is indexed at boot and the first admin is created afterwards,
// so the account that owns the earliest secrets arrives after the index has
// already passed over them. Without this call the first account's own `dm`
// secrets are shown to nobody until someone remembers to reindex.
type AuthorRetryer interface {
	RetryUnresolvedAuthors(ctx context.Context) (sync.BatchResult, error)
}

// retryUnresolvedAuthors is called after an account is created, because a
// secret fence names its author by username and secrets.author_id is a foreign
// key: a fence whose author was not yet an account gets no index row at all, so
// it is shown to nobody until it is re-checked. A fresh vault is indexed at
// boot and the first admin is created afterwards, so without this call the very
// first account's own secrets are invisible.
//
// Failure is logged and swallowed. The alternative is refusing an account
// creation because a background repair did not finish, which trades a stale
// index for a user who cannot log in.
func (s *Server) retryUnresolvedAuthors(ctx context.Context) {
	if s.authorRetryer == nil {
		return
	}
	if _, err := s.authorRetryer.RetryUnresolvedAuthors(ctx); err != nil {
		s.log.Warn("a secret fence whose author was not yet an account is still unindexed",
			"reason", err.Error())
	}
}
