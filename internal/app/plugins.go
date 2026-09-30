package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// The plugin lifecycle, driven from the composition root.
//
// This is the only place the host is constructed, and it is here rather than in
// internal/plugin for one reason: `plugin` sits below `vault`, `auth` and
// `secrets` in the dependency order, so it cannot build the things a plugin's
// host hands out. A page store is a store query, the plugin's config is a meta
// row, and a clock is a closure. `app` is the package allowed to know about all
// of them, which is what the composition root is for.

// loadPlugins runs the lifecycle and records what it produced.
//
// It returns an error only for a failure of the *host*, never for a plugin that
// failed to register. A plugin that cannot register is recorded with a reason and
// the boot continues: a campaign that will not start because of a plugin nobody
// is using turns a small problem into an outage, and the report is where the
// difference becomes visible.
func (a *App) loadPlugins(ctx context.Context) error {
	offered := make([]plugin.Plugin, 0, len(a.opts.Plugins))
	for _, id := range sortedPluginIDs(a.opts.Plugins) {
		offered = append(offered, a.opts.Plugins[id])
	}

	reg, report := plugin.Load(ctx, a.pluginDeps(ctx), offered...)
	a.plugins = reg
	a.report = report

	for _, e := range report.Entries {
		if e.Status == plugin.StatusSkipped {
			// The reason is logged, not hidden, and it is the whole value of the
			// report: "the panel is missing" is not actionable, "the plugin was
			// refused because it claims the reserved page type X without Y" is.
			a.log.WarnContext(ctx, "a plugin was not registered",
				"action", "boot.plugins", "plugin", e.ID, "kind", string(e.Kind),
				"version", e.Version, "reason", e.Reason)
			continue
		}
		a.log.InfoContext(ctx, "a plugin was registered",
			"action", "boot.plugins", "plugin", e.ID, "kind", string(e.Kind),
			"version", e.Version, "status", string(e.Status),
			"page_types", e.Count.PageTypes, "panels", e.Count.Panels,
			"nav_items", e.Count.NavItems, "routes", e.Count.Routes)
	}
	for _, w := range report.Warnings {
		a.log.WarnContext(ctx, "a plugin contribution was dropped",
			"action", "boot.plugins", "reason", w)
	}
	return nil
}

// pluginDeps builds what a plugin's host is made of.
//
// Each field is a value the composition root already has, handed over rather
// than looked up, because `plugin` cannot import any of them.
func (a *App) pluginDeps(ctx context.Context) plugin.PluginDeps {
	return plugin.PluginDeps{
		Now: a.clock,

		Log: func(ctx context.Context, l plugin.Level, msg string, kv ...plugin.KV) {
			fields := make([]any, 0, len(kv)*2)
			for _, p := range kv {
				fields = append(fields, p.Key, p.Value)
			}
			a.log.Log(ctx, obsLevel(l), "plugin: "+msg, fields...)
		},

		// A plugin's configuration is its own namespaced blob in the meta table.
		//
		// It is one row rather than a table, because the shape is whatever the
		// plugin's ConfigSchema says and the host has no business knowing it. The
		// plugin validates what it got, which is the only layer that can say what
		// "valid" means for a shape the host invented the storage for.
		Config: func(pluginID string) (plugin.Config, error) {
			raw, err := store.MetaGet(ctx, a.db.Reader(), keyPluginConfig+"."+pluginID)
			// errors.Is, and only for ErrNoRows. store.MetaGet never returns
			// ("", nil) — a missing key comes back as a wrapped ErrNoRows — so
			// `err != nil || raw == ""` answered the same thing for "this plugin
			// has no stored configuration" and for "the read failed", and the
			// second one silently booted a plugin with defaults it would then
			// write over the settings it failed to read. A read that fails is
			// reported; the lifecycle turns this error into a refusal the boot
			// report names, which is the outcome a broken index should have.
			if errors.Is(err, store.ErrNoRows) {
				return plugin.Config{ID: pluginID, Values: map[string]any{}}, nil
			}
			if err != nil {
				return plugin.Config{}, fmt.Errorf("read stored configuration for plugin %s: %w", pluginID, err)
			}
			return plugin.Config{ID: pluginID, Values: parseConfigBlob(raw)}, nil
		},

		// The filesystem a plugin sees is NOT wired in this stage, and the reason
		// is the whole design and not an oversight.
		//
		// A plugin's filesystem is the one surface by which a plugin could reach
		// a secret body, so the guarantee that it cannot is a property of what is
		// put *in* — every secret segment replaced by its redaction sentinel — and
		// not of the fs.FS type. That redaction currently exists in exactly one
		// place, the page view, as a rendering step over the segments; there is no
		// reusable "public body" reader to hand a plugin.
		//
		// Writing one here, under time pressure, is the single most likely way to
		// put a secret where a plugin can see it. So the field is nil, a plugin
		// that asks for a filesystem gets an error, and the gap is recorded rather
		// than papered over. The fix is to extract the page view's redaction into
		// a named function that both it and this can call, so there is one
		// implementation and two callers.
		FS: nil,

		// A plugin's migrations run in one transaction, which is what makes a
		// migration failure roll the plugin back together with everything else it
		// registered rather than leaving a half-applied schema behind a plugin the
		// boot report calls skipped.
		Migrations: func(ctx context.Context, pluginID string, migs []plugin.Migration) error {
			return a.applyPluginMigrations(ctx, pluginID, migs)
		},

		// The sub-router is a bare mux, and the prefix and the middleware are
		// applied by the caller that owns the router.
		//
		// The alternative — building the mounted, wrapped router here — is not
		// available, and the reason is the boot order rather than a preference.
		// Plugins register before the HTTP server exists: the router needs the
		// store, the writer and the indexer that Boot is what creates, and Boot
		// needs to know whether it has a handler before it binds a listener. So
		// there is no router here to mount onto, and the composition root hands
		// the deferred handler in for exactly that reason.
		//
		// What this does guarantee is the half that is a security property: the
		// mux is built here, by the host, and handed to the plugin as a value.
		// A plugin that mounted on a router of its own would be mounting outside
		// the prefix and outside the middleware, and the audit in host.go compares
		// the router it is handed against this one so that a substituted router is
		// refused rather than served.
		SubRouter: func(string) plugin.RouteMounter { return chi.NewRouter() },

		// The page read surface, over the reader connection.
		//
		// This is the surface a feature plugin reads the campaign with: a
		// `type: houserule` page list, or one page's public summary for a link
		// preview. It is four named methods rather than a *sql.DB, and the
		// difference is the design — a plugin handed a database could compose its
		// own visibility predicate, and a hand-rolled OR-chain is how a dm secret
		// reaches a player (AGENTS.md §2.4). Every method takes the principal and
		// applies authz.SecretVisibleSQL itself, so there is no predicate left for
		// a plugin to get wrong.
		Pages: &pageStore{q: a.db.Reader()},
	}
}

// pageStore is the composition root's implementation of plugin.PageStore.
//
// It is a named type over a Queryer rather than a set of closures because a
// plugin receives the interface and the composition root is the only place that
// can satisfy it: `plugin` sits below `store` in the dependency order's
// reasoning, and `app` is the package allowed to know about both. The methods
// are store's, called verbatim — there is no query written here, because a
// query written here would be a query the store's own tests cannot see, and
// store.TestPredicateMatrixAgrees is the cross-check that matters.
type pageStore struct {
	q store.Queryer
}

func (p *pageStore) GetPageSummary(ctx context.Context, who authz.Principal, pageID int64) (store.PageSummary, error) {
	return store.GetPageSummary(ctx, p.q, who, pageID)
}

func (p *pageStore) ListPagesByType(ctx context.Context, who authz.Principal, pageType string) ([]store.Page, error) {
	return store.ListPagesByType(ctx, p.q, who, pageType)
}

func (p *pageStore) CountPagesByType(ctx context.Context, who authz.Principal, pageType string) (int, error) {
	return store.CountPagesByType(ctx, p.q, who, pageType)
}

func (p *pageStore) ListTags(ctx context.Context, who authz.Principal) ([]store.TagCount, error) {
	return store.ListTags(ctx, p.q, who)
}

var _ plugin.PageStore = (*pageStore)(nil)

// PluginRegistry returns what the lifecycle produced, for the request path.
//
// A nil return is meaningful: it means the caller booted without a lifecycle, and
// the request path must read it as "no plugins" rather than dereference it. Every
// reader nil-checks, and `/admin/plugins` renders an explicit empty state rather
// than a 500.
func (a *App) PluginRegistry() plugin.Registry { return a.plugins }

// PluginReport returns the boot report, for /admin/plugins.
func (a *App) PluginReport() plugin.Report { return a.report }

// keyPluginConfig is the meta-table prefix for a plugin's configuration blob.
const keyPluginConfig = "plugin_config"

// keyPluginMigration is the meta-table prefix for a plugin's applied migrations.
//
// The version is part of the key rather than a row's value because a plugin
// declares an ordered list and the host's job is only to know which steps have
// been applied; interpreting the order is the plugin's, in its Migration.Version.
const keyPluginMigration = "plugin_migration"

// applyPluginMigrations runs a plugin's declared schema steps, tracked so a
// second boot does not run them again.
func (a *App) applyPluginMigrations(ctx context.Context, pluginID string, migs []plugin.Migration) error {
	if len(migs) == 0 {
		return nil
	}
	tx, err := a.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, m := range migs {
		key := keyPluginMigration + "." + pluginID + "." + strconv.Itoa(m.Version)
		// A missing key is the normal first-boot case, not a failure: MetaGet
		// wraps sql.ErrNoRows rather than answering "", so the error is what
		// "not applied yet" looks like. Anything else is real and is returned.
		done, err := store.MetaGet(ctx, tx, key)
		switch {
		case err == nil && done == "applied":
			continue
		case err != nil && !errors.Is(err, store.ErrNoRows):
			return err
		}
		// The namespace is checked, not assumed. A plugin that can create a core
		// table has found a way around the host's migration transaction, and the
		// table name is the only place that is checkable at all.
		if !strings.HasPrefix(strings.TrimSpace(m.SQL), "CREATE TABLE IF NOT EXISTS plugin_"+sanitiseID(pluginID)) {
			a.log.WarnContext(ctx, "a plugin migration was refused: it does not create a table in the plugin's own namespace",
				"action", "boot.plugins", "plugin", pluginID, "version", m.Version, "name", m.Name)
			continue
		}
		if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
			return err
		}
		if err := store.MetaSet(ctx, tx, key, "applied"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// sanitiseID reduces a plugin id to the characters a table name may contain.
//
// The result is concatenated into a table name, so an id that is not already
// safe becomes something that is. The alternative is interpolating an
// unvalidated value into DDL, which is the thing AGENTS.md §2.1 forbids.
func sanitiseID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// parseConfigBlob reads a plugin's stored configuration.
//
// It is JSON rather than the typed shape a plugin's schema might describe,
// because the host stores what the plugin's Validate accepted and has no
// business interpreting it afterwards.
func parseConfigBlob(raw string) map[string]any {
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// A blob the host cannot read is a plugin that will validate against
		// nothing rather than one that takes the boot down, so it degrades to the
		// empty configuration and the plugin's own Validate reports the rest.
		return map[string]any{}
	}
	return out
}

// obsLevel maps a plugin's severity onto the host's.
//
// The mapping is explicit rather than a cast because the two are numbered
// differently, and a cast would mean a plugin's "warn" was the host's "error".
func obsLevel(l plugin.Level) slog.Level {
	switch l {
	case plugin.LevelDebug:
		return slog.LevelDebug
	case plugin.LevelError:
		return slog.LevelError
	case plugin.LevelInfo:
		return slog.LevelInfo
	default:
		return slog.LevelWarn
	}
}

// sortedPluginIDs returns the offered ids in order.
//
// The map is the caller's, so the only way to make its order reproducible is to
// impose one — and a registry that iterates a map is a registry whose boot
// report changes between runs.
func sortedPluginIDs(m map[string]plugin.Plugin) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
