package httpapi_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/PopinjayJohn/vtt-semiplane/internal/config"
	"github.com/PopinjayJohn/vtt-semiplane/internal/plugin"
	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
)

// The link preview's core-owned surface, and the two properties that make it
// safe to put behind a hover.
//
// The one that matters most is that a summary of a page the reader may not read
// is byte-identical to a summary of a page that does not exist, and byte-
// identical to navigating to either. It holds here because the 404 is written by
// writeError, which renders a fixed copy table with nothing in the model that
// could differ between two renderings. Every test below that asserts a 404
// asserts it on the bytes, not on the status: a status check would pass against
// a distinguishable body, which is the leak.

// fixedProvider is a SummaryProvider that answers the same thing for every page.
//
// It is a double rather than the real plugin because these tests are about the
// route core owns and the policy it applies, neither of which changes when the
// plugin's card body does.
type fixedProvider struct {
	id  string
	ok  bool
	err error
	// body is what a successful Summary returns.
	body templ.Component
	// declineAbove makes Summary decline for any page id at or above it, which
	// is how a real provider behaves: it reads the page, finds no such page, and
	// declines. It exists because "the page does not exist" and "the provider
	// declines" are the same refusal from the outside, and a fixture whose
	// provider answered yes to a page nobody wrote would be asserting core
	// second-guesses the provider — which is a second code path for one decision.
	declineAbove int64
	// seen records the page ids core asked about, so a test can assert core
	// asked nothing at all when it refused before reaching the provider.
	seen []int64
}

func (f *fixedProvider) ID() string { return f.id }

func (f *fixedProvider) Summary(ctx context.Context, pageID int64) (templ.Component, bool, error) {
	f.seen = append(f.seen, pageID)
	if f.err != nil {
		return nil, false, f.err
	}
	if f.declineAbove > 0 && pageID >= f.declineAbove {
		return nil, false, nil
	}
	return f.body, f.ok, nil
}

// previewRegistry is a plugin.Registry carrying exactly what these tests need:
// one summary provider and, optionally, one mounted sub-router. Every other
// accessor answers "nothing was registered", which is the honest answer for a
// registry holding only the two surfaces under test.
type previewRegistry struct {
	provider *fixedProvider
	// sub, when non-nil, is mounted under the prefix core derives from
	// pluginID. It is the fixture for the sub-router gating tests.
	sub *chi.Mux
	// pluginID is the id the registry claims ownership of.
	pluginID string
	// mounted is a handler the sub-router serves, so a test can tell a mounted
	// route from a 404 produced by core.
	mounted http.HandlerFunc
}

func (r previewRegistry) Report() plugin.Report { return plugin.Report{} }

func (r previewRegistry) PageType(string) (plugin.PageType, bool) { return plugin.PageType{}, false }

func (r previewRegistry) PageTypes() []plugin.Owned[plugin.PageType] { return nil }

func (r previewRegistry) Panels() []plugin.Owned[plugin.Panel] { return nil }

func (r previewRegistry) PanelsFor(string) []plugin.Owned[plugin.Panel] { return nil }

func (r previewRegistry) NavItems() []plugin.Owned[plugin.NavItem] { return nil }

func (r previewRegistry) SearchResolvers() []plugin.Owned[plugin.SearchResolver] { return nil }

func (r previewRegistry) Extenders() []plugin.Owned[any] { return nil }

func (r previewRegistry) Config(string) (plugin.Config, bool) { return plugin.Config{}, false }

func (r previewRegistry) Plugin(string) (plugin.Plugin, bool) { return nil, false }

func (r previewRegistry) Summaries() []plugin.Owned[plugin.SummaryProvider] {
	if r.provider == nil {
		return nil
	}
	return []plugin.Owned[plugin.SummaryProvider]{{Plugin: r.pluginID, Value: r.provider}}
}

func (r previewRegistry) Routes() []plugin.Owned[plugin.RouteMounter] {
	if r.sub == nil {
		return nil
	}
	return []plugin.Owned[plugin.RouteMounter]{{Plugin: r.pluginID, Value: r.sub}}
}

// providerBody is a templ.Component that renders a fixed token. It exists
// because the real card body belongs to the linkpreview plugin, and a test in
// this package that depended on it would fail for that package's reasons rather
// than for core's.
type providerBody struct{ token string }

func (p providerBody) Render(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, p.token)
	return err
}

// TestTheSummaryRouteDeclinesInEveryWayThatIsNotYes is the test that matters
// most in this file.
//
// A preview is a way to ask "what is on that page" about a page the reader may
// not have read, so the interesting assertions are all the negative ones and the
// property they share is that they are indistinguishable. A build with no
// provider, a provider that declines, a page that does not exist, a page id that
// is not a number, and a provider that errors all have to produce the same
// bytes — and those bytes have to be the same ones a 404 from anywhere else in
// the app produces.
func TestTheSummaryRouteDeclinesInEveryWayThatIsNotYes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		registry previewRegistry
		path     string
	}{
		{
			name:     "no plugin registered a summary provider",
			registry: previewRegistry{},
			path:     "/plugin/linkpreview/summary/1",
		},
		{
			name:     "the provider declines the page",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", ok: false}},
			path:     "/plugin/linkpreview/summary/1",
		},
		{
			// A page nobody wrote. The provider is the one that knows, so the
			// fixture models a provider that read it and found nothing rather
			// than one that says yes to an id it has never heard of.
			name:     "the page does not exist",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}, declineAbove: 2}},
			path:     "/plugin/linkpreview/summary/999999",
		},
		{
			name:     "the page id is not a number",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}}},
			path:     "/plugin/linkpreview/summary/not-a-number",
		},
		{
			name:     "the page id is zero or negative",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}}},
			path:     "/plugin/linkpreview/summary/0",
		},
		{
			name:     "the provider fails",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", err: errPreview}},
			path:     "/plugin/linkpreview/summary/1",
		},
		{
			name:     "a plugin that is not the one the url names",
			registry: previewRegistry{pluginID: "linkpreview", provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}}},
			path:     "/plugin/someotherplugin/summary/1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixturePlugins(t, campaignFiles, tc.registry)
			fx.accountsFor()
			s := fx.asUser(dmName, dmPass)

			// The reference is a 404 from a *page* route, taken from the same
			// build and the same session.
			//
			// Same build matters and is not pedantry: the shell carries a CSRF
			// token and a `previews` signal, and both differ between two servers
			// and would make every comparison across one a false failure. What
			// the requirement is about is that within one server a reader cannot
			// tell a page they may not read from a page that is not there, so
			// that is the comparison being made — and it is the harder one,
			// because it is the same shell in both.
			reference := summaryBytesAs(t, s, "/p/NoSuchPage.md")
			got := summaryBytesAs(t, s, tc.path)

			if got.status != reference.status {
				t.Errorf("status %d, an ordinary 404 is %d: the two refusals are distinguishable by status",
					got.status, reference.status)
			}
			if got.body != reference.body {
				t.Errorf("the refusal body differs from the body of an ordinary 404.\n got: %q\nwant: %q",
					got.body, reference.body)
			}
			if strings.Contains(got.body, "CARD") {
				t.Error("the refusal body carries the provider's card content")
			}
		})
	}
}

// TestASummaryOfAPageTheReaderMayNotReadIsTheSameAsNoPageAtAll is the property
// AGENTS.md §7 states for link previews, asserted on the bytes.
//
// It runs the whole campaign fixture as each role, because the campaign carries
// five secret fences at four visibilities and a summary that leaked one of them
// would show up as a token in a body.
func TestASummaryOfAPageTheReaderMayNotReadIsTheSameAsNoPageAtAll(t *testing.T) {
	t.Parallel()

	// Every fixture secret body token, from campaignFiles. A summary that
	// rendered any of them would be the leak this test exists to catch, and the
	// assertion is a substring search over the response rather than a check of
	// the component, because the component is the plugin's and the response is
	// core's.
	tokens := []string{
		"PRIVATE-BODY-TOKEN-9f3a2c",
		"DM-BODY-TOKEN-7b1e4d",
		"OWNER-BODY-TOKEN-2a6e10",
		"TABLE-BODY-TOKEN-5d0a8f",
		"RUIN-BODY-TOKEN-2c8f61",
	}

	for _, role := range matrixRoles {
		t.Run(role.name, func(t *testing.T) {
			t.Parallel()
			registry := previewRegistry{
				pluginID: "linkpreview",
				provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}},
			}
			fx := newFixturePlugins(t, campaignFiles, registry, func(c *config.Config) { c.AllowAnonymousRead = role.anonymousRead })
			if !role.noAccounts {
				fx.accountsFor()
			}
			s := fx.newSession()
			if role.signIn != "" {
				resp := s.login(role.signIn, role.pass)
				defer drain(resp)
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("sign %s in: status %d, want 303", role.signIn, resp.StatusCode)
				}
			}
			// The tavern is the page every secret in the fixture lives on, so a
			// summary of it is the one most likely to carry a body.
			for _, id := range []string{"2", "999999"} {
				resp := summaryBytesAs(t, s, "/plugin/linkpreview/summary/"+id)
				for _, token := range tokens {
					if strings.Contains(resp.body, token) {
						t.Errorf("the summary of page %s as %s carries %s", id, role.name, token)
					}
				}
			}
		})
	}
}

// TestTheSummaryIsNeverCached checks the one cache header a preview must carry.
//
// A shared browser cache holding a summary is a place a 404 and a 200 for the
// same URL would be confused, and a pinned pane that outlives a permission change
// is exactly the reader the leak would reach. `private, max-age=0` says to this
// browser only and not at all beyond this response.
func TestTheSummaryIsNeverCached(t *testing.T) {
	t.Parallel()

	registry := previewRegistry{
		pluginID: "linkpreview",
		provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}},
	}
	fx := newFixturePlugins(t, campaignFiles, registry)
	fx.accountsFor()
	s := fx.asUser(dmName, dmPass)

	resp := s.do(s.get("/plugin/linkpreview/summary/1"))
	defer drain(resp)
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "max-age=0") {
		t.Errorf("Cache-Control is %q, want a max-age=0 so no cache retains a summary", got)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "private") {
		t.Errorf("Cache-Control is %q, want private so a shared cache never holds one", got)
	}
}

// TestAPluginSubRouterIsMountedBehindTheSameGatesAsATableRoute closes the hole
// that mounting a sub-router would otherwise open.
//
// chain() wraps the router, so a mounted sub-router is already behind Session.
// checkCSRF and permit are applied per row inside the table loop, and a mount is
// not a row — so without mountPluginRoutes re-applying them, a plugin's POST
// would run with no CSRF check and no permission at all, which is precisely the
// escape the boundary exists to prevent.
//
// What this cannot be asked is which methods the mount gates: a mount is
// registered once for every method its sub-router serves, so the answer is a
// property of each request rather than of the mount. That is
// TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest, and it is the half
// that was wrong for as long as this file existed — checkCSRF was applied to the
// mount whole, which gated the reads as well as the writes.
func TestAPluginSubRouterIsMountedBehindTheSameGatesAsATableRoute(t *testing.T) {
	t.Parallel()

	sub := chi.NewRouter()
	sub.Get("/rules", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("RULES"))
	})
	sub.Post("/write", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("WROTE"))
	})

	registry := previewRegistry{pluginID: "houserules", sub: sub}
	fx := newFixturePlugins(t, campaignFiles, registry)
	fx.accountsFor()
	s := fx.asUser(playerName, playerPass)

	t.Run("a read is served", func(t *testing.T) {
		t.Parallel()
		// noCSRF for the same reason the mutation below carries it: session.do
		// presents a valid token unless it is told not to, so a GET that
		// presented one would have been measuring the harness rather than the
		// gate. It passed for exactly that reason while the mount refused every
		// untokened read with 403.
		resp := s.do(&call{method: http.MethodGet, path: "/plugin/houserules/rules", noCSRF: true})
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200: the sub-router is not mounted, or its reads are gated as mutations", resp.StatusCode)
		}
	})

	t.Run("a mutation without a token is refused", func(t *testing.T) {
		t.Parallel()
		// noCSRF is required and not optional: session.do presents a valid token
		// unless it is told not to, so a plain post here would be a request that
		// *should* be served and would test the harness rather than the gate.
		//
		// This is the whole point: the route is not in the table, so
		// TestCSRFRequiredOnAllMutations never sees it and nothing else would
		// have checked it.
		resp := s.do(&call{method: http.MethodPost, path: "/plugin/houserules/write", noCSRF: true})
		defer drain(resp)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a plugin route served a mutation with no CSRF token")
		}
	})

	t.Run("an anonymous reader is refused", func(t *testing.T) {
		t.Parallel()
		anon := fx.newSession()
		resp := anon.do(anon.get("/plugin/houserules/rules"))
		defer drain(resp)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("a plugin route served an anonymous reader")
		}
	})
}

// TestAPluginCannotServeOutsideItsOwnPrefix pins the property the prefix is for.
//
// The mount is derived from the registry's own record of which plugin owns the
// router, never from anything the plugin said, so a router handed to a plugin
// under one id cannot be reached under another's.
func TestAPluginCannotServeOutsideItsOwnPrefix(t *testing.T) {
	t.Parallel()

	sub := chi.NewRouter()
	sub.Get("/rules", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("RULES"))
	})
	registry := previewRegistry{pluginID: "houserules", sub: sub}
	fx := newFixturePlugins(t, campaignFiles, registry)
	fx.accountsFor()
	s := fx.asUser(playerName, playerPass)

	for _, path := range []string{
		"/plugin/linkpreview/rules",
		"/plugin/houserules/../linkpreview/rules",
		"/rules",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp := s.do(s.get(path))
			defer drain(resp)
			if resp.StatusCode == http.StatusOK {
				t.Errorf("%s was served by another plugin's sub-router", path)
			}
		})
	}
}

// TestTheShellSaysWhetherPreviewsExist is the graceful-degradation seam.
//
// A build with no summary provider must bind no preview handler at all, so the
// client needs to know. The key is a build fact and nothing more: it carries no
// page id, no path and no title, and the tripwire in TestSignalsCarryNoContent
// audits the payload the same way it audits the HTML.
func TestTheShellSaysWhetherPreviewsExist(t *testing.T) {
	t.Parallel()

	t.Run("off when no plugin registered a provider", func(t *testing.T) {
		t.Parallel()
		fx := newFixturePlugins(t, campaignFiles, previewRegistry{})
		fx.accountsFor()
		s := fx.asUser(playerName, playerPass)
		seed := signalsSeed(t, s.getOK("/"))
		if _, ok := seed["previews"]; !ok {
			t.Fatal("the shell's signal seed has no previews key, so the client cannot tell whether to bind")
		}
		if seed["previews"] != false {
			t.Errorf("previews is %v, want false with no provider registered", seed["previews"])
		}
	})

	t.Run("on when a plugin registered one", func(t *testing.T) {
		t.Parallel()
		registry := previewRegistry{
			pluginID: "linkpreview",
			provider: &fixedProvider{id: "p", ok: true, body: providerBody{token: "CARD"}},
		}
		fx := newFixturePlugins(t, campaignFiles, registry)
		fx.accountsFor()
		s := fx.asUser(playerName, playerPass)
		seed := signalsSeed(t, s.getOK("/"))
		if seed["previews"] != true {
			t.Errorf("previews is %v, want true with a provider registered", seed["previews"])
		}
	})
}

// summaryBytesAs performs one summary request and returns the status and body.
func summaryBytesAs(t *testing.T, s *session, path string) summaryResponse {
	t.Helper()
	resp := s.do(s.get(path))
	defer drain(resp)
	body := s.read(resp)
	return summaryResponse{status: resp.StatusCode, body: body}
}

// summaryResponse is what a refusal is compared on.
type summaryResponse struct {
	status int
	body   string
}

// errPreview is a provider failure, kept as a sentinel so the test reads as a
// case rather than as a construction.
var errPreview = &previewError{}

type previewError struct{}

func (*previewError) Error() string { return "the preview provider failed" }
