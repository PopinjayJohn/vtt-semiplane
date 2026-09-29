package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest is the test the
// route-table gates structurally cannot be.
//
// TestCSRFRequiredOnAllMutations and TestTheMatrixCoversEveryRoute both read
// Routes(), and a mount is not a row: mountPluginRoutes registers one sub-router
// for every method it serves, so no row of the table describes the gate in front
// of it and no row changes when that gate is wrong. That is not a theoretical
// gap. checkCSRF was applied to the mount unconditionally, which answered 403 to
// every safe method on every plugin surface, and both table-derived gates stayed
// green the whole time because neither of them ever looked at a mount.
//
// Three requests, through the real router, at a real sub-router:
//
//   - a GET carrying no token — which is what a browser sends — is served. It
//     asks for noCSRF deliberately: session.do presents a valid token unless it
//     is told not to, so a GET that presented one would be asking the gate a
//     question it passes, and the test would be green against the bug.
//   - a POST carrying no token is refused with 403, which is the CSRF gate and
//     not the router: nothing here is a 404, the route exists.
//   - a POST carrying the session's own token is served. This is the control,
//     and it is what stops the two above passing against a mount that refuses
//     everything or that is not mounted at all.
//
// The principal is an administrator, so permit admits it and the only gate left
// to refuse the untokened POST is the CSRF one.
func TestAMountedPluginRouteGatesCSRFByTheMethodOfEachRequest(t *testing.T) {
	t.Parallel()

	sub := chi.NewRouter()
	sub.Get("/rules", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("RULES"))
	})
	sub.Post("/write", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("WROTE"))
	})

	fx := newFixturePlugins(t, campaignFiles, previewRegistry{pluginID: "houserules", sub: sub})
	fx.accountsFor()
	s := fx.asUser(adminName, adminPass)

	t.Run("a safe method is served with no token", func(t *testing.T) {
		t.Parallel()
		resp := s.do(&call{method: http.MethodGet, path: "/plugin/houserules/rules", noCSRF: true})
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /plugin/houserules/rules with no csrf token: status %d, want 200. A safe method has no state to forge, and the mount is registered once for every method its sub-router serves, so asking this at mount time refuses every plugin read.",
				resp.StatusCode)
		}
	})

	t.Run("a mutation with no token is refused", func(t *testing.T) {
		t.Parallel()
		resp := s.do(&call{method: http.MethodPost, path: "/plugin/houserules/write", noCSRF: true})
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST /plugin/houserules/write with no csrf token: status %d, want 403. The sub-router's own verb decides this per request, and the POST case is the one the whole boundary exists for.",
				resp.StatusCode)
		}
	})

	t.Run("a mutation with the session's own token is served", func(t *testing.T) {
		t.Parallel()
		resp := s.do(&call{method: http.MethodPost, path: "/plugin/houserules/write"})
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST /plugin/houserules/write with a valid csrf token: status %d, want 200", resp.StatusCode)
		}
	})
}
