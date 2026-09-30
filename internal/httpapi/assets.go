package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/app"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
	"github.com/go-chi/chi/v5"
)

// assetContentTypes is the whole content-type table, as a constant map.
//
// It is a map rather than a switch on the extension because the set of files is
// closed and known: the stylesheet, the shell script, the icon sprite and the
// vendored DataStar bundle. A file whose name is not in this table is a 404, not
// a guess, and no file is ever served under a type this table did not name.
var assetContentTypes = map[string]string{
	"app.css":              "text/css; charset=utf-8",
	"app.js":               "text/javascript; charset=utf-8",
	"icons.svg":            "image/svg+xml",
	"vendor/datastar.js":   "text/javascript; charset=utf-8",
	"favicon.ico":          "image/vnd.microsoft.icon",
	"manifest.webmanifest": "application/manifest+json",
}

// asset is the only file-serving route in the app.
//
// It serves from an embedded filesystem, never from the vault and never from
// the directory the executable happens to be in. That is what makes a build a
// single file, and it is also the structural half of §2.5: a page's script, its
// stylesheet and its icon cannot be redirected anywhere, because there is no
// path from this handler to anything that is not in the binary.
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "*")
	if name == "" {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	// path.Clean plus a rejection of any cleaned name that is not the one asked
	// for: a request for ../../etc/passwd cleans to something outside the
	// embedded filesystem, and fs.ValidPath refuses it, but a request for
	// "vendor/../app.css" would clean to a name that *is* valid, so the round
	// trip is checked rather than trusted.
	clean := path.Clean(name)
	if clean != name || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	ctype, ok := assetContentTypes[clean]
	if !ok {
		// The table is the allow-list. A file that is in the binary but not in
		// the table is not reachable over HTTP, which is how a debug artefact
		// shipped by accident stays unreachable.
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	body, err := fs.ReadFile(s.assets, clean)
	if err != nil {
		s.writeError(w, r, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", assetCacheControl(clean))
	// The bytes come out of the binary and were not user input, but the header
	// costs nothing and it is the belt to the nosniff braces.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, clean, assetModTime, bytes.NewReader(body))
}

// assetModTime is the modification time reported for every embedded asset.
//
// It is fixed rather than the build time, deliberately: it must be stable across
// builds so that a browser's cached copy and this binary agree, and a build
// timestamp would make every rebuild invalidate every visitor's cache for a file
// whose content did not change.
var assetModTime = time.Unix(0, 0).UTC()

// assetCacheControl is how long a browser may keep an asset.
//
// Long for a fingerprinted-looking name, and in practice never, because the
// names are stable: a client that has the current one has the current bytes, and
// a new build overwrites them. A short max-age with must-revalidate would be the
// tidier choice if the names carried a hash, and they do not — so the honest
// answer is a modest cache and a revalidation.
func assetCacheControl(name string) string {
	if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css") {
		return "public, max-age=3600, must-revalidate"
	}
	return "public, max-age=86400"
}

// healthz is the liveness probe: the process is running and can answer.
//
// It touches no database and reads no configuration, because a liveness probe
// that fails when the disk is slow turns a degraded vault into a restart loop.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz is the readiness probe: the vault is open and the index is current.
//
// It answers the boot state rather than re-deriving it, and it says which
// generation the authorization world is in so that a client holding a stream
// can tell whether its stream is stale. It carries no page title, no secret id
// and no file content: a probe is reachable by anything that can open a socket.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	// A missing boot state is "not ready", not a fault: a vault that has never
	// finished its first index pass has nothing to say about readiness, and a
	// probe that reported 500 for that would page somebody for a vault that is
	// doing exactly what it should.
	state, err := store.MetaGet(r.Context(), s.db.Reader(), store.KeyBootState)
	if errors.Is(err, store.ErrNoRows) {
		state = store.BootStateIndexing
	} else if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable)
		return
	}
	generation, err := store.AuthzGeneration(r.Context(), s.db.Reader())
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable)
		return
	}
	status := http.StatusOK
	if state != store.BootStateReady {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, readyReport{
		Status:          state,
		AuthzGeneration: generation,
		Build:           s.build,
		// The port is echoed so that a proxy or a port-forward script can read
		// it back out of the probe, and it is a number the client already knows.
		Port: s.cfg.Port,
	})
}

// readyReport is the readiness payload.
type readyReport struct {
	// Status is store.BootStateReady or store.BootStateIndexing.
	Status string `json:"status"`
	// AuthzGeneration is what a stale live-push stream compares against.
	AuthzGeneration int64 `json:"authz_generation"`
	// Build is the version, commit, date and Go version of this binary.
	Build app.BuildInfo `json:"build"`
	// Port is the configured port, which need not be the one bound.
	Port int `json:"port"`
}

// writeJSON writes a small JSON response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The payloads here are fixed shapes built in this file, so an encoding
	// failure is not a client error and there is nothing to fall back to.
	_ = json.NewEncoder(w).Encode(body)
}
