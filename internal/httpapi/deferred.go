package httpapi

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// Deferred is a handler that is mounted before the real one exists.
//
// It exists because of a boot-order constraint rather than a design preference.
// app.Boot needs the handler to decide whether to bind a listener, and the
// handler needs the store, the writer and the indexer that Boot is what
// creates. Something has to break the cycle, and the two candidates are a
// handler that answers 503 until the real one is installed, or a two-phase boot
// in app that would change a finished package.
//
// So: the mount point is a Deferred, the composition root installs the real
// handler immediately after Boot returns, and anything that arrives in the
// window between the listener accepting and the install landing is answered 503
// with a Retry-After. That window is a few microseconds, it is reported in the
// boot banner rather than hidden, and the alternative — a nil handler that panics
// on the first request, or a boot that binds nothing at all — is worse.
type Deferred struct {
	inner atomic.Pointer[http.Handler]
	// installing is closed the first time Install is called, so a second install
	// is refused rather than silently swapping the handler under a request.
	installing chan struct{}
	once       sync.Once
}

// NewDeferred returns an unmounted Deferred handler.
func NewDeferred() *Deferred {
	return &Deferred{installing: make(chan struct{})}
}

// Install mounts the real handler. It may be called once; a second call is
// ignored, because a handler that changed mid-flight would answer some requests
// with one policy and some with another.
func (d *Deferred) Install(h http.Handler) {
	if h == nil {
		return
	}
	d.once.Do(func() {
		d.inner.Store(&h)
		close(d.installing)
	})
}

// Installed reports whether the real handler has been mounted.
func (d *Deferred) Installed() bool {
	select {
	case <-d.installing:
		return true
	default:
		return false
	}
}

// ServeHTTP answers with the real handler once there is one.
func (d *Deferred) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := d.inner.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusServiceUnavailable)
	// The body says what it is and nothing else. An error page here would be
	// rendered by a renderer that does not exist yet, and a panic would be the
	// one thing worse than a 503.
	_, _ = w.Write([]byte("the server is still starting\n"))
}
