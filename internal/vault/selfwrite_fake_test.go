package vault

import (
	"context"
	"sync"
	"time"
)

// fakeSelfwrites is an in-memory SelfwriteStore. It is the seam the watcher and
// the writer tests share, and it is deliberately naive: the point of the real
// one is the selfwrites table in sync, and neither this package nor its tests
// may depend on store to prove that a DM's edit still lands.
type fakeSelfwrites struct {
	mu     sync.Mutex
	seen   map[string][]byte
	expiry map[string]time.Time
	now    time.Time
	// failPut makes registration fail, for the path where the bytes are already
	// on disk and only the announcement is lost.
	failPut bool
	// calls counts the lookups, so a test can prove a nil store is asked
	// nothing rather than merely answering true.
	calls int
}

func newFakeSelfwrites() *fakeSelfwrites {
	return &fakeSelfwrites{
		seen:   map[string][]byte{},
		expiry: map[string]time.Time{},
		now:    time.Date(2026, 9, 28, 10, 4, 11, 0, time.UTC),
	}
}

func (f *fakeSelfwrites) PutSelfwrite(_ context.Context, path string, hash []byte, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPut {
		return errFakePut
	}
	f.seen[path] = append([]byte(nil), hash...)
	f.expiry[path] = expires
	return nil
}

func (f *fakeSelfwrites) IsSelfwrite(_ context.Context, path string, hash []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	want, ok := f.seen[path]
	if !ok {
		return false, nil
	}
	if f.expiry[path].Before(f.now) {
		return false, nil
	}
	return string(want) == string(hash), nil
}

// count is the number of lookups the store has served.
func (f *fakeSelfwrites) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

var errFakePut = &fakeError{"selfwrites is down"}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }
