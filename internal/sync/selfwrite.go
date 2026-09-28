package sync

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/obs"
	"github.com/PopinjayJohn/vtt-semiplane/internal/store"
)

// selfwritePruneInterval is how often expired registrations are swept. The
// table is keyed by path, so it cannot grow without bound, but an entry per file
// ever written is still an entry per file ever written.
const selfwritePruneInterval = 5 * time.Minute

// Selfwrites implements vault.SelfwriteStore over the index database.
//
// It exists as a type rather than as two free functions because vault declares
// the interface, and vault sits below store: the implementation is where the
// arrow may point up, and the interface is how the arrow is declared without an
// import. Nothing in internal/vault may import internal/store, and this is the
// file that makes that true rather than merely intended.
//
// Suppression is by content hash, never by time. A time window alone would
// swallow a DM's edit to a page the app happened to save ten seconds earlier; a
// hash means the app suppresses only the bytes it wrote, so a genuine external
// edit inside the window still lands.
type Selfwrites struct {
	db  *store.DB
	log *obs.Logger

	// clock is the time source, injected so a test never depends on wall time.
	// SetClock must be called before the first PutSelfwrite, and the race
	// detector is what enforces that rather than a lock on every read.
	clock obs.Clock
	// lastPruneUnixNano guards the sweep so a watcher flushing every 300 ms does
	// not issue a DELETE for every batch. It is an atomic rather than a field
	// under a lock because two saves on different paths reach here at once.
	lastPruneUnixNano atomic.Int64
}

// NewSelfwrites returns a Selfwrites over db. A nil log discards.
func NewSelfwrites(db *store.DB, log *obs.Logger) *Selfwrites {
	return &Selfwrites{db: db, log: loggerOf(log), clock: obs.SystemClock}
}

// SetClock replaces the time source. It exists for tests and for a boot that
// takes its clock from configuration.
func (s *Selfwrites) SetClock(clock obs.Clock) {
	if clock != nil {
		s.clock = clock
	}
}

// PutSelfwrite records the bytes this process just wrote to path. The expires
// argument is the caller's window and is honoured as given, so
// vault.Writer.SelfwriteWindow stays the single place that decides how long a
// self-write is suppressible.
func (s *Selfwrites) PutSelfwrite(ctx context.Context, path string, hash []byte, expires time.Time) error {
	if err := store.RecordSelfwrite(ctx, s.db.Writer(), path, hash, s.clock()); err != nil {
		return err
	}
	s.prune(ctx)
	return nil
}

// IsSelfwrite reports whether path currently holds bytes this process wrote and
// has not expired the registration for.
//
// It reads through the read pool rather than the write pool, which is the whole
// point of the split: the watcher asks this question while the indexer may be
// holding the single write connection inside a transaction, and a check that
// queued behind that transaction would delay every event in the batch.
func (s *Selfwrites) IsSelfwrite(ctx context.Context, path string, hash []byte) (bool, error) {
	return store.SelfwriteMatches(ctx, s.db.Reader(), path, hash, s.clock())
}

// Prune removes registrations that expired before now and returns how many went.
func (s *Selfwrites) Prune(ctx context.Context) (int64, error) {
	return store.PruneSelfwrites(ctx, s.db.Writer(), s.clock())
}

// prune sweeps expired registrations, at most once per selfwritePruneInterval.
// A failure is logged rather than returned: the caller is a save that has
// already succeeded, and failing it here would report a user's write as failed
// because a housekeeping DELETE did not land.
func (s *Selfwrites) prune(ctx context.Context) {
	now := s.clock()
	nanos := now.UnixNano()
	last := s.lastPruneUnixNano.Load()
	if last != 0 && now.UnixNano()-last < int64(selfwritePruneInterval) {
		return
	}
	// One sweep per interval across every goroutine: the winner writes the new
	// stamp, and a loser sees the fresh stamp on its next load and stops.
	if !s.lastPruneUnixNano.CompareAndSwap(last, nanos) {
		return
	}
	if _, err := store.PruneSelfwrites(ctx, s.db.Writer(), now); err != nil {
		s.log.WarnContext(ctx, "could not prune self-write registrations",
			"action", "selfwrite.prune", "err", err.Error())
		s.lastPruneUnixNano.Store(0)
	}
}
