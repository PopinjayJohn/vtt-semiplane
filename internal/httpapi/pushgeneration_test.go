package httpapi_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PopinjayJohn/vtt-semiplane/internal/authz"
	"github.com/PopinjayJohn/vtt-semiplane/internal/httpapi"
)

// TestAPushRenderIsRefusedOnceTheAuthorizationGenerationHasMoved is the test for
// the guard that makes a live push safe rather than usually safe.
//
// The rule is absolute: a stream carries a trigger, never content, and ends on
// any authorization change. It was implemented as a race. A reveal bumps the
// generation and reindexes, in that order, and a content change in the same
// window produced a render whose bytes were computed against the *new* index
// while the subscriber still held its *old* entitlement. The stream was closed
// only by terminateStale, which sweeps on an interval, so anything rendered and
// flushed between the bump and the sweep reached a reader the stream was already
// entitled to have ended for. On a fast runner the sweep won; on the macOS job,
// whose runner is slower, it did not — and the suite reported a live push
// carrying a private body to a player.
//
// The window cannot be scheduled from outside, so it is opened from inside: the
// authz poll is pushed far out so the sweep cannot run, the generation is moved
// under an open stream, and a content change is then published. Without the poll
// change the test would pass whenever the sweep won, which is exactly the
// condition that made the bug intermittent.
func TestAPushRenderIsRefusedOnceTheAuthorizationGenerationHasMoved(t *testing.T) {
	t.Parallel()
	fx := seeded(t)
	// Long enough that the sweep cannot run inside the test. The fixture's
	// cleanup shuts the registry down, which stops the watcher, so this does not
	// leave a goroutine waiting on it.
	fx.hub.SetTimings(testWindow, time.Hour)
	player := fx.asUser(otherName, otherPass)
	es := fx.openStream(t, player, "Tavern.md")
	waitUntil(t, "the stream to be registered", func() bool { return fx.hub.Subscribers() == 1 })

	// The reader is entitled right now, and a render must still happen. Without
	// this the test would also pass on a stream that never renders anything,
	// which is the failure mode of a test whose subject is a refusal.
	fx.save(t, "Tavern.md", "Written before the generation moved.\n")
	es.waitFor(t, "a render for a reader whose entitlement has not moved",
		func(s string) bool { return strings.Contains(s, "event: "+httpapi.EventChanged) })

	// Now a reveal moves the generation, as it does for every subscriber at once.
	dm := fx.principalFor(t, dmName, authz.RoleDM)
	if err := fx.Secrets.Reveal(context.Background(), dm, "a1a1a1a1a1a1"); err != nil {
		t.Fatalf("reveal the Tavern's private secret: %v", err)
	}

	// Publish a content change, which is the thing that would have rendered the
	// newly readable body for a reader the stream should already have ended.
	fx.save(t, "Tavern.md", "Written after the generation moved.\n")

	// The stream is ended by the guard, because a stream whose entitlement moved
	// is a stream this file's contract says must be over.
	after := es.waitFor(t, "the stream to end on the generation moving",
		func(string) bool { return es.isClosed() })

	// Exactly one fragment on the whole connection: the one the positive control
	// was waiting for. A second one would be a render produced after the
	// generation moved, which is the bug — and counting the whole stream rather
	// than a suffix matters, because the first fragment is legitimately here and
	// a suffix-only check would be satisfied by an empty one.
	if got := countEvents(parseSSE(after), httpapi.EventFragment); got != 1 {
		t.Errorf("%d fragments on the connection, want 1: a render produced after the entitlement "+
			"moved is a body delivered to a reader the stream had already ended for", got)
	}
	// And the body that has just become readable is on it nowhere.
	assertNoLeak(t, "player", after)
}
