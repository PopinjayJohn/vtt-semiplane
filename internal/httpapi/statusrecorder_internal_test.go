package httpapi

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The status recorder's two jobs, and the tests that hold them to those.
//
// It has a second writer on it since the live-push stream arrived. Every other
// route in this package writes its response from the goroutine running the
// handler, so the shape is invisible everywhere else: `subscriber.serve` starts a
// goroutine to drain the outbound queue and is allowed to return — taking the
// handler with it — while that goroutine is still inside Write or Flush. The
// request logger then reads the counters the same goroutine is incrementing, and
// the socket is being flushed underneath a response net/http has already
// finished.
//
// So there are two properties here, and they are not the same one. The counters
// are a data race, and a mutex is the answer to that. The late Flush is a write
// into a finished response, and no mutex answers that: only the latch can, which
// is why close() exists and why the two halves are one critical section.

// countingWriter is a response writer that records what reached it.
//
// Its two counters are atomic and its body is a mutex-guarded string, and the
// asymmetry is load-bearing: the interleave counters are deliberately *not* taken
// under a lock that the Write holds, because a writer that serialised them
// itself would answer the question the serialisation test asks no matter what
// the recorder did. The counters here are a witness, not a gate.
type countingWriter struct {
	header   http.Header
	mu       sync.Mutex
	body     strings.Builder
	status   int
	inFlight atomic.Int64
	flushed  atomic.Int64
	// flushInsideWrite counts a Flush that arrived while a Write was in progress,
	// which is the interleave http.ResponseWriter does not permit.
	flushInsideWrite atomic.Int64
}

func newCountingWriter() *countingWriter {
	return &countingWriter{header: make(http.Header)}
}

func (c *countingWriter) Header() http.Header { return c.header }

func (c *countingWriter) WriteHeader(code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status == 0 {
		c.status = code
	}
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body.Write(b)
}

func (c *countingWriter) Flush() {
	if c.inFlight.Load() > 0 {
		c.flushInsideWrite.Add(1)
	}
	c.flushed.Add(1)
}

func (c *countingWriter) state() (body, flushes, flushesInsideWrite int) {
	c.mu.Lock()
	n := c.body.Len()
	c.mu.Unlock()
	return n, int(c.flushed.Load()), int(c.flushInsideWrite.Load())
}

// TestTheRecorderRefusesToWriteAfterTheHandlerReturns is the property the latch
// exists for, and it is the half no lock on the counters could have given.
//
// Without it, a stream's writer goroutine that outlives its handler forwards a
// Write and a Flush into a response the server has already finished: the bytes
// land after the chunked terminator, or not at all, and the connection is
// corrupt. With it, both are refused and the stream's own teardown decides when
// the connection ends.
func TestTheRecorderRefusesToWriteAfterTheHandlerReturns(t *testing.T) {
	t.Parallel()

	t.Run("a write after the handler returned is refused", func(t *testing.T) {
		t.Parallel()
		w := newCountingWriter()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		rec.WriteHeader(http.StatusOK)
		if _, err := rec.Write([]byte("before")); err != nil {
			t.Fatalf("the write before the handler returned: %v", err)
		}
		status, written := rec.close()

		// The count reported to the log includes the write that really happened.
		// Reporting a short one would be a lie about a request whose bytes did
		// reach the client, and a log an operator reads is the wrong place to be
		// conservative.
		if status != http.StatusOK {
			t.Errorf("the log was told %d, want 200", status)
		}
		if written != len("before") {
			t.Errorf("the log was told %d bytes, want %d", written, len("before"))
		}

		n, err := rec.Write([]byte("after"))
		if err != nil {
			t.Errorf("a refused write reported an error: %v", err)
		}
		if n != len("after") {
			t.Errorf("a refused write reported %d bytes, want %d: a caller that checks the count must not see a short write loop as a failure", n, len("after"))
		}

		body, flushes, _ := w.state()
		if body != len("before") {
			t.Errorf("the wrapped writer received %d bytes, want %d: something reached the socket after the handler returned", body, len("before"))
		}
		if flushes != 0 {
			t.Errorf("the wrapped writer was flushed %d times after the handler returned, want 0", flushes)
		}
	})

	t.Run("a second status after the handler returned is refused", func(t *testing.T) {
		t.Parallel()
		w := newCountingWriter()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.close()
		rec.WriteHeader(http.StatusTeapot)
		if got := w.status; got != 0 {
			t.Errorf("the wrapped writer was given status %d, want 0: nothing may reach a finished response", got)
		}
		if status, _ := rec.close(); status != http.StatusOK {
			t.Errorf("the recorded status is %d, want the 200 the handler chose", status)
		}
	})
}

// TestTheRecorderHoldsItsLockAcrossTheWrappedWrite is the reason the mutex is
// held over the forwarded call and not only over the counters.
//
// http.ResponseWriter requires a Write and a Flush not to interleave, and the
// two arrive from two different goroutines here. A lock that guarded only
// `written` would let a Flush land in the middle of a Write, which is the same
// class of corruption as the late one and much harder to notice: it shows up as
// a stream that occasionally desynchronises rather than as a build that fails.
func TestTheRecorderHoldsItsLockAcrossTheWrappedWrite(t *testing.T) {
	t.Parallel()

	w := newCountingWriter()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 64 {
			_, _ = rec.Write([]byte("x"))
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 64 {
			rec.Flush()
		}
	}()
	wg.Wait()

	_, flushes, inside := w.state()
	if flushes != 64 {
		t.Errorf("the wrapped writer was flushed %d times, want 64", flushes)
	}
	if inside != 0 {
		t.Errorf("%d flushes arrived in the middle of a write: the recorder let a flush interleave with the write beside it", inside)
	}
}

// TestTheRecorderIsSafeUnderAConcurrentStreamWriter is the race itself, stated
// as a shape rather than as a schedule.
//
// It is deliberately unsynchronised. Any channel or WaitGroup between the two
// goroutines would create the happens-before edge that the race detector looks
// for, and the test would then pass against the very bug it exists to catch — the
// same trap AGENTS.md §11 records for the non-recursive plugin walker. Started
// together, the stream writer's Write and Flush and the logger's read of the
// counters are unordered, which is exactly the production condition.
//
// Without -race this asserts nothing about ordering and passes either way; the
// proof is `./scripts/test.sh -race`.
func TestTheRecorderIsSafeUnderAConcurrentStreamWriter(t *testing.T) {
	t.Parallel()

	w := newCountingWriter()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	const (
		writers = 4
		rounds  = 256
	)
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				_, _ = rec.Write([]byte("stream"))
				rec.Flush()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			// What requestLogger does once the handler is gone: latch, then read.
			status, written := rec.close()
			if status != http.StatusOK {
				t.Errorf("the recorded status is %d, want the 200 the recorder was built with", status)
			}
			if written < 0 {
				t.Errorf("the recorded byte count is %d, which cannot be true", written)
			}
		}
	}()
	close(start)
	wg.Wait()
}
