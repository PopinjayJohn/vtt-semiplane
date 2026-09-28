package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// countingQueryer counts the statements a query helper issues, so a test can
// assert the shape of the access rather than only its answer. The whole point of
// a bulk lookup is that it is one statement rather than one per name, and an
// answer-only test cannot tell the two apart.
type countingQueryer struct {
	Queryer
	calls int
	args  [][]any
}

func (c *countingQueryer) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	c.calls++
	c.args = append(c.args, args)
	return c.Queryer.QueryContext(ctx, query, args...)
}

// TestGetUserIDsByUsernames covers the three things the indexer's retry depends
// on: the answer, the case-folding that lets a fence write `Alice` for the
// account `alice`, and the one-statement shape.
func TestGetUserIDsByUsernames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	alice := seedUser(t, db.Writer(), "alice", "player")
	dorn := seedUser(t, db.Writer(), "dorn", "dm")
	q := &countingQueryer{Queryer: db.Reader()}

	names := []string{"Alice", "DORN", "nobody"}
	got, err := GetUserIDsByUsernames(ctx, q, names)
	if err != nil {
		t.Fatalf("look up usernames: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d ids, want 2: %v", len(got), got)
	}
	if got["alice"] != alice {
		t.Errorf("alice resolved to %d, want %d", got["alice"], alice)
	}
	if got["dorn"] != dorn {
		t.Errorf("dorn resolved to %d, want %d", got["dorn"], dorn)
	}
	if _, ok := got["nobody"]; ok {
		t.Error("a name that is not an account came back with an id")
	}
	if q.calls != 1 {
		t.Errorf("%d statements for %d names; the lookup is one query, not one per name", q.calls, len(names))
	}
	// Every name rides as a bind parameter, which is what keeps a fence
	// directive's value out of the statement text.
	for i, args := range q.args {
		if len(args) != len(names) {
			t.Errorf("statement %d bound %d values, want %d", i, len(args), len(names))
		}
	}
}

// TestGetUserIDsByUsernamesIsEmptySafe covers the two degenerate inputs a caller
// can produce by accident: no names, and a name that is the empty string. The
// empty name must not reach the statement as a stray placeholder, because a
// username can never be empty and the query would be asking about nothing.
func TestGetUserIDsByUsernamesIsEmptySafe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	seedUser(t, db.Writer(), "alice", "player")

	for _, names := range [][]string{nil, {}, {""}} {
		got, err := GetUserIDsByUsernames(ctx, db.Reader(), names)
		if err != nil {
			t.Fatalf("look up %v: %v", names, err)
		}
		if len(got) != 0 {
			t.Errorf("look up %v returned %v, want nothing", names, got)
		}
	}
}

// TestGetUserIDsByUsernamesChunks pins the chunking: a set larger than one
// statement's worth of bind parameters is asked about in several statements, and
// the answer is the same as if it had been asked in one.
func TestGetUserIDsByUsernamesChunks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := newMigratedDB(t)
	seedUser(t, db.Writer(), "alice", "player")

	names := make([]string, 0, userNameChunk+7)
	names = append(names, "alice")
	for i := range userNameChunk + 6 {
		names = append(names, fmt.Sprintf("ghost-%d", i))
	}
	q := &countingQueryer{Queryer: db.Reader()}
	got, err := GetUserIDsByUsernames(ctx, q, names)
	if err != nil {
		t.Fatalf("look up %d names: %v", len(names), err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ids, want 1: %v", len(got), got)
	}
	if q.calls != 2 {
		t.Errorf("%d statements for %d names, want one per chunk of %d", q.calls, len(names), userNameChunk)
	}
	total := 0
	for i, args := range q.args {
		if len(args) > userNameChunk {
			t.Errorf("statement %d bound %d values, over the %d chunk", i, len(args), userNameChunk)
		}
		if len(args) == 0 {
			t.Errorf("statement %d bound no values; a chunk must advance", i)
		}
		total += len(args)
	}
	if total != len(names) {
		t.Errorf("the statements bound %d names in total, want %d", total, len(names))
	}
}

func TestBindMarkers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, ""}, {-1, ""}, {1, "?"}, {2, "?,?"}, {3, "?,?,?"},
	} {
		if got := bindMarkers(tc.n); got != tc.want {
			t.Errorf("bindMarkers(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
