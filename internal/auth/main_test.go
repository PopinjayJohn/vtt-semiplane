package auth

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// maxFullCostDerivations is how many real Argon2id derivations the whole suite
// may perform.
//
// It is a ceiling, not a target. The agreed parameters cost roughly 140 ms
// each on an ordinary machine, so the suite is budgeted at a few seconds of
// argon2 and the fixtures use a cheap parameter set instead — which is only
// possible because the costs travel inside the hash. A future test that reaches
// for the real parameters "just for realism" adds about a seventh of a second
// each time, and without this number nothing says so until CI takes half a
// minute and somebody raises the timeout, which AGENTS.md §11 forbids.
//
// The count is deterministic for a given set of tests, so a failure here means
// the budget was genuinely exceeded rather than that the machine was slow.
const maxFullCostDerivations = 64

// TestMain reports the argon2 bill and refuses to pass a suite that went over
// it.
//
// Reporting the number unconditionally is deliberate: the cost of this package
// is the first thing a maintainer needs to know about, and a figure that only
// appears on failure is a figure nobody reads.
func TestMain(m *testing.M) {
	started := time.Now()
	code := m.Run()

	derivations := fullCostDerivations.Load()
	fmt.Fprintf(os.Stderr, "internal/auth: %d full-cost argon2id derivations, %s, budget %d\n",
		derivations, time.Since(started).Round(time.Millisecond), maxFullCostDerivations)
	if derivations > maxFullCostDerivations {
		fmt.Fprintf(os.Stderr,
			"internal/auth: the suite performed %d real argon2id derivations, over the budget of %d; "+
				"use hashPassphraseWith for fixtures\n", derivations, maxFullCostDerivations)
		code = 1
	}
	os.Exit(code)
}
