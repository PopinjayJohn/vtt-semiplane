// Package testutil holds test infrastructure: temp vaults, a deterministic clock,
// fixtures, and an in-process harness that boots the whole app on a random port
// with seeded users for each role.
//
// It sits outside the dependency order, above app, because it is allowed to
// import everything.

package testutil
