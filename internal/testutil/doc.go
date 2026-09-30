// Package testutil holds test infrastructure: temp vaults, a deterministic
// clock, and small fixtures.
//
// It is not an application harness, and there is no `Harness` here. A test that
// needs the whole app builds one for itself, and each of those lives in its own
// package's test files: a shared one would have to import `app`, and this
// package is imported by every test that wants a temp vault — so the app's
// whole dependency graph would sit behind all of them.
//
// It sits outside the dependency order rather than in it: `exempt` in
// architecture_test.go allows it to import anything. It imports nothing of ours
// today, which is what a shared test helper should look like — the exemption is
// the permission to reach in, not a record of having done so.
package testutil
