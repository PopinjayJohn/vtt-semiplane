// Package example is the plugin that exists to be refused.
//
// It is the demonstration half of §7 of the working agreement. A boundary is
// only evidence if something actually gets stopped by it, and "the host would
// have caught it" is not a test — AGENTS.md's own preamble forbids a rule
// documented as enforced when nothing enforces it. So this package is a
// first-party plugin that breaks five different ways, each aimed at a named
// host check, and the tests beside it assert that every refusal is *specific*:
// that the reason names the thing that was wrong. A plugin that is generically
// broken proves nothing about which check fired.
//
// Two limits on what this package claims, stated up front because §11 of the
// design plan requires them and a demo implying otherwise would be a lie:
//
//   - It demonstrates *registration* refusals, not a sandbox. A plugin is
//     compiled-in Go sharing the address space; one that wanted to misbehave
//     would simply do so. What the host prevents is a plugin misbehaving by
//     accident — two plugins both deciding that `character` is theirs, a
//     feature plugin inventing a game system's vocabulary, a page type
//     surviving the rollback of the plugin that contributed it.
//
//   - It is wrong at runtime and correct at compile time. Every violation here
//     is a declaration or a registration, never an import: a package that would
//     not compile is not evidence of anything, because the tests asserting the
//     refusal would never run.
//     TestThisPackageCompilesWithinTheBoundary is this package checking the
//     boundary on itself first, precisely because the whole claim is that the
//     boundary holds.
//
// One more thing this package is careful about: two of the five are refused by a
// check with no exported predicate — a feature plugin declaring page types, and a
// plugin colliding with another. Those two rows record every reserved-name claim
// as *not* refused, which is an assertion and not an omission: it proves that
// every other rule admits them, so the reason in a boot report cannot have come
// from reserved.go when the real cause was a kind violation or a collision. A
// case that could be refused for two different reasons is not evidence for
// either.
//
// The evidence comes in two layers. The tests that call plugin.CheckReservedPageType
// and plugin.CheckReservedRoute directly are about the *rule*; the tests that
// boot a real registry with plugin.Load are about the *host*. Neither layer
// asserts only that a plugin was refused: asserting that would pass against a
// host that refused everything for one unstated reason, which is exactly the
// shape of a boundary that is documented rather than enforced.
//
// One boundary judgement call, stated rather than buried: plugin.go imports
// net/http. AGENTS.md §7 forbids `net` in a plugin, and what it means is a
// socket — but a plugin that registers routes cannot name an HTTP handler type
// without it, so the choice is between the import and a route surface that
// cannot be written. The import is allowed.
//
// It is allowed by this package's own test rather than by assertion, and the
// test is strict about the difference between naming a client and calling one.
// Two of its three earlier versions were wrong and are worth recording: a byte
// grep failed on the paragraph above, and a token-stream grep failed on a
// qualified identifier, which is several tokens and cannot be found by joining
// them. Matching the selector in the syntax tree is the version that is right —
// so this file names the capability it does not have rather than the symbol,
// because TestNoOutboundNetwork greps bytes and a comment is a byte.
package example
