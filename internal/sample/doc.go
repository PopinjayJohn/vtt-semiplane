// Package sample is the written campaign the binary carries.
//
// An operator who downloads one file and runs it should find a campaign in the
// vault, not an empty folder and a setup form. That is the whole reason this
// package exists: the alternative is a second artefact to download, and a second
// artefact is a second thing that can be the wrong version, or absent, or from a
// mirror.
//
// # What is here
//
// `campaign/` is ordinary Obsidian-compatible Markdown: frontmatter, wikilinks,
// images, and fenced blocks that hide DM-only text. Nothing about it is special
// to this app. A DM who wants to edit it edits the files, in Obsidian or in a
// text editor, and the app indexes what is on disk.
//
// The fence syntax is the one §6 of the plan defines, and the rules on it — the
// closed key set, the quoting requirement on a value with a space, the fact that
// a fence whose directive cannot be read is hidden rather than made public — are
// documented on the campaign's own "Writing secrets" page, because that is where
// an author will look. This package doc deliberately does not restate them: a
// copy of the grammar here is a copy that can disagree with internal/md.
//
// # What this package is not
//
// It is not a fixture and not a test double. The secret-leak suite in
// internal/httpapi does not run against this campaign: it runs against its own
// hand-built fixture in `leaksuite_test.go`, which exists to walk every route as
// seven principals and needs its page ids and its tokens pinned as literals.
//
// What stops the two from drifting into being two different demonstrations is
// TestSampleCampaignExercisesEveryFeature, in this package, which asserts that
// this campaign carries the feature classes the app has to demonstrate: the page
// types the host knows, a wikilink graph that connects, the tags the panel
// reads, secret fences in each of the three visibilities, a fence whose
// directive deliberately cannot be read, the house-rule split, and an
// attachment referenced only from inside a secret.
//
// # Why the walk is not here
//
// The extraction — writing the campaign into a vault that does not have it — is
// not in this package, and the reason is the import boundary rather than a
// preference. internal/architecture_test.go holds this package to the plugin
// boundary: it may import `plugin`, `md`, `store`, `web`, `authz` and `secrets`,
// and explicitly not `vault`. So the code that calls `vault.Write` cannot live
// here. It is a method on `*App` in internal/app, which is exempt from the
// dependency order and is the composition root — which is where a walk that
// reaches into the vault belongs anyway.
package sample
