# ADR-0005: `internal/sample` is bytes; the extraction walk lives in `internal/app`

Status: accepted · Date: 2026-09-29

## Context

An operator who downloads one file and runs it should find a campaign in the
vault, not an empty folder and a setup form. That is the whole reason the sample
campaign exists, and it is why the alternative — a second artefact to download —
was never seriously on the table: a second artefact is a second thing that can be
absent, of the wrong version, or from a mirror.

The design plan puts the campaign in a package and names the function that
writes it: on first boot with an empty vault, `sample.Extract` writes the
campaign to `Campaigns/Ashes of the Hollow Crown/` through a non-clobbering walk.
Read as a Go package, that sentence cannot be built.

The obstacle is
[`ADR-0001-canonical-dependency-order.md`](ADR-0001-canonical-dependency-order.md).
`internal/sample` is outside the canonical order, and
`TestDependencyDirection` in
[`../internal/architecture_test.go`](../internal/architecture_test.go) holds it
to the **plugin boundary** — the same allow-list the plugin roots under
`internal/` are held to. `vault` is not on that list, and the reason it is not
is the one the list exists to enforce: `vault` is the only writer of a campaign
file, and a package that can call it can write to somebody's vault.

`sample.Extract` needs `vault.Resolve`, `vault.Read` and `vault.Write`. Written
as planned, it would have put a vault writer inside a package on the wrong side
of that boundary, and the gate that would have caught it is
`TestPluginImportsAreWithinBoundary` — so the plan's function could not be
written at all without a change to a rule the boundary is made of.

## Decision

**`internal/sample` is a name, a root and a list of byte slices. The walk that
turns that list into files in a vault is `(*App).extractSample`, in
[`../internal/app/sample.go`](../internal/app/sample.go).**

`sample` holds a `//go:embed` of `campaign/` and imports nothing of ours — not
`vault`, not `store`, not even `plugin`. `app` is the composition root and is
exempt from the order; it already has the vault root, the writer, the log and
the boot warnings, so it is where the decision about a file that is *already
there* could be made anyway.

The separation is the design, not a workaround. Three properties of the
extraction are all properties of the vault, not of the campaign:

- **The non-clobber rule.** One `vault.Read` per file and only `ErrNotFound`
  means absent — every other error is evidence of something other than absence,
  and treating one as absence is exactly the overwrite the rule refuses.
- **Containment.** The destination is built with `vault.Resolve`, not
  `vault.New`, because a DM who symlinks `Campaigns/` at a shared drive is
  doing something entirely ordinary and the walk would otherwise write outside
  the vault.
- **A file the vault would not index is not written at all**, asked through
  `vault.Ignored` on a name that came from a walk of a filesystem compiled into
  the binary — which is the point: the check is about *agreement* with the vault,
  not about trust, and it costs one map lookup to make that a property of the
  walk rather than of today's content.

All three are facts about the vault, so all three belong where the vault is.

## Alternatives considered

1. **Put `Extract` in `sample` and import `vault`.** The plan's spelling, and
   the one that cannot be built: it fails `TestDependencyDirection` and
   `TestPluginImportsAreWithinBoundary`, so shipping it means weakening a gate
   whose entire claim is that a plugin-shaped package cannot reach a vault
   writer. The weakening would then apply to every future sample that is a
   plugin's content, not just to this one.

2. **Hand `sample` a writer closure from `app` and let `Extract` keep the
   walk.** This is the shape that was chosen *within* the same separation — but
   it is worth naming why the walk did not move with it. A closure can only be
   `write-if-absent`; the decision that a file is already there, the decision
   that it is a directory rather than a file, and the decision to report rather
   than fail are three more, and all three are about the vault. Splitting them
   across the boundary would have produced a `sample` whose API had to grow a
   parameter for every vault fact it needed.

3. **Move the campaign outside `internal/` — a top-level `campaign/` with its
   own `//go:embed`.** Legal, and worse: it creates a second owner of embedded
   bytes and moves the drift check — `TestTheEmbeddedCampaignMatchesTheSourceTree`,
   which compares every embedded file with the source tree byte for byte — out of
   reach of the package the rest of the module can reason about.

4. **Ship the campaign as a separate download or a `go install` of content.**
   Refused for the reason in the Context: the product promise is one static
   binary, and a DM who cannot move that binary to a thumb drive has the design
   and none of the deployment.

## Consequences

- **`sample` is testable in isolation and the extraction is not.** The package
  owns "the bytes in the binary are the bytes on disk, in a stable order", and
  `TestFilesIsSortedAndWhole` plus
  `TestTheEmbeddedCampaignMatchesTheSourceTree` are the whole of it. Everything
  about touching a vault is tested in `internal/app`, where the vault is.
- **The extraction runs on every boot, not on a first boot.** Gating it on a
  marker would buy no work — the walk costs one resolve and one read per file
  and changes nothing when the campaign is there — and would add a state file
  whose loss, from a restored backup or a directory deleted with its marker,
  silently skips the campaign for ever. Being wrong in that direction is worse
  than re-checking. It also means a later binary that ships an extra page puts
  it into an existing vault on the next restart.
- **A file that cannot be written is a warning and not a boot failure.** The
  operator gets an app with a missing page and a banner that names it, which is
  the same bargain the vault walk makes for a file it cannot read.
- **The claim is proved against a shipped binary, not against a development
  tree.** `TestStandaloneBinaryRunsInEmptyDir`
  ([`../internal/app/sample_standalone_test.go`](../internal/app/sample_standalone_test.go),
  behind the `integration` build tag) builds `cmd/semiplane` with `CGO_ENABLED=0`,
  runs it from a directory with no repository near it, points it at an empty
  vault and asks the resulting server for a page. An in-process test cannot tell
  a shipped binary from a development one, and that difference is the entire
  point of the decision.
- **It forecloses plugin-supplied sample content inside this package.** A
  plugin that wants first-boot content of its own must have it written by the
  composition root, on the same terms, rather than reaching for a vault writer
  it is not allowed to hold.
- **A plugin cannot ship a campaign**, and neither can the design's own
  `internal/plugin`. That is the boundary doing its job, not an oversight, and
  `internal/app/plugins.go` is where the analogous decision — the plugin's
  `fs.FS` left deliberately `nil` — is recorded.
