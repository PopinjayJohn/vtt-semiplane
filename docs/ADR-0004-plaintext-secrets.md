# ADR-0004: Secrets are plaintext at rest

Status: accepted · Date: 2026-09-28 · Plan decision D4, revisited by U1

## Context

A DM writes hidden information into the same Obsidian vault everyone uses:
"Door 2 is trapped, roll a save-or-suffocate" next to the description the
players are allowed to read. The app's job is to show each person a different
version of that file.

The obvious answer is to encrypt the secret bodies. The design question is what
that would actually protect, and against whom.

## Decision

**Secret bodies are stored in plaintext, in the Markdown file and in the
database.** There is no at-rest encryption in v1.

The protection is:

1. **Filesystem permissions.** The vault is `0700`, the database `0600`, backups
   `0600`. The binary warns when the platform offers no equivalent (Windows
   ACLs).
2. **Server-side authorization.** Every read of a secret body goes through
   `authz.CanReadSecret`; every query that can return a secret-derived row
   carries `authz.SecretVisibleSQL`. This is where the real work is, and it is
   the part that also protects a database that were encrypted.
3. **No derived copies.** A secret body enters no FTS table except
   `secret_fts` while its visibility is `table`, no cache, no log, no
   `data-*` attribute, no revision until the file is written.
4. **No outbound network.** Nothing leaves the machine, so there is no
   exfiltration path to reason about.

## Rationale

- **The threat model is a LAN, not a data centre.** The realistic losses are a
  stolen laptop, a copied backup directory, a vault synced to cloud storage, or
  a `semiplane.db` file read off the disk. Encryption at rest with a key derived
  from something the binary can read does not help against any of those: a
  determined reader of the disk gets the key too.
- **Encryption in the file would break the file's usefulness.** The vault is
  Obsidian-compatible on purpose. A DM edits notes in Obsidian on a laptop
  between sessions; the app must index what the file says, byte for byte.
  An encrypted body inside the fence would be unreadable in Obsidian and would
  make the "edit the same page in two apps and resolve the conflict" story
  incoherent.
- **It keeps one renderer.** The security argument for the whole design is that
  there is exactly one place a secret becomes readable and one predicate that
  decides. Adding a storage format adds a second place for a body to be
  decrypted and a second place for a decrypted string to live.
- **The residual risk is stated, not hidden.** A stolen disk is a full
  compromise. That is in the README, in this ADR, and in the backup command's
  help text.

## The migration path is designed for, not deferred

The `visibility=` directive is already a stable key on the fence line, and only
metadata is in cleartext. A future
`storage=aesgcm:<nonce>` token requires:

- no syntax change beyond one new directive key,
- no database migration for the body column,
- no change to any authorization path,
- one change in `secrets.Store`, because every layer above it treats the body as
  an opaque blob.

The `storage=` hook is the reason this decision is cheap to revisit rather than
expensive.

## Consequences

- Backup media inherits the vault's sensitivity, and is documented as such.
- Revoking a secret does not make the *old bytes* unrecoverable from a backup
  taken before the revoke. This is stated in the UI and the docs rather than
  papered over; a player who was online when a secret was revealed has seen it
  (S17).
- `TestSecretFixturesNeverLeak` is the compensating control for the whole
  design, and it is the single highest-value test in the project. It runs on
  every CI run over every page type, as every role, against the response body,
  the headers and the `data-signals` payload.
