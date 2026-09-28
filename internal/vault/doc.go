// Package vault is the canonical file store: the markdown files, attachments,
// and the .semiplane/ directory beside them.
//
// The vault is the source of truth. SQLite is a derived cache that can be
// discarded at any moment; every write leaves the file as the authority.
//
// Path is the only way a user-supplied string becomes a filesystem path, and
// its constructor is the only place containment is established. Nothing in the
// codebase may do filepath.Join(root, userInput) directly.

package vault
