// Package app is the composition root: the one place a vault is opened, the
// one place the boot order exists, and the one place a failure is turned into a
// refusal.
//
// It imports everything and is exempt from the dependency order, because its job
// is to wire the parts that cannot see each other. It contains no business
// logic: a query belongs in store, a markdown construct in md, a page type in a
// plugin, a route in httpapi. What is here is sequence, lifetime and report.
//
// The boot order is the package's reason to exist. A vault is opened by exactly
// one process at a time, and that claim is taken before any file or database in
// the vault is opened — so the lock is the second thing Boot does and the first
// thing it does that touches the vault. After it, in order: the audit log, the
// index database (quarantined and rebuilt if it cannot be read), a backup and the
// migration, the search index, a full pass over the vault, housekeeping, the
// watcher and its one reconciliation goroutine, the banner, and the listener.
// Each step that fails stops the boot and names itself, and the lock is released
// on the way out of every one of them.
//
// The same package holds the one-shot commands the binary dispatches — reindex,
// backup, restore, vault info, plugins list — because they are the same boot
// without a listener. That is the seam internal/httpapi will be mounted into: a
// caller that injects an http.Handler gets a served app, and a caller that
// injects nil gets a locked, migrated, indexed vault and a returned App.
package app
