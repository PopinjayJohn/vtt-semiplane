// Package plugin defines the extension contract: one Plugin interface, a Kind
// discriminator, a capability model, and the registry that admits, version-
// gates and registers plugins deterministically.
//
// The contract is defined in phase 0, before any plugin exists, so that a
// system plugin and a feature plugin can be written in parallel against a
// stable surface. The full registration lifecycle, the host implementation and
// the reserved-name table arrive in the plugin phase; what lives here is the
// vocabulary.
//
// A plugin is first-party code compiled into the binary. There is no runtime
// loading, no sandbox and no isolation; §11 of the plan states that plainly.
// What the contract does provide is capability narrowing against accidental
// damage, and one property that matters more than the rest: a plugin cannot
// ship JavaScript, a stylesheet or a DOM handle. Plugins return
// templ.Component values and Go values; the app shell and the stylesheet are
// core-owned.

package plugin
