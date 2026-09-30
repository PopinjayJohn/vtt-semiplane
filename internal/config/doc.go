// Package config resolves runtime configuration from flags, then environment,
// then defaults, and validates the result before anything opens a file.
//
// Stdlib flag parsing, not a config library: there are eight settings and a
// third-party config framework would add a dependency and a learning curve for
// nothing.
package config
