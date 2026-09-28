// Package authz is the single implementation of "may this principal do this
// thing to this resource".
//
// It owns the canonical vocabulary of the whole application — Role, Principal,
// Permission, Resource and the secret-visibility constants — because those
// types are referenced by every other package. It deliberately does NOT import
// internal/secrets: the arrow runs secrets -> authz, so that the redactor can
// ask CanReadSecret without a cycle. See AGENTS.md for the full dependency
// order.

package authz
