# ADR-0001: The canonical dependency order

Status: accepted · Date: 2026-09-28

## Context

The design plan §1 lists the packages in one order and then states a different
partial order in a parenthesis, and the two are not consistent. `store`'s own
queries must embed `authz.SecretVisibleSQL` verbatim — that is the whole point
of having one canonical predicate — so `store` imports `authz`. But the plan's
parenthetical order places `authz` above `secrets`, which would stop the
redactor from calling `authz.CanReadSecret`, and §8.5 says the redactor's whole
job is to ask that one function.

A dependency order that no package can satisfy is not a rule; it is a
contradiction that would be discovered by whichever agent hit it first and then
resolved locally, inconsistently.

## Decision

The canonical order, lowest first:

```
config < obs < authz < store < md < plugin < vault < auth < secrets < sync < search < httpapi < web
```

Two deliberate deviations from the plan, both to break a cycle the plan
contains:

- **`authz` sits below `store`.** store's queries embed
  `authz.SecretVisibleSQL`. authz is made safe to place that low by importing
  nothing of ours: it takes an `authz.Resource` struct handed to it by the
  service that already holds the row, so it never queries a database and never
  holds a `*sql.DB`.
- **The authz/secrets arrow runs `secrets → authz`.** The redactor asks
  `authz.CanReadSecret`; `authz` may not import `secrets`, and
  `TestPluginImportsAreWithinBoundary` plus `TestDependencyDirection` enforce
  it. To stop the two packages naming the three visibilities differently,
  `authz` owns the canonical `Visibility` constants and `secrets.Visibility` is
  an alias of the authz type.

`app` and `testutil` are exempt: `app` is the composition root and imports
everything; `testutil` boots the app in-process. `sample` is a leaf and imports
nothing internal.

## Consequences

- `TestDependencyDirection` in `internal/architecture_test.go` walks every
  package and fails on an import that goes upward. The rule is mechanical, not
  a review convention.
- The Go-level check (`authz.CanReadSecret`) and the SQL check
  (`authz.SecretVisibleSQL`) live in the same package on purpose, so a change to
  the visibility rules is one edit in one place and
  `TestSecretVisiblePredicateMatchesMatrix` can assert that the two agree across
  all twenty-four `(visibility, is_dm, is_author, is_page_owner)` combinations.
- A feature that needs data from two non-adjacent packages is in the wrong
  package. That is a design signal, not an obstacle to route around.
