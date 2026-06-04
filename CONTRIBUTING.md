# Contributing to probectl

probectl is built one small, CI-backed sprint at a time. Before starting work,
read the canonical context (kept in the private Cowork working folder, not in
this repo): `CLAUDE.md`, `probectl-PRD-v0.5.md`, and `probectl-sprint-plan.md`. Then
read the active sprint brief. **Work one sprint at a time; do not exceed the
active sprint's scope.**

## Workflow

1. **Plan → implement → test → document → PR.** Keep the change the smallest
   coherent one that satisfies the sprint.
2. Branch from `main` (e.g. `s7-icmp-canary`).
3. Run `make ci` (lint + test + the cross-tenant isolation gate) before pushing.
4. Open a PR using the template; it must reference the **sprint ID** and the
   **requirement (F-) IDs** it implements.

## Commits — Conventional Commits

Format: `type(scope): subject` (≤100 chars, imperative, no trailing period),
referencing the sprint/F-IDs, e.g.:

```
feat(canary): ICMP network test [S7, F2]
```

Allowed types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`,
`build`, `ci`, `style`, `revert`. Enforced by commitlint in CI. Enable the local
message template with `git config commit.template .gitmessage`.

## Definition of Done

See `CLAUDE.md §8`. In short: compiles and is lint-clean; unit + relevant
integration tests pass; OpenAPI + `docs/` updated; any DB change ships an
idempotent migration; new config keys are documented; the feature is
self-observable; and the security guardrails (`CLAUDE.md §7`) hold.

## Non-negotiables

- **Tenant isolation is the outermost boundary.** Never write a data-access path
  that can return cross-tenant rows; a cross-tenant isolation test accompanies
  any data-path change (`make test-isolation`).
- **No phone-home**, no secrets in code, crypto only through `internal/crypto`,
  TLS on every listener, audit everything. See `CLAUDE.md §7`.

## Local development

See [`docs/development.md`](docs/development.md) for the toolchain, `make`
targets, and CI job names, and [`docs/configuration.md`](docs/configuration.md)
for the dev-stack services and ports.
