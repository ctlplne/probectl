# Contributing to probectl

Thanks for your interest in probectl. This guide explains how a change gets from
your editor to a merged pull request, and — just as importantly — *why* the few
hard rules exist. probectl is a self-hosted, multi-tenant network observability
platform, so a handful of its invariants (tenant isolation above all) are
load-bearing: a regression there is a security incident, not a bug. The CI gates
below exist to make those invariants impossible to break by accident.

If you read nothing else, read the **Non-negotiables** section.

## The shape of a change

Keep each pull request the **smallest coherent change** that does one thing.
Small PRs are easier to review, easier to revert, and far less likely to trip a
guardrail you didn't know about. If a change naturally splits in two (a refactor
plus a feature, say), make it two PRs.

The loop is the usual one — **plan → implement → test → document → PR** — with
one probectl-specific twist: the test and document steps aren't optional. A
change is "done" only when it compiles clean, its tests pass, the docs that
describe it are updated, and the guardrails hold (the full checklist is the
[Definition of Done](#definition-of-done) below, and it's mirrored in the PR
template you'll fill out).

1. Branch from `main` with a short descriptive name (e.g. `icmp-canary` or
   `fix-bgp-withdraw-parse`).
2. Make your change, with tests.
3. Run **`make ci`** locally — it runs the linters, the unit tests, and the
   cross-tenant isolation gate, which is exactly what CI runs first on your PR.
   Catching a red gate on your laptop is much cheaper than catching it in CI.
4. Open a pull request using the template. Fill in the checklist honestly — the
   reviewer reads it as a summary of what you verified.

The complete toolchain, every `make` target, and the names of the CI jobs are
documented in [`docs/development.md`](docs/development.md); the dev-stack
services and ports are in [`docs/configuration.md`](docs/configuration.md).

## Commits — Conventional Commits

Commit messages follow [Conventional
Commits](https://www.conventionalcommits.org/): `type(scope): subject`. The
subject is imperative, ≤100 characters, and has no trailing period.

```
feat(canary): add ICMP network test
fix(bgp): handle empty AS_PATH in withdraw messages
docs(install): correct the compose cert path
```

The allowed types are `feat`, `fix`, `docs`, `chore`, `test`, `refactor`,
`perf`, `build`, `ci`, `style`, and `revert`. This is enforced in CI by the
`commitlint` job (config: `commitlint.config.mjs`) — a non-conforming subject
fails the build. To get the format right locally, enable the message template
once:

```sh
git config commit.template .gitmessage
```

## Sign-off — Developer Certificate of Origin (DCO)

Every commit must carry a **`Signed-off-by:` trailer**. By adding it you certify,
under the [Developer Certificate of Origin 1.1](https://developercertificate.org/),
that you wrote the change (or otherwise have the right to submit it) under the
project's license. The easy way is the `-s` flag, which appends the trailer
using your `git` identity:

```sh
git commit -s
```

CI enforces this in the **`dco`** job, which runs a dependency-free
`scripts/check_dco.sh` over every commit in the PR and fails if any commit is
missing the trailer. It is a required merge gate. The DCO applies to commits
going forward.

A **Contributor License Agreement (CLA)** may additionally be required. That
decision, the project's `LICENSE`, and the SPDX headers all depend on the
licensing outcome that is still being finalized — until then, source files carry
a placeholder `SPDX-License-Identifier: LicenseRef-probectl-TBD`, which will be
replaced in a single pass once the license is chosen.

## Definition of Done

A change is complete only when **all** of these hold:

- It **compiles** and is lint-clean — `gofmt` + `go vet` + `golangci-lint` for
  Go, `ruff` + `black` for the Python analyzer. (`make lint` runs all of them.)
- **Unit tests** pass, plus any **integration tests** relevant to the change
  (the integration suite runs against the real `test/` dependency stack).
- The **OpenAPI spec** and the **`docs/`** are updated in the same PR — there are
  no undocumented API routes.
- Any **schema change** ships an **idempotent migration** (`IF NOT EXISTS`,
  `ON CONFLICT`), and any new tenant-owned table carries `tenant_id` with its
  index/partition from the *first* migration.
- Any **new config key** is documented in `docs/configuration.md`.
- The feature is **self-observable** — it emits the logs and metrics that let an
  operator see it working (probectl observes probectl).
- The **security guardrails below hold.**

## Non-negotiables

These are the rules a reviewer cannot wave through. If a task seems to require
breaking one, that's a signal to stop and discuss the design, not to work around
it.

- **Tenant isolation is the outermost boundary.** Cross-tenant data leakage is
  the highest-severity failure in this codebase. Every data path is scoped by
  `tenant_id` at the **storage and query layer** (Postgres RLS, ClickHouse row
  policies, per-tenant prefixes) — *not* by handler code alone, which is only the
  second line of defense. **Any change to a data-access path must come with a
  cross-tenant isolation test.** The standing `cross-tenant-isolation` CI gate
  runs the suite (`make test-isolation`); a bypass fails the build. When in
  doubt, fail closed and return nothing.
- **No phone-home.** Never add default outbound telemetry, analytics beacons, or
  call-home behavior. License verification is offline local math; open-data
  fetches are read-only, cached, and degrade gracefully.
- **Crypto only through `internal/crypto`.** Never call cryptographic primitives
  from handlers or services — the abstraction exists so a FIPS-validated module
  can be compiled in. A CI lint guard rejects primitive imports elsewhere.
- **TLS on every listener; secrets never in code.** Agent↔control-plane is mTLS;
  the API, UI, OTLP, and MCP surfaces are HTTPS; outbound fetches validate
  certificates. Never hardcode credentials or log a secret. When a required
  secure channel, credential, or signature is missing, fail closed.
- **Audit everything.** Config changes and data-access actions go to the
  tamper-evident audit log; provider-plane and break-glass actions go to a
  separate provider audit stream.

## Proto schemas are append-only

The protobuf schemas in `proto/` are the **wire contract** between agents, the
bus, and the control plane — and the bus history is replayable, so a breaking
change can strand deployed agents and corrupt the ability to re-read old events.
Because of that, schemas are **additive-only**, enforced by the **`buf breaking`
gate** in the `proto` CI job (it compares your branch against `main` and blocks
the merge on any incompatible change).

If you genuinely need an incompatible change, the path is to ship a **new
versioned package** (`probectl.<domain>.v2`) alongside the old one — never mutate
a published message. Overriding the gate for a field that provably never shipped
in a release requires explicit maintainer sign-off in the PR.

## Where to ask

If you're unsure how a change interacts with the tenant boundary, crypto, auth,
audit, the editions split (`ee/` vs core), or an external data source — ask in
the PR or an issue before writing a lot of code. The established convention is
almost always the right default, and the maintainers would much rather discuss a
design up front than unwind it in review.
