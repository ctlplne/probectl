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
3. Run **`make ci`** locally — it runs the same core gates CI runs (the
   linters, the unit tests, and the cross-tenant isolation gate). The full
   pipeline runs a lot more — real databases, real kernels, real Kafka; see
   [`docs/ci-pipeline.md`](docs/ci-pipeline.md) — but catching a red core gate
   on your laptop is much cheaper than catching it in CI.
4. Open a pull request using the template. Fill in the checklist honestly — the
   reviewer reads it as a summary of what you verified.

The complete toolchain, every `make` target, and the names of the CI jobs are
documented in [`docs/development.md`](docs/development.md); the dev-stack
services and ports are in [`docs/configuration.md`](docs/configuration.md).

## Commits — Conventional Commits

Commit messages follow [Conventional
Commits](https://www.conventionalcommits.org/): `type(scope): subject` — a
small grammar that makes every commit's *kind* machine-readable, so a human
(or release tooling) can scan history and tell features from fixes from docs
without opening a single diff. The subject is imperative ("add", not "added" —
read it as *"this commit will…"*) with no trailing period, and the whole
header line stays within 100 characters.

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

Every commit must carry a **`Signed-off-by:` trailer** (a trailer is a
`Key: value` line at the end of the commit message). By adding it you certify,
under the [Developer Certificate of Origin 1.1](https://developercertificate.org/),
that you wrote the change (or otherwise have the right to submit it) under the
project's license — the DCO is the lightweight, per-commit alternative to a
signed contributor agreement, and the trailer is what makes the certification
auditable years later, commit by commit. The easy way is the `-s` flag, which
appends the trailer using your `git` identity:

```sh
git commit -s
```

CI enforces this in the **`dco`** job, which runs a dependency-free
`scripts/check_dco.sh` over every commit in the PR and fails if any commit is
missing the trailer — and a red `dco` does not get merged. The DCO applies to
commits going forward.

The repository is open-core and the target file decides the contribution
license. Core source outside `ee/` is MPL-2.0; commercial source under `ee/`
uses the terms referenced by `ee/LICENSE`. The DCO certifies that you have the
right to submit the contribution under that target license; it does not change
the license boundary. No Contributor License Agreement is required today.

For new first-party source, use these machine-readable identifiers:

- core: `SPDX-License-Identifier: MPL-2.0`, together with the MPL Exhibit A
  notice; do **not** add Exhibit B;
- `ee/`: `SPDX-License-Identifier: LicenseRef-Probectl-Commercial`, together
  with a pointer to `ee/LICENSE`.

Generated files and third-party material keep generator/upstream notices. The
tree-wide replacement of the historical pre-MPL placeholder identifier is
enforced by the licensing header gate; never copy that retired identifier into
a new file. See [`LICENSING.md`](LICENSING.md) for the complete split.

## Definition of Done

A change is complete only when **all** of these hold:

- It **compiles** and is lint-clean — `gofmt` + `go vet` + `golangci-lint` for
  Go, `ruff` + `black` for the Python analyzer. (`make lint` runs all of them.)
- **Unit tests** pass, plus any **integration tests** relevant to the change
  (the integration suite runs against the real `test/` dependency stack).
- The **OpenAPI spec** and the **`docs/`** are updated in the same PR — there are
  no undocumented API routes.
- Any **schema change** ships an **idempotent migration** — one that is safe to
  run twice, converging to the same state instead of erroring (`IF NOT EXISTS`,
  `ON CONFLICT`) — and any new tenant-owned table carries `tenant_id` with its
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
  second line of defense. The AI assistant and the MCP tools obey the same
  boundary, in the same order: **tenant first, then RBAC** — an answer can only
  cite data the caller's tenant and role could already see. **Any change to a
  data-access path must come with a cross-tenant isolation test.** The standing
  `cross-tenant-isolation` CI gate runs the suite (`make test-isolation`); a
  bypass fails the build. When in doubt, fail closed and return nothing.
- **No phone-home.** Never add default outbound telemetry, analytics beacons, or
  call-home behavior. License verification is offline local math; open-data
  fetches are read-only, cached, and degrade gracefully — a down or rate-limited
  external source must never break core function.
- **Crypto only through `internal/crypto`.** Never call cryptographic primitives
  from handlers or services — the abstraction exists so a FIPS-validated module
  can be compiled in. A CI lint guard rejects primitive imports elsewhere.
- **TLS on every listener; secrets never in code.** Agent↔control-plane is
  **mTLS, always** — no plaintext agent transport exists. The API, UI, OTLP, and
  MCP surfaces are HTTPS; inbound ingestion is authenticated, tenant-scoped, and
  treated as untrusted; outbound fetches validate certificates (never disabled).
  Never hardcode credentials or log a secret. When a required secure channel,
  credential, or signature is missing, fail closed.
- **Remediation is observe-only and human-gated.** probectl observes and
  recommends; it does not act on the network by itself. Any action path requires
  explicit human approval, supports dry-run, enforces blast-radius limits, is
  tenant- and RBAC-scoped, and is fully audited. An un-gated autonomous network
  action is never acceptable, in any tier.
- **Detection is a signal, never an IPS.** Threat detections are
  confidence-scored, tunable, suppressible, and exportable to your SIEM —
  probectl never auto-blocks traffic and never sits inline. Wiring a detection
  to an enforcement hook is a design discussion, not a pull request.
- **Audit everything.** Config changes and data-access actions go to the
  tamper-evident audit log; provider-plane and break-glass actions go to a
  separate, equally tamper-evident provider audit stream.

## Proto schemas are append-only

The protobuf schemas in `proto/` are the **wire contract** between agents, the
bus, and the control plane — and the bus history is replayable, so a breaking
change can strand deployed agents and corrupt the ability to re-read old events.
Mutating a published message is like changing what a column means in a ledger
everyone has already written rows into: every old row silently reads wrong.
Because of that, schemas are **additive-only**, enforced by the **`buf breaking`
gate** in the `proto` CI job (`buf` is the protobuf toolchain — linter,
breaking-change checker, code generator; the gate compares your branch against
`main` and blocks the merge on any incompatible change).

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
