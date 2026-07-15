# probectl — Product Requirements Document (v1.1, delivered state)

| | |
|---|---|
| **Product** | probectl |
| **Owner** | Shankar (solo founder) |
| **Status** | v1.1 — remediation delivered; local software gates green; four explicitly parked operator/counsel proofs remain |
| **Last Updated** | July 15, 2026 |
| **License** | Open-core: core is MPL-2.0; `ee/` is separately commercial. Final commercial/reseller paper remains counsel-owned (§4) |
| **Supersedes** | v1.0 as the current steering document; `probectl-PRD-v1.0.md` remains the detailed code/evidence inventory and v0.5 remains frozen history |

> **One-sentence delivered state:** probectl is a self-hosted, open-core,
> multi-tenant network observability platform that unifies active testing,
> routing, flow, device, and eBPF signals in one OpenTelemetry-aligned control
> plane, with tenant-scoped cited RCA, security signals, change-aware topology,
> cost/SLO intelligence, and an operator-ready native product surface—without
> sending operator telemetry outside the deployment.

## 1. How to read v1.1

This is the short, current steering contract. The 57-row feature traceability
table, architecture detail, and code pointers remain in
[`probectl-PRD-v1.0.md`](probectl-PRD-v1.0.md); v1.1 changes their program status,
not their technical meaning. A delivered claim is still bounded by its cited
gate. Environment-dependent measurements are not converted into proof merely
because the software that runs them exists.

The remediation harness closed **75/75 agent-executable tasks**. Its end gate
replayed every task verifier and the complete build, unit, race, editions,
OpenAPI, migration, SDK, web, accessibility, surface-coverage, backup/restore,
real-store integration, and cross-tenant isolation gates. The exact source
commit and machine-readable results are recorded in the fresh
[`dataroom-receipts-20260715/`](dataroom-receipts-20260715/README.md) bundle.

## 2. Delivered delta from v1.0

The v1.0 code inventory is now paired with executable, exact-source remediation
evidence. The completed delta includes:

- **Foundation and trust:** tenant-first storage/query enforcement, real-store
  two-tenant isolation, TLS-by-default deployment paths, authenticated ingestion,
  crypto abstraction, offline licensing, edition fencing, secret/dependency
  scans, recovery drills, and fail-closed negative-path tests.
- **Five-plane product completeness:** active/path, BGP, flow, device, and eBPF
  paths have native/operator surfaces, correlation evidence, honest empty/error
  states, and documented operational boundaries.
- **Enterprise operations:** persisted alert operations, siloed ClickHouse
  routing, tenant lifecycle, provider metadata operations, human-gated fleet
  rollout, and scheduled tenant-safe dashboard PDF/CSV reports are delivered
  across API, CLI, native web, tests, OpenAPI, and operator docs.
- **Product experience:** every declared capability has a native, federated, or
  none-by-design surface; the six deterministic operator journeys meet the
  competitive "better" target in
  [`docs/ux/rubric-results.md`](docs/ux/rubric-results.md). Design tokens cover
  density, charts, focus/selection, layers, and motion without hardcoded product
  values, and rendered accessibility gates remain binding.
- **Truthful documentation:** OTLP metrics/traces/logs, alert-operation
  persistence, IPv6 eBPF capture, FIPS evidence, fleet rollout, siloed
  ClickHouse, and marketplace scope now match the implementation and tests.

The remediation drift ledger is cleared: no agent-executable backlog item is
left in `todo`. A future code change can of course reopen a gate; the receipt is
proof for its named commit, not a promise that arbitrary later commits are green.

## 3. Delivered product boundary

The v1.0 F1–F57 accounting remains **55 delivered, one partial, and one deliberate
future item**:

- **F33 multi-region/HA stays partial.** Stateless/fenced HA paths, failover
  tooling, and runbooks are delivered. Representative multi-region data-volume
  execution and operator RTO/RPO sign-off remain E3 below.
- **F49 marketplace stays future/out-of-GA.** It is a visible Phase-4 option with
  a `none-by-design` surface declaration, not a missing GA screen or a hidden
  current capability.

All safety boundaries remain unchanged. Tenant isolation is outermost; AI/MCP
apply tenant scope before RBAC; agent transport is mTLS; listeners use TLS;
crypto enters through `internal/crypto`; no default phone-home exists; threat
detections are signals rather than an IPS; and remediation cannot perform an
automatic network action without explicit, scoped human approval and audit.

## 4. Explicitly parked proof—do not promote

These are the only four open harness items. They need an environment or authority
that a source-code agent cannot manufacture:

| ID | Status | Required closure evidence |
|---|---|---|
| **E2** | needs hardware | Run L/XL load and soak profiles on the declared reference hardware, fill `docs/scale-gate.md`, and remove `PROVISIONAL` only for measured rows. |
| **E3** | needs hardware | Run the representative-data multi-region DR drill, record measured RTO/RPO, and obtain operator sign-off before removing the provisional banner. |
| **E4** | needs hardware | Run the agent/eBPF overhead benchmark on the declared reference host and commit the measured table/whitepaper row. |
| **L4** | needs human | Counsel approves final `ee/LICENSE`, reseller terms, DPA/MSA, trademark treatment, and the open-data commercial-resale AUP matrix. Core MPL-2.0 is already final. |

Developer-machine performance and recovery smoke results are regression
detectors, not production capacity, customer RTO/RPO, or reference-host overhead
claims. Draft commercial paper is not legal approval.

## 5. Release interpretation

For an exact commit, software readiness is determined by the machine-readable
receipt plus the named CI gates—not prose alone. The July 15 receipt covers the
complete local end gate and identifies its exact tested source parent. A later
receipt-only commit may point to that parent because adding evidence does not
alter the tested product source.

Operational promotion remains a human release decision. Before making
buyer-facing reference-scale, multi-region DR, overhead, or final commercial
license claims, close the matching E2/E3/E4/L4 row and attach its evidence. No
other delivered feature is waiting on those four claims to exist in code.
