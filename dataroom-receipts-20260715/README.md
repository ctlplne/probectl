# Exact-source remediation end-gate receipt — 2026-07-15

This refreshed same-day receipt records the authoritative remediation source
proof for commit `9a691590e1bae6d948bfa1f52ef59f1d31aa4abf`. The evidence-only
commit that updates this directory does not alter the tested product source.
Auditors should treat the full hash above—not a moving branch name—as the
execution boundary.

## Outcome

- The proof ran from a clean local clone at the exact source hash. The
  operator's pre-existing dirty files in the shared worktree were not visible.
- The source phase executed **100/100** durable task commands and reopened zero
  tasks. E1 is necessarily verified only after this receipt exists; E8 is the
  recursion point and is represented by the outer end-gate invocation. The
  final receipt-aware replay is recorded in the harness handoff as 101/101.
- The expanded gates passed: default and `probectl_core` builds, all Go tests,
  editions, OpenAPI, migrations, SDKs, web type/build/tests, backup/restore,
  and the race-enabled real-store cross-tenant isolation suite.
- Core licensing is consistently MPL-2.0 across source, generated artifacts,
  package metadata, fixtures, and documentation. The retired placeholder
  identifier is absent; `ee/` remains separately commercial and core never
  imports it.
- Go/Python lint and documentation-claim checks passed. Go statement coverage
  was 80.5% with every per-package floor intact. Eleven FIPS artifacts built
  with Go 1.26.5 and their power-on/known-answer tests passed.
- The web chain passed 76 test files / 417 tests, coverage thresholds,
  production build, two rendered-browser accessibility passes, performance and
  bundle budgets, capability-surface coverage, and design-token enforcement.
- Required Postgres, Kafka, ClickHouse, and Prometheus services were healthy.
  Full integration, repeated cross-plane correlation, tenant-scoped subject
  erasure, pooled/siloed boundaries, and aggregate isolation passed. The
  explicit S-tier load smoke confirmed 12/12 result series and 200/200 flow
  rows, including a cold Kafka consumer-assignment handshake.
- The full-history gitleaks self-test rejected a planted deleted key, then the
  real scan checked 994 commits with zero findings. govulncheck reported zero
  reachable findings and the supply/image pin gates passed.
- Dark-package, production-stub-pattern, and final UX-rubric sweeps were clean.

`verify-all-summary.json` is the machine-readable index. Every top-level entry
has `result: success`, so E1 rejects any red or malformed gate. `SHA256SUMS`
binds both files.

## Runner corrections before the authoritative pass

No failed or incomplete pass is represented as success:

- The end-gate enumerator now replays both `done` and `verified` ledger tasks,
  gives each command `/dev/null` stdin, asserts the exact count, and excludes
  only E8's self-recursive verifier.
- The core-license header gate now covers every tracked source/metadata format
  and rejects the retired placeholder identifier anywhere in the repository.
- Full-stack load is activated only by its dedicated Make targets. Generic
  integration and coverage jobs cannot inherit service URLs and accidentally
  generate load.
- Kafka warmup has a finite dependency deadline. Readiness actively republishes
  a run-scoped probe until the cold `FromEnd` consumer, Prometheus remote-write,
  and tenant query path complete an end-to-end handshake.
- `make test-integration` now supplies the complete, overridable local dev-stack
  endpoint set, so required-service mode cannot omit the OTLP ClickHouse store.
- Postgres, Kafka, ClickHouse, and Prometheus were health-checked before the
  authoritative run. Service absence is a runner failure, never product
  success.

## Explicitly not promoted by this receipt

This local software receipt does not manufacture evidence that needs reference
hardware or independent authority:

- **E2:** L/XL/XXL reference-hardware load and soak rows remain provisional.
- **E3:** representative-data multi-region DR and operator RTO/RPO sign-off
  remain open.
- **E4:** reference-host agent/eBPF overhead measurements remain open.
- **L4:** final `ee/LICENSE`, reseller terms, DPA/MSA, trademark treatment, and
  commercial open-data resale review remain counsel-owned. Core MPL-2.0 is
  already final.

Developer-machine smoke numbers are regression detectors, not buyer-facing
capacity, DR, or overhead claims.
