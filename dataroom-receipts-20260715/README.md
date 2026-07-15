# Exact-source remediation end-gate receipt — 2026-07-15

This receipt records the authoritative remediation end gate for source commit
`b2a038a31aa921d0fbebe0f110f8dd5934d8a9c1`. The receipt-only commit that adds
this directory does not change the tested product source. Auditors should treat
the full hash above—not a moving branch name—as the execution boundary.

## Outcome

- The run used a detached, clean Git worktree at the exact source hash. The
  operator's pre-existing dirty files in the shared worktree were not visible.
- The harness executed **101/101** verifier commands across all 75
  agent-executable tasks and reopened zero tasks.
- The expanded gates then passed: default and `probectl_core` builds, all Go
  tests, editions, OpenAPI, migrations, SDKs, web type/build/tests,
  backup/restore, and the race-enabled real-store cross-tenant isolation suite.
- Go/Python lint and documentation-claim checks passed. Eleven FIPS artifacts
  built with the pinned Go 1.26.5 toolchain and their power-on/known-answer
  tests passed.
- The web chain passed 76 test files / 417 tests, coverage thresholds,
  production build, two rendered-browser accessibility passes, performance and
  bundle budgets, capability-surface coverage, and design-token enforcement.
- Required Postgres, Kafka, ClickHouse, and Prometheus services were healthy.
  Full integration, repeated cross-plane correlation, tenant-scoped subject
  erasure, pooled/siloed boundaries, and the aggregate isolation suite passed.
- The full-history gitleaks self-test rejected a planted deleted key, then the
  real scan checked 1,037 commits with zero findings. govulncheck reported zero
  reachable findings and the supply/image pin gates passed.
- Dark-package, production-stub-pattern, and final UX-rubric sweeps were clean.

`verify-all-summary.json` is the machine-readable index. Every top-level entry
has `result: success`, so E1 rejects any red or malformed gate.

## Runner corrections before the authoritative pass

No failed or incomplete pass is represented as success:

- The original end-gate loop allowed a backup command to consume its
  process-substitution stdin. The harness now gives every verifier `/dev/null`
  stdin and asserts the exact command count, preventing a truncated false pass.
- The exhaustive replay found and fixed one Go lint shadow, a finite BGP replay
  retry loop, a stale ClickHouse verifier credential, and the missing committed
  executable bit on the history scanner.
- The final proof used the exact downloaded Go 1.26.5 binary. This matters
  because `GOTOOLCHAIN=local` correctly refuses to substitute that version when
  the host's base Go binary is older.
- A temporary clean-worktree `node_modules` symlink was replaced with a real
  lockfile installation before the authoritative run so the Linux Playwright
  container overlay could not replace Darwin-native optional packages.
- Postgres, Kafka, ClickHouse, and Prometheus were all health-checked before the
  authoritative run. Service absence was treated as a runner failure, never a
  product success.

## Explicitly not promoted by this receipt

This local software receipt does not manufacture evidence that needs reference
hardware or independent authority:

- **E2:** L/XL reference-hardware load and soak rows remain provisional.
- **E3:** representative-data multi-region DR and operator RTO/RPO sign-off
  remain open.
- **E4:** reference-host agent/eBPF overhead measurements remain open.
- **L4:** final `ee/LICENSE`, reseller terms, DPA/MSA, trademark treatment, and
  commercial open-data resale review remain counsel-owned. Core MPL-2.0 is
  already final.

Developer-machine smoke numbers are regression detectors, not buyer-facing
capacity, DR, or overhead claims.
