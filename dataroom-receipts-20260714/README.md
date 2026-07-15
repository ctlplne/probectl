# Data-room local gate receipt — 2026-07-14

This bundle records the local GA gate run for source commit
`1331b664e160fac2851221a09394c8cd9498bc4d`. The receipt-only commit that adds
this directory does not change the source that was tested; this full hash is the
execution boundary auditors should compare with the drill CSVs, SBOM property,
container build argument, and coverage heading.

The run was performed on 2026-07-14 EDT. The two recovery drills crossed
midnight in UTC, so their machine timestamps are 2026-07-15Z. The host used Go
1.26.5 on Darwin/arm64, Docker Engine 29.6.1, the repository's Node 22 and
Playwright 1.55.1 containers, govulncheck 1.1.4, CycloneDX GoMod 1.7.0, and
Trivy 0.71.1 with a vulnerability database refreshed during the run.

## Outcome

- All nine native binaries built. Every binary also cross-compiled for Linux
  amd64 and arm64; the endpoint agent built for Linux, macOS, and Windows on
  amd64 and arm64.
- All eleven FIPS artifacts built with `GOFIPS140=v1.0.0`; the power-on
  self-test, known-answer tests, transparent provider swap, and artifact
  coverage checks passed.
- The full Go race suite, core-only editions suite, Python analyzer suite, and
  service-backed integration/isolation suites passed. Go coverage was 78.0%
  and every declared package floor passed; Python coverage was 92.58%.
- The Node 22 web chain passed typecheck, formatting, lint, 362 tests,
  coverage gates, and production build. Rendered Chromium reported no
  accessibility violations across 23 native routes in both themes.
- Real Postgres, Kafka, ClickHouse, and Prometheus tests passed. The black-box
  E2E test observed tenant-specific ingest through the public API and proved
  isolation in both directions.
- The local performance smoke measured 85,850 results/s for the in-process
  ingest baseline and 2,701 tenant-scoped queries/s with isolation true. The
  S-tier full-stack smoke measured 15 results/s and 357 flows/s. These are
  smoke-detector numbers on a developer machine, not production capacity
  claims.
- Backup/restore recovered 137 Postgres rows, 251 + 17 tenant-separated
  ClickHouse rows, and a three-event signed WORM chain byte-for-byte from
  sealed artifacts. Backup and restore each measured one second.
- Postgres failover promoted the streaming replica in 604 ms with zero
  acknowledged rows lost at 7.6 writes/s. The dependency-chaos drill passed
  all four recovery assertions.
- Full-history gitleaks scanned 1,013 commits with no leaks. govulncheck found
  zero reachable vulnerabilities; one required-module advisory was not called
  by product code. Trivy found zero fixed HIGH/CRITICAL vulnerabilities in the
  filesystem manifests, Debian runtime, or embedded Go binary.
- The clean-archive `probectl-control` image ID is
  `sha256:bda1c4bafca91136c239584a699e0a54344f11bd54f878f34057baa3ecdc6d37`.
  Its CycloneDX 1.5 SBOM is target-specific to Linux/arm64, contains 26 runtime
  module components, and carries the verified source commit as metadata.
- The built-in RCA evaluation passed 25 scenarios with 0.92 answer accuracy,
  0.92 mean citation precision, and the honesty check true.

`verify-all-summary.json` is the machine-readable index. Every top-level entry
has `result: success`, so the repository's E1 receipt check can mechanically
reject any red or malformed entry.

## Execution notes

The first integration invocation inherited system Python and therefore could
not import the pinned analyzer dependency `structlog`; its bounded analyzer
retry timed out. The authoritative rerun put the prepared analyzer virtualenv
first on `PATH` and passed. The first failover invocation failed closed before
starting because `POSTGRES_PASSWORD` was absent; the rerun supplied the
throwaway dev-stack credential and passed. A sandboxed editions invocation was
unable to bind `httptest` loopback listeners; the authoritative outside-sandbox
rerun passed. These were runner preparation/policy errors, not product gate
failures, and none is represented as a success until its corrected rerun.

## Artifacts

- `coverage.out` and `coverage-summary.txt`: exact-source Go coverage profile
  and per-function summary.
- `rca-eval-report.json`: machine-readable deterministic RCA evaluation.
- `backup-restore.csv` / `.log`: sealed three-store recovery measurements and
  full transcript.
- `failover.csv` / `.log`: measured streaming-replica RTO/RPO and transcript.
- `gitleaks-history.json`: empty JSON result from the full-history scan.
- `govulncheck.txt`, `trivy-fs.txt`, and `trivy-image.txt`: dependency and image
  vulnerability reports.
- `probectl-control-linux-arm64.cdx.json`: CycloneDX 1.5 application SBOM.
- `SHA256SUMS`: hashes for the committed receipt artifacts.

## Explicitly not promoted by this receipt

This local bundle does not convert environment-dependent work into GA proof:

- E2: L/XL/XXL reference-hardware scale and 72-hour soak.
- E3: representative multi-region disaster-recovery drill.
- E4: reference-host eBPF/agent overhead measurements.
- L4: counsel-owned `ee/LICENSE`, reseller terms, DPA/MSA, trademark, and
  open-data resale review. Core MPL-2.0 is already final and is not part of this
  legal remainder.
- The optional strict-stock interop provenance gate. The normal offline interop
  replay passed, but the current fixture manifests do not yet carry independent
  stock-capture provenance, so that stricter proof is not claimed.

