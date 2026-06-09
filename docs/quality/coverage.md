# Quality receipts (coverage + scan artifacts)

Think of this as the "show your work" drawer for CI. Every CI run leaves behind
the evidence a reviewer (or a future you) would ask for — "is the code actually
tested? did the vulnerability scan run? what did it find?" — and it leaves that
evidence as **downloadable run artifacts**, never as a bot pushing files back to
`main`. Why artifacts and not commits: you keep a full audit trail without the
release branch growing extra commits or a bot ever needing write access.

## What is retained, where (90-day retention)

Each row is a zipped artifact attached to a CI run. The "producing job" is the
CI job (in `.github/workflows/ci.yml`) that creates it.

| Artifact | Producing job | Contents |
|---|---|---|
| `coverage-receipt` | `coverage` | `coverage.out` (the raw Go cover profile over the gated packages) + `coverage-summary.txt` (a per-function tail + the total) |
| `test-go-log` | `test-go` | the full `make test` output — every Go workspace module, run with the race detector (`-race`) |
| `dependency-scan-receipts` | `dependency-scan` | `govulncheck-report.txt` (Go vulnerability scan) + `trivy-fs-report.txt` (filesystem vuln scan, CRITICAL/HIGH only). Committed secrets are a *different* job — the `secret-scan` gitleaks gate. |
| `rca-eval-report` | `rca-eval` | the AI root-cause-analysis quality scores — `answer_accuracy` and `mean_citation_precision` (plus the raw eval log) |

On a pull request, the `coverage` job additionally posts a best-effort comment
with the coverage summary, so you see the numbers without downloading anything.

## Fetching a receipt

```sh
gh run list --workflow ci --limit 5                 # pick a run id
gh run download <run-id> -n coverage-receipt
gh run download <run-id> -n dependency-scan-receipts
```

## Floors (enforced, not aspirational)

A "floor" is a minimum coverage percentage a package must keep. Drop below it
and CI goes red — that is the whole point: a floor turns "we should test this"
into "the build won't pass if you don't."

- **Per-package Go floors** live in `scripts/check_coverage.sh` and run in the
  `coverage` job. The script measures statement coverage from `coverage.out`
  and fails if any package is under its declared floor. It covers the
  service-free packages (pure logic, parsers, probes) — the ones whose coverage
  is meaningful without a live database or message bus.
- **`internal/store` integration floor: 60%**, enforced inside the
  `integration` job — not the `coverage` job. The store package only does
  anything useful against a real Postgres (with row-level security on), so its
  coverage is measured *with* the integration tests running, then held to the
  floor.
- **Python analyzer: 85%**, via `fail_under = 85` in
  `analyzer/pyproject.toml`'s `[tool.coverage.report]`, enforced in the
  `test-python` job.

The rule for all three: **raise a floor when coverage goes up; never lower one
just to make a regression pass.** Lowering a floor to get green is how a
codebase quietly loses its test coverage.
