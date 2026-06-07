# Quality receipts (coverage + scan artifacts)

Sprint 1 (TEST-008, DATAROOM-005, DATAROOM-011): every CI run retains the
evidence a diligence reviewer asks for — as **workflow artifacts**, never as
bot commits to `main` (a bot push would violate the branch ruleset in
`.github/rulesets/main.json`).

## What is retained, where (90-day retention)

| Artifact | Producing job | Contents |
|---|---|---|
| `coverage-receipt` | `coverage` | `coverage.out` (atomic profile over the gated packages) + `coverage-summary.txt` (per-function tail + total) |
| `test-go-log` | `test-go` | full `make test` output (`-race`, all workspace modules) |
| `dependency-scan-receipts` | `dependency-scan` | `govulncheck-report.txt` + `trivy-fs-report.txt` (CRITICAL/HIGH, vuln+secret scanners) |
| `rca-eval-report` | `rca-eval` | RCA quality scores (answer accuracy / citation precision), tracked since U-049 |

PRs additionally get a best-effort coverage summary comment.

## Fetching a receipt

```sh
gh run list --workflow ci --limit 5                 # pick a run id
gh run download <run-id> -n coverage-receipt
gh run download <run-id> -n dependency-scan-receipts
```

## Floors (enforced, not aspirational)

- Per-package Go floors: `scripts/check_coverage.sh` (the `coverage` job).
- `internal/store` integration floor: 60% inside the `integration` job (U-057).
- Python analyzer: 85% floor via `[tool.coverage.report] fail_under`
  (`test-python` job, U-094).

Raise floors with coverage; never lower one to make a regression pass.
