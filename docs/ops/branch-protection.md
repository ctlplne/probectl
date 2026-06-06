# Branch protection for `main` (U-022) and release gating (U-083)

Two layers make CI gates **enforcing**, not advisory:

1. **Branch protection on `main`** (this doc — a one-time GitHub console action;
   the repo cannot set it from code).
2. **`release.yml` → `require-green-ci`** (already in the workflow): a `v*` tag
   builds/publishes **nothing** unless the full `ci` workflow concluded green on
   the exact tagged commit. This holds even for a tag cut off-branch or by an
   admin, independent of branch protection.

## Operator console steps (one-time, ~5 minutes)

GitHub → repository → **Settings → Branches → Add branch protection rule**:

- **Branch name pattern:** `main`
- ✅ **Require status checks to pass before merging**
  - ✅ **Require branches to be up to date before merging**
  - **Required checks** — add ALL of the `ci` workflow's jobs (list below).
    They appear in the picker after the next `ci` run on a PR.
- ✅ **Require a pull request before merging** — review count per team size
  (a solo maintainer may leave approvals at 0; the required checks still block
  the merge button).
- ✅ **Do not allow bypassing the above settings** ("Include administrators") —
  without this, every gate stays advisory for admins, which is exactly U-022.
- ✅ Block force pushes and deletions (defaults of the rule).

Then **Settings → Tags → New rule** (tag protection): pattern `v*` — only
maintainers can create release tags. The release workflow independently refuses
red/untested commits either way.

## Required status checks for `main` (the full `ci` suite)

Add every job — a check that isn't required is advisory:

| Required check | Gate it enforces |
|---|---|
| `action-pins` | every workflow action SHA-pinned (U-007) |
| `lint-go` | gofmt + go vet + golangci-lint |
| `lint-python` | ruff + black (analyzer) |
| `editions-gate` | core never imports `ee/`; core-only build green (CLAUDE.md §2) |
| `fips-gate` | FIPS artifact builds; validated module active (guardrail 3) |
| `test-go` | unit tests, fuzz smoke, cross-compile, endpoint cross-OS |
| `coverage` | per-package coverage floor |
| `test-python` | BGP analyzer tests |
| `browser-worker` | Playwright worker real-browser smoke |
| `openapi-gate` | no undocumented /v1 routes |
| `migration-gate` | expand/contract (zero-downtime) migrations |
| `helm-gate` | chart lints + hardening invariants; compose config valid |
| `terraform-gate` | terraform fmt + validate |
| `cross-tenant-isolation` | **permanent** RLS isolation gate (guardrail 1) — never remove |
| `integration` | real Kafka/Postgres/ClickHouse stack |
| `perf-smoke` | ingest-path performance floor |
| `proto` | buf lint/breaking |
| `web` | typecheck, eslint, npm audit gate (U-028), surface-coverage + a11y + tests |
| `dependency-scan` | govulncheck / npm / pip advisories |
| `build-images` | release Dockerfiles build |
| `image-scan` | trivy image scan |
| `commitlint` | conventional commits |

When a job is added to or renamed in `ci.yml`, update the rule (and this table)
in the same change — an unlisted job is advisory again.

## How the release gate works (`release.yml`)

`require-green-ci` queries the Actions API for the `ci` workflow run on
`github.sha` (the tagged commit): success → the `images` and `binaries` jobs
(which `needs:` it) proceed; failure/cancelled → the release fails; still
running → it waits (up to 30 min); **no run at all** (commit never pushed to
`main`/a PR) → the release fails with instructions. Releasing is therefore:
push to `main` → ci goes green → `git tag -a vX.Y.Z && git push origin vX.Y.Z`.
