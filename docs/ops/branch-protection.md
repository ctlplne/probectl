# Branch protection for `main` and release gating

## What this is

CI runs a long list of checks on every pull request. By themselves those
checks are only **advisory** — GitHub will happily let you click "Merge" on a
red PR unless you tell it not to. This page is how you make the checks
**blocking**, so a change cannot land on `main` until CI is green.

There are two independent layers, and you want both:

1. **Branch protection on `main`** — a GitHub repository **setting** (not
   something in this repo's code), configured once in the web console. It is
   what makes the merge button refuse a red or out-of-date PR. Because it is a
   server-side setting, the repo cannot turn it on for you; an admin must.
2. **`release.yml` → `require-green-ci`** — a job already in the release
   workflow. When you push a `v*` tag, it refuses to build or publish anything
   unless the **full `ci` workflow** concluded green on that exact commit. This
   is a second, independent backstop: it holds even for a tag cut off a side
   branch, or by an admin who bypassed branch protection.

Layer 1 guards the *merge*; layer 2 guards the *release*. Neither depends on
the other.

> There is **no CI job that verifies branch protection** — it cannot be checked
> from inside the repo, because the setting lives in GitHub's server config, not
> in the tree. Auditing it is a manual console check (below).

## Turn on branch protection (one-time console steps, ~5 minutes)

GitHub → repository → **Settings → Branches → Add branch protection rule**:

- **Branch name pattern:** `main`
- Enable **Require status checks to pass before merging**
  - Enable **Require branches to be up to date before merging** (forces a PR to
    re-run CI against the current tip of `main` before it can merge — catches
    "passed in isolation, breaks after someone else's merge").
  - **Required checks** — add the check(s) from the next section. A check that
    is *not* listed here is advisory again, so this list is the whole point of
    the rule.
- Enable **Require a pull request before merging** — set the approval count to
  fit the team (a solo maintainer can leave approvals at 0; the required status
  checks still block the merge button).
- Enable **Do not allow bypassing the above settings** (a.k.a. "Include
  administrators"). Without this, every gate above is advisory *for admins* —
  which defeats the purpose.
- Leave **Block force pushes** and **Block deletions** on (they are defaults of
  the rule, and they stop history from being rewritten out from under the
  gates).

Then **Settings → Tags → New rule** (tag protection): pattern `v*`, so only
maintainers can create release tags. (Even without this, `require-green-ci`
refuses to release an untested commit — but tag protection stops an accidental
tag in the first place.)

## Which checks to require

The simplest, lowest-maintenance choice is to require the **`verify-all`** job
and nothing else. `verify-all` is an umbrella job in `ci.yml` that `needs:` the
whole verification suite and fails red if any of them is red or skipped — so
requiring it is equivalent to requiring all of them, but you never have to edit
the branch-protection rule again when a job is added or renamed.

A few jobs run *outside* the `verify-all` umbrella (they are not in its
`needs:` list). If you want belt-and-suspenders, add them explicitly:

| Required check | Gate it enforces |
|---|---|
| `verify-all` | umbrella — fails unless every gate in its `needs:` list is green |
| `image-scan` | Trivy image vulnerability scan |
| `commitlint` | Conventional Commits on PR commits |
| `dco` | Developer Certificate of Origin sign-off |
| `sbom` | release SBOM (SPDX) generates cleanly |

If your organization's policy instead requires listing every job by name (some
auditors prefer the explicit list), the **complete** set of top-level `ci.yml`
jobs is below. Keep it in sync with the workflow — **a job you forget to list
is advisory again**, so prefer the `verify-all` approach unless you have a
reason not to.

| Required check | Gate it enforces |
|---|---|
| `action-pins` | every workflow action is pinned to a commit SHA |
| `secret-scan` | no committed secrets (gitleaks) |
| `no-devauth-in-release` | the eval-only `dev` auth mode cannot ship in a release build |
| `lint-go` | gofmt + go vet + golangci-lint |
| `lint-python` | ruff + black (the BGP analyzer) |
| `editions-gate` | core never imports `ee/`; the core-only build stays green (CLAUDE.md §2) |
| `fips-gate` | the FIPS artifact builds; the validated module is active (guardrail 3) |
| `test-go` | unit tests, fuzz smoke, cross-compile, endpoint cross-OS |
| `rca-eval` | AI root-cause-analysis quality eval |
| `coverage` | per-package coverage floor |
| `test-python` | BGP analyzer tests |
| `browser-worker` | Playwright worker real-browser smoke |
| `openapi-gate` | no undocumented `/v1` routes |
| `migration-gate` | expand/contract (zero-downtime) migrations |
| `helm-gate` | Helm chart lints + hardening invariants; GitOps manifests + compose config valid |
| `terraform-gate` | `terraform fmt` + `validate` |
| `ebpf-kernel-matrix` | eBPF programs load across the supported kernel matrix |
| `ebpf-image-live` | the shipped eBPF-agent image is the live (not fixture-replay) build |
| `cross-tenant-isolation` | **permanent** RLS isolation gate (guardrail 1) — never remove |
| `integration` | real Kafka/Postgres/ClickHouse stack |
| `perf-smoke` | ingest-path performance floor |
| `backup-drill` | backup → restore drill survives (see [backup-restore.md](backup-restore.md)) |
| `failover-drill` | timed Postgres failover drill (see [dr.md](dr.md)) |
| `load-smoke` | load/soak smoke |
| `proto` | buf lint + breaking-change check |
| `web` | typecheck, eslint, npm audit, surface-coverage + a11y + tests |
| `dependency-scan` | govulncheck / npm / pip advisories |
| `build-images` | the release Dockerfiles build |
| `image-scan` | Trivy image scan |
| `commitlint` | Conventional Commits |
| `dco` | Developer Certificate of Origin sign-off |
| `sbom` | release SBOM (SPDX) generates |

If you require `verify-all`, you do **not** also need to list the jobs it
already covers — listing them is redundant (though harmless).

## How the release gate works (`release.yml`)

Pushing a `v*` tag does not trigger `ci` (tag pushes and branch pushes are
different events), so the release workflow can't just "wait for its own CI". The
`require-green-ci` job instead **looks up** the `ci` run for the tagged commit
via the GitHub Actions API (`ci.yml/runs?head_sha=<the tag's commit>`):

- **completed + success** → the `images` and `binaries` jobs (which `needs:` it)
  proceed and publish.
- **completed + failure/cancelled** → the release fails; nothing is built.
- **still running** → it polls for up to ~30 minutes (60 tries, 30 s apart),
  then proceeds or fails based on the outcome.
- **no run at all** (the commit was never pushed to `main` or a PR, so `ci`
  never ran on it) → the release fails with instructions.

So the only path to a release is: push to `main` → `ci` goes green on that
commit → `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`. A tag on an
untested or red commit produces no artifacts, with or without branch
protection.
