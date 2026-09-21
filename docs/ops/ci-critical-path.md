# CI critical path — measured, not estimated

Source: ci.yml run 35423586013 on `ac90177` (2026-09-19T05:18:05Z), the FIRST run on `main`
ever allowed to live to a verdict — every earlier run was canceled by the next push
(DPR-235). Regenerate this from a completed run rather than editing it.

**Wall clock: 20m10s.** The run is one job deep: `test-go` at 20m10s IS the critical
path, and the second-slowest job finishes 12m19s earlier. Every other job is already
hidden behind it, so making the rest faster buys nothing.

Recorded because the pipeline had been described as taking four hours. It does not, and that
matters: the cost of a canceled run was never compute, it was the missing verdict.

51 jobs ran, 3 were skipped, 1 never started.

| Job | Result | Wall clock |
|---|---|---|
| `test-go` | success | 20m10s |
| `cross-tenant-isolation` | success | 7m51s |
| `integration` | failure | 6m34s |
| `lint-go` | failure | 4m11s |
| `build-images (probectl-browser-agent, deploy/docker/Dockerfile.browser-agent, probectl-agent)` | success | 4m02s |
| `ebpf-kernel-matrix (5.15)` | success | 2m56s |
| `ebpf-kernel-matrix (6.6)` | success | 2m51s |
| `editions-gate` | success | 2m30s |
| `build-images (probectl-ebpf-agent, deploy/docker/Dockerfile.ebpf, probectl-ebpf-agent)` | success | 2m27s |
| `build-images (probectl-bgp-analyzer, deploy/docker/Dockerfile.bgp-analyzer, probectl-control)` | success | 2m12s |
| `ebpf-kernel-matrix (6.6-lockdown)` | success | 2m08s |
| `ebpf-image-live (EBPF-004)` | success | 2m04s |
| `coverage` | success | 1m55s |
| `delivery-audit-gate` | success | 1m19s |
| `backup-drill` | success | 1m16s |
| `fips-gate` | success | 1m07s |
| `packaging-smoke` | success | 1m04s |
| `load-smoke` | success | 1m04s |
| `browser-worker` | failure | 1m02s |
| `perf-smoke` | success | 0m52s |
| `openapi-gate` | success | 0m49s |
| `build-images (probectl-flow-agent, deploy/docker/Dockerfile, probectl-flow-agent)` | failure | 0m46s |
| `no-devauth-in-release` | success | 0m42s |
| `device-live (SNMP integration)` | success | 0m38s |
| `completeness-gate` | success | 0m38s |
| `sbom` | success | 0m37s |
| `dependency-scan` | success | 0m37s |
| `build-images (probectl-endpoint, deploy/docker/Dockerfile, probectl-endpoint)` | failure | 0m36s |
| `failover-drill` | success | 0m35s |
| `build-images (terraform-provider-probectl, deploy/docker/Dockerfile, terraform-provider-probectl)` | failure | 0m34s |
| `migration-gate` | success | 0m34s |
| `chaos-dependency-drill` | success | 0m33s |
| `build-images (probectl-device-agent, deploy/docker/Dockerfile, probectl-device-agent)` | failure | 0m33s |
| `web-rendered-a11y` | failure | 0m33s |
| `build-images (probectl-agent, deploy/docker/Dockerfile, probectl-agent)` | failure | 0m33s |
| `secret-scan` | success | 0m32s |
| `build-images (probectl-control, deploy/docker/Dockerfile, probectl-control)` | failure | 0m31s |

(14 jobs under 30s omitted; skipped jobs carry no duration: `commitlint`, `dco`, `coverage-comment`.)

## The job that never started, and why the release gate hung (resolved, D-13)

Resolved on 2026-09-19 by decision D-13: the arm64 row is removed and the claim
narrowed to compile-verified (DPR-250). The rest of this section is kept because it
is the diagnosis, and because restoring the row re-creates the situation exactly.

## The job that never starts, and why the release gate hangs

`ebpf-kernel-matrix (6.6-arm64)` is still `queued` and its `completedAt` is `0001-01-01T00:00:00Z` — it has never
been scheduled. It wants a self-hosted Linux/ARM64 runner carrying the custom `kvm` label;
ci.yml states the reason plainly (arm64 eBPF support cannot be claimed without a live
verifier/attach run). No such runner is attached to this account.

So the RUN never reaches `completed`, and `release.yml`'s `require green ci on the tagged sha`
polls exactly `status`/`conclusion`. That is why v0.6.3's release spent 1824s and reported
"timed out waiting for ci to complete" — while its other two gates, `license trust anchor
present` (6s) and `published components complete` (4s), both PASSED.

Un-canceling main runs (DPR-235) does not fix this half, and no amount of speed does either.
It needs a decision — provision the runner, or change what arm64 eBPF support claims — which
is why it is D-13 in `../design-partner-readiness/decisions-needed.md` rather than something
worked around here.

It also had a second-order cost that DPR-242 had to fix. While `main` shared one concurrency
group per ref, a run that never concludes HELD that group, so the next push sat at `pending`
until somebody canceled the stuck run by hand — observed on 2026-09-19, eleven hours after the
run on `ac90177` started. `main` is now keyed on `github.sha`, so each commit gets its own group
and a stuck run is stuck alone. Branches still share one group per ref, with cancellation, which
is what that setting is for.
