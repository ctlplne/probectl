# CI pipeline overview

A deeply-technical-ELI5 map of what happens **every time you push** — what runs,
why each gate exists, and what "green" actually proves. The source of truth is
`.github/workflows/ci.yml`; this doc explains it.

## When it runs

`ci.yml` triggers on **push to `main`** and on **every pull request**. A
`concurrency` group keyed on the ref cancels any in-progress run when you push
again, so a rapid second push abandons the first (no wasted runners). The
workflow starts with only `contents: read` permission — it can read the repo but
not write to it, so CI can never push to `main`.

The repo's other three workflows do **not** run on a normal push:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push to `main` + every PR | the gate described here |
| `release.yml` | push of a `v*` tag | build/sign/publish a release — its `require-green-ci` job refuses any tag whose commit doesn't have a green `ci` run |
| `nightly.yml` | daily 03:17 UTC (+ manual) | the slow stuff: `e2e` (black-box full stack against the real compose dependencies), `ingest-bench` (consumer hot-path benchmarks), and `scale-gate-m` (the M-profile SLO regression guard, `make scale-gate-m`, plus an M-tier full-stack run against real Kafka + Prometheus) |
| `security-scan.yml` | weekly, Mondays 05:17 UTC (+ manual) | scheduled dependency-CVE scans that upload evidence artifacts and gate — `govulncheck` fails on any *reachable* Go vulnerability, `npm-audit` and `trivy-fs` on Critical findings — so a new CVE in an *unchanged* repo still goes red |

## The shape: fan-out, then one umbrella

A push is like sending the change through a checkpoint with **32 specialist
inspectors**, each examining one thing, all in parallel. A 33rd job —
`verify-all` — is the supervisor: it `needs:` 28 of them, runs with
`if: always()`, writes a receipt artifact, and **fails loudly listing any
non-green gate**. It is the one status you actually watch: green `verify-all` =
the whole pipeline passed.

Four jobs sit outside the roll-up and report as their own checks: `commitlint`
and `dco` run only on pull requests (on a push to `main` they'd register as
"skipped" and falsely redden the umbrella), and `image-scan` and `sbom` are the
image-vulnerability and bill-of-materials jobs. If you turn on branch
protection, [`docs/ops/branch-protection.md`](ops/branch-protection.md)
recommends requiring `verify-all` plus those four explicitly.

The guiding principle, visible throughout the repo: **every rule in the
[Non-negotiables](../CONTRIBUTING.md#non-negotiables) has a matching CI gate,
and the gates _execute_ the thing rather than just inspecting it** — they boot
real kernels, real databases, real Kafka, and drill real failovers.
Verification you ran, not verification you described.

## The jobs, by stage

### 1. Cheap gatekeeping — "is this change even well-formed?"

- **action-pins** — every GitHub Action is pinned to a commit SHA, not a moving
  tag, so a hijacked upstream action can't slip in; a second pass
  (`scripts/check_supply_pins.sh`) rejects `:latest` image tags and unpinned
  tool installs anywhere in the workflows (supply-chain).
- **secret-scan** — gitleaks, a scanner that pattern-matches the tree for
  anything *shaped* like a credential (tokens, private keys, `key=value`
  passwords): nothing secret-shaped gets committed. The deliberately fake
  secrets inside redaction tests are allowlisted in `.gitleaks.toml`.
- **commitlint** — commit messages follow Conventional Commits (`feat(...)`,
  `fix(ci): ...`).
- **dco** — every commit carries a `Signed-off-by` (the Developer Certificate of
  Origin; what `git commit -s` adds).
- **no-devauth-in-release** — proves the dev-auth bypass is *physically absent*
  from a release binary (symbol + literal absence + a boot-time refusal of
  `PROBECTL_AUTH_MODE=dev`), and compiles a tagged build to confirm the check
  isn't vacuous.

### 2. Static checks — compile, lint, spec; no services yet

- **lint-go** / **lint-python** — gofmt + `go vet` + golangci-lint on Go, plus
  the repo's guard scripts (crypto primitives only via `internal/crypto`, no
  swallowed errors, hardened HTTP clients, no string-built SQL, unified TLS
  config); ruff/black on the BGP analyzer.
- **editions-gate** — enforces the open-core boundary via `make editions-gate`:
  `scripts/check_editions_imports.sh` (self-tested) proves **core never imports
  `ee/`**, then the core-only build (`-tags probectl_core`) compiles and passes
  its tests with the `ee/` tree linked out entirely.
- **fips-gate** — the FIPS artifact (`-tags probectl_fips`, validated Go
  Cryptographic Module via `GOFIPS140`) builds, and its power-on self-test
  passes with the validated module active — the build is real, not just tagged.
- **proto** — `buf lint`, then **`buf breaking` against `main`** (the schemas
  are the agent/bus wire contract, so incompatible changes block the merge —
  see [CONTRIBUTING.md](../CONTRIBUTING.md#proto-schemas-are-append-only)), then
  regenerates and asserts the committed `*.pb.go` match the `.proto` files (no
  drift, no codegen poisoning).
- **openapi-gate** — every registered `/v1` route exactly matches the OpenAPI 3.1
  spec; no undocumented routes ship.
- **migration-gate** — DB migrations are additive / expand-only: it rejects
  destructive or blocking changes (drop column, column-type change, rename,
  adding `NOT NULL`) so release N's schema still works with N-1's code during a
  rolling upgrade.

### 3. Tests + coverage

- **test-go** — the Go unit suite across every workspace module, run with
  `-race` (Go's race detector: it catches two goroutines touching the same
  memory unsynchronized — the class of bug that stays invisible until
  production load), plus a fuzz smoke over the untrusted-input parsers
  (fuzzing = feeding a parser machine-mutated random inputs to find the
  crashes no human would think to type). The fuzz smoke discovers every Go
  `Fuzz*` target under `internal/`, and `make fuzz-policy` proves the scheduled
  nightly job is matrix-sharded so each target gets its own long budget instead
  of all targets sharing one timeout. This job also runs the
  backup-encryption/erasure gate, an agent-overhead bench smoke, and
  cross-compile checks (linux amd64+arm64; the endpoint agent additionally
  builds for macOS and Windows).
- **test-python** — the BGP analyzer's tests, installed from a hash-locked
  requirements file (which is itself checked against `pyproject.toml` for
  drift), with an 85% coverage floor.
- **coverage** — per-package statement-coverage **floors** on the service-free
  logic/parser/probe packages (`scripts/check_coverage.sh`); retains
  `coverage.out` + a summary (the per-function tail of `go tool cover -func`)
  as a downloadable receipt artifact
  (see [`docs/quality/coverage.md`](quality/coverage.md)).
- **web** — the frontend: typecheck, lint, production build; the test step *is*
  the WCAG 2.2 AA accessibility + theme-token gate.
- **browser-worker** — the Playwright browser-synthetic worker, run inside the
  official Playwright image (a real scripted login, timings + failure screenshot).

### 4. eBPF — building and loading real BPF objects

- **ebpf-kernel-matrix** — boots real LTS kernels (5.15 and 6.6) in QEMU — a
  machine emulator that runs a complete virtual machine, real kernel and all,
  inside the CI runner (driven by `vimto`) — and actually **loads + attaches**
  the BPF programs (tracepoint + uprobes, one flush cycle). Static analysis
  cannot prove a BPF program loads; only a kernel's verifier can. One matrix
  entry raises kernel lockdown to INTEGRITY inside the VM and proves
  load+attach still works on a hardened kernel. amd64 runs under KVM
  (hardware-accelerated virtualization); the arm64 runner has no `/dev/kvm`,
  so it compiles + digest-verifies the arm64 objects but skips the (too-slow
  emulated) boot.
- **ebpf-image-live** — the shipped `probectl-ebpf-agent` image must carry the
  *live* CO-RE loader (CO-RE = Compile Once – Run Everywhere: the BPF object is
  relocated at load time to fit the running kernel's struct layouts), built
  from `Dockerfile.ebpf` and asserting `-tags=ebpf` — not the fixture replayer.

### 5. Real-infrastructure suites — spin up actual Postgres / Kafka / ClickHouse

- **cross-tenant-isolation** — the
  [tenant-isolation non-negotiable](../CONTRIBUTING.md#non-negotiables),
  executed (`make test-isolation`): row-level-security posture (RLS is the
  Postgres feature where the *database itself* filters every query by tenant,
  so even buggy handler code cannot return another tenant's rows) +
  cross-tenant injection against a real Postgres (over TLS,
  `sslmode=verify-full` — the client checks the server's certificate *and*
  hostname, like production) *and* a real ClickHouse (including its row-policy
  DDL).
- **integration** — boots the control plane against real Postgres (TLS,
  `verify-full`) plus a remote-write Prometheus; migrations are idempotent,
  `/readyz` passes, the result pipeline round-trips — and `internal/store` must
  hold its 60% integration-coverage floor.
- **perf-smoke** — a cheap, repeatable latency/throughput baseline; the first
  place a pooled-cardinality or RLS-cost regression would surface.
- **backup-drill** — backup → wipe → restore actually runs; nonce-marked rows
  must survive a full database drop.
- **failover-drill** — kills the primary, promotes the streaming standby, and
  times RTO (first write on the new primary) / RPO (acked rows lost).
- **load-smoke** — synthetic agents → real Kafka → the production consumer
  (retry/DLQ — a dead-letter queue, where a message that repeatedly fails
  processing is parked for inspection instead of retried forever or silently
  dropped — plus cardinality caps) → Prometheus remote-write → tenant-scoped
  PromQL, end to end.

### 6. AI quality

- **rca-eval** — a **blocking** evaluation of the AI root-cause analysis against
  fixtures, with quality floors (0.85 / 0.85). If RCA quality regresses, the build
  fails — the AI is held to a measured bar, not just "it compiled."

### 7. Deploy / packaging config

- **helm-gate** — the Helm charts lint for every reference profile and uphold
  the secure-by-default invariants (non-root/read-only pod,
  NetworkPolicy/PDB/HPA, drain probe, HSTS — the response header that pins
  browsers to HTTPS — and no default credentials); the rendered manifests are
  schema-validated with `kubeconform`, the GitOps (ArgoCD/Flux) manifests are
  checked, and the shipped compose file must pass `docker compose config`.
- **terraform-gate** — the Terraform module is `fmt`-clean and `terraform
  validate`s via an example root that consumes it.

### 8. Supply chain & artifacts

- **dependency-scan** — vulnerability scan of the dependency graph.
- **build-images** — builds the multi-arch container images.
- **image-scan** — scans those built images for known vulnerabilities.
- **sbom** — emits a software bill of materials for the build.

### 9. The umbrella

- **verify-all** — depends on the gates above, writes `verify-all-summary.json`
  as a receipt, and goes red listing any gate that wasn't green. This is the
  single signal of overall pipeline health.

## What a green pipeline proves

When `verify-all` is green for a commit, you've demonstrated — *on that exact
commit* — that the code:

- compiles and passes lint in every mode (normal, FIPS, eBPF);
- passes unit, real-Postgres, real-ClickHouse, and real-Kafka tests;
- keeps tenants isolated at the storage layer (RLS, enforced and tested);
- ships container images that scan clean, with an SBOM and SHA-pinned actions;
- didn't drift its API spec, protobufs, or migrations, and keeps zero-downtime
  upgrade compatibility;
- holds the AI's root-cause quality above its floor;
- survives a backup/restore and a primary failover.

That is a heavier pipeline than most projects run — closer to what a regulated
enterprise expects — which matches where probectl is aimed (sovereign,
multi-tenant, source-available).

## What the pipeline cannot self-apply

Branch-protection *enforcement* (making GitHub refuse to merge a red PR) is a
server-side repository setting, not something a workflow in the tree can turn
on. Until an admin configures it, every check above is advisory at the merge
button — the recommended ruleset (require `verify-all`, plus the four jobs
outside its roll-up) and the one-time console steps are in
[`docs/ops/branch-protection.md`](ops/branch-protection.md). The release path
has its own independent backstop either way: `release.yml` refuses to publish a
tag whose commit lacks a green `ci` run.
