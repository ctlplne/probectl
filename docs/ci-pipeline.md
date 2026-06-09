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
| `release.yml` | push of a `v*` tag | build/sign/publish a release (requires CI green first) |
| `nightly.yml` | daily 03:17 UTC (+ manual) | longer-running checks off the push path |
| `security-scan.yml` | weekly, Mondays (+ manual) | scheduled security scans |

## The shape: fan-out, then one umbrella

A push is like sending the change through a checkpoint with **32 specialist
inspectors**, each examining one thing, all in parallel. A 33rd job —
`verify-all` — is the supervisor: it `needs:` 28 of them (the four that don't
gate a merge — `commitlint`, `dco`, `image-scan`, `sbom` — are left out of the
roll-up), runs with `if: always()`, writes a receipt artifact, and **fails
loudly listing any non-green gate**. It is the one status you actually watch:
green `verify-all` = the whole pipeline passed.

The guiding principle, visible throughout the repo: **every guardrail in
`CLAUDE.md` has a matching CI gate, and the gates _execute_ the thing rather than
just inspecting it** — they boot real kernels, real databases, real Kafka, and
drill real failovers. Verification you ran, not verification you described.

## The jobs, by stage

### 1. Cheap gatekeeping — "is this change even well-formed?"

- **action-pins** — every GitHub Action is pinned to a commit SHA, not a moving
  tag, so a hijacked upstream action can't slip in (supply-chain).
- **secret-scan** — gitleaks: no credentials/keys committed. Deliberate
  redaction-test fixtures are allowlisted in `.gitleaks.toml`.
- **commitlint** — commit messages follow Conventional Commits (`feat(...)`,
  `fix(ci): ...`).
- **dco** — every commit carries a `Signed-off-by` (the Developer Certificate of
  Origin; what `git commit -s` adds).
- **no-devauth-in-release** — proves the dev-auth bypass is *physically absent*
  from a release binary (symbol + literal absence + a boot-time refusal of
  `PROBECTL_AUTH_MODE=dev`), and compiles a tagged build to confirm the check
  isn't vacuous.

### 2. Static checks — compile, lint, spec; no services yet

- **lint-go** / **lint-python** — golangci-lint (gofmt, vet, the hardened-HTTP
  client check) on Go; ruff/black on the BGP analyzer.
- **editions-gate** — enforces the open-core boundary: **core never imports
  `ee/`**.
- **fips-gate** — the FIPS build (`-tags probectl_fips`) still compiles and passes.
- **proto** — the generated `*.pb.go` match the `.proto` files (no drift).
- **openapi-gate** — every registered `/v1` route exactly matches the OpenAPI 3.1
  spec; no undocumented routes ship.
- **migration-gate** — DB migrations are additive / expand-only: it rejects
  destructive or blocking changes (drop column, column-type change, rename,
  adding `NOT NULL`) so release N's schema still works with N-1's code during a
  rolling upgrade.

### 3. Tests + coverage

- **test-go** — the Go unit suite, run with `-race`.
- **test-python** — the BGP analyzer's tests.
- **coverage** — per-package statement-coverage **floors** on the service-free
  logic/parser/probe packages (`scripts/check_coverage.sh`); retains
  `coverage.out` + a per-package summary as a diligence-receipt artifact.
- **web** — the frontend: typecheck, lint, production build; the test step *is*
  the WCAG 2.2 AA accessibility + theme-token gate.
- **browser-worker** — the Playwright browser-synthetic worker, run inside the
  official Playwright image (a real scripted login, timings + failure screenshot).

### 4. eBPF — building and loading real BPF objects

- **ebpf-kernel-matrix** — boots real LTS kernels in QEMU (via `vimto`) and
  actually **loads + attaches** the BPF programs (tracepoint + uprobes, one flush
  cycle). amd64 runs under KVM; the arm64 runner has no `/dev/kvm`, so it
  compiles + digest-verifies the objects but skips the (too-slow emulated) boot.
- **ebpf-image-live** — the shipped `probectl-ebpf-agent` image must carry the
  *live* CO-RE loader (built from `Dockerfile.ebpf`, asserting `-tags=ebpf`), not
  the fixture replayer.

### 5. Real-infrastructure suites — spin up actual Postgres / Kafka / ClickHouse

- **cross-tenant-isolation** — the `CLAUDE.md` §7.1 guardrail, executed: RLS
  posture + cross-tenant injection against real Postgres *and* ClickHouse, over
  TLS `verify-full` like production.
- **integration** — boots the control plane against real Postgres; migrations are
  idempotent and `/readyz` passes.
- **perf-smoke** — a cheap, repeatable latency/throughput baseline; the first
  place a pooled-cardinality or RLS-cost regression would surface.
- **backup-drill** — backup → wipe → restore actually runs; nonce-marked rows
  must survive a full database drop.
- **failover-drill** — kills the primary, promotes the streaming standby, and
  times RTO (first write on the new primary) / RPO (acked rows lost).
- **load-smoke** — synthetic agents → real Kafka → the production consumer
  (retry/DLQ + cardinality caps) → Prometheus remote-write → tenant-scoped PromQL,
  end to end.

### 6. AI quality

- **rca-eval** — a **blocking** evaluation of the AI root-cause analysis against
  fixtures, with quality floors (0.85 / 0.85). If RCA quality regresses, the build
  fails — the AI is held to a measured bar, not just "it compiled."

### 7. Deploy / packaging config

- **helm-gate** — the Helm chart lints for every reference profile and upholds the
  secure-by-default invariants (non-root/read-only pod, NetworkPolicy/PDB/HPA,
  drain probe, HSTS, no default credentials).
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

That is an unusually thorough pipeline for a solo, pre-GA project — closer to what
a regulated enterprise runs — which matches where probectl is aimed (sovereign,
multi-tenant, source-available).

## Not (yet) gated on push

Branch-protection *enforcement* (requiring these checks before a merge) is a
separate GitHub repository setting, not something the pipeline can self-apply. It
was deliberately dropped for the solo, pre-GA stage; re-introduce a ruleset that
requires `verify-all` if/when a team or a public repo makes it worthwhile.
