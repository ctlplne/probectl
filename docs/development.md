# Development

This is the orientation page for building, testing, and contributing to probectl
from source. It tells you what toolchain to install, how the repo is laid out as a
Go workspace, which `make` target does what, and which CI gates your change has to
pass. If you just want to _deploy_ probectl, see [`install.md`](install.md)
instead.

## Toolchain

Install these once. Exact pinned versions for the tools probectl installs for you
(golangci-lint, buf, the protobuf plugins) live at the top of the
[`Makefile`](../Makefile) and are fetched by `make tools` / `make proto-tools` —
you do not pin them yourself.

| Tool            | Version              | Used for                                                                                          |
| --------------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| Go              | 1.26.4 (exact)       | control plane, agents, CLI (the patch is pinned — see [`build/toolchain.md`](build/toolchain.md)) |
| Python          | 3.11+ (CI runs 3.12) | the BGP analyzer (`analyzer/`)                                                                    |
| Docker + Buildx | recent               | dev stack + multi-arch images                                                                     |
| golangci-lint   | v2.12.2              | Go linting (installed via `make tools`)                                                           |
| buf             | v1.50.0              | protobuf lint + codegen (installed via `make proto-tools`)                                        |

> The Go version is pinned to the _exact patch_ (`1.26.4`), not a loose `1.26`.
> That is intentional — it keeps `govulncheck`'s standard-library scan honest and
> keeps the FIPS build working under `GOTOOLCHAIN=local`. Details:
> [`build/toolchain.md`](build/toolchain.md).

Two terms from that table that recur on this page: a **linter** is a program
that reads source code and flags suspicious-but-compiling constructs — the
compiler answers "does it build?", the linter answers "will it bite?" —
golangci-lint being Go's standard meta-linter (it runs many individual linters
as one). **Protobuf** is the typed binary wire format probectl's agents and
bus speak (schemas live in `proto/`), and **buf** is the tool that lints those
schemas and drives the Go code generation from them.

## Go workspace & modules

A Go **module** is a versioned unit of Go code with its own dependency
manifest (`go.mod`); a **workspace** (the [`go.work`](../go.work) file) tells
the Go tool to build several modules side-by-side from local source, as if
they were one project. Picture two workshops sharing one driveway: tools and
work-in-progress roll freely between them while each keeps its own inventory
list — and when a product ships, only that workshop's own list counts. The
repo is a workspace tying together two modules:

- **`.`** — the primary module `github.com/imfeelingtheagi/probectl` (`cmd/`,
  `internal/`, `pkg/`). Production code and unit tests live here.
- **`./test`** — the black-box integration harness. Kept as a _separate_ module on
  purpose: its heavy, test-only dependencies stay out of the main module's
  `go.mod`/`go.sum`, so production builds never pull them. These tests talk to
  services over the wire, not through `internal/`.

`make` commands that span modules iterate both (the `GO_MODULE_DIRS` loop in the
`Makefile`). Production builds use each module's own `go.mod`; the workspace is a
local/CI convenience.

## Make targets

Run `make help` for the authoritative, self-documenting list. The ones you'll
reach for most:

| Target                             | What it does                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| `make build`                       | Build all binaries into `./bin` (version stamped via `-ldflags`)                  |
| `make build-cross`                 | Cross-compile every binary for linux amd64 + arm64 (smoke)                        |
| `make run`                         | Run `probectl-control` locally                                                    |
| `make test`                        | Unit tests across all workspace modules (`-race`)                                 |
| `make test-isolation`              | Cross-tenant isolation gate (`-tags=isolation`)                                   |
| `make test-integration`            | Integration tests (`-tags=integration`; needs a DB / dev stack)                   |
| `make test-python`                 | `pytest` for the analyzer (incl. Hypothesis property tests)                       |
| `make cover-gate`                  | Per-package coverage floor on service-free packages (`scripts/check_coverage.sh`) |
| `make fuzz-smoke`                  | Run each Go fuzz target briefly to catch crashers                                 |
| `make lint`                        | `lint-go` + `lint-python`                                                         |
| `make fmt`                         | Auto-format Go (`gofmt`) and Python (`ruff check --fix`, `black`)                 |
| `make sdk`                         | Generate Go + TypeScript REST SDKs from `internal/control/openapi.json`           |
| `make sdk-gate`                    | Regenerate REST SDKs, fail on drift, and compile the generated Go SDK sample      |
| `make proto`                       | `buf lint` + generate Go (+ gRPC) from `proto/`                                   |
| `make proto-tools`                 | Install protobuf codegen tools (buf + Go plugins, pinned)                         |
| `make migrate`                     | Apply DB migrations via `probectl-control migrate`                                |
| `make vuln`                        | `govulncheck` over Go dependencies                                                |
| `make images`                      | Multi-arch (`amd64`/`arm64`) images for every component                           |
| `make compose-up` / `compose-down` | Start / stop the local dev dependency stack                                       |
| `make tools`                       | Install pinned dev tools (golangci-lint)                                          |
| `make ci`                          | `lint` + `test` + `test-isolation` (the core gates locally)                       |

> `make ci` runs the **core** gates fast and locally. It is _not_ the full CI
> suite — the integration, isolation-against-real-DBs, eBPF-kernel-matrix,
> coverage, and supply-chain gates run in GitHub Actions (next section). Most
> per-surface gates have an identically-named `make` target you can run
> yourself: `editions-gate`, `fips-gate`, `openapi-gate`, `sdk-gate`, `migration-gate`,
> `helm-gate`, `gitops-gate`, `terraform-gate`, `cover-gate`, `perf-smoke`,
> `e2e`.

## CI jobs (`.github/workflows/ci.yml`)

The CI job names are a **contract** — every pull request runs them, and they are
how a change earns its way to `main`. A **gate** is a job that must conclude
green before the change may proceed: each one defends a specific invariant, so
the table below doubles as a list of the things probectl refuses to break.
This is the full list; `ci.yml` is the source of truth.

| Job                      | Gate                                                                                                                                                                                                                                                     |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `action-pins`            | every workflow action is commit-SHA-pinned + the supply-pins gate (no `:latest` image refs under `deploy/`, no unpinned installs)                                                                                                                        |
| `secret-scan`            | gitleaks over every reachable git commit (`fetch-depth: 0`, `gitleaks git --log-opts=--all`); `.gitleaks.toml` allow-lists only deliberate test fixtures and exact historical false positives                                                           |
| `no-devauth-in-release`  | the dev-auth bypass is **physically absent** from release binaries — symbol + literal absence, and the binary refuses `PROBECTL_AUTH_MODE=dev` at boot                                                                                                   |
| `lint-go`                | `gofmt` + `go vet` + `golangci-lint` + crypto/editions/SQL/TLS import guards                                                                                                                                                                             |
| `lint-python`            | `ruff check` + `black --check`                                                                                                                                                                                                                           |
| `editions-gate`          | `ee/` import guard + the core-only build/test (`-tags probectl_core`)                                                                                                                                                                                    |
| `fips-gate`              | FIPS artifact builds + power-on self-test passes                                                                                                                                                                                                         |
| `test-go`                | unit tests (`-race`) + backup/erasure tests + **fuzz smoke** (parsers must not crash) + bench smoke + cross-compile (incl. the endpoint agent's Linux/macOS/Windows builds)                                                                              |
| `rca-eval`               | the AI root-cause eval set through the real pipeline; **blocking** floors: answer accuracy ≥ 0.85, citation precision ≥ 0.85                                                                                                                             |
| `coverage`               | per-package coverage floor on service-free packages (`make cover-gate`)                                                                                                                                                                                  |
| `test-python`            | analyzer `pytest` (incl. Hypothesis property tests) + hash-lock drift refusal                                                                                                                                                                            |
| `browser-worker`         | the Playwright synthetic worker: real-browser scripted-login smoke inside the official Playwright image                                                                                                                                                  |
| `openapi-gate`           | spec is valid OpenAPI 3.1 and the registered `/v1` routes exactly match it (no undocumented routes)                                                                                                                                                      |
| `sdk-gate`               | REST SDKs regenerate from `internal/control/openapi.json` without drift, and the generated Go SDK sample compiles against `ListTests`                                                                                                                     |
| `migration-gate`         | expand/contract migrations only — rejects destructive/blocking schema changes                                                                                                                                                                            |
| `helm-gate`              | chart hardening for every profile + the agent chart (`make helm-gate`), kubeconform on the rendered charts, GitOps manifest validation (`make gitops-gate`), compose config validation                                                                   |
| `compose-image-gate`     | shipped Compose image, install docs, GHCR auth/mirror instructions, and optional anonymous-pull smoke stay in lockstep                                                                                                                                   |
| `terraform-gate`         | `terraform fmt -check` + `terraform validate` of the module's example root                                                                                                                                                                               |
| `ebpf-kernel-matrix`     | the BPF programs **load and attach** on real LTS kernels (5.15/6.6 plus a lockdown-hardened entry) booted under QEMU/KVM on amd64 and on the self-hosted Linux/ARM64 `kvm` runner; missing KVM is a CI failure, not a green skip |
| `ebpf-image-live`        | the shipped eBPF-agent image is the live `-tags ebpf` build, not the fixture replayer                                                                                                                                                                    |
| `cross-tenant-isolation` | **permanent** tenant-isolation gate (a [non-negotiable](../CONTRIBUTING.md#non-negotiables)), against real Postgres (TLS) + ClickHouse                                                                                                                   |
| `integration`            | migrations are idempotent + `/readyz` passes + result pipeline, against a real Postgres + Prometheus                                                                                                                                                     |
| `perf-smoke`             | ingest baseline + pooled multi-tenant query-latency smoke                                                                                                                                                                                                |
| `backup-drill`           | the backup → wipe → restore drill executes against real stores                                                                                                                                                                                           |
| `failover-drill`         | timed kill-the-primary → promote-the-replica drill (RTO/RPO measured)                                                                                                                                                                                    |
| `chaos-dependency-drill` | dependency chaos injects agent-buffer disk pressure, a disposable control-plane pod kill, dependency outage, memory pressure, and prints recovery counters                                                                                               |
| `load-smoke`             | S-tier full-stack load smoke through real Kafka + Prometheus + ClickHouse                                                                                                                                                                                |
| `proto`                  | `buf lint` + `buf breaking` vs `main` (additive-only wire contract) + generated-code drift                                                                                                                                                               |
| `web`                    | typecheck + lint + the frontend surface-coverage gate + jsdom axe/theme/no-hardcoded-token gates + rendered Chromium a11y (`web-rendered-a11y`) + `npm audit` + production build                                                                         |
| `dependency-scan`        | `govulncheck` + Trivy filesystem scan (**vulnerabilities only**)                                                                                                                                                                                         |
| `image-scan`             | Trivy image scan (**vulnerabilities only**)                                                                                                                                                                                                              |
| `build-images`           | multi-arch image build for every component (Buildx + QEMU)                                                                                                                                                                                               |
| `commitlint`             | Conventional Commits (pull requests only)                                                                                                                                                                                                                |
| `dco`                    | every commit carries a `Signed-off-by` trailer (pull requests only)                                                                                                                                                                                      |
| `sbom`                   | CycloneDX SBOM (a **software bill of materials** — the machine-readable parts list) of the Go module graph, retained 90 days (informational, not a merge gate)                                                                                           |
| `verify-all`             | the umbrella check: red unless every verification job it depends on concluded green — the gates are wired in series, like a strand of old holiday lights: one dark bulb darkens the whole strand                                                         |

> **Trivy is vulnerability-only here, by design.** Secret scanning is the separate
> `secret-scan` job (gitleaks), which owns the `.gitleaks.toml` allow-list for the
> deliberate fake secrets inside redaction tests. Trivy can't see that allow-list,
> so pointing it at secrets would re-flag those intentional fixtures — hence
> `scanners: vuln` in both Trivy jobs.

Two more workflows run outside the pull-request loop: **`nightly.yml`** (the
black-box full-stack e2e via `make e2e`, ingest benchmarks, and the M-profile
scale-gate regression guard — too slow to run per-PR) and
**`security-scan.yml`** (weekly `govulncheck` / `npm audit` / Trivy with
retained evidence artifacts, so a newly-disclosed CVE in an _unchanged_ pin
still goes red on its own).

CI itself cannot make merges blocking — that is **branch protection**, a GitHub
repository setting documented in
[`ops/branch-protection.md`](ops/branch-protection.md). Independently of it, the
release pipeline refuses to publish any tag whose CI run isn't green (see
[`releasing.md`](releasing.md)).

## Testing layers

probectl tests in layers, fast-to-slow, each catching a different class of bug —
sieves of decreasing mesh, where each pass is slower and catches what the
previous mesh let through. The vocabulary: a **unit test** runs a function
in-process with no real services — fast, deterministic, repeatable anywhere.
An **integration test** talks to the real thing (a live Postgres, a real
Kafka broker) over the wire, catching the bugs that only exist where two
systems meet. The **race detector** (`-race`) instruments the test binary so
that two goroutines touching the same memory without synchronization fail the
run on the spot, instead of corrupting state in production some Tuesday. And a
**build tag** (`-tags=integration`, `-tags=isolation`) is a compile-time label
on a file: tagged tests exist only when the tag is passed, which is how the
slow, service-needing suites stay out of the default fast path.

### Local test DSNs (documented dev-only plaintext)

Integration and isolation tests fall back to `sslmode=disable` DSNs (**data
source names** — database connection strings)
**only when `PROBECTL_DATABASE_URL` is unset** — the local-dev convenience path
against the `test/` compose stack. CI never uses those fallbacks: every DB-backed
job starts Postgres with TLS under a per-run test CA and connects
`sslmode=verify-full` (`scripts/ci_pg_tls.sh`), the production posture. The shipped
deploy recipes are `sslmode=require` or stricter.

- **Unit** (`make test`, `-race`) — hermetic (no real services, everything
  in-process), table-driven (one test body run over a table of cases); the
  default fast path.
- **Integration** (`make test-integration`, `-tags=integration`) — against real
  Kafka (in-process kfake), Postgres, ClickHouse, and Prometheus, plus in-process
  HTTPS/DNS servers and loopback sockets for the probes. The DNS/HTTP/TLS canary
  behaviour (success / 5xx / slow / expired-cert / DNSSEC-bogus) lives here.
- **Fuzz** (`make fuzz-smoke`) — **fuzzing** feeds a parser thousands of
  mutated, adversarial inputs hunting for the one that crashes it. The Go fuzz
  targets cover the untrusted-input parsers and tenant-bound ingest invariants.
  `scripts/list_fuzz_targets.sh` discovers every `Fuzz*` target under
  `internal/`, so adding a fuzz function automatically puts it in PR smoke and
  the nightly matrix. The invariant is "never panic", and tenant-sensitive
  paths must additionally never publish a tenant-less event under fuzzing — the
  fail-closed tenancy rule (see the
  [non-negotiables](../CONTRIBUTING.md#non-negotiables)). CI runs a short smoke;
  nightly runs each target in its own long-budget shard.
- **Property** (Hypothesis, in the analyzer suite) — where fuzzing asks "does it
  crash?", a **property test** asserts a stated invariant holds for every
  generated input: the MRT parser and RPKI
  validator are checked over thousands of generated inputs (robustness +
  round-trip + soundness), the Python counterpart to the Go fuzzers.
- **Coverage gate** (`make cover-gate` → the `coverage` CI job) — **statement
  coverage** is the fraction of code statements the tests actually executed; a
  **floor** fails CI when a package drops below its number. This gate floors the
  service-free logic / parser / probe packages
  (`scripts/check_coverage.sh`). The stateful DB/transport packages are gated for
  _correctness_ by the `integration` and `cross-tenant-isolation` jobs instead — a
  stronger guarantee than a coverage percentage — so they are not floored here.

## Commits

Use **Conventional Commits** (e.g. `feat(canary): add ICMP network test`) — a
machine-parseable subject format, `type(scope): summary`, which is what lets
release notes be generated from history instead of written by hand — and
sign off every commit (`git commit -s`, which adds the `Signed-off-by` trailer the
`dco` CI job requires; the **DCO**, Developer Certificate of Origin, is your
recorded assertion that you have the right to contribute the change). See
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). You can
pre-load the message template with:

```sh
git config commit.template .gitmessage
```
