# Development

## Toolchain

| Tool          | Version  | Used for                                  |
| ------------- | -------- | ----------------------------------------- |
| Go            | 1.26+    | control plane, agents, CLI                |
| Python        | 3.12+    | the BGP analyzer (`analyzer/`)            |
| Docker + Buildx | recent | dev stack + multi-arch images             |
| golangci-lint | v2.x     | Go linting (installed via `make tools`)   |
| buf           | v2.x     | protobuf codegen (only once `.proto` exists) |

## Go workspace & modules

The repo is a `go.work` workspace with two modules:

- **`.`** — the primary module `github.com/imfeelingtheagi/probectl` (`cmd/`,
  `internal/`, `pkg/`). Production code and unit tests live here.
- **`./test`** — `…/probectl/test`, the black-box integration harness. Kept
  separate so heavy, test-only dependencies stay out of the main module
  (deps arrive in S6+). These tests talk to services over the wire, not via
  `internal/`.

`make` commands that span modules iterate both (see the `GO_MODULE_DIRS` loop).

## Make targets

| Target              | What it does                                                  |
| ------------------- | ------------------------------------------------------------ |
| `make build`        | Build all binaries into `./bin` (ldflags-stamped version)    |
| `make build-cross`  | Cross-compile every binary for linux amd64 + arm64 (smoke)   |
| `make run`          | Run `probectl-control` locally                                 |
| `make test`         | Unit tests across all workspace modules (`-race`)            |
| `make test-isolation` | Cross-tenant isolation gate (`-tags=isolation`)            |
| `make test-integration` | Integration tests (`-tags=integration`; needs the dev stack) |
| `make test-python`  | `pytest` for the analyzer (incl. Hypothesis property tests)  |
| `make cover-gate`   | Per-package coverage floor on service-free packages (`scripts/check_coverage.sh`) |
| `make fuzz-smoke`   | Run each Go fuzz target briefly to catch crashers            |
| `make lint`         | `lint-go` + `lint-python`                                     |
| `make fmt`          | Auto-format Go (`gofmt`) and Python (`ruff --fix`, `black`)   |
| `make proto`        | `buf lint` + generate Go (+ gRPC) from `proto/`              |
| `make proto-tools`  | Install protobuf codegen tools (buf + Go plugins)           |
| `make migrate`      | Apply DB migrations via `probectl-control migrate`             |
| `make test-integration` | Integration tests across modules (needs a database)     |
| `make vuln`         | `govulncheck` over Go dependencies                           |
| `make images`       | Multi-arch (`amd64`/`arm64`) images for every component       |
| `make compose-up` / `compose-down` | Start / stop the dev stack                    |
| `make tools`        | Install pinned dev tools (golangci-lint)                     |
| `make ci`           | `lint` + `test` + `test-isolation` (the core gates locally)  |

## CI jobs (`.github/workflows/ci.yml`)

The job names are a **contract** introduced in S0:

| Job                      | Gate                                                         |
| ------------------------ | ----------------------------------------------------------- |
| `lint-go`                | `gofmt` + `go vet` + `golangci-lint`                        |
| `lint-python`            | `ruff check` + `black --check`                              |
| `test-go`                | unit tests + **fuzz smoke** (parsers must not crash)        |
| `test-python`            | analyzer `pytest` (incl. Hypothesis property tests)         |
| `coverage`               | per-package coverage floor on service-free packages         |
| `cross-tenant-isolation` | **permanent** tenant-isolation gate (CLAUDE.md §7 g.1)      |
| `integration`            | migrations + readiness + agent mTLS against a Postgres service |
| `proto`                  | `buf lint` + breaking-change check + codegen drift          |
| `dependency-scan`        | `govulncheck` + Trivy filesystem scan (vulns + secrets)     |
| `build-images`           | multi-arch image build for every component (Buildx + QEMU)  |
| `image-scan`             | Trivy image scan                                            |
| `commitlint`             | Conventional Commits on PRs                                 |

## Testing layers

- **Unit** (`make test`, `-race`) — hermetic, table-driven; the default fast path.
- **Integration** (`make test-integration`, `-tags=integration`) — against real
  Kafka (in-process kfake), Postgres, ClickHouse, and Prometheus, plus in-process
  HTTPS/DNS servers and loopback sockets for the probes. The DNS/HTTP/TLS canary
  behaviour (success / 5xx / slow / expired-cert / DNSSEC-bogus) lives here.
- **Fuzz** (`make fuzz-smoke`) — Go `-fuzz` targets over the untrusted-input
  parsers (ICMP/Time-Exceeded/MPLS in `internal/path`, the BGP-event ingest in
  `internal/bgp`). The invariant is "never panic", and the bridge additionally
  must never publish a tenant-less event under fuzzing (fail-closed, guardrail 1).
  CI runs a short smoke; run longer locally with `-fuzztime`.
- **Property** (Hypothesis, in the analyzer suite) — the MRT parser and RPKI
  validator are checked over thousands of generated inputs (robustness +
  round-trip + soundness), the Python counterpart to the Go fuzzers.
- **Coverage gate** (`make cover-gate` → `coverage` CI job) — a per-package
  statement-coverage **floor** on the service-free logic / parser / probe
  packages (`scripts/check_coverage.sh`). The stateful DB/transport packages are
  gated for correctness by the `integration` and `cross-tenant-isolation` jobs
  instead — a stronger guarantee than a percentage — so they are not floored here.

## Commits

Conventional Commits, referencing the sprint + requirement IDs — see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). Enable the message template with
`git config commit.template .gitmessage`.
