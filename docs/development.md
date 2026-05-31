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

- **`.`** — the primary module `github.com/imfeelingtheagi/netctl` (`cmd/`,
  `internal/`, `pkg/`). Production code and unit tests live here.
- **`./test`** — `…/netctl/test`, the black-box integration harness. Kept
  separate so heavy, test-only dependencies stay out of the main module
  (deps arrive in S6+). These tests talk to services over the wire, not via
  `internal/`.

`make` commands that span modules iterate both (see the `GO_MODULE_DIRS` loop).

## Make targets

| Target              | What it does                                                  |
| ------------------- | ------------------------------------------------------------ |
| `make build`        | Build all binaries into `./bin` (ldflags-stamped version)    |
| `make run`          | Run `netctl-control` locally                                 |
| `make test`         | Unit tests across all workspace modules (`-race`)            |
| `make test-isolation` | Cross-tenant isolation gate (`-tags=isolation`)            |
| `make test-integration` | Integration tests (`-tags=integration`; needs the dev stack) |
| `make test-python`  | `pytest` for the analyzer                                     |
| `make lint`         | `lint-go` + `lint-python`                                     |
| `make fmt`          | Auto-format Go (`gofmt`) and Python (`ruff --fix`, `black`)   |
| `make proto`        | `buf generate` (no-op until the first `.proto`, S4/S6)       |
| `make migrate`      | Apply DB migrations (runner in S1; migrations from S2)        |
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
| `test-go`                | unit tests across modules                                   |
| `test-python`            | analyzer `pytest`                                           |
| `cross-tenant-isolation` | **permanent** tenant-isolation gate (CLAUDE.md §7 g.1)      |
| `dependency-scan`        | `govulncheck` + Trivy filesystem scan (vulns + secrets)     |
| `build-images`           | multi-arch image build for every component (Buildx + QEMU)  |
| `image-scan`             | Trivy image scan                                            |
| `commitlint`             | Conventional Commits on PRs                                 |

## Commits

Conventional Commits, referencing the sprint + requirement IDs — see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). Enable the message template with
`git config commit.template .gitmessage`.
