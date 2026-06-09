# Development

This is the orientation page for building, testing, and contributing to probectl
from source. It tells you what toolchain to install, how the repo is laid out as a
Go workspace, which `make` target does what, and which CI gates your change has to
pass. If you just want to *deploy* probectl, see [`install.md`](install.md)
instead.

## Toolchain

Install these once. Exact pinned versions for the tools probectl installs for you
(golangci-lint, buf, the protobuf plugins) live at the top of the
[`Makefile`](../Makefile) and are fetched by `make tools` / `make proto-tools` —
you do not pin them yourself.

| Tool            | Version           | Used for                                          |
| --------------- | ----------------- | ------------------------------------------------- |
| Go              | 1.26.4 (exact)    | control plane, agents, CLI (the patch is pinned — see [`build/toolchain.md`](build/toolchain.md)) |
| Python          | 3.11+ (CI runs 3.12) | the BGP analyzer (`analyzer/`)                 |
| Docker + Buildx | recent            | dev stack + multi-arch images                     |
| golangci-lint   | v2.12.2           | Go linting (installed via `make tools`)           |
| buf             | v1.50.0           | protobuf lint + codegen (installed via `make proto-tools`) |

> The Go version is pinned to the *exact patch* (`1.26.4`), not a loose `1.26`.
> That is intentional — it keeps `govulncheck`'s standard-library scan honest and
> keeps the FIPS build working under `GOTOOLCHAIN=local`. Details:
> [`build/toolchain.md`](build/toolchain.md).

## Go workspace & modules

The repo is a [`go.work`](../go.work) workspace tying together two modules:

- **`.`** — the primary module `github.com/imfeelingtheagi/probectl` (`cmd/`,
  `internal/`, `pkg/`). Production code and unit tests live here.
- **`./test`** — the black-box integration harness. Kept as a *separate* module on
  purpose: its heavy, test-only dependencies stay out of the main module's
  `go.mod`/`go.sum`, so production builds never pull them. These tests talk to
  services over the wire, not through `internal/`.

`make` commands that span modules iterate both (the `GO_MODULE_DIRS` loop in the
`Makefile`). Production builds use each module's own `go.mod`; the workspace is a
local/CI convenience.

## Make targets

Run `make help` for the authoritative, self-documenting list. The ones you'll
reach for most:

| Target                  | What it does                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `make build`            | Build all binaries into `./bin` (version stamped via `-ldflags`) |
| `make build-cross`      | Cross-compile every binary for linux amd64 + arm64 (smoke)   |
| `make run`              | Run `probectl-control` locally                               |
| `make test`             | Unit tests across all workspace modules (`-race`)            |
| `make test-isolation`   | Cross-tenant isolation gate (`-tags=isolation`)             |
| `make test-integration` | Integration tests (`-tags=integration`; needs a DB / dev stack) |
| `make test-python`      | `pytest` for the analyzer (incl. Hypothesis property tests) |
| `make cover-gate`       | Per-package coverage floor on service-free packages (`scripts/check_coverage.sh`) |
| `make fuzz-smoke`       | Run each Go fuzz target briefly to catch crashers           |
| `make lint`             | `lint-go` + `lint-python`                                    |
| `make fmt`              | Auto-format Go (`gofmt`) and Python (`ruff --fix`, `black`)  |
| `make proto`            | `buf lint` + generate Go (+ gRPC) from `proto/`             |
| `make proto-tools`      | Install protobuf codegen tools (buf + Go plugins, pinned)   |
| `make migrate`          | Apply DB migrations via `probectl-control migrate`          |
| `make vuln`             | `govulncheck` over Go dependencies                          |
| `make images`           | Multi-arch (`amd64`/`arm64`) images for every component     |
| `make compose-up` / `compose-down` | Start / stop the local dev dependency stack      |
| `make tools`            | Install pinned dev tools (golangci-lint)                    |
| `make ci`              | `lint` + `test` + `test-isolation` (the core gates locally) |

> `make ci` runs the **core** gates fast and locally. It is *not* the full CI
> suite — the integration, isolation-against-real-DBs, eBPF-kernel-matrix,
> coverage, and supply-chain gates run in GitHub Actions (next section).

## CI jobs (`.github/workflows/ci.yml`)

The CI job names are a **contract** — every pull request runs them, and they are
how a change earns its way to `main`. The table below is the load-bearing subset;
`ci.yml` is the source of truth.

| Job                      | Gate                                                              |
| ------------------------ | ---------------------------------------------------------------- |
| `lint-go`                | `gofmt` + `go vet` + `golangci-lint` + crypto/editions/SQL/TLS import guards |
| `lint-python`            | `ruff check` + `black --check`                                  |
| `test-go`                | unit tests (`-race`) + **fuzz smoke** (parsers must not crash) + cross-compile |
| `test-python`            | analyzer `pytest` (incl. Hypothesis property tests)             |
| `coverage`               | per-package coverage floor on service-free packages             |
| `editions-gate`          | `ee/` import guard + the core-only build/test (`-tags probectl_core`) |
| `fips-gate`              | FIPS artifact builds + power-on self-test passes                |
| `cross-tenant-isolation` | **permanent** tenant-isolation gate (CLAUDE.md §7 g.1), real Postgres + ClickHouse |
| `integration`            | migrations are idempotent + `/readyz` passes + result pipeline, against a real Postgres |
| `proto`                  | `buf lint` + breaking-change check + generated-code drift       |
| `dependency-scan`        | `govulncheck` + Trivy filesystem scan (**vulnerabilities only**) |
| `image-scan`             | Trivy image scan (**vulnerabilities only**)                    |
| `build-images`           | multi-arch image build for every component (Buildx + QEMU)     |
| `commitlint`             | Conventional Commits (pull requests only)                       |
| `dco`                    | every commit carries a `Signed-off-by` trailer (pull requests only) |

> **Trivy is vulnerability-only here, by design.** Secret scanning is the separate
> `secret-scan` job (gitleaks), which owns the `.gitleaks.toml` allow-list for the
> deliberate fake secrets inside redaction tests. Trivy can't see that allow-list,
> so pointing it at secrets would re-flag those intentional fixtures — hence
> `scanners: vuln` in both Trivy jobs.

There is no branch-protection job in CI: it was removed as premature ceremony for
a solo, pre-GA repo. The release pipeline still refuses to publish a tag whose CI
run isn't green (see [`releasing.md`](releasing.md)).

## Testing layers

probectl tests in layers, fast-to-slow, each catching a different class of bug.

### Local test DSNs (documented dev-only plaintext)

Integration and isolation tests fall back to `sslmode=disable` connection strings
**only when `PROBECTL_DATABASE_URL` is unset** — the local-dev convenience path
against the `test/` compose stack. CI never uses those fallbacks: every DB-backed
job starts Postgres with TLS under a per-run test CA and connects
`sslmode=verify-full` (`scripts/ci_pg_tls.sh`), the production posture. The shipped
deploy recipes are `sslmode=require` or stricter.

- **Unit** (`make test`, `-race`) — hermetic, table-driven; the default fast path.
- **Integration** (`make test-integration`, `-tags=integration`) — against real
  Kafka (in-process kfake), Postgres, ClickHouse, and Prometheus, plus in-process
  HTTPS/DNS servers and loopback sockets for the probes. The DNS/HTTP/TLS canary
  behaviour (success / 5xx / slow / expired-cert / DNSSEC-bogus) lives here.
- **Fuzz** (`make fuzz-smoke`) — Go fuzz targets over the untrusted-input parsers
  (ICMP / Time-Exceeded / MPLS in `internal/path`, the BGP-event ingest in
  `internal/bgp`). The invariant is "never panic", and the bridge must
  additionally never publish a tenant-less event under fuzzing (fail-closed,
  guardrail 1). CI runs a short smoke; run longer locally with `-fuzztime`.
- **Property** (Hypothesis, in the analyzer suite) — the MRT parser and RPKI
  validator are checked over thousands of generated inputs (robustness +
  round-trip + soundness), the Python counterpart to the Go fuzzers.
- **Coverage gate** (`make cover-gate` → the `coverage` CI job) — a per-package
  statement-coverage **floor** on the service-free logic / parser / probe packages
  (`scripts/check_coverage.sh`). The stateful DB/transport packages are gated for
  *correctness* by the `integration` and `cross-tenant-isolation` jobs instead — a
  stronger guarantee than a coverage percentage — so they are not floored here.

## Commits

Use **Conventional Commits** (e.g. `feat(canary): add ICMP network test`), and
sign off every commit (`git commit -s`, which adds the `Signed-off-by` trailer the
`dco` CI job requires). See [`../CONTRIBUTING.md`](../CONTRIBUTING.md). You can
pre-load the message template with:

```sh
git config commit.template .gitmessage
```
