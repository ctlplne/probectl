# netctl

Self-hosted, source-available, multi-tenant **network observability platform**.
netctl unifies five observability planes — active/synthetic testing, BGP/routing
intelligence, flow analytics, device telemetry, and eBPF host/L7 — into one
**OpenTelemetry-native** control plane, with an AI assistant for cross-plane
root-cause analysis, a native security/threat layer, change-aware topology, and
cost/SLO intelligence. Telemetry **never leaves the operator's network**.

One codebase serves two operating modes: **sovereign single-tenant** (a regulated
or air-gapped org self-hosts; the deployment *is* the tenant) and
**multi-tenant / provider** (an MSP self-hosts once and serves many hard-isolated,
white-labeled tenants). The single-tenant install is just the one-tenant case —
there is no separate code path. **Tenant is the outermost scope and security
boundary** on every record, agent, query, metric, event, and object.

> **Status: pre-code → M1 scaffolding (Sprint S0).** This is the repository,
> tooling, CI, and dev-stack bootstrap. There is no business logic yet — each
> subsystem is filled in by its sprint. The license is intentionally **`TBD`**.

## Repository layout

```
cmd/            # binaries: netctl-control, netctl-agent, netctl-ebpf-agent,
                #           netctl-endpoint, netctl (CLI)
internal/       # subsystem packages (control, tenancy, path, bgp, crypto, ...)
pkg/            # shared, public libraries
proto/          # protobuf schemas (gRPC + bus) — buf-managed
analyzer/       # Python BGP analyzer
migrations/     # sequential, idempotent SQL migrations
web/            # frontend (framework chosen in S8a)
deploy/         # compose (dev stack), helm, terraform, docker
docs/           # configuration, development, architecture, runbooks
test/           # integration harness (separate Go module)
```

## Quickstart

Prerequisites: **Go 1.26+**, **Docker** (with Buildx) for the dev stack and
images, and **Python 3.12+** for the analyzer tooling.

```sh
make build          # build all binaries into ./bin
make test           # unit tests across the workspace
make lint           # gofmt + go vet + golangci-lint, and ruff + black
make compose-up     # start Postgres + Kafka + ClickHouse + Prometheus
make run            # run netctl-control locally
make compose-down   # tear the dev stack down
make help           # list every target
```

See [`docs/development.md`](docs/development.md) for the full toolchain, `make`
targets, and CI jobs, and [`docs/configuration.md`](docs/configuration.md) for
dev-stack service names, ports, and credentials.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Work proceeds one sprint at a time;
commits follow **Conventional Commits** and reference their sprint + requirement
IDs. The canonical product/engineering specs (`CLAUDE.md`, the PRD, and the
sprint plan) are internal and are kept in the private working folder — they are
**not committed** to this repository.

## License

`TBD` — the license and the open-core / reseller boundary are an open decision
and have not been finalized. Until then, no OSS license is granted.
