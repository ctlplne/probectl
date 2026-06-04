# probectl

Self-hosted, source-available, multi-tenant **network observability platform**.
probectl unifies five observability planes — active/synthetic testing, BGP/routing
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

> **Status: Phase 1 GA (M6).** The MVP is in place: the five-plane foundation
> (active/synthetic tests, BGP/routing intelligence, path discovery), alerting,
> cross-plane incident correlation, OIDC SSO + RBAC, a tamper-evident audit log,
> and **HTTPS-by-default** compose + Helm deploys. The license is intentionally
> **`TBD`** (the open-core / reseller boundary is an open decision).

## Repository layout

```
cmd/            # binaries: probectl-control, probectl-agent, probectl-ebpf-agent,
                #           probectl-endpoint, probectl (CLI)
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

## Quickstart (run it)

Bring up the control plane **over HTTPS** with a bundled Postgres (a self-signed
cert is generated on first boot):

```sh
cp deploy/compose/.env.example deploy/compose/.env     # set PROBECTL_ENVELOPE_KEY etc.
docker compose -f deploy/compose/probectl.yml up -d
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt
curl --cacert ./ca.crt https://localhost:8443/readyz
```

The API is HTTPS-only (no plaintext port). Full guide, real certificates, SSO, and
the Kubernetes/Helm path: **[`docs/install.md`](docs/install.md)**; day-2
operation (audit, roles, SSO): **[`docs/admin.md`](docs/admin.md)**.

## Build from source

Prerequisites: **Go 1.26+**, **Docker** (with Buildx) for the dev stack and
images, and **Python 3.12+** for the analyzer tooling.

```sh
make build          # build all binaries into ./bin
make test           # unit tests across the workspace
make lint           # gofmt + go vet + golangci-lint, and ruff + black
make compose-up     # start the dev dependency stack (Postgres/Kafka/ClickHouse/Prometheus)
make run            # run probectl-control locally
make help           # list every target
```

See [`docs/development.md`](docs/development.md) for the toolchain, `make` targets,
and CI jobs, [`docs/configuration.md`](docs/configuration.md) for every config
key, and [`SECURITY.md`](SECURITY.md) for vulnerability disclosure.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Work proceeds one sprint at a time;
commits follow **Conventional Commits** and reference their sprint + requirement
IDs. The canonical product/engineering specs (`CLAUDE.md`, the PRD, and the
sprint plan) are internal and are kept in the private working folder — they are
**not committed** to this repository.

## License

`TBD` — the license and the open-core / reseller boundary are an open decision
and have not been finalized. Until then, no OSS license is granted.
