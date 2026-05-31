# test/

Integration / end-to-end test harness.

These are **black-box** tests: they exercise the running services over their
public interfaces (REST, gRPC, the bus) against the real dev stack defined in
[`deploy/compose/dev.yml`](../deploy/compose/README.md) — Postgres, Kafka,
ClickHouse, and Prometheus — rather than importing `internal/` packages.

## Why a separate module

`test/` is its own Go module (`github.com/imfeelingtheagi/netctl/test`) tied into
the workspace via `go.work`. This keeps heavy, test-only dependencies
(Kafka/ClickHouse/Postgres drivers, testcontainers, …) out of the main module's
`go.mod`/`go.sum`. Those dependencies arrive with the result pipeline (S6+).

## Running

```sh
make test-integration   # go test -tags=integration ./...  (needs the dev stack up)
```

Build-tagged `integration`, so these never run during the default `make test`.
The unit-level **cross-tenant isolation** gate is separate — see
`make test-isolation` and `internal/tenancy/` (CLAUDE.md §7 guardrail 1).
