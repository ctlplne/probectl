# Hot-path performance SLO catalog

This catalog defines the first-pass latency and throughput objectives for
user-visible probectl hot paths. It answers a simple operational question:
"when a tenant clicks, queries, ingests, or asks, what is fast enough?"

These rows are **target definitions plus measurement receipts**. They do not
replace the L/XL reference-hardware scale proof in
[`scale-gate.md`](scale-gate.md). PERF-001 owns that external measurement. This
catalog closes the separate gap where most hot paths had no written p50/p95/p99
target and no receipt to measure against.

## How to read the table

- **p50** is the median request: half are faster, half are slower.
- **p95** is the "one slow request in twenty" ceiling. This is the main user
  experience target.
- **p99** is the tail ceiling. If this is red, a small but real slice of users
  feels pain.
- **Throughput floor** is the minimum steady request/payload rate at the normal
  payload shape for that path.
- **Receipt** is the runnable benchmark, load gate, or trace field used to
  measure the row.

## Catalog

| ID | Hot path | Served surface | p50 | p95 | p99 | Throughput floor | Receipt |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `hp-agent-control-checkin` | Agent control-plane check-in/read model | `GET /v1/agents/{id}/ci` | 50 ms | 250 ms | 750 ms | 50 req/s | `duration_ms` access logs plus `make perf-smoke` pooled query receipt |
| `hp-results-latest` | Latest synthetic result read model | `GET /v1/results/latest` | 75 ms | 300 ms | 1 s | 40 req/s | `duration_ms` access logs grouped by method and path |
| `hp-incident-feed` | Incident feed and detail | `GET /v1/incidents`, `GET /v1/incidents/{id}` | 100 ms | 500 ms | 1.5 s | 25 req/s | `duration_ms` access logs grouped by method and path |
| `hp-incident-correlation` | Incident cross-plane correlation | `GET /v1/incidents/{id}/cis`, MCP `correlate_incident` | 250 ms | 1.5 s | 3 s | 5 req/s | access-log `duration_ms`; `go test ./internal/ai/mcp -bench BenchmarkHandleToolCallListTests -run '^$' -benchmem` |
| `hp-flow-query` | Flow analytics query | `/v1/flows/*`, MCP `query_flows` | 200 ms | 1 s | 2.5 s | 10 req/s | access-log `duration_ms`; MCP tool-call benchmark |
| `hp-topology-read` | Topology graph read | `GET /v1/topology`, MCP `get_path` | 250 ms | 1.5 s | 3 s | 8 req/s | access-log `duration_ms`; MCP tool-call benchmark |
| `hp-topology-whatif` | Topology what-if simulation | `POST /v1/topology/whatif` | 300 ms | 2 s | 5 s | 3 req/s | access-log `duration_ms` |
| `hp-ai-ask` | AI RCA answer request | `POST /v1/ai/ask`, MCP `explain_degradation` | 1.5 s | 8 s | 20 s | 0.2 req/s | access-log `duration_ms`; MCP tool-call benchmark; deployment traces for model-adapter time |
| `hp-mcp-jsonrpc` | MCP JSON-RPC dispatch | `initialize`, `ping`, `tools/list`, `tools/call` | 50 ms | 250 ms | 1 s | 100 req/s | `go test ./internal/ai/mcp -bench BenchmarkHandlePing -run '^$' -benchmem`; tool-call benchmark |
| `hp-otlp-http-ingest` | OTLP HTTP metrics/traces/logs ingest | `POST /v1/metrics`, `POST /v1/traces`, `POST /v1/logs` | 20 ms | 100 ms | 250 ms | 200 payloads/s | `go test ./internal/otel/otlp -bench BenchmarkOTLPHTTP -run '^$' -benchmem`; `make load-test-smoke` |
| `hp-prom-query` | Prometheus-compatible query/federation | Grafana query/query_range, federate | 150 ms | 750 ms | 2 s | 15 req/s | access-log `duration_ms`; `make load-test-smoke` query leg |

## CI guard

The catalog is code, not just documentation:

- `go test ./internal/perf -run TestHotPathCatalog` verifies every row has a
  stable ID, p50/p95/p99 ceilings, a throughput floor, and a trace/benchmark/load
  receipt.
- `go test ./internal/control -run TestHotPathCatalogControlRoutesExist` verifies
  control API rows still point at mounted routes.
- `go test ./internal/ai/mcp -bench BenchmarkHandle -run '^$' -benchmem` measures
  MCP protocol overhead.
- `go test ./internal/otel/otlp -bench BenchmarkOTLPHTTP -run '^$' -benchmem`
  measures OTLP HTTP handler overhead.

The access-log receipt is emitted by `internal/control` as the structured
`duration_ms` field. In production, derive p50/p95/p99 by grouping that field by
method and normalized path. Tenant data stays out of the self-observability
stream; this is process/request timing, not tenant telemetry.
