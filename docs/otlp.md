# OTLP exposure & OBI

## What this is

OTLP (the OpenTelemetry Protocol) is the standard wire format for shipping
telemetry between systems. It carries three signal types: **metrics** (numeric
measurements over time — counters, gauges), **traces** (the tree of timed
**spans** — one span per operation — that a single request leaves behind as it
crosses services), and **logs** (timestamped text records). Because probectl's
internal signal schemas already follow OpenTelemetry conventions (see
[`otel-mapping.md`](otel-mapping.md)), it can speak OTLP in both directions
without a translation layer:

- a **receiver** (`internal/otel/otlp`) — a TLS-only, authenticated,
  tenant-scoped endpoint that ingests all three OTLP signals, so a stock
  OpenTelemetry Collector (the standard relay daemon most OTel pipelines
  already run) or an OBI agent can push straight into probectl;
- an **exporter** — emits probectl's own signals as OTLP metrics to an external
  collector;
- the **conversion** between probectl signals and OTLP `ResourceMetrics`, built
  from the canonical mapping.

The framing to hold onto: OTLP ingest exists for **correlation**, not as a
product probectl is trying to be. probectl is OTel-native so it can *fit into*
your existing telemetry pipeline — not so it can replace your APM or your log
store (see "Deliberate bounds" below).

## Scope — what "OTel-native" means here, precisely

- **Conventions.** OTel resource + network semantic conventions on every signal
  in every plane ([`otel-mapping.md`](otel-mapping.md)); eBPF capture follows the
  OBI model.
- **OTLP ingest (all three signals).** gRPC (the HTTP/2-based RPC protocol)
  `MetricsService` + `TraceService` +
  `LogsService`, and HTTP `POST /v1/metrics` + `/v1/traces` + `/v1/logs` — each
  authenticated, tenant-scoped server-side, and bounded. Ingested **metrics**
  land in the TSDB (the time-series database); **traces + logs** land in the
  otelstore (memory, or
  ClickHouse with `(tenant_id, day)` partitioning + a retention TTL) and are
  queryable, tenant-scoped, at `GET /v1/otlp/traces` and `GET /v1/otlp/logs`. A
  standard OTel Collector exports straight to the receiver — there's a reference
  config at `deploy/otel-collector/config.yaml`.
- **OTLP export (all three signals).** When `PROBECTL_OTLP_EXPORT_ENDPOINT` is
  configured, probectl forwards ingested **metrics, traces, and logs** to the
  operator's upstream OTLP collector. For OTLP/HTTP, the configured metrics
  endpoint's signal suffix is used to derive the sibling trace/log endpoints.
  Because this is tenant telemetry leaving probectl, remote export is encrypted
  by default and fails closed if a remote collector is configured without TLS.
  This is the portability and no-lock-in path: operators decide when data leaves,
  where it goes, and which upstream collector receives it. OTLP export is an
  exit path under your control, not a vendor-hosted siphon or a paid hostage
  feature.
- **Deliberate bounds.** probectl ingests traces + logs for **correlation** —
  bounded attributes, capped bodies, retention-limited, and redacted before
  persistence. Span names, service/resource attributes, span/log attributes,
  and log bodies pass through the governance redactor at ingest so common PII
  and secrets (emails, user/account/session identifiers, IP addresses,
  bearer/API/password/token values, and URL query/fragment data) do not land raw
  in the memory or ClickHouse otelstore. Trace IDs and span IDs are retained as
  correlation keys. It keeps the receipts, not the warehouse: enough of each
  span and log line to join evidence across planes, never the full archive.
  Metric TSDB conversion supports OTLP gauge, sum, and explicit-bucket
  histogram points. OTLP summary and exponential histogram points are accepted
  at the receiver but are not converted into queryable TSDB series; probectl
  counts them at `/metrics` as
  `probectl_otlp_metrics_summary_skipped_total` and
  `probectl_otlp_metrics_exponential_histogram_skipped_total` so an operator can
  see the bound instead of losing it silently. It is **not** an APM /
  distributed-tracing replacement and **not** a log-analytics store. probectl
  claims three-signal OTLP ingest/export with exactly those bounds — and no
  more.

## Receiver — inbound, TLS-only, authenticated, tenant-scoped

The receiver is an inbound ingestion surface, so it gets probectl's full
ingestion-guardrail treatment (see
[`security/threat-model.md`](security/threat-model.md)): TLS is required, every
push is authenticated and tenant-scoped, the payload is untrusted, and anything
missing makes it **fail closed**.

- **Transports & signals.** Both OTLP/gRPC (`MetricsService`, `TraceService`,
  `LogsService`) and OTLP/HTTP (`POST /v1/metrics`, `/v1/traces`, `/v1/logs`,
  protobuf bodies) serve all three signals. They run on their own listeners,
  separate from the `/v1` REST API — so these OTLP paths don't touch the REST
  OpenAPI surface even though two of them happen to start with `/v1`.
- **TLS.** The gRPC server refuses to start without a TLS config; the HTTP
  handlers are served over an HTTPS listener. No plaintext OTLP, ever.
- **Auth.** A **bearer token** — a secret string that grants access to whoever
  carries it, hence the name — sent as `Authorization: Bearer <token>` maps
  to a tenant. The preferred path is DB-backed tokens minted at
  `/v1/otlp-tokens`: only the hash is stored, and `DELETE /v1/otlp-tokens/{id}`
  revokes the token for the very next request. `PROBECTL_OTLP_TOKENS` still
  exists as an optional legacy/bootstrap map, but it is not required to start
  the receiver. Missing/invalid/revoked → gRPC `Unauthenticated` / HTTP `401`.
  mTLS / SPIFFE (mutual TLS, where the client presents a certificate too;
  SPIFFE is the workload-identity standard for those certs) is the stronger
  channel identity option; the transport already requires TLS regardless.
- **Freshness / replay protection.** For generic OTel collectors, TLS + bearer
  auth + downstream idempotency remain compatible defaults. First-party
  collectors can additionally enable `PROBECTL_OTLP_FRESHNESS_HMAC_KEY`, a
  hex-encoded 32-byte HMAC key. When set, every OTLP/gRPC and OTLP/HTTP push
  must include `X-Probectl-OTLP-Sent-At`, `X-Probectl-OTLP-Nonce`, and
  `X-Probectl-OTLP-Signature: sha256=<hex>` (gRPC uses the same lowercase
  metadata keys). The signature covers protocol, method/path, timestamp, nonce,
  and payload hash. Stale timestamps, repeated nonces, missing headers, or bad
  signatures fail closed.
- **Tenant scoping.** The authenticated tenant *is* the scope — the token works
  like a hotel keycard: whatever floor a guest claims, the card only ever opens
  their own. A resource that
  names a **different** tenant is rejected (`PermissionDenied` / `403`); a
  resource with **no** tenant is **stamped** with the authenticated one (the
  `probectl.tenant.id` resource attribute). The same enforcement applies
  identically to metrics, spans, and log records — a tenant can never push
  another tenant's data.
- **Untrusted input.** Bounded receive size (default 4 MiB), and the protobuf is
  unmarshalled and validated before use.
- **Sinks.** Ingested signals are tenant-tagged and published to per-signal bus
  topics: `probectl.otlp.metrics`, `probectl.otlp.traces`, `probectl.otlp.logs`.
  All three sinks are required — a receiver that silently dropped a signal would
  be the exact failure shape this design rules out.

Enable it on the control plane with `PROBECTL_OTLP_GRPC_ADDR` /
`PROBECTL_OTLP_HTTP_ADDR`, plus `PROBECTL_OTLP_TLS_CERT_FILE` /
`PROBECTL_OTLP_TLS_KEY_FILE` (see [`configuration.md`](configuration.md)). It is
off by default and **fails config validation** if an address is set without TLS.
Create DB-backed tokens through the API, or use `PROBECTL_OTLP_TOKENS` only as
an explicit bootstrap/legacy source.

## Token rotation & revocation

Bearer tokens map to tenants. DB-backed OTLP tokens are the normal operational
path: an authenticated operator creates one with `POST /v1/otlp-tokens`, gets
the plaintext once, and future authentication checks the stored hash through the
database. The receiver can start in DB-only mode with **zero** static
`PROBECTL_OTLP_TOKENS`.

**Rotate** without downtime by creating a new DB token, repointing each OTLP
sender, then revoking the old token. The authenticator checks DB-issued tokens
against the DB on every request, even after the in-process cache knows them, so
revocation is hot: no config change and no restart.

`PROBECTL_OTLP_TOKENS=token=tenant,...` remains available for legacy/bootstrap
deployments. Those static tokens are checked in constant time over a SHA-256
hash and can overlap during rotation, but because they live in process config
they are revoked by removing the entry and restarting. Prefer DB-backed tokens
for production operations.

## Exporter — outbound

`otlp.NewGRPCExporter` / `otlp.NewHTTPExporter` send OTLP
`ExportMetricsServiceRequest`, `ExportTraceServiceRequest`, and
`ExportLogsServiceRequest` batches to an external collector over TLS with a
bearer token. The gRPC exporter refuses to dial a remote target without TLS
(unless an explicit loopback/dev-only `Insecure` is set). On the wire, exported
probectl metrics carry dotted `probectl.*` names (e.g.
`probectl.probe.success`, `probectl.flow.bytes`) — distinct from the underscore
Prometheus names the TSDB uses internally. Exported traces and logs are the
already tenant-stamped OTLP batches accepted by the receiver; they are forwarded
to the operator's own trace/log backend, not expanded into an unbounded
probectl store.

## OBI (OpenTelemetry eBPF Instrumentation)

**eBPF** lets a program observe the kernel's network and library activity from
inside the kernel, without touching application code; **OBI** is
OpenTelemetry's instrumentation agent built on it, emitting standard OTLP.
probectl's own eBPF flow/L7 signals already follow the OTel network conventions
(`source.*` / `destination.*` / `network.*` / `http.*` / `rpc.*`), so **OBI's
OTLP output is ingested by the receiver without a translation shim** — probectl
integrates OBI rather than forking it, and the eBPF signals probectl exports are
likewise OBI-shaped.

## Round-trip & conformance

Two checks pin this layer in CI:

- `internal/otel/otlp` round-trips a probectl signal through exporter → receiver
  → sink over **both** gRPC and HTTP (`TestRoundTripGRPC` / `TestRoundTripHTTP`),
  asserting the canonical resource attributes survive and the tenant is
  enforced. The full three-signal ingest path is exercised by
  `TestOTLPThreeSignalRoundTrip` (`internal/pipeline`).
- `internal/otel.TestAllSignalMappingsConform` holds **every** signal mapping —
  result, eBPF flow, L7, device/cloud flow, device telemetry, BGP, path — to the
  OTel / `probectl.*` naming discipline.

## Deploying behind an OTel Collector

probectl's receiver speaks the standard OTLP wire protocol on the standard
paths, so a stock **opentelemetry-collector** exports to it with the ordinary
`otlphttp` exporter — no probectl-specific Collector component:

1. Enable the receiver (`PROBECTL_OTLP_HTTP_ADDR=:4318` + the TLS pair), then
   mint a tenant token with `POST /v1/otlp-tokens`. Use
   `PROBECTL_OTLP_TOKENS=tok=tenant-id` only for explicit bootstrap/legacy
   deployments.
2. Run the Collector with the reference config
   [`deploy/otel-collector/config.yaml`](../deploy/otel-collector/config.yaml):
   apps export to the Collector as usual; it batches and forwards
   metrics + traces + logs to probectl over TLS with the bearer token.
3. Query them back, tenant-scoped: `GET /v1/otlp/traces` and `GET /v1/otlp/logs`
   (and metrics via the unified metrics path).

The token determines the tenant: probectl verifies or stamps `probectl.tenant.id`
server-side, so a mislabeled resource is rejected — never misfiled. The
three-signal round-trip is pinned in CI (`TestOTLPThreeSignalRoundTrip` in
`internal/pipeline`).

## Exactly-once-effective storage (dedup)

OTLP delivery is at-least-once: the receiver→bus→consumer→store path can
redeliver a span/log batch on retry. To stop a redelivery becoming a permanent
duplicate, the span and log tables are `ReplacingMergeTree`s (CORRECT-004):
spans collapse on their natural `(trace_id, span_id)` key; logs — which carry no
native unique id — collapse on a deterministic `dedup_id` hashed over the
record's distinguishing fields (ts, severity, service, trace/span, body). Reads
(`GET /v1/otlp/traces`, `GET /v1/otlp/logs`) use `FINAL`, so a redelivered span
or log is returned exactly once even before background merges run. The schema
ships as a versioned `chmigrate` migration (otelstore v2); pre-existing rows
carry over (logs get an empty `dedup_id`, since they predate dedup).
Future-dated event times are clamped on ingest (CORRECT-006).
