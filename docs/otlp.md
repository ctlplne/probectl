# OTLP exposure & OBI

## What this is

OTLP (the OpenTelemetry Protocol) is the standard wire format for shipping
telemetry — metrics, traces, and logs — between systems. Because probectl's
internal signal schemas already follow OpenTelemetry conventions (see
[`otel-mapping.md`](otel-mapping.md)), it can speak OTLP in both directions
without a translation layer:

- a **receiver** (`internal/otel/otlp`) — a TLS-only, authenticated,
  tenant-scoped endpoint that ingests all three OTLP signals, so a stock
  OpenTelemetry Collector or an OBI agent can push straight into probectl;
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
- **OTLP ingest (all three signals).** gRPC `MetricsService` + `TraceService` +
  `LogsService`, and HTTP `POST /v1/metrics` + `/v1/traces` + `/v1/logs` — each
  authenticated, tenant-scoped server-side, and bounded. Ingested **metrics**
  land in the TSDB; **traces + logs** land in the otelstore (memory, or
  ClickHouse with `(tenant_id, day)` partitioning + a retention TTL) and are
  queryable, tenant-scoped, at `GET /v1/otlp/traces` and `GET /v1/otlp/logs`. A
  standard OTel Collector exports straight to the receiver — there's a reference
  config at `deploy/otel-collector/config.yaml`.
- **OTLP export.** Metrics only. Re-exporting ingested traces/logs is not a goal.
- **Deliberate bounds (CLAUDE.md §10).** probectl ingests traces + logs for
  **correlation** — bounded attributes, capped bodies, retention-limited. It is
  **not** an APM / distributed-tracing replacement and **not** a log-analytics
  store. Positioning language may claim three-signal OTLP ingest with exactly
  those bounds — and no more.

## Receiver — inbound, TLS-only, authenticated, tenant-scoped

The receiver is an inbound ingestion surface, so it gets the full guardrail-12
treatment (CLAUDE.md §7): TLS is required, every push is authenticated and
tenant-scoped, the payload is untrusted, and anything missing makes it **fail
closed**.

- **Transports & signals.** Both OTLP/gRPC (`MetricsService`, `TraceService`,
  `LogsService`) and OTLP/HTTP (`POST /v1/metrics`, `/v1/traces`, `/v1/logs`,
  protobuf bodies) serve all three signals. They run on their own listeners,
  separate from the `/v1` REST API — so these OTLP paths don't touch the REST
  OpenAPI surface even though two of them happen to start with `/v1`.
- **TLS.** The gRPC server refuses to start without a TLS config; the HTTP
  handlers are served over an HTTPS listener. No plaintext OTLP, ever.
- **Auth.** A bearer token (`Authorization: Bearer <token>`) maps to a tenant via
  `PROBECTL_OTLP_TOKENS`. Missing/invalid → gRPC `Unauthenticated` / HTTP `401`.
  mTLS / SPIFFE is the stronger option; the transport already requires TLS
  regardless.
- **Tenant scoping.** The authenticated tenant *is* the scope. A resource that
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
`PROBECTL_OTLP_TLS_KEY_FILE` and `PROBECTL_OTLP_TOKENS` (see
[`configuration.md`](configuration.md)). It is off by default and **fails config
validation** if an address is set without TLS + tokens.

## Token rotation & revocation

Bearer tokens map to tenants (`PROBECTL_OTLP_TOKENS=token=tenant,...`). The
comparison is **constant-time over a SHA-256 of the token**: the authenticator
keeps only the hash (never the plaintext after construction) and checks *every*
configured token without an early exit, so neither a near-miss nor the matching
token's position can leak through timing (`internal/otel/otlp/auth.go`).

**Rotate** without downtime by running two tokens during the migration: add the
new token to `PROBECTL_OTLP_TOKENS` (both valid now), repoint each OTLP sender at
the new token, then drop the old token and restart the receiver. Multiple
concurrently-valid tokens and optional per-token expiry are first-class in the
authenticator (`Add`).

**Revoke** a leaked token immediately by dropping it from `PROBECTL_OTLP_TOKENS`
and restarting (the env-config path); the authenticator's in-process `Revoke`
gives the same effect for an admin-driven path. A revoked or expired token fails
closed (`Unauthenticated` / `401`). The count of currently-valid tokens is
exposed for rotation visibility.

## Exporter — outbound

`otlp.NewGRPCExporter` / `otlp.NewHTTPExporter` send probectl signals — built
from the canonical mapping as OTLP `ResourceMetrics` — to an external collector
over TLS with a bearer token. The gRPC exporter refuses to dial without TLS
(unless an explicit dev-only `Insecure` is set). On the wire, exported metrics
carry dotted `probectl.*` names (e.g. `probectl.probe.success`,
`probectl.flow.bytes`) — distinct from the underscore Prometheus names the TSDB
uses internally.

## OBI (OpenTelemetry eBPF Instrumentation)

probectl's eBPF flow/L7 signals already follow the OTel network conventions
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
  result, flow, L7, BGP, path — to the OTel / `probectl.*` naming discipline.

## Deploying behind an OTel Collector

probectl's receiver speaks the standard OTLP wire protocol on the standard
paths, so a stock **opentelemetry-collector** exports to it with the ordinary
`otlphttp` exporter — no probectl-specific Collector component:

1. Mint a tenant token (`PROBECTL_OTLP_TOKENS=tok=tenant-id`) and enable the
   receiver (`PROBECTL_OTLP_HTTP_ADDR=:4318` + the TLS pair).
2. Run the Collector with the reference config
   [`deploy/otel-collector/config.yaml`](../deploy/otel-collector/config.yaml):
   apps export to the Collector as usual; it batches and forwards
   metrics + traces + logs to probectl over TLS with the bearer token.
3. Query them back, tenant-scoped: `GET /v1/otlp/traces` and `GET /v1/otlp/logs`
   (and metrics via the unified metrics path).

The token determines the tenant: probectl verifies or stamps `probectl.tenant.id`
server-side, so a mislabeled resource is rejected — never misfiled. The
three-signal round-trip is pinned in CI (`TestOTLPThreeSignalRoundTrip`); the
live exercise against a real Collector on real infrastructure is the part of
acceptance that needs infrastructure rather than a unit test.
