# OTLP exposure & OBI (S22)

probectl is OpenTelemetry-native: its signal schemas have followed OTel
resource + network semantic conventions since S6, and `internal/otel/otlp`
provides a TLS-only, authenticated, tenant-scoped **receiver for all three
OTLP signals — metrics, traces, and logs** (ARCH-001, Sprint 22) — plus an
**exporter** (emit probectl signals as OTLP metrics) and the
signal↔OTLP-metrics conversion. The canonical mapping is in
[`otel-mapping.md`](otel-mapping.md).

## Scope (U-020 — the authoritative claims wording)

What "OTel-native" means here, precisely:

- **Conventions:** OTel resource + network semantic conventions on every
  signal in every plane (`otel-mapping.md`); eBPF capture follows the OBI
  model.
- **OTLP ingest (all three signals):** gRPC `MetricsService` +
  `TraceService` + `LogsService` and HTTP `/v1/metrics` + `/v1/traces` +
  `/v1/logs` — authenticated, tenant-scoped server-side, bounded. Metrics
  land in the TSDB; traces + logs land in the otelstore (memory or
  ClickHouse with `(tenant_id, day)` partitioning + retention TTL) and are
  queryable at `GET /v1/otlp/traces` / `GET /v1/otlp/logs`. A standard OTel
  Collector exports straight to it (`deploy/otel-collector/config.yaml`).
- **OTLP export:** metrics. Trace/log re-export is not a goal.
- **Deliberate bounds (CLAUDE.md §10):** probectl ingests traces + logs for
  CORRELATION (bounded attributes, capped bodies, retention-limited) — it
  is not an APM/distributed-tracing replacement and not a log-analytics
  store. Positioning language may claim three-signal OTLP ingest with
  exactly those bounds.

## Token rotation & revocation (U-076/U-077)

Bearer tokens map to tenants (`PROBECTL_OTLP_TOKENS=token=tenant,...`).
Comparison is **constant-time over a SHA-256 of the token** — the
authenticator keeps only the hash, never the plaintext, and checks every
configured token without an early exit, so neither a near-miss nor the
matching token's position leaks through timing (`internal/otel/otlp/auth.go`).

**Rotate** without downtime by running two tokens during the migration:
add the new token to `PROBECTL_OTLP_TOKENS` (both are now valid), repoint
each OTLP sender at the new token, then remove the old token from the env
and restart the receiver. Multiple concurrently-valid tokens and optional
per-token expiry are first-class in the authenticator (`Add`).

**Revoke** a leaked token immediately by dropping it from
`PROBECTL_OTLP_TOKENS` and restarting (the env-config path); the
authenticator's in-process `Revoke` provides the same effect for an
admin-driven path. A revoked or expired token fails closed
(`Unauthenticated`/`401`). The active-token count is exposed for rotation
visibility.

## Receiver — inbound, TLS-only, authenticated, tenant-scoped

The receiver is an **inbound surface** and is treated as one (CLAUDE.md §7
guardrail 12): TLS is required, every push is authenticated and tenant-scoped,
and the payload is untrusted input — it **fails closed**.

- **Transports:** OTLP/gRPC (`MetricsService`) and OTLP/HTTP (`POST /v1/metrics`,
  protobuf), on their own listeners (separate from the `/v1` REST API, so the
  OpenAPI gate is unaffected).
- **TLS:** the gRPC server refuses to start without a TLS config; the HTTP handler
  is served over an HTTPS listener. No plaintext OTLP, ever.
- **Auth:** a bearer token (`Authorization: Bearer <token>`) maps to a tenant
  (`PROBECTL_OTLP_TOKENS`). Missing/invalid → gRPC `Unauthenticated` / HTTP `401`.
  mTLS / SPIFFE is the stronger alternative; the transport already requires TLS.
- **Tenant scoping:** the authenticated tenant is the scope. A `ResourceMetrics`
  that names a **different** tenant is rejected (`PermissionDenied` / `403`); one
  with no tenant is **stamped** with the authenticated tenant. A tenant can never
  push another tenant's data.
- **Untrusted input:** bounded receive size; the protobuf is validated before use.
- **Sink:** ingested metrics are tenant-tagged and published to the
  `probectl.otlp.metrics` bus topic.

Enable it on the control plane with `PROBECTL_OTLP_GRPC_ADDR` /
`PROBECTL_OTLP_HTTP_ADDR` plus `PROBECTL_OTLP_TLS_CERT_FILE` /
`PROBECTL_OTLP_TLS_KEY_FILE` and `PROBECTL_OTLP_TOKENS` (see
[`configuration.md`](configuration.md)). It is off by default and **fails config
validation** if an address is set without TLS + tokens.

## Exporter — outbound

`otlp.NewGRPCExporter` / `otlp.NewHTTPExporter` send probectl signals (as OTLP
`ResourceMetrics`, built from the canonical mapping) to an external collector over
TLS with a bearer token. The gRPC exporter refuses to dial without TLS (or an
explicit dev-only `Insecure`).

## OBI (OpenTelemetry eBPF Instrumentation)

probectl's eBPF flow/L7 signals already follow the OTel network conventions
(`source.*` / `destination.*` / `network.*` / `http.*` / `rpc.*`), so **OBI's OTLP
output is ingested by the receiver without a translation shim** — probectl
integrates OBI rather than forking it, and the eBPF signals probectl exports are
likewise OBI-shaped.

## Round-trip & conformance

`internal/otel/otlp` round-trips a probectl signal through exporter → receiver →
sink over both gRPC and HTTP, asserting the canonical resource attributes survive
and the tenant is enforced (the S22 "round-trips with an external collector"
check). `internal/otel.TestAllSignalMappingsConform` holds **every** signal type
— result, flow, L7, BGP, path — to the OTel / `probectl.*` naming discipline (the S6
regression, now across all planes).


## Deploying behind an OTel Collector (ARCH-006)

probectl's receiver speaks the standard OTLP wire protocol on the standard
paths, so a stock **opentelemetry-collector** exports to it with the
ordinary `otlphttp` exporter — no probectl-specific Collector component:

1. Mint a tenant token (`PROBECTL_OTLP_TOKENS=tok=tenant-id`) and enable
   the receiver (`PROBECTL_OTLP_HTTP_ADDR=:4318` + the TLS pair).
2. Run the Collector with the reference config
   [`deploy/otel-collector/config.yaml`](../deploy/otel-collector/config.yaml):
   apps export to the Collector as usual; the Collector batches and
   forwards metrics+traces+logs to probectl over TLS with the bearer token.
3. Query them back, tenant-scoped: `GET /v1/otlp/traces`,
   `GET /v1/otlp/logs` (and metrics via the unified metrics path).

The token determines the tenant: probectl verifies or stamps
`probectl.tenant.id` server-side, so a mislabeled resource is rejected —
never misfiled. The three-signal round-trip is pinned in CI
(`TestOTLPThreeSignalRoundTrip`); the live Collector exercise on real
infrastructure is the [needs infra] half of the acceptance.
