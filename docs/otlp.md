# OTLP exposure & OBI (S22)

probectl is OpenTelemetry-native **on the metrics signal**: its signal schemas
have followed OTel resource + network semantic conventions since S6, so this
layer **exposes** them as OTLP rather than remapping a divergent model. OTLP
**traces and logs are not ingested today** — see [Scope & roadmap](#scope--roadmap-u-020). `internal/otel/otlp` provides a TLS-only,
authenticated, tenant-scoped **receiver** (ingest external OTLP), an **exporter**
(emit probectl signals as OTLP), and the signal↔OTLP-metrics conversion. The
canonical mapping is in [`otel-mapping.md`](otel-mapping.md).

## Scope & roadmap (U-020)

What "OTel-native" means here, precisely:

- **Today:** OTel resource + network **semantic conventions** on every signal
  in every plane (`otel-mapping.md`), an OTLP **metrics** receiver
  (gRPC `MetricsService` + HTTP `/v1/metrics`), and an OTLP **metrics**
  exporter. eBPF capture follows the OBI model.
- **Not yet:** OTLP **traces** and **logs** ingestion. probectl is not a
  tracing backend or a log store by design (CLAUDE.md §10 — no APM/SIEM
  replacement); the roadmapped traces/logs work is OTLP *ingest for
  correlation* (e.g. exemplars and change events), with conformance tests,
  tracked as a separate roadmap item. Until that lands, marketing/positioning
  language must scope OTel-native claims to metrics + conventions — this is
  the authoritative wording.

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
