# Architecture (seed)

This is a seed document. The authoritative architecture and product spec
(`CLAUDE.md`, `netctl-PRD-v0.5.md`) are internal and kept in the private working
folder — **not committed** to this repo. This file is filled out as the
subsystems land; the canonical **tenant-scoped data model** is documented here in
**S2**.

## Shape

```
Provider / Management Plane (MSP operators — a distinct privilege domain)
        │  tenant lifecycle · fleet-across-tenants · metering/billing ·
        │  white-label · audited break-glass (no implicit tenant-data access)
        ▼  (tenant-scoped, isolated)
Control Plane (Go, stateless, TENANT-AWARE)
        REST (OpenAPI 3.1) · gRPC (agents, mTLS) · MCP · Webhooks/OTLP
        Auth (SSO/RBAC/ABAC) · Audit · Tenant → Org → Team → Project
        subsystems: tenancy · path · bgp · opendata · threat · change ·
                    topology · cost · slo · compliance · ai · ...
        ▲ gRPC(mTLS)         ▲ bus (tenant-tagged)      ▲ queries (tenant-first)
   Agents (Go, single binary, tenant-bound)   Kafka/NATS    Postgres · ClickHouse ·
   canary plugins · path engine · eBPF (P2)                 Prometheus/VM · graph · object
        External (read-only, cached, degrade gracefully): RouteViews · RIPE RIS/Atlas ·
        RPKI · PeeringDB · MaxMind/Cymru · CT logs · threat-intel · cloud pricing
```

Data flows agents → bus (tenant-tagged) → control-plane consumers → stores, all
scoped by `tenant_id`; the API/UI/AI/MCP query the unified stores **within the
caller's tenant first, then RBAC**.

## First principles (enforced from S0)

- **Tenant is the outermost scope and security boundary.** Every tenant-owned
  record, message, metric, and object is `tenant_id`-scoped at the storage/query
  layer — never application code alone. A cross-tenant isolation test is a
  permanent CI gate (`cross-tenant-isolation`).
- **OpenTelemetry-native.** Signal schemas map to OTel resource + network
  semantic conventions from first emission (S6), so OTLP/OBI is exposure (S22),
  not a retrofit.
- **Self-hosted, no phone-home.** No outbound telemetry on by default.
- **Crypto is abstracted** behind `internal/crypto` (FIPS-swappable, S3); **mTLS**
  everywhere agent↔control-plane; **TLS on every listener**.
- **Observe-only / human-gated** remediation; threat detection is a **signal**,
  not an inline IPS.

See `CLAUDE.md §3–§7` (internal) for the full architecture, stack decisions, and
security guardrails.

## Component map

Each `internal/<subsystem>` package carries a one-line purpose and the sprint
that implements it (see the package `doc.go` files). `docs/runbooks/` holds
operational runbooks as services reach GA.
