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

## Tenant-scoped data model (S2)

Tenancy is the outermost scope and security boundary on every tenant-owned record
(F50). The hierarchy is **Tenant → Organization → Team → Project**; identity, RBAC,
audit, and the placeholder planes all hang off a tenant.

| Table | Scope | Notes |
| ----- | ----- | ----- |
| `tenants` | global registry | the outermost entity; provider-managed; no `tenant_id`, no RLS |
| `organizations`, `teams`, `projects` | tenant-owned | the hierarchy; each carries `tenant_id` + a parent FK |
| `users`, `service_accounts` | tenant-owned | per-tenant identity |
| `permissions` | global catalog | the grantable action set (same for every tenant) |
| `roles`, `role_permissions`, `role_bindings` | tenant-owned | RBAC foundation (enforcement in S18) |
| `provider_operators`, `break_glass_grants` | global / provider | the provider privilege domain — operators are NOT tenant users |
| `audit_events` | tenant-owned | per-tenant hash chain, append-only |
| `provider_audit_events` | global / provider | the separate provider / break-glass hash chain |
| `agents`, `tests`, `results` | tenant-owned | placeholders, fleshed out in S4–S7 |

Every tenant-owned table carries a **non-null `tenant_id`** with an index from its
first migration — never retrofitted.

### Pooled isolation (F52-pooled): a missing check cannot leak

Two layers enforce isolation, so an application bug cannot cause a cross-tenant
read (PRD §3.2):

1. **Storage layer — Row-Level Security.** Every tenant-owned table has RLS
   `ENABLE`d and `FORCE`d, with a policy keyed on the `netctl.tenant_id` GUC. When
   the GUC is unset the policy matches no rows (fail closed). Even a raw
   `SELECT * FROM organizations` returns only the current tenant's rows.
2. **Query layer — the tenancy choke point.** `tenancy.InTenant(ctx, pool, fn)` is
   the only way to obtain a tenant-scoped querier. It opens a transaction,
   `SET LOCAL ROLE netctl_app` (a `NOSUPERUSER`/`NOBYPASSRLS` role, so RLS applies
   even from a privileged session), and sets the GUC — then runs `fn`.

`netctl_app` holds least-privilege DML (audit is append-only: no UPDATE/DELETE).
The application's Postgres login role must be able to assume `netctl_app` — a
superuser always can; otherwise `GRANT netctl_app TO <login_role>`. A cross-tenant
isolation test is a permanent CI gate.

### Provider plane & break-glass (F51)

Provider operators are a distinct privilege domain — not tenant users. Managing a
tenant grants no read access to its telemetry; that requires a time-bounded,
consented, **separately audited** `break_glass_grant`. Provider repositories use
the pool directly (global tables); break-glass data access goes through `InTenant`
for the target tenant and is recorded on the provider audit stream.

### Audit (F23-foundation)

Two append-only, hash-chained streams — the tenant stream (`audit_events`, one
chain per tenant) and the provider stream (`provider_audit_events`). Each record
chains over the previous record's hash via `internal/crypto`, so tampering,
reordering, or deletion breaks verification (`internal/audit` Verify).

## Agent transport (S4)

Agents connect to the control plane over **gRPC + mTLS** (`internal/agenttransport`,
`netctl.agent.v1.AgentService`: Register / Attest / Heartbeat / StreamConfig /
StreamResults). The server requires and verifies a client certificate; the agent's
tenant and id are read from its certificate's tenant-bound SPIFFE identity
(`spiffe://netctl/tenant/<t>/agent/<a>`), never from the request body — so an agent
is bound to exactly one tenant and registration persists tenant-attributed (F50).
The proto lives under `proto/netctl/agent/v1/` (versioned, additive-only). The
agent binary itself is S5; result processing is S6.
