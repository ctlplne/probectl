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
The proto lives under `proto/netctl/agent/v1/` (versioned, additive-only).

## Agent runtime (S5)

`netctl-agent` (`cmd/netctl-agent`, `internal/agent`) is a single, multi-arch,
DB-free binary. A plugin **host** runs compiled-in canaries (`internal/canary`:
the `Canary` interface + a no-op plugin; real probes from S7) on a schedule into a
disk-backed, bounded **store-and-forward buffer** (append-only framed log,
compacted on drain). A **forwarder** registers, heartbeats, and drains the buffer
to the control plane over mTLS, reconnecting with backoff. Probing runs
independently of connectivity, so results accumulate during an outage and drain
on reconnect (at-least-once); every buffered/emitted result is stamped with the
agent's tenant + id.

## Result pipeline (S6)

A result travels agent → gRPC `StreamResults` → control-plane ingest
(`internal/agenttransport`) → result bus (`internal/bus`) → consumer
(`internal/pipeline`) → time-series writer (`internal/store/tsdb`). The wire
payload is the canonical OTel-aligned result (`proto/netctl/result/v1`), whose
attribute names follow OTel resource + network semantic conventions from first
emission (the discipline S22 later *exposes* as OTLP/OBI rather than retrofits;
see [`otel-mapping.md`](otel-mapping.md)).

**Tenant integrity at ingest:** the control plane overwrites the result's
`tenant_id`/`agent_id` with the identity from the verified mTLS certificate before
publishing, and keys the bus message by tenant — a result can never be attributed
to another tenant by a malformed or hostile payload (CLAUDE.md §7 guardrails 1
and 5). The bus has a **memory** mode (in-process, the lightweight <5-agent
default) and a **kafka** mode behind one interface; the writer has a **memory**
mode and a **prometheus** remote-write mode (Prometheus/VictoriaMetrics). The
consumer converts each result to `netctl_probe_*` series labeled by
`tenant_id`/`agent_id`/`canary_type`/`server_address`; tenant scoping at read time
(S23) enforces isolation at the TSDB, which has no row-level security of its own.

## Network tests & agent-to-agent (S7–S8)

Probes are compiled-in `Canary` plugins (`internal/canary`): `icmp` (loss/latency/
jitter, S7), `tcp` (connect latency) + `udp` (echo round-trip) agent-to-server
tests (S8), `dns` (resolver/trace + DNSSEC, S12), and `http` (availability +
timing breakdown + TLS capture, S13). All share one latency-stats core and emit
through the S6 pipeline.

**Agent-to-agent** (S8) measures between two registered agents, **brokered by the
control plane** (`internal/a2a`). The broker assigns roles, rendezvouses the
responder's listen endpoint to the initiator, and hands each agent its task when
it polls (`PollCoordination`/`ReportEndpoint`); all broker state is tenant-scoped
(an agent only ever gets its own tasks, and only a session's responder may report
an endpoint — guardrail 1). The measurement is TWAMP-lite (T1 send, T2/T3
responder recv/send, T4 recv), giving round-trip plus **forward and reverse
one-way delay**; one-way delays assume NTP-synced clocks across hosts. Results
from both agents flow through the same result pipeline into the TSDB.

## DNS tests (S12)

The `dns` canary (`internal/canary/dns.go`) queries DNS over **UDP, TCP, DoT, or
DoH** in two modes. In **resolver** mode it sends one query and reports resolution
time, answer count, rcode, and an answer summary; in **trace** mode it performs an
**iterative delegation walk** from the root hints (`dnstrace.go`), following
`NS`/glue referrals to the authoritative server and recording the delegation chain.
DoT verifies the resolver certificate; DoH is RFC 8484 `application/dns-message`
over HTTPS (guardrail 12 — outbound TLS validated, response treated as untrusted).

**DNSSEC validation (`dnssec.go`) verifies the zone's signature, not the AD bit.**
`verifyRRSIG` is a pure check — given the answer RRset, its `RRSIG`s, and the zone
`DNSKEY`s it returns `secure` (a matching-keytag signature inside its validity
window that verifies), `insecure` (no RRSIG — the zone is unsigned), or `bogus`
(signatures present but none verify: tampered, expired, or wrong key). The network
wrapper fetches the signer zone's `DNSKEY` when it isn't already in the response;
chain-to-root anchoring is a later refinement. A bogus verdict fails the probe, so
forged answers are caught rather than trusted. The crypto lives entirely inside
`miekg/dns`, keeping the FIPS crypto-abstraction guard green (guardrail 3). The
pure validator is fixture-tested with locally signed RRsets (secure / expired /
tampered / no-key); in-process DNS servers cover the resolver, DoH, and DNSSEC
paths hermetically, with skip-safe live DoT + trace tests.

## HTTP server tests (S13)

The `http` canary (`internal/canary/http.go`) measures HTTP(S) availability with a
per-phase **response-time breakdown** captured via `net/http/httptrace`
(`httptrace.go`): DNS, TCP connect, TLS handshake, time-to-first-byte, and total,
plus status, content length, and throughput. Availability is decided by an
`expect_status` matcher (codes / `Nxx` classes / ranges). The resolved peer IP is
recorded as `network.peer.address`, the join key that **correlates an HTTP result
to path/traceroute data** for the same destination (S10) without re-running a
trace inside every probe.

On HTTPS it **captures the TLS handshake** — version, cipher, and the leaf
certificate's subject/issuer/validity/SANs plus the chain shape and a
cert-expiry-days metric — as the forward contract the **S27 TLS-posture plane**
consumes (sprint watch-out: capture now, analyze later). To capture the chain
*even when it is invalid*, the canary sets `InsecureSkipVerify` and performs the
standard chain + hostname verification **itself** in `VerifyConnection` (honoring a
`ca_file` trust anchor), so an expired or untrusted cert still fails the probe
while its details are attached for posture review. All crypto stays in
`crypto/tls` + `crypto/x509` (FIPS-swappable; guardrail 3). Integration tests run a
local HTTPS server through the required cases — success, 5xx, slow/timeout, and
expired-cert (asserting the cert is captured despite the failure) — using
`internal/crypto` to mint the test CA and (expired) leaf certs.

## Path discovery (S10)

`internal/path` is the ECMP/MPLS-aware path engine — the substrate for the hero
path visualization (S11). It runs **Paris-style traceroutes**: each trace fixes a
flow identifier so a load-balancing router keeps that trace on one stable path,
and different identifiers explore the ECMP branches. In ICMP mode the flow
identifier is a **forced ICMP checksum** — the engine solves a 2-byte payload
"balance" word so the checksum field equals a chosen value while the packet stays
valid, so ECMP hashing is stable per flow. In TCP mode the flow is the fixed
5-tuple. It detects **MPLS label stacks** (RFC 4884/4950) quoted on Time Exceeded
responses, and merges `TraceCount` per-flow traces into one multi-path `Path`:
each TTL is a hop whose multiple responders are **ECMP branches**, with per-node
RTT/loss + MPLS and the **links** observed within individual flows (no adjacency
is inferred across an unresponsive `*` hop).

A full per-hop trace needs **raw sockets** (`CAP_NET_RAW`) to read intermediate
Time Exceeded; unprivileged, the datagram-ICMP path still discovers the
destination. The correctness of the checksum trick, the MPLS parsing, and the
multi-path merge is covered by fixtures; a loopback trace is the live test.

Path data is high-cardinality time-series, so it is stored in **ClickHouse**
(`internal/store/pathstore`) — a `memory` store for the lightweight mode/tests and
a `clickhouse` adapter that reads/writes hop/link rows over ClickHouse's **HTTP
interface** (no native-driver dependency), partitioned by `tenant_id` so path
data never crosses a tenant.

## Path visualization (S11)

The **path-viz data API** is `GET /v1/tests/{id}/path` (the latest stored path
for a test) + `POST /v1/tests/{id}/path` (run a discovery now and store it); both
are tenant-scoped through the test lookup, and the discoverer is injectable
(default `path.Run`) so it is testable without a network. Path discovery runs
from the control plane for now (operator-triggered); an agent-vantage scheduler
is a later refinement.

The **hero UI** (`web/src/viz`) renders the merged multi-path on the S8a design
system: a pure `layoutPath` places hops in TTL columns with ECMP branches stacked
and links from observed adjacencies; the SVG `PathGraph` draws nodes colored by
loss (the lossy hop stands out), MPLS markers, hover/focus tooltips, and
keyboard-operable nodes that open a per-hop drill-down — backed by a
visually-hidden hop table so assistive tech gets the same data. A **loss-by-hop**
sparkline pinpoints where drops occur. Layout is O(nodes+links) for dense graphs;
animation respects `prefers-reduced-motion`.
