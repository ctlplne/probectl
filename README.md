```
                 _               _   _
 _ __  _ __ ___ | |__   ___  ___| |_| |
| '_ \| '__/ _ \| '_ \ / _ \/ __| __| |
| |_) | | | (_) | |_) |  __/ (__| |_| |
| .__/|_|  \___/|_.__/ \___|\___|\__|_|
|_|        see everything · send nothing
```

[![CI](https://github.com/imfeelingtheagi/probectl/actions/workflows/ci.yml/badge.svg)](https://github.com/imfeelingtheagi/probectl/actions/workflows/ci.yml)
[![tag](https://img.shields.io/github/v/tag/imfeelingtheagi/probectl?label=tag&sort=semver)](https://github.com/imfeelingtheagi/probectl/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/imfeelingtheagi/probectl)](https://goreportcard.com/report/github.com/imfeelingtheagi/probectl)
![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)
![status](https://img.shields.io/badge/status-active%20development-orange)
![license](https://img.shields.io/badge/license-source--available%20%C2%B7%20not%20OSS%20yet-lightgrey)

Self-hosted, source-available, multi-tenant **network observability platform**.
probectl unifies five observability planes — active/synthetic testing, BGP/routing
intelligence, flow analytics, device telemetry, and eBPF host/L7 — into one
**OpenTelemetry-native** control plane: OTel resource + network semantic
conventions describe every signal in every plane, and the platform ingests all
three OTLP signals — **metrics, traces, and logs** — bounded for correlation, and
re-exports its own signals as OTLP **metrics** ([docs/otlp.md](docs/otlp.md)).
Layered on top: an AI assistant for cross-plane root-cause analysis, a native
security/threat layer, change-aware topology, and cost/SLO intelligence.
Telemetry **never leaves the operator's network**.

One codebase serves two operating modes: **sovereign single-tenant** (a regulated
or air-gapped org self-hosts; the deployment *is* the tenant) and
**multi-tenant / provider** (an MSP self-hosts once and serves many hard-isolated,
white-labeled tenants). The single-tenant install is just the one-tenant case —
there is no separate code path. **Tenant is the outermost scope and security
boundary** on every record, agent, query, metric, event, and object.

> **Status: the platform is built; the work now is hardening toward GA.** All
> five observability planes are shipped, alongside cross-plane AI root-cause
> analysis, an MCP server, change-aware topology + what-if, a security/threat
> layer (TLS posture + NDR-lite), cost/SLO/compliance, RUM/carbon/chaos, and the
> multi-tenant provider/MSP plane (hard isolation, white-label, metering, BYOK,
> governance) — plus the Enterprise track: a build against the FIPS 140-3-validated
> Go Cryptographic Module (CMVP #5247), multi-region HA,
> supportability, and guarded (proposal-only, human-gated) remediation.
> Compose + Helm are **HTTPS-by-default**. The license is intentionally **`TBD`** —
> **source-available, not open source (yet)** (the open-core / reseller boundary is
> an open decision).

## Why probectl

When something on the network breaks, the symptom and the cause usually live in
different places. A slow checkout page might be a BGP route flap three networks
away, a saturated uplink, a DNS timeout, a misbehaving host, or a config change
that shipped ten minutes ago — and the tools that each see one of those are
typically five separate products with five separate dashboards. You find out at
2 a.m., by stitching them together by hand.

probectl collapses that. It pulls every plane — synthetic probes, BGP/routing,
flow records, device telemetry, and eBPF host/L7 — into **one** tenant-scoped
control plane, correlates them into a single incident, and lets an AI assistant
explain the root cause *across* planes instead of leaving you to guess which
dashboard to open first.

Three choices set it apart:

- **It stays yours.** probectl is self-hosted and **never phones home** — no
  telemetry beacons, no "call home," nothing. Hosted observability SaaS works by
  shipping your network data to a vendor's cloud; probectl keeps every byte
  inside your own infrastructure. For regulated, air-gapped, or
  sovereignty-conscious operators, that isn't a nice-to-have — it's the
  requirement.
- **It's unified and standard.** One **OpenTelemetry-native** model spans all
  five planes, so a flow record, a probe result, and a BGP event share the same
  schema and the same query layer — no per-tool silos, and you can feed standard
  OTLP into it or hand its signals to your SIEM without re-instrumenting anything.
  (Scope: the schemas follow OTel resource + network semantic conventions
  everywhere; the receiver ingests all three OTLP signals — **metrics, traces,
  and logs** — bounded for correlation, and it re-exports probectl's own signals
  as OTLP **metrics**. See `docs/otlp.md`.)
- **It's multi-tenant to the core.** The same binary runs as a single sovereign
  tenant for one org, or as a hard-isolated, white-labeled, individually-metered
  platform an MSP self-hosts and resells. **Tenant is the outermost security
  boundary** on every record — there is no separate enterprise fork to drift out
  of sync.

## What it answers

probectl is organized around the questions operators actually ask at 2 a.m.:

- *"The Berlin office says the app is slow — is it the network, the path in
  between, or the server?"* — synthetic probes, ECMP/MPLS-aware path discovery,
  and flow show you **where** the latency is, not just that it exists.
- *"Did the 14:03 change cause this?"* — change-aware topology correlates
  config/deploy events with the symptoms that followed them.
- *"Why did this prefix go dark — is it us, or the internet?"* — BGP/routing
  intelligence from RouteViews/RIPE RIS, RPKI validity, and a collective outage
  view separate a you-problem from an everyone-problem.
- *"What breaks if I drain this node?"* — the topology **what-if** simulates the
  blast radius before you touch production.
- *"Who's saturating this link, and what's it costing?"* — flow analytics plus
  per-tenant FinOps egress attribution.

Or just ask the built-in assistant *"why is checkout slow for tenant X?"* — it
runs the cross-plane correlation and answers with **cited evidence**, scoped to
exactly what the caller is allowed to see. (The default engine is a
**deterministic, air-gapped heuristic** — no LLM is involved or contacted
unless you explicitly configure one; see the AI row below.)

## Who it's for

- **Regulated & sovereignty-conscious orgs** (finance, healthcare, public sector,
  defense, critical infrastructure) that need deep network observability but
  cannot send telemetry to a third-party cloud. You self-host; the deployment
  *is* your tenant.
- **MSPs & internal platform teams** serving many customers or business units —
  self-host once and serve hard-isolated, white-labeled, individually-metered
  tenants from one control plane.
- **Network & platform engineers** tired of hand-correlating five dashboards who
  want a single OTel-native source of truth they actually own (OTLP metrics,
  traces, and logs ingest — bounded for correlation, not an APM replacement).

## Capabilities

The five observability planes:

| Plane | What it covers |
|---|---|
| **Active / synthetic** | canaries (ICMP/TCP/UDP/HTTP/DNS/…), ECMP/MPLS-aware path discovery, browser-synthetic checks, endpoint digital-experience monitoring |
| **BGP / routing** | RouteViews + RIPE RIS ingestion, route/path analysis, RPKI validity, a collective internet-outage view |
| **Flow analytics** | NetFlow / sFlow / IPFIX into ClickHouse, with per-tenant anomaly detection |
| **Device telemetry** | SNMP polling + gNMI streaming, folded into the topology graph |
| **eBPF host / L7** | service map + L7 visibility, observation-only (the Retina model). **Default builds replay recorded fixtures** (no kernel access needed — CI/macOS/demo path); live kernel capture is the separate `-tags ebpf` build on a BTF kernel ([build matrix](docs/ebpf-agent.md)) |

Intelligence, security, and platform layers built across the planes:

| Layer | What it does |
|---|---|
| **AI assistant** | cross-plane RCA grounded in correlated incidents, natural-language semantic query, AI test authoring, and an **MCP server** (read-only tools + a proposal-only remediation tool) — all **tenant- then RBAC-scoped**, with a fully air-gapped local-model path. **Default engine: a deterministic in-process heuristic (no LLM)** — connecting a model (local Ollama/vLLM or a cloud provider) is explicit opt-in ([`docs/ai-rca.md`](docs/ai-rca.md)) |
| **Topology** | a versioned, change-aware dependency graph with **what-if** impact simulation |
| **Security / threat** | TLS/cert posture + NDR-lite, **confidence-scored detections** (a signal exported to your SIEM — never an inline IPS) |
| **Cost / SLO** | FinOps egress-cost attribution, an OpenSLO engine, and segmentation/compliance validation with evidence |
| **Guarded remediation** | the AI **proposes** a fix grounded in RCA + a dry-run; a human **approves**; probectl **never executes** — proposal-only, blast-radius-limited, fully audited |
| **Multi-tenancy** | tenant is the outermost boundary; **pooled / siloed / hybrid** isolation, selectable per deployment and per tenant |
| **Provider / MSP plane** | tenant lifecycle, fleet-across-tenants, per-tenant metering + quotas, white-label branding, and audited break-glass (no implicit access to tenant telemetry) |
| **Sovereignty & crypto** | no phone-home, mTLS/SPIFFE agent identity, envelope encryption, per-tenant **BYOK**, per-tenant export + verifiable erasure, and an optional build against the **FIPS 140-3-validated Go Cryptographic Module** (CMVP cert **#5247**; probectl itself holds no product-level certificate — see [`docs/hardening.md`](docs/hardening.md)) |

## How it works

Lightweight **agents** — a single Go binary, each bound to one tenant — run the
probes and watch the wire, then push results onto a **bus**. The stateless
**control plane** consumes that stream, persists each signal to the store that
fits it (Postgres for state, ClickHouse for high-cardinality events,
Prometheus/VictoriaMetrics for metrics), and continuously builds incidents and a
versioned topology graph. Every record, query, metric, and message is scoped by
`tenant_id` **first**, then by your RBAC — so the API, web UI, AI assistant, and
MCP server all read through the same tenant-then-RBAC boundary, and a query
cannot cross a tenant line even by mistake.

External intelligence (RouteViews, RIPE RIS/Atlas, RPKI, threat-intel, cloud
pricing) is fetched **once**, cached, and enriched per tenant; if a feed is
rate-limited or down, that view degrades gracefully instead of taking the
platform with it.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart TB
    Provider["Provider / Management Plane — MSP operators (distinct privilege domain)<br/>tenant lifecycle · fleet-across-tenants · metering/billing · white-label<br/>audited break-glass (no implicit tenant-data access)"]

    subgraph CP["Control Plane — Go, stateless, TENANT-AWARE"]
        Edge["REST (OpenAPI 3.1) · gRPC (agents, mTLS) · MCP · Webhooks/OTLP<br/>Auth (SSO/RBAC/ABAC) · Audit · Tenant → Org → Team → Project"]
        Subsys["subsystems: tenancy · path · bgp · opendata · threat · change ·<br/>topology · cost · slo · compliance · ai · remediation · …"]
    end

    Agents["Agents — Go, single binary, tenant-bound<br/>canary plugins · path engine · eBPF host/L7"]
    Analyzer["BGP analyzer (Python)<br/>RouteViews/RIS MRT + RIS Live"]
    Bus["Bus — Kafka / NATS / in-process<br/>(tenant-tagged)"]
    Stores["Postgres · ClickHouse · Prometheus/VM<br/>topology graph · object store"]
    External["External (read-only, cached, degrade gracefully)<br/>RouteViews · RIPE RIS/Atlas · RPKI · PeeringDB · MaxMind/Cymru · CT logs · threat-intel · cloud pricing"]

    Provider -->|tenant-scoped, isolated| CP
    Agents -->|gRPC mTLS| Edge
    Analyzer -->|probectl.bgp.events| Bus
    Agents -->|results, tenant-tagged| Bus
    Bus --> Subsys
    Subsys -->|queries, tenant-first| Stores
    External -.->|ingest once, scope per tenant| Analyzer
    External -.->|cached| Subsys

    classDef prov fill:#26215C,stroke:#7F77DD,color:#CECBF6
    classDef agent fill:#042C53,stroke:#378ADD,color:#B5D4F4
    classDef analyzer fill:#04342C,stroke:#1D9E75,color:#9FE1CB
    classDef bus fill:#412402,stroke:#EF9F27,color:#FAC775
    classDef store fill:#173404,stroke:#639922,color:#C0DD97
    classDef ext fill:#2C2C2A,stroke:#888780,color:#D3D1C7
    class Provider prov
    class Agents agent
    class Analyzer analyzer
    class Bus bus
    class Stores store
    class External ext
```

The provider/management plane spans tenants for **operations only** — never for
silent data access; any access is explicit, time-bounded, tenant-consented, and
separately audited. Full data-flow and per-subsystem diagrams live in
**[`docs/architecture.md`](docs/architecture.md)**.

## What probectl is not

It's a **signal layer, not an enforcement layer**. Threat detections are
confidence-scored and exported to your SIEM — probectl does **not** inline-block
traffic or act as an IPS. The AI **proposes** remediations; a human approves and
an operator acts — there is **no autonomous execution**. And it complements,
rather than replaces, a full APM/distributed-tracing stack or a SIEM/log-analytics
platform. probectl is honest about its edges by design.

## Editions

The full five-plane platform — all observability, the AI assistant, security/threat,
topology, cost/SLO, and single-tenant self-hosting — is **core, and free**.
Commercial code lives in a **publicly-readable `ee/` tree** (the fence is the
license + trademark, not source secrecy) and is gated at runtime by an
**offline-verifiable, signed license** that **never phones home**. **Enterprise**
adds the validated-module (FIPS) build, BYOK/governance, multi-region HA, and guarded remediation;
**Provider/MSP** adds the management plane, hard tenant isolation, metering/billing,
and white-label. Unlicensed commercial features are simply hidden (no lockware).
See **[`docs/editions.md`](docs/editions.md)**.

## Quickstart (run it)

Bring up the control plane **over HTTPS** with a bundled Postgres (a self-signed
cert is generated on first boot):

```sh
cp deploy/compose/.env.example deploy/compose/.env     # set PROBECTL_ENVELOPE_KEY etc.
docker compose -f deploy/compose/probectl.yml up -d
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt
curl --cacert ./ca.crt https://localhost:8443/readyz
```

Once `/readyz` is green, open the UI at `https://localhost:8443`, register an
agent, and run your first synthetic test — or ask the assistant a question. The
API is HTTPS-only (no plaintext port). Full guide, real certificates, SSO, and
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

## Repository layout

```
cmd/            # binaries: probectl-control, probectl-agent, probectl-ebpf-agent,
                #           probectl-flow-agent, probectl-device-agent,
                #           probectl-endpoint, probectl-license, probectl (CLI)
internal/       # subsystem packages (control, tenancy, path, bgp, crypto, ai, ...)
ee/             # commercial tree (provider plane, white-label, metering, BYOK,
                #   remediation) — publicly readable; core never imports it
pkg/            # shared, public libraries
proto/          # protobuf schemas (gRPC + bus) — buf-managed
analyzer/       # Python BGP analyzer
migrations/     # sequential, idempotent SQL migrations
web/            # frontend (React + Vite + TypeScript, themeable design tokens)
deploy/         # compose (dev stack), helm, terraform, docker, gitops
docs/           # configuration, development, architecture, runbooks
test/           # integration harness (separate Go module)
```

## Documentation

New here? Start with **Why probectl** and **How it works** above, then the
install guide. Going deeper:

| Topic | Doc |
|---|---|
| Install & deploy (compose / Helm / air-gapped) | [`docs/install.md`](docs/install.md) |
| Day-2 admin (audit, roles, SSO) | [`docs/admin.md`](docs/admin.md) |
| Architecture deep-dives | [`docs/architecture.md`](docs/architecture.md) |
| Every config key | [`docs/configuration.md`](docs/configuration.md) |
| Editions & licensing model | [`docs/editions.md`](docs/editions.md) |
| Tenant isolation (pooled/siloed/hybrid) | [`docs/isolation.md`](docs/isolation.md) |
| Provider / MSP plane | [`docs/provider-plane.md`](docs/provider-plane.md) |
| AI RCA · semantic query · MCP | [`docs/ai-rca.md`](docs/ai-rca.md) · [`docs/ai-query.md`](docs/ai-query.md) · [`docs/mcp.md`](docs/mcp.md) |
| Guarded remediation (policy) | [`docs/remediation.md`](docs/remediation.md) |
| FIPS / hardening · multi-region HA · BYOK | [`docs/hardening.md`](docs/hardening.md) · [`docs/multi-region.md`](docs/multi-region.md) · [`docs/byok.md`](docs/byok.md) |
| Development & CI | [`docs/development.md`](docs/development.md) |
| Vulnerability disclosure | [`SECURITY.md`](SECURITY.md) |

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Commits follow **Conventional
Commits** (enforced by commitlint in CI) and carry a **DCO sign-off**
(`git commit -s`). Before pushing, run `make ci` — it runs the linters, the unit
tests, and the cross-tenant isolation gate, the same checks CI enforces on every
pull request. The non-negotiable rules (tenant isolation, no phone-home, crypto
only through `internal/crypto`, TLS on every listener) are summarized in
`CONTRIBUTING.md` and enforced by standing CI gates.

## License

**Source-available — not open source (yet).** The source is published to be read,
audited, and self-hosted, but it is **not** released under an OSI-approved
open-source license, and **no open-source rights are granted at this time**.

The license is intentionally **[`TBD`](LICENSE)**: the open-core / reseller
boundary is still an open decision, with a Business Source License (BSL)–family,
open-core model intended (a core that may open over time; commercial use of the
provider/MSP and Enterprise features reserved). Until a grant is added here, treat
the code as **all rights reserved**.
