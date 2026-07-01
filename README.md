```
                 _               _   _
 _ __  _ __ ___ | |__   ___  ___| |_| |
| '_ \| '__/ _ \| '_ \ / _ \/ __| __| |
| |_) | | | (_) | |_) |  __/ (__| |_| |
| .__/|_|  \___/|_.__/ \___|\___|\__|_|
|_|        see everything · send nothing
```

<p align="center">Self-hosted, multi-tenant network observability — five planes, one OpenTelemetry-native control plane,<br>
and an AI assistant that explains root cause <em>across</em> them. Telemetry never leaves your network.</p>

<p align="center">
<a href="https://github.com/imfeelingtheagi/probectl/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/imfeelingtheagi/probectl/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/imfeelingtheagi/probectl/tags"><img alt="tag" src="https://img.shields.io/github/v/tag/imfeelingtheagi/probectl?label=tag&sort=semver"></a>
<a href="https://goreportcard.com/report/github.com/imfeelingtheagi/probectl"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/imfeelingtheagi/probectl"></a>
<img alt="Go" src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white">
<img alt="status" src="https://img.shields.io/badge/status-active%20development-orange">
<img alt="license" src="https://img.shields.io/badge/license-source--available%20%C2%B7%20not%20OSS%20yet-lightgrey">
</p>

<p align="center">
<a href="#why-probectl">Why</a> ·
<a href="#what-it-answers">What it answers</a> ·
<a href="#capabilities">Capabilities</a> ·
<a href="#how-it-works">How it works</a> ·
<a href="#quickstart-run-it">Quickstart</a> ·
<a href="#documentation">Docs</a> ·
<a href="#license">License</a>
</p>

probectl unifies five observability planes — **active/synthetic testing**
(scheduled probes that send traffic and time the answer), **BGP/routing
intelligence** (BGP being the protocol networks use to tell each other which
routes exist), **flow analytics** (the per-connection traffic summaries routers
export), **device telemetry**, and **eBPF host/L7** (sandboxed programs the
Linux kernel runs to observe real connections from the inside) —
into one **OpenTelemetry-native** control plane, then layers cross-plane AI
root-cause analysis, a security/threat signal layer, change-aware topology with
what-if simulation, and cost/SLO intelligence on top.

One codebase serves two operating modes: **sovereign single-tenant** (a
regulated or air-gapped org self-hosts; the deployment *is* the tenant) and
**multi-tenant / provider** (an MSP self-hosts once and serves many
hard-isolated, white-labeled tenants). A **tenant** is one isolated customer or
organization in a deployment, and the single-tenant install is just the
one-tenant case — there is no separate code path, no enterprise fork to drift
out of sync. **Tenant is the outermost scope and security boundary** on every
record, agent, query, metric, event, and object.

> **Status:** the platform is built — all five planes plus the intelligence,
> security, and provider/MSP layers in the tables below are shipped; the work
> now is hardening toward GA. Compose + Helm are **HTTPS-by-default**. The
> license is intentionally **`TBD`** — **source-available, not open source
> (yet)** ([details](#license)).

**Try it in a few minutes** (Docker only, no Go toolchain on your host — the
image builds from source on first run, then it's ~60 seconds to first data;
full walkthrough in the [Quickstart](#quickstart-run-it)):

```sh
docker compose -f deploy/compose/eval.yml up --build -d
docker compose -f deploy/compose/eval.yml --profile tools run --rm viewer   # → your first data
```

## Why probectl

When something on the network breaks, the symptom and the cause usually live in
different places. A slow checkout page might be a BGP route flap three networks
away, a saturated uplink, a DNS timeout, a misbehaving host, or a config change
that shipped ten minutes ago — and the tools that each see one of those are
typically five separate products with five separate dashboards. You find out at
2 a.m., by stitching them together by hand.

probectl collapses that. Every plane lands in **one** tenant-scoped control
plane, gets correlated into a single incident, and an AI assistant explains the
root cause *across* planes instead of leaving you to guess which dashboard to
open first.

Four choices set it apart:

- **It stays yours.** Self-hosted and **never phones home** — no telemetry
  beacons, no "call home," nothing. Hosted observability SaaS works by shipping
  your network data to a vendor's cloud; probectl keeps every byte inside your
  own infrastructure. For regulated, air-gapped, or sovereignty-conscious
  operators that isn't a nice-to-have — it's the requirement.
- **It's unified and standard.** One OpenTelemetry-native model spans all five
  planes, so a flow record, a probe result, and a BGP event share the same
  schema and the same query layer. (OpenTelemetry is the vendor-neutral open
  standard for telemetry; OTLP is its wire protocol.) The receiver ingests all
  three OTLP signals
  — **metrics, traces, and logs** — bounded for correlation, and re-exports
  probectl's own signals as OTLP **metrics**; the schemas follow OTel resource +
  network semantic conventions everywhere ([`docs/otlp.md`](docs/otlp.md)).
- **It does not meter the core by surprise.** The full five-plane core platform
  is free; commercial gates are about tenant-band/provider operations,
  governance, HA, BYOK, and resale controls, not per-host, per-flow, or per-GB
  tolls on the signals you already collect.
- **It's multi-tenant to the core.** The same binary runs as a single sovereign
  tenant for one org, or as a hard-isolated, white-labeled, individually-metered
  platform an MSP resells — one codebase, one security boundary.

## What it answers

probectl is organized around the questions operators actually ask at 2 a.m.:

- *"The Berlin office says the app is slow — is it the network, the path in
  between, or the server?"* — synthetic probes, ECMP/MPLS-aware path discovery
  (it maps correctly even through networks that split traffic across parallel
  paths), and flow show you **where** the latency is, not just that it exists.
- *"Did the 14:03 change cause this?"* — change-aware topology correlates
  config/deploy events with the symptoms that followed them.
- *"Why did this prefix go dark — is it us, or the internet?"* — BGP/routing
  intelligence from RouteViews/RIPE RIS (public archives of the internet's
  routing table), RPKI validity (signed records of who may announce which
  address block), and a collective outage
  view separate a you-problem from an everyone-problem.
- *"What breaks if I drain this node?"* — the topology **what-if** simulates the
  blast radius before you touch production.
- *"Who's saturating this link, and what's it costing?"* — flow analytics plus
  per-tenant FinOps egress attribution.

Or just ask the built-in assistant *"why is checkout slow for tenant X?"* — this
is sovereign network observability AI by default: it runs the cross-plane
correlation inside your control plane, answers with **cited evidence**, and is
scoped to exactly what the caller is allowed to see. Local Ollama/vLLM keeps the
LLM path air-gapped; any remote model requires explicit consent, redaction, and
audit before tenant evidence can leave your network.

## Who it's for

- **Regulated & sovereignty-conscious orgs** (finance, healthcare, public
  sector, defense, critical infrastructure) that need deep network
  observability but cannot send telemetry to a third-party cloud.
- **MSPs & internal platform teams** serving many customers or business units —
  self-host once, serve hard-isolated, white-labeled, individually-metered
  tenants from one control plane.
- **Network & platform engineers** tired of hand-correlating five dashboards
  who want a single OTel-native source of truth they actually own.

## Capabilities

The five observability planes:

| Plane | What it covers |
|---|---|
| **Active / synthetic** | canaries — scheduled probes that send traffic and time the answer (ICMP/TCP/UDP/HTTP/DNS/…) — plus ECMP/MPLS-aware path discovery, browser-synthetic checks, endpoint digital-experience monitoring |
| **BGP / routing** | RouteViews + RIPE RIS ingestion, direct mTLS BMP sessions from routers, route/path analysis, RPKI validity, a collective internet-outage view |
| **Flow analytics** | NetFlow / sFlow / IPFIX plus AWS VPC, Azure NSG, and GCP VPC flow-log import into ClickHouse, with local learned per-tenant anomaly detection |
| **Device telemetry** | tenant-scoped SNMP discovery/import review, SNMP polling + gNMI streaming, folded into the topology graph |
| **eBPF host / L7** | service map + L7 visibility, observation-only (the Retina model). **Default builds replay recorded fixtures** (no kernel access needed — CI/macOS/demo path); live kernel capture is the separate `-tags ebpf` build on a BTF kernel ([build matrix](docs/ebpf-agent.md)) |

Intelligence, security, and platform layers built across the planes:

| Layer | What it does |
|---|---|
| **AI assistant** | sovereign network observability AI: cross-plane RCA grounded in correlated incidents, natural-language semantic query, AI test authoring, and an **MCP server** (MCP — the Model Context Protocol, how external AI apps call tools; here read-only tools + a proposal-only remediation tool) — all **tenant- then RBAC-scoped**. **Default engine: a deterministic in-process heuristic — no LLM is involved or contacted unless you explicitly connect one** (local Ollama/vLLM for full air-gap, or a cloud provider only after explicit consent, redaction, and audit; start with [`docs/ai-quickstart.md`](docs/ai-quickstart.md)) |
| **Topology** | a versioned, change-aware dependency graph with **what-if** impact simulation |
| **Security / threat** | TLS/cert posture + NDR-lite, **confidence-scored detections** (a signal exported to your SIEM — never an inline IPS) |
| **Cost / SLO** | FinOps egress-cost attribution, an OpenSLO engine, and segmentation/compliance validation with evidence |
| **Guarded remediation** | the AI **proposes** a fix grounded in RCA + a dry-run; a human **approves**; probectl **never executes** — proposal-only, blast-radius-limited, fully audited |
| **Multi-tenancy** | **pooled / siloed / hybrid** isolation, selectable per deployment and per tenant |
| **Provider / MSP plane** | tenant lifecycle, fleet-across-tenants, per-tenant metering + quotas, white-label branding, and audited break-glass (no implicit access to tenant telemetry) |
| **Sovereignty & crypto** | mTLS/SPIFFE agent identity (mutual TLS — both ends prove who they are — with standard workload-identity naming), envelope encryption, per-tenant **BYOK** (bring-your-own-key), per-tenant export + verifiable erasure, and an optional build against the **FIPS 140-3-validated Go Cryptographic Module** (CMVP cert **#5247**; probectl itself holds no product-level certificate — see [`docs/hardening.md`](docs/hardening.md)) |

## How it works

Lightweight **producers** — a small family of single static Go binaries, each
bound to one tenant — run probes, collect flows/device/endpoint signals, and
watch the wire, then push results onto a **bus**. The stateless
**control plane** consumes that stream, persists each signal to the store that
fits it (Postgres for state, ClickHouse for high-cardinality events,
Prometheus/VictoriaMetrics for metrics), and continuously builds incidents and a
versioned topology graph. Every record, query, metric, and message is scoped by
`tenant_id` **first**, then by your RBAC (role-based access control — the
caller's permission set) — the API, web UI, AI assistant, and
MCP server all read through that same boundary, so a query cannot cross a
tenant line even by mistake.

External intelligence (RouteViews, RIPE RIS/Atlas, RPKI, threat-intel, cloud
pricing) is fetched **once**, cached, and enriched per tenant; if a feed is
rate-limited or down, that view degrades gracefully instead of taking the
platform with it.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'transparent','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#768390','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','titleColor':'#e6edf3','edgeLabelBackground':'#161b22','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart TB
    Provider["Provider / Management Plane — MSP operators (distinct privilege domain)<br/>tenant lifecycle · fleet-across-tenants · metering/billing · white-label<br/>audited break-glass (no implicit tenant-data access)"]

    subgraph CP["Control Plane — Go, stateless, TENANT-AWARE"]
        Edge["REST (OpenAPI 3.1) · gRPC (agents, mTLS) · MCP · Webhooks/OTLP<br/>Auth (SSO/RBAC/ABAC) · Audit · Tenant → Org → Team → Project"]
        Subsys["subsystems: tenancy · path · bgp · opendata · threat · change ·<br/>topology · cost · slo · compliance · ai · remediation · …"]
    end

    Agents["Producer binaries — Go, static, tenant-bound<br/>canary/path · eBPF host/L7 · flow · device · endpoint"]
    Analyzer["BGP analyzer (Python)<br/>RouteViews/RIS MRT + RIS Live"]
    Bus["Bus — Kafka / in-process<br/>(tenant-tagged)"]
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

The full five-plane platform — all observability, the AI assistant,
security/threat, topology, cost/SLO, and single-tenant self-hosting — is
**core, and free**. Commercial code lives in a **publicly-readable `ee/` tree**
(the fence is the license + trademark, not source secrecy) and is gated at
runtime by an **offline-verifiable, signed license** that never phones home.
That boundary is operational rather than volume-taxed: tenant-band/provider
controls, governance, HA, BYOK, and resale are gated; the core signal plane is
not priced by per-host, per-flow, or per-GB meters.
**Enterprise** adds the validated-module (FIPS) build, BYOK/governance,
multi-region HA, and guarded remediation; **Provider/MSP** adds the management
plane, siloed/hybrid physical isolation and residency controls,
metering/billing, and white-label. Hard tenant isolation is a core-platform
property; Provider/MSP adds stronger placement and operations controls on top.
Unlicensed commercial features are simply hidden (no lockware). See
**[`docs/editions.md`](docs/editions.md)**.

## Quickstart (run it)

**One idea first: the control plane is a *consumer*, not a producer.** It
ingests, correlates, stores, and serves — but it never observes the network
itself. The things that watch the wire and run probes are the **producers**:
the agents and collectors. So a control plane with **no producers attached
collects nothing** — `/readyz` goes green and the dashboards stay empty. That's
expected, not a bug. To see data you have to attach at least one producer.

### Fastest path to *first data* — the evaluation stack

This brings up the control plane **plus** an eBPF agent in **fixture mode**
(replaying a recorded, clearly-labelled file of SAMPLE flows — no kernel, works
on macOS/Windows/Linux), so you watch a real signal flow end-to-end with one
command and no Go toolchain:

```sh
docker compose -f deploy/compose/eval.yml up --build -d
# ~20s for the control plane to migrate + start, then:
docker compose -f deploy/compose/eval.yml --profile tools run --rm viewer
```

`viewer` prints the `/v1/topology` service map the control plane folded out of
those sample flows — and that JSON **is your first data** (pretty-printed here;
your `at` timestamp will differ):

```json
{
  "at": "2026-06-10T18:42:07Z",
  "coverage": {
    "path_edges": 0, "flow_edges": 2, "routing_edges": 0, "device_edges": 0,
    "notes": [
      "no routing-plane (BGP) edges — prefix impact may be incomplete",
      "no device→hop interface links — device-level impact unavailable"
    ]
  },
  "edges": [
    {"from": "service:10.0.1.5", "to": "service:10.0.2.9", "kind": "flow"},
    {"from": "service:10.0.1.5", "to": "service:10.0.3.3", "kind": "flow"}
  ],
  "nodes": [
    {"id": "service:10.0.1.5", "kind": "service", "label": "10.0.1.5"},
    {"id": "service:10.0.2.9", "kind": "service", "label": "10.0.2.9"},
    {"id": "service:10.0.3.3", "kind": "service", "label": "10.0.3.3"}
  ],
  "topology_running": true
}
```

That's the whole pipeline in one read: the agent replayed three sample flows
(one host talking to an HTTPS endpoint and a Postgres), the control plane
folded them into two service edges, and the `coverage` block honestly reports
which planes this little graph does *not* yet see.

This stack is **evaluation-only** (loopback dev-auth — every request is an
unauthenticated admin — plus plaintext Kafka and a self-signed cert), so it's
never reachable from your network and never for production. Walk it all the way
through — including synthetic (canary) probes and the build-from-source path —
in **[`docs/getting-started.md`](docs/getting-started.md)**, and meet every
producer you can attach in **[`docs/deploying-agents.md`](docs/deploying-agents.md)**.

### Production-shaped stack

The shipped all-in-one deploy is `deploy/compose/probectl.yml`: the control
plane **over HTTPS** with a bundled Postgres (a self-signed cert is generated on
first boot), no evaluation weakenings.

```sh
cp deploy/compose/.env.example deploy/compose/.env     # set POSTGRES_PASSWORD (required) + PROBECTL_ENVELOPE_KEY
docker compose -f deploy/compose/probectl.yml up -d
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt
curl --cacert ./ca.crt https://localhost:8443/readyz
```

Once `/readyz` is green, open the UI at `https://localhost:8443` — then (per the
consumer/producer rule above) register an agent and run your first synthetic
test, or ask the assistant a question. The API is HTTPS-only (no plaintext
port). Full guide, real certificates, SSO, and the Kubernetes/Helm path:
**[`docs/install.md`](docs/install.md)**; day-2 operation (audit, roles, SSO):
**[`docs/admin.md`](docs/admin.md)**.

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
deploy/         # compose (eval + production + dev stacks), docker, helm,
                #   agent hardening profiles, terraform, gitops
docs/           # journeys/ (usage paths) + features/ (per-capability) + glossary;
                #   configuration, development, architecture, runbooks
test/           # integration harness (separate Go module)
```

## Documentation

New here? Start with the **[user journeys](docs/journeys.md)** — the end-to-end paths
through the product (onboarding, alert→root-cause, threat response, tenant setup,
cost/SLO governance, production operations). Each is a copy-along route that links to
the feature pages behind it. The **[feature index](docs/features.md)** maps every
capability (F1–F57) to its page, and the **[glossary](docs/glossary.md)** defines every
term from zero knowledge. (Or skim **Why probectl** and **How it works** above first.)
Going deeper:

| Topic | Doc |
|---|---|
| **Start here — user journeys** (the product usage paths) | **[`docs/journeys.md`](docs/journeys.md)** |
| Feature index — every capability (F1–F57) → its page | [`docs/features.md`](docs/features.md) |
| Glossary — the zero-knowledge dictionary | [`docs/glossary.md`](docs/glossary.md) |
| Getting started (zero → first real data) | [`docs/getting-started.md`](docs/getting-started.md) |
| Deploying agents & collectors (the producers) | [`docs/deploying-agents.md`](docs/deploying-agents.md) |
| Install & deploy (compose / Helm / air-gapped) | [`docs/install.md`](docs/install.md) |
| Day-2 admin (audit, roles, SSO) | [`docs/admin.md`](docs/admin.md) |
| Architecture deep-dives | [`docs/architecture.md`](docs/architecture.md) |
| Every config key | [`docs/configuration.md`](docs/configuration.md) |
| Editions & licensing model | [`docs/editions.md`](docs/editions.md) |
| Tenant isolation (pooled/siloed/hybrid) | [`docs/isolation.md`](docs/isolation.md) |
| Provider / MSP plane | [`docs/provider-plane.md`](docs/provider-plane.md) |
| Using the AI (ask → local model → MCP, in 10 min) | [`docs/ai-quickstart.md`](docs/ai-quickstart.md) |
| AI RCA · semantic query · MCP | [`docs/ai-rca.md`](docs/ai-rca.md) · [`docs/ai-query.md`](docs/ai-query.md) · [`docs/mcp.md`](docs/mcp.md) |
| Guarded remediation (policy) | [`docs/remediation.md`](docs/remediation.md) |
| FIPS / hardening · multi-region HA · BYOK | [`docs/hardening.md`](docs/hardening.md) · [`docs/multi-region.md`](docs/multi-region.md) · [`docs/byok.md`](docs/byok.md) |
| Development & CI | [`docs/development.md`](docs/development.md) |
| Vulnerability disclosure | [`SECURITY.md`](SECURITY.md) |

## Getting help

Bug reports and questions: **GitHub Issues** on this repo. Security
vulnerabilities: **never** a public issue — follow
[`SECURITY.md`](SECURITY.md). Most "how do I…" answers live in the
[documentation table](#documentation) above; start with
[`docs/getting-started.md`](docs/getting-started.md).

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Commits follow **Conventional
Commits** (enforced by commitlint in CI) and carry a **DCO sign-off**
(`git commit -s`). Before pushing, run `make ci` — it runs the linters, the unit
tests, and the cross-tenant isolation gate, the same checks CI enforces on every
pull request. The non-negotiable rules (tenant isolation, no phone-home, crypto
only through `internal/crypto`, TLS on every listener) are summarized in
[`CONTRIBUTING.md`](CONTRIBUTING.md) and enforced by standing CI gates.

## License

**Source-available — not open source (yet).** The source is published to be read,
audited, and self-hosted, but it is **not** released under an OSI-approved
open-source license, and **no open-source rights are granted at this time**.

The license is intentionally **[`TBD`](LICENSE)**: the open-core / reseller
boundary is still an open decision, with a Business Source License (BSL)–family,
open-core model intended (a core that may open over time; commercial use of the
provider/MSP and Enterprise features reserved). Until a grant is added here, treat
the code as **all rights reserved**.
