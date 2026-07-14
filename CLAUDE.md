# CLAUDE.md — probectl

*Engineering reference for the probectl codebase. The PRD (`probectl-PRD-v1.0.md` — delivered-state + remaining-to-GA; v0.5 is frozen history) is the product contract; if this file and the PRD ever conflict, flag it.*

## 0. Read first — the non-negotiables

All your responses should be deeply technical ELI5 format.

If you read nothing else, read this. Full text in §7.

- **Tenant isolation is the outermost boundary** — cross-tenant data leakage is the highest-severity failure. Every path is scoped by `tenant_id` at the **storage/query layer** (RLS/partition or physical silo), not by handler code alone. A cross-tenant isolation test accompanies any change to a data-access path. AI/MCP enforce **tenant first, then RBAC**. When in doubt, fail closed (return nothing). [§7.1, §7.5]
- **No phone-home, ever** — no default outbound telemetry/beacons; license verification is offline local math; open-data fetches are read-only and degrade gracefully. [§7.2, §7.10]
- **Crypto only through `internal/crypto`** (FIPS-swappable) — never call primitives from handlers/services. [§7.3]
- **TLS on every channel and listener** — mTLS agent↔control-plane; HTTPS for API/UI/OTLP/MCP; HTTPS-by-default compose+Helm; inbound ingestion is authenticated, tenant-scoped, signature-verified, treated as untrusted; outbound validates certs. Missing secure channel/credential/signature → fail closed. [§7.4, §7.12]
- **Remediation is observe-only / human-gated; detection is a signal, never an IPS.** [§7.8, §7.9]
- **Editions:** one repo, no edition branches. Commercial code only under `ee/`; **core never imports `ee/`** (CI-guarded). Tier checks live in exactly one place (`internal/license`) and gate only at the `main.go` `Build*` seams. [§2]

**Ask the human before:** changing an architecture/stack decision (§4), touching a guardrail (§7), or adding an external dependency or data source. Default to the established convention; prefer the smallest coherent change (§9).

## 1. What probectl is

A **self-hosted, open-core, multi-tenant network observability platform**. It unifies five planes — active/synthetic testing, BGP/routing, flow analytics, device telemetry, and eBPF host/L7 — on an **OpenTelemetry-native** control plane, with an **AI assistant** for cross-plane root-cause analysis, a native **security/threat** layer (TLS/cert posture + NDR-lite signals), **change-aware topology**, and **cost/SLO** intelligence. Enriched by public open-data + threat-intel; **telemetry never leaves the operator's network**.

- **Two operating modes, one codebase.** (1) *Sovereign single-tenant* — a regulated/air-gapped org self-hosts; the deployment *is* the tenant boundary. (2) *Multi-tenant / provider* — an MSP (or internal platform team) self-hosts once and serves many hard-isolated tenants under the probectl banner. The single-tenant install is just the one-tenant case — **there is no separate code path**. Tenant is the outermost scope on every record, agent, query, metric, event, and object (see §7.1).
- **Mode:** solo founder + AI agents; built in the open. Core is MPL-2.0; `ee/` remains separately commercially licensed. Enterprise is flat-rate self-hosted; MSP is consumption-based self-hosted resale under the probectl banner, with operator-run usage export and no phone-home.
- **Sibling:** `trustctl` (certificate/NHI lifecycle). probectl reuses its patterns (control-plane + agents, MCP server) and hands TLS/cert findings to it.

## 2. Editions & business model

probectl is **open-core**: the core platform is licensed under MPL-2.0; commercial Enterprise and MSP tiers are gated. How the split works in the codebase:

- **One repo, no edition branches.** Commercial code lives in a top-level **`ee/`** tree under a commercial-license header; in a public repo `ee/` source is readable (GitLab/CockroachDB model) — the fence is the license + trademark, not source secrecy.
- **One-way boundary:** `ee/` may import core; **core never imports `ee/`**, enforced by CI (`make editions-gate` + the import guard). The core-only build (`-tags probectl_core`) passes the full suite with `ee/` inert.
- **Runtime gating** via `internal/license`: an offline-verifiable **Ed25519-signed license file** (tier, informational pricing model, features, expiry, tenant band, customer), verified against build-time-baked public keys — **never phone-home**. The single feature→tier table lives in `internal/license` (`tierFeatures`); gating is wired only at the `main.go` `Build*` seams, never scattered through handlers.
- **Enterprise (self-host): flat rate.** Grants FIPS build access, BYOK/governance, guarded remediation, HA support, and siloed/hybrid isolation.
- **MSP: consumption-based.** Inherits the Enterprise set, adds the provider plane and local metering/export, and resells under the probectl banner. The MSP sets its own customer prices. Reporting is operator-run export — never phone-home.
- **Core (deliberately free):** per-tenant export/verifiable deletion (a compliance right), fairness enforcement (protects the pooled platform), support-bundle generation (the tool is core; the support SLA is a contract).
- **Unlicensed UX:** commercial features are *hidden* (no lockware); one **Admin → Editions** page shows tier/pricing/features/state. **Expiry:** a 30-day grace banner, then commercial features degrade **read-only** (no new tenants/config; telemetry pipelines never break).

The enforcement mechanics are complete. The root **`LICENSE` is the unmodified MPL-2.0 text**, and Exhibit B is not invoked. Counsel still owns the bespoke `ee/LICENSE`, commercial header wording, reseller terms, DPA/MSA, trademark posture, and commercial open-data/threat-intel AUP review. Those pending commercial documents do not make the core grant provisional.

## 3. Architecture (the shape)

```
         ┌──── Provider / Management Plane (MSP operators; distinct privilege domain) ────┐
         │  tenant lifecycle (provision/suspend/offboard) · fleet-across-tenants ·         │
         │  per-tenant metering/billing · white-label · audited break-glass (NO implicit   │
         │  read access to tenant telemetry)                                               │
         └───────────────────────────────────────▲─────────────────────────────────────────┘
                                                  │ (tenant-scoped, isolated)
                 ┌─────────────────────────── Control Plane (Go, stateless, TENANT-AWARE) ──────────────────┐
                 │  REST API (OpenAPI 3.1, versioned)  ·  gRPC (agents)  ·  MCP server  ·  Webhooks/OTLP      │
                 │  Auth (SSO/SCIM/RBAC/ABAC; per-tenant IdP) · Audit · Tenant → Orgs/Teams/Projects ·        │
                 │  Alerting · Incidents                                                                      │
                 │  Subsystems: tenancy · path · bgp · opendata · threat · change · topology · cost · slo ·    │
                 │              compliance · ai (semantic query/RCA/adapter — enforces TENANT then RBAC)       │
                 └───────▲───────────────────────▲────────────────────────▲──────────────────────────────────┘
        gRPC (mTLS)      │ (tenant-bound)         │ bus (tenant-tagged /    │ queries (tenant-scoped first)
   ┌─────────────────────┴──────┐        ┌────────┴─── namespaced) ──┐ ┌────┴───────────────────────────────┐
   │ Agents (Go single binary)  │        │ Kafka (default)  │          │ Postgres (tenants, state, RBAC,     │
   │  canary plugins (icmp/tcp/  │  ───▶  │  probectl.*.results│ ───────▶ │   audit, SLOs; pooled row-level     │
   │  udp/http/dns/...) ·        │        │  probectl.*.events │          │   tenant_id / siloed per-schema)    │
   │  path engine                │        │  (Protobuf)      │          │ ClickHouse (flow/eBPF/threat/change │
   ├────────────────────────────┤        │  NATS / direct   │          │   /cost; tenant_id partition key)   │
   │ eBPF agent (cilium/ebpf)    │        │  = lightweight   │          │ Prometheus/VictoriaMetrics (tenant  │
   │ Endpoint agent (DEM)        │        └──────────────────┘          │   label / per-tenant series)        │
   └────────────────────────────┘                                      │ Topology graph · Object store       │
                                                                        │   (per-tenant prefix/bucket)        │
                                                                        └─────────────────────────────────────┘
   Isolation models: POOLED (shared stores, logical tenant_id, enforced at storage+query layer) ·
   SILOED (per-tenant schema/DB/namespace/bucket; optional per-tenant keys) · HYBRID. Selectable per
   deployment AND per tenant. External feeds are ingested ONCE (shared), then scoped/enriched per tenant.
   External (read-only, cached, graceful-degrade, TLS-validated): RouteViews · RIPE RIS/Live · RIPE Atlas ·
   RPKI · PeeringDB · MaxMind/Team Cymru · CT logs · IODA/Cloudflare Radar · threat-intel · cloud pricing.
   Python BGP analyzer (structlog) consumes MRT/RIS → emits probectl.bgp.events.
```

Flow: tenant-bound agents probe → push results to the bus (tenant-tagged) → control-plane consumers persist and build incidents/topology → API/UI/AI/MCP query the unified stores within the caller's tenant first, then RBAC. eBPF/flow are the shared substrate for observability *and* security/segmentation/cost. The provider plane spans tenants for operations only — never silent data access (§7.1, §7.7).

## 4. Tech stack

- **Tenancy (ground-up):** `tenant_id` resolved at the control-plane edge and propagated API → bus → storage → AI; pooled isolation enforced at the storage+query layer. The provider/management plane is a separate privilege domain (operators ≠ tenant users). Full rules: §7.1.
- **Control plane & agents:** Go (single static multi-arch binaries; `linux/amd64`,`linux/arm64`). Agent = one binary with compiled-in canary plugins, bound to a single tenant at registration.
- **BGP analyzer:** Python (rich BGP libs); `structlog`.
- **eBPF:** `cilium/ebpf` (Go) or libbpf; CNI-agnostic, observability-only (Retina model).
- **Datastores:** PostgreSQL (durable state; pooled = row-level `tenant_id` + RLS, siloed = per-tenant schema/instance); ClickHouse (high-cardinality events; `tenant_id` in partition/order key, or per-tenant DB siloed); Prometheus/VictoriaMetrics (tenant label or per-tenant series); object store pluggable (filesystem / S3 / MinIO; per-tenant prefix/bucket).
- **Bus:** Kafka (default) with a lightweight mode (NATS / Redis Streams / direct-to-TSDB) for small deployments. Tenant-tagged (pooled) or topic-namespaced per tenant (siloed).
- **Transport & serialization:** gRPC bidi streaming agent↔control-plane over mTLS + SPIFFE-style tenant-bound identity (trustctl synergy); Protobuf for bus + gRPC (schemas in `proto/`), JSON only as a dev fallback. Transport security: §7.4, §7.12.
- **Telemetry standard:** OpenTelemetry (OTLP ingest/export; OBI for eBPF); tenant carried as a resource attribute. The result/event schema is modeled on OTel resource + network semantic conventions, so OTLP/OBI is *exposed* from the schema rather than retrofitted.
- **AI:** pluggable model adapter (Anthropic/OpenAI/Azure/Bedrock + local Ollama/vLLM for sovereignty); MCP server; every AI/MCP call enforces tenant boundary first, then RBAC (§7.1, §7.5).
- **Frontend (`web/`):** themeable design tokens (white-label-ready from token #1; no hardcoded design values), a component library, an app shell + command palette + keyboard-first model, auth-aware routing, a WCAG 2.2 AA baseline (CI a11y gate), and a dark-native aesthetic (PRD v1.0 §2.7). Per-tenant white-label is a token *override*, not a per-screen retrofit; an always-visible tenant indicator is built in; the provider console is a visually-separate surface. The hero visuals (the path map, the topology/what-if view) and the AI surface are the design-led parts of the UI.
- **Packaging:** multi-arch Docker (`<version>` + `latest`); Helm (K8s/OpenShift) with single-tenant and multi-tenant/provider reference values; docker-compose (small/all-in-one + dev/test stack); air-gapped bundle. Shipped compose + Helm are HTTPS-by-default (§7.12).

## 5. Repository layout

```
probectl/
├── CLAUDE.md  README.md  LICENSE(MPL-2.0)  LICENSING.md  Makefile  go.work/go.mod
├── cmd/
│   ├── probectl-control/      # control-plane API server
│   ├── probectl-agent/        # canary/enterprise agent (single binary)
│   ├── probectl-ebpf-agent/   # eBPF agent
│   ├── probectl-endpoint/     # endpoint/DEM agent
│   ├── probectl-license/      # offline license signing CLI (gen-key/sign/verify/inspect)
│   └── probectl/              # CLI/TUI (web-parity)
├── internal/
│   ├── control/    # API handlers, services, domain logic
│   ├── tenancy/    # tenant model, context propagation, isolation enforcement, provider plane
│   ├── billing/    # per-tenant metering, usage export, quotas
│   ├── agent/      # agent runtime + plugin host + store-and-forward
│   ├── canary/     # canary plugins: icmp, tcp, udp, http, dns, ...
│   ├── path/  bgp/  ebpf/  opendata/  threat/  change/  topology/  cost/  slo/  compliance/
│   ├── ai/         # semantic query, RCA, model adapter, MCP, authoring
│   ├── crypto/     # crypto provider interface (FIPS-swappable) + envelope encryption + mTLS/SPIFFE + Ed25519; per-tenant keys/BYOK
│   ├── auth/  audit/  store/  bus/  otel/  branding/  support/  perf/
│   └── license/    # offline-signed license verify + the ONE feature→tier table
├── ee/             # commercial tree (provider plane, white-label, metering, BYOK, remediation).
│                   #   commercial header; imports core, NEVER imported by core (CI-guarded)
├── pkg/  proto/  analyzer/(Python BGP)  migrations/(sequential, idempotent)
├── web/            # frontend (design tokens, component library, app shell; theme-overridable per tenant for white-label)
├── deploy/{compose,helm,terraform}/  docs/  test/(real Kafka+Prometheus+ClickHouse+Postgres)
```

## 6. Conventions (mechanics — follow exactly)

- **Tenancy:** every tenant-owned table carries a non-null `tenant_id` with the appropriate index/partition from its first migration; every query, bus message, metric series, and object key is tenant-scoped. Scope at the storage/query layer, not only in handlers. Provider/operator + break-glass actions go to a separate audit stream. (Rule: §7.1.)
- **Errors:** services return domain errors; handlers map to HTTP status. Canary/probe failures return `success:false` with a message — never panic in production paths.
- **Logging:** Go `slog` with structured fields (include `tenant_id` where applicable); Python `structlog`. No `fmt.Printf` in production code; never log another tenant's data or any secret.
- **Config:** control plane via env (`PROBECTL_` prefix); agent via YAML or env. Document every key in `docs/configuration.md`.
- **Migrations:** sequential numbered files; idempotent (`IF NOT EXISTS`, `ON CONFLICT`); backward-compatible (zero-downtime); new tenant-owned tables include `tenant_id` + index/partition from the first migration.
- **Bus topics:** `probectl.<type>.results` / `probectl.<type>.events` (e.g. `probectl.network.results`, `probectl.bgp.events`, `probectl.threat.events`), partitioned by type and tenant-tagged (pooled) or namespaced per tenant (siloed). Protobuf payloads; schemas in `proto/`.
- **API:** OpenAPI 3.1, versioned (`/v1/...`), deprecation policy + LTS. No undocumented routes. Update the spec in the same PR as the handler.
- **Testing:** table-driven unit tests; handler tests via `httptest`; integration tests use the real `test/` Compose stack; BGP analyzer uses recorded MRT/RIS fixtures; eBPF uses recorded fixtures where kernel access is unavailable.
- **Commits/PRs:** Conventional Commits (e.g. `feat(canary): add ICMP network test`).
- **Naming:** packages lowercase, no stutter; exported API documented; no dead code.
- **Editions:** commercial code only under `ee/`; core never imports `ee/` (the CI guard blocks it); tier checks exist only in `internal/license`'s feature→tier table and gate only at the `main.go` `Build*` seams; the core-only build stays green with `ee/` inert; unlicensed features stay hidden except on Admin → Editions. (See §2.)
- **UI / design system:** build on the design tokens + components — never hardcode colors, spacing, type, radius, or motion (white-label resolves per-tenant token overrides; any hardcoded value breaks it). Meet WCAG 2.2 AA (keep the CI a11y gate green); keep the tenant indicator always visible; no third-party/phoning-home fonts (§7.11).
- **Telemetry conventions:** new signal types map to OTel resource + network semantic conventions from their first emission — don't invent attribute names where a standard exists.
- **Transport & ingestion:** this is guardrail §7.12 — apply it to every new listener, webhook, fetch, and datastore/bus client.

## 7. Security & safety guardrails (non-negotiable)

Hard rules. **If a task seems to require violating one, stop and ask the human.**

1. **Tenant isolation is the outermost boundary (catastrophic if broken).** Cross-tenant leakage is the highest-severity failure. Every data path is scoped by `tenant_id`; pooled isolation is enforced at the storage+query layer (defense-in-depth, above RBAC), not by application code alone. A cross-tenant isolation test must accompany any change to a data-access path; CI runs a cross-tenant isolation suite. The AI/MCP query layer enforces tenant first, then RBAC. Provider/MSP operators get no implicit read access to tenant telemetry — access is only via explicit, time-bounded, tenant-consented, separately-audited break-glass. When in doubt, fail closed (return nothing).
2. **Self-hosted, no phone-home.** Never add default outbound telemetry, analytics beacons, or call-home behavior. Adoption metrics, if any, are opt-in / download-proxy only.
3. **Crypto abstraction (FIPS).** All crypto goes through `internal/crypto` so a FIPS 140-3 validated module can be compiled in. Never call primitives from handlers/services. (Per-tenant keys/BYOK build on this.)
4. **mTLS everywhere agent↔control-plane** (SPIFFE-style, tenant-bound). No plaintext agent transport.
5. **Tenant boundary + RBAC/ABAC on every path — including AI and MCP.** Answers and MCP tools return only data within the caller's tenant and authorization scope.
6. **Secrets handling.** Never hardcode credentials/tokens/keys; never log secrets. Sensitive config/credentials use envelope encryption at rest; the control plane never stores plaintext private keys for managed-host flows. No secrets in URLs/query strings or git.
7. **Audit everything.** Config changes and data-access actions go to the immutable, tamper-evident audit log; provider-plane and break-glass actions go to a separate, equally-tamper-evident provider audit stream.
8. **Remediation is observe-only / human-gated by default.** Any agentic action layer requires explicit human approval, supports dry-run/simulation, enforces blast-radius limits, is tenant- and RBAC-scoped, and is fully audited. Never ship un-gated autonomous network actions.
9. **Threat detection is a signal, not an IPS.** Detections are confidence-scored, tunable, suppressible, and exported to the SIEM — probectl does not auto-block traffic or act as an inline IPS.
10. **Open-data/threat-intel:** treat external sources as read-only, ingest once (shared) then scope per tenant, cache them, and degrade gracefully — a down/rate-limited source must never break core function. Fetch over TLS with certificate validation (never disabled); treat fetched content as untrusted. Track per-source AUP/provenance (relevant to MSP/commercial resale).
11. **No browser storage in the web UI** beyond what's explicitly designed; keep the UI usable without third-party calls (sovereignty).
12. **TLS on every listener; verified, authenticated, untrusted ingestion on every inbound surface.** Every listener serves TLS (1.2+, prefer 1.3): agent transport is mTLS (guardrail 4); REST API, web UI, OTLP, and MCP are HTTPS; shipped compose + Helm are HTTPS-by-default (TLS-terminating ingress, HSTS, no plaintext API), with the UI setting a CSP and Secure+HttpOnly+SameSite cookies. Every inbound ingestion surface (OTLP, webhooks, API) is authenticated, tenant-scoped, signature-verified where the sender signs (e.g. Git/CI webhook HMAC), and treated as untrusted. Datastore and bus connections support TLS in transit (default-on in multi-tenant/regulated profiles). Outbound fetches validate certificates (never disabled). When a secure channel, credential, or required signature is missing, fail closed.

## 8. Quality bar (every change to the repo)

Any change is complete only when: it compiles and is `gofmt`/`golangci-lint` clean (Python: `ruff`/`black`); unit + relevant integration tests pass in CI; the OpenAPI spec and `docs/` are updated; any DB change ships an idempotent migration; new config keys are documented; the feature emits logs/metrics (probectl observes probectl); the guardrails (§7) hold; and commits are conventional. No undocumented API routes.

Two standing CI gates beyond the per-change checks:

1. **Surface coverage** — every user-facing capability has a surface: native (design system) / federated (Grafana–OTLP) / none-by-design. A capability with no declared surface fails the gate.
2. **Cross-plane correlation** — inject a known multi-plane fault and assert it surfaces as **one correlated, fully tenant-scoped incident** with cross-plane evidence. A red gate fails the build even when unit tests are green.

## 9. Operating model (working with Claude / Cowork)

- **Read first:** this file + the PRD.
- **Smallest coherent change.** Prefer the minimal change that satisfies the task; note necessary out-of-scope work as a follow-up rather than silently expanding.
- **Plan → implement → test → document → PR.**
- **Ask before:** changing an architecture/stack decision (§4), touching a guardrail (§7), or adding an external dependency or data source. Default to the established convention.
- **No scope creep into security-product territory:** TLS/cert + threat-intel enrichment + confidence-scored detections are *signals* — never an IPS/SIEM/full-NDR.

## 10. Deliberate non-goals

By design, probectl is **not**: a vendor-operated first-party public SaaS (the multi-tenant *capability* exists for partners/MSPs to self-host and resell; a probectl-hosted SaaS is not offered); an APM/distributed-tracing replacement; a SIEM/log-analytics platform or an inline IPS; an owner of a global cloud-agent/BGP fleet. It does not perform un-gated autonomous remediation (§7.8) and never phones home by default (§7.2). See PRD v1.0 §7.

## 11. References

- Product spec: `probectl-PRD-v1.0.md` (delivered + remaining; `probectl-PRD-v0.5.md` frozen as the pre-build contract)
- Editions model: `docs/editions.md` · Config: `docs/configuration.md`
- Architecture deep-dives, runbooks, isolation, scale-gate, perf-baseline: `docs/`
- Sibling product: `trustctl` (control-plane + agents, MCP, lifecycle).
