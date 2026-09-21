# CLAUDE.md — probectl

*Engineering reference for the probectl codebase and contract. `probectl-PRD-v1.1.md` is the current steering contract; `probectl-PRD-v1.0.md` remains the detailed feature/evidence inventory. If they conflict, flag it, don't guess. All responses: deeply technical, ELI5 format.*

## 0. Non-negotiables (full text §7)

- **Tenant isolation is the outermost boundary.** Every path scoped by `tenant_id` at the storage/query layer (RLS/partition/silo), never handler code alone. Isolation test accompanies any data-path change. AI/MCP: tenant first, then RBAC. In doubt → fail closed. [§7.1]
- **No phone-home, ever.** License verify is offline math; open-data is read-only + cached + degrades gracefully. [§7.2]
- **Crypto only through `internal/crypto`** (FIPS-swappable). [§7.3]
- **TLS on every listener; mTLS agent↔control-plane; ingestion authenticated, tenant-scoped, signature-verified, untrusted; missing channel/credential/signature → fail closed.** [§7.4, §7.12]
- **Remediation observe-only/human-gated; detection is a signal, never an IPS.** [§7.8–9]
- **Editions:** commercial code only in `ee/`; core never imports `ee/` (CI-guarded); tier checks live in `internal/license` only, gated at the `main.go` `Build*` seams only. [§2]

**Ask before:** changing an architecture/stack decision, touching a guardrail, or adding a dependency/data source. A backlog item is not permission to relax §7. Smallest coherent change always.

## 1. What probectl is

Self-hosted, source-available, **multi-tenant** network observability: five planes — active/synthetic, BGP/routing, flow, device telemetry, eBPF host/L7 — on an OTel-native control plane, with cited cross-plane AI RCA, a TLS/NDR-lite threat layer (signals, never an IPS), change-aware topology, and cost/SLO intelligence. Open-data enriched; **telemetry never leaves the operator's network**. Two modes, one codebase: sovereign single-tenant (deployment = tenant boundary, air-gap capable) and MSP-hosted multi-tenant — single-tenant is the one-tenant case, no separate code path. Solo founder + AI agents. Sibling: `trustctl` (cert/NHI lifecycle; same patterns; receives TLS findings).

## 2. Editions & business model (decision of record 2026-07-14)

- **Core = BUSL-1.1** (source-available; production use permitted under the Additional Use Grant; each version converts to MPL-2.0 four years after publication). **`pkg/`, `proto/` and `examples/` = MPL-2.0** so clients and other implementations can embed them freely. Commercial code only under **`ee/`** (commercial license; fence is license + trademark, not source secrecy). One repo, no edition branches; `ee/` imports core, **core never imports `ee/`** (CI: `make editions-gate`); core-only build (`-tags probectl_core`) stays green with `ee/` inert.
- **Gating:** offline **Ed25519-signed license files** verified against baked public keys — never phone-home. One feature→tier table (`internal/license` `tierFeatures`), wired only at `main.go` `Build*` seams. Unlicensed = hidden, not lockware (Admin → Editions is the one visibility point). Expiry → 30-day grace → commercial features go **read-only**; telemetry pipelines never break.
- **Enterprise (self-host).** Opens all `ee/` gates for that deployment — the customer bears its own hosting costs.
- **MSP.** The MSP self-hosts and **resells the service under the probectl banner**; its license opens the `ee/` gates for every tenant it hosts. The MSP sets its own customer pricing. probectl↔MSP usage reporting is **export-based usage metering** — never phone-home. Provider plane + metering are MSP-tier only (self-hosters don't resell).
- **No published pricing.** No price list or pricing model is published anywhere in the repo or on the website; commercial terms are set per agreement. `pricing_model` in the license file is a reserved, informational field.
- **No white-label — removed by design.** Theming is deployment-level design tokens; tenants see probectl branding; the always-visible tenant indicator and the visually-separate provider console remain.
- Core keeps (deliberately free): per-tenant export/verifiable deletion, fairness enforcement, support-bundle generation.

## 3. Architecture (the shape)

Tenant-bound **agents** (Go single binary, compiled-in canary plugins; mTLS + SPIFFE identity from enrollment — tenant comes from the cert, never the payload) → **bus** (Kafka default at scale; NATS+JetStream as the DURABLE lightweight mode for small deployments; an in-process `memory` transport that is VOLATILE and for development only — the two are named apart on purpose, DPR-119; `probectl.<type>.results|events`, Protobuf in `proto/`, tenant-tagged pooled or topic-namespaced siloed) → **control plane** (Go; stateless request path; REST `/v1` OpenAPI 3.1 · gRPC agents · MCP · webhooks/OTLP; SSO/SCIM/RBAC/ABAC; hash-chained audit + separate provider stream) → **stores**: Postgres (state; pooled = FORCE-RLS on `tenant_id`, siloed = per-schema/DB), ClickHouse (events; `tenant_id` in partition key), Prometheus/VictoriaMetrics (tenant label), object store (per-tenant prefix). Python **BGP analyzer** (structlog) bridges RouteViews/RIS/RPKI → `probectl.bgp.events`. **AI/MCP** query the same stores tenant-FIRST then RBAC; consumers correlate cross-plane signals into one tenant-scoped incident. **Provider plane** = separate privilege domain: cross-tenant operations, never silent data access; break-glass is explicit, time-bounded, separately audited. Open-data/threat feeds ingested once (shared), scoped per tenant; BGP collector ingest runs per tenant (scaling boundary recorded in `docs/adr/bgp-ingest-model.md`). Isolation pooled/siloed/hybrid, selectable per deployment AND per tenant.

## 4. Stack

Go control plane + agents (static, `linux/amd64|arm64`) · Python analyzer · eBPF via `github.com/cilium/ebpf` (CO-RE, observe-only, digest-verified objects) · gRPC bidi mTLS + Protobuf · OTel-native schema (OTLP ingest/export; tenant as resource attribute) · AI adapters: builtin deterministic (air-gapped default), Ollama, OpenAI-compatible (covers Azure OpenAI/vLLM), Anthropic — remote egress consent-gated + redacted · web/: React, design tokens only (no hardcoded values), WCAG 2.2 AA CI gate, command palette, dark-native, tenant indicator always visible · packaging: multi-arch Docker, hardened HTTPS-by-default Helm + compose, air-gap bundle, Terraform.

## 5. Layout

```
cmd/        probectl-control · probectl-agent · probectl-ebpf-agent · probectl-endpoint ·
            probectl-flow-agent · probectl-device-agent · probectl-bmp-listener ·
            probectl-cloud-metrics · probectl-license · probectl-sdkgen ·
            probectl-scorecard ·
            probectl-workflow-policy · probectl-chaos-dependency-drill ·
            probectl-delivery-audit (repository-only independent auditor) ·
            probectl-deadseams (zero-call-site gate) ·
            terraform-provider-probectl · probectl (CLI, web-parity)
internal/   a2a (agent-to-agent measurement broker) · agent (canary-plugin agent runtime) ·
            agentlabel (placement-metadata validation) · agenttransport (agent gRPC lane, tenant-verifying) ·
            ai (AI query/RCA/MCP + egress gate) · alert (alerting engine) ·
            anomaly (tenant-scoped anomaly models) · apierror (domain error vocabulary) ·
            audit (immutable audit log + WORM) · auth (OIDC SSO, RBAC/ABAC) ·
            backup (at-rest backup encryption) · bakeoff (buyer comparison scorecards) ·
            bgp (BGP bridge to control plane) ·
            branding (deployment theming) · breaker (storage-client circuit breaker) ·
            browser (browser/transaction synthetics) · browsercanary (browser engine as canary plugin) ·
            bus (Kafka, NATS/JetStream durable-lightweight, and in-process volatile transports) · canary (canary plugin interface) ·
            carbon (carbon/power observability) · change (change ingest + incident correlation) ·
            chaos (local test-only fault injector) · cipolicy (CI/workflow policy tests) ·
            cli (probectl CLI) · cloudmetrics (cloud metric importers) ·
            cluster (multi-region HA) · cmdb (CMDB correlation) ·
            compliance (segmentation validation + evidence) ·
            completeness (capability/surface completeness contract) · config (config load/validate) ·
            configschema (config YAML schema helpers) · control (HTTP API server) ·
            cost (FinOps/egress cost engine) · crypto (the only crypto door) ·
            deliveryaudit (independent signed delivery evidence) ·
            device (SNMP/device telemetry plane) · docslint (doc-accuracy tests) ·
            ebpf (eBPF host agent) · endpoint (endpoint/DEM agent) ·
            evidence (signed offline incident packages) ·
            enroll (agent trust root/enrollment) · fairness (per-tenant admission fairness) ·
            flow (NetFlow/sFlow/IPFIX plane) · gen (generated code: protobuf/gNMI/prometheus) ·
            govern (data-governance core) · httpbody (bounded HTTP body readers) ·
            i18n (server/CLI message catalog) · incident (cross-plane incident correlation) ·
            ingesthealth (payload-free ingest observability) · inventory (operator-list primitives) ·
            license (offline edition gating) · lifecycle (zero-downtime upgrade) ·
            logging (structured slog setup) · metrics (self-observability) ·
            notify (on-call/notification wiring) · objectstore (per-tenant blob store) ·
            opendata (open-data enrichment) · otel (OTel semconv mapping) ·
            outage (collective outage view) · path (ECMP/MPLS path discovery) ·
            perf (load/perf harness) · pipeline (bus-to-store result pipeline, tenant-verifying) ·
            preflight (deployment self-check) · promapi (Prometheus-compatible surfaces) ·
            redactpat (shared secret/PII recognition patterns) ·
            remediation (core guarded-remediation seam) · reporting (tenant report artifacts) ·
            rum (real-user monitoring) · schema (offline schema lints) ·
            scim (SCIM 2.0 provisioning) · secrets (secret-backend integration) ·
            siem (SIEM export) · slo (OpenSLO engine) ·
            store (tenant-scoped datastore adapters) · support (support bundles/health) ·
            tenancy (tenant boundary: fences + posture) · tenantcrypto (per-tenant at-rest crypto seam) ·
            tenantlife (tenant lifecycle: export/erasure) · terraformprovider (Terraform provider core) ·
            testspec (synthetic-test schema) · testsupport (shared test helpers, fail-closed skips) ·
            testsync (signed pull-based test distribution) · threat (TLS/NDR-lite threat signals) ·
            topology (versioned topology + what-if) · usage (core metering seam) ·
            version (build metadata) · webui (embedded web UI) ·
            wire (bounded reader for untrusted wire input)
ee/         billing (metering/usage export) · cmd (commercial offline CLIs) ·
            governance (ee governance workflows) · pricing (offline TCO model; no license prices) ·
            provider (provider/management plane) · remediation (guarded remediation workflow) ·
            silo (siloed/hybrid isolation) · tenantkeys (BYOK) · web (embedded provider-console assets)
analyzer/   Python BGP · proto/ schemas · migrations/ (sequential, idempotent) · web/ frontend
deploy/     helm · compose · terraform · backup · packaging | docs/ · test/ (real-stack integration)
../design-partner-readiness/  the one live agent programme — OUTSIDE the repo, at the workspace root (§11)
```

## 6. Conventions

- **Tenancy:** every tenant-owned table has non-null `tenant_id` + index/partition from its first migration; every query/bus message/metric/object key tenant-scoped at the storage layer.
- **Errors:** services return domain errors; handlers map to HTTP. Probe failures = `success:false`, never panic in production paths.
- **Logging:** Go `slog` / Python `structlog`, structured, `tenant_id` where applicable; no `fmt.Printf`; never log secrets or another tenant's data.
- **Config:** control plane `PROBECTL_*` env; agent YAML/env; every key documented in `docs/configuration.md`.
- **Migrations:** sequential, idempotent (`IF NOT EXISTS`/`ON CONFLICT`), zero-downtime (expand/contract).
- **Bus:** `probectl.<type>.results|events`, Protobuf, schemas in `proto/`.
- **API:** OpenAPI 3.1 `/v1`, spec updated in the same PR as the handler; no undocumented routes; lifecycle/deprecation via `x-probectl-lifecycle`.
- **Testing:** table-driven; `httptest` handlers; integration on the real `test/` stack; recorded fixtures for BGP/eBPF.
- **Commits:** Conventional Commits.
- **Editions:** tier checks only in `internal/license` at `Build*` seams; unlicensed hidden except Admin → Editions.
- **UI:** design tokens + component library only — never hardcode color/spacing/type/radius/motion; WCAG 2.2 AA gate green; tenant indicator visible; no third-party/phoning-home assets.
- **Telemetry:** new signals map to OTel semantic conventions from first emission.
- **Licensing headers:** new core files carry BUSL-1.1 (SPDX + the BSL notice); new `pkg/`, `proto/` and `examples/` files carry MPL-2.0 (SPDX + Exhibit A); new `ee/` files carry the commercial header.

## 7. Guardrails (non-negotiable; a task requiring a violation → stop, ask)

1. **Tenant isolation outermost** (catastrophic if broken): storage-layer enforcement above RBAC; isolation test with every data-path change; CI isolation suite; AI/MCP tenant-then-RBAC; provider operators get no implicit telemetry read — only explicit, time-bounded, consented, separately-audited break-glass; fail closed.
2. **No phone-home:** no default outbound telemetry/beacons/update-checks; adoption metrics opt-in/download-proxy only; consumption reporting export-based.
3. **Crypto via `internal/crypto` only** (FIPS 140-3 swappable; per-tenant keys/BYOK build on it).
4. **mTLS agent↔control-plane** (SPIFFE-style, tenant-bound); no plaintext agent transport.
5. **Tenant boundary + RBAC/ABAC on every path** — including AI answers and MCP tools.
6. **Secrets:** never hardcoded/logged/in URLs or git; envelope encryption at rest; no plaintext private keys server-side.
7. **Audit everything:** immutable tamper-evident tenant streams; separate provider/break-glass stream.
8. **Remediation observe-only/human-gated:** explicit approval, dry-run, blast-radius limits, tenant+RBAC scoped, fully audited; never un-gated autonomous action.
9. **Detection is a signal, not an IPS:** confidence-scored, tunable, suppressible, SIEM-exported; never inline blocking.
10. **Open-data/threat-intel:** read-only, ingest-once-then-scope, cached, graceful-degrade; TLS validated (never disabled); fetched content untrusted; per-source AUP/provenance tracked.
11. **No browser storage** beyond design; UI usable without third-party calls.
12. **TLS on every listener (1.2+, prefer 1.3); HTTPS-by-default deploys (HSTS, CSP, secure cookies); every ingest surface authenticated, tenant-scoped, signature-verified where senders sign, untrusted; datastore/bus TLS in transit; outbound validates certs; missing channel/credential/signature → fail closed.**

## 8. Quality bar (every change)

Compiles; `gofmt`/`golangci-lint`/`ruff` clean; unit + relevant integration tests pass; OpenAPI + docs + idempotent migration in the same change; config keys documented; emits logs/metrics (probectl observes probectl); guardrails hold; conventional commit. Standing gates: **surface coverage** (every capability declares native/federated/none-by-design) and **cross-plane correlation** (injected multi-plane fault → exactly one tenant-scoped incident).

## 9. Operating model

Read this file + PRD first. Plan → implement → test → document → PR. Smallest coherent change; out-of-scope work becomes a follow-up task, never silent expansion. No scope creep into IPS/SIEM/full-NDR territory — TLS/cert + threat-intel + detections stay signals.

## 10. Non-goals (binding)

Not a vendor-operated public SaaS (multi-tenancy exists for MSP/partner self-hosting); not an APM/tracing replacement; not a SIEM/log platform; not an inline IPS/full NDR; no global first-party agent/BGP fleet; no un-gated remediation; no phone-home; **no white-label/OEM rebranding** — MSPs resell under the probectl banner.

## 11. The live programme

`../design-partner-readiness/` is the ONE live agent programme (started
2026-09-16). It lives outside the repository so product releases never ship
planning state. Start at `../design-partner-readiness/PLAN.md` (plan of record
and every decision of record, which wins over defaults in this file), then
`../design-partner-readiness/RUN_PROMPT.md` (the autonomous run),
`../design-partner-readiness/FINDINGS.md` with its
`../design-partner-readiness/findings.json` (the ledger),
`../design-partner-readiness/journeys/` (per-journey checkpoints),
`../design-partner-readiness/connectors.md` (real vs simulated vs blocked) and
`../design-partner-readiness/decisions-needed.md` (the only list kept for the
owner). Standing rules of that programme: fix everything found — no backlog —
§7 guardrails never relaxed, commit on `main` as Shankar, never push, only this
repository is in scope.

Predecessor programmes are RETIRED, read-only reference and must not be worked:
the 2026-08-08 comprehensive backlog (`../probectl-comprehensive-backlog-2026-08-08.html`),
the completeness loop, the audit harness and the red-team loop. Neither a
foundation-loop directory nor a root backlog file exists any more; both were
named here after they stopped existing, which is how a fresh agent ended up
pointed at nothing.
The retired harness's parked proofs E2/E3/E4/L4 live in `probectl-PRD-v1.1.md`
§4. Business decisions of record live in §2 of this file (decision of record
2026-07-14).

## 12. References

Current steering contract: `probectl-PRD-v1.1.md` · detailed feature/evidence inventory: `probectl-PRD-v1.0.md` · editions: `docs/editions.md` · config: `docs/configuration.md` · runbooks/architecture/compliance: `docs/` · sibling: `trustctl`.
