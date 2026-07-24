# CLAUDE.md — probectl

*Engineering reference for the probectl codebase and contract. The PRD (`probectl-PRD-v1.0.md`) is the product contract — if they conflict, flag it, don't guess. All responses: deeply technical, ELI5 format.*

## 0. Non-negotiables (full text §7)

- **Tenant isolation is the outermost boundary.** Every path scoped by `tenant_id` at the storage/query layer (RLS/partition/silo), never handler code alone. Isolation test accompanies any data-path change. AI/MCP: tenant first, then RBAC. In doubt → fail closed. [§7.1]
- **No phone-home, ever.** License verify is offline math; open-data is read-only + cached + degrades gracefully. [§7.2]
- **Crypto only through `internal/crypto`** (FIPS-swappable). [§7.3]
- **TLS on every listener; mTLS agent↔control-plane; ingestion authenticated, tenant-scoped, signature-verified, untrusted; missing channel/credential/signature → fail closed.** [§7.4, §7.12]
- **Remediation observe-only/human-gated; detection is a signal, never an IPS.** [§7.8–9]
- **Editions:** commercial code only in `ee/`; core never imports `ee/` (CI-guarded); tier checks live in `internal/license` only, gated at the `main.go` `Build*` seams only. [§2]

**Ask before:** changing an architecture/stack decision, touching a guardrail, or adding a dependency/data source — except work pre-authorized by the harness backlog (§11). Smallest coherent change always.

## 1. What probectl is

Self-hosted, open-core, **multi-tenant** network observability: five planes — active/synthetic, BGP/routing, flow, device telemetry, eBPF host/L7 — on an OTel-native control plane, with cited cross-plane AI RCA, a TLS/NDR-lite threat layer (signals, never an IPS), change-aware topology, and cost/SLO intelligence. Open-data enriched; **telemetry never leaves the operator's network**. Two modes, one codebase: sovereign single-tenant (deployment = tenant boundary, air-gap capable) and MSP-hosted multi-tenant — single-tenant is the one-tenant case, no separate code path. Solo founder + AI agents. Sibling: `trustctl` (cert/NHI lifecycle; same patterns; receives TLS findings).

## 2. Editions & business model (decision of record 2026-07-14)

- **Core = MPL-2.0**, free and open source. Commercial code only under **`ee/`** (commercial license; fence is license + trademark, not source secrecy). One repo, no edition branches; `ee/` imports core, **core never imports `ee/`** (CI: `make editions-gate`); core-only build (`-tags probectl_core`) stays green with `ee/` inert.
- **Gating:** offline **Ed25519-signed license files** verified against baked public keys — never phone-home. One feature→tier table (`internal/license` `tierFeatures`), wired only at `main.go` `Build*` seams. Unlicensed = hidden, not lockware (Admin → Editions is the one visibility point). Expiry → 30-day grace → commercial features go **read-only**; telemetry pipelines never break.
- **Enterprise (self-host): flat rate.** Opens all `ee/` gates for that deployment — the customer bears its own hosting costs.
- **MSP: consumption-based.** The MSP self-hosts and **resells the service under the probectl banner**; its license opens the `ee/` gates for every tenant it hosts. The MSP sets its own customer pricing (consumption tool). probectl↔MSP consumption reporting is **export-based usage metering** — never phone-home. Provider plane + metering are MSP-tier only (self-hosters don't resell).
- **No white-label — removed by design.** Theming is deployment-level design tokens; tenants see probectl branding; the always-visible tenant indicator and the visually-separate provider console remain.
- Core keeps (deliberately free): per-tenant export/verifiable deletion, fairness enforcement, support-bundle generation.

## 3. Architecture (the shape)

Tenant-bound **agents** (Go single binary, compiled-in canary plugins; mTLS + SPIFFE identity from enrollment — tenant comes from the cert, never the payload) → **bus** (Kafka default; NATS/direct lightweight mode; `probectl.<type>.results|events`, Protobuf in `proto/`, tenant-tagged pooled or topic-namespaced siloed) → **control plane** (Go; stateless request path; REST `/v1` OpenAPI 3.1 · gRPC agents · MCP · webhooks/OTLP; SSO/SCIM/RBAC/ABAC; hash-chained audit + separate provider stream) → **stores**: Postgres (state; pooled = FORCE-RLS on `tenant_id`, siloed = per-schema/DB), ClickHouse (events; `tenant_id` in partition key), Prometheus/VictoriaMetrics (tenant label), object store (per-tenant prefix). Python **BGP analyzer** (structlog) bridges RouteViews/RIS/RPKI → `probectl.bgp.events`. **AI/MCP** query the same stores tenant-FIRST then RBAC; consumers correlate cross-plane signals into one tenant-scoped incident. **Provider plane** = separate privilege domain: cross-tenant operations, never silent data access; break-glass is explicit, time-bounded, separately audited. External feeds ingested once (shared), scoped per tenant. Isolation pooled/siloed/hybrid, selectable per deployment AND per tenant.

## 4. Stack

Go control plane + agents (static, `linux/amd64|arm64`) · Python analyzer · eBPF via `cilium/ebpf` (CO-RE, observe-only, digest-verified objects) · gRPC bidi mTLS + Protobuf · OTel-native schema (OTLP ingest/export; tenant as resource attribute) · AI adapters: builtin deterministic (air-gapped default), Ollama, OpenAI-compatible (covers Azure OpenAI/vLLM), Anthropic — remote egress consent-gated + redacted · web/: React, design tokens only (no hardcoded values), WCAG 2.2 AA CI gate, command palette, dark-native, tenant indicator always visible · packaging: multi-arch Docker, hardened HTTPS-by-default Helm + compose, air-gap bundle, Terraform.

## 5. Layout

```
cmd/        probectl-control · probectl-agent · probectl-ebpf-agent · probectl-endpoint ·
            probectl-flow-agent · probectl-device-agent · probectl-bmp-listener ·
            probectl-cloud-metrics · probectl-license · probectl-sdkgen · probectl (CLI, web-parity)
internal/   control (API) · tenancy · agent · canary · path · bgp · ebpf · flow · device ·
            opendata · threat · change · topology · cost · slo · compliance · ai (query/RCA/MCP) ·
            crypto (the only crypto door) · auth · audit · store · bus · otel · license · fairness ·
            lifecycle/tenantlife · branding (deployment theming) · support · perf
ee/         provider · billing (metering) · silo · tenantkeys (BYOK) · remediation · governance
analyzer/   Python BGP · proto/ schemas · migrations/ (sequential, idempotent) · web/ frontend
deploy/     helm · compose · terraform · backup · packaging | docs/ · test/ (real-stack integration)
../harness/ self-driving remediation program — OUTSIDE the repo, at the workspace root (§11)
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
- **Licensing headers:** new core files carry MPL-2.0 (Exhibit A/SPDX); new `ee/` files carry the commercial header.

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

## 11. Remediation harness (standing program)

`../harness/` (a sibling of this repo at the workspace root — deliberately outside the repo so program state never ships with the product) = the self-driving GA/F500 program: `HARNESS.md` (loop + rules), `backlog.json` (state; lanes W/H/L/E/X; sealed `policy` block — agents may not edit policy or weaken the E8 end gate), `harness.sh` (helpers; `serve` hosts the board), `tracker.html` (live read-only tracker over the backlog), `UX_SEED.md` (competitive rubric seed). "Continue the remediation harness" ⇒ start at `../harness/HARNESS.md`. Backlog `pre_authorized` items satisfy §0's "ask before" rule; §7 holds at full autonomy. Business decisions of record live in `backlog.json` `policy.business_model` (MPL-2.0 core; enterprise flat self-host; MSP consumption resale, probectl banner; no white-label).

## 12. References

PRD: `probectl-PRD-v1.0.md` (v0.5 frozen) · editions: `docs/editions.md` · config: `docs/configuration.md` · runbooks/architecture/compliance: `docs/` · audit report: `../probectl-design-feature-audit-2026-07-14.html` · sibling: `trustctl`.
