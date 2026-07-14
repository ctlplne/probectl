# probectl — Product Requirements Document (v1.0, post-MVP delivery pass)

| | |
|---|---|
| **Product** | probectl |
| **Owner** | Shankar (solo founder) |
| **Status** | v1.0 — code-backed delivery inventory plus remaining GA evidence debt; current green proof requires fresh gate receipts on the exact commit |
| **Last Updated** | July 1, 2026 |
| **License** | Source-available; legal texts are the top remaining item (§5.3) — `LICENSE` is a placeholder pending counsel |
| **Supersedes** | `probectl-PRD-v0.5.md` (frozen as the historical pre-build contract; section map in §10) |

> **One-sentence vision (unchanged, now built):** probectl is a self-hosted, source-available, **multi-tenant** network observability platform that unifies active/synthetic testing, BGP/routing intelligence, flow analytics, device telemetry, and eBPF host visibility into a single OpenTelemetry-aligned control plane — with an AI assistant that performs cited cross-plane root-cause analysis, a native security/threat layer, change-aware topology, and cost/SLO intelligence, enriched by public internet + threat-intel data — deployable as a sovereign single-tenant install *or* operated by an MSP that resells hard-isolated, white-labeled tenants, with telemetry never leaving the operator's network.

> **How to read this document.** v0.5 was a promise written before the build; v1.0 is an inventory written after it. Every "delivered" claim carries an evidence pointer — a repo path, a CI gate, or a diligence-register ID (`U-xxx`, from `probectl-audit/outputs/00-UNIFIED-REGISTER.html`). After the July 1, 2026 audit harness run, read those pointers as **code-backed evidence targets**, not as a blanket current-green claim: coverage, integration, isolation, and e2e proof are current only when the named gates have rerun green on the exact commit. Items whose code exists but whose *evidence* is still provisional (e.g. load numbers on real iron, or a red/unknown gate receipt) are listed as remaining or evidence debt, not buyer-facing GA proof. §2–§4 are the diligence read; §5 is the steering read.

**Status legend:** ✅ delivered (code + CI evidence) · 🔶 partial (built; evidence, validation, or a named slice pending) · ⏳ remaining · ⛔ not started (deliberate).

---

## 1. What probectl is

A **self-hosted, source-available, multi-tenant network observability platform**, built in private by a solo founder + AI agents, to an acquirable, Fortune-500-procurable bar. Two operating modes, one codebase: **sovereign single-tenant** (the deployment is the tenant boundary; air-gap capable) and **multi-tenant / provider** (an MSP self-hosts once and resells hard-isolated, white-labeled tenants). The single-tenant install is the one-tenant case — there is no separate code path.

**The moat as built** (each item now has running code behind it, per §2):
1. **Sovereign by construction** — no phone-home, air-gapped AI default, open data fetched read-only and cached, everything self-hosted.
2. **Multi-tenant by construction** — `tenant_id` as the outermost scope on every record/agent/query/metric/event/object; pooled isolation enforced at the storage layer (Postgres RLS + ClickHouse scoping), siloed/hybrid models, a separately-privileged provider plane with audited break-glass, per-tenant metering/branding/keys/erasure — all CI-gated.
3. **Five planes, one pane** — active/synthetic + BGP/routing + flow + device + eBPF host/L7, correlated into single tenant-scoped incidents (a CI gate injects a multi-plane fault and asserts one correlated incident).
4. **AI-native, grounded, honest** — cited RCA over a tenant-then-RBAC semantic query layer; deterministic air-gapped default model; remote models gated on recorded consent + redaction; a scored eval harness; citation integrity enforced in code.
5. **Security-native** — TLS/cert posture, NDR-lite confidence-scored detections, threat-intel enrichment — signals and SIEM export, never an IPS.
6. **Change-aware** — change ingestion (webhook HMAC-verified), change-to-incident correlation, a versioned topology graph feeding RCA and what-if.
7. **Enterprise trust** — SSO/SCIM/RBAC/ABAC, tamper-evident audit with WORM export, envelope crypto behind a FIPS-swappable seam, editions/licensing enforced offline.

**Audience** (unchanged from v0.5 §3 — personas P1–P7 carried as written): regulated/sovereign F500 platform, network, and security teams; MSPs reselling managed observability; the self-hosting OSS community at public launch.

---

## 2. What shipped — code-backed delivery inventory

Everything in this section is backed by code in the repo and a named evidence path. A row counts as current GA proof only after its cited gate is green on the exact commit under review; otherwise it remains code-backed inventory plus remediation evidence debt. Pointers are `repo paths` · *CI jobs* · U-IDs.

### 2.1 The five planes

- ✅ **Active/synthetic (plane 1).** Single-binary multi-arch canary agent with compiled-in plugins — ICMP/TCP/UDP/HTTP(S)/DNS (incl. DNSSEC + trace), voice/RTP (MOS), agent-to-agent tests brokered by the control plane, store-and-forward, SSRF-guarded targets (U-022). `cmd/probectl-agent`, `internal/canary`, `internal/agent` · *test-go, integration*.
- ✅ **Path visualization (the hero).** ECMP-aware (Paris-style) path engine, ICMP/TCP/UDP modes, MPLS detection, per-hop loss/latency, merged multi-path topology. `internal/path` (incl. fuzzed parsers) · *test-go, fuzz-smoke*.
- ✅ **BGP/routing (plane 2).** Python analyzer (RouteViews/RIS MRT + RIS Live; hijack/origin-change/withdrawal/leak heuristics; RPKI validation, degrade-to-unknown) bridged to Go (`probectl.bgp.events`). `analyzer/` (94% coverage, 85% floor — U-094), `internal/bgp` (fuzzed ingest) · *test-python, fuzz-smoke*.
- ✅ **Flow analytics (plane 3).** NetFlow v5/v9, IPFIX, sFlow collectors → ClickHouse; top-talkers; cardinality caps per agent/tenant (U-026). `internal/flow` (one fuzzed decode entry point covers all four wire formats — U-082), `cmd/probectl-flow-agent`, `internal/store/flowstore` · *test-go, cross-tenant-isolation*.
- ✅ **Device telemetry (plane 4).** SNMP v2c/v3 polling (interfaces, sensors, inventory) + gNMI streaming; secrets via a credential-source seam (Vault-pluggable). `internal/device` (fuzzed against hostile PDUs), `cmd/probectl-device-agent`, `internal/secrets` · *test-go, fuzz-smoke*.
- ✅ **eBPF host/L7 (plane 5).** IPv4/IPv6 CO-RE L4 flow capture (tracepoint, observe-only — a CI guard test forbids enforcement hooks), service map, L7/TLS capture via TLS-library uprobes (OpenSSL-compatible + GnuTLS; default-off, consent-gated, redacted — U-018/C13), embedded-object digest verification before any kernel load (U-014), ring-buffer sizing from config (U-050), kernel-lockdown detection with explicit degradation (U-075), unsupported non-IPv4/IPv6 family counter (`filtered_non_ipv4_total`, legacy name; U-073). `internal/ebpf`, `cmd/probectl-ebpf-agent` · *ebpf-kernel-matrix (real kernels under QEMU — U-021), observe-only gate*.

### 2.2 Cross-plane intelligence

- ✅ **Unified incidents.** Cross-plane signals correlate into one tenant-scoped incident with a timeline; a standing CI gate injects a known multi-plane fault and asserts exactly one correlated, fully tenant-scoped incident. `internal/incident`, `internal/pipeline` · *integration (correlation gate)*.
- ✅ **Topology graph.** Telemetry-fed, versioned, tenant-keyed; rebuild-on-restart by design (ADR `docs/adr/volatile-stores.md`, U-047) with cold-start tests. `internal/topology`.
- ✅ **Change intelligence.** Git/CI/deploy webhook ingestion (HMAC-verified, treated as untrusted), change timeline, change-to-incident candidates, feeds RCA. `internal/change`, `docs/change-intel.md`.
- ✅ **AI RCA + NL query.** Deterministic planner → tenant-first-then-RBAC semantic query engine → synthesis → **citation-integrity grounding** (a finding citing nonexistent evidence is dropped). Air-gapped builtin model is the default; Ollama/OpenAI/Anthropic adapters are gated on per-tenant recorded egress consent + audit + PII redaction (U-013/C7/C8); prompt-injection hardening with non-guessable evidence IDs (U-037/D9); process-wide concurrency backstop (U-048); per-domain evidence field allow-list (U-092); optional persisted answer artifacts with retention for disputes (U-093). `internal/ai` · *test-go, rca-eval*.
- ✅ **RCA quality eval.** 24 labeled scenarios across planes, scoring answer accuracy / citation precision / honesty (negative control must yield "insufficient evidence"); builtin baseline 0.91/0.92/pass; the blocking CI job enforces 0.85/0.85 floors and uploads the score artifact (U-049). `internal/ai/eval` · *rca-eval*.
- ✅ **MCP server.** Tenant- + RBAC-scoped tools over the same query boundary; hashed tokens with RLS-backed storage (U-091). `internal/ai/mcp`, `internal/store/mcptokens.go`.
- ✅ **AI test authoring + auto-discovery.** NL → canary config; heuristic by default, model-backed when configured. `internal/ai/author`, `docs/ai-authoring.md`.

### 2.3 Security & threat layer

- ✅ **TLS/cert observability.** Expiry/chain/issuer/SAN, protocol/cipher posture, CT-log correlation, trustctl handoff. `internal/threat`, `docs/tls-observability.md`.
- ✅ **NDR-lite detections.** DNS exfil/DGA, beaconing, egress anomalies, bad-ASN/Tor, segmentation violations — confidence-scored, tunable, suppressible, exported to SIEM; **a signal, never an IPS** (guardrail §7.9). Forensic copy persisted with incidents (U-047). `internal/threat`.
- ✅ **Threat-intel enrichment.** Open feeds ingested once (shared), scoped per tenant, cached, graceful-degrade, per-source AUP/provenance tracked (`docs/opendata-aup.md` — the commercial-resale AUP matrix is a counsel item, §5.3). `internal/opendata`.

### 2.4 Cost, SLO, compliance, DEM

- ✅ **FinOps/egress cost.** Flow + cloud pricing → per-service/flow cost, cross-AZ/region detection. `internal/cost`, `docs/finops.md`.
- ✅ **SLO engine.** OpenSLO-compatible SLI/SLO, error budgets, burn rates. `internal/slo`.
- ✅ **Segmentation validation.** Declared policy vs observed eBPF/flow traffic; exportable evidence. `internal/compliance`, `docs/compliance.md`.
- ✅ **RUM + endpoint DEM.** Browser beacons (consent-gated, redacted, fuzzed parser — U-082) and the endpoint agent (Linux/macOS/Windows builds in CI). `internal/rum`, `internal/endpoint`, `cmd/probectl-endpoint`.
- ✅ **Browser/transaction synthetic.** Playwright worker, real-browser smoke in CI. `browser-worker/`, `internal/browser` · *browser-worker*.
- ✅ **Outage view, chaos, carbon.** Collective outage signals (`internal/outage`); fault injection with SLO-catch validation (`internal/chaos`); Kepler-style power/carbon (`internal/carbon`).

### 2.5 Tenancy & the provider plane

- ✅ **Hard tenant isolation (the foundation).** `tenant_id` outermost on every entity from its first migration; Postgres RLS (FORCE) + ClickHouse row policies + per-tenant TSDB scoping + object prefixes; tenant context propagated API → bus → storage → AI; **the AI/MCP layer enforces tenant first, then RBAC**; agents are tenant-bound via SPIFFE identity in their mTLS cert, never the request body. `internal/tenancy`, `migrations/` · ***cross-tenant-isolation* (a dedicated CI suite, incl. ClickHouse — U-025/D5) — the highest-severity invariant has its own standing gate.**
- ✅ **Isolation models.** Pooled / siloed / hybrid, selectable per deployment **and per tenant**; registry-driven silo router (fail-closed, stale-cap 1×TTL — U-090); per-tenant residency targeting (documented honestly for pooled mode — U-042). `ee/silo`, `docs/isolation.md`.
- ✅ **Provider/MSP plane.** Tenant lifecycle (provision/suspend/offboard), fleet-across-tenants, **no implicit telemetry access** — break-glass is explicit, time-bounded, tenant-consented, separately audited. `ee/provider`, `internal/tenantlife`, `docs/provider-plane.md`.
- ✅ **Metering/billing export, white-label, per-tenant keys.** Usage meters + export (`ee/billing`, `internal/usage`); branding as design-token overrides with an always-visible tenant indicator (`ee/whitelabel`, `internal/branding`); per-tenant envelope keys/BYOK on the crypto seam (`ee/tenantkeys`, `internal/tenantcrypto`, `docs/byok.md`).
- ✅ **Per-tenant lifecycle.** Export, **verifiable deletion across all stores with attestation** (U-027/D7), offboarding runbook. `internal/lifecycle`, `docs/lifecycle.md`.
- ✅ **Fairness.** Per-tenant quotas, rate limits, ingest backpressure isolation, query-cost guards (+ the tenant-visible self-view, deliberately core); noisy-neighbor load scenario in the harness. `internal/fairness` · *perf-smoke*.
- ✅ **Editions/licensing enforcement.** One repo, `ee/` commercial tree, core-never-imports-ee (CI-guarded with self-test), offline Ed25519-signed license verification (no phone-home), single feature→tier table, hidden-not-locked UX, 30-day grace → read-only. `internal/license`, `cmd/probectl-license`, `docs/editions.md` · *editions-gate*. (The legal *texts* are the gap — §5.3.)

### 2.6 Enterprise trust

- ✅ **Identity.** OIDC SSO (per-tenant IdP), SCIM 2.0, RBAC + custom roles + ABAC (deny-override), delegated admin, MFA via IdP, auth rate-limiting + lockout (U-024); **fail-closed auth default** — no configured mode refuses requests (U-001). `internal/auth`, `internal/scim`, `internal/abac*`.
- ✅ **Audit.** Hash-chained tamper-evident tenant streams + a separate provider/break-glass stream; signed WORM export to object storage with chain verification (U-041/D8); SIEM forwarding with a monotonic cursor. `internal/audit`, `internal/siem`.
- ✅ **Crypto.** Everything through `internal/crypto` (FIPS-swappable seam; a CI ratchet forbids primitives elsewhere); envelope encryption at rest; mTLS + SPIFFE everywhere agent↔control-plane with trust-domain pinning (C2) and a registry-driven revocation deny-list (U-038); TLS on every listener, HTTPS-by-default deploys, CSP/HSTS/secure cookies (U-003/B5). · *crypto-import ratchet, fips-gate*.
- ✅ **Supply chain.** SHA-pinned actions with pin lint (U-007), digest-pinned images + SBOM + cosign keyless signing (U-068/C6/C11), locked + audited npm (U-061/62), pinned codegen/lint/scanner tools with a generated-code diff gate (U-059/60), dependabot + scheduled scans (C12), dependency policy incl. the cilium/ebpf pre-1.0 risk entry (`docs/dependency-policy.md`, U-080/81).
- ✅ **Governance & compliance posture.** Data classification/retention/redaction (`internal/govern`); SOC 2 mapping, threat model, agent security whitepaper, IR plan, procurement pack drafts (`docs/compliance/`, `docs/security/` — U-033/034/065/066); honest claims pass (FIPS/AI/eBPF wording grounded — U-019/B10).

### 2.7 Operations, frontend, packaging

- ✅ **Frontend foundation.** Design tokens (no hardcoded values — white-label is a token override), component library, app shell + command palette, WCAG 2.2 AA CI gate, dark-native; tenant indicator always visible; provider console visually separate; a **surface-coverage CI gate** requires every capability to declare native/federated/none-by-design. `web/` · *web (a11y + frontend-coverage)*.
- ✅ **Packaging.** Multi-arch images; Helm for control plane (hardening-gated: non-root, read-only FS, drop-ALL, **NetworkPolicy default-on with documented holes** — U-086) + the agent DaemonSet chart (explicit BPF/PERFMON contract, seccomp — U-016/D10); compose profiles; VM installer; air-gapped bundle; Terraform + GitOps validation. `deploy/` · *helm-gate, terraform-gate, kubeconform*.
- ✅ **Reliability tooling.** Backup/restore scripts + runbook + **a CI drill that drops and restores both databases on every pass** (U-030); failover drill + DR runbook (U-053 — sign-off pending, §5.2); staged fleet rollout engine with health gates + rollback (U-031 — console wiring pending, §5.1); bounded retry + DLQ on store writes; circuit breakers on Prom/CH clients (U-078); async batched bus publish + backpressure (U-023); in-memory TSDB retention/eviction (U-029). · *backup-drill, failover-drill*.
- ✅ **Self-observability.** probectl observes probectl (metrics/logs per subsystem); load harness for S–XL tiers with an S-tier smoke + scale-gate floor in CI (U-005/U-055 — L/XL evidence runs pending, §5.2); agent overhead bench suite with a throughput tripwire (U-051 — reference row pending). `internal/perf`, `scripts/bench/` · *load-smoke, perf-smoke*.
- ✅ **Black-box e2e.** Compose-stack boot → API → agent → result-flow assertions, nightly (U-054). `test/` · *nightly*.

### 2.8 The verification net (the diligence centerpiece)

The repo's claims are enforced by **55 workflow jobs** across `.github/workflows/` (40 in the main CI workflow plus 15 nightly/release/security jobs); the notable standing gates:

| Gate | Invariant it holds |
|---|---|
| *cross-tenant-isolation* | a tenant-scoped caller (incl. AI/MCP) can never read another tenant — Postgres RLS + ClickHouse suites |
| *integration* (correlation gate) | a multi-plane fault surfaces as ONE tenant-scoped incident; store integration coverage ≥ 60% (U-057) |
| *editions-gate* + import guard | core never imports `ee/`; core-only build stays green |
| *observe-only* (in test-go) | the eBPF programs attach no enforcement hook — detection is a signal, never an IPS |
| *ebpf-kernel-matrix* | the real BPF objects load/run on the supported kernel range under QEMU |
| *fuzz-smoke* | 8 fuzz targets over every externally-fed parser (path/BGP/flow/SNMP/OTLP/RUM — U-082) |
| *crypto-import ratchet* | no crypto primitives outside `internal/crypto` (FIPS seam intact) |
| *helm-gate* | secure-by-default rendering: no default creds, hardened pods, HTTPS, NetworkPolicy default-on |
| *backup-drill / failover-drill* | restore and failover paths cannot silently rot — executed on every pass |
| *scale-gate floor + load-smoke* | ingest pipeline materiality floor; S-tier full-stack smoke |
| *rca-eval* (blocking) | RCA answer accuracy / citation precision enforced at 0.85 / 0.85 and published as an artifact |
| *coverage floors* | per-package Go floors; analyzer 85% floor; web a11y + surface-coverage |
| *action-pins, proto (buf breaking + codegen diff), openapi-gate, migration-gate* | supply-chain pins; additive-only wire contract; spec-code parity; idempotent migrations |

A 94-finding third-party-style diligence register (`probectl-audit/`) was worked to closure across seven remediation waves (A–G); the open remainder is exactly §5.

---

## 3. Feature delivery matrix (v0.5 F-numbers)

Strict standard; one line each. Evidence = package / doc / gate / U-ID.

| F# | Feature | Status | Evidence |
|---|---|---|---|
| F1 | Canary agent | ✅ | `cmd/probectl-agent`, `internal/canary` |
| F2 | Network tests (a2s + a2a) | ✅ | `internal/canary`, `internal/a2a` |
| F3 | Path visualization | ✅ | `internal/path`, web hero view |
| F4/F5 | HTTP / DNS tests | ✅ | `internal/canary` (http, dns, dnssec, trace) |
| F6 | BGP monitoring | ✅ | `analyzer/`, `internal/bgp` |
| F7 | Open-data enrichment | ✅ | `internal/opendata` (shared-once, per-tenant scoping) |
| F8/F9 | Alerting / dashboards + incident timeline | ✅ | `internal/alert`, `internal/incident`, `web/`; silences/acks persist through `migrations/0043_alert_ops.sql`, `internal/store/alertops.go`, `internal/control/alertsactive.go`, `internal/control/alerteval.go` |
| F10 | Control plane + REST/gRPC + CLI | ✅ | `internal/control`, `proto/`, `cmd/probectl` · *openapi-gate* |
| F11 | eBPF host/L7 agent | ✅ | `internal/ebpf` · *kernel-matrix* |
| F12 | OTel-aligned data model + OTLP | ✅ | `internal/otel`, `internal/otel/otlp`, `internal/pipeline/otlpexport.go` (metrics/traces/logs ingest/export; three-signal claim pinned by docslint — ARCH-002/003) |
| F13 | AI RCA + NL query | ✅ | `internal/ai` · *rca-eval* |
| F14 | MCP server | ✅ | `internal/ai/mcp` |
| F15 | Browser synthetic | ✅ | `browser-worker/` · *browser-worker* |
| F16 | Endpoint agent (DEM) | ✅ | `internal/endpoint`, cross-OS builds |
| F17 | Flow analytics | ✅ | `internal/flow` |
| F18 | Device telemetry | ✅ | `internal/device` (SNMP + gNMI) |
| F19 | Internet-outage view | ✅ | `internal/outage` |
| F20 | RUM | ✅ | `internal/rum` |
| F21 | Voice/RTP | ✅ | `internal/canary/voice.go` |
| F22 | SSO + role model | ✅ | `internal/auth` (fail-closed default — U-001) |
| F23 | Audit foundation | ✅ | `internal/audit` (+ WORM, U-041) |
| F24 | Tenant→Org→Team→Project | ✅ | `internal/store/hierarchy.go` |
| F25 | SCIM/ABAC/delegated admin | ✅ | `internal/scim`, ABAC deny-override |
| F26 | SIEM integration | ✅ | `internal/siem` (cursor, tenant-routed) |
| F27 | On-call & ITSM | ✅ | `internal/notify`, `docs/oncall-itsm.md` |
| F28 | Zero-downtime lifecycle + fleet rollout | ✅ | migrations gate + rollout engine ✅ (`internal/agent/rollout.go`); operator CLI/API surface ✅ (`probectl rollout`, `/v1/rollouts`, `docs/ops/fleet-rollout.md`) |
| F29 | IaC & GitOps | ✅ | `deploy/terraform`, *gitops-gate*, *helm-gate* |
| F30 | CMDB / Grafana / Prom federation | ✅ | `internal/cmdb`, `internal/promapi`, federated surfaces declared |
| F31 | Secrets integration | ✅ | `internal/secrets` (seam + Vault path), device creds |
| F32 | FIPS-mode crypto | ✅ | seam + build-tag + *fips-gate* ✅; dated module evidence in `docs/compliance/fips-evidence.md` (Go Cryptographic Module v1.0.0, CMVP #5247, CAVP A6650); probectl itself has no separate CMVP certificate |
| F33 | Multi-region / HA | 🔶 | stateless request/ingest path + PostgreSQL-leased, epoch-fenced singleton background loops; HA control plane, failover drill, runbooks ✅; multi-region validated runbooks + rep-hardware sign-off ⏳ (§5.2) |
| F34 | Advanced governance | ✅ | `internal/govern`, retention/erasure/redaction, BYOK |
| F35 | Supportability | ✅ | `internal/support` (tenant-scoped, secret-stripped bundles) |
| F36 | TLS/cert observability | ✅ | `internal/threat`, trustctl handoff |
| F37 | NDR-lite detection engine | ✅ | `internal/threat` (confidence-scored, suppression, SIEM) |
| F38 | Threat-intel enrichment | ✅ | `internal/opendata` + AUP tracking (resale terms = counsel, §5.3) |
| F39 | Change intelligence | ✅ | `internal/change` (HMAC webhooks) |
| F40 | Live topology graph | ✅ | `internal/topology` (versioned, what-if; ADR U-047) |
| F41 | FinOps/egress cost | ✅ | `internal/cost` |
| F42 | SLO + business impact | ✅ | `internal/slo` (OpenSLO) |
| F43 | Segmentation validation | ✅ | `internal/compliance` |
| F44 | Guarded remediation | ✅ | `ee/remediation` — observe-only/human-gated, dry-run, blast-radius, audited (guardrail intact) |
| F45 | AI authoring + discovery | ✅ | `internal/ai/author` |
| F46 | Last-mile/WiFi/ISP diagnostics | ✅ | `internal/endpoint` + `docs/endpoint-dem.md` |
| F47 | Network chaos | ✅ | `internal/chaos` |
| F48 | Carbon/power | ✅ | `internal/carbon` |
| F49 | Plugin/detection marketplace | ⛔ | explicitly excluded from GA completeness; deliberate Phase-4 future bet with a `none-by-design` surface declaration (`web/src/surfaces.ts`; §6) |
| F50 | Tenancy & hard isolation | ✅ | `internal/tenancy` + RLS/CH policies · *cross-tenant-isolation* |
| F51 | Provider/MSP plane | ✅ | `ee/provider` (break-glass audited; no implicit access) |
| F52 | Pooled/siloed/hybrid | ✅ | `ee/silo` (per-tenant ClickHouse provisioning/routing delivered across flow, path, eBPF, and OTLP; see `docs/isolation.md`; pinned by `TestProvisionDrivesEveryCHPlane`) |
| F53 | Metering/billing export | ✅ | `ee/billing`, `internal/usage` |
| F54 | White-label | ✅ | tokens-first design system + `ee/whitelabel` |
| F55 | Export/residency/verifiable deletion | ✅ | `internal/lifecycle` (attested erasure — U-027) |
| F56 | Per-tenant keys/BYOK | ✅ | `ee/tenantkeys`, `internal/tenantcrypto` |
| F57 | Tenant fairness | ✅ | `internal/fairness` (deliberately core, incl. tenant self-view) |

**Score: 55 ✅ · 1 🔶 (F33) · 1 ⛔ future/out-of-GA (F49).** GA completeness excludes F49 by design; the row stays in the forward traceability denominator so the future marketplace promise is visible, not silently dropped. Epics A–U are delivered at GA scope; US-U1–U6 acceptance criteria are individually CI-gated.

---

## 4. Non-functional posture (delivered)

The v0.5 §7 requirements are now the **twelve hard guardrails of `CLAUDE.md` §7**, each enforced mechanically where possible: tenant isolation at the storage layer with its own CI suite; no phone-home (offline license math, opt-in-only telemetry); crypto only through the FIPS-swappable seam (ratchet); mTLS + SPIFFE everywhere with revocation; TLS on every listener, authenticated/signature-verified/untrusted ingestion, fail-closed; secrets enveloped, never logged; everything audited (separate provider stream); remediation human-gated; detection never an IPS; open data read-only/cached/degrading; no stray browser storage; HTTPS-by-default deploys. Performance and reliability mechanics (HA, store-and-forward, DLQ, breakers, backpressure, retention) are in §2.7 — the **numeric** SLOs remain PROVISIONAL pending the §5.2 evidence runs.

---

## 5. Remaining to GA (the steering list)

Everything left, grouped by what unblocks it. IDs link the register/roadmap; nothing here is silently dropped from v0.5 — it is the honest tail.

### 5.1 Engineering (founder + agents; ordered by leverage)

F52 note: per-tenant ClickHouse provisioning/routing is delivered across flow,
path, eBPF, and OTLP (`ee/silo`, `docs/isolation.md`; pinned by
`TestProvisionDrivesEveryCHPlane`). It is no longer a remaining migration-routing
item.

1. **Fleet rollout polish** — the delivered rollout engine (`internal/agent/rollout.go`, U-031) is operator-usable through `probectl rollout` plus `/v1/rollouts` (`docs/ops/fleet-rollout.md`). Remaining GA work is UX/evidence polish around scripted fleet workflows, not the missing operator surface itself.
2. **OTLP conformance polish** — the three-signal OTLP path is delivered (metrics, traces, and logs ingest/export). Remaining GA work is edge-case conformance and hardening, not a traces/logs product decision: materialize or explicitly reject unsupported metric point types, keep trace/log fuzz coverage current, and preserve the all-signal docslint contract.
3. **eBPF capture follow-ups** — IPv6 L4 capture is delivered (`internal/ebpf/bpf/l4flow.bpf.c`, `internal/ebpf/l4event.go`, `internal/ebpf/live_smoke_ebpf_test.go`; U-073). Go `crypto/tls` plaintext capture is explicitly post-GA/out-of-scope for GA (disclosed limitation, U-074): keep C-library TLS uprobes default-off/consent-gated/redacted, and treat Go `crypto/tls` as a separately-scoped future module rather than silent coverage.
4. **Alert operation UX/evidence polish** — silences/acks persistence is delivered (`migrations/0043_alert_ops.sql`, `internal/store/alertops.go`, `internal/control/alertsactive.go`, `internal/control/alerteval.go`; ARCH-005/U-047). Remaining GA work is evidence/UX polish around persisted alert operations, not the persistence mechanism itself.
5. **Backup CronJobs into the Helm chart** behind `backup.enabled` (follow-up noted in `deploy/backup/README.md`).
6. **Design-led polish on the hero surfaces** — path map + topology/what-if iterated to the "crush the incumbents" bar (PRD v0.5 §6 ambition; the foundation and gates exist, the polish loop is product work, not plumbing).
7. **GA milestone gate** — surface-coverage, correlation, coverage, integration, isolation, and nightly e2e receipts green at GA scope on the exact release commit; nightly e2e extended to the canary-agent mTLS path.

### 5.2 Evidence runs (need real iron, not code)

- **L/XL load runs on reference hardware** → fill `docs/scale-gate.md`, flip numeric SLOs from PROVISIONAL (U-005; `make load-test TIER=L|XL` is ready, S-tier runs in CI every pass).
- **Representative DR drill** → RTO/RPO sign-off, remove the PROVISIONAL banner in `docs/ops/dr.md` (U-053; the CI drill already executes the full path at dev size).
- **Reference-host agent overhead row** → complete `docs/agent-overhead.md` + the whitepaper numbers (U-051; bench suite ready).

### 5.3 Counsel / legal (the actual critical path to any commercial motion)

- **LICENSE + commercial texts** — BSL parameters, the commercial license, `ee/` header, **reseller terms** (the MSP channel is legally off until this lands). `LICENSE` is a TBD placeholder by design.
- **Procurement pack legal review** — DPA/MSA templates, subprocessor posture, CAIQ finalization (drafts exist — U-065).
- **Open-data / threat-intel AUP matrix for commercial resale** — tracked per source (`docs/opendata-aup.md`); single-tenant OSS use is unaffected; MSP resale is gated on this review.

### 5.4 Organizational (need hires / an acquirer, not code)

- **SOC 2 readiness → Type II** — the technical controls are mapped (`docs/compliance/soc2-mapping.md`); separation-of-duties and formal policies close with the first hires.
- **STIG/CIS and certification-grade customer package** — FIPS module certificate evidence and the validated-module build path are in repo (F32 ✅); remaining work is deployment hardening/compliance packaging, not claiming a probectl-owned CMVP certificate.
- **VPAT publication** — the WCAG 2.2 AA gate runs in CI; the formal VPAT document is a publication task.
- **Public launch** — the repo is private by strategy; OSS launch (and every adoption metric in §8) starts the clock when flipped.

---

## 6. Future bets (post-GA, unchanged in spirit from v0.5)

- **F49 marketplace / detection-as-code flywheel** — explicitly outside GA completeness; no current GA surface is promised. Future scope is community plugins, dashboards, Sigma-style rules, and signed/verified publishing. The detection-as-code substrate already exists.
- **First-party managed offering** — an optional business decision; explicitly not an architectural gap (multi-tenancy is built).
- **FedRAMP** — achievable-but-deferred; building blocks (FIPS seam, audit, isolation) in place.
- **Rust hot paths, dedicated graph engine at XL, deeper OTLP conformance, deeper last-mile diagnostics** — revisit on evidence from the L/XL runs.

---

## 7. Non-goals (binding, unchanged)

By design, probectl is **not**: a vendor-operated first-party public SaaS (the multi-tenant capability exists for partners/MSPs to self-host and resell); an APM/distributed-tracing replacement; a SIEM/log-analytics platform; an inline IPS or full NDR suite (detections are signals + SIEM export); an owner of a global cloud-agent/BGP fleet. It performs no un-gated autonomous remediation and never phones home by default. *(Carried verbatim in force from v0.5 §4.5; referenced by `CLAUDE.md` §10.)*

---

## 8. Success metrics

**Now measurable (engineering readiness — green only with fresh receipts, otherwise tracked as evidence debt):** gate pass rates (§2.8), eval scores (*rca-eval* artifact), coverage floors, drill timings (backup/failover printed each CI pass), zero cross-tenant test failures (standing), register burn-down (94 findings → §5 tail).

**Measurable at launch (adoption — clock starts at public release):** stars/deployments/agents/contributors; MSP resellers + tenants served + onboarding time; TTFI; AI/MCP usage; detections actioned; cost surfaced; SLOs tracked. Collection stays sovereignty-respecting: opt-in, self-hostable, download-proxy counts only — no phone-home (guardrail).

**The acquisition signal** (unchanged thesis): parity-plus breadth + sovereign multi-tenancy + the verification net is the diligence story; §5.3 (license) is what converts MSP interest into a channel.

---

## 9. Risks — closed vs standing

**Closed by construction since v0.5** (the register documents each): cross-tenant leakage (RLS + CH policies + CI suite + isolation pen-focus); tenancy retrofit (built ground-up); noisy neighbor (fairness + load scenario); provider-plane abuse (separate domain, audited break-glass); integration-surface exposure (TLS/auth/HMAC everywhere, fail-closed); supply chain (pins/SBOM/signing/scans); eBPF fragility (kernel matrix, digest-verified objects, lockdown detection, observe-only gate); AI safety (consent-gated egress, redaction, injection hardening, citation integrity, concurrency caps); detection false positives (confidence/suppression/eval); storage cost (caps, retention, breakers, DLQ).

**Standing:**
- **Legal/licensing on the critical path** (§5.3) — the MSP channel and any commercial motion wait on counsel. *Highest leverage, lowest engineering content.*
- **Evidence debt** (§5.2) — numeric claims stay PROVISIONAL until the L/XL + DR + overhead runs on real iron; an acquirer will ask.
- **Solo-founder bandwidth + bus factor** — mitigated by the verification net and documentation density, not eliminated.
- **Market timing** — incumbents adding AI/depth; the moat is the intersection (sovereign + multi-tenant + five planes + verification), which is still unoccupied.
- **Adoption unknowns** — every §8 launch metric is untested until the repo goes public.

---

## 10. References & v0.5 section map

| v1.0 | carries | v0.5 |
|---|---|---|
| §1 | vision, modes, moat, personas | §1, §2, §3 |
| §2–§4 | functional + technical + NFR requirements → delivered inventory | §4.1–4.4, §5, §6, §7 |
| §3 matrix | F1–F57 with status | §4.1–4.4 |
| §5 | implementation plan → remaining work | §9 (+ roadmap `docs/roadmap.md`) |
| §6 | phase-4 / optional items | §4.3 tails, §9.1 Phase 4 |
| §7 | non-goals | §4.5 |
| §8 | metrics, reframed delivered-vs-launch | §8 |
| §9 | risks, closed-vs-standing | §10 |

- Engineering contract: `probectl/CLAUDE.md` (guardrails §7 are the operative non-functionals).
- Delivery ground truth: the repo + CI (`.github/workflows/`), `docs/` (architecture, runbooks, compliance pack), `CHANGELOG.md`.
- Diligence: `probectl-audit/outputs/00-UNIFIED-REGISTER.html` (94 findings; remediation waves A–G), `docs/audit/`.
- Forward plan: `docs/roadmap.md` (quarterly; §5 is its product-level rollup).
- Historical contract: `probectl-PRD-v0.5.md` (frozen May 31, 2026).
