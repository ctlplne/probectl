# Buyer memo: probectl

probectl is the self-hosted network observability control plane for operators
who need the answer to "what broke?" without sending telemetry to a vendor's
cloud. The short version is simple: **see everything, send nothing**. Run the
control plane in your own account, datacenter, or MSP environment; enroll your
own agents and collectors; keep tenant data, credentials, traces, flows, BGP
events, device telemetry, and AI evidence inside your boundary.

## Decision in one sentence

Buy probectl when the winning requirement is sovereign, multi-plane network
visibility with predictable self-hosted pricing, hard tenant isolation, and proof-based
operations; do not buy it when you need a vendor-hosted SaaS, a global vendor
probe fleet, an APM replacement, a SIEM, or an inline IPS.

## What it replaces or reduces

probectl is not a clone of one incumbent. It is the owned-control-plane
replacement motion for several network-observability spend lines:

| Buyer job | Common tool shape | probectl replacement motion |
|---|---|---|
| Traffic, routing, and cost visibility | Kentik-style flow, BGP, and cost analytics | Ingest flow records, BGP signals, cloud/open-data context, cost/SLO views, and topology into one tenant-scoped model that the operator owns. |
| Active path and synthetic monitoring | ThousandEyes-style tests and path visibility | Run tenant-bound canary agents from sites you control; use owned vantage points rather than a vendor-operated global probe fleet. |
| Device telemetry and network health | SolarWinds-style polling and operational inventory | Collect device telemetry, topology, incidents, and alert state into the same control plane as active tests and flows. |
| Network-adjacent observability inside a larger telemetry estate | Datadog-style dashboards and cross-signal views | Federate through OpenTelemetry and served APIs while keeping probectl focused on network planes, not general APM ownership. |
| MSP resale | Managed monitoring platform with per-customer portals | Run the MSP tier yourself, isolate tenants, explicitly export usage for consumption reporting, resell under the probectl banner, and keep probectl out of customer data custody. |

The ELI5 picture: most shops buy one flashlight for the road, one for the
router, one for the server, and one for the billing meter. probectl gives the
operator one switchboard for those flashlights, with a tenant lock on every
wire.

## Custody and sovereignty

The custody stance is the product. probectl is source-available and self-hosted;
the vendor does not receive default telemetry, diagnostics, usage beacons, flow
records, probe results, device data, or AI prompts. Offline license verification
is local math. Open-data and threat-intel fetches are operator-controlled,
read-only, cached, TLS-validated, and degrade gracefully.

For a single regulated enterprise, the deployment can be one sovereign tenant.
For an MSP or internal platform team, the same codebase serves many tenants, but
the MSP owns and operates the platform. probectl's vendor still has no managed
service custody path. Provider operators do not get silent tenant telemetry
access; break-glass is explicit, time-bounded, tenant-consented, and separately
audited.

## Commercial posture

The commercial posture follows who bears the operating cost:

- Core stays free as the five-plane self-hosted platform.
- Enterprise and MSP are commercial tiers. Enterprise is a self-hosted license
  opening every non-resale `ee/` capability; MSP receives the Enterprise set
  plus provider operations and resells under the probectl banner at its own
  customer pricing.
- No price list or pricing model is published; commercial terms are set per
  agreement.
- Usage counters are collected locally and leave only through an operator-run
  export. There is no phone-home billing path.

The split stays legible: a sovereign enterprise that already pays for its
infrastructure licenses the software for its own deployment; an MSP operating a
resale business uses the local usage record while retaining custody of every
tenant signal.

## Proof receipts

Use proof receipts as the buyer's map. A static product page is a promise; a
receipt is a command, test, or artifact that keeps that promise honest.

Current receipt posture:

| Area | Receipt to ask for | Buyer meaning |
|---|---|---|
| Core build and edition boundary | `make lint test editions-gate` | The repo compiles, tests pass, and core still does not import `ee/`. |
| Web surface coverage | `npm --prefix web run coverage-gate`, `npm --prefix web test`, `npm --prefix web run build` | User-facing surfaces have declared live/static/non-live status and the UI still builds. |
| End-to-end tenant isolation | `make e2e` | A black-box stack ingests data and proves tenants cannot see each other's records. |
| Integration services | `make test-integration` with real Postgres, Kafka, ClickHouse, and Prometheus | The important storage and transport seams run against real backing services, not only mocks. |
| Failover mechanics | `make failover-drill` | Local compose failover has an RTO/RPO receipt; regional WAN, DNS, proxy, fence, ClickHouse, and object-store recovery still need operator reference evidence. |
| Scale | `make scale-gate-m`; pending `make scale-gate TIER=L`, `XL`, `XXL` on `PERF-REF-CLUSTER-*` | CI-scale mechanics are covered; L/XL/XXL production capacity remains provisional until reference-cluster rows are recorded in `docs/scale-gate.md`. |
| Audit traceability | `node tools/verify-inspected-files.mjs --repo ../probectl --outputs outputs --out outputs/21-VERIFY-inspected-files.json --allow-exceptions` | The audit report is backed by inspected file/line evidence and calls out sensitive exceptions instead of inventing proof. |

Do not treat a claimed capability as production-served until its receipt matches
the surface and denominator being discussed. A green unit test for a library is
not the same thing as a served buyer surface.

## Known limitations and accepted risks

These are decision inputs, not footnotes:

- Core is licensed under BUSL-1.1 and converts to MPL-2.0 four years after
  each release; `pkg/`, `proto/` and `examples/` are MPL-2.0; `ee/` remains
  separately commercial. Counsel
  still must finalize the bespoke `ee/LICENSE`, reseller terms, DPA/MSA, and
  trademark posture before commercial/MSP motion.
- L/XL/XXL scale rows are targets until reference-cluster runs are recorded.
- The regional disaster-recovery receipt is partial: local failover mechanics
  have proof, but regional DNS/WAN/proxy/fence timing and ClickHouse/object-store
  recovery need an operator-run reference drill.
- Live-kernel eBPF overhead needs a Linux reference-host receipt for the exact
  kernel and workload being claimed.
- probectl is not a vendor-hosted public SaaS, an APM replacement, a SIEM, an
  inline IPS/firewall, or an autonomous remediation engine.
- Remediation stays observe-only and human-gated by default.
- The served-vs-library list is canonical in
  [`limitations.md`](limitations.md#built-not-yet-served-edges). If a page
  sounds stronger than that list, the limitation wins until the serving path and
  receipt exist.

## Managed-SaaS replacement strategy

For a buyer replacing managed SaaS, the pattern is:

1. Put probectl in a customer-owned or MSP-owned environment.
2. Use owned agents, collectors, vantages, and integrations.
3. Keep telemetry, AI prompts, evidence, and exports inside that environment.
4. Federate outward only through explicit operator-configured exports such as
   OTLP, SIEM export, or support bundles.
5. Budget the deployment on the infrastructure and operations you control; commercial terms are set per agreement.

The strategy intentionally trades a vendor's global hosted fabric for local
custody, auditable tenant isolation, and predictable economics. If the buyer's
must-have is "I want someone else to run a first-party public SaaS and hold all
the telemetry," probectl is the wrong answer.

## Pilot checklist

A good pilot has five pass/fail questions:

- **Custody:** Can the buyer operate the stack without default outbound vendor
  telemetry?
- **Coverage:** Do the five network planes cover the top incident classes the
  buyer actually has?
- **Isolation:** Can two test tenants fail to see each other's data through API,
  UI, AI/MCP, exports, and stores?
- **Scale:** Does the chosen deployment tier have a fresh receipt for the
  buyer's expected agent, flow, probe, and tenant counts?
- **Operations:** Can the buyer run backup, restore, failover, upgrades,
  support-bundle export, and evidence review with their own team or MSP?

If those pass, the adoption case is strong. If any fail, the memo should turn
into a remediation plan, not a sales deck.

## Source map

- Positioning and quickstart: [`../README.md`](../README.md)
- Editions and source-available boundary: [`editions.md`](editions.md)
- Plans and metering: [`pricing.md`](pricing.md)
- Tenant isolation: [`security/tenant-isolation.md`](security/tenant-isolation.md)
- Provider/MSP plane: [`provider-plane.md`](provider-plane.md)
- Scale receipts and provisional rows: [`scale-gate.md`](scale-gate.md)
- Limitations and non-goals: [`limitations.md`](limitations.md)
- Compliance evidence: [`compliance/control-evidence.md`](compliance/control-evidence.md)
- AI egress/custody: [`ai-egress.md`](ai-egress.md)
