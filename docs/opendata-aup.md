# Open-data sources — provenance & AUP matrix

netctl's enrichment layer (`internal/opendata`, S15) annotates IPs with ASN / geo
/ IXP / allocation context from public datasets. Each source carries machine-readable
**provenance and acceptable-use (AUP) metadata** (the `OpenDataSource` model — a
source's `Descriptor().AUP`), surfaced at runtime via `Enricher.Status()`.

**Why this matters.** Open data is ingested **once and shared across tenants**;
enrichment is applied per-tenant. The AUP terms below are **not a constraint on
private development or single-tenant OSS use** — they become a gating item only
for **commercial / MSP resale** (commercial use across many customers), per
CLAUDE.md §2 and PRD §10.3. Resolve the commercial/reseller redistribution terms
before enabling provider mode commercially.

Every source is fetched **over TLS with certificate validation (never disabled)**
and its content is treated as **untrusted** (CLAUDE.md §7 guardrails 10, 12). A
source that is disabled, rate-limited, or failing is **logged and skipped** — it
never breaks a core path (graceful degradation).

## Matrix

| Source | Kind | Provides | License / terms | Commercial use | Attribution required |
| ------ | ---- | -------- | --------------- | -------------- | -------------------- |
| **Team Cymru** IP-to-ASN | `asn` | ASN, prefix, registry, AS name | Community service (free) | allowed-with-attribution | "IP-to-ASN mapping by Team Cymru" |
| **MaxMind GeoLite2** | `geo` | country, city, lat/lon | GeoLite2 EULA (CC BY-SA 4.0) | allowed-with-attribution | "This product includes GeoLite2 data created by MaxMind" |
| **PeeringDB** | `ixp` | IXP / facility presence | PeeringDB AUP (CC BY 4.0) | allowed-with-attribution | "Data from PeeringDB" |
| **RIR delegated-stats** | `allocation` | RIR, country, allocation status/date | Open data (RIR statistics) | allowed | — |
| **RIPE Atlas** (optional hook) | `measurement` | active ping/traceroute scheduling | Credit-based; RIPE Atlas terms | restricted (credits/terms) | per RIPE Atlas terms |

Notes:

- **MaxMind GeoLite2** is **not shipped** with netctl — the operator supplies the
  `.mmdb` under MaxMind's license and points the geo source at it (`OpenMMDB`).
- **RIPE Atlas** is an **optional** active-measurement hook, not part of the
  passive enrichment path: it schedules measurements on the shared RIPE Atlas
  platform when an API key + credits are configured, and is **disabled (fail
  closed) by default** (`NoopScheduler` → `ErrAtlasDisabled`).
- The framework caches enrichment per IP and each network source caches its own
  dataset (PeeringDB per ASN; RIR stats parsed once into a sorted index), so a
  rate-limited upstream is queried at most once per key (cache aggressively).

Threat-intel feeds (with their own, often non-commercial, terms) are a separate
source set added in S28; cloud-pricing data lands in S44. Both reuse this same
provenance/AUP model.
