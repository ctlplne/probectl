# Open-data sources — provenance and acceptable-use matrix

## What this is

When probectl sees an IP address, that address alone is not very useful. Which
network owns it? Which country is it in? Is it at an internet exchange? The
**open-data enrichment layer** answers those questions by looking the IP up in
public datasets and attaching the context to the record.

It lives in `internal/opendata`. The framework annotates an IP with ASN / geo /
IXP / allocation context, and — this is the part this document is about — every
source carries machine-readable **provenance and acceptable-use (AUP)
metadata** describing where the data came from and what you are allowed to do
with it. That metadata is the `OpenDataSource` model — a source's
`Descriptor().AUP` — and the live health of each source is surfaced at runtime
via `Enricher.Status()`.

## Why provenance matters

Two reasons, and they pull in different directions:

1. **Tenancy.** Open data is the same for everybody, so probectl ingests it
   **once and shares it across tenants**; the enrichment is then attached
   per-tenant to each flow or test result. The `opendata` package is
   deliberately tenant-agnostic — it returns plain data and the caller stores
   it on a tenant-scoped record, so the tenant boundary is enforced where the
   data lands, not in the shared lookup (CLAUDE.md §3).
2. **Licensing for resale.** The AUP terms below are **not a constraint on
   private development or single-tenant open-source use.** They become a gating
   item only for **commercial / MSP resale** — i.e. reselling probectl as a
   service to many customers (CLAUDE.md §2). If you plan to run provider mode
   commercially, resolve the reseller redistribution terms first.

## How sources behave (the three guardrails)

Every source obeys the same safety rules, enforced in code:

- **Fetched over TLS, treated as untrusted.** Outbound lookups use a hardened
  HTTPS client with **certificate validation that is never disabled**, and the
  fetched content is parsed as untrusted input — bounds-checked, malformed rows
  skipped (CLAUDE.md §7, rules 10 and 12).
- **Graceful degradation.** A source that is disabled, rate-limited, or failing
  is **logged and skipped** — it never breaks a core path. The `Enricher` runs
  each source under a timeout and even recovers from a panicking plugin
  (`runSource` in `enricher.go`), so one flaky dataset cannot take enrichment
  down. A failed source is marked `degraded`; the rest still contribute.
- **Cached aggressively.** Enrichment is cached per IP, and each network-bound
  source caches its own dataset (PeeringDB caches per ASN; the RIR stats file is
  parsed once into a sorted in-memory index). So a rate-limited upstream is
  queried at most once per key.

## Matrix

| Source | Kind | Provides | License / terms | Commercial use | Attribution required |
| ------ | ---- | -------- | --------------- | -------------- | -------------------- |
| **Team Cymru** IP-to-ASN | `asn` | ASN, prefix, registry, AS name | Team Cymru community service (free) | allowed-with-attribution | "IP-to-ASN mapping by Team Cymru" |
| **MaxMind GeoLite2** | `geo` | country, city, lat/lon | GeoLite2 EULA (CC BY-SA 4.0 attribution) | allowed-with-attribution | "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com" |
| **PeeringDB** | `ixp` | IXP / facility presence | PeeringDB data (CC BY 4.0) | allowed-with-attribution | "Data from PeeringDB" |
| **RIR delegated-stats** | `allocation` | RIR, country, allocation status/date | RIR delegated statistics (open data) | allowed | — |
| **RIPE Atlas** (optional hook) | `measurement` | active ping/traceroute scheduling | RIPE Atlas terms (credit-based) | restricted (credits/terms) | per RIPE Atlas terms |

(The license, attribution, and commercial-use cells above are taken verbatim
from each source's `Descriptor().AUP` in `internal/opendata` — `cymru.go`,
`maxmind.go`, `peeringdb.go`, `rir.go`.)

Notes:

- **MaxMind GeoLite2** is **not shipped** with probectl. The operator supplies
  the `.mmdb` database file under MaxMind's license and points the geo source at
  it via `OpenMMDB(path)` (`maxmind.go`). probectl reading a database you
  provide keeps probectl clear of redistributing MaxMind's data.
- **RIPE Atlas** is an **optional active-measurement hook**, not part of the
  passive enrichment path. It schedules measurements on the shared RIPE Atlas
  platform *only* when an API key and credits are configured, and is **disabled
  (fail closed) by default**: with no key, the default `NoopScheduler` returns
  `ErrAtlasDisabled` (`atlas.go`). Because it costs RIPE Atlas credits and is
  governed by RIPE's terms, its commercial use is marked `restricted`.
- **Why "allowed-with-attribution" for three of them?** Team Cymru, MaxMind, and
  PeeringDB permit commercial use but require you to credit the source. The
  required attribution string is carried in each descriptor so a reseller can
  surface it correctly.

## Related source sets

Threat-intel feeds are a **separate** source set (with their own, often
non-commercial, terms) layered on top of this same framework — see
`docs/threat-intel.md` for that matrix. Cloud-pricing data for cost analytics
reuses the same provenance/AUP model as well. The pattern is deliberate: every
external dataset, whether for enrichment, threat-intel, or pricing, declares its
provenance the same way.
