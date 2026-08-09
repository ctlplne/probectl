# Open-data sources — provenance and acceptable-use matrix

## What this is

When probectl sees an IP address, that address alone is not very useful. Which
network owns it? Which country is it in? Is it at an internet exchange? The
**open-data enrichment layer** answers those questions by looking the IP up in
public datasets and attaching the context to the record — *enrichment* means
exactly that: adding context to data you already have, not collecting new data.

It lives in `internal/opendata`. The framework annotates an IP with ASN / geo /
IXP / allocation context (an **ASN** is an autonomous-system number — the ID of
the network operator that announces the address; an **IXP** is an internet
exchange point, where networks physically interconnect; *allocation* is which
regional registry handed the address space out, and when). And — this is the
part this document is about — every
source carries machine-readable **provenance and acceptable-use (AUP)
metadata** describing where the data came from and what you are allowed to do
with it: **provenance** is the data's origin story; the **AUP** (acceptable-use
policy) is its publisher's terms. Think of it as a nutrition label printed on
every dataset — ingredients and permitted use, readable by code, carried with
the data instead of buried in a wiki. That metadata is the `OpenDataSource`
model — a source's
`Descriptor().AUP` — and the live health of each source is surfaced at runtime
via `Enricher.Status()` and the operator route
`GET /v1/threat/intel/status`.

## Why provenance matters

Two reasons, and they pull in different directions:

1. **Tenancy.** Open data is the same for everybody, so probectl ingests it
   **once and shares it across tenants** (one reference library, not a copy
   per reader); the enrichment is then attached
   per-tenant to each flow or test result. The `opendata` package is
   deliberately tenant-agnostic — it returns plain data and the caller stores
   it on a tenant-scoped record, so the tenant boundary is enforced where the
   data lands, not in the shared lookup (see
   [`security/tenant-isolation.md`](security/tenant-isolation.md)).
2. **Licensing for resale.** These labels are an engineering safety control,
   not legal advice. `restricted` or `unknown` means **do not enable the source
   in a commercial/provider deployment until the operator has source-specific
   rights in writing**. Even a source that is safe for internal use can forbid
   sharing its data with an MSP's customers. See the dated counsel worksheet in
   [`legal/open-data-source-review-2026-08-09.md`](legal/open-data-source-review-2026-08-09.md).

## How sources behave (the three guardrails)

Every source obeys the same safety rules, enforced in code:

- **Fetched over TLS, treated as untrusted.** Outbound lookups use a hardened
  HTTPS client with **certificate validation that is never disabled**, and the
  fetched content is parsed as untrusted input — bounds-checked, malformed rows
  skipped (two of probectl's
  [non-negotiables](../CONTRIBUTING.md#non-negotiables)). A public dataset is
  someone else's bytes; the parser assumes they could be hostile.
- **Graceful degradation.** A source that is disabled, rate-limited, or failing
  is **logged and skipped** — it never breaks a core path. The `Enricher` runs
  each source under a timeout and even recovers from a panicking plugin
  (`runSource` in `enricher.go`), so one flaky dataset cannot take enrichment
  down. A failed source is marked `degraded`; the rest still contribute.
  Enrichment is garnish, never load-bearing: losing it makes records plainer,
  not absent.
- **Cached aggressively.** Enrichment is cached per IP, and each network-bound
  source caches its own dataset (PeeringDB caches per ASN; the RIR stats file is
  parsed once into a sorted in-memory index). So a rate-limited upstream is
  queried at most once per key — being a polite client of a free public
  service is part of the contract.

## Matrix

| Source | `name` | Kind | Provides | License / terms | Commercial use | Attribution required |
| ------ | ------ | ---- | -------- | --------------- | -------------- | -------------------- |
| **Team Cymru** IP-to-ASN | `team-cymru` | `asn` | ASN, prefix, registry, AS name | Community service; no redistribution grant established | **unknown** | "IP-to-ASN mapping by Team Cymru" |
| **MaxMind GeoLite2** | `maxmind-geolite2` | `geo` | country, city, lat/lon | GeoLite EULA, including CC BY-SA terms | **restricted** | "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com" |
| **PeeringDB** | `peeringdb` | `ixp` | IXP / facility presence | PeeringDB AUP | **restricted** | "Data from PeeringDB" |
| **RIR delegated-stats** | `rir-stats` | `allocation` | RIR, country, allocation status/date | Five registry-specific terms | **unknown** | — |

(The `name`, license, attribution, and commercial-use cells above are taken
verbatim from each source's `Descriptor().AUP` in `internal/opendata` —
`cymru.go`, `maxmind.go`, `peeringdb.go`, `rir.go`. The `name` is what
`Enricher.Status()` and `GET /v1/threat/intel/status` report per source at
runtime. The served route also returns `enabled`, `status`, `last_success`, and
`last_error` so an operator can see which public datasets are actually active
without sampling probectl's own docs. Each source is enabled by its own
`PROBECTL_FLOW_ENRICH_*` key — the table in `configuration.md` maps key to
source — and `GET /v1/opendata/enrichment?ip=<addr>` serves the merged
per-IP context with this provenance attached.)

Notes:

- **MaxMind GeoLite2 is not shipped.** The operator supplies the `.mmdb` file.
  This prevents probectl from distributing the database, but it does **not** by
  itself authorize an MSP to expose derived GeoLite data to customers. The
  current GeoLite EULA grants internal-business use and MaxMind separately
  offers redistribution licensing, so provider use stays `restricted` until
  the operator's agreement covers it.
- **PeeringDB stays off the commercial green list.** Its own API-key guide says
  the AUP prevents commercial use. Public availability is not a commercial
  license.
- **Team Cymru and RIR statistics stay `unknown`.** “Free” or “public” describes
  access, not necessarily resale rights. Counsel or the operator must map the
  exact intended use to written permission for each publisher.
- Attribution text still travels with every contributing record, but
  attribution never upgrades `restricted` or `unknown` into permission.

## Related source sets

Threat-intel feeds are a **separate** source set (with their own, often
non-commercial, terms) layered on top of this same framework — see
[`threat-intel.md`](threat-intel.md) for that matrix. Cloud-pricing data for cost analytics
reuses the same provenance/AUP model as well. The pattern is deliberate: every
external dataset, whether for enrichment, threat-intel, or pricing, declares its
provenance the same way.
