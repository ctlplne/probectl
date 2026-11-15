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
| **PeeringDB local IX prefixes** | `peeringdb-ix-prefix-file` | `ixp` | complete operator-supplied `ixpfx` LAN subnets; no fetch or membership inference | PeeringDB AUP | **restricted** | "Data from PeeringDB" |
| **Local RPKI validator export** | `rpki-vrp-file` | `rpki` | complete validated ROA payloads for route-prefix/origin validation; no fetch, IP-only verdict or traffic blocking | Underlying TAL/repository terms remain the operator's responsibility | **unknown** | Underlying source terms apply; no dataset distributed |
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

### Published service range input

`PROBECTL_FLOW_ENRICH_SERVICE_FILE` imports complete original publisher JSON from
an operator-supplied local cache. The current adapters accept `aws`, `google`
(`goog.json`) and `google_cloud` (`cloud.json`). Nothing is downloaded by this
reader and no dataset ships with probectl. Source terms still apply to internal,
MSP/provider and redistribution use; public access is not a resale licence.

Sources checked on 2026-11-15:

| Publisher | Primary format/use documentation | Scope and terms handling |
| --- | --- | --- |
| AWS | [Traffic identification, local history and validated TLS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html), [original JSON schema and overlaps](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html) | Documentation describes downloading and processing the list to identify AWS traffic. Preserve original service/region labels, including overlaps. Coverage excludes some services and BYOIP. No dataset redistribution or commercial resale grant is asserted. |
| Google | [Published global/regional lists and local processing](https://cloud.google.com/vpc/docs/configure-private-google-access) | Documentation describes local processing of `goog.json` and `cloud.json`. Global ownership alone cannot identify individual Google APIs; cloud ranges label infrastructure available to customers. No dataset redistribution or commercial resale grant is asserted. |

The offline envelope is versioned separately from its unchanged original vendor
documents. `complete:true` attests that the operator imported the full response;
it is not a publisher signature. `fetched_at` is the original successful bulk-fetch
time, copied unchanged during offline transfer. For example (replace the placeholder
with the entire original JSON document, not selected ranges):

```text
{
  "version": 1,
  "sources": [
    {
      "publisher": "aws",
      "fetched_at": "2026-11-15T09:00:00Z",
      "complete": true,
      "data": <complete original ip-ranges.json object>
    }
  ]
}
```

For an explicitly requested online bulk refresh, run:

```sh
probectl opendata fetch-ranges \
  --publishers aws,google,google_cloud \
  --output /operator/cache/service-ranges.json \
  --memory-bytes 268435456 --max-age 24h --timeout 1m
```

This local command fetches only the named canonical public documents, using the
existing certificate-validating TLS client. It sends no API token, tenant,
address lookup or telemetry. It validates all selected complete responses before
atomically replacing the owner-only cache and syncing the file/directory. A
failed, malformed, untrusted-TLS or over-budget fetch leaves the prior cache and
its original clocks unchanged. HTTP `Age` is preserved instead of renewing an
intermediary's cached response. `--memory-bytes` and the per-publisher `--timeout`
can be increased for the complete workload; nothing is truncated. No fetch is
scheduled or enabled by default. Transfer the complete file offline when needed,
then configure `PROBECTL_FLOW_ENRICH_SERVICE_FILE` and restart to import it.

Use an atomic file replacement and restart to load a complete replacement. The
reader admits the whole input, duplicate-key validation, decoder workspace and
index against `PROBECTL_FLOW_ENRICH_SERVICE_MEMORY_BYTES`; inadequate admission
refuses the whole replacement. Raise the configured memory for the intended
complete workload. A malformed or missing input remains visible as unavailable
through the existing source-status and enrichment APIs; telemetry continues.

`GET /v1/opendata/enrichment?ip=<address>` returns `services` entries with each
publisher's original version, JSON digest, publication/fetch clocks, expiry and
all matching service/region/prefix labels. Overlaps remain explicit; a range
match does not establish which hosted application or customer generated traffic.
An unmatched address has no matches. A stale or disabled list also has no matches
and retains its original clocks and status, making unknown attribution visible.
Freshness is checked on every lookup, including a shared IP-cache hit. File
mtime, restart and repeated lookups never renew the source's original fetch time.

These are shared public reference records. Existing tenant authentication and
current `flow.read` authorization still apply; no tenant traffic, address or query
is sent to a publisher. This initial offline reader does not yet add service
dimensions to saved flow queries or claim complete SaaS application detection.

Threat-intel feeds are a **separate** source set (with their own, often
non-commercial, terms) layered on top of this same framework — see
[`threat-intel.md`](threat-intel.md) for that matrix. Cloud-pricing data for cost analytics
reuses the same provenance/AUP model as well. The pattern is deliberate: every
external dataset, whether for enrichment, threat-intel, or pricing, declares its
provenance the same way.

## Local RPKI validator input

An operator may supply an existing validator's complete JSON export using
`PROBECTL_FLOW_ENRICH_RPKI_FILE`. The reader makes no network requests, accepts
the full IPv4/IPv6 VRP population (including AS0 denials and 32-bit ASNs), and
rejects any malformed row, duplicate JSON key or trailing input as a whole.
Unknown metadata is validated completely; it is not silently clipped. The
configured memory/work budgets admit the complete source and can be raised.

The source clock comes from `metadata.generated` (Unix seconds) and/or
`metadata.generatedTime` (RFC3339, preserving fractional seconds), consistent
with [Routinator's JSON output](https://routinator.docs.nlnetlabs.nl/en/latest/output-formats.html).
If both are present their whole seconds must agree. A raw ROA array can be read
but cannot establish freshness without an original generation clock. Copying
the file, changing its modification time, restarting or reading it never
renews that clock. Missing, disabled, expired or ambiguous sources remain
unavailable; they cannot turn missing evidence into a `not_found` verdict.

The primitive follows [RFC6811](https://www.rfc-editor.org/rfc/rfc6811):
`not_found` requires a current complete source with no covering VRP; `valid`
requires a covering VRP matching the route origin and permitted length;
`invalid` means covering VRPs exist but none authorizes that route. AS0
assertions never authorize a route. An unknown/ambiguous route origin remains
`unknown`. Validation reports evidence and never blocks traffic. Authenticated flow capture retains the original source digest, generation
clock, complete covering set and each path verdict in existing tenant-isolated
routing facts. Historical reads preserve that original validation and still
reauthorize the original routing sources and the current reader. Mixed path
verdicts remain unknown in the scalar query field.

No validator data is shipped with probectl. Permission to read a local file is
not permission to download or redistribute repository data: the operator must
comply with the underlying TAL and repository terms. Commercial-use permission
is reported as unknown, not inferred from the protocol specification.
