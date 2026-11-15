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

Published-range flow attribution is a preview while full real-flow and served
qualification remains outstanding.

`PROBECTL_FLOW_ENRICH_SERVICE_FILE` imports complete original publisher JSON from
an operator-supplied local cache. The current adapters accept `aws`, `google`
(`goog.json`), `google_cloud` (`cloud.json`), `cloudflare` (the public `/ips` API)
and the Salesforce, Azure, Zoom, Microsoft365 and Slack Huddles originals described below. Nothing is downloaded by this
reader and no dataset ships with probectl. Source terms still apply to internal,
MSP/provider and redistribution use; public access is not a resale licence.

Sources checked on 2026-11-15:

| Publisher | Primary format/use documentation | Scope and terms handling |
| --- | --- | --- |
| AWS | [Traffic identification, local history and validated TLS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html), [original JSON schema and overlaps](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html) | Documentation describes downloading and processing the list to identify AWS traffic. Preserve original service/region labels, including overlaps. Coverage excludes some services and BYOIP. No dataset redistribution or commercial resale grant is asserted. |
| Google | [Published global/regional lists and local processing](https://cloud.google.com/vpc/docs/configure-private-google-access) | Documentation describes local processing of `goog.json` and `cloud.json`. Global ownership alone cannot identify individual Google APIs; cloud ranges label infrastructure available to customers. No dataset redistribution or commercial resale grant is asserted. |

Cloudflare sources were checked on 2026-11-15: the [public IP API](https://developers.cloudflare.com/api/resources/ips/methods/list/),
[range usage documentation](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)
and [website/online-service terms](https://www.cloudflare.com/website-terms/).
The API supplies IPv4/IPv6 and optional JD Cloud ranges, with an optional ETag;
network documentation describes local programmatic configuration. Existing source
terms, API limits and prohibited uses apply. No dataset resale or redistribution
grant is asserted. The adapter preserves every supplied family. `region` is empty
because the source does not locate an anycast address in one region. `published_at`
is absent because no generation clock is published. When ETag is absent, `version`
is explicitly `sha256:<embedded-content-digest>`, not an invented publisher version.

Salesforce sources were checked on 2026-11-15: [Hyperforce network-use instructions](https://help.salesforce.com/s/articleView?id=xcloud.hf_ip_ranges_to_allow.htm&language=en_US&type=5)
publish the complete bulk JSON for local network identification and allowlisting.
The [website terms](https://www.salesforce.com/company/legal/sfdc-website-terms-of-service/)
retain publisher ownership and require permission or another lawful basis; the
adapter uses the specifically documented local network workflow and distributes
no dataset.
The adapter imports every IPv4/IPv6 prefix in every provider/region group and
preserves its source region. `salesforce` selects this original export in
`opendata fetch-ranges`; offline import uses the same envelope. The service label
is Salesforce, independent of its AWS/GCP host. Coverage excludes email,
Marketing Cloud, Commerce Cloud and Slack; these must never inherit a Salesforce
label merely from related branding. Publisher terms remain applicable and no
dataset redistribution or resale rights are asserted. The source's `createDate`
has no explicit offset, so `published_time` preserves it and `published_at` stays
absent. The opaque `syncToken` remains its original version.

Azure sources were checked on 2026-11-15: [service-tag documentation](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview)
explicitly links complete downloads for local on-premises processing. Microsoft
terms remain applicable; no dataset resale or redistribution grant is asserted.
`--publishers azure` selects all four original cloud exports. Individual IDs are
`azure_public`, `azure_usgov`, `azure_china` and `azure_germany`. An explicit bulk
refresh discovers the current JSON link from the cloud's fixed Microsoft
Download Center page, using verified TLS. It accepts one unique matching
`download.microsoft.com` cloud file, without credentials, tenant selectors,
encoded paths or query parameters. A failed or ambiguous discovery preserves
the previous cache atomically; no automatic poller is installed.

The reader preserves every published IPv4/IPv6 prefix, original `changeNumber`,
`systemService` and explicit `region`. Generic AzureCloud ownership yields to a
specific service. An unknown global region does not erase a uniquely published
regional match; conflicting known regions remain unknown. When `systemService`
is empty, the tag name is retained, removing only an explicitly matching region
suffix. Neither the weekly filename nor the change number supplies a generation
clock: `published_at` remains absent. Original fetch age is the older of the
discovery response and the JSON response, including HTTP `Age`; cached responses
do not renew source validity. An already stale publisher response remains visibly
stale under the configured freshness profile.

The separate [Microsoft Cloud Germany is retired](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azureauthorityhosts.azuregermany?view=azure-dotnet).
Its still-linked original is retained under `azure_germany` for provenance and
inspection, without current service attribution. This is distinct from current
German regions in the public Azure cloud.

Slack sources were checked on 2026-11-15: the [Huddles network guide](https://slack.com/help/articles/36284146785427-Guide-to-network-and-system-configuration-for-Slack-huddles)
publishes shared Amazon Chime media paths. `--publishers slack` selects this
scoped original under ID `slack_huddles`. The adapter imports every native CIDR
in that document's Huddles network-path lists, preserving the complete HTML,
original body digest and fetch age. It supports both address families when
published; it does not invent absent IPv6 coverage. Region and publication clock
remain unknown and the version is explicitly a local `sha256:` content identity.
Malformed or incomplete documents preserve the previous cache atomically.
Source-specific local network use is described by the guide; Slack/Salesforce
terms and rights remain applicable, with no dataset resale or redistribution
grant asserted.

These are **shared network dependencies**, not an exclusive Slack allocation.
Matching candidates remain visible as `Slack Huddles network dependency`, but
they cannot establish Slack application attribution. General [Slack network
guidance](https://slack.com/help/articles/360001603387-Manage-Slack-connection-issues)
uses authenticated per-workspace URL allowlists. Those are not a public bulk IP
allocation: probectl does not resolve them, send account context, or turn general
AWS/Salesforce hosting into a Slack label. Broader exclusive Slack attribution
requires a suitable authoritative prefix source; unrelated flows remain unknown.

Zoom sources were checked on 2026-11-15: the [network firewall/proxy guide](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548)
publishes the product/family TXT files for local operator network configuration.
[Zoom terms](https://www.zoom.com/en/trust/terms/) retain Zoom and third-party
rights; no dataset redistribution or resale licence is asserted. All fetches are
explicit bulk HTTPS requests without tenant, credential, address or query selectors.

`--publishers zoom` fetches the full bundle below. Individual IDs select exactly
one published file; choosing a subset does not imply complete Zoom coverage.
Version-two offline `data` contains the exact TXT contents as a JSON string,
including its original line endings. Both CIDRs and bare IPv4/IPv6 hosts are
accepted; a bare host has exactly `/32` or `/128` scope. Each source keeps its own digest, fetch age
and expiry. No publication clock or geographic region is supplied, so those
values remain unknown. A malformed, invalid-UTF-8 or wrong-family file rejects
the entire refresh and preserves the previous cache and clocks.

| Offline/individual publisher ID | Original file | Published scope |
| --- | --- | --- |
| `zoom_common` | [Zoom.txt](https://assets.zoom.us/docs/ipranges/Zoom.txt) | Zoom |
| `zoom_meetings_ipv4` | [ZoomMeetings.txt](https://assets.zoom.us/docs/ipranges/ZoomMeetings.txt) | Meetings IPv4 |
| `zoom_meetings_ipv6` | [ZoomMeetings-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomMeetings-IPv6.txt) | Meetings IPv6 |
| `zoom_crc` | [ZoomCRC.txt](https://assets.zoom.us/docs/ipranges/ZoomCRC.txt) | Cloud Room Connector |
| `zoom_phone_ipv4` | [ZoomPhone.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone.txt) | Phone IPv4 |
| `zoom_phone_ipv6` | [ZoomPhone-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-IPv6.txt) | Phone IPv6 |
| `zoom_phone_tcp443` | [ZoomPhone-TCP443.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-TCP443.txt) | Phone TCP 443 |
| `zoom_phone_tcp5091` | [ZoomPhone-TCP5091.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-TCP5091.txt) | Phone TCP 5091 |
| `zoom_phone_tcp390` | [ZoomPhone-TCP390.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-TCP390.txt) | Phone TCP 390 |
| `zoom_phone_udp3478` | [ZoomPhone-UDP3478.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-UDP3478.txt) | Phone UDP 3478 |
| `zoom_phone_udp20000_64000` | [ZoomPhone-UDP20000-64000.txt](https://assets.zoom.us/docs/ipranges/ZoomPhone-UDP20000-64000.txt) | Phone UDP 20000–64000 |
| `zoom_contact_center_ipv4` | [ZoomCC.txt](https://assets.zoom.us/docs/ipranges/ZoomCC.txt) | Contact Center IPv4 |
| `zoom_contact_center_ipv6` | [ZoomCC-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomCC-IPv6.txt) | Contact Center IPv6 |
| `zoom_contact_center_widget` | [ZCCFlowScriptCallWidget.txt](https://assets.zoom.us/docs/ipranges/ZCCFlowScriptCallWidget.txt) | Widget network dependency |
| `zoom_virtual_agent_ipv4` | [ZoomZVA.txt](https://assets.zoom.us/docs/ipranges/ZoomZVA.txt) | Virtual Agent IPv4 |
| `zoom_virtual_agent_ipv6` | [ZoomZVA-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomZVA-IPv6.txt) | Virtual Agent IPv6 |
| `zoom_virtual_agent_widget` | [ZVAFlowScriptCallWidget.txt](https://assets.zoom.us/docs/ipranges/ZVAFlowScriptCallWidget.txt) | Widget network dependency |
| `zoom_cdn_ipv4` | [ZoomCDN.txt](https://assets.zoom.us/docs/ipranges/ZoomCDN.txt) | CDN network dependency IPv4 |
| `zoom_cdn_ipv6` | [ZoomCDN-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomCDN-IPv6.txt) | CDN network dependency IPv6 |
| `zoom_apps` | [ZoomApps.txt](https://assets.zoom.us/docs/ipranges/ZoomApps.txt) | Apps network dependency |
| `zoom_apps_ipv6` | [ZoomApps-IPv6.txt](https://assets.zoom.us/docs/ipranges/ZoomApps-IPv6.txt) | Apps network dependency IPv6 |
| `zoom_pso_ipv4` | [ZoomPSO.txt](https://assets.zoom.us/docs/ipranges/ZoomPSO.txt) | PSO Network Assessment IPv4 |

Apps, widget and CDN lists contain shared infrastructure dependencies. Their
matches remain visible in source provenance but cannot, alone, classify traffic
as a Zoom application. Specific service lists supersede the generic Zoom list
and generic AWS EC2/AMAZON or Google hosting ownership. Conflicting specific
services stay ambiguous. Every flow is counted once, including unknown traffic.

Microsoft 365 sources were checked on 2026-11-15: the [web-service documentation](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service)
explicitly supports customers and network-device vendors identifying traffic;
[Learn terms](https://learn.microsoft.com/en-us/legal/termsofuse) and applicable
operator agreements remain in force. No dataset redistribution rights are asserted.

`--publishers m365` fetches all four instances. Individual offline/bulk IDs are
`m365_worldwide`, `m365_china`, `m365_usgovdod` and `m365_usgovgcchigh`.
Provide `--m365-client-request-id <machine-GUID>` for online fetching. Generate
one random GUID for that machine and reuse it; it is a public client association,
not a tenant or login credential. It is not retained in the shared cache or output.
No tenant name, service-area filter or IPv6 exclusion is sent. Offline imports
need no GUID and make no network calls.

Microsoft recommends checking its version service at most hourly and downloading
endpoints after a version change. Refresh is explicit, with no scheduled polling,
retry or GUID rotation to evade throttling. Failure preserves the previous cache.
Original endpoint JSON, including URL-only records, is retained; URLs are never
resolved into invented IP ranges. Service labels preserve area keys such as
`Microsoft 365 Exchange` and `Microsoft 365 Skype`. Region/publication time remain
unknown. Because the endpoints payload has no publisher version, `version` is
explicitly the local `sha256:<original-document-digest>` content ID.

Google's current `creationTime` values can omit a timezone offset. The reader
preserves that exact calendar text as `published_time`; it does not guess UTC,
use the operator host's timezone or reinterpret an opaque `syncToken` as a clock.
`published_at` is emitted only when an absolute source time can be established.
Source validity continues to use the original successful bulk-fetch time, so an
unresolved publication offset does not reject an otherwise complete valid list
or renew a cached response's age.

The offline envelope is versioned separately from its unchanged original vendor
documents. Bulk refresh writes version 2: `data` is a JSON string containing the
complete original UTF-8 document, including leading/trailing whitespace and
line endings. Decoding reconstructs those exact bytes, and `digest` hashes them.
Quoted document contents are independently validated; nested duplicate keys or
malformed originals reject the whole cache. Offline copy and restart preserve
both the digest and original fetch age. Version 1 remains readable for existing
operator files; its `data` is an embedded JSON value and its digest covers that
value, without whitespace outside it. Version and document encoding must agree.
`complete:true` attests that the operator imported the full response;
it is not a publisher signature. `fetched_at` is the original successful bulk-fetch
time, copied unchanged during offline transfer. For an existing version-one file
(replace the placeholder with the entire original JSON value, not selected ranges):

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
publisher's original version, document digest, publication/fetch clocks, expiry and
all matching service/region/prefix labels. Overlaps remain explicit; a range
match does not establish which hosted application or customer generated traffic.
An unmatched address has no matches. A stale or disabled list also has no matches
and retains its original clocks and status, making unknown attribution visible.
Freshness is checked on every lookup, including a shared IP-cache hit. File
mtime, restart and repeated lookups never renew the source's original fetch time.

In the Flow Explorer, **Published service sources** looks up an IPv4 or IPv6
address against the same local source index. Expand a publisher to inspect every
matching candidate, its explicit region, original fetch/validity clocks, native
version and body digest. A missing publication time or region stays unknown.
The view removes expired matches while retaining their original metadata, clears
the previous lookup on tenant/user/access changes, and makes no publisher calls.
This is current source inspection; stored flow labels remain capture-time facts.

### Service attribution on stored flows

The control plane derives `src_service`, `src_service_region`,
`src_service_provider`, `src_service_status` and the corresponding `dst_*`
fields after tenant admission and original-flow fingerprinting. Agents cannot
assert these storage-only fields. They are available to the structured flow
query registry, including grouping, filtering, charts and matrices; the same
registry drives SDK/CLI/UI/native operations.

Classification uses the most specific current published range. Documented
supersets do not hide their specialized labels: AWS `AMAZON` yields to its
service subsets, S3 membership excludes the EC2 fallback, and Google Cloud
membership specializes generic Google ownership. Published SaaS-specific ranges
supersede generic hosting ownership, while network dependencies alone do not
assert an application. Equal-specificity conflicts
between services remain ambiguous, with an empty service/provider. Conflicting
regions remain empty while a unique known service is retained. This is range
attribution, not proof of a hosted application or customer.

Every original flow remains one observation. Matching three overlapping labels
does not triple its bytes or packets. Per-flow provenance retains all original
candidate/source metadata and a separate classification clock; it never changes
the original signed-flow capture, observation time or deduplication identity.
The local source index is consulted directly, independently of asynchronous
ASN/geo warming. Expired, disabled or unavailable source data makes **new**
classifications unknown and does not stop telemetry collection.

Retained classifications are historical capture facts. Changing or expiring a
catalogue never substitutes today's service labels into an older flow. Older
records without attribution remain unknown. The additive raw/rollup schema
preserves both history and tenant partitions. Additional buffered attribution
is flushed in complete chunks under the existing source memory profile; there
is no flow-count ceiling, candidate truncation or partially acknowledged batch.
Original traffic still follows the normal retry/dead-letter contract.

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
