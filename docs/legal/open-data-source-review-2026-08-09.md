# External-data commercial-use review — 2026-08-09

## Scope and rule

This is a dated engineering review of official publisher pages, not legal
advice. It covers sources currently modeled in `internal/opendata` and the two
outage feeds documented in `docs/outage.md`.

ELI5: a public tap can let anyone drink while still forbidding a company from
bottling and reselling the water. Therefore:

- `allowed` means the official source page explicitly supports the relevant
  commercial use in terms clear enough for engineering metadata, still subject
  to counsel and the operator's compliance;
- `restricted` means current terms limit commercial use, redistribution, or the
  access method;
- `unknown` means no sufficiently clear source-specific commercial grant was
  established;
- attribution alone never changes a red/yellow status to green.

## Review matrix

| Source / descriptor | Official evidence reviewed | Engineering status | Why / counsel action |
|---|---|---|---|
| Team Cymru IP-to-ASN / `team-cymru` | [IP-to-ASN service](https://www.team-cymru.com/ip-asn-mapping); [commercial data-services terms](https://www.team-cymru.com/terms) | **unknown** | The community page says the lookup is free but does not state a redistribution/resale grant. Obtain written confirmation for MSP use or contract for the commercial data right. |
| MaxMind GeoLite / `maxmind-geolite2` | [GeoLite EULA](https://www.maxmind.com/en/geolite/eula); [site-license/redistribution overview](https://www.maxmind.com/en/site-license-overview) | **restricted** | The EULA includes attribution and an internal-business grant; MaxMind separately offers redistribution licensing. Operator-supplied data avoids probectl shipping the DB but does not grant an MSP permission to expose it to customers. |
| PeeringDB / `peeringdb` | [API-key guide](https://docs.peeringdb.com/howto/api_keys/); [AUP link and docs](https://docs.peeringdb.com/) | **restricted** | PeeringDB's guide says its AUP prevents commercial use. Obtain written permission/terms before commercial provider use. The former repository label “CC BY 4.0 / allowed-with-attribution” was unsupported and was removed. |
| Five RIR delegated-stat files / `rir-stats` | [NRO statistics overview](https://www.nro.net/about/rirs/statistics/); example [RIPE Database terms](https://www.ripe.net/manage-ips-and-asns/db/support/documentation/terms/) | **unknown** | Files come from separate registries and their terms are not a single blanket open-data license. Counsel must review ARIN, RIPE NCC, APNIC, LACNIC, and AFRINIC for the exact file/use; do not infer bulk redistribution rights from public access. |
| Spamhaus DROP / `spamhaus_drop` | [DROP Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/); [commercial data options](https://www.spamhaus.org/blocklists/commercial/) | **restricted** | The DROP policy reserves IP/database rights and limits commercial references to Spamhaus data; the commercial page directs commercial users to subscriptions. Obtain a commercial agreement that covers the product use and attribution wording. |
| Feodo Tracker / `feodo_tracker` | [Feodo blocklist terms](https://feodotracker.abuse.ch/blocklist/) | **allowed** | The dataset page explicitly permits commercial and non-commercial use without limitation under CC0. Preserve source provenance and current endpoint/fair-use behavior. |
| SSLBL cert and JA3 / `sslbl`, `sslbl_ja3` | [SSLBL dataset terms](https://sslbl.abuse.ch/blacklist/) | **allowed** | The dataset page explicitly permits commercial and non-commercial use under CC0. Preserve source provenance and do not convert a noisy signal into automatic blocking. |
| URLhaus / `urlhaus` | [URLhaus community API](https://urlhaus.abuse.ch/api/) | **restricted** | The current API page says commercial/for-profit use may require the enhanced commercial API and now documents authenticated access. Confirm commercial access, endpoint, authentication, limits, and redistribution before MSP use. |
| Tor bulk exit list / `tor_exit` | [bulk exit list](https://check.torproject.org/torbulkexitlist); [Tor data index](https://collector.torproject.org/recent/exit-lists/) | **unknown** | A Tor-hosted CC0 page for unrelated build metadata is not enough to label this dataset CC0. Obtain an official dataset-license answer or counsel analysis before commercial redistribution. |
| FireHOL level 1 / `firehol_level1` | [FireHOL list catalog](https://iplists.firehol.org/) | **restricted** | It aggregates upstream sources with mixed terms. Every upstream right would need to cover the exact snapshot/use; leave restricted. |
| IODA outage feed / `ioda` | [IODA project](https://ioda.inetintel.cc.gatech.edu/) | **unknown** | Academic/public availability does not establish an MSP redistribution right. Obtain written terms for commercial API/service use. |
| Cloudflare Radar / `cloudflare_radar` | [Radar API terms/data license](https://developers.cloudflare.com/radar/) | **restricted** | Repository metadata identifies CC BY-NC 4.0/non-commercial restrictions. Counsel should verify the current endpoint-specific terms and any commercial agreement before provider use. |

## Repository remediation completed

The runtime AUP descriptors and user-facing matrices now use conservative
statuses:

- `restricted`: MaxMind, PeeringDB, Spamhaus DROP, URLhaus, FireHOL;
- `unknown`: Team Cymru, RIR delegated statistics, Tor exit list;
- `allowed`: Feodo Tracker and SSLBL based on their dataset-specific CC0 terms.

All sources remain optional and degrade gracefully. This review did **not** add a
new feed, contact a publisher, accept a new agreement, or create a runtime
commercial-use waiver. Source rights are external facts and remain counsel/MSP
evidence until a written agreement is attached.

## Questions for counsel / rights holders

Use this exact short form for each red/yellow source:

1. May a self-hosted commercial software customer query/use the data internally?
2. May an MSP query once and use derived fields or detections for multiple
   separately isolated customer tenants?
3. May results be displayed to end customers, exported, cached, backed up, and
   retained after the source updates?
4. May raw data be redistributed, or only derived facts? What counts as a
   derivative database?
5. What attribution must appear in UI, API, documentation, and marketing?
6. Are API keys per MSP, per deployment, or per end customer? What rate limits
   and audit/reporting duties apply?
7. Are there geography, sanctions, privacy, or prohibited-use restrictions?
8. What happens to cached/derived data at termination or a terms change?

Recommended evidence record: executed agreement or rights-holder email; exact
source and endpoint; permitted entities/tenants/use; attribution; rate limits;
effective/expiry dates; termination/deletion terms; and counsel approver. Until
that record exists, retain the conservative descriptor.
