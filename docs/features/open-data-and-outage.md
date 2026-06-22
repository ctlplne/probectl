# Open-data enrichment and the internet-outage view

## What it is

Two related features that add public context to your own telemetry without ever
sending your telemetry out:

- **Open-data enrichment** answers "what is this address?" When probectl sees an
  IP address, the address alone is not very useful. Enrichment looks it up in
  public datasets and attaches context — which network operator owns it (its
  autonomous-system number, or ASN), which country it is in, whether it sits at
  an internet exchange, and which regional registry allocated it. Enrichment
  means adding context to data you already have, not collecting new data.
- **The internet-outage view** answers "is it us, our ISP, or the wider
  internet?" When a test starts failing, you need to know whether the fault is
  inside your network or out in some Internet Service Provider (ISP) or region
  you do not control. probectl joins two honest inputs — your own failing tests
  and public outage signals — and is explicit about the limits of both. It is
  served at `GET /v1/outages`.

See [glossary](../glossary.md) for ASN, NetFlow / IPFIX / sFlow, and IPS
(Intrusion Prevention System).

## Why it exists

Raw flow records and probe results carry IP addresses, not stories. "AS13335
suddenly became your top talker" is a sentence an operator can act on;
"104.16.0.0/12 became your top talker" is not. Enrichment turns the second into
the first by attaching the operator name, the country, and the exchange-point
presence behind an address. Because public data is the same for everybody,
probectl ingests it once and shares it across all tenants — one reference library,
not a copy per reader — and attaches the result per tenant onto each flow or test
result. The shared lookup is deliberately tenant-agnostic: it returns plain data,
and the caller stamps it onto a tenant-scoped record, so the tenant boundary is
enforced where the data *lands*, not in the shared lookup.

The outage view exists because the first question after any failure is the one
operators waste the most time on: is this my fault? It is the porch-light check —
before blaming your own wiring, you look down the street at your own lamps and at
the utility company's outage map. probectl can honestly know exactly those two
things, so it joins exactly those two things and refuses to pretend it knows more.

## How it works

**Three guardrails on every open-data source.** Every public dataset probectl
reads obeys the same three rules, enforced in code:

- **Fetched over validated TLS, treated as untrusted.** Outbound lookups use a
  hardened HTTPS client whose certificate validation is never disabled, and the
  fetched bytes are parsed as untrusted input — bounds-checked, with malformed
  rows skipped. A public dataset is someone else's bytes; the parser assumes they
  could be hostile. ("TLS" is Transport Layer Security, the encryption-and-identity
  layer under HTTPS.)
- **Degrades gracefully.** A source that is disabled, rate-limited, or failing is
  logged and skipped — it never breaks a core path. Each source runs under a
  timeout, and even a source that crashes is contained, so one flaky dataset
  cannot take enrichment down. A failed source is marked degraded; the rest still
  contribute. Enrichment is garnish, never load-bearing: losing it makes records
  plainer, not absent.
- **Cached aggressively.** Enrichment is cached per address, and each source caches
  its own dataset, so a rate-limited upstream is queried at most once per key.
  Being a polite client of a free public service is part of the contract.

The datasets cover ASN (network operator), geographic country and city,
internet-exchange presence, and allocation registry. The geographic database is
*not* shipped with probectl — you supply the file under its own license and point
probectl at it, which keeps probectl clear of redistributing someone else's data:
you hold the license, probectl just reads your copy. Each source also carries a
machine-readable label describing where the data came from and what you are allowed
to do with it, like a nutrition label printed on every dataset. Those terms are not
a constraint on private use or single-tenant use; they become relevant only if you
resell probectl as a service to many customers, in which case you confirm the
reseller redistribution terms first.

**The outage view joins two inputs.** It builds situational awareness from:

1. **Public outage signals** — fetched opt-in from public internet-outage
   observatories, ingested once (shared across all tenants, never tenant-owned
   data), and cached so a feed failure keeps the last-good events instead of going
   blank. This is the utility's outage map.
2. **Your own vantage points** — the places you already observe the internet
   *from*, which is your synthetic-result stream. probectl never operates a global
   probe fleet; your agents are your vantages.

From those it derives two kinds of finding. A **vantage-detected outage** fires
when several *distinct* targets inside one external scope (an ISP's ASN, or a
country) start failing together — deliberately conservative, so one failing test
alone is never called an outage; that case is what ordinary alerting is for. A
**correlation** fires when one of your failing tests sits inside the scope of an
*active public outage event*, which lets the view say "your checkout test is
failing because that autonomous system is melting."

Both are **signals** into the incident pipeline at warning severity —
situational awareness, not a pager storm — and never an automated action.
Detection is a signal, not an IPS: probectl never blocks traffic on the back of
one. Everything derived from your telemetry (the vantage events and the affected
tests) is tenant-scoped and computed per caller; one tenant's view can reach
nothing from any other tenant. The honesty contract is built into the response:
every reply carries coverage notes, and a degraded mode — feeds off, or
address-to-ASN enrichment off — is stated plainly rather than papered over.
probectl never phones home: the outage feeds and every enrichment lookup are
outbound only when you opt in, and the local outage engine makes no outbound calls
at all.

## Use it

Enrichment that uses outbound lookups is opt-in, because probectl makes no
outbound call by default. Turn on ASN/geo enrichment for flow records:

```sh
# Fill in the network operator and country behind each flow address.
PROBECTL_FLOW_ENRICH_ASN=true ./bin/probectl-control
# Observe: flow records and the /v1/flows/top?by=src_asn view now carry
# source/destination AS numbers, AS organization names, and ISO country codes.
# Device-asserted AS numbers always pass through unchanged; enrichment only
# fills blanks. A down or rate-limited source never blocks ingest.
```

Turn on the public outage feeds, then read the joined view (tenant comes from your
authenticated identity, never from the URL):

```sh
# The local engine (vantage detection + correlation) is on by default and makes
# no outbound calls. Turning on feeds is what creates the outbound fetches.
export PROBECTL_OUTAGE_FEEDS_ENABLED=true
export PROBECTL_FLOW_ENRICH_ASN=true   # needed to resolve a failing peer IP to a scope
./bin/probectl-control

curl -sS "https://localhost:8443/v1/outages"
# Observe a JSON snapshot: shared public events (with deep links to the source),
# your tenant-scoped vantage-detected outages, and any correlations between your
# failing tests and an active event — plus a scope_resolution block and coverage
# notes. With enrichment off, the response still renders and says plainly that
# vantage detection and correlation are unavailable.
```

## Pitfalls & limits

- **Coverage equals your vantage points plus public open data — nothing more.**
  probectl does not run a global probe fleet and never claims to. A region you do
  not test from, and that the public feeds do not cover, is simply not visible.
  The response says so rather than implying full coverage.
- **Confidence and severity are heuristics, not vendor-calibrated probabilities.**
  The scores are documented rules of thumb derived from each source's own signals.
  Treat the outage view as situational awareness, not as a precise measurement.
- **One failing test is never an outage.** Vantage detection requires at least two
  distinct failing targets in a scope, and the episode latches (fires once and
  holds) with a recovery bar set well below the firing bar so a scope hovering at
  the threshold does not flap on and off. A single failing target is a job for
  ordinary alerting.
- **Outbound features are off until you opt in.** Enrichment lookups and outage
  feeds make outbound calls, so they are disabled by default to preserve the
  no-phone-home posture. The geographic database is also not shipped — you supply
  it under its own license.
- **A down source degrades, it never breaks you.** A failing enrichment source
  makes records plainer; a failing outage feed serves its last-good events,
  labeled stale. Neither takes a core path down.
- **Public-data terms matter only for resale.** If you resell probectl as a service
  to many customers, some feeds carry non-commercial or attribution terms you must
  confirm first. Private and single-tenant use is unaffected. The required
  attribution travels with each dataset so a downstream reseller cannot forget it.

## Reference

- Outage endpoint: `GET /v1/outages` (requires the metrics read permission;
  reads the synthetic/metrics plane). Each event carries a `source`, a `scope`
  (the autonomous-system or country join key), `severity` and `confidence`, a
  `start`/`end` window, and a deep link to the source.
- Outage configuration keys: `PROBECTL_OUTAGE_ENABLED` (local engine, default on,
  no outbound calls), `PROBECTL_OUTAGE_FEEDS_ENABLED` (opt-in public feeds,
  default off), `PROBECTL_OUTAGE_FEEDS`, `PROBECTL_OUTAGE_REFRESH`,
  `PROBECTL_OUTAGE_RETENTION`, and the per-feed token for any feed that requires
  one (resolvable as a secret reference, never a literal).
- Enrichment configuration key: `PROBECTL_FLOW_ENRICH_ASN` (opt-in; also gates the
  address-to-scope resolution the outage view uses).
- The five-tuple from a flow record reuses the standard OpenTelemetry
  `source.*`/`destination.*`/`network.*` attribute names; AS and geo enrichment use
  the widely-used Elastic Common Schema names (`source.as.number`,
  `source.as.organization.name`, `source.geo.country.iso_code`) because no
  OpenTelemetry convention covers them.
- Related terms: ASN, prefix, origin AS, RPKI, tenant, and IPS in the
  [glossary](../glossary.md).

**Covers:** F7, F19
