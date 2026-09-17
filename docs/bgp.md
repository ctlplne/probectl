# BGP & routing monitoring — know the moment the internet starts sending your traffic the wrong way

## What it is

**BGP** (Border Gateway Protocol) is how the tens of thousands of independent networks
that make up the internet tell each other where your addresses live: "to reach
`203.0.113.0/24`, send the traffic to me." Each network is an **autonomous system**,
identified by an **ASN** (autonomous system number, e.g. `AS64500`). BGP monitoring is
probectl listening to that global conversation for the parts that mention *your*
address blocks — and telling you when something looks wrong.

Think of BGP as the world's gossip-based postal routing: there's no central map, every
post office just tells its neighbors which mail it can deliver, and they pass it on. It
works astonishingly well — until someone, by mistake or malice, announces "send me all
the mail for that street," and the neighbors believe them. Monitoring is the smoke
detector for that moment.

## Why it exists

Two things go wrong in BGP, both routinely, and both invisible from inside your own
network:

- A **hijack** — another network announces your address block, or a *more-specific*
  slice of it (a smaller block, which always wins), and traffic meant for you flows to
  them instead. This is how interception and sudden outages happen.
- A **route leak** — a network re-announces routes it shouldn't, and traffic that
  should take a short, trusted path detours through a congested or hostile one.

The cruel part: your own dashboards stay green the whole time, because the fault is
*upstream*, in how the rest of the world routes toward you. You want this if you run
your own address space, peer with anyone, or have ever watched traffic disappear while
every internal light stayed on.

## How it works

The model: listen to what the world is saying about your prefixes, and compare it to
what *should* be true.

1. **Listen.** probectl reads a live feed of BGP announcements from public **route
   collectors** — independent vantage points run by RouteViews and RIPE **RIS**
   (Routing Information Service) that record what they hear other networks announce.
   The archived form of that feed is **MRT** (a standard binary record format,
   **RFC 6396**). If you operate routers that export BMP (BGP Monitoring
   Protocol), `probectl-bmp-listener` can also accept their direct route-monitoring
   stream over mTLS and publish it into the same tenant-scoped event path.
2. **Filter to you.** It keeps only the announcements that touch the prefixes you've
   declared as yours.
3. **Check against ground truth.** For each one it asks: did the **origin AS** change?
   Is there a new more-specific prefix (a hijack's signature)? And, using **RPKI**
   (Resource Public Key Infrastructure — a signed registry of which AS is *allowed* to
   originate which prefix), is the announcement **ROA**-valid, ROA-invalid, or unknown?
   A ROA-invalid origin change for your prefix is a high-confidence alarm.
4. **Correlate.** A confirmed anomaly becomes one entry on your incident timeline, tied
   to the other planes (e.g. the synthetic tests that began failing the same second) —
   not a lonely BGP alert you have to interpret by yourself.

What probectl guarantees you:

- **It only watches — it never touches routing.** probectl does not announce, withdraw,
  or filter a single route. Detections are *signals*: confidence-scored, tunable,
  suppressible (one event per prefix, kind and origin per `event_suppression_seconds`
  window, 5 minutes by default — a real anomaly is otherwise re-announced by every
  collector peer on every update; DPR-056), and exported to your SIEM. It is not an inline blocker (an **IPS**) and
  will never "fix" BGP for you.
- **The feeds are read-only and degrade gracefully.** The only feed the analyzer
  fetches itself is RPKI VRP data — read-only over validated TLS, refreshed per run,
  never cached to disk, **streamed** and reduced to the ROAs that overlap your
  monitored prefixes as it arrives (a full validator export, ~100 MB and 600k
  ROAs, costs the sidecar a few MB of memory and is bounded at 1 GiB; DPR-055) —
  and a failed fetch degrades that run to RPKI *unknown*
  instead of stopping analysis. Collector archives (RouteViews / RIS MRT dumps) are
  bring-your-own artifacts you download and decompress yourself; RIS Live streaming
  reads RIPE's public websocket. A flaky upstream never takes your monitoring down.
- **Your data stays yours.** The feeds are public, but which prefixes you care about and
  what probectl finds are scoped to your tenant and never leave your network.
- **Direct router feeds are tenant-authenticated.** A BMP peer's tenant comes from
  its verified SPIFFE client certificate, not from the BMP payload. Unknown or
  plaintext peers are refused before route data is read.
- **Collector ingestion is per tenant (decision of record).** Each tenant's
  analyzer subprocess consumes its own feed — one RIS Live websocket and its own
  supplied MRT artifacts per tenant — so N monitored tenants means N feed
  consumers. This is deliberate at current scale: binding the tenant at the
  process boundary keeps cross-tenant state out of the analyzer entirely. The
  trigger condition and design for a shared ingest-once fan-out (one collector
  consumer, per-tenant scoping at publish) are recorded in
  [`docs/adr/bgp-ingest-model.md`](adr/bgp-ingest-model.md).

## Use it

Declare your prefixes, then ask the assistant in plain language — the natural-language
query surface is `POST /v1/ai/ask`:

```sh
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"any routing anomalies for my prefixes in the last 6 hours?"}' \
  https://probectl.example.com/v1/ai/ask
```

A clean result reads like:

> No origin changes or ROA-invalid announcements for `203.0.113.0/24` or
> `198.51.100.0/24` in the last 6h. Last collector update 41s ago (RouteViews, RIS).

When something is wrong, probectl emits a routing event you'll also see on the incident
timeline. `GET /v1/bgp/events` (filters `prefix`, `asn`, `limit`) lists them in the
shape the API really returns — the event is an incident signal, so it carries its
incident id and the correlation verdict next to the detection context (DPR-057):

```json
{
  "id": "4031a404-aca0-4e8a-b2c9-12a215dba519",
  "incident_id": "4031a404-aca0-4e8a-b2c9-12a215dba519",
  "kind": "bgp.possible_hijack",
  "severity": "critical",
  "title": "203.0.113.0/24 announced by unexpected AS65021 (expected [64500])",
  "prefix": "203.0.113.0/24",
  "attributes": {
    "collector": "rrc00",
    "confidence": "0.85",
    "expected_origins": "64500",
    "new_origin_asn": "65021",
    "new_as_path": "64511,65021",
    "peer_asn": "64511",
    "rpki_status": "RPKI_STATUS_INVALID",
    "correlation.state": "grouped"
  },
  "occurred_at": "2026-06-22T14:03:11Z"
}
```

You see the prefix, the AS that *should* originate it versus the one that *did*, and
the RPKI verdict — enough to act in seconds.

Run the public-collector analyzer through its shipped tenant-bound bridge (the
sidecar is opt-in and needs the same TLS Kafka settings as the control plane):

```sh
PROBECTL_BGP_ANALYZER_CONFIG=/etc/probectl/bgp/analyzer.json \
PROBECTL_BGP_ANALYZER_SOURCE=mrt \
PROBECTL_BGP_ANALYZER_SOURCE_FILE=/var/lib/probectl/routes.mrt \
PROBECTL_BUS_MODE=kafka \
PROBECTL_BUS_BROKERS=kafka-1:9093 \
PROBECTL_BUS_TLS_ENABLED=true \
  probectl-control bgp-analyzer
```

The Go supervisor treats the JSON config's `tenant_id` as the trusted binding,
rejects a Python payload that claims any other tenant, and only then publishes
the canonical protobuf. A Python crash backs off and restarts without affecting
the API or other telemetry planes. For a deterministic local proof, run the
Compose `bgp-analyzer` profile documented in `deploy/compose/eval.yml`.
The source must be selected explicitly. The stock sidecar image supports MRT
and recorded RIS replay; live RIS streaming requires the analyzer's separately
documented optional `websockets` package in a custom analyzer image.

To ingest direct router BMP streams, run the listener with a server certificate and
the CA that signs router/client certificates:

From the product surface, go to **Admin & Settings > Agents > Register
collector**, choose **BGP**, and enter a source label such as `rrc00`. The
control plane mints and consumes a one-time tenant token without the browser
sending `tenant_id`, then returns the BMP env/YAML hints, `source_type: bmp`,
and the startup command. Automation can call the same surface with:

```sh
probectl bgp setup --body '{"token":"pjt_...","plane":"bgp","hostname":"rrc00"}'
```

```sh
PROBECTL_BMP_LISTEN_ADDR=:1179 \
PROBECTL_BMP_TLS_CERT_FILE=/etc/probectl/bmp/tls.crt \
PROBECTL_BMP_TLS_KEY_FILE=/etc/probectl/bmp/tls.key \
PROBECTL_BMP_TLS_CA_FILE=/etc/probectl/agent-ca.crt \
PROBECTL_BMP_DATABASE_URL='postgres://bmp_registry@postgres:5432/probectl?sslmode=verify-full' \
PROBECTL_BMP_REVOCATION_DATABASE_URL='postgres://bmp_revocation@postgres:5432/probectl?sslmode=verify-full' \
PROBECTL_BMP_BUS_MODE=kafka \
PROBECTL_BMP_BUS_BROKERS=kafka-1:9093 \
PROBECTL_BMP_BUS_TLS_ENABLED=true \
  probectl-bmp-listener
```

Register each router through the existing collector enrollment surface with a
router-owned CSR:

```sh
probectl collector register --body '{"token":"pjt_...","plane":"bmp","hostname":"edge-router-1","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}'
```

The private key stays on the router. The response returns a registry-issued
`spiffe://probectl/tenant/<tenant>/bmp/<router-id>` SVID, its serial and expiry,
and the operator-owned CA bundle. The listener accepts only that BMP plane and
checks the exact tenant/router/SPIFFE/serial tuple in the existing identity
registry before reading a BMP frame. A CA-valid self-issued SVID and an
agent-plane SVID both fail closed. Rotation uses the existing
`/enroll/agent/rotate` proof path; `probectl agent revoke <router-id>` or
`POST /v1/agents/{id}/revoke` uses the existing identity/serial revocation
lifecycle. There is no separate BMP identity system.

The standalone listener loads the existing registry's authoritative revocation
snapshot before it binds and refreshes it every 30 seconds. The revocation DSN
must use PostgreSQL `sslmode=verify-full` and a login granted only the
`probectl_bmp_revocation_reader` NOLOGIN role. If the initial read fails,
startup fails closed; if a later bounded refresh fails, the last valid list is
retained. This is a local intra-deployment connection and never phones home.

The listener bounds peer-controlled resources by default: an mTLS handshake has
10 seconds, each complete BMP header and payload has 2 minutes, and at most 256
sessions are admitted concurrently. Override these limits with
`PROBECTL_BMP_HANDSHAKE_TIMEOUT`, `PROBECTL_BMP_READ_TIMEOUT`, and
`PROBECTL_BMP_MAX_SESSIONS` (or the matching command-line flags). Values must be
positive. A full listener refuses excess sockets immediately and exports
`probectl_agent_active_sessions`,
`probectl_agent_session_timeouts_total`, and
`probectl_agent_session_rejections_total` without tenant or peer labels.

Each embedded BGP UPDATE also has fixed, non-configurable parser safety limits:
at most 512 AS-path entries, 4,096 announced prefixes, and 262,144 aggregate
AS-path-entry × announcement work units. The listener checks these limits before
constructing route announcements and shares one immutable decoded AS path across
the update instead of copying it for every prefix. An UPDATE over any limit is
logged and skipped without publishing or adding it to peer inventory; the
authenticated session can continue with its next valid BMP frame.

## Performance and freshness

Live BMP/router events are treated like an alarm bell, not like a nightly
report. Once a tenant-authenticated route event lands on `probectl.bgp.events`,
the hot-path target is: p50 <= 250 ms, p95 <= 2 s, and p99 <= 5 s from route
event consume to tenant-scoped incident evidence. The SLO row is
`hp-bgp-route-event-to-incident` in [perf-hotpaths.md](perf-hotpaths.md), and
the runnable receipt is:

```sh
go test -tags integration ./internal/control \
  -run '^TestBGPCollectorRegistrationReturnsBMPConfigAndPublishBinding$' \
  -count=1 -v
```

Archived MRT and public RouteViews/RIS replay are different: they are a batch
freshness path, not the live alerting path. Release evidence for batch routing
feeds records the source event timestamp, replay command, ingest timestamp, and
maximum staleness. The GA target is max staleness <= 5 minutes for packaged or
cached replay fixtures, with no live public collector access required in
default CI.

## Pitfalls & limits

- **It's a signal, not a shield.** probectl tells you about a hijack; stopping it
  (calling your upstream, pushing the RPKI fix) is still your move. By design — see
  [limitations.md](limitations.md).
- **You only see what the collectors and your routers see.** Public vantage points
  are broad but not omniscient; a hijack visible only deep inside one region may
  never reach a collector. Direct BMP improves your own routing-fabric view, but
  it still cannot see the whole internet by itself.
- **RPKI "unknown" is not "safe."** Many legitimate prefixes still have no ROA; an
  unknown verdict lowers confidence rather than raising an alarm, so you'll tune
  thresholds to your own address space.

## Reference

- Inputs: public route collectors (RouteViews, RIPE RIS); direct router BMP
  route-monitoring sessions; RPKI origin validation; MRT (RFC 6396) for archived
  records.
- Event types: `origin_change`, `possible_hijack`, `possible_leak`,
  `rpki_invalid`.
- Config: the prefix allow-list you monitor, collector endpoints, and per-type
  confidence thresholds (see [configuration.md](configuration.md)).
- Standards: BGP (RFC 4271), RPKI prefix-origin validation (RFC 6811).

## See also

[Internet-outage view](outage.md) · [Live topology graph](topology.md) ·
[glossary](glossary.md) (BGP, ASN, prefix, origin AS, RPKI, ROA, route leak, MRT)

**Covers:** F6
