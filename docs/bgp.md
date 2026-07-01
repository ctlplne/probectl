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
  suppressible, and exported to your SIEM. It is not an inline blocker (an **IPS**) and
  will never "fix" BGP for you.
- **The feeds are read-only and degrade gracefully.** Collectors and RPKI data are
  fetched read-only over validated TLS and cached; if a collector goes dark or
  rate-limits you, the rest of the view keeps working and the page tells you the data
  is stale — a flaky upstream never takes your monitoring down.
- **Your data stays yours.** The feeds are public, but which prefixes you care about and
  what probectl finds are scoped to your tenant and never leave your network.
- **Direct router feeds are tenant-authenticated.** A BMP peer's tenant comes from
  its verified SPIFFE client certificate, not from the BMP payload. Unknown or
  plaintext peers are refused before route data is read.

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
timeline:

```json
{
  "event_type": "origin_change",
  "prefix": "203.0.113.0/24",
  "expected_origin": "AS64500",
  "observed_origin": "AS65021",
  "rpki": "invalid",
  "confidence": 0.94,
  "first_seen": "2026-06-22T14:03:11Z"
}
```

You see the prefix, the AS that *should* originate it versus the one that *did*, and
the RPKI verdict — enough to act in seconds.

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
PROBECTL_BMP_BUS_MODE=kafka \
PROBECTL_BMP_BUS_BROKERS=kafka-1:9093 \
PROBECTL_BMP_BUS_TLS_ENABLED=true \
  probectl-bmp-listener
```

Each router/client certificate uses the same tenant-bound identity shape as
probectl agents: `spiffe://probectl/tenant/<tenant>/agent/<router-id>`. The
listener records a per-tenant peer inventory in memory and emits `BGPEvent`
records keyed by that tenant.

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
