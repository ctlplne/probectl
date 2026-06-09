# Flow analytics — NetFlow / IPFIX / sFlow

## What this is

Every router and switch can tell you, after the fact, *who talked to whom*: it
summarizes the packets it forwarded into **flow records** (a 5-tuple — source IP,
destination IP, source port, destination port, protocol — plus byte/packet
counts) and ships them off the box. NetFlow, IPFIX, and sFlow are the three
common wire formats for that export.

probectl's **flow plane** is the passive, after-the-fact view of real traffic —
the complement to the active testing plane (synthetic probes the agent sends on
purpose). Network gear exports flow records to a small collector,
`probectl-flow-agent`; the collector decodes every format into one normalized,
tenant-bound record; the control plane enriches and stores them in ClickHouse;
and the API serves the three questions operators actually ask of flow data:
*who are my top talkers, is a link filling up, and is anything anomalous?*

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  R[routers / switches<br/>NetFlow v5/v9 · IPFIX · sFlow v5] -- UDP --> C[probectl-flow-agent<br/>decode · templates · sampling]
  C -- "probectl.flow.events (FlowBatch, tenant-keyed)" --> B[(bus)]
  B --> P[control-plane FlowConsumer<br/>verify tenant · ASN/geo enrich (opt-in)]
  P --> S[(ClickHouse probectl_flows<br/>tenant-first partition + ORDER BY)]
  S --> API["/v1/flows/top · /v1/flows/capacity · /v1/flows/anomalies"]
```

The path through the code is worth holding in your head, because every other
section is just a zoom-in on one arrow:

1. devices export UDP datagrams to the collector (`internal/flow/collector.go`);
2. the collector decodes them into a normalized `Record` and emits a
   `FlowBatch` on the bus topic `probectl.flow.events`
   (`internal/flow/emit.go`);
3. the control plane's `FlowConsumer` (`internal/pipeline/flow.go`) verifies the
   tenant, optionally enriches ASN/geo, and inserts rows into ClickHouse
   (`internal/store/flowstore/`);
4. the `/v1/flows/*` handlers (`internal/control/flows.go`) run the analytics
   queries, tenant-scoped, against that store.

## Wire protocols

The collector binds three UDP listeners — one socket shared by NetFlow v5 and
v9 (it sniffs the version word in the header), plus IPFIX and sFlow on their own
IANA ports. Disable any listener you don't run.

| Protocol   | Port (default) | Notes                                                                   |
| ---------- | -------------- | ----------------------------------------------------------------------- |
| NetFlow v5 | `:2055`        | fixed-layout records; sampling interval lives in the v5 header          |
| NetFlow v9 | `:2055`        | template-based (RFC 3954); shares the v5 socket (version-sniffed)       |
| IPFIX      | `:4739`        | RFC 7011; unknown/enterprise + variable-length fields are skipped by their declared length |
| sFlow v5   | `:6343`        | raw-packet-header samples, parsed Ethernet / 802.1Q / IPv4 / IPv6 / TCP / UDP far enough for the 5-tuple |

**Templates (v9 / IPFIX).** Unlike v5's fixed layout, v9 and IPFIX describe
their record shape in a *template* the exporter sends periodically; a data
record is undecodable until its template arrives. Data that shows up before its
template is counted as a **template miss** and dropped — the exporter re-sends
templates on its refresh cycle, so the gap self-heals. Template state is keyed
per `(exporter, observation domain)`, expires on a TTL (default 30m,
`PROBECTL_FLOW_TEMPLATE_TTL`), and is size-capped (default 4096,
`PROBECTL_FLOW_MAX_TEMPLATES`) so a hostile or misconfigured exporter cannot
grow collector memory without bound.

**Sampling.** High-rate links don't export every flow — they sample (say, 1 in
1000) to keep export volume sane. A record that represents 1-in-N traffic would
undercount by Nx if you trusted its raw counters, so every `Record` keeps the
**raw exported counters** *and* the sampling rate, and carries pre-scaled
estimates (`bytes_scaled = bytes × rate`, `packets_scaled = packets × rate`)
that all analytics read. The rate is sourced — in precedence order — from the v5
header, the v9/IPFIX options-template sampler elements (information elements
34 / 50 / 305), an inline element, or the sFlow sample itself. Unsampled traffic
is rate 1, so scaling is always safe (it never multiplies by zero).

## Normalized record and its OpenTelemetry names

All four formats decode into one `Record` (`internal/flow/model.go`), serialized
on the bus as `probectl.flow.v1.FlowRecord`. The schema was modeled on
OpenTelemetry conventions from its first field, so the OTLP layer *exposes* these
signals rather than remapping them. The mapping (see
[`otel-mapping.md`](otel-mapping.md)):

- the 5-tuple uses the standard OTel keys — `source.address`, `source.port`,
  `destination.address`, `destination.port`, `network.transport`
  (`tcp` / `udp` / `icmp`, or the IP protocol number as a string when there's no
  standard name), `network.type` (`ipv4` / `ipv6`);
- flow-specific detail with no OTel home uses the `probectl.flow.*` namespace —
  `probectl.flow.exporter.address` (the device that emitted the datagram),
  `probectl.flow.protocol` (`netflow5` | `netflow9` | `ipfix` | `sflow5`),
  `probectl.flow.interface.in` / `.interface.out`, `probectl.flow.sampling.rate`;
- enrichment uses the ECS-aligned `source.as.number`,
  `source.as.organization.name`, `source.geo.country.iso_code` (and the
  `destination.*` equivalents), because OTel has no AS/geo convention.

## Security posture

Flow export is **plaintext UDP with no authentication — by protocol design**
(the same reality every flow collector lives with). probectl treats it as an
untrusted ingestion surface (CLAUDE.md §7 guardrail 12):

- every datagram is **untrusted input**: decoders are pure and bounds-checked,
  record counts and template state are capped, and malformed input is counted
  and dropped — never a panic in a production path;
- the tenant on every record comes from the **collector's own tenant binding**
  (its config / SPIFFE identity), never from anything the datagram claims — a
  datagram cannot assert which tenant it belongs to;
- deploy the collector **adjacent to its exporters** (management network / same
  site) so flow datagrams never cross an untrusted segment;
- everything downstream of the collector rides the standard authenticated paths
  (bus → control plane → ClickHouse over HTTP(S)). The control-plane consumer
  re-verifies each batch's claimed tenant against the agent registry and drops
  unverifiable batches fail-closed.

## Enrichment (opt-in)

Raw flow records often lack the AS number and country of an IP. The
control-plane consumer can fill `source.as.number` / `destination.as.number`,
the AS organization name, and the ISO country code via the opendata enricher —
but it is **opt-in** (`PROBECTL_FLOW_ENRICH_ASN=true`), because the Team Cymru
lookups it uses are outbound DNS and probectl never phones home by default.
Device-asserted AS numbers (NetFlow v5/v9/IPFIX can export them) always pass
through and are never overridden — enrichment only fills blanks, is cached, and
degrades gracefully: a down or rate-limited source never blocks ingest.

## Storage

Records land in the ClickHouse table `probectl_flows`, created idempotently by
the flow store (`internal/store/flowstore/clickhouse.go`):

- `PARTITION BY (tenant_id, toYYYYMMDD(ts))` and
  `ORDER BY (tenant_id, ts, exporter, src_addr, dst_addr)` — the tenant leads
  both keys, so a tenant-scoped read prunes at the storage layer (it never scans
  another tenant's data, which is the tenancy guardrail enforced *below* the
  query) and a single day's parts stay bounded even at NetFlow volumes;
- `PROBECTL_FLOW_RETENTION_DAYS=N` (when > 0) applies a ClickHouse delete-TTL
  (`toDateTime(ts) + INTERVAL N DAY DELETE`);
- a `memory` store (the default) implements the same `Store` contract for the
  lightweight / single-node deploy, and is the reference implementation the
  ClickHouse SQL must agree with (the two share one anomaly detector, so both
  backends flag identically).

In siloed/hybrid isolation, a per-tenant ClickHouse database holds that tenant's
`probectl_flows` table; the store routes each tenant to its target and **fails
closed** on any routing error rather than landing a siloed tenant's rows in the
pooled table.

## Query API (tenant-scoped, `flow.read`)

Three read endpoints, all gated by the `flow.read` permission and scoped to the
authenticated principal's tenant before any value is read (the tenant never
comes from a query parameter):

```text
GET /v1/flows/top?by=src|dst|pair|src_asn|dst_asn&window=1h&limit=10
GET /v1/flows/capacity?exporter=&direction=in|out&window=1h&bucket=3m
GET /v1/flows/anomalies?window=1h&bucket=3m&k=3&min_bps=1000
```

- **Top-talkers** aggregates the sampling-corrected bytes / packets / flow-counts
  by the requested key and returns the highest contributors (`limit` defaults to
  10, capped at 1000). `by=pair` groups source→destination; `by=src_asn` /
  `dst_asn` group by enriched AS number.
- **Capacity** buckets per-`(exporter, interface)` throughput into bps/pps over
  time. `direction` selects which interface (ingress/egress) to group by
  (default `in`); `bucket` defaults to `window/20`, with a one-minute floor.
- **Anomalies** runs the capacity series through a baseline detector: for each
  interface, the latest bucket is compared against the mean + `k`·stddev of its
  *own* preceding buckets (it needs at least three baseline buckets plus the one
  under test). `k` defaults to 3 and `min_bps` to 1000 (so tiny links don't
  trip). The same detector runs over both store backends.

## Operations

- The collector logs a stats line every 60s with: packets, records, decode
  errors, template misses, queue drops, emit errors, dropped records (telemetry
  lost after emit retries were exhausted — never silently), and cached
  templates. probectl observes probectl.
- **High-volume tuning.** Raise `PROBECTL_FLOW_READ_BUFFER_BYTES` (the kernel
  socket buffer that absorbs bursts) and `PROBECTL_FLOW_WORKERS` (readers per
  socket) first. Queue overflow is *counted*, not back-pressured: on a UDP
  reader, back-pressure only moves the drop into the kernel, so probectl drops
  visibly and keeps a counter instead.
- Decode throughput is gated in CI (`TestHighVolumeDecode`, with a deliberately
  conservative 50k records/s floor so slow runners stay green; real hardware is
  far above it).

## Example

```bash
# collector (run it near the devices)
PROBECTL_FLOW_TENANT=t-acme PROBECTL_FLOW_BUS_MODE=kafka \
PROBECTL_FLOW_BUS_BROKERS=localhost:9092 ./bin/probectl-flow-agent

# point a device at it (Cisco-style)
# flow exporter EXP destination <collector-ip> transport udp 2055

# ask the API (tenant comes from the authenticated principal, not the URL)
curl -s "https://localhost:8443/v1/flows/top?by=src_asn&window=15m&limit=5"
```

See `deploy/agent/probectl-flow-agent.example.yml` for the YAML form of every
key, and [`configuration.md`](configuration.md) for the full `PROBECTL_FLOW_*`
reference.
