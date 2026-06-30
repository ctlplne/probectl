# Canonical signal → OpenTelemetry mapping

## What this is

probectl is OpenTelemetry-native, and this file is the contract that makes that
claim true: it lists, for every signal probectl produces, exactly which
OpenTelemetry attribute each field becomes. First, three words: an
**attribute** is one key/value tag on a signal (`server.address=db1`); OTel's
**semantic conventions** are its published dictionary of standard attribute
names; and a **resource** is the attribute set describing *who produced* a
signal (which agent, which tenant) rather than what it says. The point of
being OTel-native is
that probectl's internal schemas were modeled on OTel **resource** and
**network** semantic conventions *from their first field* — the address written
in the post office's format from the first letter, so nothing needs
re-addressing at the border: the OTLP layer
(see [`otlp.md`](otlp.md)) *exposes* probectl signals as OTLP instead of
remapping a divergent model into it.

The discipline is enforced, not aspirational: a CI conformance test
(`internal/otel.TestAllSignalMappingsConform`) asserts that no mapping ever
invents an attribute name where an OTel convention already exists. The allowed
set is "OTel-standard names, plus the `probectl.*` namespace for things OTel
has no convention for" — chiefly tenant/agent identity, since OTel defines no
tenancy attribute. It works like radio phraseology: only words from the
approved list may go on the air, and CI fails the checkride for an invented
one. Each mapping file below registers its keys (an `init` in the file) into
that
shared `KnownAttributes` set, and the test rejects anything outside it.

A quick orientation to the two namespaces you'll see:

- a **standard** key like `server.address` or `network.transport` — used as-is;
- a **`probectl.*`** key like `probectl.tenant.id` or `probectl.flow.protocol` —
  used only where no OTel (or ECS) convention fits.

## Result (`probectl.result.v1.Result`)

The canary probe result — the active-testing signal. Mapping in
`internal/otel/conventions.go` (`ResultAttributes`).

| proto field             | OTel attribute / role            | notes                                              |
| ----------------------- | -------------------------------- | -------------------------------------------------- |
| `tenant_id`             | resource: `probectl.tenant.id`   | outermost scope; `probectl.*` (no OTel tenancy key) |
| `agent_id`              | resource: `probectl.agent.id`    | the producing agent; `probectl.*`                   |
| `canary_type`           | `probectl.canary.type`           | icmp / tcp / udp / http / dns / … (`probectl.*`)     |
| `server_address`        | `server.address`                 | the probed target                                  |
| `server_port`           | `server.port`                    | omitted when 0                                     |
| `network_transport`     | `network.transport`              | tcp / udp / icmp                                   |
| `network_protocol_name` | `network.protocol.name`          | http / dns / …                                     |
| `start_time_unix_nano`  | span/metric start timestamp      | OTel nanosecond epoch                              |
| `duration_nano`         | duration                         | nanoseconds                                        |
| `success`               | outcome                          | → `probectl_probe_success` (1/0); see TSDB below    |
| `metrics{}`             | metric data points               | name → value (see TSDB below)                      |
| `attributes{}`          | additional OTel-convention attrs | canary-supplied (`network.*`, `server.*`, `client.*`) — passed through verbatim |

`error_message` is carried on the Result (it's the human-readable failure detail
the API surfaces), but the conventions layer does **not** promote it to an
`error.message` attribute today — so it is not part of the OTel attribute set
above. The `attributes{}` map is the extension point: a canary can attach any
OTel-convention key it likes, and those flow through unchanged.

Tenant and agent identity use the `probectl.*` namespace because OTel has no
standard tenancy attribute; everything else follows the OTel specification.

## TSDB metric / label schema (Prometheus / VictoriaMetrics)

A probe Result becomes time series in `internal/pipeline` (`ResultToSeries`),
which writes through `internal/store/tsdb` (a time series is one metric name
plus one exact label combination, tracked over time):

- `probectl_probe_success` — 1 on success / 0 on failure;
- `probectl_probe_duration_seconds` — the probe duration in seconds;
- `probectl_probe_<metric>` — one series per entry in `metrics{}`, with the key
  sanitized to a valid Prometheus name (e.g. `rtt.avg.ms` → `rtt_avg_ms`).

**Labels** (deliberately cardinality-bounded — **cardinality** is the number of
distinct values a label takes, and every new value mints a whole new series):
`tenant_id`, `agent_id`,
`canary_type`, `server_address`. `tenant_id` is a label in pooled mode; siloed
mode uses per-tenant series, and query-time tenant scoping enforces isolation at
the TSDB. High-cardinality per-hop / per-target detail belongs in ClickHouse,
**not** as a metric label — unbounded label values are how a time-series store
falls over.

## eBPF flow (`probectl.ebpf.v1.Flow`)

The host/L4 observability signal from the eBPF agent. Mapping in
`internal/otel/flow.go` (`FlowAttributes`).

| proto field                                | OTel attribute                          |
| ------------------------------------------ | --------------------------------------- |
| `tenant_id` / `agent_id`                   | `probectl.tenant.id` / `probectl.agent.id` |
| `host`                                     | `host.name`                             |
| `source_address` / `source_port`          | `source.address` / `source.port`        |
| `destination_address` / `destination_port` | `destination.address` / `destination.port` |
| `network_transport` / `network_type`      | `network.transport` / `network.type`    |
| `direction`                                | `network.io.direction`                  |
| `process_name` / `container_id`           | `process.executable.name` / `container.id` |

## eBPF L7 call (`probectl.ebpf.v1.L7Call`)

One application-protocol call, captured before encryption. Mapping in
`internal/otel/l7.go` (`L7CallAttributes`), keyed off the protocol:

| protocol      | OTel attributes                                                         |
| ------------- | ---------------------------------------------------------------------- |
| http1 / http2 | `http.request.method`, `url.path`, `http.response.status_code`         |
| grpc          | `rpc.system=grpc`, `rpc.method`, `rpc.grpc.status_code`                |
| dns           | `dns.question.name`, `dns.response.code`                               |
| kafka         | `messaging.system=kafka`, `messaging.operation.name`, `messaging.destination.name` |

Plus `network.protocol.name` (the protocol itself) on every call, and
`probectl.l7.encrypted` when the call was captured via a TLS-library uprobe
(a hook on a userspace library's functions — here, reading the plaintext
before the library encrypts it).

## Device and cloud flow — NetFlow / IPFIX / sFlow / cloud flow logs (`probectl.flow.v1.FlowRecord`)

The passive flow-plane signal (see [`flow.md`](flow.md)) — one record per flow
a router, switch, or cloud flow-log export emitted. Mapping in `internal/otel/netflow.go`
(`NetFlowAttributes`). The 5-tuple reuses the same `source.*` /
`destination.*` / `network.*` keys the eBPF flow mapping registers; the
flow-export specifics have no OTel home and use `probectl.flow.*`; AS/geo
enrichment uses the ECS-aligned names, because neither OTel nor `probectl.*`
needs a new name where ECS already has one.

| proto field                                 | OTel attribute                                  | notes                                           |
| ------------------------------------------- | ----------------------------------------------- | ----------------------------------------------- |
| `tenant_id` / `agent_id`                    | `probectl.tenant.id` / `probectl.agent.id`      | tenant is the outermost scope                   |
| `exporter_address`                          | `probectl.flow.exporter.address`                | the device that emitted the datagram            |
| `flow_protocol`                             | `probectl.flow.protocol`                        | `netflow5` \| `netflow9` \| `ipfix` \| `sflow5` |
| `source_address` / `source_port`            | `source.address` / `source.port`                | zero/empty omitted                              |
| `destination_address` / `destination_port`  | `destination.address` / `destination.port`      | zero/empty omitted                              |
| `network_transport` / `network_type`        | `network.transport` / `network.type`            |                                                 |
| `input_interface` / `output_interface`      | `probectl.flow.interface.in` / `.interface.out` | the exporter's ifIndex values                   |
| `sampling_rate`                             | `probectl.flow.sampling.rate`                   | 1 = unsampled                                   |
| `source_asn` / `source_as_name` / `source_country` | `source.as.number` / `source.as.organization.name` / `source.geo.country.iso_code` | ECS-aligned; `destination.*` equivalents likewise |

## Device telemetry (`probectl.device.v1.DeviceMetric`)

The SNMP/gNMI device-plane sample (see
[`device-telemetry.md`](device-telemetry.md)). Mapping in
`internal/otel/device.go` (`DeviceMetricAttributes`). No OTel semantic
convention covers network-device telemetry, so the identity attributes live
under `probectl.device.*` — and the metric *names* themselves
(`probectl.device.if.in.octets`, …) are probectl-owned for the same reason.

| proto field          | OTel attribute                                        |
| -------------------- | ----------------------------------------------------- |
| `tenant_id` / `agent_id` | `probectl.tenant.id` / `probectl.agent.id`        |
| `device_address`     | `probectl.device.address`                             |
| `device_name`        | `probectl.device.name`                                |
| `source`             | `probectl.device.source` (`snmp` \| `gnmi`)           |
| `if_index` / `if_name` | `probectl.device.interface.index` / `.interface.name` (omitted when device-wide) |

## BGP event (`probectl.bgp.v1.BGPEvent`)

BGP has no OTel semantic convention, so the routing signal uses the
`probectl.bgp.*` namespace. Mapping in `internal/otel/bgp.go`
(`BGPEventAttributes`): `probectl.bgp.event_type`, `.severity`, `.confidence`,
`.prefix`, `.origin_asn`, `.peer_asn`, `.rpki_status` (RPKI is the
cryptographic registry of which AS may originate which prefix), `.collector`.
The one
standard key it can reuse is the collector peer's address →
`network.peer.address`.

## Path / traceroute (`PathSummary`)

Mapping in `internal/otel/path.go` (`PathAttributes`): the target IP uses the
standard `destination.address`; path specifics use `probectl.path.*` —
`probectl.path.target`, `probectl.path.mode`, `probectl.path.hop_count`,
`probectl.path.destination_reached`.

## Conformance

`internal/otel.TestAllSignalMappingsConform` holds **every** mapping — result,
eBPF flow, L7, device flow (NetFlow/IPFIX/sFlow), device telemetry, BGP, path —
to two rules: it may emit only OTel-standard (or ECS-aligned) or `probectl.*`
names, and it must carry the tenant. The OTLP layer (`internal/otel/otlp`) then
turns these attribute sets into OTLP `ResourceMetrics` for export and ingest;
see [`otlp.md`](otlp.md) for that side.
