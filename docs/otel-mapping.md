# Canonical signal → OpenTelemetry mapping

probectl's signal schemas are modeled on OpenTelemetry **resource** and **network
semantic conventions from their first emission** (S6), so the OTLP layer (S22)
*exposes* signals as OTLP rather than remapping a divergent model. This file is
the canonical mapping; a CI conformance test (`internal/otel`) enforces that the
code never invents an attribute name where an OTel convention exists.

## Result (`probectl.result.v1.Result`)

| proto field             | OTel attribute / role            | notes                                   |
| ----------------------- | -------------------------------- | --------------------------------------- |
| `tenant_id`             | resource: `probectl.tenant.id`     | outermost scope (F50); probectl namespace |
| `agent_id`              | resource: `probectl.agent.id`      | producing agent; probectl namespace       |
| `canary_type`           | `probectl.canary.type`             | icmp/tcp/udp/http/dns/… (probectl)        |
| `server_address`        | `server.address`                 | the probed target                       |
| `server_port`           | `server.port`                    | omitted when 0                          |
| `network_transport`     | `network.transport`              | tcp / udp / icmp                        |
| `network_protocol_name` | `network.protocol.name`          | http / dns / …                          |
| `start_time_unix_nano`  | span/metric start timestamp      | OTel nanosecond epoch                   |
| `duration_nano`         | duration                         | nanoseconds                             |
| `success`               | outcome                          | → `probectl_probe_success` (1/0)          |
| `error_message`         | `error.message` (when failing)   |                                         |
| `metrics{}`             | metric data points               | name → value (see TSDB below)           |
| `attributes{}`          | additional OTel-convention attrs | canary-supplied (`network.*`, `server.*`, `client.*`) |

There is no standard OTel tenancy attribute, so tenant/agent identity uses the
`probectl.*` namespace; everything else follows the OTel specification.

## TSDB metric/label schema (Prometheus / VictoriaMetrics)

The consumer (`internal/tsdb`) turns each Result into time series:

- `probectl_probe_success` — gauge, 1 on success / 0 on failure.
- `probectl_probe_duration_seconds` — gauge, the probe duration.
- `probectl_probe_<metric>` — one gauge per entry in `metrics{}` (the metric key is
  sanitized to a valid Prometheus name, e.g. `rtt.avg.ms` → `rtt_avg_ms`).

**Labels** (cardinality-bounded on purpose): `tenant_id`, `agent_id`,
`canary_type`, `server_address`. `tenant_id` is a label (pooled mode); siloed mode
uses per-tenant series. High-cardinality per-hop/per-target detail belongs in
ClickHouse, not as metric labels (CLAUDE.md / S6 watch-out).

## eBPF flow (`probectl.ebpf.v1.Flow`, S20)

| proto field                                | OTel attribute                          |
| ------------------------------------------ | --------------------------------------- |
| `tenant_id` / `agent_id`                   | `probectl.tenant.id` / `probectl.agent.id`  |
| `host`                                     | `host.name`                             |
| `source_address` / `source_port`          | `source.address` / `source.port`        |
| `destination_address` / `destination_port` | `destination.address` / `destination.port` |
| `network_transport` / `network_type`      | `network.transport` / `network.type`    |
| `direction`                                | `network.io.direction`                  |
| `process_name` / `container_id`           | `process.executable.name` / `container.id` |

## eBPF L7 call (`probectl.ebpf.v1.L7Call`, S21)

| protocol      | OTel attributes                                                         |
| ------------- | ---------------------------------------------------------------------- |
| http1 / http2 | `http.request.method`, `url.path`, `http.response.status_code`         |
| grpc          | `rpc.system=grpc`, `rpc.method`, `rpc.grpc.status_code`                |
| dns           | `dns.question.name`, `dns.response.code`                               |
| kafka         | `messaging.system=kafka`, `messaging.operation.name`, `messaging.destination.name` |

Plus `network.protocol.name` and `probectl.l7.encrypted` (TLS-uprobe capture).

## BGP event (`probectl.bgp.v1.BGPEvent`, S14)

BGP has no OTel standard, so it uses the `probectl.bgp.*` namespace (`event_type`,
`severity`, `confidence`, `prefix`, `origin_asn`, `peer_asn`, `rpki_status`,
`collector`); the collector peer uses `network.peer.address`.

## Path / traceroute (S10)

`destination.address` (target IP) + `probectl.path.*` (`target`, `mode`,
`hop_count`, `destination_reached`).

## Conformance (finalized S22)

`internal/otel.TestAllSignalMappingsConform` asserts EVERY signal mapping —
result, flow, L7, BGP, path — emits only OTel-standard or `probectl.*` names and
carries the tenant. The OTLP layer (`internal/otel/otlp`) exposes these as OTLP
`ResourceMetrics`; see [`otlp.md`](otlp.md).
