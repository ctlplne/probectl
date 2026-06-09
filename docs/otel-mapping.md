# Canonical signal → OpenTelemetry mapping

## What this is

probectl is OpenTelemetry-native, and this file is the contract that makes that
claim true: it lists, for every signal probectl produces, exactly which
OpenTelemetry attribute each field becomes. The point of being OTel-native is
that probectl's internal schemas were modeled on OTel **resource** and
**network** semantic conventions *from their first field* — so the OTLP layer
(see [`otlp.md`](otlp.md)) *exposes* probectl signals as OTLP instead of
remapping a divergent model into it.

The discipline is enforced, not aspirational: a CI conformance test
(`internal/otel.TestAllSignalMappingsConform`) asserts that no mapping ever
invents an attribute name where an OTel convention already exists. The allowed
set is "OTel-standard names, plus the `probectl.*` namespace for things OTel
has no convention for" — chiefly tenant/agent identity, since OTel defines no
tenancy attribute. Each mapping function below registers its keys into that
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
which writes through `internal/store/tsdb`:

- `probectl_probe_success` — 1 on success / 0 on failure;
- `probectl_probe_duration_seconds` — the probe duration in seconds;
- `probectl_probe_<metric>` — one series per entry in `metrics{}`, with the key
  sanitized to a valid Prometheus name (e.g. `rtt.avg.ms` → `rtt_avg_ms`).

**Labels** (deliberately cardinality-bounded): `tenant_id`, `agent_id`,
`canary_type`, `server_address`. `tenant_id` is a label in pooled mode; siloed
mode uses per-tenant series, and query-time tenant scoping enforces isolation at
the TSDB. High-cardinality per-hop / per-target detail belongs in ClickHouse,
**not** as a metric label — unbounded label values are how a time-series store
falls over.

## eBPF flow (`probectl.ebpf.v1.Flow`)

The host/L4 observability signal. Mapping in `internal/otel/flow.go`
(`FlowAttributes`).

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

Plus `network.protocol.name` (the protocol itself) and `probectl.l7.encrypted`
on every call (set when the call was captured via a TLS-library uprobe, i.e.
plaintext read before encryption).

## BGP event (`probectl.bgp.v1.BGPEvent`)

BGP has no OTel semantic convention, so the routing signal uses the
`probectl.bgp.*` namespace. Mapping in `internal/otel/bgp.go`
(`BGPEventAttributes`): `probectl.bgp.event_type`, `.severity`, `.confidence`,
`.prefix`, `.origin_asn`, `.peer_asn`, `.rpki_status`, `.collector`. The one
standard key it can reuse is the collector peer's address →
`network.peer.address`.

## Path / traceroute (`PathSummary`)

Mapping in `internal/otel/path.go` (`PathAttributes`): the target IP uses the
standard `destination.address`; path specifics use `probectl.path.*` —
`probectl.path.target`, `probectl.path.mode`, `probectl.path.hop_count`,
`probectl.path.destination_reached`.

## Conformance

`internal/otel.TestAllSignalMappingsConform` holds **every** mapping — result,
eBPF flow, L7, BGP, path — to two rules: it may emit only OTel-standard or
`probectl.*` names, and it must carry the tenant. The OTLP layer
(`internal/otel/otlp`) then turns these attribute sets into OTLP
`ResourceMetrics` for export and ingest; see [`otlp.md`](otlp.md) for that side.
