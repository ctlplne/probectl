# Configuration

This documents netctl's configuration conventions and the local dev-stack
service contract. Concrete config **keys** are added by the sprints that
introduce them (the control plane in S1, the agent in S5, …); every new key is
documented here in the same PR (CLAUDE.md §6, §8).

## Conventions

- **Control plane:** configured via environment variables with the `NETCTL_`
  prefix; the S1 keys are listed below.
- **Agent:** configured via a YAML file or environment variables. Schema lands
  in S5.
- **Secrets** are never hardcoded, logged, or placed in URLs/query strings;
  sensitive values at rest use envelope encryption (S3). See CLAUDE.md §7.

## Control plane (`netctl-control`) — S1

Subcommands: `netctl-control [serve]` (default), `netctl-control migrate` (apply
migrations and exit), `netctl-control version`.

| Variable                          | Default                                                              | Description                                  |
| --------------------------------- | ------------------------------------------------------------------- | -------------------------------------------- |
| `NETCTL_HTTP_ADDR`                | `:8080`                                                             | API listen address                           |
| `NETCTL_HTTP_READ_TIMEOUT`        | `15s`                                                              | HTTP read timeout                            |
| `NETCTL_HTTP_WRITE_TIMEOUT`       | `15s`                                                              | HTTP write timeout                           |
| `NETCTL_HTTP_IDLE_TIMEOUT`        | `60s`                                                              | HTTP idle (keep-alive) timeout               |
| `NETCTL_SHUTDOWN_TIMEOUT`         | `15s`                                                              | graceful-shutdown drain timeout              |
| `NETCTL_DATABASE_URL`             | `postgres://netctl:netctl@localhost:5432/netctl?sslmode=disable`    | PostgreSQL DSN (`sslmode` controls TLS)      |
| `NETCTL_DATABASE_MAX_CONNS`       | `10`                                                               | max pool connections (1–1000)                |
| `NETCTL_DATABASE_MIN_CONNS`       | `0`                                                                | min pool connections                         |
| `NETCTL_DATABASE_CONNECT_TIMEOUT` | `5s`                                                              | per-connection connect timeout               |
| `NETCTL_MIGRATE_ON_BOOT`          | `false`                                                            | apply migrations during `serve` startup      |
| `NETCTL_LOG_LEVEL`                | `info`                                                             | `debug` \| `info` \| `warn` \| `error`       |
| `NETCTL_LOG_FORMAT`               | `json`                                                             | `json` \| `text`                             |
| `NETCTL_HSTS_ENABLED`             | `true`                                                             | send `Strict-Transport-Security`             |
| `NETCTL_HSTS_MAX_AGE`             | `8760h`                                                            | HSTS `max-age`                               |
| `NETCTL_TLS_CERT_FILE`            | (none)                                                            | PEM server certificate; serves HTTPS when set with the key |
| `NETCTL_TLS_KEY_FILE`             | (none)                                                            | PEM server private key (set together with the cert)        |
| `NETCTL_ENVELOPE_KEY`             | (none)                                                            | base64-encoded 32-byte KEK for at-rest envelope encryption |
| `NETCTL_ENVELOPE_KEY_ID`          | `dev`                                                             | identifier recorded with each sealed value                 |
| `NETCTL_AGENT_GRPC_ADDR`          | (none)                                                            | agent gRPC listen address; enables the transport when set with mTLS |
| `NETCTL_AGENT_TLS_CERT_FILE`      | (none)                                                            | agent-transport server certificate (PEM)                   |
| `NETCTL_AGENT_TLS_KEY_FILE`       | (none)                                                            | agent-transport server private key (PEM)                   |
| `NETCTL_AGENT_TLS_CA_FILE`        | (none)                                                            | CA bundle that signs agent client certificates (PEM)       |
| `NETCTL_BUS_MODE`                 | `memory`                                                         | result bus: `memory` (lightweight, in-process) \| `kafka`  |
| `NETCTL_BUS_BROKERS`              | (none)                                                           | comma-separated `host:port` Kafka brokers (required for `kafka`) |
| `NETCTL_TSDB_MODE`                | `memory`                                                         | time-series writer: `memory` (in-process) \| `prometheus`  |
| `NETCTL_TSDB_URL`                 | (none)                                                           | Prometheus/VictoriaMetrics base URL for remote-write (required for `prometheus`) |

Invalid values fail fast: `netctl-control` reports **all** configuration problems
at once and exits non-zero. The database password is redacted from logs.

From S2, tenant-owned tables are protected by Row-Level Security. The
`NETCTL_DATABASE_URL` role must be able to assume the least-privilege `netctl_app`
role (a superuser always can; otherwise run `GRANT netctl_app TO <login_role>`),
which `internal/tenancy` assumes per transaction so isolation holds regardless of
how the control plane authenticated. See [`architecture.md`](architecture.md).

### HTTP endpoints (S1)

| Method & path      | Purpose                                                  |
| ------------------ | -------------------------------------------------------- |
| `GET /healthz`     | Liveness — `200` while the process is serving            |
| `GET /readyz`      | Readiness — `200` when the database is reachable, else `503` |
| `GET /version`     | Build and runtime metadata                               |
| `GET /openapi.json`| The OpenAPI 3.1 document                                 |

Every response carries an `X-Request-Id` (honoring an inbound one) and the
security headers `Strict-Transport-Security` (when enabled) and
`X-Content-Type-Options: nosniff`. Versioned resource routes under `/v1` arrive
in S9+.

### Error envelope

All errors share one JSON shape and a stable domain-error → HTTP mapping:

```json
{ "error": { "code": "not_found", "message": "…", "request_id": "…" } }
```

| Domain kind   | Code           | HTTP |
| ------------- | -------------- | ---- |
| BadRequest    | `bad_request`  | 400  |
| Unauthorized  | `unauthorized` | 401  |
| Forbidden     | `forbidden`    | 403  |
| NotFound      | `not_found`    | 404  |
| Conflict      | `conflict`     | 409  |
| Validation    | `validation`   | 422  |
| Internal      | `internal`     | 500  |
| Unavailable   | `unavailable`  | 503  |

### Transport security (S3)

The API listens over TLS in two interchangeable ways:

- **App-terminated TLS** — set `NETCTL_TLS_CERT_FILE` + `NETCTL_TLS_KEY_FILE`, and
  the control plane serves **HTTPS only** (TLS 1.2+, prefer 1.3; plaintext is
  refused).
- **Ingress-terminated TLS** — leave them unset and serve HTTP behind a
  TLS-terminating ingress (the shipped Helm/compose default). HSTS is set either
  way, so the posture is correct end to end.

All TLS and crypto policy lives in `internal/crypto`; a CI guard
(`scripts/check_crypto_imports.sh`) forbids crypto-primitive imports elsewhere so
a FIPS 140-3 module can be swapped in (F32). At-rest secrets use the envelope
helper (a per-record data key wrapped by a KMS/HSM-pluggable KEK; the dev
`StaticKeyProvider` reads `NETCTL_ENVELOPE_KEY`).

### Agent transport (S4)

The agent gRPC transport (`netctl.agent.v1.AgentService`) runs when
`NETCTL_AGENT_GRPC_ADDR` and the three `NETCTL_AGENT_TLS_*` files are set. It is
**mTLS-only** (`RequireAndVerifyClientCert`): an agent's tenant and id come from
its client certificate's tenant-bound SPIFFE identity
(`spiffe://netctl/tenant/<t>/agent/<a>`), never from the request body, so every
result it emits is tenant-attributable at the source (F50). Generate dev mTLS
material with the `internal/crypto` CA helpers. The `.proto` lives under
`proto/netctl/agent/v1/`; regenerate Go with `make proto` (tools via
`make proto-tools`).

### netctl-agent (S5)

The agent is configured by a YAML file (`-config` or `NETCTL_AGENT_CONFIG`); see
[`deploy/agent/netctl-agent.example.yml`](../deploy/agent/netctl-agent.example.yml).
Its tenant and id are derived from its client certificate's SPIFFE identity, not
configured. `NETCTL_AGENT_GRPC_ADDR`, `NETCTL_AGENT_TLS_{CERT,KEY,CA}_FILE`,
`NETCTL_AGENT_BUFFER_DIR`, and `NETCTL_AGENT_LOG_{LEVEL,FORMAT}` override the file.
Results buffer to disk (`buffer.dir`, bounded by `max_records`) while the control
plane is unreachable and drain on reconnect (at-least-once). Probing runs
independently of connectivity, so an outage never blocks measurement.

### Result pipeline (S6)

A streamed result flows agent → gRPC `StreamResults` → control-plane ingest →
result bus (`netctl.network.results`, Protobuf) → consumer → time-series writer.
The agent sends the canonical OTel-aligned result (`proto/netctl/result/v1`); the
control plane **re-stamps the tenant and agent id from the verified mTLS
certificate** before publishing, so a result is always attributed to the sending
agent's tenant regardless of payload contents (CLAUDE.md §7 guardrails 1 and 5).
The bus key is the `tenant_id`.

`NETCTL_BUS_MODE` selects the bus: `memory` (default; in-process, for the
lightweight <5-agent deployment and single-binary runs) or `kafka` (set
`NETCTL_BUS_BROKERS`). `NETCTL_TSDB_MODE` selects the writer: `memory` (default;
in-process) or `prometheus` remote-write to `NETCTL_TSDB_URL` (Prometheus with
`--web.enable-remote-write-receiver`, or VictoriaMetrics; use an `https://` URL
for TLS in transit). Each probe emits `netctl_probe_success`,
`netctl_probe_duration_seconds`, and one `netctl_probe_<metric>` per custom
metric, labeled `tenant_id`, `agent_id`, `canary_type`, and `server_address`. The
canonical signal→OTel mapping is in [`otel-mapping.md`](otel-mapping.md).

### ICMP test (S7)

The `icmp` canary measures echo **loss, latency, and jitter** to a `target`
(IPv4 or IPv6). Configure it per-canary under `canaries:` (see
[`netctl-agent.example.yml`](../deploy/agent/netctl-agent.example.yml)). The
schedule `interval` and reply `timeout` are canary fields; the rest are `params`:

| Param           | Default | Meaning                                                                 |
| --------------- | ------- | ----------------------------------------------------------------------- |
| `count`         | `5`     | echo requests per probe (continuous mode defaults to the interval in s) |
| `payload_bytes` | `56`    | ICMP data bytes (minimum 8)                                             |
| `dscp`          | `0`     | DSCP marking 0–63 on outgoing packets (best-effort by platform)         |
| `mode`          | `batch` | `batch` (back-to-back) or `continuous` (1 packet/sec)                   |
| `privileged`    | `false` | `true` prefers raw sockets; default is unprivileged datagram ICMP       |

It emits `netctl_probe_loss_ratio`, `netctl_probe_rtt_{min,avg,max,stddev}_ms`,
`netctl_probe_jitter_ms`, and `netctl_probe_packets_{sent,received}`. A probe with
100% loss reports `success=false` (target unreachable); partial loss is a success
with a non-zero loss ratio. **Continuous mode** records a per-second drop-timing
record as result attributes (`icmp.dropped_seqs`, `icmp.drop_send_offsets_ms`) —
carried as OTel attributes, not TSDB labels, so they don't widen cardinality.

**Privileges.** By default the agent uses **unprivileged** datagram ICMP
(`IPPROTO_ICMP`), which on Linux requires the agent's group to be within
`net.ipv4.ping_group_range` (e.g. `sysctl -w net.ipv4.ping_group_range="0
2147483647"`). Alternatively grant raw-socket capability
(`setcap cap_net_raw+ep /usr/bin/netctl-agent`, or run with `CAP_NET_RAW`) and set
`privileged: "true"`. The canary tries the preferred socket and falls back to the
other; if neither can be opened it returns an internal error (the probe is not
silently reported as loss).

### TCP & UDP tests (S8)

The `tcp` and `udp` canaries are agent-to-server probes. Configure a `target` of
`host:port` (or a `host` with `params.port`). Both accept `count` and `dscp`.

The **`tcp`** canary measures **connect latency + reachability** (a connect-based,
unprivileged equivalent of a TCP-SYN test): it establishes a connection and times
the handshake, emitting `netctl_probe_connect_{min,avg,max,stddev}_ms`,
`netctl_probe_jitter_ms`, and `netctl_probe_loss_ratio` (failed connects = loss;
all-failed = `success=false`).

The **`udp`** canary is an **echo round-trip** probe: it sends token-tagged
datagrams and matches the echoes, emitting `netctl_probe_rtt_*` + loss. It needs a
target that echoes (a UDP echo service, or a netctl agent-to-agent responder); a
non-echoing target reports as 100% loss. `params.payload_bytes` (≥10) sets the
datagram size.

### Agent-to-agent tests (S8)

An agent-to-agent (A2A) test measures **between two registered agents**, brokered
by the control plane. The control plane assigns roles (one agent **responds**,
opening a short-lived listener; the other **initiates**), rendezvouses the
responder's endpoint to the initiator, and hands each agent its task when it
polls (`PollCoordination` / `ReportEndpoint`). The measurement is TWAMP-lite: the
initiator timestamps each probe (T1), the responder stamps receive/send (T2/T3)
and echoes, and the initiator stamps receive (T4), yielding **round-trip**
(`netctl_probe_rtt_*`) plus **forward** and **reverse** one-way delay
(`netctl_probe_forward_avg_ms`, `netctl_probe_reverse_avg_ms`). The responder also
reports forward-direction delivery (`netctl_probe_packets_received`,
`netctl_probe_loss_ratio`), so both agents and both directions are observed.

Enable participation in the agent's `a2a` block: `enabled: true`,
`advertise_host` (the address peers use to reach this agent's responder),
`poll_interval`, and `responder_ttl`. **Caveats (document for production):**

- **NAT/firewall.** The responder advertises `advertise_host`; behind NAT this
  must be a reachable address and the responder's ephemeral port must be
  reachable from the initiator. Auto-detection picks a non-loopback IPv4 — set
  `advertise_host` explicitly when that is wrong.
- **Clocks.** Forward/reverse one-way delays assume the two agents' clocks are
  synchronized (exact within one host; use **NTP** across hosts). Round-trip is
  clock-independent.

Sessions are brokered in-memory and triggered by the test API in a later sprint.

### Path discovery (S10)

The ECMP/MPLS-aware path engine (`internal/path`) runs Paris-style traceroutes
(ICMP and TCP) and merges per-flow traces into a multi-path result; see
[`architecture.md`](architecture.md). A **full per-hop trace needs raw sockets**:
grant `CAP_NET_RAW` (`setcap cap_net_raw+ep`, or run privileged) to capture
intermediate hops + MPLS; unprivileged, only the destination is discovered.
Discovered paths persist via `internal/store/pathstore` — `memory`
(lightweight/tests) or `clickhouse` (writes hop/link rows to a ClickHouse HTTP
endpoint, e.g. `http://localhost:8123`, partitioned by tenant). Scheduling path
tests on agents and ingesting results lands with the S11 visualization that
consumes them.

### Resource API & CLI (S9)

The versioned resource API lives under **`/v1`** (full schema at `/openapi.json`):

- `GET/POST /v1/tests`, `GET/PUT/DELETE /v1/tests/{id}` — synthetic-test CRUD.
- `GET /v1/agents`, `GET/PATCH/DELETE /v1/agents/{id}` — agents register over
  mTLS; the API lists, renames, and deregisters them.

Every `/v1` route is **tenant-scoped** through `internal/tenancy` + Postgres RLS,
so a request can never read or write across tenants. **Authentication is a dev
stub in S9** (real SSO/SCIM + per-tenant IdP land in S18): the tenant is the
seeded default, overridable with an `X-Netctl-Tenant: <tenant-uuid>` header for
multi-tenant dev. A `Authorization: Bearer <token>` header is accepted but not
yet verified. The `no undocumented routes` rule is enforced by a test that
matches the route table against `openapi.json`.

The **`netctl` CLI** is the web-parity client. Configure it with flags or
environment: `NETCTL_API_URL` (default `http://localhost:8080`),
`NETCTL_API_TOKEN` (sent as Bearer), `NETCTL_TENANT` (sent as `X-Netctl-Tenant`).

```bash
netctl test list
netctl test create --name edge-dns --type icmp --target 1.1.1.1 --interval 30
netctl test delete <id>
netctl agent list
netctl --json test list      # machine-readable output
```

## Local dev stack (`deploy/compose/dev.yml`)

Started with `make compose-up`. **Local, non-production** defaults — plaintext
listeners and dev credentials for convenience. Production deploys are
TLS/HTTPS-by-default (CLAUDE.md §7 guardrail 12).

| Service      | Compose name | Host port(s)        | Purpose                                   | Dev credentials                 |
| ------------ | ------------ | ------------------- | ----------------------------------------- | ------------------------------- |
| PostgreSQL   | `postgres`   | `5432`              | Durable state, tenants, RBAC, audit, SLOs | user/pass/db = `netctl`         |
| Kafka        | `kafka`      | `9092`              | Result/event bus (KRaft, no ZooKeeper)    | none (PLAINTEXT)                |
| ClickHouse   | `clickhouse` | `8123` (HTTP), `9000` (native) | High-cardinality events/flows  | user/pass/db = `netctl`         |
| Prometheus   | `prometheus` | `9090`              | Metrics TSDB (remote-write enabled)       | none                            |

Kafka listeners: host clients use `localhost:9092`; in-network containers use
`kafka:19092`; the KRaft controller uses `9093` (internal). Prometheus runs with
`--web.enable-remote-write-receiver` so the result pipeline (S6) can remote-write
into it.

These names and ports are a **contract** introduced in S0 — later sprints and
the integration harness depend on them.

## Tear-down

`make compose-down` removes the containers **and volumes** (`pgdata`, `chdata`,
`promdata`).
