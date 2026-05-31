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
