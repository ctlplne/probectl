# Configuration

This documents probectl's configuration conventions and the local dev-stack
service contract. Concrete config **keys** are added by the sprints that
introduce them (the control plane in S1, the agent in S5, …); every new key is
documented here in the same PR (CLAUDE.md §6, §8).

## Conventions

- **Control plane:** configured via environment variables with the `PROBECTL_`
  prefix; the S1 keys are listed below.
- **Agent:** configured via a YAML file or environment variables. Schema lands
  in S5.
- **Secrets** are never hardcoded, logged, or placed in URLs/query strings;
  sensitive values at rest use envelope encryption (S3). See CLAUDE.md §7.

## Control plane (`probectl-control`) — S1

Subcommands: `probectl-control [serve]` (default), `probectl-control migrate` (apply
migrations and exit), `probectl-control version`.

| Variable                          | Default                                                              | Description                                  |
| --------------------------------- | ------------------------------------------------------------------- | -------------------------------------------- |
| `PROBECTL_HTTP_ADDR`                | `:8080`                                                             | API listen address                           |
| `PROBECTL_HTTP_READ_TIMEOUT`        | `15s`                                                              | HTTP read timeout                            |
| `PROBECTL_HTTP_WRITE_TIMEOUT`       | `15s`                                                              | HTTP write timeout                           |
| `PROBECTL_HTTP_IDLE_TIMEOUT`        | `60s`                                                              | HTTP idle (keep-alive) timeout               |
| `PROBECTL_SHUTDOWN_TIMEOUT`         | `15s`                                                              | graceful-shutdown drain timeout              |
| `PROBECTL_DATABASE_URL`             | `postgres://probectl:probectl@localhost:5432/probectl?sslmode=require`    | PostgreSQL DSN; `sslmode=require` is the default (U-039). Dev-only: a local source-dev stack without TLS may explicitly append `sslmode=disable` to its own DSN |
| `PROBECTL_DATABASE_MAX_CONNS`       | `10`                                                               | max pool connections (1–1000)                |
| `PROBECTL_DATABASE_MIN_CONNS`       | `0`                                                                | min pool connections                         |
| `PROBECTL_DATABASE_CONNECT_TIMEOUT` | `5s`                                                              | per-connection connect timeout               |
| `PROBECTL_MIGRATE_ON_BOOT`          | `false`                                                            | apply migrations during `serve` startup      |
| `PROBECTL_LOG_LEVEL`                | `info`                                                             | `debug` \| `info` \| `warn` \| `error`       |
| `PROBECTL_LOG_FORMAT`               | `json`                                                             | `json` \| `text`                             |
| `PROBECTL_HSTS_ENABLED`             | `true`                                                             | send `Strict-Transport-Security`             |
| `PROBECTL_HSTS_MAX_AGE`             | `8760h`                                                            | HSTS `max-age`                               |
| `PROBECTL_TLS_CERT_FILE`            | (none)                                                            | PEM server certificate; serves HTTPS when set with the key |
| `PROBECTL_TLS_KEY_FILE`             | (none)                                                            | PEM server private key (set together with the cert)        |
| `PROBECTL_ENVELOPE_KEY`             | (none)                                                            | base64-encoded 32-byte KEK for at-rest envelope encryption |
| `PROBECTL_ENVELOPE_KEY_ID`          | `dev`                                                             | identifier recorded with each sealed value                 |
| `PROBECTL_AGENT_GRPC_ADDR`          | (none)                                                            | agent gRPC listen address; enables the transport when set with mTLS |
| `PROBECTL_AGENT_TLS_CERT_FILE`      | (none)                                                            | agent-transport server certificate (PEM)                   |
| `PROBECTL_AGENT_TLS_KEY_FILE`       | (none)                                                            | agent-transport server private key (PEM)                   |
| `PROBECTL_AGENT_TLS_CA_FILE`        | (none)                                                            | CA bundle that signs agent client certificates (PEM)       |
| `PROBECTL_BUS_MODE`                 | `memory`                                                         | result bus: `memory` (lightweight, in-process) \| `kafka`  |
| `PROBECTL_BUS_BROKERS`              | (none)                                                           | comma-separated `host:port` Kafka brokers (required for `kafka`) |
| `PROBECTL_BUS_MEMORY_BUFFER`        | `1024`                                                           | in-memory bus: per-subscriber channel depth (lightweight mode, U-079) |
| `PROBECTL_BUS_MEMORY_OVERFLOW`      | `block`                                                          | in-memory bus overflow policy: `block` (back-pressure publisher) \| `drop` (drop + count, no deadlock) |
| `PROBECTL_BUS_TLS_ENABLED`          | `false`     | TLS to the Kafka brokers (U-010). **Required in kafka mode** unless the explicit dev flag below is set |
| `PROBECTL_BUS_TLS_CA_FILE`          | (none)      | private CA bundle for the brokers |
| `PROBECTL_BUS_TLS_CERT_FILE`        | (none)      | client certificate (broker mTLS; with `_KEY_FILE`) |
| `PROBECTL_BUS_TLS_KEY_FILE`         | (none)      | client key (broker mTLS) |
| `PROBECTL_BUS_SASL_MECHANISM`       | (none)      | `plain` \| `scram-sha-256` \| `scram-sha-512` |
| `PROBECTL_BUS_SASL_USER`            | (none)      | SASL username |
| `PROBECTL_BUS_SASL_PASSWORD`        | (none)      | SASL password (S41 secret references supported; never logged) |
| `PROBECTL_BUS_ALLOW_PLAINTEXT`      | `false`     | **dev only**: allow a plaintext broker (the dev compose stack). Production never sets this |
| `PROBECTL_BUS_MAX_BUFFERED`         | `65536`     | U-004: bound on the async producer's in-flight records; a full buffer SHEDS new records (counted, never blocking ingest) |
| `PROBECTL_INGEST_MAX_SERIES_PER_AGENT`  | `1000`  | U-017: active series identities one agent may mint; new identities past the cap are rejected per-series + counted |
| `PROBECTL_INGEST_MAX_SERIES_PER_TENANT` | `50000` | U-017: tenant-wide active-series wall (one tenant's explosion never bleeds into others) |
| `PROBECTL_TSDB_MEMORY_RETENTION` | `1h`     | U-018: lightweight-mode TSDB retention window (arrival-based sweep) |
| `PROBECTL_TSDB_MEMORY_MAX_BYTES` | `268435456` | U-018: byte wall for the in-memory TSDB; oldest-first eviction, usage + eviction counters exposed |
| `PROBECTL_AUDIT_WORM_DIR` | (none) | U-041: enable WORM export — the provider audit chain is exported as Ed25519-signed segments into this directory (mount an S3/MinIO **object-lock** bucket for true WORM) and chain-verified each cycle |
| `PROBECTL_AUDIT_WORM_INTERVAL` | `1h` | export + chain-verify cadence |
| `PROBECTL_TSDB_MODE`                | `memory`                                                         | time-series writer: `memory` (in-process) \| `prometheus`  |
| `PROBECTL_TSDB_URL`                 | (none)                                                           | Prometheus/VictoriaMetrics base URL for remote-write (required for `prometheus`) |
| `PROBECTL_ALERT_EVAL_INTERVAL`      | `30s`                                                            | how often the alerting engine evaluates rules over the TSDB (S16) |
| `PROBECTL_INCIDENT_WINDOW`          | `10m`                                                            | time window within which related signals correlate into one incident (S17) |
| `PROBECTL_AUTH_MODE`                | `session`                                                          | identity mode (S18): `session` (real OIDC SSO + session cookies) \| `dev` (LOCAL EVALUATION ONLY — exists only in `-tags devauth` builds; release binaries refuse it at boot, RED-001) |
| `PROBECTL_DEV_AUTH_ACK`             | (none)                                                             | RED-001: must be `i-understand` to start in dev auth mode (tagged builds only, loopback bind required) |
| `PROBECTL_SESSION_TTL`              | `12h`                                                            | server-side session lifetime (S18)                         |
| `PROBECTL_AUTH_RATE_MAX_FAILURES`   | `5`         | auth brute-force guard (U-024): failures per window before lockout |
| `PROBECTL_AUTH_RATE_WINDOW`         | `1m`        | failure-counting window for the auth throttle |
| `PROBECTL_AUTH_RATE_LOCKOUT`        | `1m`        | base lockout; doubles per consecutive lockout, capped at 1h; lockouts are audited |
| `PROBECTL_OIDC_ISSUER`              | (none)                                                           | OIDC issuer URL; SSO discovery is performed against it (S18) |
| `PROBECTL_OIDC_CLIENT_ID`          | (none)                                                           | OIDC client ID registered with the IdP (S18)               |
| `PROBECTL_OIDC_CLIENT_SECRET`      | (none)                                                           | OIDC client secret (kept out of logs/URLs; S18)            |
| `PROBECTL_OIDC_REDIRECT_URL`       | (none)                                                           | the control plane's `/auth/callback` URL registered with the IdP (S18) |

Invalid values fail fast: `probectl-control` reports **all** configuration problems
at once and exits non-zero. The database password is redacted from logs.

From S2, tenant-owned tables are protected by Row-Level Security. The
`PROBECTL_DATABASE_URL` role must be able to assume the least-privilege `probectl_app`
role (a superuser always can; otherwise run `GRANT probectl_app TO <login_role>`),
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

- **App-terminated TLS** — set `PROBECTL_TLS_CERT_FILE` + `PROBECTL_TLS_KEY_FILE`, and
  the control plane serves **HTTPS only** (TLS 1.2+, prefer 1.3; plaintext is
  refused).
- **Ingress-terminated TLS** — leave them unset and serve HTTP behind a
  TLS-terminating ingress (the shipped Helm/compose default). HSTS is set either
  way, so the posture is correct end to end.

All TLS and crypto policy lives in `internal/crypto`; a CI guard
(`scripts/check_crypto_imports.sh`) forbids crypto-primitive imports elsewhere so
a FIPS 140-3 module can be swapped in (F32). At-rest secrets use the envelope
helper (a per-record data key wrapped by a KMS/HSM-pluggable KEK; the dev
`StaticKeyProvider` reads `PROBECTL_ENVELOPE_KEY`).

### Agent transport (S4)

The agent gRPC transport (`probectl.agent.v1.AgentService`) runs when
`PROBECTL_AGENT_GRPC_ADDR` and the three `PROBECTL_AGENT_TLS_*` files are set. It is
**mTLS-only** (`RequireAndVerifyClientCert`): an agent's tenant and id come from
its client certificate's tenant-bound SPIFFE identity
(`spiffe://probectl/tenant/<t>/agent/<a>`), never from the request body, so every
result it emits is tenant-attributable at the source (F50). Generate dev mTLS
material with the `internal/crypto` CA helpers. The `.proto` lives under
`proto/probectl/agent/v1/`; regenerate Go with `make proto` (tools via
`make proto-tools`).

**Version-skew policy (S34).** At registration the control plane rejects agents
outside the supported window, so a rolling upgrade never admits an incompatible
agent. See [`lifecycle.md`](lifecycle.md).

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_AGENT_SKEW_WINDOW` | `1` | allowed minor-version skew on either side (N/N-1); the control plane at minor N accepts agents at N-1…N+1. `0` requires an exact minor match |
| `PROBECTL_AGENT_MIN_VERSION` | (none) | an explicit floor — agents older than this are rejected regardless of the window (force-retire a known-bad version) |

A rejected agent gets a gRPC `FailedPrecondition` ("upgrade required"); a dev/unpinned
build (`0.0.0-dev`) on either side skips the check.

### probectl-agent (S5)

The agent is configured by a YAML file (`-config` or `PROBECTL_AGENT_CONFIG`); see
[`deploy/agent/probectl-agent.example.yml`](../deploy/agent/probectl-agent.example.yml).
Its tenant and id are derived from its client certificate's SPIFFE identity, not
configured. `PROBECTL_AGENT_GRPC_ADDR`, `PROBECTL_AGENT_TLS_{CERT,KEY,CA}_FILE`,
`PROBECTL_AGENT_BUFFER_DIR`, and `PROBECTL_AGENT_LOG_{LEVEL,FORMAT}` override the file.
Results buffer to disk (`buffer.dir`, bounded by `max_records`) while the control
plane is unreachable and drain on reconnect (at-least-once). Probing runs
independently of connectivity, so an outage never blocks measurement.

### Result pipeline (S6)

A streamed result flows agent → gRPC `StreamResults` → control-plane ingest →
result bus (`probectl.network.results`, Protobuf) → consumer → time-series writer.
The agent sends the canonical OTel-aligned result (`proto/probectl/result/v1`); the
control plane **re-stamps the tenant and agent id from the verified mTLS
certificate** before publishing, so a result is always attributed to the sending
agent's tenant regardless of payload contents (CLAUDE.md §7 guardrails 1 and 5).
The bus key is the `tenant_id`.

`PROBECTL_BUS_MODE` selects the bus: `memory` (default; in-process, for the
lightweight <5-agent deployment and single-binary runs) or `kafka` (set
`PROBECTL_BUS_BROKERS`). `PROBECTL_TSDB_MODE` selects the writer: `memory` (default;
in-process) or `prometheus` remote-write to `PROBECTL_TSDB_URL` (Prometheus with
`--web.enable-remote-write-receiver`, or VictoriaMetrics; use an `https://` URL
for TLS in transit). Each probe emits `probectl_probe_success`,
`probectl_probe_duration_seconds`, and one `probectl_probe_<metric>` per custom
metric, labeled `tenant_id`, `agent_id`, `canary_type`, and `server_address`. The
canonical signal→OTel mapping is in [`otel-mapping.md`](otel-mapping.md).

### ICMP test (S7)

The `icmp` canary measures echo **loss, latency, and jitter** to a `target`
(IPv4 or IPv6). Configure it per-canary under `canaries:` (see
[`probectl-agent.example.yml`](../deploy/agent/probectl-agent.example.yml)). The
schedule `interval` and reply `timeout` are canary fields; the rest are `params`:

| Param           | Default | Meaning                                                                 |
| --------------- | ------- | ----------------------------------------------------------------------- |
| `count`         | `5`     | echo requests per probe (continuous mode defaults to the interval in s) |
| `payload_bytes` | `56`    | ICMP data bytes (minimum 8)                                             |
| `dscp`          | `0`     | DSCP marking 0–63 on outgoing packets (best-effort by platform)         |
| `mode`          | `batch` | `batch` (back-to-back) or `continuous` (1 packet/sec)                   |
| `privileged`    | `false` | `true` prefers raw sockets; default is unprivileged datagram ICMP       |

It emits `probectl_probe_loss_ratio`, `probectl_probe_rtt_{min,avg,max,stddev}_ms`,
`probectl_probe_jitter_ms`, and `probectl_probe_packets_{sent,received}`. A probe with
100% loss reports `success=false` (target unreachable); partial loss is a success
with a non-zero loss ratio. **Continuous mode** records a per-second drop-timing
record as result attributes (`icmp.dropped_seqs`, `icmp.drop_send_offsets_ms`) —
carried as OTel attributes, not TSDB labels, so they don't widen cardinality.

**Privileges.** By default the agent uses **unprivileged** datagram ICMP
(`IPPROTO_ICMP`), which on Linux requires the agent's group to be within
`net.ipv4.ping_group_range` (e.g. `sysctl -w net.ipv4.ping_group_range="0
2147483647"`). Alternatively grant raw-socket capability
(`setcap cap_net_raw+ep /usr/bin/probectl-agent`, or run with `CAP_NET_RAW`) and set
`privileged: "true"`. The canary tries the preferred socket and falls back to the
other; if neither can be opened it returns an internal error (the probe is not
silently reported as loss).

### TCP & UDP tests (S8)

The `tcp` and `udp` canaries are agent-to-server probes. Configure a `target` of
`host:port` (or a `host` with `params.port`). Both accept `count` and `dscp`.

The **`tcp`** canary measures **connect latency + reachability** (a connect-based,
unprivileged equivalent of a TCP-SYN test): it establishes a connection and times
the handshake, emitting `probectl_probe_connect_{min,avg,max,stddev}_ms`,
`probectl_probe_jitter_ms`, and `probectl_probe_loss_ratio` (failed connects = loss;
all-failed = `success=false`).

The **`udp`** canary is an **echo round-trip** probe: it sends token-tagged
datagrams and matches the echoes, emitting `probectl_probe_rtt_*` + loss. It needs a
target that echoes (a UDP echo service, or a probectl agent-to-agent responder); a
non-echoing target reports as 100% loss. `params.payload_bytes` (≥10) sets the
datagram size.

### Voice/RTP tests (S47c)

The `voice` canary streams real RTP packets at codec cadence to an echoing
target and scores the path: **MOS + R-factor (simplified ITU-T G.107
E-model), RFC 3550 jitter, loss, and a one-way delay estimate**. `target` is
`host:port`. Parameters: `codec` (`g711` default, `g729`),
`duration_seconds` (1–10, default 3), `dscp` (default 46/EF). The model
variant and the one-way-estimate method ride the result attributes — a
computed MOS is never presented as a measured listening score. See
`docs/voice.md`.

### DNS tests (S12)

The `dns` canary queries DNS and reports **resolution time, the answer, and an
optional DNSSEC verdict**. The `target` is the **query name**. Parameters:

| Param | Values | Default | Meaning |
| ----- | ------ | ------- | ------- |
| `type` | `A`, `AAAA`, `MX`, `TXT`, `NS`, … | `A` | record type to query |
| `transport` | `udp` \| `tcp` \| `dot` \| `doh` | `udp` | how the query is sent |
| `server` | `host[:port]` or a DoH URL | per-transport | resolver to query |
| `mode` | `resolver` \| `trace` | `resolver` | single query vs. delegation walk |
| `dnssec` | `true` \| `false` | `false` | validate the zone signature |

`server` defaults by transport: the first nameserver in `/etc/resolv.conf` (or
`1.1.1.1:53`) for `udp`/`tcp`, `1.1.1.1:853` for **DoT**, and
`https://cloudflare-dns.com/dns-query` for **DoH**. DoT verifies the resolver's
TLS certificate (TLS 1.2+); DoH posts an RFC 8484 `application/dns-message` query
over HTTPS.

In **resolver mode** the canary emits `probectl_probe_dns_query_ms` (round-trip) and
`probectl_probe_dns_answers` (answer count), with `dns.rcode` and a compact
`dns.answer` summary as attributes. The probe is `success=false` on a non-`NOERROR`
rcode or an empty answer.

With `dnssec: "true"` the canary requests DNSSEC records (the DO bit) and
**validates the zone's `RRSIG` over the answer against the zone `DNSKEY`** — it
does **not** trust the resolver's AD bit. The verdict lands in the `dns.dnssec`
attribute (`secure`, `insecure` for an unsigned zone, or `bogus`) and
`probectl_probe_dns_dnssec_secure` (1/0); a **bogus** result (tampered, expired, or
wrong-key signature) fails the probe. Validation verifies the signature on the
answer RRset; full chain-to-root anchoring is a later refinement.

In **trace mode** the canary performs an **iterative delegation walk** from the
root hints, following `NS`/glue referrals down to the authoritative server (UDP,
capped iterations, with a recursive fallback when a referral ships no glue). It
emits `probectl_probe_dns_query_ms` (total walk time) and
`probectl_probe_dns_trace_hops`, with the delegation chain in the `dns.trace`
attribute. DNS-exfiltration detection and open-data baselines are out of scope here
(S42 / open-data sprints).

### HTTP server tests (S13)

The `http` canary measures **HTTP(S) availability** with a full **response-time
breakdown** and captures **TLS handshake details** for the TLS-posture plane
(S27). The `target` is the URL. Parameters:

| Param | Values | Default | Meaning |
| ----- | ------ | ------- | ------- |
| `method` | `GET`, `HEAD`, `POST`, … | `GET` | request method |
| `expect_status` | codes / classes / ranges | `2xx,3xx` | which statuses count as available |
| `follow_redirects` | `true` \| `false` | `true` | follow 3xx redirects |
| `insecure_skip_verify` | `true` \| `false` | `false` | capture TLS but don't fail on an invalid cert. **Deny-by-default (U-040):** requires the admin-only `test.insecure_tls` permission and is flagged in the `test.create`/`test.update` audit entry |
| `ca_file` | path to a PEM bundle | — | extra trust anchor (private/internal CA) |
| `body` | string | — | request body (e.g. for `POST`) |
| `max_body_bytes` | integer | `10485760` | cap bytes read per probe (10 MiB) |
| `allow_private_targets` | `true` \| `false` | `false` | **SSRF-guard override (U-002).** Every canary (http/tcp/udp/icmp/dns/voice) denies loopback, RFC1918/ULA, link-local (incl. `169.254.169.254` cloud metadata), CGNAT, multicast and numeric-encoding bypasses by default, enforcing the check on the **resolved** address at dial time (rebind-proof). Setting `true` lifts the guard for that one test — requires the admin-only `test.allow_private` permission and is written to the tenant audit trail |

`expect_status` is a comma list of exact codes (`200`), classes (`2xx`), and
inclusive ranges (`200-204`); a response outside the set is `success=false` (the
status is still reported). The probe emits the timing breakdown as metrics —
`probectl_probe_http_dns_ms` (resolution), `probectl_probe_http_connect_ms` (TCP
connect), `probectl_probe_http_tls_ms` (TLS handshake), `probectl_probe_http_ttfb_ms`
(time to first byte), and `probectl_probe_http_total_ms` — plus
`probectl_probe_http_status`, `probectl_probe_http_content_bytes`, and
`probectl_probe_http_throughput_kbps`. A phase that does not occur (no DNS for an IP
target, no TLS for `http://`) is omitted rather than reported as zero. The resolved
server IP is captured as the `network.peer.address` attribute, which **correlates
the result to path/traceroute data** for the same destination (S10).

**TLS capture (for S27).** On HTTPS the canary records the negotiated
`tls.protocol.version` and `tls.cipher`, the leaf certificate's
`tls.server.{subject,issuer,not_before,not_after,san}`, the chain shape
(`tls.server.chain`), and a `probectl_probe_http_tls_cert_expiry_days` metric
(negative once expired). It verifies the chain itself (hostname + trust, honoring
`ca_file`) **after** capturing the certificate, so the handshake details are
recorded **even when the certificate is invalid or expired** — an invalid cert
fails the probe but its details are still attached. Set `insecure_skip_verify:
"true"` to capture posture without failing the availability check. probectl performs
no TLS *posture analysis* here (issuer trust, weak-cipher/expiry policy, CT) — that
is S27, which consumes these captured fields.

### Agent-to-agent tests (S8)

An agent-to-agent (A2A) test measures **between two registered agents**, brokered
by the control plane. The control plane assigns roles (one agent **responds**,
opening a short-lived listener; the other **initiates**), rendezvouses the
responder's endpoint to the initiator, and hands each agent its task when it
polls (`PollCoordination` / `ReportEndpoint`). The measurement is TWAMP-lite: the
initiator timestamps each probe (T1), the responder stamps receive/send (T2/T3)
and echoes, and the initiator stamps receive (T4), yielding **round-trip**
(`probectl_probe_rtt_*`) plus **forward** and **reverse** one-way delay
(`probectl_probe_forward_avg_ms`, `probectl_probe_reverse_avg_ms`). The responder also
reports forward-direction delivery (`probectl_probe_packets_received`,
`probectl_probe_loss_ratio`), so both agents and both directions are observed.

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

### BGP routing intelligence (S14)

The BGP plane is a Python analyzer (`analyzer/`) plus a Go bridge (`internal/bgp`);
see [`architecture.md`](architecture.md). The analyzer ingests **public** collector
data and emits `probectl.bgp.events`:

```sh
python -m probectl_analyzer --config config.json --mrt rib.mrt        # RouteViews/RIS dump
python -m probectl_analyzer --config config.json --replay cap.jsonl   # recorded RIS Live
python -m probectl_analyzer --config config.json --ris-live           # live RIS Live websocket
```

The JSON config is **per tenant** (`tenant_id` is required — every event carries
it, and the bridge rejects any event without one):

| Key | Meaning |
| --- | ------- |
| `tenant_id` | the owning tenant (outermost scope) |
| `monitored_prefixes[].prefix` | a prefix to watch (a more-specific announcement is matched too) |
| `monitored_prefixes[].expected_origins` | allowed origin ASNs — an origin outside this set raises `possible_hijack` |
| `monitored_prefixes[].no_transit` | ASNs that must not transit this prefix — mid-path appearance raises `possible_leak` |
| `collector` | collector label recorded on events (e.g. `rrc00`) |
| `rpki_vrp_file` / `rpki_vrp_url` | a `rpki-client`/Routinator VRP JSON export for RFC 6811 validation (absent → `unknown`) |

The analyzer emits `probectl.bgp.events` as **JSON Lines**; the Go bridge tails that
stream, validates the tenant, and republishes each as the canonical
`probectl.bgp.v1.BGPEvent` protobuf onto the bus (topic `probectl.bgp.events`, keyed by
tenant). Event types: `origin_change` (old/new origin + AS path), `possible_hijack`,
`possible_leak`, `rpki_invalid`; each carries an RPKI status (`valid` / `invalid` /
`not_found` / `unknown`), a severity, and a confidence — they are **signals**, not
actions (CLAUDE.md §7 guardrail 9). MRT dumps are **stream-processed** (no full RIB
in memory); a down RPKI/collector source degrades gracefully (guardrail 10).
RouteViews/RIS are open data — their AUP/provenance matters for MSP/commercial
resale, not for private development or single-tenant OSS use.

### Open-data enrichment (S15)

`internal/opendata` annotates IPs with ASN / geo / IXP / allocation context from
public datasets; see [`architecture.md`](architecture.md) and the source
provenance/AUP matrix in [`opendata-aup.md`](opendata-aup.md). The framework is a
library (wired into flow/test enrichment in later sprints); each source is
pluggable and individually enable-able:

| Source | Kind | Input it needs | Notes |
| ------ | ---- | -------------- | ----- |
| Team Cymru | `asn` | a DNS resolver | IP→ASN/prefix/registry/AS-name via the Cymru IP-to-ASN DNS service |
| MaxMind GeoLite2 | `geo` | a `.mmdb` path (`OpenMMDB`) | country/city/lat-lon; **operator-supplied DB** (not shipped) |
| PeeringDB | `ixp` | the ASN (from Cymru) | IXP/facility presence via the PeeringDB REST API; cached per ASN |
| RIR delegated-stats | `allocation` | a delegated-extended stats file | RIR/country/status/date; parsed once into a sorted index |
| RIPE Atlas (optional) | `measurement` | an API key + credits | active ping/traceroute scheduling hook; **off (fail-closed) by default** |

The `Enricher` runs every **enabled** source over an IP and merges the results,
**caching per IP** and **degrading gracefully**: a disabled / failing / slow /
panicking source is logged, marked `degraded` or `disabled` in `Enricher.Status()`,
and skipped — a partial enrichment is returned and a down dataset never breaks a
core path. Sources run in registration order (register the ASN source before
PeeringDB). Each contribution records `Provenance` (source + license + attribution
+ fields); a source's AUP (license, commercial-use permission, attribution) is on
its `Descriptor` — the matrix that gates MSP/commercial resale (not private or
single-tenant OSS use). All fetches are over TLS with certificate validation and
treated as untrusted (CLAUDE.md §7 guardrails 10, 12). Open data is ingested
**once and shared**; enrichment is scoped per tenant by the consuming record.

### Alerting (S16)

The alerting engine (`internal/alert`) evaluates rules over the TSDB and notifies
channels; see [`architecture.md`](architecture.md). Rules are CRUD'd via
**`/v1/alerts`** (tenant-scoped) and the engine runs in the control plane, ticking
every `PROBECTL_ALERT_EVAL_INTERVAL` (default `30s`).

A rule targets a metric series and is either a **threshold** or a **baseline**
rule:

| Field | Applies | Meaning |
| ----- | ------- | ------- |
| `metric` + `match` | both | the TSDB metric (e.g. `probectl_probe_loss_ratio`) and label matchers |
| `type` | both | `threshold` \| `baseline` |
| `comparison` + `threshold` | threshold | `gt`/`lt`/`gte`/`lte`/`eq`/`neq` vs a bound |
| `window` + `sensitivity` | baseline | rolling-history size and deviation (in std-devs); warms up until the window fills |
| `for_n` | both | consecutive breaching evals before firing (debounce) |
| `renotify_seconds` | both | re-notify cadence while firing (`0` = notify once) |
| `severity` | both | `info` \| `warning` \| `critical` |
| `channels` | both | webhook / email destinations |

A `channels` entry is `{"type":"webhook","url":...,"secret":...}` or
`{"type":"email","recipients":[...]}`. The webhook **secret** is the HMAC key; it
is **redacted (`***`) from API responses** and never returned. SMTP for email is
configured at the deployment level (a follow-up exposes it as config).

**Webhook payload (`probectl.alert.v1`).** On fire/resolve the webhook channel POSTs:

```json
{
  "version": "probectl.alert.v1",
  "state": "firing",
  "rule": { "id": "…", "name": "loss-high" },
  "tenant_id": "…",
  "severity": "critical",
  "metric": "probectl_probe_loss_ratio",
  "labels": { "server_address": "1.1.1.1" },
  "value": 0.9,
  "threshold": 0.5,
  "comparison": "gt",
  "reason": "probectl_probe_loss_ratio=0.9 gt 0.5",
  "fired_at": "2026-01-02T15:04:05Z"
}
```

When the channel has a secret, the request carries
`X-Probectl-Signature: sha256=<hex>` — the HMAC-SHA256 of the exact body — so the
receiver can verify the sender. Each channel delivers independently: a failing
channel is logged and skipped, never blocking the others. Alerts are **signals**;
probectl notifies and does not act on the network (on-call/ITSM routing is S33,
detection-as-code is S42).

### Incidents (S17)

The incident correlator (`internal/incident`) groups related signals across planes
into one **Incident** with a unified **timeline**; see [`architecture.md`](architecture.md).
It runs in the control plane, fed by the alert engine (network plane) and a
`probectl.bgp.events` consumer (BGP plane), and is exposed at **`/v1/incidents`**
(tenant-scoped):

- `GET /v1/incidents` — the tenant's incidents, most-recently-active first.
- `GET /v1/incidents/{id}` — an incident with its time-ordered signal timeline.
- `PATCH /v1/incidents/{id}` with `{"status":"resolved"}` — resolve an incident.

Signals correlate into one incident when they are **close in time**
(within `PROBECTL_INCIDENT_WINDOW`, default `10m`) **and related in target** — the
same target, an IP inside the other's prefix (either direction), or overlapping
prefixes (so a network alert on `192.0.2.10` and a BGP event on `192.0.2.0/24`
land together). An incident's severity is the **max** of its signals; a signal
without a tenant is rejected (fail closed).

The model is **extensible without schema churn**: a `Signal` carries a free-form
`plane`/`kind` and an arbitrary `attributes` map, so later sprints attach the
change (S29), threat (S42), cost, and SLO planes as additional signal types onto
the same `Incident`/timeline. AI root-cause analysis over the timeline is S24.

### SSO & RBAC (S18)

probectl authenticates users with **OIDC SSO** and authorizes them with **RBAC** over
the S2 role model. The security order is the **two-level boundary** (CLAUDE.md §7
guardrails 1, 5): a request resolves to **exactly one tenant first**, then RBAC
decides whether the caller may perform the route's action within that tenant.

**Login flow.** `GET /auth/login` (optionally `?tenant=<uuid>`) starts the OIDC
authorization-code flow: it sets a short-lived, HttpOnly CSRF `state` cookie and
redirects to the tenant's identity provider. The IdP redirects back to
`GET /auth/callback`, which verifies the `state`, exchanges the code, verifies the
ID token, **just-in-time provisions** the user within the tenant (a brand-new user
gets **no roles** — a secure default; an admin grants access), mints a server-side
session, and sets the session cookie. `POST /auth/logout` revokes the session.
`GET /v1/me` returns the caller's tenant, identity, and effective permissions.

**Sessions.** A session is a random, high-entropy opaque token. Only its **hash**
is stored (table `sessions`), so a database read cannot mint a session (guardrail
6). The session cookie is **HttpOnly + SameSite=Lax**, and **Secure** whenever the
API serves HTTPS. `PROBECTL_SESSION_TTL` (default `12h`) bounds its lifetime.

**Per-tenant IdP.** Providers are resolved per tenant through a provider factory —
the seam for a tenant bringing its own SSO. S18 ships the env-configured default
(`PROBECTL_OIDC_*`); DB-backed per-tenant IdP config is a later sprint. A login
always resolves to a single tenant. Provider/MSP operators authenticate into the
**provider domain** (S-T1), not into tenant data.

**RBAC.** Every `/v1` route declares a required **permission key**; the wrapped
handler returns **401** when unauthenticated and **403** when the principal lacks
the permission — checked *before* the handler runs. Effective permissions are
loaded per request from the user's role bindings (RLS-scoped to the tenant), so a
role grant or revoke takes effect immediately. The permission catalog:

| Permission        | Granted to (seeded roles)   | Guards |
| ----------------- | --------------------------- | ------ |
| `test.read`       | viewer, editor, admin       | `GET /v1/tests*`, `GET /v1/tests/{id}/path` |
| `test.write`      | editor, admin               | `POST/PUT/DELETE /v1/tests*`, `POST .../path` |
| `agent.read`      | viewer, editor, admin       | `GET /v1/agents*` |
| `agent.write`     | admin                       | `PATCH/DELETE /v1/agents/{id}` |
| `alert.read`      | viewer, editor, admin       | `GET /v1/alerts*` |
| `alert.write`     | editor, admin               | `POST/PUT/DELETE /v1/alerts*` |
| `incident.read`   | viewer, editor, admin       | `GET /v1/incidents*` |
| `incident.write`  | editor, admin               | `PATCH /v1/incidents/{id}` |

The seeded system roles for the default tenant are **admin** (all permissions),
**editor** (read everything + manage tests/alerts/incidents), and **viewer**
(read-only). `GET /v1/me` requires only authentication (no specific permission).

**Dev mode.** `PROBECTL_AUTH_MODE=dev` bypasses SSO and synthesizes an
all-permissions principal for the default tenant, with the
`X-Probectl-Tenant: <uuid>` override for multi-tenant dev. Since RED-001 it is
**triple-gated**: (1) the code path exists only in binaries built with
`-tags devauth` (`make build-devauth`) — a release binary **refuses to start**
in this mode; (2) `PROBECTL_DEV_AUTH_ACK=i-understand` must be set; (3) the
listener must bind loopback (`PROBECTL_HTTP_ADDR=127.0.0.1:…`). When active it
logs at error level and writes an `auth.dev_mode_active` audit event. The CI
gate `no-devauth-in-release` proves release binaries contain neither the
symbols nor the dev-principal literal. The test suite installs its own hook
in `_test.go` files, which never ship.

### Resource API & CLI (S9)

The versioned resource API lives under **`/v1`** (full schema at `/openapi.json`):

- `GET/POST /v1/tests`, `GET/PUT/DELETE /v1/tests/{id}` — synthetic-test CRUD.
- `GET /v1/agents`, `GET/PATCH/DELETE /v1/agents/{id}` — agents register over
  mTLS; the API lists, renames, and deregisters them.
- `GET/POST /v1/tests/{id}/path` (S11) — the latest discovered network path for a
  test, and a trigger to discover it now. The path-viz hero UI (Path & Topology)
  consumes this.

Every `/v1` route is **tenant-scoped** through `internal/tenancy` + Postgres RLS,
so a request can never read or write across tenants. **Authentication and RBAC are
real from S18** (see *SSO & RBAC* below): the caller's tenant and effective
permissions come from an authenticated session, and each route requires a
permission. The `no undocumented routes` rule is enforced by a test that matches
the route table against `openapi.json`.

The **`probectl` CLI** is the web-parity client. Configure it with flags or
environment: `PROBECTL_API_URL` (default `http://localhost:8080`),
`PROBECTL_API_TOKEN` (sent as Bearer), `PROBECTL_TENANT` (sent as `X-Probectl-Tenant`).

```bash
probectl test list
probectl test create --name edge-dns --type icmp --target 1.1.1.1 --interval 30
probectl test delete <id>
probectl agent list
probectl --json test list      # machine-readable output
```

### eBPF host agent (S20)

The eBPF agent (`probectl-ebpf-agent`) is configured by a YAML file (`-config` or
`PROBECTL_EBPF_CONFIG`); see
[`deploy/agent/probectl-ebpf-agent.example.yml`](../deploy/agent/probectl-ebpf-agent.example.yml)
and [`ebpf-agent.md`](ebpf-agent.md). `PROBECTL_EBPF_*` env vars override the file.
The agent is **observe-only**; the CO-RE loader is compiled in only with
`-tags ebpf` — otherwise set `fixture_path` for the no-kernel path.

| Variable                     | Default     | Description                                                     |
| ---------------------------- | ----------- | -------------------------------------------------------------- |
| `PROBECTL_EBPF_CONFIG`         | (none)      | path to the YAML config (`-config` flag overrides)             |
| `PROBECTL_EBPF_TENANT_ID`      | (required)  | tenant every flow is stamped with (F50)                        |
| `PROBECTL_EBPF_HOST`           | OS hostname | observing host name                                            |
| `PROBECTL_EBPF_BUS_MODE`       | `memory`    | `memory` \| `kafka`                                            |
| `PROBECTL_EBPF_BUS_BROKERS`    | (none)      | comma-separated Kafka brokers (kafka mode)                     |
| `PROBECTL_EBPF_FIXTURE_PATH`   | (none)      | replay recorded flows instead of loading eBPF (no-kernel path) |
| `PROBECTL_EBPF_L7_FIXTURE_PATH` | (none)     | replay recorded L7 events (no-kernel L7 path, S21)             |
| `PROBECTL_EBPF_LIBSSL`         | (auto)      | libssl path for TLS-uprobe L7 capture (`-tags ebpf`)           |
| `PROBECTL_EBPF_L7_CAPTURE`     | `false`     | **U-003:** live TLS-plaintext capture is OFF by default; `true` alone is not enough — consent below is also required |
| `PROBECTL_EBPF_L7_CONSENT_TENANT` | (none)   | the EXPLICIT per-tenant consent: must equal this agent's bound tenant id exactly, else capture stays off |
| `PROBECTL_EBPF_L7_REDACTION`   | `headers`   | capture-boundary policy: `headers` zeroes payload bodies in place before any retention (protocol metadata survives); `full` (consented debugging) disables masking |
| `PROBECTL_EBPF_PROC_ROOT`      | `/proc`     | procfs root for process/cgroup enrichment                      |
| `PROBECTL_EBPF_FLUSH_INTERVAL` | `10s`       | how often flows + the service map are emitted                  |
| `PROBECTL_EBPF_LOG_LEVEL`      | `info`      | `debug` \| `info` \| `warn` \| `error`                         |
| `PROBECTL_EBPF_LOG_FORMAT`     | `json`      | `json` \| `text`                                               |

Flows + service edges are published to `probectl.ebpf.flows` (`ebpfv1.FlowBatch`,
tenant-keyed). The live loader needs a BTF Linux kernel (≥5.8) and
`CAP_BPF`/`CAP_PERFMON`; see [`ebpf-agent.md`](ebpf-agent.md).

### Endpoint / DEM agent (`probectl-endpoint`, S37)

The endpoint agent runs on a user's device (Linux/macOS/Windows), captures
last-mile experience, and attributes slowdowns to WiFi/ISP/network. It reads a
YAML config (default path `PROBECTL_ENDPOINT_CONFIG`); `PROBECTL_ENDPOINT_*` env vars
override the file. See [`endpoint-dem.md`](endpoint-dem.md).

| Variable                              | Default        | Meaning                                                          |
| ------------------------------------- | -------------- | ---------------------------------------------------------------- |
| `PROBECTL_ENDPOINT_CONFIG`              | (none)         | path to the YAML config (`-config` flag overrides)               |
| `PROBECTL_ENDPOINT_TENANT_ID`           | (required)     | tenant every DEM result is stamped with (F50)                    |
| `PROBECTL_ENDPOINT_AGENT_ID`            | OS hostname    | device identifier in the fleet                                   |
| `PROBECTL_ENDPOINT_BUS_MODE`            | `memory`       | `memory` \| `kafka`                                              |
| `PROBECTL_ENDPOINT_BUS_BROKERS`         | (none)         | comma-separated Kafka brokers (kafka mode)                       |
| `PROBECTL_ENDPOINT_INTERVAL`            | `60s`          | how often a sample is collected                                  |
| `PROBECTL_ENDPOINT_TARGETS`             | 1.1.1.1,google | comma-separated targets (first = last-mile trace; all = session) |
| `PROBECTL_ENDPOINT_MAX_HOPS`            | `20`           | last-mile trace hop cap                                          |
| `PROBECTL_ENDPOINT_COLLECT_SSID`        | `true`         | retain the WiFi network name (SSID)                              |
| `PROBECTL_ENDPOINT_COLLECT_BSSID`       | `false`        | retain the AP MAC (BSSID) — geolocatable PII, off by default     |
| `PROBECTL_ENDPOINT_COLLECT_GATEWAY_IP`  | `true`         | retain the (private) default-gateway address                    |
| `PROBECTL_ENDPOINT_COLLECT_PUBLIC_HOPS` | `false`        | retain PUBLIC last-mile hop IPs (reveal ISP/geo), off by default |
| `PROBECTL_ENDPOINT_LOG_LEVEL`           | `info`         | `debug` \| `info` \| `warn` \| `error`                           |
| `PROBECTL_ENDPOINT_LOG_FORMAT`          | `json`         | `json` \| `text`                                                 |

DEM results (WiFi / gateway / last-mile / session signals + the attribution
verdict) are published to `probectl.endpoint.results` (`resultv1.Result`,
tenant-keyed), flowing through the same pipeline as every other canary. The agent
**discloses exactly what it collects at startup** and never phones home.

### Flow collector (`probectl-flow-agent`, S38)

The flow collector listens for NetFlow v5/v9, IPFIX, and sFlow v5 datagrams from
network devices, decodes them (template + sampling handling), and publishes
normalized batches to `probectl.flow.events` (`flowv1.FlowBatch`, tenant-keyed).
It reads a YAML config (default path `PROBECTL_FLOW_CONFIG`); `PROBECTL_FLOW_*`
env vars override the file. See [`flow.md`](flow.md) for the security posture —
flow export protocols are plaintext UDP by design, so every datagram is treated
as untrusted and the collector should sit adjacent to its exporters.

| Variable                          | Default     | Meaning                                                        |
| --------------------------------- | ----------- | --------------------------------------------------------------- |
| `PROBECTL_FLOW_CONFIG`             | (none)      | path to the YAML config (`-config` flag overrides)              |
| `PROBECTL_FLOW_BUS_NAMESPACE` | (none) | TENANT-107: publish this agent's batches on its tenant's SILOED bus lane (`probectl.<ns>.flow.events`); malformed value refuses start (RED-006). Same key exists per plane: `PROBECTL_DEVICE_BUS_NAMESPACE`, `PROBECTL_EBPF_BUS_NAMESPACE`, `PROBECTL_ENDPOINT_BUS_NAMESPACE` |
| `PROBECTL_FLOW_TENANT`             | (required)  | tenant every flow record is stamped with (F50)                  |
| `PROBECTL_FLOW_AGENT_ID`           | OS hostname | collector identifier                                            |
| `PROBECTL_FLOW_BUS_MODE`           | `memory`    | `memory` \| `kafka`                                             |
| `PROBECTL_FLOW_BUS_BROKERS`        | (none)      | comma-separated Kafka brokers (kafka mode)                      |
| `PROBECTL_FLOW_NETFLOW_ENABLED`    | `true`      | serve NetFlow v5 **and** v9 (version-sniffed) on one socket     |
| `PROBECTL_FLOW_NETFLOW_LISTEN`     | `:2055`     | NetFlow UDP listen address                                      |
| `PROBECTL_FLOW_IPFIX_ENABLED`      | `true`      | serve IPFIX                                                     |
| `PROBECTL_FLOW_IPFIX_LISTEN`       | `:4739`     | IPFIX UDP listen address                                        |
| `PROBECTL_FLOW_SFLOW_ENABLED`      | `true`      | serve sFlow v5                                                  |
| `PROBECTL_FLOW_SFLOW_LISTEN`       | `:6343`     | sFlow UDP listen address                                        |
| `PROBECTL_FLOW_BATCH_SIZE`         | `1000`      | records per emitted batch                                       |
| `PROBECTL_FLOW_FLUSH_INTERVAL`     | `2s`        | max time a record waits before emission                         |
| `PROBECTL_FLOW_TEMPLATE_TTL`       | `30m`       | v9/IPFIX template expiry                                        |
| `PROBECTL_FLOW_MAX_TEMPLATES`      | `4096`      | template-cache size cap (untrusted-input bound)                 |
| `PROBECTL_FLOW_READ_BUFFER_BYTES`  | `4194304`   | kernel UDP receive buffer (burst absorption)                    |
| `PROBECTL_FLOW_QUEUE_SIZE`         | `65536`     | decode→flush channel depth (overflow drops are counted)         |
| `PROBECTL_FLOW_WORKERS`            | `2`         | reader goroutines per socket                                    |
| `PROBECTL_FLOW_LOG_LEVEL`          | `info`      | `debug` \| `info` \| `warn` \| `error`                          |
| `PROBECTL_FLOW_LOG_FORMAT`         | `json`      | `json` \| `text`                                                |

The **control plane** consumes the topic, optionally enriches ASN/geo, and
persists to the flow store backing `/v1/flows/*` (top-talkers / capacity /
anomalies):

| Variable                        | Default  | Meaning                                                             |
| -------------------------------- | -------- | -------------------------------------------------------------------- |
| `PROBECTL_FLOWSTORE_MODE`         | `memory` | `memory` \| `clickhouse`                                             |
| `PROBECTL_FLOWSTORE_URL`          | (none)   | ClickHouse HTTP(S) endpoint (required in clickhouse mode)            |
| `PROBECTL_FLOW_RETENTION_DAYS`    | `0`      | > 0 applies a ClickHouse delete-TTL to `probectl_flows`              |
| `PROBECTL_FLOW_ENRICH_ASN`        | `false`  | OPT-IN Team Cymru ASN enrichment (outbound DNS — off by default per the no-phone-home guardrail; device-exported AS numbers always pass through) |

### Device telemetry agent (`probectl-device-agent`, S39)

The device agent polls network devices over **SNMP v2c/v3** and subscribes to
**gNMI/OpenConfig** streams, normalizes both into one `DeviceMetric` model, and
publishes to `probectl.device.metrics` (`devicev1.DeviceMetricBatch`,
tenant-keyed). The control plane lands the samples in the TSDB as
`probectl_device_*` series. Devices and transports are declared in a YAML
config (see `deploy/agent/probectl-device-agent.example.yml`); the env vars
below override the file and offer a single-device quick start. See
[`device-telemetry.md`](device-telemetry.md).

| Variable                       | Default     | Meaning                                                          |
| ------------------------------- | ----------- | ----------------------------------------------------------------- |
| `PROBECTL_DEVICE_CONFIG`         | (none)      | path to the YAML config (`-config` flag overrides)                |
| `PROBECTL_DEVICE_TENANT`         | (required)  | tenant every device metric is stamped with (F50)                  |
| `PROBECTL_DEVICE_AGENT_ID`       | OS hostname | agent identifier                                                  |
| `PROBECTL_DEVICE_BUS_MODE`       | `memory`    | `memory` \| `kafka`                                               |
| `PROBECTL_DEVICE_BUS_BROKERS`    | (none)      | comma-separated Kafka brokers (kafka mode)                        |
| `PROBECTL_DEVICE_TARGET`         | (none)      | quick start: add one device by address                            |
| `PROBECTL_DEVICE_TRANSPORT`      | `snmpv2c`   | quick-start transport: `snmpv2c` \| `snmpv3` \| `gnmi`            |
| `PROBECTL_DEVICE_CREDENTIAL`     | (none)      | quick start: credential NAME for the device (see below)           |
| `PROBECTL_DEVICE_PORT`           | `161`/`9339`| quick start: SNMP/gNMI port override                              |
| `PROBECTL_DEVICE_INTERVAL`       | `60s`       | quick start: poll/sample interval                                 |
| `PROBECTL_DEVICE_LOG_LEVEL`      | `info`      | `debug` \| `info` \| `warn` \| `error`                            |
| `PROBECTL_DEVICE_LOG_FORMAT`     | `json`      | `json` \| `text`                                                  |

**Credentials are referenced by NAME, never inlined** (guardrail 6). The
default `CredentialSource` resolves names from the environment; S41 plugs
Vault/CyberArk into the same seam. An unresolvable name fails closed at
startup. `<NAME>` is the upper-cased credential name with `-`/`.` → `_`:

| Variable                                  | Used by        | Meaning                                        |
| ------------------------------------------ | -------------- | ----------------------------------------------- |
| `PROBECTL_DEVICE_CRED_<NAME>_COMMUNITY`     | snmpv2c        | community string                                |
| `PROBECTL_DEVICE_CRED_<NAME>_USERNAME`      | snmpv3, gnmi   | USM user / gNMI metadata user                   |
| `PROBECTL_DEVICE_CRED_<NAME>_AUTH_PROTO`    | snmpv3         | `sha` (default) \| `sha256` \| `sha512` \| `md5` |
| `PROBECTL_DEVICE_CRED_<NAME>_AUTH_PASS`     | snmpv3         | auth passphrase (empty → NoAuthNoPriv)          |
| `PROBECTL_DEVICE_CRED_<NAME>_PRIV_PROTO`    | snmpv3         | `aes` (default) \| `aes256` \| `des`            |
| `PROBECTL_DEVICE_CRED_<NAME>_PRIV_PASS`     | snmpv3         | privacy passphrase (empty → AuthNoPriv)         |
| `PROBECTL_DEVICE_CRED_<NAME>_PASSWORD`      | gnmi           | gNMI metadata password                          |

gNMI connections are **TLS with certificate verification** (system roots or a
per-device `ca_file`); there is no skip-verify option. `plaintext: true` is an
explicit lab-only YAML opt-in and is loudly logged (guardrail 12).

### OTLP receiver (S22)

The control plane optionally ingests external OpenTelemetry metrics over OTLP —
**TLS-only, authenticated, and tenant-scoped** (CLAUDE.md §7 guardrail 12). It is
off by default and runs on its own listeners (separate from the `/v1` REST API).
See [`otlp.md`](otlp.md).

| Variable                    | Default | Description                                                  |
| --------------------------- | ------- | ------------------------------------------------------------ |
| `PROBECTL_OTLP_GRPC_ADDR`     | (none)  | OTLP/gRPC listen address (e.g. `:4317`)                      |
| `PROBECTL_OTLP_HTTP_ADDR`     | (none)  | OTLP/HTTP listen address (e.g. `:4318`; `POST /v1/metrics`)  |
| `PROBECTL_OTLP_TLS_CERT_FILE` | (none)  | PEM server certificate (required to enable)                  |
| `PROBECTL_OTLP_TLS_KEY_FILE`  | (none)  | PEM server private key (required to enable)                  |
| `PROBECTL_OTLP_TOKENS`        | (none)  | bearer-token→tenant map: `token1=tenant1,token2=tenant2`     |

Setting an address without the TLS files **and** at least one token fails config
validation — the receiver is never anonymous plaintext. Ingested metrics are
tenant-tagged and published to the `probectl.otlp.metrics` bus topic.

### Ecosystem integrations (S40)

The Grafana datasource API (`/v1/grafana/api/v1/*`), the federation endpoint
(`/v1/prometheus/federate`), and the remote-write receiver
(`/v1/prometheus/write`) ride the existing TSDB config (`PROBECTL_TSDB_MODE` /
`PROBECTL_TSDB_URL`) and the `/v1` API listener — no extra keys. Reads need
`metrics.read`, remote-write `metrics.write` (migration 0022). See
[`ecosystem-integrations.md`](ecosystem-integrations.md).

The ServiceNow CMDB correlation is off unless configured:

| Variable                  | Default   | Meaning                                                            |
| -------------------------- | --------- | ------------------------------------------------------------------- |
| `PROBECTL_CMDB_PROVIDER`    | (none)    | `servicenow` enables CI correlation (`/v1/cmdb/*`, incident/agent CIs) |
| `PROBECTL_CMDB_URL`         | (none)    | instance URL, e.g. `https://acme.service-now.com` (https; http only for loopback test doubles) |
| `PROBECTL_CMDB_SECRET`      | (none)    | `user:password` for the read-only integration user (env only — never in files/logs) |
| `PROBECTL_CMDB_TABLE`       | `cmdb_ci` | CI table queried via the Table API                                  |
| `PROBECTL_CMDB_CACHE_TTL`   | `10m`     | CI lookup cache TTL (a down CMDB serves stale entries)              |

### AI assistant (S24)

The AI assistant (RCA / NL query) is on by default using the **built-in,
in-process synthesizer** — fully air-gapped, no network, no phone-home. Point it
at a model only if you want LLM-written prose; a remote endpoint must be `https`
(a non-loopback `http` endpoint is refused — guardrail 12), while loopback may be
`http` for a co-located local model. See [`ai-rca.md`](ai-rca.md).

| Variable                   | Default   | Description                                                         |
| -------------------------- | --------- | ------------------------------------------------------------------ |
| `PROBECTL_AI_MODEL_PROVIDER` | `builtin` | `builtin` (air-gapped) \| `ollama` \| `openai` \| `anthropic`      |
| `PROBECTL_AI_EGRESS_ACK` | (none) | **required for a REMOTE model endpoint** (U-013): must equal `yes-send-tenant-data-to-the-remote-model`; the server refuses to start otherwise. Per-tenant consent + audit on top — see [`docs/ai-egress.md`](ai-egress.md) |
| `PROBECTL_AI_REDACT_IPS` | `true` | C8: mask IPs in prompts before a REMOTE model call (stable per-value tokens; local paths never redacted) |
| `PROBECTL_AI_REDACT_HOSTNAMES` | `false` | C8: also mask hostnames in remote prompts (secrets are always masked) |
| `PROBECTL_AI_MODEL_ENDPOINT` | (none)    | base URL of the model (required for a non-`builtin` provider)      |
| `PROBECTL_AI_MODEL_NAME`     | (none)    | model name (e.g. `llama3.1`, `gpt-4o-mini`)                        |
| `PROBECTL_AI_MODEL_TOKEN`    | (none)    | API key / bearer token (optional for a local Ollama)              |
| `PROBECTL_AI_MODEL_TIMEOUT`  | `60s`     | per-request timeout for the model endpoint                         |
| `PROBECTL_AI_MAX_EVIDENCE`   | `50`      | cost guard: max signals an answer may gather                       |
| `PROBECTL_AI_MAX_CONCURRENT` | `8`       | U-048: process-wide cap on concurrent RCA analyses (fail-fast 429); a backstop under the per-tenant fairness gate |
| `PROBECTL_AI_PERSIST_ANSWERS` | `false`  | U-093: persist every RCA answer (full cited JSON + model + config hash) for reproducibility/disputes |
| `PROBECTL_AI_ANSWER_RETENTION` | `2160h` (90d) | U-093: prune persisted answers older than this (enforced opportunistically on write) |

A non-`builtin` provider without an endpoint fails config validation. Whatever
the backend, every answer is tenant-and-RBAC-scoped by the S23 query layer and
every claim is citation-checked before it reaches the user — a model can never
see out-of-scope data or inject an ungrounded claim.

### MCP server (S25)

The MCP server exposes read-only, tenant- + RBAC-scoped tools to AI clients. The
**HTTP** transport is off by default and is **TLS-only + bearer-authenticated**
(guardrail 12); the **stdio** transport is local (`probectl-control mcp-stdio`,
token from `PROBECTL_MCP_TOKEN`). See [`mcp.md`](mcp.md).

| Variable                   | Default | Description                                                   |
| -------------------------- | ------- | ------------------------------------------------------------- |
| `PROBECTL_MCP_HTTP_ADDR`     | (none)  | MCP HTTP listen address (e.g. `:8090`) — enables the transport |
| `PROBECTL_MCP_TLS_CERT_FILE` | (none)  | PEM server certificate (required to enable HTTP)              |
| `PROBECTL_MCP_TLS_KEY_FILE`  | (none)  | PEM server private key (required to enable HTTP)              |
| `PROBECTL_MCP_RATE_PER_MIN`  | `120`   | per-tenant tool-call rate limit (0 disables)                  |

Setting `PROBECTL_MCP_HTTP_ADDR` without the TLS files fails config validation — the
MCP endpoint is never anonymous plaintext.

### TLS / certificate observability (S27)

The control plane analyzes TLS/cert posture from **already-captured** TLS (S13/S21)
— it never re-handshakes — and correlates findings into threat-plane incidents.
See [`tls-observability.md`](tls-observability.md).

| Variable                    | Default        | Description                                                       |
| --------------------------- | -------------- | ----------------------------------------------------------------- |
| `PROBECTL_TRUSTCTL_URL`        | (none)         | trustctl base URL; enables a one-click renewal deep-link on findings |
| `PROBECTL_TLS_EXPIRY_WARNING` | `504h` (21d)   | expiring-soon window                                              |
| `PROBECTL_CT_ENABLED`         | `false`        | opt in to Certificate Transparency correlation (external fetch)   |
| `PROBECTL_CT_ENDPOINT`        | `https://crt.sh` | CT log API endpoint                                             |

CT correlation is **off by default** (an external fetch — sovereignty / AUP /
rate limits) and degrades gracefully when the CT source is down.

### Threat-intel enrichment (S28)

The control plane can match peer IPs / hostnames / certs / JA3 against public
threat-intel feeds, surfacing **confidence-scored, source-attributed** threat-plane
signals (a **signal, not an IPS** — never blocks). See
[`threat-intel.md`](threat-intel.md) for the feed/AUP matrix and caveats.

| Variable                     | Default | Description                                                       |
| ---------------------------- | ------- | ----------------------------------------------------------------- |
| `PROBECTL_THREATINTEL_ENABLED` | `false` | master switch (outbound feed fetches); off ⇒ no IOC code runs     |
| `PROBECTL_THREATINTEL_REFRESH` | `6h`    | feed refresh cadence                                              |
| `PROBECTL_THREATINTEL_FEEDS`   | (all)   | comma-separated feed names (`spamhaus_drop`, `feodo_tracker`, `sslbl`, `sslbl_ja3`, `urlhaus`, `tor_exit`, `firehol_level1`); empty ⇒ all |

**Off by default** (an outbound fetch — sovereignty / no-phone-home). The
refresher keeps each source's **last-good** indicators, so a feed outage degrades
gracefully and never breaks a core path.

### Enterprise identity: SCIM + ABAC (S31)

SCIM 2.0 provisioning and ABAC have **no environment keys** — the SCIM bearer token
an IdP presents is minted with the control-plane CLI, and ABAC policies are managed
over the API. See [`scim-abac.md`](scim-abac.md).

```
# mint a per-tenant SCIM token for an IdP (shown once)
probectl-control scim-token --tenant <tenant-uuid> --name okta
```

The `/scim/v2/*` surface is gated by a valid SCIM token (no token ⇒ `401`), and the
directory-admin API (`/v1/abac/policies`) requires `directory.read`/`directory.write`.

### Change intelligence (S29)

Ingest per-provider-signed change webhooks (deploys/config/route/IaC/commits) into
a change timeline + change-to-incident correlation, feeding the AI RCA. See
[`change-intel.md`](change-intel.md) for the webhook contract + provider/signature
table.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_CHANGE_WEBHOOKS` | (none) | comma-separated `id:tenant:provider:secret` webhook credentials (`provider` ∈ `generic`/`github`/`gitlab`). The secret is the last field, so it may contain `:` but not `,` — use URL-safe (hex/base64) secrets. |
| `PROBECTL_CHANGE_CORRELATION_WINDOW` | `24h` | how far before an incident a change is treated as a candidate cause |

Each inbound delivery is **TLS + signature-verified (HMAC/token, constant-time) +
tenant-bound to the credential**; an unsigned or forged event is rejected before
storage, and one tenant cannot inject another's changes. Webhook secrets are
runtime config — inject them from a secret manager, never commit them.

### SIEM export (S32)

Forward the **audit stream** and **threat-plane signals** to a SOC's SIEM over
hardened TLS. probectl is the **forwarder, not a SIEM** — events are rendered into a
standard format and pushed; nothing is auto-blocked. See [`siem.md`](siem.md) for
formats, delivery guarantees, and per-SIEM setup.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_SIEM_ENABLED` | `false` | master switch (an outbound connection to your SIEM); off ⇒ no SIEM code runs |
| `PROBECTL_SIEM_PRESET` | `generic` | SIEM adapter: `generic`, `splunk`, `sentinel`, `elastic`, `chronicle` (sets the auth scheme + default format) |
| `PROBECTL_SIEM_FORMAT` | (preset) | wire format: `syslog` (RFC 5424), `cef`, `ecs`, `otlp`; empty ⇒ the preset's native default (Elastic⇒ecs, Chronicle⇒otlp, else cef) |
| `PROBECTL_SIEM_ENDPOINT` | (none) | HTTPS ingest URL (e.g. the Splunk HEC / Sentinel / Chronicle / Elasticsearch endpoint). Required when enabled |
| `PROBECTL_SIEM_TOKEN` | (none) | ingest credential (Splunk ⇒ `Splunk <tok>`, Elastic ⇒ `ApiKey <tok>`, others ⇒ `Bearer <tok>`). Inject from a secret manager |
| `PROBECTL_SIEM_POLL_INTERVAL` | `30s` | audit-stream drain cadence |
| `PROBECTL_SIEM_BUFFER` | `1024` | threat-signal buffer; full ⇒ producers block (backpressure, never drop) |
| `PROBECTL_SIEM_REDACT_KEYS` | (none) | extra audit `data` keys to scrub (on top of the built-in secret/PII denylist) |

**Off by default** (an outbound connection — sovereignty / no-phone-home). Audit
forwarding resumes from a **durable per-tenant cursor**, and delivery **retries
without dropping** under a SIEM outage. Exported audit events are **PII/secret
redacted** (built-in denylist + `PROBECTL_SIEM_REDACT_KEYS`).

### On-call + ITSM integration (S33)

Mirror incidents into operational tooling: page on-call (PagerDuty/Opsgenie), post
to chat (Slack/Teams), and open + **bidirectionally sync** tickets (ServiceNow/Jira).
probectl is the forwarder, not the system of record — it never auto-blocks anything.
See [`oncall-itsm.md`](oncall-itsm.md) for the connector matrix, mapping, and the
inbound webhook contract.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_NOTIFY_CONNECTORS` | (none) | outbound connectors, comma-separated, each `tenant\|provider\|endpoint\|secret` (pipe-delimited because the endpoint is a URL). `provider` ∈ `pagerduty`/`opsgenie`/`slack`/`teams`/`servicenow`/`jira`. `secret` is the provider credential (PagerDuty routing key, Opsgenie API key, ServiceNow `user:password`, Jira `email:token`; unused for chat). |
| `PROBECTL_NOTIFY_INBOUND` | (none) | inbound status-sync credentials, comma-separated, each `id:tenant:provider:secret` (the `id` is the URL selector for `POST /ingest/itsm/{provider}/{id}`; `secret` verifies the delivery). |

**Off by default** (each connector is an outbound connection to the operator's
tooling). Paging + ticket creation are **idempotent** (an incident opens at most
once per connector — a retry/restart never double-pages), status sync is
**bidirectional** with **loop protection** (an inbound resolve from one system is
never echoed back to it), and routing is **per-tenant** (a connector only fires for
its own tenant). Endpoint specifics: a Slack/Teams endpoint is the incoming-webhook
URL; a Jira endpoint carries the project (and optional resolve transition) as query
params, e.g. `…/rest/api/2/issue?project=OPS&resolve_transition=31`; a ServiceNow
endpoint is the `…/api/now/table/incident` URL. Inbound deliveries must include
`X-Probectl-Signature: sha256=<hmac>` or `X-Probectl-Token: <secret>` over TLS; an
unsigned or forged delivery is rejected (`401`). Secrets are runtime config —
inject them from a secret manager, never commit them.

### Topology graph + what-if (S43)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_TOPOLOGY_ENGINE` | `indexed` | graph engine: `indexed` (adjacency-indexed, L/XL) or `memory` (S30 reference). Transparent behind the same query API |

The graph feeds from eBPF/BGP/device streams + path discoveries; served at
`GET /v1/topology` with what-if simulation at `POST /v1/topology/whatif`.
See `docs/topology.md`.

### FinOps / egress cost (S44)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_COST_ENABLED`     | `true` | cost engine over the local flow stream (volume × public pricing; no billing-API calls) |
| `PROBECTL_COST_ZONES`       | (none) | CIDR→zone rules, e.g. `10.0.1.0/24=us-east-1a,…` (locality classification) |
| `PROBECTL_COST_SERVICES`    | (none) | CIDR→`service:team` attribution rules (showback) |
| `PROBECTL_COST_BUDGETS`     | (none) | monthly USD budgets, e.g. `team:payments=500` (breach = one cost-plane signal per month) |
| `PROBECTL_COST_PRICES_FILE` | (none) | JSON price-table override; embedded public list rates otherwise (provenance + as-of surfaced) |
| `PROBECTL_COST_PRICED`      | `true` | `false` = volume-only mode (bytes attributed, dollars never invented) |

Summary at `GET /v1/cost/summary` and the Cost page; deep dashboards are
federated to Grafana (S40). See `docs/finops.md`.

### SLO engine (S45)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_SLO_ENABLED` | `true` | OpenSLO SLI/SLO engine over the synthetic-result stream (error budgets + multi-window burn-rate signals) |
| `PROBECTL_SLO_DIR`     | (none) | directory of OpenSLO v1 YAML definitions (strictly validated; malformed/duplicate definitions fail startup) |

Statuses at `GET /v1/slos`, OpenSLO export at `GET /v1/slos/openslo`, and the
SLOs page. See `docs/slo.md`.

### Compliance / segmentation validation (S46)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_COMPLIANCE_ENABLED`    | `true` | segmentation validator over observed flow/eBPF traffic (validation only — never enforcement) |
| `PROBECTL_COMPLIANCE_POLICY_DIR` | (none) | segmentation policy YAML directory (strictly validated; malformed files fail startup) |

Verdicts at `GET /v1/compliance`, hash-chained audit evidence at
`GET /v1/compliance/evidence`, and the Compliance page. See
`docs/compliance.md`.

### Collective internet-outage view (S47a)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_OUTAGE_ENABLED`       | `true`  | the local engine: vantage detection over your own results + correlation with external events (no outbound calls) |
| `PROBECTL_OUTAGE_FEEDS_ENABLED` | `false` | **opt-in** public outage feeds (IODA, Cloudflare Radar) — enabling makes outbound fetches (sovereignty / no-phone-home) |
| `PROBECTL_OUTAGE_FEEDS`         | (all)   | feeds to load: `ioda`, `cloudflare_radar` |
| `PROBECTL_OUTAGE_REFRESH`       | `10m`   | feed refresh cadence (last-good kept on failure) |
| `PROBECTL_OUTAGE_RETENTION`     | `48h`   | event window kept/queried |
| `PROBECTL_OUTAGE_RADAR_TOKEN`   | (none)  | Cloudflare API token the radar feed requires (secret-ref resolvable, S41); the feed is omitted without it |

The collective view at `GET /v1/outages` (events + the caller-tenant's
affected tests + vantage detections + feed AUP/health + coverage notes) and
the Internet outages page. Scope resolution (IP→ASN/country) rides the S15
enricher (`PROBECTL_FLOW_ENRICH_ASN`); without it the response reports the
degradation honestly. See `docs/outage.md`.

### RUM convergence (S47b)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_RUM_ENABLED`      | `false` | the browser-beacon ingest + synthetic↔RUM convergence engine (an inbound surface — opt-in) |
| `PROBECTL_RUM_APPS`         | (none)  | app-key registry `pk_key=tenant/app,...` — each beacon binds to its KEY's tenant; enabled-but-empty fails startup |
| `PROBECTL_RUM_RATE_PER_MIN` | `300`   | per-key beacon rate limit (429 + Retry-After above it; 0 = unlimited) |

Beacons ingest at `POST /ingest/rum` (app-key authenticated, consent-gated,
URL-redacted, no IP stored — privacy is enforced server-side, fail closed);
the convergence view serves at `GET /v1/rum` and folds into the Endpoints
surface; `rum.*` vitals flow to the TSDB for dashboards. The SDK is
`web/public/probectl-rum.js`. See `docs/rum.md`.

### Carbon / power observability (S48)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_CARBON_ENABLED`    | `true` | coefficient-based energy/carbon ESTIMATES over the local flow stream (local-only; methodology served with every response) |
| `PROBECTL_CARBON_GRID_GCO2E` | `436`  | your grid's carbon intensity in gCO2e/kWh (defaults to the world average — set yours) |

Attribution reuses `PROBECTL_COST_ZONES` / `PROBECTL_COST_SERVICES`. The
estimate serves at `GET /v1/carbon` and folds into the Cost page. See
`docs/carbon.md`; the chaos injector and the L/XL scale gate (also S48) are
test-harness deliverables — see `docs/chaos.md` and `docs/scale-gate.md`.

### Editions / license (S-T0)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_LICENSE_FILE` | (none) | path to the Ed25519-signed license file. Unset = Community (the full core, default-open). Set-but-missing/invalid = **startup error** (fail closed on configuration) |

Verification is **offline** — local signature math against public keys baked
into the binary at build time (never an env var; never phone-home). Expiry
runs the 30-day-grace → read-only ladder and **never breaks running
telemetry**. License state + the feature→tier map serve at
`GET /v1/editions` and render on **Admin → Editions** — the one place tiers
appear when unlicensed. See `docs/editions.md` for the file format, the
signing CLI (`probectl-license`), and the gating pattern.

### Provider / management plane (S-T1, ee/)

Active only when the license grants `provider_plane`; otherwise `/provider/*`
is a plain 404 (hidden, not locked).

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_PROVIDER_BOOTSTRAP_TOKEN` | (none) | creates the FIRST operator via `POST /provider/v1/auth/bootstrap`; single-use — inert once any operator exists |
| `PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES` | `240` | cap on break-glass grant lifetimes (5–1440) |

The provider plane additionally **requires `PROBECTL_ENVELOPE_KEY`** (operator
TOTP secrets are envelope-sealed at rest) and a database. Operator MFA is
mandatory; operators are a privilege domain distinct from tenant users with
**no implicit access to tenant telemetry** — see `docs/provider-plane.md` for
the model, the break-glass consent flow, and the storage-layer confinement
(`probectl_provider` role). Suspending a tenant rejects its users at the API
(`tenant_suspended`) without touching data or ingestion.

### Siloed / hybrid isolation (S-T2, ee/)

Pooled isolation stays the default and needs no configuration. Siloed and
hybrid tenants (per-tenant Postgres schema / ClickHouse database / bus topic
namespace / object key namespace) require a license granting
`siloed_isolation` and are selected per tenant at provisioning
(`isolation_model` + optional `residency`).

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_DATAPLANES` | (none) | named residency data planes — `name=clickhouseURL[;name=clickhouseURL...]` (e.g. `eu=https://ch-eu:8123;us=https://ch-us:8123`). A tenant's `residency` pins its ClickHouse database to that plane |

Residency pins the tenant's **ClickHouse flow data** in this release;
Postgres control state, the TSDB, object storage, and bus brokers are NOT
region-pinned yet — `docs/isolation.md` states the exact contract, the
catch-up/migration story for silo schemas, and the offboard-teardown
semantics.

### White-label branding (S-T4, ee/)

No configuration keys: branding activates with a license granting
`white_label` and is configured per tenant (or as the provider master) from
the provider console. The public `GET /branding` endpoint serves the resolved
brand pre-auth (Host-resolved for custom domains; the probectl default when
unlicensed); custom-domain login resolves the tenant from the serving host.
Custom domains need a certificate at the TLS-terminating ingress (or via
trustctl) — see `docs/white-label.md` for the token-override contract, the
no-bleed rules, and the email-template contract.

### Advanced data governance (S-EE3, `governance` ee/)

Per-tenant data classification + redaction, composed with retention (S-T5),
residency (S-T2/S-EE2) and BYOK (S-T6). No new config keys: classification +
redaction MECHANISM is core (the `?redact=true` export toggle works anywhere,
masking PII with a partial strategy); the `governance` feature adds per-tenant
POLICY (stored in `tenant_governance`, migration 0033) set from the provider
plane (`GET/PUT /provider/v1/tenants/{id}/governance`). IPs are PII by default.
Full model: `docs/governance.md`. Redacted export: `GET /v1/lifecycle/export?redact=true`.

### Tenant lifecycle: export, retention, erasure (S-T5, core)

Export + verifiable deletion are a compliance right — core in every edition.
`GET /v1/lifecycle/export` (permission `lifecycle.export`) streams the
portability bundle; `GET/PUT /v1/lifecycle/retention` + `POST
/v1/lifecycle/erase` (permission `lifecycle.erase`, slug-confirmed,
irreversible) manage retention and run the attested cross-store erasure. The
provider console adds the operator-side erase trigger. See
`docs/runbooks/tenant-offboarding.md` for the full procedure and the
per-store verification table.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_BACKUP_RETENTION_NOTE` | (a generic statement) | your backup-TTL statement, included VERBATIM in every deletion attestation — be explicit about snapshot expiry |

The daily retention sweeper enforces per-tenant `flow_retention_days`
(tighter than the deployment TTL). Prometheus-mode TSDB series deletion is a
documented manual step (the attestation says so honestly).

### Per-tenant metering & quotas (S-T3, ee/)

No configuration keys: metering activates with a license granting `metering`
(provider/MSP tier). Counters flush every minute; gauge snapshots run every
15 minutes; usage and quotas live in Postgres (migration 0026). The usage
API, the CSV/JSONL billing-export feed, per-tenant quotas (creation-gating
only — telemetry is never quota-dropped), and the console showback card are
documented in `docs/metering.md`.

### Per-tenant key isolation / BYOK (S-T6, ee/)

Unlocked by the `byok` feature (Enterprise). No new config keys: the keyring
wraps managed tenant KEKs under **`PROBECTL_ENVELOPE_KEY`** (required when
byok is licensed — startup fails loudly without it) and resolves BYOK
references through the S41 secret backends. Surfaces: `GET/POST
/v1/security/keys[...]` (permission `security.keys`) + the Admin →
Encryption keys card. The full model — sealing formats, rotation, the BYOK
lockout warning, crypto-offboarding — is in `docs/byok.md`.

### Tenant fairness (S-T7, core)

Per-tenant ingest bounds + query-cost guards protecting the pooled platform
(enforcement is core in every edition). All defaults are **0 = unlimited** —
fairness is opt-in per bound; per-tenant overrides are set from the provider
console into `tenant_fairness`. Full model: `docs/fairness.md`.

| Key | Default | Description |
| --- | --- | --- |
| `PROBECTL_FAIRNESS_RESULTS_PER_SEC` | `0` | per-tenant result-message admission rate |
| `PROBECTL_FAIRNESS_FLOW_EVENTS_PER_SEC` | `0` | per-tenant flow-record admission rate |
| `PROBECTL_FAIRNESS_INGEST_BYTES_PER_SEC` | `0` | per-tenant result-payload byte rate |
| `PROBECTL_FAIRNESS_BURST_SECONDS` | `10` | bucket capacity = rate × burst |
| `PROBECTL_FAIRNESS_QUERY_CONCURRENCY` | `0` | per-tenant in-flight query cap (429 over it) |
| `PROBECTL_FAIRNESS_QUERIES_PER_MIN` | `0` | per-tenant query budget (429 over it) |

### Multi-region / active-active HA (S-EE2, core)

Inert unless `PROBECTL_REGION` is set (single-region deployments need none of
these). The control plane stays stateless and active in every region; the
split-brain fence pauses API writes during a failover while reads + telemetry
keep flowing. Full model + the failover runbook: `docs/multi-region.md`,
`docs/runbooks/region-failover.md`.

| Key | Default | Description |
| --- | --- | --- |
| `PROBECTL_REGION` | (empty) | this replica's region; empty = single-region (fence inert) |
| `PROBECTL_REGIONS` | (empty) | comma list of all regions in the deployment |
| `PROBECTL_DATABASE_URL` | … | the WRITER endpoint (DNS/proxy that resolves to the current primary) |
| `PROBECTL_DATABASE_READ_URL` | (empty) | optional local read-replica endpoint; empty = reads use the writer |
| `PROBECTL_REPLICATION_MODE` | `async` | `sync` (RPO 0) or `async` (RPO ≈ lag) — descriptive; configure Postgres to match |
| `PROBECTL_RESIDENCY` | (empty) | default data-residency region (governance) |
| `PROBECTL_RPO_SECONDS` | `0` | provisional RPO target (human sign-off) |
| `PROBECTL_RTO_SECONDS` | `60` | provisional RTO target (human sign-off) |

The writer must be reachable for API writes; `cluster_state` (migration 0032)
holds the promotion epoch the fence reads. Promotion is `cluster_promote()` in
the failover runbook.

### Supportability (S-EE4, core)

Deep health + a secret-stripped support bundle for triage (CORE; the support
org/SLA is contract). No new config keys; `diagnostics.read` (migration 0034,
admin-seeded) gates `GET /v1/diagnostics` and `GET /v1/diagnostics/bundle`. An
offline bundle: `probectl-control support-bundle [-o file]`. Self-monitoring
series `probectl_self_*` + `probectl_build_info` feed
`deploy/grafana/dashboards/probectl-self.json`. The bundle NEVER contains
secrets/credentials/PII (allowlist config + anonymized topology + a final
scrub). Full model: `docs/supportability.md`.

### Guarded agentic remediation (S-EE5, `remediation` ee/)

The assistant PROPOSES remediations; a human APPROVES; probectl NEVER executes —
there is no executor in the codebase (guardrail 8, F44). Approve is a recorded,
audited, blast-radius-limited, human-only sign-off that an operator carries out
in their own change process; ingested data (e.g. a prompt-injection routed
through the `propose_remediation` MCP tool) can at most create a `proposed`
proposal a human must approve via the authenticated UI. The feature is hidden
(404) when the `remediation` Enterprise feature is unlicensed.

| Variable | Default | Notes |
|---|---|---|
| `PROBECTL_REMEDIATION_APPROVALS_ENABLED` | `false` | advisory-only master switch — until an operator turns this on, Approve is unavailable and proposals are review-only |
| `PROBECTL_REMEDIATION_MAX_BLAST_RADIUS` | `50` | a proposal whose simulated (S43 what-if) blast radius exceeds this cannot be approved; an unknown radius (no topology) is also blocked — fail closed |

Permissions `remediation.propose` and `remediation.approve` (migration 0035,
admin-seeded) gate the `/v1/remediation/*` routes; the dry-run blast radius is a
read-only topology simulation. Full policy + architecture: `docs/remediation.md`.

### NDR-lite detection (S42)

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_NDR_ENABLED`   | `true` | behavioral detection engine (DGA/exfil/beaconing/egress/lateral) over local DNS/flow/eBPF streams; signals only — never blocks |
| `PROBECTL_NDR_RULES_DIR` | (none) | detection-as-code overlay directory; rules merge by id over the embedded defaults (a malformed dir fails startup) |

Detections are confidence-scored threat-plane signals (`ndr.*`) exported to
incidents (S17), the Security triage surface (S-FE3), and the SIEM (S32).
See `docs/ndr.md` for the detector and tuning reference.

### Secrets integration (S41)

Any credential value in this document may be a **secret reference** instead of
the literal material — `env:NAME`, `vault:<mount>/<path>#<field>`,
`cyberark:<query>`, `aws:<id>[#<json-field>]`, `azure:<vault>/<name>`,
`gcp:<project>/<secret>[/<version>]`, or `literal:<value>` as the escape
hatch. The control plane resolves `PROBECTL_OIDC_CLIENT_SECRET`,
`PROBECTL_CMDB_SECRET`, `PROBECTL_AI_MODEL_TOKEN`, `PROBECTL_SIEM_TOKEN`, and
the secret parts of `PROBECTL_CHANGE_WEBHOOKS` / `PROBECTL_NOTIFY_CONNECTORS` /
`PROBECTL_NOTIFY_INBOUND` at startup (fail closed); the device agent resolves
every `PROBECTL_DEVICE_CRED_<NAME>_*` value per poll cycle. Resolved values are
cached only encrypted, for a short lease (5 m). See `docs/secrets.md`.

Backend access settings (environment only; all over verified TLS):

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_SECRETS_VAULT_ADDR`      | (none) | Vault base URL; enables `vault:` references |
| `PROBECTL_SECRETS_VAULT_TOKEN`     | (none) | static Vault token (alternative to AppRole) |
| `PROBECTL_SECRETS_VAULT_ROLE_ID` / `_SECRET_ID` | (none) | AppRole login; the lease-aware client token is renewed at ⅔ TTL |
| `PROBECTL_SECRETS_VAULT_NAMESPACE` | (none) | `X-Vault-Namespace` (Vault Enterprise) |
| `PROBECTL_SECRETS_CYBERARK_URL`    | (none) | CyberArk CCP base URL; enables `cyberark:` |
| `PROBECTL_SECRETS_CYBERARK_APP_ID` | (none) | CCP AppID |
| `PROBECTL_SECRETS_CYBERARK_CERT_FILE` / `_KEY_FILE` / `_CA_FILE` | (none) | optional CCP client-certificate auth |
| `AWS_REGION` (or `AWS_DEFAULT_REGION`), `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | (none) | enables `aws:` (Secrets Manager, SigV4) |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | (none) | enables `azure:` (Key Vault) |
| `GOOGLE_APPLICATION_CREDENTIALS` | (none) | service-account key file; enables `gcp:` (Secret Manager) |

Backend health (counters + redacted last error, never secret material) is
served at `GET /v1/secrets/health` and on the Admin page.

## Local dev stack (`deploy/compose/dev.yml`)

Started with `make compose-up`. **Local, non-production** defaults — plaintext
listeners and dev credentials for convenience. Production deploys are
TLS/HTTPS-by-default (CLAUDE.md §7 guardrail 12).

| Service      | Compose name | Host port(s)        | Purpose                                   | Dev credentials                 |
| ------------ | ------------ | ------------------- | ----------------------------------------- | ------------------------------- |
| PostgreSQL   | `postgres`   | `5432`              | Durable state, tenants, RBAC, audit, SLOs | user/pass/db = `probectl`         |
| Kafka        | `kafka`      | `9092`              | Result/event bus (KRaft, no ZooKeeper)    | none (PLAINTEXT)                |
| ClickHouse   | `clickhouse` | `8123` (HTTP), `9000` (native) | High-cardinality events/flows  | user/pass/db = `probectl`         |
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
