# Configuration

This is the full reference for every knob probectl reads at startup. The short
version: **the control plane and every server-side feature read environment
variables** (all prefixed `PROBECTL_`); **the agents read a YAML file** (with the
same env vars as overrides). An environment variable is a named string the
operating system hands a process at launch — and because the control plane is
stateless, these variables are the *only* place its behavior comes from. This
page lists each variable, its default, and what it does — and it is the
contract, so every row here is checked against the code.

How to read this page:

- A variable's **default** is what you get if you set nothing. The defaults are
  chosen so a fresh install boots in a safe, sovereign posture (no outbound calls,
  fail-closed on missing TLS/secrets) — probectl's standing security guardrails
  (see [`security/threat-model.md`](security/threat-model.md)).
- A default of **`(none)`** means the value is empty/unset; the feature usually
  stays off until you give it one.
- **Where it's read:** the control plane resolves its config in
  `internal/config/config.go` (one `Load` function that reports *every* bad value
  at once and exits non-zero — a preflight checklist that reads all the gauges
  before refusing takeoff, so you never chase config errors one at a time). Each
  agent has its own loader (`internal/agent`, `internal/ebpf`, `internal/flow`,
  `internal/device`, `internal/endpoint`).

## Conventions

- **Control plane (`probectl-control`):** environment variables, `PROBECTL_`
  prefix. Listed in the next section.
- **Agents:** a YAML config file is the source of truth; the matching `PROBECTL_*`
  env vars override individual fields (handy for containers). Each agent's keys
  are in its own section below.
- **Secrets** are never hardcoded, logged, or placed in URLs/query strings.
  Sensitive values at rest are sealed with **envelope encryption** — each value is
  encrypted with its own data key, and all those data keys are encrypted by one
  master key (the *envelope key*): individual lockboxes whose keys live in a
  single safe. Any credential in this document may be a *secret reference* (e.g.
  `vault:…`) instead of the raw value — see
  [Secrets integration](#secrets-integration).

## Control plane (`probectl-control`)

The control plane is the brain: it serves the API/UI, accepts agent connections,
runs the alerting/incident/correlation engines, and talks to the datastores. It is
**stateless** — all durable state lives in Postgres/ClickHouse/the TSDB — so every
behavioral choice it makes comes from these environment variables, read once at
boot. The table below is the base set every deployment uses; the feature-specific
sections that follow add more.

Subcommands: `probectl-control [serve]` (default), `probectl-control migrate` (apply
database migrations and exit), `probectl-control version`, and
`probectl-control gen-cert [dir]` — a convenience that writes a self-signed
`tls.crt`/`tls.key`/`ca.crt` for an HTTPS quickstart (`PROBECTL_CERT_HOSTS`, default
`localhost,127.0.0.1`, sets the certificate's host names; production brings its own
CA-issued cert). The other subcommands are covered with their features:
`agent-ca init|export`, `enroll-token`, and `revoke-agent` (agent transport and
enrollment — [`agent/enrollment.md`](agent/enrollment.md)), `scim-token`
(SCIM, below), `mcp-stdio` and `mcp-token` (MCP server, below), `preflight`
(the storage-encryption preflight — [`hardening.md`](hardening.md)),
`support-bundle` (supportability, below), `backup-seal` / `backup-open`
(sealed backups — *Tenant lifecycle*, below), and `replay-deadletter`
(re-ingest dead-lettered records — [`ops/dead-letter-replay.md`](ops/dead-letter-replay.md)).

A note on the defaults: the listen address is `:8080`, the database DSN — the
*data source name*, the one connection string carrying host, user, password,
database, and TLS mode — points at a local Postgres with **`sslmode=require`**
(TLS to the database is the default, not an afterthought), and HSTS — the
response header that tells browsers to only ever reach this host over HTTPS — is
on. These defaults assume you front the process with a TLS-terminating ingress
(the shipped Helm/compose posture); set the TLS cert/key pair below to have the
process serve HTTPS itself instead.

| Variable                          | Default                                                              | Description                                  |
| --------------------------------- | ------------------------------------------------------------------- | -------------------------------------------- |
| `PROBECTL_HTTP_ADDR`                | `:8080`                                                             | API listen address                           |
| `PROBECTL_HTTP_READ_TIMEOUT`        | `15s`                                                              | HTTP read timeout                            |
| `PROBECTL_HTTP_WRITE_TIMEOUT`       | `15s`                                                              | HTTP write timeout                           |
| `PROBECTL_HTTP_IDLE_TIMEOUT`        | `60s`                                                              | HTTP idle (keep-alive) timeout               |
| `PROBECTL_SHUTDOWN_TIMEOUT`         | `15s`                                                              | graceful-shutdown drain timeout              |
| `PROBECTL_DATABASE_URL`             | `postgres://probectl:probectl@localhost:5432/probectl?sslmode=require`    | PostgreSQL DSN; `sslmode=require` is the default (TLS to the DB out of the box). Dev-only: a local source-dev stack without TLS may explicitly append `sslmode=disable` to its own DSN |
| `PROBECTL_DATABASE_MAX_CONNS`       | `10`                                                               | max pool connections (1–1000)                |
| `PROBECTL_DATABASE_MIN_CONNS`       | `0`                                                                | min pool connections                         |
| `PROBECTL_DATABASE_CONNECT_TIMEOUT` | `5s`                                                              | per-connection connect timeout               |
| `PROBECTL_MIGRATE_ON_BOOT`          | `false`                                                            | apply migrations during `serve` startup      |
| `PROBECTL_LOG_LEVEL`                | `info`                                                             | `debug` \| `info` \| `warn` \| `error`       |
| `PROBECTL_LOG_FORMAT`               | `json`                                                             | `json` \| `text`                             |
| `PROBECTL_HSTS_ENABLED`             | `true`                                                             | send `Strict-Transport-Security`             |
| `PROBECTL_HSTS_MAX_AGE`             | `8760h`                                                            | HSTS `max-age`                               |
| `PROBECTL_TLS_CERT_FILE`            | (none)                                                            | PEM server certificate; the process serves HTTPS directly when set together with the key |
| `PROBECTL_TLS_KEY_FILE`             | (none)                                                            | PEM server private key (set together with the cert)        |
| `PROBECTL_PUBLIC_TLS`               | `false`                                                          | tells the app that TLS terminates at the edge (an ingress in front) even though the app itself serves plaintext. Browsers only see the edge, so this is what flips cookies to `Secure` when you run behind a TLS ingress |
| `PROBECTL_ALLOW_PLAINTEXT_HTTP`     | `false`                                                          | explicit, loud opt-in for a **non-loopback** plaintext control listener — only valid behind a TLS-terminating ingress (the Helm chart sets it). Without it, plaintext + a non-loopback bind = refuse to start (fail closed) |
| `PROBECTL_SECURITY_CONTACT`         | (none)                                                          | your vulnerability-disclosure mailbox; published in the served `/.well-known/security.txt` (left as a template comment when unset) |
| `PROBECTL_ENVELOPE_KEY`             | (none)                                                            | base64-encoded 32-byte key-encryption key (KEK) for at-rest envelope encryption. The single root secret behind sealed credentials and backups — **back it up** |
| `PROBECTL_ENVELOPE_KEY_FILE`        | (none)                                                            | path to the KEK file — loaded, or GENERATED+persisted (0600) on first boot if absent; an explicit `PROBECTL_ENVELOPE_KEY` wins over it. Shipped compose mounts it on the `controldata` volume |
| `PROBECTL_ENVELOPE_KEY_ID`          | `dev`                                                             | identifier recorded alongside each sealed value (so a future key rotation can tell which key sealed what) |
| `PROBECTL_REQUIRE_AT_REST_ENCRYPTION` | `false`                                                        | when `true`, the control plane **refuses to start** if no envelope key resolves — a hard guarantee against accidentally running with plaintext-at-rest |
| `PROBECTL_STORAGE_ENCRYPTION_ATTESTED` | `false`                                                       | operator attestation that the bulk-store volumes are encrypted *below* the host (e.g. encrypted cloud volumes the startup preflight can't see); logged, and downgrades the preflight warning |
| `PROBECTL_AGENT_GRPC_ADDR`          | (none)                                                            | agent gRPC listen address; enables the transport when set together with the agent mTLS files below |
| `PROBECTL_AGENT_TLS_CERT_FILE`      | (none)                                                            | agent-transport server certificate (PEM)                   |
| `PROBECTL_AGENT_TLS_KEY_FILE`       | (none)                                                            | agent-transport server private key (PEM)                   |
| `PROBECTL_AGENT_TLS_CA_FILE`        | (none)                                                            | CA bundle that signs agent client certificates (PEM)       |
| `PROBECTL_BUS_MODE`                 | `memory`                                                         | result bus: `memory` (lightweight, in-process) \| `kafka`  |
| `PROBECTL_BUS_BROKERS`              | (none)                                                           | comma-separated `host:port` Kafka brokers (required for `kafka`) |
| `PROBECTL_BUS_MEMORY_BUFFER`        | `1024`                                                           | in-memory bus: per-subscriber channel depth (lightweight mode) |
| `PROBECTL_BUS_MEMORY_OVERFLOW`      | `drop`                                                           | in-memory bus overflow policy (SCALE-006): `drop` (default — drop + count, no deadlock; a stuck consumer never stalls ingest; drops surface at `probectl_bus_memory_dropped`) \| `block` (back-pressure the publisher) |
| `PROBECTL_BUS_TLS_ENABLED`          | `false`     | TLS to the Kafka brokers. **Required in kafka mode** unless the explicit dev flag below is set |
| `PROBECTL_BUS_TLS_CA_FILE`          | (none)      | private CA bundle for the brokers |
| `PROBECTL_BUS_TLS_CERT_FILE`        | (none)      | client certificate (broker mTLS; with `_KEY_FILE`) |
| `PROBECTL_BUS_TLS_KEY_FILE`         | (none)      | client key (broker mTLS) |
| `PROBECTL_BUS_SASL_MECHANISM`       | (none)      | `plain` \| `scram-sha-256` \| `scram-sha-512` |
| `PROBECTL_BUS_SASL_USER`            | (none)      | SASL username |
| `PROBECTL_BUS_SASL_PASSWORD`        | (none)      | SASL password (secret references supported; never logged) |
| `PROBECTL_BUS_ALLOW_PLAINTEXT`      | `false`     | **dev only**: allow a plaintext broker (the dev compose stack). Production never sets this |
| `PROBECTL_BUS_MAX_BUFFERED`         | `0` (= built-in bound `65536`) | bound on the async Kafka producer's in-flight records; a full buffer SHEDS new records (counted, never blocking ingest). `0`/unset keeps the built-in 65536-record bound — there is deliberately no unbounded mode |
| `PROBECTL_BUS_WORKERS`              | `4`         | per-subscription consume parallelism — each Kafka poll batch is fanned out across this many key-sharded workers (per-key ordering preserved). `0`/`1` = serial |
| `PROBECTL_INGEST_MAX_SERIES_PER_AGENT`  | `0` (= built-in cap `1000`) | cap on active metric-series identities one agent may mint; a NEW identity past the cap is rejected per-series and counted (known series keep flowing), and an identity idle for 1h frees its slot. `0`/unset keeps the built-in 1000 cap — the wall always exists (there is no unlimited setting) |
| `PROBECTL_INGEST_MAX_SERIES_PER_TENANT` | `0` (= built-in cap `50000`) | tenant-wide active-series wall, so one tenant's cardinality explosion never bleeds into others. `0`/unset keeps the built-in 50000 cap |
| `PROBECTL_TSDB_MEMORY_RETENTION` | `0` (= built-in window `1h`) | lightweight-mode (in-memory) TSDB retention window, aged by ARRIVAL time (backfilled or clock-skewed sample timestamps are never swept early). `0`/unset keeps the built-in 1h window — the buffer never grows forever |
| `PROBECTL_TSDB_MEMORY_MAX_BYTES` | `0` (= built-in wall 256 MiB) | byte ceiling for the in-memory TSDB; oldest-first eviction once exceeded, with usage + eviction counters exposed. `0`/unset keeps the built-in 256 MiB wall |
| `PROBECTL_AUDIT_WORM_DIR` | (none) | enable write-once audit export — the provider audit chain is exported as Ed25519-signed segments into this directory (mount an S3/MinIO **object-lock** bucket for true write-once-read-many) and chain-verified each cycle |
| `PROBECTL_AUDIT_WORM_INTERVAL` | `1h` | export + chain-verify cadence |
| `PROBECTL_WORM_SIGNING_KEY_FILE` | (none) | path to the Ed25519 audit-export signing key (PKCS#8 PEM) — loaded, or GENERATED+persisted (0600) on first boot, so the key is **stable across restarts** (an ephemeral per-boot key would break cross-restart chain verification). Required when `PROBECTL_AUDIT_WORM_DIR` is set unless `PROBECTL_WORM_SIGNING_KEY` is. **Back it up like the envelope key** |
| `PROBECTL_WORM_SIGNING_KEY` | (none) | base64-encoded Ed25519 private-key PEM (KMS/secret-manager injection) — wins over `PROBECTL_WORM_SIGNING_KEY_FILE`. Enabling audit export with neither set **fails closed** (no silent ephemeral key) |
| `PROBECTL_TSDB_MODE`                | `memory`                                                         | time-series writer: `memory` (in-process) \| `prometheus`  |
| `PROBECTL_TSDB_URL`                 | (none)                                                           | Prometheus/VictoriaMetrics base URL for remote-write (required for `prometheus`) |
| `PROBECTL_REMOTE_WRITE_BATCH_ENABLED` | **`true` in `prometheus` mode** (else `false`)                | SCALE-001: coalesce concurrent results into one remote-write POST instead of one POST per result. Defaults ON for `prometheus` so the production ingest path is batched by default; set explicitly to override |
| `PROBECTL_REMOTE_WRITE_BATCH_SERIES`  | `500`                                                          | flush when this many series have accumulated |
| `PROBECTL_REMOTE_WRITE_BATCH_WAIT`    | `50ms`                                                         | max time a batch waits before flushing |
| `PROBECTL_ALERT_EVAL_INTERVAL`      | `30s`                                                            | how often the alerting engine evaluates rules over the TSDB |
| `PROBECTL_INCIDENT_WINDOW`          | `10m`                                                            | time window within which related signals correlate into one incident |
| `PROBECTL_AUTH_MODE`                | `session`                                                          | identity mode: `session` (real OIDC SSO + session cookies) \| `dev` (LOCAL EVALUATION ONLY — exists only in `-tags devauth` builds; release binaries refuse it at boot) |
| `PROBECTL_DEV_AUTH_ACK`             | (none)                                                             | must be `i-understand` to start in dev auth mode (tagged builds only, loopback bind required) |
| `PROBECTL_SESSION_TTL`              | `12h`                                                            | server-side session lifetime                               |
| `PROBECTL_AUTH_RATE_MAX_FAILURES`   | `5`         | auth brute-force guard: failures per window before lockout |
| `PROBECTL_AUTH_RATE_WINDOW`         | `1m`        | failure-counting window for the auth throttle |
| `PROBECTL_AUTH_RATE_LOCKOUT`        | `1m`        | base lockout; doubles per consecutive lockout, capped at 1h; lockouts are audited |
| `PROBECTL_OIDC_ISSUER`              | (none)                                                           | OIDC issuer URL; SSO discovery is performed against it |
| `PROBECTL_OIDC_CLIENT_ID`          | (none)                                                           | OIDC client ID registered with the IdP               |
| `PROBECTL_OIDC_CLIENT_SECRET`      | (none)                                                           | OIDC client secret (kept out of logs/URLs)            |
| `PROBECTL_OIDC_REDIRECT_URL`       | (none)                                                           | the control plane's `/auth/callback` URL registered with the IdP |
| `PROBECTL_REQUIRE_MFA`             | `false`                                                         | require multi-factor auth. The session's MFA state comes from the ID token's `amr`/`acr` claims (a second factor like `otp`/`hwk`/`mfa`, or `acr` aal2+/loa2+). When `true`, every authenticated `/v1` request from a single-factor session gets 403 (enforced at request time). Off by default |

Invalid values fail fast: `probectl-control` reports **all** configuration problems
at once and exits non-zero. The database password is redacted from logs.

Tenant-owned tables are protected by Postgres Row-Level Security (RLS): the
*database itself* filters every row by the requesting tenant, so even a buggy or
hostile SQL query cannot read another tenant's rows — the isolation does not
depend on application code getting a `WHERE` clause right. The
`PROBECTL_DATABASE_URL` role must be able to assume the least-privilege `probectl_app`
role (a superuser always can; otherwise run `GRANT probectl_app TO <login_role>`),
which `internal/tenancy` assumes per transaction so isolation holds regardless of
how the control plane authenticated. See [`architecture.md`](architecture.md).

### HTTP endpoints

| Method & path      | Purpose                                                  |
| ------------------ | -------------------------------------------------------- |
| `GET /healthz`     | Liveness — `200` while the process is serving            |
| `GET /readyz`      | Readiness — `200` when the database is reachable, else `503` |
| `GET /version`     | Build and runtime metadata                               |
| `GET /openapi.json`| The OpenAPI 3.1 document                                 |

Every response carries an `X-Request-Id` (honoring an inbound one) and the
security headers `Strict-Transport-Security` (when enabled) and
`X-Content-Type-Options: nosniff`. The versioned resource routes under `/v1` are
documented in *Resource API & CLI* below.

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

### Transport security

probectl never wants a plaintext channel exposed to the network. There are two
*correct* ways to get TLS in front of the API, and the config lets you pick:

The API listens over TLS in two interchangeable ways:

- **App-terminated TLS** — set `PROBECTL_TLS_CERT_FILE` + `PROBECTL_TLS_KEY_FILE`, and
  the control plane serves **HTTPS only** (TLS 1.2+, prefer 1.3; plaintext is
  refused).
- **Ingress-terminated TLS** — leave them unset and serve HTTP behind a
  TLS-terminating ingress (the shipped Helm/compose default). HSTS is set either
  way, so the posture is correct end to end.

All TLS and crypto policy lives in `internal/crypto`; a CI guard
(`scripts/check_crypto_imports.sh`) forbids crypto-primitive imports elsewhere so
a FIPS 140-3 validated module can be swapped in. At-rest secrets use the envelope
helper (a per-record data key wrapped by a KMS/HSM-pluggable KEK; the dev
`StaticKeyProvider` reads `PROBECTL_ENVELOPE_KEY`).

### Agent transport

This is how agents talk to the control plane, and it is locked down by design.
The transport is gRPC — a binary remote-procedure-call protocol over HTTP/2,
carrying Protobuf (compact, typed) messages — and it runs only when
`PROBECTL_AGENT_GRPC_ADDR` **and** all three `PROBECTL_AGENT_TLS_*` files are set
(address + server cert + server key + the CA that signs client certs). The
service is `probectl.agent.v1.AgentService`, and it is **mutual-TLS only**
(`RequireAndVerifyClientCert`): in mutual TLS *both* sides prove their identity
with certificates — the server to the agent, and the agent back to the server —
so the agent must present a client certificate, and its tenant and id are read
**out of that certificate's identity**
(`spiffe://probectl/tenant/<t>/agent/<a>`), never from the request body. So even a
misbehaving or malicious agent can only ever write to its own tenant — the identity
is cryptographic, not self-asserted. Populate `PROBECTL_AGENT_TLS_CA_FILE` (the
client-cert CA pool) with `probectl-control agent-ca export <file>`, which writes the
public agent-CA bundle (root + intermediate, no key). Generate dev mTLS material with the
`internal/crypto` CA helpers. The `.proto` lives under `proto/probectl/agent/v1/`;
regenerate Go with `make proto` (tools via `make proto-tools`).

**Version-skew policy.** At registration the control plane rejects agents outside
the supported version window, so a rolling upgrade never admits an incompatible
agent. See [`lifecycle.md`](lifecycle.md).

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_AGENT_SKEW_WINDOW` | `1` | allowed minor-version skew on either side (N/N-1); the control plane at minor N accepts agents at N-1…N+1. `0` requires an exact minor match |
| `PROBECTL_AGENT_MIN_VERSION` | (none) | an explicit floor — agents older than this are rejected regardless of the window (force-retire a known-bad version) |

A rejected agent gets a gRPC `FailedPrecondition` ("upgrade required"); a dev/unpinned
build (`0.0.0-dev`) on either side skips the check.

### probectl-agent

The canary agent is the worker that actually runs the probes (ping, TCP, DNS,
HTTP, …). Unlike the control plane, its primary config is a **YAML file**
(`-config`, or the path in `PROBECTL_AGENT_CONFIG`) — see
[`deploy/agent/probectl-agent.example.yml`](../deploy/agent/probectl-agent.example.yml).
Crucially, the agent does **not** configure its own tenant or id: those come from
its mTLS client certificate (above), so you can't accidentally point an agent at
the wrong tenant by editing a file.

A handful of env vars override individual YAML fields — useful in containers where
mounting a full file is awkward:

| Variable | Overrides (YAML) | Meaning |
| -------- | ---------------- | ------- |
| `PROBECTL_AGENT_CONFIG` | — | path to the YAML config (the `-config` flag wins over it) |
| `PROBECTL_AGENT_GRPC_ADDR` | `control_plane.grpc_addr` | the control plane's agent-gRPC endpoint to dial |
| `PROBECTL_AGENT_TLS_CERT_FILE` | `tls.cert_file` | the agent's mTLS client certificate (PEM) |
| `PROBECTL_AGENT_TLS_KEY_FILE` | `tls.key_file` | the agent's mTLS client key (PEM) |
| `PROBECTL_AGENT_TLS_CA_FILE` | `tls.ca_file` | the CA that signed the control plane's server cert (PEM) |
| `PROBECTL_AGENT_BUFFER_DIR` | `buffer.dir` | on-disk store-and-forward directory (see below) |
| `PROBECTL_AGENT_IDENTITY_SERVER` | `identity.server` | control-plane HTTPS base URL enabling automatic certificate rotation — the agent rotates its mTLS identity at ~2/3 of its lifetime via `/enroll/agent/rotate`. See [`agent/enrollment.md`](agent/enrollment.md) |
| `PROBECTL_AGENT_JOIN_TOKEN` | — | a one-time join token for **first-boot enrollment**: with no identity present yet, the agent redeems it, writes its identity, then runs. Idempotent (a present identity is never overwritten) and fail-closed. See [`agent/enrollment.md`](agent/enrollment.md) |
| `PROBECTL_AGENT_ENROLL_TOKEN_FILE` | `enroll.token_file` | a file holding the join token (a mounted secret, read once); `PROBECTL_AGENT_JOIN_TOKEN` takes precedence |
| `PROBECTL_AGENT_ENROLL_SERVER` | `enroll.server` | enrollment target for first-boot enrollment; defaults to `identity.server` |
| `PROBECTL_AGENT_ENROLL_CA_PIN` | `enroll.ca_pin` | optional hex sha256 pin of the server cert for first contact; otherwise `tls.ca_file` verifies the server |
| `PROBECTL_AGENT_CANARY_CA_DIR` | `tls.canary_ca_dir` | the **one** directory that probe `ca_file:` parameters may reference (a trust-anchor allowlist for HTTP/DNS-over-TLS probes); empty = the `ca_file` parameter is refused |
| `PROBECTL_AGENT_LOG_LEVEL` | — | `debug` \| `info` (default) \| `warn` \| `error` |
| `PROBECTL_AGENT_LOG_FORMAT` | — | `json` (default) \| `text` |

Results buffer to disk (`buffer.dir`, bounded by `max_records`, default `10000`)
while the control plane is unreachable and drain on reconnect (at-least-once
delivery). Probing keeps running regardless of connectivity, so a control-plane
outage never blocks measurement — the agent just queues and catches up.

The buffer is also bounded by **on-disk bytes** (`buffer.max_bytes`, RESIL-009) to
pre-empt ENOSPC: `0`/unset uses the built-in default of 256 MiB; a negative value
disables the byte bound (records-only). Each frame costs `4` header bytes plus the
payload, so the footprint of a full record-capped buffer is roughly
`max_records × (4 + avg_payload_bytes)`. `Enqueue` fails closed (sheds the newest
result, counted as `dropped`) when **either** the record or byte cap would be
exceeded, and the agent logs a WARN when the buffer crosses 90% of either bound.

### Result pipeline

This is the path every measurement takes from an agent to a queryable metric, and
two env vars decide how heavy that pipeline is: `PROBECTL_BUS_MODE` (the message
bus — the queue that decouples ingest from storage, so a slow consumer never
stalls an agent) and `PROBECTL_TSDB_MODE` (the time-series writer; a TSDB is a
database specialized for timestamped measurements and the range queries
dashboards make over them). The `memory` defaults make a single binary work with
zero external dependencies; switch them to `kafka` / `prometheus` when you
outgrow that.

A streamed result flows agent → gRPC `StreamResults` → control-plane ingest →
result bus (`probectl.network.results`, Protobuf) → consumer → time-series writer.
The agent sends the canonical OTel-aligned result (`proto/probectl/result/v1`); the
control plane **re-stamps the tenant and agent id from the verified mTLS
certificate** before publishing, so a result is always attributed to the sending
agent's tenant regardless of payload contents — the tenant boundary is
cryptographic, never self-asserted. The bus key is the `tenant_id`.

`PROBECTL_BUS_MODE` selects the bus: `memory` (default; in-process, for the
lightweight <5-agent deployment and single-binary runs) or `kafka` (set
`PROBECTL_BUS_BROKERS`). `PROBECTL_TSDB_MODE` selects the writer: `memory` (default;
in-process) or `prometheus` remote-write to `PROBECTL_TSDB_URL` (Prometheus with
`--web.enable-remote-write-receiver`, or VictoriaMetrics; use an `https://` URL
for TLS in transit). Each probe emits `probectl_probe_success`,
`probectl_probe_duration_seconds`, and one `probectl_probe_<metric>` per custom
metric, labeled `tenant_id`, `agent_id`, `canary_type`, and `server_address`. The
canonical signal→OTel mapping is in [`otel-mapping.md`](otel-mapping.md).

### ICMP test

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

`dscp` (here and on every canary that takes it) sets the Differentiated Services
Code Point — the priority field in the IP header that asks routers to treat a
packet as a given traffic class — so you can measure the *same path your real
traffic class rides*, e.g. probing with the voice marking to see what voice sees.

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

### TCP & UDP tests

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

### Voice/RTP tests

The `voice` canary streams real RTP packets (RTP is the protocol that carries
live audio in VoIP calls) at codec cadence to an echoing target and scores the
path: **MOS + R-factor (simplified ITU-T G.107 E-model), RFC 3550 jitter, loss,
and a one-way delay estimate**. MOS is the 1–5 "how did the call sound" scale;
the R-factor is the 0–100 engineering score it is derived from — both *computed
from* measured loss/delay/jitter by the E-model, not from a human listener.
`target` is `host:port`. Parameters: `codec` (`g711` default, `g729`),
`duration_seconds` (1–10, default 3), `dscp` (default 46/EF). The model
variant and the one-way-estimate method ride the result attributes — a
computed MOS is never presented as a measured listening score. See
`docs/voice.md`.

### DNS tests

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
`1.1.1.1:53`) for `udp`/`tcp`, `1.1.1.1:853` for **DoT** (DNS over TLS — the
classic query inside an encrypted TLS session), and
`https://cloudflare-dns.com/dns-query` for **DoH** (DNS over HTTPS — the query
as an HTTPS request). DoT verifies the resolver's TLS certificate (TLS 1.2+);
DoH posts an RFC 8484 `application/dns-message` query over HTTPS.

In **resolver mode** the canary emits `probectl_probe_dns_query_ms` (round-trip) and
`probectl_probe_dns_answers` (answer count), with `dns.rcode` and a compact
`dns.answer` summary as attributes. The probe is `success=false` on a non-`NOERROR`
rcode or an empty answer.

DNSSEC adds cryptographic signatures to DNS, so an answer can be *proven* to
come from the zone's owner, untampered. With `dnssec: "true"` the canary
requests DNSSEC records (the DO bit) and **validates the zone's `RRSIG` over the
answer against the zone `DNSKEY`** — it does **not** trust the resolver's AD bit
(the resolver's own "I checked" flag, which a misbehaving resolver could simply
set). The verdict lands in the `dns.dnssec`
attribute (`secure`, `insecure` for an unsigned zone, or `bogus`) and
`probectl_probe_dns_dnssec_secure` (1/0); a **bogus** result (tampered, expired, or
wrong-key signature) fails the probe. Validation verifies the signature on the
answer RRset; full chain-to-root anchoring is a later refinement.

In **trace mode** the canary performs an **iterative delegation walk** from the
root hints, following `NS`/glue referrals down to the authoritative server (UDP,
capped iterations, with a recursive fallback when a referral ships no glue). It
emits `probectl_probe_dns_query_ms` (total walk time) and
`probectl_probe_dns_trace_hops`, with the delegation chain in the `dns.trace`
attribute. DNS-exfiltration detection and open-data baselines are out of scope for
this probe (they live in the NDR and open-data features).

### HTTP server tests

The `http` canary measures **HTTP(S) availability** with a full **response-time
breakdown** and captures **TLS handshake details** for the TLS-posture plane (see
*TLS / certificate observability* below). The `target` is the URL. Parameters:

| Param | Values | Default | Meaning |
| ----- | ------ | ------- | ------- |
| `method` | `GET`, `HEAD`, `POST`, … | `GET` | request method |
| `expect_status` | codes / classes / ranges | `2xx,3xx` | which statuses count as available |
| `follow_redirects` | `true` \| `false` | `true` | follow 3xx redirects |
| `insecure_skip_verify` | `true` \| `false` | `false` | capture TLS but don't fail on an invalid cert. **Deny-by-default:** requires the admin-only `test.insecure_tls` permission and is flagged in the `test.create`/`test.update` audit entry |
| `ca_file` | path to a PEM bundle | — | extra trust anchor (private/internal CA); must live under `PROBECTL_AGENT_CANARY_CA_DIR` |
| `body` | string | — | request body (e.g. for `POST`) |
| `max_body_bytes` | integer | `10485760` | cap bytes read per probe (10 MiB) |
| `allow_private_targets` | `true` \| `false` | `false` | **SSRF-guard override.** Every canary (http/tcp/udp/icmp/dns/voice) denies loopback, RFC1918/ULA, link-local (incl. `169.254.169.254` cloud metadata), CGNAT, multicast and numeric-encoding bypasses by default, enforcing the check on the **resolved** address at dial time (rebind-proof). Setting `true` lifts the guard for that one test — requires the admin-only `test.allow_private` permission and is written to the tenant audit trail |

A word on the last row: **SSRF** (server-side request forgery) is the attack
where someone defines a "test" that makes *your* agent fetch an internal-only
address — the cloud metadata service, a loopback admin port — and report back
what it found. That is why every canary ships the private-target deny-list, why
it checks the **resolved** IP at dial time (a DNS name that later re-resolves to
something internal is caught too), and why lifting it is a per-test, admin-only,
audited act rather than a global switch.

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
the result to path/traceroute data** for the same destination.

**TLS capture.** On HTTPS the canary records the negotiated
`tls.protocol.version` and `tls.cipher`, the leaf certificate's
`tls.server.{subject,issuer,not_before,not_after,san}`, the chain shape
(`tls.server.chain`), and a `probectl_probe_http_tls_cert_expiry_days` metric
(negative once expired). It verifies the chain itself (hostname + trust, honoring
`ca_file`) **after** capturing the certificate, so the handshake details are
recorded **even when the certificate is invalid or expired** — an invalid cert
fails the probe but its details are still attached. Set `insecure_skip_verify:
"true"` to capture posture without failing the availability check. **WIRE-004:**
at the agent, `insecure_skip_verify=true` is *refused* unless the agent config
sets `security.allow_insecure_skip_verify: true` (default false); when permitted,
the probe runs but its result carries `tls.verification_disabled="true"` so every
verification-disabled probe is auditable. probectl performs no TLS *posture
analysis* here (issuer trust, weak-cipher/expiry policy, CT) — that is the *TLS /
certificate observability* feature below, which consumes these captured fields.

### Agent-to-agent tests

An agent-to-agent (A2A) test measures **between two registered agents**, brokered
by the control plane. The control plane assigns roles (one agent **responds**,
opening a short-lived listener; the other **initiates**), rendezvouses the
responder's endpoint to the initiator, and hands each agent its task when it
polls (`PollCoordination` / `ReportEndpoint`). The measurement is TWAMP-lite —
TWAMP is the standard two-way active measurement protocol; "lite" here means its
four-timestamp echo idea without the full session protocol: the
initiator timestamps each probe (T1), the responder stamps receive/send (T2/T3)
and echoes, and the initiator stamps receive (T4), yielding **round-trip**
(`probectl_probe_rtt_*`) plus **forward** and **reverse** one-way delay
(`probectl_probe_forward_avg_ms`, `probectl_probe_reverse_avg_ms`). The responder also
reports forward-direction delivery (`probectl_probe_packets_received`,
`probectl_probe_loss_ratio`), so both agents and both directions are observed.

Enable participation in the agent's `a2a` block: `enabled: true`,
`advertise_host` (the address peers use to reach this agent's responder),
`poll_interval` (default `2s`), and `responder_ttl` (default `15s`).
**Caveats (document for production):**

- **NAT/firewall.** The responder advertises `advertise_host`; behind NAT this
  must be a reachable address and the responder's ephemeral port must be
  reachable from the initiator. Auto-detection picks a non-loopback IPv4 — set
  `advertise_host` explicitly when that is wrong.
- **Clocks.** Forward/reverse one-way delays assume the two agents' clocks are
  synchronized (exact within one host; use **NTP** across hosts). Round-trip is
  clock-independent.

Sessions are brokered in-memory; triggering them from the test API is a later
addition.

### Path discovery

The path engine (`internal/path`) is the traceroute brain — it runs Paris-style
traceroutes (ICMP and TCP) and merges per-flow traces into one multi-path
picture; see [`architecture.md`](architecture.md). "Paris-style" matters because
of **ECMP** — routers spreading traffic across several equal-cost paths by
hashing packet header fields. A naive traceroute varies those very fields probe
to probe, so its hops come from *different* paths stitched into a nonsense
route; Paris holds the hashed fields constant so each trace coherently follows
one path, and varies them *deliberately* to enumerate the others. It also
captures MPLS labels (the tags carriers use to switch packets through
label-tunnels) where routers expose them. A **full per-hop trace needs raw sockets**:
grant `CAP_NET_RAW` (`setcap cap_net_raw+ep`, or run privileged) to capture the
intermediate hops + MPLS labels. Without it, only the destination is discovered.

Where the discovered hops/links are stored is a control-plane choice:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_PATHSTORE_MODE` | `memory` | `memory` (in-process, for the lightweight/single-binary case and tests) \| `clickhouse` (durable hop/link rows) |
| `PROBECTL_PATHSTORE_URL` | (none) | ClickHouse HTTP(S) endpoint (e.g. `http://localhost:8123`), partitioned by tenant; **required** when mode is `clickhouse` |
| `PROBECTL_PATH_RETENTION_DAYS` | `90` | delete-after-N-days TTL on the path/traceroute ClickHouse tables (applied at boot); `0` disables the TTL |

### BGP routing intelligence

BGP is the protocol networks use to tell each other which IP blocks (prefixes)
they can reach — the internet's routing gossip — so a wrong announcement
elsewhere can silently hijack or blackhole *your* traffic without touching your
equipment. The BGP plane watches for exactly that: a Python analyzer
(`analyzer/`) plus a Go bridge (`internal/bgp`); see
[`architecture.md`](architecture.md). The analyzer ingests **public** collector
data — MRT files (the archive format for routing-table dumps, e.g.
RouteViews/RIPE RIS) and RIS Live (RIPE's websocket firehose of route updates as
they happen) — and emits `probectl.bgp.events`:

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

RPKI is the cryptographic registry recording which network is *allowed* to
originate which prefix; a validator (`rpki-client`, Routinator) distills its
signed objects into VRPs — validated prefix→origin records — and RFC 6811
validation compares each seen announcement against them, labeling it `valid`,
`invalid`, or `not_found`. With no VRP source configured, everything is
honestly `unknown`.

The analyzer emits `probectl.bgp.events` as **JSON Lines**; the Go bridge tails that
stream, validates the tenant, and republishes each as the canonical
`probectl.bgp.v1.BGPEvent` protobuf onto the bus (topic `probectl.bgp.events`, keyed by
tenant). Event types: `origin_change` (old/new origin + AS path), `possible_hijack`,
`possible_leak`, `rpki_invalid`; each carries an RPKI status (`valid` / `invalid` /
`not_found` / `unknown`), a severity, and a confidence — they are **signals**, not
actions — probectl never acts on routing. MRT dumps are **stream-processed** (no
full RIB in memory); a down RPKI/collector source degrades gracefully rather
than breaking the plane.
RouteViews/RIS are open data — their AUP/provenance matters for MSP/commercial
resale, not for private development or single-tenant OSS use.

### Open-data enrichment

`internal/opendata` annotates IPs with context from public datasets: the **ASN**
(the numbered autonomous system — i.e. which network organization an IP belongs
to), geolocation, **IXP** presence (internet exchange points, the shared
facilities where networks interconnect), and registry allocation data. A bare
address like `203.0.113.7` becomes "AS64500, ExampleNet, DE, allocated 2014" —
the difference between a number and a story. See
[`architecture.md`](architecture.md) and the source provenance/AUP matrix in
[`opendata-aup.md`](opendata-aup.md). The framework is a library (the flow and
test pipelines consume it where enrichment is enabled); each source is
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
treated as untrusted — external content never gets implicit trust. Open data is ingested
**once and shared**; enrichment is scoped per tenant by the consuming record.

### Alerting

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
`X-Probectl-Signature: sha256=<hex>` — the HMAC-SHA256 of the exact body. An
HMAC is a keyed checksum: only a holder of the shared secret can compute it, so
the receiver can verify both *who sent this* and *that nothing was altered*
before acting on the alert. Each channel delivers independently: a failing
channel is logged and skipped, never blocking the others. Alerts are **signals**;
probectl notifies and does not act on the network (on-call/ITSM routing and
detection-as-code are their own features below).

### Incidents

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
`plane`/`kind` and an arbitrary `attributes` map, so the change, threat, cost, and
SLO planes attach as additional signal types onto the same `Incident`/timeline
without schema changes. AI root-cause analysis runs over the timeline.

### SSO & RBAC

probectl authenticates users with **OIDC SSO** — OIDC (OpenID Connect) is the
standard login handshake built on OAuth 2.0, and SSO (single sign-on) means
users sign in at their organization's identity provider (the IdP: Okta, Entra,
Keycloak, …) rather than holding a probectl-local password — and authorizes them
with **role-based access control (RBAC)**: every action requires a permission,
and permissions come from roles. The security order is the **two-level
boundary**: a request resolves to **exactly one
tenant first**, then RBAC decides whether the caller may perform the route's action
within that tenant.

**Login flow.** `GET /auth/login` (optionally `?tenant=<uuid>`) starts the OIDC
authorization-code flow: it sets a short-lived, HttpOnly CSRF `state` cookie and
redirects to the tenant's identity provider. The IdP redirects back to
`GET /auth/callback`, which verifies the `state`, exchanges the code, verifies the
ID token, **just-in-time provisions** the user within the tenant (a brand-new user
gets **no roles** — a secure default; an admin grants access), mints a server-side
session, and sets the session cookie. `POST /auth/logout` revokes the session.
`GET /v1/me` returns the caller's tenant, identity, and effective permissions.

**Sessions.** A session is a random, high-entropy opaque token. Only its **hash**
is stored (table `sessions`), so a database read cannot mint a session. The
session cookie is **HttpOnly + SameSite=Lax**, and **Secure** whenever the
API serves HTTPS. `PROBECTL_SESSION_TTL` (default `12h`) bounds its lifetime.

**Per-tenant IdP.** Providers are resolved per tenant through a provider factory —
the seam for a tenant bringing its own SSO. The shipped default is the
env-configured one (`PROBECTL_OIDC_*`); database-backed per-tenant IdP config is a
later addition. A login always resolves to a single tenant. Provider/MSP operators
authenticate into the **provider domain** (the management plane), not into tenant
data.

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
`X-Probectl-Tenant: <uuid>` override for multi-tenant dev. It is
**triple-gated**: (1) the code path exists only in binaries built with
`-tags devauth` (`make build-devauth`) — a release binary **refuses to start**
in this mode; (2) `PROBECTL_DEV_AUTH_ACK=i-understand` must be set; (3) the
listener must bind loopback (`PROBECTL_HTTP_ADDR=127.0.0.1:…`). When active it
logs at error level and writes an `auth.dev_mode_active` audit event. The CI
gate `no-devauth-in-release` proves release binaries contain neither the
symbols nor the dev-principal literal. The test suite installs its own hook
in `_test.go` files, which never ship.

### Resource API & CLI

The versioned resource API lives under **`/v1`** (full schema at `/openapi.json`):

- `GET/POST /v1/tests`, `GET/PUT/DELETE /v1/tests/{id}` — synthetic-test CRUD.
- `GET /v1/agents`, `GET/PATCH/DELETE /v1/agents/{id}` — agents register over
  mTLS; the API lists, renames, and deregisters them.
- `GET/POST /v1/tests/{id}/path` — the latest discovered network path for a test,
  and a trigger to discover it now. The Path & Topology UI consumes this.

Every `/v1` route is **tenant-scoped** through `internal/tenancy` + Postgres RLS,
so a request can never read or write across tenants. **Authentication and RBAC are
real** (see *SSO & RBAC* below): the caller's tenant and effective permissions come
from an authenticated session, and each route requires a permission. The "no
undocumented routes" rule is enforced by a test that matches the route table
against `openapi.json`.

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

### eBPF host agent

The eBPF agent watches a host's network from inside the Linux kernel — it sees
which processes talk to which services without you instrumenting anything. It is
**observe-only**: it never blocks or modifies traffic. Like the canary agent, its
real config is a **YAML file** (`-config` / `PROBECTL_EBPF_CONFIG`); see
[`deploy/agent/probectl-ebpf-agent.example.yml`](../deploy/agent/probectl-ebpf-agent.example.yml)
and [`ebpf-agent.md`](ebpf-agent.md), with `PROBECTL_EBPF_*` env vars overriding
individual fields. The in-kernel loader is compiled in only with the `ebpf` build
tag; without it (or for tests), point `fixture_path` at a recording to replay.

The big idea in the keys below: **layer-7 plaintext capture is off, and stays off
until you prove three separate intents** — turn it on (`L7_CAPTURE`), name the
tenant that consents (`L7_CONSENT_TENANT`), and list the exact workloads
(`L7_SCOPE`). Miss any one and the kernel copies no payload. That is the
fail-closed posture for the most sensitive thing this agent can do.

| Variable                     | Default     | Description                                                     |
| ---------------------------- | ----------- | -------------------------------------------------------------- |
| `PROBECTL_EBPF_CONFIG`         | (none)      | path to the YAML config (`-config` flag overrides)             |
| `PROBECTL_EBPF_TENANT_ID`      | (required)  | the tenant every flow is stamped with — the agent refuses to start without it |
| `PROBECTL_EBPF_HOST`           | OS hostname | observing host name                                            |
| `PROBECTL_EBPF_BUS_MODE`       | `memory`    | `memory` \| `kafka`                                            |
| `PROBECTL_EBPF_BUS_BROKERS`    | (none)      | comma-separated Kafka brokers (kafka mode)                     |
| `PROBECTL_EBPF_BUS_NAMESPACE`  | (none)      | publish on this tenant's siloed bus lane (`probectl.<ns>.ebpf.flows`) instead of the shared topic; for per-tenant-namespaced (siloed) deployments |
| `PROBECTL_EBPF_FIXTURE_PATH`   | (none)      | replay recorded flows instead of loading eBPF (no-kernel path) |
| `PROBECTL_EBPF_L7_FIXTURE_PATH` | (none)     | replay recorded layer-7 events (no-kernel L7 path)             |
| `PROBECTL_EBPF_RING_BUFFER_BYTES` | `16777216` | size of the kernel→userspace ring buffer (16 MiB; live loader only). Bigger absorbs bigger traffic bursts at the cost of memory |
| `PROBECTL_EBPF_LIBSSL`         | (auto)      | explicit libssl path for TLS-plaintext (uprobe) L7 capture; auto-discovered when unset (`ebpf` build) |
| `PROBECTL_EBPF_L7_CAPTURE`     | `false`     | master switch — live TLS-plaintext capture is OFF by default. `true` alone is **not** enough; consent AND scope below are also required |
| `PROBECTL_EBPF_L7_CONSENT_TENANT` | (none)   | the explicit per-tenant consent: must equal this agent's bound tenant id exactly, else capture stays off |
| `PROBECTL_EBPF_L7_SCOPE`       | (none)      | the explicit workload opt-in — comma-separated `pid:<n>`, `exe:/abs/path`, `cgroup:/abs/cgroup-dir` entries. The kernel program drops every other process BEFORE copying a byte; empty = capture refuses to start. Host-wide capture is deliberately not expressible. Container/pod scoping is the `cgroup:` form (a container IS a cgroup); `exe:` entries are re-resolved every 10s so restarts stay in scope |
| `PROBECTL_EBPF_L7_REDACTION`   | `headers`   | how much of a payload may survive capture: `headers` zeroes the bodies in place before anything is retained (protocol metadata survives); `length` captures NO payload bytes (traffic shape only, no parsed calls); `full` (consented debugging) disables masking |
| `PROBECTL_EBPF_L7_KERNEL_WINDOW` | `1024`    | max plaintext bytes per chunk that may cross from kernel into userspace under `headers` redaction (128–4095); bytes past the window never leave the kernel. `length` forces 0, `full` forces 4095. An unprogrammed kernel defaults to length-only, so it ships no plaintext |
| `PROBECTL_EBPF_PROC_ROOT`      | `/proc`     | procfs root for process/cgroup enrichment                      |
| `PROBECTL_EBPF_FLUSH_INTERVAL` | `10s`       | how often flows + the service map are emitted (also the idle-prune cadence) |
| `PROBECTL_EBPF_MAX_SERVICE_EDGES` | `50000`  | cap on live service-map edges (EBPF-001/SCALE-003); least-recently-seen evicted past the cap. `0` = unbounded (lightweight/test only) |
| `PROBECTL_EBPF_MAX_L7_CONNS`   | `8192`      | cap on live L7 per-connection trackers (FUZZ-001); oldest-seen connection evicted past the cap. `0` = unbounded |
| `PROBECTL_EBPF_L7_CONN_IDLE_TTL` | `5m`      | a connection/edge idle longer than this is abandoned on the flush ticker (FUZZ-001) — connIDs have no socket-close signal yet, so this sweep bounds the maps |
| `PROBECTL_EBPF_HEALTH_ADDR`    | (none)      | bind a liveness/readiness probe server (e.g. `:9090`; `/healthz` = process up, `/readyz` = flow source attached). Empty disables it. The Helm DaemonSet sets it from `health.port` |
| `PROBECTL_EBPF_LOG_LEVEL`      | `info`      | `debug` \| `info` \| `warn` \| `error`                         |
| `PROBECTL_EBPF_LOG_FORMAT`     | `json`      | `json` \| `text`                                               |

Flows + service edges are published to `probectl.ebpf.flows` (`ebpfv1.FlowBatch`,
tenant-keyed). The live loader needs a BTF Linux kernel (≥5.8; BTF is the type
metadata modern kernels embed, which lets one compiled eBPF program adapt itself
to many kernel versions instead of being rebuilt per machine) and
`CAP_BPF`/`CAP_PERFMON`; see [`ebpf-agent.md`](ebpf-agent.md).

#### Agent→bus TLS/SASL (eBPF, endpoint, flow, and device agents)

When a telemetry agent publishes straight to Kafka, its broker connection takes
the same hardening keys as the control plane's `PROBECTL_BUS_*` set, under the
agent's own prefix: `PROBECTL_EBPF_BUS_*` here, and likewise
`PROBECTL_ENDPOINT_BUS_*`, `PROBECTL_FLOW_BUS_*`, and `PROBECTL_DEVICE_BUS_*`
for the agents below. TLS encrypts the broker hop; SASL is Kafka's
authentication layer on top of it — a username/password proven either directly
(`plain`, safe only inside TLS) or via a challenge that never sends the
password (`scram-sha-256`/`-512`). The policy is the same fail-closed one: kafka
mode without TLS refuses to start unless the explicit dev-only plaintext flag is
set. (The canary agent has no bus keys — it talks gRPC/mTLS to the control
plane, which publishes on its behalf.)

| Suffix (append to the agent's prefix) | Default | Meaning |
| --- | --- | --- |
| `_BUS_TLS_ENABLED` | `false` | TLS to the brokers — **required in kafka mode** unless `_BUS_ALLOW_PLAINTEXT` is set |
| `_BUS_TLS_CA_FILE` | (none) | private CA bundle for the brokers |
| `_BUS_TLS_CERT_FILE` / `_BUS_TLS_KEY_FILE` | (none) | client certificate + key (broker mTLS) |
| `_BUS_SASL_MECHANISM` | (none) | `plain` \| `scram-sha-256` \| `scram-sha-512` |
| `_BUS_SASL_USER` / `_BUS_SASL_PASSWORD` | (none) | SASL credentials (the agents read these as literal env values — the secret-reference schemes are a control-plane feature) |
| `_BUS_ALLOW_PLAINTEXT` | `false` | **dev only**: allow a plaintext broker (the dev compose stack). Production never sets this |
| `_BUS_MAX_BUFFERED` | `0` (= built-in bound `65536`) | async-producer in-flight bound; a full buffer sheds + counts, never blocks |

### Endpoint / DEM agent (`probectl-endpoint`)

"DEM" is digital experience monitoring: this agent runs on an end-user's laptop
(Linux/macOS/Windows), measures their actual last-mile experience, and figures out
whether a slowdown is the WiFi, the ISP, or the network. Because it sits on a
personal device, its defaults are **privacy-first** — it collects the WiFi name
and gateway (useful, low-risk) but **not** the AP MAC or public hop IPs (which can
geolocate a person), and it discloses exactly what it collects on startup. It reads
a YAML config (default path `PROBECTL_ENDPOINT_CONFIG`); `PROBECTL_ENDPOINT_*` env
vars override it. See [`endpoint-dem.md`](endpoint-dem.md).

| Variable                              | Default        | Meaning                                                          |
| ------------------------------------- | -------------- | ---------------------------------------------------------------- |
| `PROBECTL_ENDPOINT_CONFIG`              | (none)         | path to the YAML config (`-config` flag overrides)               |
| `PROBECTL_ENDPOINT_TENANT_ID`           | (required)     | the tenant every result is stamped with — refuses to start without it |
| `PROBECTL_ENDPOINT_AGENT_ID`            | OS hostname    | device identifier in the fleet                                   |
| `PROBECTL_ENDPOINT_BUS_MODE`            | `memory`       | `memory` \| `kafka`                                              |
| `PROBECTL_ENDPOINT_BUS_BROKERS`         | (none)         | comma-separated Kafka brokers (kafka mode)                       |
| `PROBECTL_ENDPOINT_BUS_NAMESPACE`       | (none)         | publish on this tenant's siloed bus lane instead of the shared topic (siloed deployments) |
| `PROBECTL_ENDPOINT_INTERVAL`            | `60s`          | how often a sample is collected                                  |
| `PROBECTL_ENDPOINT_TARGETS`             | `https://1.1.1.1,https://www.google.com` | comma-separated targets (first = last-mile trace; all = session probes) |
| `PROBECTL_ENDPOINT_MAX_HOPS`            | `20`           | last-mile trace hop cap                                          |
| `PROBECTL_ENDPOINT_COLLECT_SSID`        | `true`         | retain the WiFi network name (SSID)                              |
| `PROBECTL_ENDPOINT_COLLECT_BSSID`       | `false`        | retain the access-point MAC (BSSID) — geolocatable PII, off by default |
| `PROBECTL_ENDPOINT_COLLECT_GATEWAY_IP`  | `true`         | retain the (private) default-gateway address                    |
| `PROBECTL_ENDPOINT_COLLECT_PUBLIC_HOPS` | `false`        | retain PUBLIC last-mile hop IPs (which reveal ISP/geo), off by default |
| `PROBECTL_ENDPOINT_LOG_LEVEL`           | `info`         | `debug` \| `info` \| `warn` \| `error`                           |
| `PROBECTL_ENDPOINT_LOG_FORMAT`          | `json`         | `json` \| `text`                                                 |

Results (WiFi / gateway / last-mile / session signals + the attribution verdict)
are published to `probectl.endpoint.results` (`resultv1.Result`, tenant-keyed),
flowing through the same pipeline as every other canary. The agent **discloses
exactly what it collects at startup** and never phones home.

### Flow collector (`probectl-flow-agent`)

A **flow record** is a router's summary of one conversation — who talked to
whom, on which ports/protocol, when, and how many bytes/packets — with **no
payload**: the phone bill, not the phone call. NetFlow, IPFIX, and sFlow are the
three export dialects devices speak. The flow collector listens for NetFlow
v5/v9, IPFIX, and sFlow v5 datagrams from
network devices, decodes them (template + sampling handling), and publishes
normalized batches to `probectl.flow.events` (`flowv1.FlowBatch`, tenant-keyed).
It reads a YAML config (default path `PROBECTL_FLOW_CONFIG`); `PROBECTL_FLOW_*`
env vars override the file. The defaults serve all three protocols on their
standard ports (NetFlow `:2055`, IPFIX `:4739`, sFlow `:6343`). See
[`flow.md`](flow.md) for the security posture: flow export is plaintext UDP by
design, so every datagram is treated as untrusted and the collector should sit
**adjacent to its exporters** (not exposed to the wider network).

| Variable                          | Default     | Meaning                                                        |
| --------------------------------- | ----------- | --------------------------------------------------------------- |
| `PROBECTL_FLOW_CONFIG`             | (none)      | path to the YAML config (`-config` flag overrides)              |
| `PROBECTL_FLOW_TENANT`             | (required)  | the tenant every flow record is stamped with — refuses to start without it |
| `PROBECTL_FLOW_BUS_NAMESPACE`      | (none)      | publish this agent's batches on its tenant's siloed bus lane (`probectl.<ns>.flow.events`) instead of the shared topic; a malformed value refuses start. The same key exists for the other agents: `PROBECTL_DEVICE_BUS_NAMESPACE`, `PROBECTL_EBPF_BUS_NAMESPACE`, `PROBECTL_ENDPOINT_BUS_NAMESPACE` |
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

The **control plane** consumes that flow topic, optionally enriches each record
with ASN/geo, and persists to the flow store behind `/v1/flows/*` (top-talkers /
capacity / anomalies). These are control-plane keys (not flow-agent keys):

| Variable                        | Default  | Meaning                                                             |
| -------------------------------- | -------- | -------------------------------------------------------------------- |
| `PROBECTL_FLOWSTORE_MODE`         | `memory` | where flow records live: `memory` (lightweight/single-binary) \| `clickhouse` (durable, high-cardinality) |
| `PROBECTL_FLOWSTORE_URL`          | (none)   | ClickHouse HTTP(S) endpoint; **required** in clickhouse mode         |
| `PROBECTL_DEPLOYMENT_PROFILE` | `single` | isolation posture (TENANT-004): `single` (sovereign/single-tenant — app-layer WHERE scoping is the boundary) \| `multi-tenant` \| `regulated`. The latter two default **DB-enforced ClickHouse tenant isolation ON for every telemetry plane** (flow/otel/eBPF/path) — defense-in-depth above app code (guardrail 7.1). The per-plane `*_TENANT_SCOPING` toggles below default off this profile; set one explicitly to override |
| `PROBECTL_FLOWSTORE_TENANT_SCOPING` | profile | defense-in-depth: also constrain flow reads at the **database** by attaching a per-request tenant setting that a ClickHouse row policy enforces (needs server-side `custom_settings_prefixes=SQL_` + a reader user). Defaults ON under `multi-tenant`/`regulated`, off under `single` |
| `PROBECTL_FLOWSTORE_READER_USER` | (none) | the ClickHouse reader user the setting-scoped row policy is installed on at boot (pairs with the toggle above) |
| `PROBECTL_OTELSTORE_TENANT_SCOPING` | profile | TENANT-003/004: DB-level reader scoping on the OTLP traces+logs plane (the PII-heaviest). Same mechanism as flow; defaults ON under `multi-tenant`/`regulated` |
| `PROBECTL_OTELSTORE_READER_USER` | (none) | the ClickHouse reader user the otel setting-scoped row policy is installed on at boot |
| `PROBECTL_EBPFSTORE_TENANT_SCOPING` | profile | TENANT-004: DB-level reader scoping on the eBPF L7 edge plane; defaults ON under `multi-tenant`/`regulated` |
| `PROBECTL_EBPFSTORE_READER_USER` | (none) | the ClickHouse reader user the eBPF setting-scoped row policy is installed on at boot |
| `PROBECTL_PATHSTORE_TENANT_SCOPING` | profile | TENANT-004: DB-level reader scoping on the path plane; defaults ON under `multi-tenant`/`regulated` |
| `PROBECTL_PATHSTORE_READER_USER` | (none) | the ClickHouse reader user the path setting-scoped row policy is installed on at boot |
| `PROBECTL_INGEST_STRICT_TENANT_LANES` | profile | WIRE-001: refuse agent-published collector planes (flow/eBPF/device/endpoint) on the **shared pooled bus lane**, forcing them onto tenant-namespaced lanes (broker-ACL isolated, forgery-proof). Closes the residual shared-lane forgery surface. Defaults ON under `multi-tenant`/`regulated`, OFF under `single`. Rejections increment `probectl_pipeline_tenant_rejected_total` on `/metrics` |
| `PROBECTL_FLOW_RETENTION_DAYS`    | `0` (keep) | when `> 0`, applies a delete-after-N-days TTL to the `probectl_flows` ClickHouse table; `0` keeps flows indefinitely |
| `PROBECTL_FLOW_ENRICH_ASN`        | `false`  | opt-in Team Cymru ASN enrichment. Off by default because it makes outbound DNS lookups (the no-phone-home guardrail); AS numbers the device itself exported always pass through regardless |

### Device telemetry agent (`probectl-device-agent`)

This agent reads metrics straight off network gear (routers, switches). It polls
the old way (**SNMP v2c/v3**) and subscribes the modern streaming way
(**gNMI/OpenConfig**), normalizes both into one `DeviceMetric` shape, and publishes
to `probectl.device.metrics` (tenant-keyed); the control plane lands them in the
TSDB as `probectl_device_*` series. The full device list lives in a YAML config
(see `deploy/agent/probectl-device-agent.example.yml`); the env vars below override
it and give a **single-device quick start** for trying one device fast. See
[`device-telemetry.md`](device-telemetry.md).

| Variable                       | Default     | Meaning                                                          |
| ------------------------------- | ----------- | ----------------------------------------------------------------- |
| `PROBECTL_DEVICE_CONFIG`         | (none)      | path to the YAML config (`-config` flag overrides)                |
| `PROBECTL_DEVICE_TENANT`         | (required)  | the tenant every device metric is stamped with — refuses to start without it |
| `PROBECTL_DEVICE_AGENT_ID`       | OS hostname | agent identifier                                                  |
| `PROBECTL_DEVICE_BUS_MODE`       | `memory`    | `memory` \| `kafka`                                               |
| `PROBECTL_DEVICE_BUS_BROKERS`    | (none)      | comma-separated Kafka brokers (kafka mode)                        |
| `PROBECTL_DEVICE_BUS_NAMESPACE`  | (none)      | publish on this tenant's siloed bus lane instead of the shared topic (siloed deployments) |
| `PROBECTL_DEVICE_TARGET`         | (none)      | quick start: add one device by address                            |
| `PROBECTL_DEVICE_TRANSPORT`      | `snmpv2c`   | quick-start transport: `snmpv2c` \| `snmpv3` \| `gnmi`            |
| `PROBECTL_DEVICE_CREDENTIAL`     | (none)      | quick start: credential NAME for the device (see below)           |
| `PROBECTL_DEVICE_PORT`           | `161` (SNMP) / `9339` (gNMI) | quick start: port override (defaults to the transport's standard port) |
| `PROBECTL_DEVICE_INTERVAL`       | `60s`       | quick start: poll/sample interval                                 |
| `PROBECTL_DEVICE_LOG_LEVEL`      | `info`      | `debug` \| `info` \| `warn` \| `error`                            |
| `PROBECTL_DEVICE_LOG_FORMAT`     | `json`      | `json` \| `text`                                                  |

**Credentials are referenced by NAME, never inlined** — no secrets in
the device list. The default credential source resolves those names from the
environment (the `PROBECTL_DEVICE_CRED_<NAME>_*` vars below); the secrets backends
plug Vault/CyberArk into the same seam. An unresolvable name fails closed at
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

(USM is SNMPv3's user security model: a named user *authenticates* with the
`AUTH_*` pair and optionally *encrypts* with the `PRIV_*` pair — leaving a
passphrase empty steps the security level down, as the table notes.)

gNMI connections are **TLS with certificate verification** (system roots or a
per-device `ca_file`); there is no skip-verify option. `plaintext: true` is an
explicit lab-only YAML opt-in and is loudly logged — never a silent plaintext default.

### OTLP receiver

OTLP is the OpenTelemetry protocol — the vendor-neutral standard wire format for
metrics, traces, and logs. This receiver lets *other* systems push their OTLP
data into probectl: anything that already speaks OpenTelemetry can send here
without changing its exporter. It
is **off by default** and, when on, is locked to the same posture
as everything else: **TLS-only, token-authenticated, tenant-scoped**, on its own
listeners separate from the `/v1` REST API. There is no anonymous-plaintext mode —
setting a listen address without both a TLS cert/key pair and at least one bearer
token fails config validation. See [`otlp.md`](otlp.md).

| Variable                    | Default | Description                                                  |
| --------------------------- | ------- | ------------------------------------------------------------ |
| `PROBECTL_OTLP_GRPC_ADDR`     | (none)  | OTLP/gRPC listen address (e.g. `:4317`)                      |
| `PROBECTL_OTLP_HTTP_ADDR`     | (none)  | OTLP/HTTP listen address (e.g. `:4318`); accepts all three signals — `POST /v1/metrics`, `/v1/traces`, `/v1/logs` |
| `PROBECTL_OTELSTORE_MODE`     | `memory` | where ingested OTLP traces+logs live: `memory` (lightweight) \| `clickhouse` (production; `(tenant_id, day)` partition) |
| `PROBECTL_OTELSTORE_URL`      | (none)  | ClickHouse HTTP URL for `clickhouse` mode (https = TLS in transit) |
| `PROBECTL_OTEL_RETENTION_DAYS` | `30`   | delete-TTL for stored OTLP traces+logs (0 disables) |
| `PROBECTL_OTLP_TLS_CERT_FILE` | (none)  | PEM server certificate (required to enable)                  |
| `PROBECTL_OTLP_TLS_KEY_FILE`  | (none)  | PEM server private key (required to enable)                  |
| `PROBECTL_OTLP_TOKENS`        | (none)  | bearer-token→tenant map: `token1=tenant1,token2=tenant2`     |

Setting an address without the TLS files **and** at least one token fails config
validation — the receiver is never anonymous plaintext. Ingested metrics are
tenant-tagged and published to the `probectl.otlp.metrics` bus topic.

### OTLP export

probectl can *export* OTLP to an upstream collector. All three signals are
forwarded — **metrics, traces, and logs** (ARCH-003): ingested traces/logs are
re-exported to a customer's own trace/log backend, not just queryable inside
probectl. For OTLP/HTTP the per-signal paths are derived from the configured
endpoint (`…/v1/metrics` → `…/v1/traces`, `…/v1/logs`). This egresses
confidential customer telemetry (plus the bearer token), so a **remote** collector
must be encrypted — guardrail 12. Config validation **fails closed** otherwise:
for `http` a remote endpoint must be `https://`; for `grpc` the `INSECURE` flag is
refused for a remote endpoint. A *loopback* collector (a co-located sidecar) may use
plain `http://` / `INSECURE` for development.

| Variable                        | Default | Description                                                  |
| ------------------------------- | ------- | ------------------------------------------------------------ |
| `PROBECTL_OTLP_EXPORT_ENDPOINT` | (none)  | upstream OTLP collector; enables export. Remote must be `https://` (HTTP) / TLS (gRPC) |
| `PROBECTL_OTLP_EXPORT_PROTOCOL` | `grpc`  | `grpc` \| `http`                                             |
| `PROBECTL_OTLP_EXPORT_TOKEN`    | (none)  | bearer token sent to the collector                           |
| `PROBECTL_OTLP_EXPORT_INSECURE` | `false` | disable TLS — **loopback endpoints only** (refused for a remote target) |

### Ecosystem integrations

The Grafana datasource API (`/v1/grafana/api/v1/*`), the federation endpoint
(`/v1/prometheus/federate`), and the remote-write receiver
(`/v1/prometheus/write`) ride the existing TSDB config (`PROBECTL_TSDB_MODE` /
`PROBECTL_TSDB_URL`) and the `/v1` API listener — no extra keys. Reads need
`metrics.read`, remote-write `metrics.write` (migration 0022). See
[`ecosystem-integrations.md`](ecosystem-integrations.md).

A CMDB (configuration management database) is an organization's IT inventory —
a registry of *configuration items* (CIs: servers, applications, services) and
who owns them. The ServiceNow CMDB correlation tags probectl incidents and
agents with the CI they belong to, so an alert arrives already knowing "this is
the payments edge proxy, owned by team X". It is off unless configured:

| Variable                  | Default   | Meaning                                                            |
| -------------------------- | --------- | ------------------------------------------------------------------- |
| `PROBECTL_CMDB_PROVIDER`    | (none)    | `servicenow` enables CI correlation (`/v1/cmdb/*`, incident/agent CIs) |
| `PROBECTL_CMDB_URL`         | (none)    | instance URL, e.g. `https://acme.service-now.com` (https; http only for loopback test doubles) |
| `PROBECTL_CMDB_SECRET`      | (none)    | `user:password` for the read-only integration user (env only — never in files/logs) |
| `PROBECTL_CMDB_TABLE`       | `cmdb_ci` | CI table queried via the Table API                                  |
| `PROBECTL_CMDB_CACHE_TTL`   | `10m`     | CI lookup cache TTL (a down CMDB serves stale entries)              |

### AI assistant

Worked per-provider setups (Ollama, vLLM, OpenAI, Anthropic, Azure) are in
[`ai-rca.md`](ai-rca.md) → *Copy-paste recipes*; the remote-egress enablement
chain (operator ack + per-tenant consent) is in [`ai-egress.md`](ai-egress.md).

The assistant (root-cause analysis + natural-language query) works **out of the
box with zero network access** — the default `builtin` provider is an in-process
synthesizer that writes its answers locally. You only point it at a real language
model if you want nicer prose, and doing so is treated as data egress: a remote
endpoint must be `https`, and you have to explicitly acknowledge that tenant data
will leave (`PROBECTL_AI_EGRESS_ACK`). A loopback endpoint may be `http` (for a
local model on the same box). The redaction keys below mask sensitive values
*before* anything reaches an external model. See [`ai-rca.md`](ai-rca.md).

| Variable                   | Default   | Description                                                         |
| -------------------------- | --------- | ------------------------------------------------------------------ |
| `PROBECTL_AI_MODEL_PROVIDER` | `builtin` | `builtin` (air-gapped, the default) \| `ollama` \| `openai` \| `anthropic` |
| `PROBECTL_AI_EGRESS_ACK` | (none) | **required to use a REMOTE model**: must equal `yes-send-tenant-data-to-the-remote-model`, or the server refuses to start. This is a deliberate "yes, I know data leaves" gate, on top of per-tenant consent + audit — see [`docs/ai-egress.md`](ai-egress.md) |
| `PROBECTL_AI_REDACT_IPS` | `true` | mask IP addresses in anything sent to an external model (stable per-value tokens, so correlation survives; local file paths are never redacted) |
| `PROBECTL_AI_REDACT_HOSTNAMES` | `false` | also mask hostnames (secrets are masked unconditionally regardless of this) |
| `PROBECTL_AI_REDACT_PII` | `true` | mask free-text PII — emails, phone numbers, MAC addresses — in anything sent to an external model (RCA prompts, MCP tool results, authoring prompts) |
| `PROBECTL_AI_REDACT_PATTERNS` | (none) | your own regexes (`;;`-separated), masked as `[custom:xxxx]` — for org-specific identifiers (employee IDs, ticket refs). A bad pattern refuses start (fail closed) |
| `PROBECTL_AI_MODEL_ENDPOINT` | (none)    | base URL of the model (required for a non-`builtin` provider)      |
| `PROBECTL_AI_MODEL_NAME`     | (none)    | model name (e.g. `llama3.1`, `gpt-4o-mini`)                        |
| `PROBECTL_AI_MODEL_TOKEN`    | (none)    | API key / bearer token (optional for a local Ollama)              |
| `PROBECTL_AI_MODEL_TIMEOUT`  | `60s`     | per-request timeout for the model endpoint                         |
| `PROBECTL_AI_MAX_EVIDENCE`   | `50`      | cost guard: the most signals one answer may gather                 |
| `PROBECTL_AI_MAX_CONCURRENT` | `8`       | process-wide cap on concurrent analyses (HTTP 429 when exceeded); a backstop beneath the per-tenant fairness gate |
| `PROBECTL_AI_PERSIST_ANSWERS` | `false`  | persist every answer (the cited JSON + model + config hash) for reproducibility/disputes |
| `PROBECTL_AI_ANSWER_RETENTION` | `2160h` (90 days) | prune persisted answers older than this (enforced opportunistically on write) |

A non-`builtin` provider without an endpoint fails config validation. Whatever the
backend, every answer is tenant- and RBAC-scoped by the query layer and every claim
is citation-checked before it reaches the user — a model can never see out-of-scope
data or inject an ungrounded claim.

### MCP server

MCP — the Model Context Protocol — is the standard by which AI applications
(Claude Desktop, IDE assistants, agent frameworks) call external tools. The MCP
server exposes read-only, tenant- + RBAC-scoped probectl tools to such clients,
which means an MCP caller is an *external AI* reading tenant data — so tool
results ride the same egress gate as the RCA model
([`ai-egress.md`](ai-egress.md)). The
**HTTP** transport is off by default and is **TLS-only + bearer-authenticated**;
the **stdio** transport is local (the client launches `probectl-control mcp-stdio`
as a subprocess and talks over stdin/stdout — no listener at all; the
token comes from `PROBECTL_MCP_TOKEN`). Mint a token with
`probectl-control mcp-token --user <user-uuid> [--tenant <uuid>] [--name <label>]` —
the token prints once and only its hash is stored, so a database read can never
recover it. See [`mcp.md`](mcp.md).

| Variable                   | Default | Description                                                   |
| -------------------------- | ------- | ------------------------------------------------------------- |
| `PROBECTL_MCP_HTTP_ADDR`     | (none)  | MCP HTTP listen address (e.g. `:8090`) — enables the transport |
| `PROBECTL_MCP_TLS_CERT_FILE` | (none)  | PEM server certificate (required to enable HTTP)              |
| `PROBECTL_MCP_TLS_KEY_FILE`  | (none)  | PEM server private key (required to enable HTTP)              |
| `PROBECTL_MCP_RATE_PER_MIN`  | `120`   | per-tenant tool-call rate limit (0 disables)                  |

Setting `PROBECTL_MCP_HTTP_ADDR` without the TLS files fails config validation — the
MCP endpoint is never anonymous plaintext.

### TLS / certificate observability

The control plane analyzes TLS/cert posture from **TLS handshakes the HTTP and
eBPF-L7 probes already captured** — it never re-handshakes a target itself — and
correlates the findings into threat-plane incidents. See
[`tls-observability.md`](tls-observability.md).

| Variable                    | Default        | Description                                                       |
| --------------------------- | -------------- | ----------------------------------------------------------------- |
| `PROBECTL_TRUSTCTL_URL`        | (none)         | trustctl base URL; enables a one-click renewal deep-link on findings |
| `PROBECTL_TLS_EXPIRY_WARNING` | `504h` (21d)   | expiring-soon window                                              |
| `PROBECTL_CT_ENABLED`         | `false`        | opt in to Certificate Transparency correlation (external fetch)   |
| `PROBECTL_CT_ENDPOINT`        | `https://crt.sh` | CT log API endpoint                                             |

CT logs are Certificate Transparency's public, append-only ledgers of every
certificate publicly issued — correlation against them answers "was a cert for
*my* name issued that I don't know about?" (a rogue or mis-issued certificate).
It is **off by default** (an external fetch — sovereignty / AUP /
rate limits) and degrades gracefully when the CT source is down.

### Threat-intel enrichment

Threat-intel feeds are public lists of **IOCs** — indicators of compromise:
known-bad IPs, certificates, URLs. A **JA3** is a fingerprint of *how* a client
performs its TLS handshake, which identifies malware families even when their
server IPs rotate. The control plane can match peer IPs / hostnames / certs /
JA3 seen in your own telemetry against these feeds, surfacing
**confidence-scored, source-attributed** threat-plane
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

### Enterprise identity: SCIM + ABAC

SCIM is the standard API identity providers use to *push* user lifecycle into
applications — a joiner appears, a leaver is deactivated, without anyone touching
probectl. ABAC (attribute-based access control) layers policy *conditions* on
top of RBAC roles — "editors may write tests only in project X". Both have
**no environment keys** — the SCIM bearer token
an IdP presents is minted with the control-plane CLI, and ABAC policies are managed
over the API. See [`scim-abac.md`](scim-abac.md).

```sh
# mint a per-tenant SCIM token for an IdP (shown once)
probectl-control scim-token --tenant <tenant-uuid> --name okta
```

The `/scim/v2/*` surface is gated by a valid SCIM token (no token ⇒ `401`), and the
directory-admin API (`/v1/abac/policies`) requires `directory.read`/`directory.write`.

### Change intelligence

Most outages follow a change. This feature ingests change webhooks — deploys,
config pushes, route changes, IaC (infrastructure-as-code) applies, commits —
each cryptographically signed by its provider, into a change timeline, and
correlates them with incidents ("this incident started 4 minutes after that
deploy"), feeding the AI RCA. See
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

### SIEM export

A SIEM (security information and event management system — Splunk, Microsoft
Sentinel, Elastic, Google Chronicle, …) is the SOC's central platform where an
organization's security events converge for detection and investigation. This
feature forwards the **audit stream** and **threat-plane signals** there over
hardened TLS. probectl is the **forwarder, not a SIEM** — events are rendered into a
standard format and pushed; nothing is auto-blocked. See [`siem.md`](siem.md) for
formats, delivery guarantees, and per-SIEM setup.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PROBECTL_SIEM_ENABLED` | `false` | master switch (an outbound connection to your SIEM); off ⇒ no SIEM code runs |
| `PROBECTL_SIEM_PRESET` | `generic` | SIEM adapter: `generic`, `splunk`, `sentinel`, `elastic`, `chronicle` (sets the auth scheme + default format) |
| `PROBECTL_SIEM_FORMAT` | (preset) | wire format: `syslog` (RFC 5424), `cef`, `ecs`, `otlp`; empty ⇒ the preset's native default (Elastic⇒ecs, Chronicle⇒otlp, else cef) |
| `PROBECTL_SIEM_ENDPOINT` | (none) | HTTPS ingest URL (e.g. the Splunk HEC / Sentinel / Chronicle / Elasticsearch endpoint). Enabled without it ⇒ a startup warning and the export stays disabled (the control plane still runs) |
| `PROBECTL_SIEM_TOKEN` | (none) | ingest credential (Splunk ⇒ `Splunk <tok>`, Elastic ⇒ `ApiKey <tok>`, others ⇒ `Bearer <tok>`). Inject from a secret manager |
| `PROBECTL_SIEM_POLL_INTERVAL` | `30s` | audit-stream drain cadence |
| `PROBECTL_SIEM_BUFFER` | `1024` | threat-signal buffer; full ⇒ producers block (backpressure, never drop) |
| `PROBECTL_SIEM_REDACT_KEYS` | (none) | extra audit `data` keys to scrub (on top of the built-in secret/PII denylist) |

The wire formats are the SIEM world's lingua francas: `syslog` (RFC 5424
structured syslog), `cef` (ArcSight's Common Event Format), `ecs` (the Elastic
Common Schema), and `otlp` (OpenTelemetry logs). **Off by default** (an outbound
connection — sovereignty / no-phone-home). Audit
forwarding resumes from a **durable per-tenant cursor** — a saved bookmark in the
audit stream, so a restart or SIEM outage picks up exactly where delivery
stopped — and delivery **retries
without dropping** under a SIEM outage. Exported audit events are **PII/secret
redacted** (built-in denylist + `PROBECTL_SIEM_REDACT_KEYS`).

### On-call + ITSM integration

ITSM (IT service management) tooling is where operations work is tracked —
ticketing systems like ServiceNow and Jira; on-call platforms like PagerDuty and
Opsgenie are what wake the right human. This feature mirrors incidents into that
tooling: page on-call, post
to chat (Slack/Teams), and open + **bidirectionally sync** tickets (ServiceNow/Jira)
— resolve it there and probectl hears about it, resolve it here and the ticket
closes. probectl is the forwarder, not the system of record — it never auto-blocks
anything.
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

### Topology graph + what-if

The topology graph is the live map probectl assembles from everything it
observes — nodes (hosts, services, devices, prefixes) and the edges between
them — and *what-if* is simulation over that map: "if this link or node
disappeared, what would be cut off?".

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_TOPOLOGY_ENGINE` | `indexed` | graph engine: `indexed` (adjacency-indexed, for large/extra-large graphs) or `memory` (the simpler reference implementation). Both sit behind the same query API. Any value other than `memory` selects the indexed engine (the key is not validated as an enum) |

The graph feeds from eBPF/BGP/device streams + path discoveries; served at
`GET /v1/topology` with what-if simulation at `POST /v1/topology/whatif`.
See `docs/topology.md`.

### FinOps / egress cost

Cloud providers bill for **egress** — bytes leaving a zone, region, or cloud —
and those line items are notoriously hard to attribute. This engine prices the
flow volume probectl *already observes* (bytes × the provider's public list
rates), entirely locally: it never calls a billing API, so the sovereignty
posture holds and the numbers are explicitly estimates with stated provenance.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_COST_ENABLED`     | `true` | cost engine over the local flow stream (volume × public pricing; no billing-API calls) |
| `PROBECTL_COST_ZONES`       | (none) | CIDR→zone rules, e.g. `10.0.1.0/24=us-east-1a,…` (locality classification) |
| `PROBECTL_COST_SERVICES`    | (none) | CIDR→`service:team` attribution rules (showback) |
| `PROBECTL_COST_BUDGETS`     | (none) | monthly USD budgets, e.g. `team:payments=500` (breach = one cost-plane signal per month) |
| `PROBECTL_COST_PRICES_FILE` | (none) | JSON price-table override; embedded public list rates otherwise (provenance + as-of surfaced) |
| `PROBECTL_COST_PRICED`      | `true` | `false` = volume-only mode (bytes attributed, dollars never invented) |

Summary at `GET /v1/cost/summary` and the Cost page; deep dashboards are federated
to Grafana (see *Ecosystem integrations* above). See `docs/finops.md`.

### SLO engine

An **SLO** (service-level objective) is a reliability target — "99.9% of probes
to this service succeed over 30 days"; the **SLI** is the measured indicator
behind it, and the **error budget** is the failure allowance the target leaves
(0.1% here): spend it slowly and you're fine, burn it fast and you get paged
*before* the month is lost. OpenSLO is the vendor-neutral YAML standard for
declaring these.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_SLO_ENABLED` | `true` | OpenSLO SLI/SLO engine over the synthetic-result stream (error budgets + multi-window burn-rate signals) |
| `PROBECTL_SLO_DIR`     | (none) | directory of OpenSLO v1 YAML definitions (strictly validated; malformed/duplicate definitions fail startup) |

Statuses at `GET /v1/slos`, OpenSLO export at `GET /v1/slos/openslo`, and the
SLOs page. See `docs/slo.md`.

### Compliance / segmentation validation

**Segmentation** is the declared rule set of who may talk to whom on your
network ("only the app tier may reach the database tier"). Firewalls *enforce*
such rules; this validator *checks* them against the traffic probectl actually
observed, producing audit-grade evidence that the declared boundaries hold — or
a verdict naming the flow that crossed one. It never blocks anything.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_COMPLIANCE_ENABLED`    | `true` | segmentation validator over observed flow/eBPF traffic (validation only — never enforcement) |
| `PROBECTL_COMPLIANCE_POLICY_DIR` | (none) | segmentation policy YAML directory (strictly validated; malformed files fail startup) |

Verdicts at `GET /v1/compliance`, hash-chained audit evidence at
`GET /v1/compliance/evidence`, and the Compliance page. See
`docs/compliance.md`.

### Collective internet-outage view

"Is it us, or is it the internet?" This view answers that: a local engine
detects outages from your own vantage points (many tests failing toward the
same provider at once), and — only if you opt in — correlates them with public
internet-outage feeds (IODA, Cloudflare Radar) reporting trouble in the same
networks or countries.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_OUTAGE_ENABLED`       | `true`  | the local engine: vantage detection over your own results + correlation with external events (no outbound calls) |
| `PROBECTL_OUTAGE_FEEDS_ENABLED` | `false` | **opt-in** public outage feeds (IODA, Cloudflare Radar) — enabling makes outbound fetches (sovereignty / no-phone-home) |
| `PROBECTL_OUTAGE_FEEDS`         | (all)   | feeds to load: `ioda`, `cloudflare_radar` |
| `PROBECTL_OUTAGE_REFRESH`       | `10m`   | feed refresh cadence (last-good kept on failure) |
| `PROBECTL_OUTAGE_RETENTION`     | `48h`   | event window kept/queried |
| `PROBECTL_OUTAGE_RADAR_TOKEN`   | (none)  | Cloudflare API token the radar feed requires (a secret reference is accepted); the feed is omitted without it |

The collective view at `GET /v1/outages` (events + the caller-tenant's
affected tests + vantage detections + feed AUP/health + coverage notes) and
the Internet outages page. Scope resolution (IP→ASN/country) rides the open-data
enricher (`PROBECTL_FLOW_ENRICH_ASN`); without it the response reports the
degradation honestly. See `docs/outage.md`.

### RUM convergence

**RUM** (real-user monitoring) is timing data real browsers report from real
visits — page-load vitals sent home as small *beacons* — the complement to
synthetic probes: synthetics tell you a path is broken before users arrive; RUM
tells you what users actually experienced. *Convergence* is laying the two over
each other for the same service.

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

### Carbon / power observability

Moving bytes costs energy; energy has a carbon intensity. This engine multiplies
observed traffic volume by published energy coefficients and your grid's
intensity to produce **estimates** — always labeled as such, with the
methodology attached to every response — entirely locally.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_CARBON_ENABLED`    | `true` | coefficient-based energy/carbon ESTIMATES over the local flow stream (local-only; methodology served with every response) |
| `PROBECTL_CARBON_GRID_GCO2E` | `436`  | your grid's carbon intensity in gCO2e/kWh (defaults to the world average — set yours) |

Attribution reuses `PROBECTL_COST_ZONES` / `PROBECTL_COST_SERVICES`. The
estimate serves at `GET /v1/carbon` and folds into the Cost page. See
`docs/carbon.md`. The chaos injector and the large/extra-large scale gate are
test-harness tools — see `docs/chaos.md` and `docs/scale-gate.md`.

### Editions / license

A license file is a small signed document stating what was bought: the tier,
the feature list, the expiry, the customer. Ed25519 is the signature scheme —
verifying needs only the *public* key, which is baked into the binary, which is
precisely why verification works with the network cable unplugged.

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

### Provider / management plane (ee/)

The provider plane is the MSP operators' own console — tenant lifecycle, fleet
view, metering — deliberately a *separate privilege domain* from tenant users.
**Break-glass** (named for the fire-alarm cover) is its only path into tenant
data: an explicit, tenant-consented, time-bounded, separately-audited emergency
grant. Active only when the license grants `provider_plane`; otherwise
`/provider/*` is a plain 404 (hidden, not locked).

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

### Siloed / hybrid isolation (ee/)

Two ways to keep tenants apart: **pooled** — shared tables where every row is
tagged and filtered by `tenant_id` (one building, locked apartments) — and
**siloed** — physically separate stores per tenant (separate buildings);
**hybrid** mixes the two per tenant. Pooled stays the default and needs no
configuration. Siloed and
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

### White-label branding (ee/)

No configuration keys: branding activates with a license granting
`white_label` and is configured per tenant (or as the provider master) from
the provider console. The public `GET /branding` endpoint serves the resolved
brand pre-auth (Host-resolved for custom domains; the probectl default when
unlicensed); custom-domain login resolves the tenant from the serving host.
Custom domains need a certificate at the TLS-terminating ingress (or via
trustctl) — see `docs/white-label.md` for the token-override contract, the
no-bleed rules, and the email-template contract.

### Advanced data governance (`governance`, ee/)

Per-tenant data classification + redaction, composed with retention, residency,
and BYOK. No new config keys: the classification + redaction MECHANISM is core (the
`?redact=true` export toggle works anywhere,
masking PII with a partial strategy); the `governance` feature adds per-tenant
POLICY (stored in `tenant_governance`, migration 0033) set from the provider
plane (`GET/PUT /provider/v1/tenants/{id}/governance`). IPs are PII by default.
Full model: `docs/governance.md`. Redacted export: `GET /v1/lifecycle/export?redact=true`.

### Tenant lifecycle: export, retention, erasure (core)

Export + verifiable deletion are a compliance right — core in every edition.
`GET /v1/lifecycle/export` (permission `lifecycle.export`) streams the
portability bundle; `GET/PUT /v1/lifecycle/retention` + `POST
/v1/lifecycle/erase` (permission `lifecycle.erase`, slug-confirmed,
irreversible) manage retention and run the attested cross-store erasure — the
**attestation** is the signed receipt enumerating what was deleted from which
store, the document an auditor or a departing tenant actually gets to keep. The
provider console adds the operator-side erase trigger. See
`docs/runbooks/tenant-offboarding.md` for the full procedure and the
per-store verification table.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_BACKUP_RETENTION_NOTE` | (empty → a generic fallback statement) | your backup-TTL statement, included VERBATIM in every deletion attestation — be explicit about when snapshots expire. When unset, a generic placeholder sentence is recorded instead |
| `PROBECTL_BACKUP_RETENTION_DAYS` | `0` | concrete backup TTL in days. When `> 0`, the tenant-erasure attestation quantifies a bounded backup-coverage window (`backup_erasure_deadline` = erased_at + this many days); `0` = note-only |
| `PROBECTL_ENVELOPE_KEY` / `PROBECTL_ENVELOPE_KEY_FILE` | (none) | the at-rest KEK (see the control-plane table) — also used by `probectl-control backup-seal`/`backup-open` to encrypt/restore backups. The chart's Postgres backup CronJob mounts it to seal dumps in the pipeline |

The daily retention sweeper enforces per-tenant `flow_retention_days`
(tighter than the deployment TTL). Prometheus-mode TSDB series deletion is a
documented manual step (the attestation says so honestly).

### Per-tenant metering & quotas (ee/)

No configuration keys: metering activates with a license granting `metering`
(provider/MSP tier). Counters flush every minute; gauge snapshots run every
15 minutes; usage and quotas live in Postgres (migration 0026). The usage
API, the CSV/JSONL billing-export feed, per-tenant quotas (creation-gating
only — telemetry is never quota-dropped), and the console showback card are
documented in `docs/metering.md`.

### Per-tenant key isolation / BYOK (ee/)

BYOK is *bring your own key*: a tenant supplies (and can revoke) the encryption
key its data is sealed under, instead of trusting the operator's. Unlocked by
the `byok` feature (Enterprise). No new config keys: the keyring
wraps managed tenant KEKs under **`PROBECTL_ENVELOPE_KEY`** (required when
byok is licensed — startup fails loudly without it) and resolves BYOK
references through the secret backends. Surfaces: `GET/POST
/v1/security/keys[...]` (permission `security.keys`) + the Admin →
Encryption keys card. The full model — sealing formats, rotation, the BYOK
lockout warning, crypto-offboarding — is in `docs/byok.md`.

### Tenant fairness (core)

These are the per-tenant bounds that protect a *pooled* (shared) deployment, so
one noisy tenant can't starve the others — and they are core in every edition. The
ingest-rate bounds are **on by default** with conservative numbers; you opt *out*
of a bound by setting it to an explicit **`0`** (unlimited). Unset keeps the
default, and a negative value is a startup error — config validation rejects it.
The two query bounds already default to `0`, i.e. unlimited until you set them.
Per-tenant overrides are set from the provider console into `tenant_fairness`.
Full model: `docs/fairness.md`.

These are token-bucket rate limits: the steady rate is the value below, and the
bucket can hold a burst of `rate × PROBECTL_FAIRNESS_BURST_SECONDS`. Telemetry over
a bound is admission-controlled (shed + counted), never silently corrupted.

| Key | Default | Description |
| --- | --- | --- |
| `PROBECTL_FAIRNESS_RESULTS_PER_SEC` | `1000` | per-tenant result-message admission rate. Explicit `0` = unlimited |
| `PROBECTL_FAIRNESS_FLOW_EVENTS_PER_SEC` | `10000` | per-tenant flow-record admission rate. Explicit `0` = unlimited |
| `PROBECTL_FAIRNESS_INGEST_BYTES_PER_SEC` | `2097152` | per-tenant ingest byte rate (2 MiB/s). Explicit `0` = unlimited |
| `PROBECTL_FAIRNESS_DEVICE_METRICS_PER_SEC` | `2000` | per-tenant SNMP/gNMI device-sample admission rate. Explicit `0` = unlimited |
| `PROBECTL_FAIRNESS_OTLP_SERIES_PER_SEC` | `5000` | per-tenant OTLP metric/trace/log series admission rate (SCALE-003). Explicit `0` = unlimited |
| `PROBECTL_FAIRNESS_BURST_SECONDS` | `10` | burst window: bucket capacity = rate × this. `0` falls back to 10 — an enforced bucket always has a burst |
| `PROBECTL_FAIRNESS_QUERY_CONCURRENCY` | `0` (unlimited) | per-tenant in-flight query cap (HTTP 429 over it) |
| `PROBECTL_FAIRNESS_QUERIES_PER_MIN` | `0` (unlimited) | per-tenant query budget per minute (HTTP 429 over it) |

### Multi-region / active-active HA (core)

Inert unless `PROBECTL_REGION` is set (single-region deployments need none of
these). The control plane stays stateless and active in every region; the
split-brain fence pauses API writes during a failover while reads + telemetry
keep flowing — **split-brain** being the failure where two regions each believe
*they* hold the writable database and diverge, which a write-pause makes
impossible. Two vocabulary keys below: **RPO** (recovery point objective) is how
much recent data a disaster may cost you, **RTO** (recovery time objective) how
long recovery may take — both recorded here as declared targets for humans to
sign off, not values the software can promise. Full model + the failover
runbook: `docs/multi-region.md`,
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

### Supportability (core)

Deep health + a secret-stripped support bundle for triage (CORE; the support
org/SLA is contract). No new config keys; `diagnostics.read` (migration 0034,
admin-seeded) gates `GET /v1/diagnostics` and `GET /v1/diagnostics/bundle`. An
offline bundle: `probectl-control support-bundle [-o file]`. Self-monitoring
series `probectl_self_*` + `probectl_build_info` feed
`deploy/grafana/dashboards/probectl-self.json`. The bundle NEVER contains
secrets/credentials/PII (allowlist config + anonymized topology + a final
scrub). Full model: `docs/supportability.md`.

### Guarded agentic remediation (`remediation`, ee/)

The assistant PROPOSES remediations; a human APPROVES; probectl NEVER executes —
there is no executor in the codebase (remediation is human-gated by design). Approve is a recorded,
audited, blast-radius-limited, human-only sign-off that an operator carries out
in their own change process; ingested data (e.g. a prompt-injection routed
through the `propose_remediation` MCP tool) can at most create a `proposed`
proposal a human must approve via the authenticated UI. The feature is hidden
(404) when the `remediation` Enterprise feature is unlicensed.

| Variable | Default | Notes |
|---|---|---|
| `PROBECTL_REMEDIATION_APPROVALS_ENABLED` | `false` | advisory-only master switch — until an operator turns this on, Approve is unavailable and proposals are review-only |
| `PROBECTL_REMEDIATION_MAX_BLAST_RADIUS` | `50` | a proposal whose simulated (topology what-if) blast radius exceeds this cannot be approved; an unknown radius (no topology available) is also blocked — fail closed |

Permissions `remediation.propose` and `remediation.approve` (migration 0035,
admin-seeded) gate the `/v1/remediation/*` routes; the dry-run blast radius is a
read-only topology simulation. Full policy + architecture: `docs/remediation.md`.

### NDR-lite detection

NDR (network detection and response) spots attacker *behavior* in traffic
patterns rather than matching known-bad lists. The detectors here: **DGA** —
the algorithmically-generated throwaway domains malware uses to find its
command server; **exfiltration** — data leaving in unusual volume or via covert
channels (e.g. DNS); **beaconing** — the metronome-regular heartbeat of an
implant calling home; plus unusual egress and **lateral movement** (an internal
host suddenly exploring its neighbors). It runs entirely over locally-collected
streams — no outbound calls — and, per the guardrails, only ever *signals*.

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_NDR_ENABLED`   | `true` | behavioral detection engine (DGA/exfil/beaconing/egress/lateral) over local DNS/flow/eBPF streams; signals only — never blocks |
| `PROBECTL_NDR_RULES_DIR` | (none) | detection-as-code overlay directory; rules merge by id over the embedded defaults (a malformed dir fails startup) |

Detections are confidence-scored threat-plane signals (`ndr.*`) exported to
incidents, the Security triage surface, and the SIEM (see *SIEM export* above).
See `docs/ndr.md` for the detector and tuning reference.

### Secrets integration

This is the feature that lets you keep raw passwords out of your config entirely.
Anywhere this document asks for a credential, you can instead hand it a **pointer**
to where the real secret lives — a Vault path, a CyberArk query, an AWS/Azure/GCP
secret id — and the control plane fetches it at boot (or per poll, for device
creds). The settings below just tell probectl how to reach each backend; the
references themselves go in the credential keys documented throughout this page.

Any credential value in this document may be a **secret reference** instead of
the literal material — `env:NAME`, `vault:<mount>/<path>#<field>`,
`cyberark:<query>`, `aws:<id>[#<json-field>]`, `azure:<vault>/<name>`,
`gcp:<project>/<secret>[/<version>]`, or `literal:<value>` as the escape
hatch. The control plane resolves `PROBECTL_OIDC_CLIENT_SECRET`,
`PROBECTL_CMDB_SECRET`, `PROBECTL_AI_MODEL_TOKEN`, `PROBECTL_SIEM_TOKEN`,
`PROBECTL_BUS_SASL_PASSWORD`, `PROBECTL_OUTAGE_RADAR_TOKEN`, and the secret
parts of `PROBECTL_CHANGE_WEBHOOKS` / `PROBECTL_NOTIFY_CONNECTORS` /
`PROBECTL_NOTIFY_INBOUND` at startup (fail closed); the device agent resolves
every `PROBECTL_DEVICE_CRED_<NAME>_*` value per poll cycle. Resolved values are
cached only encrypted, for a short lease (5 m). See `docs/secrets.md`.

Backend access settings (environment only; all over verified TLS). Two Vault
terms used below: **AppRole** is Vault's login method for machines — a role id +
secret id pair playing username/password for a service — and a **lease** is the
expiry Vault stamps on what it issues, which probectl renews before it runs out:

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
TLS/HTTPS-by-default — TLS on every listener.

| Service      | Compose name | Host port(s)        | Purpose                                   | Dev credentials                 |
| ------------ | ------------ | ------------------- | ----------------------------------------- | ------------------------------- |
| PostgreSQL   | `postgres`   | `5432`              | Durable state, tenants, RBAC, audit, SLOs | user/pass/db = `probectl`         |
| Kafka        | `kafka`      | `9092`              | Result/event bus (KRaft, no ZooKeeper)    | none (PLAINTEXT)                |
| ClickHouse   | `clickhouse` | `8123` (HTTP), `9000` (native) | High-cardinality events/flows  | user/pass/db = `probectl`         |
| Prometheus   | `prometheus` | `9090`              | Metrics TSDB (remote-write enabled)       | none                            |

Kafka listeners: host clients use `localhost:9092`; in-network containers use
`kafka:19092`; the KRaft controller uses `9093` (internal — KRaft is Kafka's
built-in consensus mode, so there is no separate ZooKeeper to run). Prometheus runs with
`--web.enable-remote-write-receiver` so the result pipeline can remote-write into
it.

These names and ports are a **contract** — the integration test harness depends on
them, so don't rename them casually.

## Tear-down

`make compose-down` removes the containers **and volumes** (`pgdata`, `chdata`,
`promdata`).
