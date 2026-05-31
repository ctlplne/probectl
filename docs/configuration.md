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
a FIPS 140-3 module can be swapped in (F32). The **agent transport** (S4) uses
mTLS with a tenant-bound SPIFFE identity (`spiffe://netctl/tenant/<t>/agent/<a>`);
`internal/crypto` provides the CA/cert layout and verification. At-rest secrets
use the envelope helper (a per-record data key wrapped by a KMS/HSM-pluggable KEK;
the dev `StaticKeyProvider` reads `NETCTL_ENVELOPE_KEY`).

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
