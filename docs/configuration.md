# Configuration

This documents netctl's configuration conventions and the local dev-stack
service contract. Concrete config **keys** are added by the sprints that
introduce them (the control plane in S1, the agent in S5, …); every new key is
documented here in the same PR (CLAUDE.md §6, §8).

## Conventions

- **Control plane:** configured via environment variables with the `NETCTL_`
  prefix (e.g. `NETCTL_HTTP_ADDR`). Keys land in S1.
- **Agent:** configured via a YAML file or environment variables. Schema lands
  in S5.
- **Secrets** are never hardcoded, logged, or placed in URLs/query strings;
  sensitive values at rest use envelope encryption (S3). See CLAUDE.md §7.

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
