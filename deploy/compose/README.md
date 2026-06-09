# deploy/compose/

Docker Compose stacks for running probectl — one production-shaped all-in-one
deploy, and one local dependency stack for developing the control plane from
source.

| File | Purpose |
| ---- | ------- |
| `probectl.yml` | **Shipped all-in-one deploy** — control plane (HTTPS-only) + Postgres, with a one-shot self-signed-cert generator |
| `.env.example` | template for the `.env` `probectl.yml` reads (Postgres password, envelope key, TLS hosts, OIDC) |
| `dev.yml` | Local dev **dependency** stack: Postgres, Kafka, ClickHouse, Prometheus |
| `prometheus.yml` | Prometheus config used by the `dev.yml` stack |
| `clickhouse-backups.xml` | ClickHouse server config that whitelists `/backups` as a server-side `BACKUP`/`RESTORE` path (used by `dev.yml`) |
| `dr-drill.yml` | overlay that adds a streaming Postgres replica so `scripts/failover_drill.sh` can time a real promote-the-standby failover |

## Shipped all-in-one (`probectl.yml`) — HTTPS-by-default

Runs the control plane behind TLS with a Postgres backing store. The API is
exposed **only over HTTPS** (port 8443); there is no plaintext listener. A
self-signed certificate is generated on first boot (`probectl-control gen-cert`)
for an immediate quickstart — production replaces it with a CA-issued cert.

```sh
cp deploy/compose/.env.example deploy/compose/.env     # then edit (envelope key, etc.)
docker compose -f deploy/compose/probectl.yml up -d
curl --cacert ./certs/ca.crt https://localhost:8443/readyz
```

See [`docs/install.md`](../../docs/install.md) for the full guide (including
extracting the generated `ca.crt` and switching to real SSO).

## Local dev dependency stack (`dev.yml`)

```sh
make compose-up      # docker compose -f deploy/compose/dev.yml up -d --wait
make compose-down    # tear it down
```

Service names, ports, and credentials are documented in
[`docs/configuration.md`](../../docs/configuration.md).

> `dev.yml` is a **local, non-production** dependency stack (plaintext, dev
> creds). The shipped deploys (`probectl.yml` + Helm) are **HTTPS-by-default** —
> TLS, HSTS, no plaintext API exposure (CLAUDE.md §7 guardrail 12).
