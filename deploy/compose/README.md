# deploy/compose/

Docker Compose stacks.

| File          | Purpose                                                                       |
| ------------- | ----------------------------------------------------------------------------- |
| `probectl.yml`  | **Shipped all-in-one deploy** — control plane (HTTPS-only) + Postgres         |
| `dev.yml`     | Local dev *dependency* stack: Postgres, Kafka, ClickHouse, Prometheus         |

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
