# deploy/compose/

Docker Compose stacks for local development and testing.

| File      | Purpose                                                             |
| --------- | ------------------------------------------------------------------- |
| `dev.yml` | Local dev dependency stack: Postgres, Kafka, ClickHouse, Prometheus |

Bring the dev stack up (and wait for health) with:

```sh
make compose-up      # docker compose -f deploy/compose/dev.yml up -d --wait
make compose-down    # tear it down
```

Service names, ports, and credentials are documented in
[`docs/configuration.md`](../../docs/configuration.md).

> The shipped production deploys (compose all-in-one + Helm) are **HTTPS-by-default**
> — TLS-terminating ingress, HSTS, no plaintext API exposure (CLAUDE.md §7
> guardrail 12). `dev.yml` is a **local, non-production** dependency stack only.
