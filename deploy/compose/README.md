# deploy/compose/

Docker Compose stacks for running probectl. Three distinct shapes live here —
one **production-shaped** all-in-one deploy, one **evaluation** stack for seeing
first data on a laptop, and one **dev dependency** stack for developing the
control plane from source. Pick by what you are trying to do; they are not
interchangeable: think the road car (`probectl.yml`), a fenced-off test track
with a crash dummy (`eval.yml` — sample data, never public roads), and the
garage with the engine out (`dev.yml` — backing services, no control plane).

One rule applies to all of them: the control plane is a **consumer** — it stores
and serves, but observes nothing on its own. A stack with no producer (agent /
collector) attached answers `/readyz` and shows empty dashboards. Only the eval
stack bundles a producer; for the others, attach one next
([`docs/deploying-agents.md`](../../docs/deploying-agents.md)).

| File | Purpose |
| ---- | ------- |
| `probectl.yml` | **Shipped all-in-one deploy** — control plane (HTTPS-only) + Postgres, with a one-shot self-signed-cert generator |
| `.env.example` | template for the `.env` `probectl.yml` reads (Postgres password, envelope key, TLS hosts, OIDC) |
| `eval.yml` | **Evaluation stack (local only, never production)** — control plane + Postgres + Kafka + an eBPF agent replaying SAMPLE flows, so one command shows real data end-to-end |
| `eval-synthetic.yml` | overlay on `eval.yml` that adds the agent CA + gRPC listener + a self-enrolling canary (synthetic probes) |
| `eval-agent.yml` | the canary config the `eval-synthetic.yml` overlay mounts (one inline HTTP probe) |
| `dev.yml` | Local dev **dependency** stack: Postgres, Kafka, ClickHouse, Prometheus — no control plane (you run that from source) |
| `prometheus.yml` | Prometheus config used by the `dev.yml` stack |
| `clickhouse-backups.xml` | ClickHouse server config that whitelists `/backups` as a server-side `BACKUP`/`RESTORE` path (used by `dev.yml`) |
| `dr-drill.yml` | overlay that adds a streaming Postgres replica (a standby continuously replaying the primary's writes) so `scripts/failover_drill.sh` can time a real promote-the-standby failover |

## Shipped all-in-one (`probectl.yml`) — HTTPS-by-default

Runs the control plane behind TLS with a Postgres backing store. The API is
exposed **only over HTTPS** (port 8443); there is no plaintext listener,
deliberately — the shipped deploys never expose an unencrypted API. A
**self-signed** certificate (one the server signs for itself: traffic is
encrypted, but clients must be told to trust it — which is what `--cacert
ca.crt` does below) is generated on first boot (`probectl-control gen-cert`)
for an immediate quickstart — production replaces it with a CA-issued cert.

```sh
cp deploy/compose/.env.example deploy/compose/.env     # set POSTGRES_PASSWORD (required) + envelope key
# If GHCR returns 401 for the pinned release image, run `docker login ghcr.io`
# with a token that has read:packages, or set PROBECTL_IMAGE in .env to a
# locally built / mirrored image.
docker compose -f deploy/compose/probectl.yml up -d
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt
curl --cacert ./ca.crt https://localhost:8443/readyz
```

See [`docs/install.md`](../../docs/install.md) for the full guide (env keys,
real certificates, switching to SSO). This stack runs **no producer**: once
`/readyz` is green, deploy an agent to see data
([`docs/deploying-agents.md`](../../docs/deploying-agents.md)).

## Evaluation stack (`eval.yml` + overlays) — local only, never production

The fastest path from nothing to **visible data**: brings up Postgres + Kafka +
the control plane **plus a producer** — an eBPF agent in fixture mode, replaying
a recorded, clearly-labelled SAMPLE flow file (no kernel needed; works on
macOS/Windows/Linux). The control plane folds those flows into the
`/v1/topology` service map — your first data.

```sh
docker compose -f deploy/compose/eval.yml up --build -d
# wait ~20s for migrate + start, then read first data:
docker compose -f deploy/compose/eval.yml --profile tools run --rm viewer
```

It is fenced as evaluation-only on purpose: the API runs **dev auth** (every
request is an unauthenticated admin), so it **binds loopback inside the
container and publishes no port** — loopback is `127.0.0.1`, the interface
whose traffic never leaves its host (here, never even leaves the container), so
the no-auth API is physically unreachable from your network; you read it
through the in-namespace `viewer` helper. The bus is plaintext and the cert
self-signed. The release image refuses dev auth outright, so this stack builds
its own local dev-auth image. Layer `eval-synthetic.yml` on top to add an
enrolled canary running synthetic probes. The full walkthrough is
[`docs/getting-started.md`](../../docs/getting-started.md); for anything real,
use `probectl.yml`.

## Local dev dependency stack (`dev.yml`)

Backing services only — Postgres, Kafka, ClickHouse, Prometheus — for running
`probectl-control` from source against them:

```sh
make compose-up      # docker compose -f deploy/compose/dev.yml up -d --wait
make compose-down    # tear it down
```

Service names, ports, and credentials are documented in
[`docs/configuration.md`](../../docs/configuration.md).

> `dev.yml` is a **local, non-production** dependency stack (plaintext, dev
> creds). The shipped deploys (`probectl.yml` + Helm) are **HTTPS-by-default** —
> TLS, HSTS, no plaintext API exposure.
