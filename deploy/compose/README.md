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

| File                             | Purpose                                                                                                                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `probectl.yml`                   | **Shipped all-in-one deploy** — control plane (HTTPS-only) + Postgres, with a one-shot self-signed-cert generator                                                                  |
| `.env.example`                   | template for the `.env` `probectl.yml` reads (Postgres password, envelope key, session-HMAC key, TLS hosts, OIDC)                                                                  |
| `dex-demo.yml` + `dex-demo.yaml` | **Local demo-only OIDC overlay** — digest-pinned Dex, HTTPS-only, one generated-password user; never use as a production directory                                                 |
| `eval.yml`                       | **Evaluation stack (local only, never production)** — control plane + Postgres + Kafka + an eBPF agent replaying SAMPLE flows, so one command shows real data end-to-end           |
| `eval-synthetic.yml`             | overlay on `eval.yml` that adds the agent CA + gRPC listener + a self-enrolling canary (synthetic probes)                                                                          |
| `eval-agent.yml`                 | the canary config the `eval-synthetic.yml` overlay mounts (one inline HTTP probe)                                                                                                  |
| `eval-browser-agent.yml`         | rendered-browser agent config used by the opt-in `browser-synthetic` profile (Playwright + explicit `browser_driver: browser`)                                                     |
| `dev.yml`                        | Local dev **dependency** stack: Postgres, Kafka, ClickHouse, Prometheus — no control plane (you run that from source)                                                              |
| `prometheus.yml`                 | Prometheus config used by the `dev.yml` stack                                                                                                                                      |
| `clickhouse-backups.xml`         | ClickHouse server config that whitelists `/backups` as a server-side `BACKUP`/`RESTORE` path (used by `dev.yml`)                                                                   |
| `dr-drill.yml`                   | overlay that adds a streaming Postgres replica (a standby continuously replaying the primary's writes) so `scripts/failover_drill.sh` can time a real promote-the-standby failover |

## Shipped all-in-one (`probectl.yml`) — HTTPS-by-default

Runs the control plane behind TLS with a Postgres backing store. The API is
exposed **only over HTTPS** (port 8443); there is no plaintext listener,
deliberately — the shipped deploys never expose an unencrypted API. A
**self-signed** certificate (one the server signs for itself: traffic is
encrypted, but clients must be told to trust it — which is what `--cacert
ca.crt` does below) is generated on first boot (`probectl-control gen-cert`)
for an immediate quickstart — production replaces it with a CA-issued cert.

```sh
cp deploy/compose/.env.example deploy/compose/.env     # set POSTGRES_PASSWORD + envelope/session-HMAC keys
# Set PROBECTL_IMAGE in .env to a digest-pinned release image, for example:
# ghcr.io/imfeelingtheagi/probectl-control:v0.6.0@sha256:<release-digest>
# If GHCR returns 401, run `docker login ghcr.io` with a token that has
# read:packages, or point PROBECTL_IMAGE at an internal mirror. Tag-only local
# or mirror refs require PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable.
# The preflight fails before Compose starts and prints exact repair commands.
bash scripts/compose_image_preflight.sh
make compose-prod-up
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt
curl --cacert ./ca.crt https://localhost:8443/readyz
```

See [`docs/install.md`](../../docs/install.md) for the full guide (env keys,
real certificates, switching to SSO). This stack runs **no producer**: once
`/readyz` is green, deploy an agent to see data
([`docs/deploying-agents.md`](../../docs/deploying-agents.md)).

### Local demo login (Dex overlay)

When a laptop demo needs an interactive login but has no real IdP, layer the
demo-only Dex service over the production-shaped stack. Dex shares the control
container's network namespace and quickstart certificate: the browser and
control plane therefore use the same verified issuer,
`https://localhost:5556/dex`, with no plaintext listener and no skipped TLS
validation. Its image is digest-pinned and its local password/client secret are
runtime inputs, never repository defaults.

```sh
export DEX_CLIENT_SECRET="$(openssl rand -hex 32)"
export DEX_DEMO_PASSWORD='<generate a demo-only password>'
export DEX_DEMO_PASSWORD_HASH="$(htpasswd -bnBC 12 demo "$DEX_DEMO_PASSWORD" | cut -d: -f2)"

docker compose -f deploy/compose/probectl.yml \
  -f deploy/compose/dex-demo.yml up -d dex control
```

Open `https://localhost:8443/ui/dashboards?demo=1`, then log in as
`demo@probectl.local` with the generated password. The account is intentionally
local/demo-only. Every tenant menu renders a populated, route-specific sample
surface, the `demo=1` marker follows navigation, and the click-through workspace
remains isolated from live tenant API calls. Replace this overlay with the
deployment's real OIDC/SCIM configuration for any production use.

## Evaluation stack (`eval.yml` + overlays) — local only, never production

The fastest path from nothing to **visible data**: brings up Postgres + Kafka +
the control plane **plus a producer** — an eBPF agent in fixture mode, replaying
a recorded, clearly-labelled SAMPLE flow file (no kernel needed; works on
macOS/Windows/Linux). The control plane folds those flows into the
`/v1/topology` service map — your first data.

```sh
docker compose -f deploy/compose/eval.yml up --build -d
# The viewer waits for control-plane readiness and sample topology data:
docker compose -f deploy/compose/eval.yml --profile tools run --rm --no-deps viewer
```

It is fenced as evaluation-only on purpose: the API runs **dev auth** (every
request is an unauthenticated admin), so it **binds loopback inside the
container and publishes no port** — loopback is `127.0.0.1`, the interface
whose traffic never leaves its host (here, never even leaves the container), so
the no-auth API is physically unreachable from your network; you read it
through the in-namespace `viewer` helper. The bus is plaintext and the cert
self-signed. The release image refuses dev auth outright, so this stack builds
its own local dev-auth image. Layer `eval-synthetic.yml` on top to add an
enrolled canary running synthetic probes. Its `synthetic` profile runs the
portable HTTP transaction driver. To exercise real Chromium instead, mint a
fresh join token and start the separate combined agent/worker image:

```sh
PROBECTL_JOIN_TOKEN=pjt_xxx docker compose -f deploy/compose/eval.yml \
  -f deploy/compose/eval-synthetic.yml --profile browser-synthetic \
  up --build -d browser-canary
```

That image opens no browser-worker listener; the Go agent communicates with its
Playwright child over stdin/stdout and sends results to the control plane over
mTLS. The full walkthrough is
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
