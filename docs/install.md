# Installing probectl

## What you're installing, and the one rule that shapes it

probectl is a self-hosted control plane plus agents. This guide gets the
**control plane** running two ways: an all-in-one Docker Compose stack (fastest
path, good for a single host or evaluation) and a Kubernetes Helm chart
(production / multi-tenant — Helm is Kubernetes's package manager, and a chart
is the installable package of manifests it deploys).

The rule that shapes both: probectl is **HTTPS-by-default**. Every shipped deploy
serves the API over TLS (the encryption layer under `https://`), sends HSTS
(the response header telling browsers to never retry this host over plain
HTTP), and exposes **no plaintext listener at all**.
This is deliberate — a network-observability control plane handles tenant data,
so there is no "just turn off TLS for a sec" mode to trip over (see
[`hardening.md`](hardening.md) for the full transport posture). The practical consequence: every example below talks to `https://`,
and a plaintext request simply will not connect.

For configuration keys, see [`configuration.md`](configuration.md). For day-2
operation (audit, roles, SSO), see [`admin.md`](admin.md).

## Prerequisites

- A released image. The shipped compose stack pins
  `ghcr.io/imfeelingtheagi/probectl-control:v0.4.0` for both `certgen` and
  `control`. If that GHCR package is public in your environment, Docker pulls it
  anonymously. If GHCR returns `401 Unauthorized`, log in first with a token that
  has `read:packages`, or set `PROBECTL_IMAGE` in `deploy/compose/.env` to a
  locally built / mirrored / digest-pinned image. The compose preflight below
  checks this before the stack starts, so a private registry fails with exact
  repair commands instead of halfway through first boot:

  ```sh
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GITHUB_USER" --password-stdin
  # or:
  PROBECTL_IMAGE=registry.internal/probectl-control:v0.4.0
  # or build from this checkout:
  docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=probectl-control -t probectl-control:local .
  PROBECTL_IMAGE=probectl-control:local
  ```
- **Compose path:** Docker with Compose v2.
- **Helm path:** a Kubernetes cluster with an ingress controller (the cluster's
  HTTP front door, which routes outside traffic to in-cluster services — nginx
  in the examples) and a way to supply a TLS certificate (cert-manager — the
  in-cluster operator that obtains and renews certificates — or a pre-created
  secret).

## Option A — Docker Compose (all-in-one)

[`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml) runs the control
plane behind TLS with a bundled Postgres. On first boot a one-shot `certgen`
service generates a **self-signed certificate** (`probectl-control gen-cert`) so
you can start immediately; you swap in a real CA-issued cert for production.
Self-signed means the server vouches for itself rather than a certificate
authority (CA — a trusted issuer your clients already know): traffic is fully
encrypted either way, but your client must be *told* to trust this server —
which is exactly what step 3 (copy out `ca.crt`) and `--cacert` in step 4 do.

```sh
# 1. Configure.
cp deploy/compose/.env.example deploy/compose/.env
# Edit deploy/compose/.env:
#   - POSTGRES_PASSWORD      (required; the stack refuses to start empty)
#   - PROBECTL_ENVELOPE_KEY  (openssl rand -base64 32 — the at-rest encryption key)
#   - PROBECTL_SESSION_HMAC_KEY (openssl rand -hex 32 — the session-token pepper)
#   - PROBECTL_TLS_HOSTS     (the hostname(s)/IP(s) the self-signed cert is valid for)
# Auth defaults to "session" (real OIDC SSO, fail-closed) — set the PROBECTL_OIDC_*
# values. PROBECTL_AUTH_MODE=dev (no-auth, all-access) is NOT a runtime toggle on
# this shipped release image: the dev-auth code path only exists in a binary built
# with -tags devauth, so setting it here makes the control plane REFUSE TO START
# with a clear error (not a warning). For a no-IdP local evaluation, use the eval
# stack (deploy/compose/eval.yml) — see docs/getting-started.md — not this stack.

# 2. Preflight the image, then start.
#    This fails before Compose starts if the pinned image is private/unreachable,
#    and prints the exact docker login, mirror override, or local-build command.
bash scripts/compose_image_preflight.sh
make compose-prod-up

# Equivalent after the preflight passes:
# docker compose --env-file deploy/compose/.env -f deploy/compose/probectl.yml up -d

# 3. Grab the generated CA so your client can trust the self-signed cert.
#    (The certs live in a named Docker volume, so copy ca.crt out of the container.)
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt

# 4. Verify — over HTTPS, on port 8443.
curl --cacert ./ca.crt https://localhost:8443/readyz
curl --cacert ./ca.crt https://localhost:8443/.well-known/security.txt
```

A note on the envelope key: this is probectl's **KEK** (key-encryption key) for
**envelope encryption** — each stored secret is sealed with its own data key,
and those data keys are sealed with this one. Think of a hotel key cabinet: the
KEK is not the key to every room, it is the one key that opens the cabinet
holding them — which is why losing it makes every sealed value unreadable, and
why it must be backed up like key material rather than like configuration. If
you leave `PROBECTL_ENVELOPE_KEY` empty, the
control plane generates one on first boot and persists it on the `controldata`
volume (mode 0600) — back that volume up like key material. Supplying your own key
(from a KMS or secret manager) is recommended for production and always wins.
Either way, at-rest encryption stays on; if no key resolves, the control plane
**fails closed** rather than writing plaintext.

There is **no** plaintext port: `http://localhost:8443` will not connect. To use a
real (CA-issued) certificate, place `tls.crt` / `tls.key` in the `certs` volume
(or mount your own) and remove the `certgen` service.

Tear down with `docker compose -f deploy/compose/probectl.yml down` (add `-v` to
also drop the database and certs).

## Option B — Kubernetes (Helm)

The chart in [`deploy/helm/probectl`](../deploy/helm/probectl) terminates TLS at
the ingress, force-redirects HTTP → HTTPS, and emits HSTS; the Service is
`ClusterIP` (a cluster-internal-only address), so nothing plaintext is
reachable from outside the cluster.
Migrations run as an init container (a one-shot container Kubernetes runs to
completion before the main one starts — so the schema is always in place before
the server boots), and the pod runs non-root with a read-only
root filesystem.

```sh
helm install probectl deploy/helm/probectl \
  --namespace probectl --create-namespace \
  --set ingress.host=probectl.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set database.url='postgres://probectl:...@db:5432/probectl?sslmode=require' \
  --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set control.authMode=session \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=probectl \
  --set oidc.clientSecret=REPLACE \
  --set oidc.redirectUrl=https://probectl.example.com/auth/callback
```

Provide the TLS secret via cert-manager (add the issuer to `ingress.annotations`)
or pre-create the secret named by `ingress.tlsSecretName`. For the MSP / provider
reference sizing, add `-f deploy/helm/probectl/values-multitenant.yaml`. Then
verify:

```sh
curl https://probectl.example.com/readyz
```

See [`../deploy/helm/README.md`](../deploy/helm/README.md) for every value and
sizing profile (small / medium / large / multitenant / multi-region / strict).

## Deploy your first agent / see data

Your control plane is up — but it is a **consumer**, and a consumer with nothing
feeding it stores nothing. `/readyz` is green and every dashboard is empty,
because the things that actually watch the network — synthetic probes, the eBPF
host agent, flow collectors — are separate **producers** you deploy next. No
producers, no data; that is expected, not a bug.

Don't follow a one-off recipe here — the canonical journey is already written:

- **See data in one command (no Go toolchain, any OS):** the **evaluation stack**
  [`deploy/compose/eval.yml`](../deploy/compose/eval.yml) brings up a control plane
  plus a sample producer so you can watch real data flow end to end:

  ```sh
  docker compose -f deploy/compose/eval.yml up --build -d
  # wait ~20s for the control plane to migrate + start, then read first data:
  docker compose -f deploy/compose/eval.yml --profile tools run --rm viewer
  ```

  The `viewer` prints the `/v1/topology` service map built from the sample flows —
  proof the agent → bus → consumer → API loop works. It is **local-evaluation
  only** (no-auth, loopback-bound, plaintext bus); the full walkthrough — including
  attaching a real canary and combining planes into one correlated incident — is in
  [`getting-started.md`](getting-started.md).
- **Attach producers to *this* stack:** [`deploying-agents.md`](deploying-agents.md)
  is the catalog of every producer (synthetic canary, eBPF, flow, device telemetry)
  and which channel each uses — gRPC/mTLS straight to the control plane, or the
  message bus.

## First-run checklist

1. **Authentication.** Outside evaluation, run with `authMode=session` and a real
   OIDC IdP (OIDC — OpenID Connect, the standard web-login protocol; the IdP is
   your identity provider — Okta, Entra ID, Keycloak, …). A brand-new SSO user
   is provisioned with **no roles** — an admin must
   grant access (see [`admin.md`](admin.md)). This is intentional: access is
   default-deny, not default-allow.
2. **Envelope key.** Set `PROBECTL_ENVELOPE_KEY` to a real 32-byte base64 key
   (KEK) and keep it safe; secrets at rest are sealed with it. probectl encrypts
   the values *it* manages — encrypting the bulk telemetry volumes (Postgres,
   ClickHouse, object store) at rest is the operator's job (dm-crypt/LUKS, ZFS, or
   encrypted cloud volumes).
3. **Session HMAC key.** Set `PROBECTL_SESSION_HMAC_KEY` to a real 32-byte hex
   key (`openssl rand -hex 32`) and keep it safe. probectl stores only HMACed
   session-token digests, so a database snapshot cannot verify token guesses
   without this app secret.
4. **Disclosure contact.** Set `PROBECTL_SECURITY_CONTACT` so
   `/.well-known/security.txt` advertises your security mailbox (RFC 9116).
5. **Database TLS.** Point `PROBECTL_DATABASE_URL` at a Postgres reachable over
   TLS (`sslmode=require` or stricter) in production.
6. **Audit.** Confirm the audit trail is recording and intact:
   `GET /v1/audit` and `GET /v1/audit/verify` (admin / `audit.read`). The audit
   log is tamper-evident, so `verify` proves the chain hasn't been altered.
