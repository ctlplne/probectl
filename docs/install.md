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

- A released image. Production Compose has no mutable image default. Set
  `PROBECTL_IMAGE` in `deploy/compose/.env` to a
  digest-pinned control-plane image such as
  `ghcr.io/ctlplne/probectl-control:v0.6.0@sha256:<release-digest>` for
  both `certgen` and `control`. If GHCR returns `401 Unauthorized`, log in first
  with a token that has `read:packages`, or point `PROBECTL_IMAGE` at an
  internally mirrored digest. A tag-only local/mirror ref is allowed only with
  `PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable`. The compose preflight
  below checks this before the stack starts, so a mutable or private registry
  failure stops with exact repair commands instead of halfway through first boot:

  ```sh
  echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GITHUB_USER" --password-stdin
  # or:
  PROBECTL_IMAGE='registry.internal/probectl-control:v0.6.0@sha256:<release-digest>'
  # or build from this checkout (it trusts the committed license public keys
  # under internal/license/trusted_keys/, so a vendor license file works —
  # docs/editions.md, "Trust anchor"):
  docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=probectl-control \
    --build-arg COMMIT=$(git rev-parse --short HEAD) -t probectl-control:local .
  # The image stamps the checkout's VERSION file (as <version>-local) and the build
  # time by itself; only the commit needs passing, because .git is not in the build
  # context. `probectl-control version` (or an authenticated GET /version; anonymous
  # callers get only the service name) then identifies the build.
  PROBECTL_IMAGE=probectl-control:local
  PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
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
service generates a **self-signed certificate** (`probectl-control gen-cert
--if-missing`) so you can start immediately; later boots preserve the complete
bundle, and you swap in a real CA-issued cert for production.
Self-signed means the server vouches for itself rather than a certificate
authority (CA — a trusted issuer your clients already know): traffic is fully
encrypted either way, but your client must be *told* to trust this server —
which is exactly what step 3 (copy out `ca.crt`) and `--cacert` in step 4 do.

```sh
# 1. Configure.
cp deploy/compose/.env.example deploy/compose/.env
# Edit deploy/compose/.env:
#   - POSTGRES_PASSWORD      (required; openssl rand -hex 24 — URL-safe, because
#                             it is spliced into PROBECTL_DATABASE_URL)
#   - PROBECTL_ENVELOPE_KEY  (openssl rand -base64 32 — the at-rest encryption key)
#   - PROBECTL_SESSION_HMAC_KEY (openssl rand -hex 32 — the session-token pepper)
#   - PROBECTL_TLS_HOSTS     (the hostname(s)/IP(s) the self-signed cert is valid for)
# Auth defaults to "session" (real OIDC SSO, fail-closed) — set the PROBECTL_OIDC_*
# values. PROBECTL_AUTH_MODE=dev (no-auth, all-access) is NOT a runtime toggle on
# this shipped release image: the dev-auth code path only exists in a binary built
# with -tags devauth, so setting it here makes the control plane REFUSE TO START
# with a clear error (not a warning). For a no-IdP local evaluation, use the eval
# stack (deploy/compose/eval.yml) — see docs/getting-started.md — not this stack.

# 2. Preflight the .env and the image, then start.
#    The env preflight refuses a password that is not URL-safe or a malformed
#    key BEFORE the control plane can crash-loop on it; the image preflight fails
#    if the pinned image is private/unreachable and prints the exact docker
#    login, mirror override, or local-build command. make compose-prod-up runs both.
bash scripts/compose_env_preflight.sh
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

There is **no** plaintext port: `http://localhost:8443` will not connect.

**Bring your own (CA-issued) certificate.** Put three files in a directory on
the host — `tls.crt` (the server certificate with intermediates appended),
`tls.key` (its private key, readable by the container user: `chown 65532
tls.key && chmod 600 tls.key`), and `ca.crt` (the issuing chain, which the
`curl --cacert` examples and the Dex overlay use) — and set
`PROBECTL_TLS_DIR=/absolute/path` in `.env`. Every service that needs the
certificate (control, Postgres, the one-shot `certgen`) then mounts that
directory instead of the named `certs` volume; `certgen --if-missing` keeps a
complete bundle untouched and refuses to touch a partial one, so it never
overwrites your files. Leave `PROBECTL_TLS_DIR` empty to keep the self-signed
quickstart certificate.

**Install your license (Enterprise / MSP).** The free core needs no license.
To unlock commercial features, set `PROBECTL_LICENSE_PATH=/absolute/path/to/license.json`
in `.env` (the offline-signed file your vendor issued) and layer the license
overlay:

```sh
make compose-prod-up PROBECTL_COMPOSE_OVERLAYS='-f deploy/compose/license.yml'
# equivalent:
docker compose --env-file deploy/compose/.env \
  -f deploy/compose/probectl.yml -f deploy/compose/license.yml up -d
```

For an **MSP** license, also layer `deploy/compose/provider.yml`: the provider
plane refuses admission until it has signed WORM audit export and an IR
public keyring, and that overlay wires both onto the persistent volume (see
[`provider-plane.md`](provider-plane.md)); the first operator's bootstrap
token goes in `deploy/compose/control.env`. Verification is local math against
the trust anchors compiled into the binary — nothing phones home. A forged or corrupt file stops the control plane
at startup; an expired one loads and degrades per the grace ladder. **Admin →
Editions** (`GET /v1/editions`) shows the loaded tier, customer, and expiry —
see [`editions.md`](editions.md).

**Any other control-plane key.** `probectl.yml` sets the security-critical
keys explicitly and forwards nothing else from `.env`. For every other
`PROBECTL_*` key in [`configuration.md`](configuration.md) — the provider
bootstrap token, the deployment profile, log level, bus and store settings —
copy `deploy/compose/control.env.example` to `deploy/compose/control.env` and
put the keys there; the control service loads that file when it exists
(`env_file`, `required: false`) and never commits it. The explicit keys in
`probectl.yml` always win over it, so the file cannot downgrade TLS, auth, or
encryption.

Tear down with `docker compose -f deploy/compose/probectl.yml down` (add `-v` to
also drop the database and certs).

## Option B — Kubernetes (Helm)

The chart in [`deploy/helm/probectl`](../deploy/helm/probectl) serves TLS on the
control pod and at the ingress, force-redirects HTTP → HTTPS, and emits HSTS.
The Service, probes, ingress backend, and optional ServiceMonitor all target the
same HTTPS listener, so the ingress-to-pod hop is not plaintext.
Migrations run as an init container (a one-shot container Kubernetes runs to
completion before the main one starts — so the schema is always in place before
the server boots), and the pod runs non-root with a read-only
root filesystem.

```sh
helm install probectl deploy/helm/probectl \
  --namespace probectl --create-namespace \
  --set ingress.host=probectl.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set control.tls.existingSecret=probectl-tls \
  --set-string image.digest='sha256:<release-digest>' \
  --set database.url='postgres://probectl:...@db:5432/probectl?sslmode=require' \
  --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set control.authMode=session \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=probectl \
  --set oidc.clientSecret=REPLACE \
  --set oidc.redirectUrl=https://probectl.example.com/auth/callback
```

Provide the TLS Secret via cert-manager (add the issuer to `ingress.annotations`)
or create it first. It must contain `tls.crt` and `tls.key`; the example reuses
the same host certificate for `ingress.tlsSecretName` and
`control.tls.existingSecret`. Helm fails closed when the control-listener Secret
is omitted. `image.digest` is also required: use the `probectl-control` digest
whose keyless signature verifies for the release workflow, or the corresponding
digest in your approved internal mirror. A mutable tag is rejected before any
workload renders. For the MSP / provider reference sizing, add
`-f deploy/helm/probectl/values-multitenant.yaml`, pre-create the referenced
`probectl-provider-objects-rwx` shared PVC and
`probectl-provider-runtime` Secret, and set the SIEM watermark values shown in
[`deploy/helm/README.md`](../deploy/helm/README.md). The PVC must be
`ReadWriteMany` and backed by object-lock/compliance-mode storage. The Secret
must carry one shared `PROBECTL_WORM_SIGNING_KEY` plus the normal runtime
credentials. Provider profiles reject pod-local `emptyDir` WORM storage and
per-replica key files, so raw audit rows cannot silently prune against missing
or split-brain evidence. Then verify:

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

**Turn on the agent listener of this stack first.** The production stack ships
with the agent gRPC/mTLS listener off, because it needs the deployment's agent
certificate authority. Create that CA once (the root key is printed exactly
once — put it in offline custody), export its public trust bundle onto the
persistent volume, then restart with the `agents.yml` overlay, which enables
the listener on port 9443 with the same server certificate the API serves:

```sh
docker compose --env-file deploy/compose/.env -f deploy/compose/probectl.yml \
  exec control /usr/local/bin/app agent-ca init
docker compose --env-file deploy/compose/.env -f deploy/compose/probectl.yml \
  exec control /usr/local/bin/app agent-ca export /var/lib/probectl/agent-ca.crt
make compose-prod-up PROBECTL_COMPOSE_OVERLAYS='-f deploy/compose/agents.yml'
```

> **Restarting or upgrading later:** re-run `make compose-prod-up` with the same
> overlays. Bring the stack up as a whole rather than one service at a time —
> the demo Dex shares the control container's network namespace, so
> `docker compose ... up -d control` alone strands Dex and every login answers
> "tenant SSO provider is unavailable" until Dex is recreated too.

Then mint a join token (**Admin & Settings → Agents → Enroll agent**, or
`exec control /usr/local/bin/app enroll-token -tenant <uuid>`) and enroll the
agent from its host against `https://<host>:8443` with gRPC at `<host>:9443`
([`deploying-agents.md`](deploying-agents.md)).

On **Kubernetes** the chart ships the same listener off; run `agent-ca init`
once through `kubectl exec`, then `helm upgrade --set
control.agentListener.enabled=true` (plus a `NodePort`/`LoadBalancer` service
type for probe hosts outside the cluster) — the chart exports the public trust
bundle itself on every start. See the
[Helm README](../deploy/helm/README.md#the-agent-listener-producers-attach-here).

Don't follow a one-off recipe here — the canonical journey is already written:

- **See data in one command (no Go toolchain, any OS):** the **evaluation stack**
  [`deploy/compose/eval.yml`](../deploy/compose/eval.yml) brings up a control plane
  plus a sample producer so you can watch real data flow end to end:

  ```sh
  docker compose -f deploy/compose/eval.yml up --build -d
  # The viewer waits for control-plane readiness and sample topology data:
  docker compose -f deploy/compose/eval.yml --profile tools run --rm --no-deps viewer
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
   default-deny, not default-allow. On a fresh deployment there is no admin
   yet, so grant the first one from the control host (the same trust as
   `migrate`); the person does not need to have logged in first:

   ```sh
   # Compose (the control image is distroless; its entrypoint is the binary):
   docker compose --env-file deploy/compose/.env -f deploy/compose/probectl.yml \
     exec control /usr/local/bin/app bootstrap-admin -email you@example.com
   # Helm:
   kubectl -n probectl exec deploy/probectl -- /usr/local/bin/app bootstrap-admin -email you@example.com
   ```

   The grant is tenant-scoped (`-tenant`, default the built-in tenant),
   idempotent, and recorded in the audit trail as `rbac.bind`; `-role` accepts
   `admin`, `editor`, `viewer`, or a custom role slug. From then on, roles come
   from SCIM group sync or from an admin.
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
