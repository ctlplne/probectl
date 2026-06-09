# Installing probectl

## What you're installing, and the one rule that shapes it

probectl is a self-hosted control plane plus agents. This guide gets the
**control plane** running two ways: an all-in-one Docker Compose stack (fastest
path, good for a single host or evaluation) and a Kubernetes Helm chart
(production / multi-tenant).

The rule that shapes both: probectl is **HTTPS-by-default**. Every shipped deploy
serves the API over TLS, sends HSTS, and exposes **no plaintext listener at all**
(CLAUDE.md §7 guardrail 12). This is deliberate — a network-observability control
plane handles tenant data, so there is no "just turn off TLS for a sec" mode to
trip over. The practical consequence: every example below talks to `https://`,
and a plaintext request simply will not connect.

For configuration keys, see [`configuration.md`](configuration.md). For day-2
operation (audit, roles, SSO), see [`admin.md`](admin.md).

## Prerequisites

- A released image (e.g. `ghcr.io/imfeelingtheagi/probectl-control:v0.4.0` — the
  version the shipped compose stack pins), or the ability to build one
  (`make images`).
- **Compose path:** Docker with Compose v2.
- **Helm path:** a Kubernetes cluster with an ingress controller (nginx in the
  examples) and a way to supply a TLS certificate (cert-manager, or a pre-created
  secret).

## Option A — Docker Compose (all-in-one)

[`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml) runs the control
plane behind TLS with a bundled Postgres. On first boot a one-shot `certgen`
service generates a **self-signed certificate** (`probectl-control gen-cert`) so
you can start immediately; you swap in a real CA-issued cert for production.

```sh
# 1. Configure.
cp deploy/compose/.env.example deploy/compose/.env
# Edit deploy/compose/.env:
#   - POSTGRES_PASSWORD      (required; the stack refuses to start empty)
#   - PROBECTL_ENVELOPE_KEY  (openssl rand -base64 32 — the at-rest encryption key)
#   - PROBECTL_TLS_HOSTS     (the hostname(s)/IP(s) the self-signed cert is valid for)
# Auth defaults to "session" (real OIDC SSO, fail-closed) — set the PROBECTL_OIDC_*
# values. For a quick NO-AUTH local evaluation ONLY, explicitly set
# PROBECTL_AUTH_MODE=dev (it logs a loud startup warning).

# 2. Start.
docker compose -f deploy/compose/probectl.yml up -d

# 3. Grab the generated CA so your client can trust the self-signed cert.
#    (The certs live in a named Docker volume, so copy ca.crt out of the container.)
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt

# 4. Verify — over HTTPS, on port 8443.
curl --cacert ./ca.crt https://localhost:8443/readyz
curl --cacert ./ca.crt https://localhost:8443/.well-known/security.txt
```

A note on the envelope key: if you leave `PROBECTL_ENVELOPE_KEY` empty, the
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
`ClusterIP`, so nothing plaintext is reachable from outside the cluster.
Migrations run as an init container, and the pod runs non-root with a read-only
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

## First-run checklist

1. **Authentication.** Outside evaluation, run with `authMode=session` and a real
   OIDC IdP. A brand-new SSO user is provisioned with **no roles** — an admin must
   grant access (see [`admin.md`](admin.md)). This is intentional: access is
   default-deny, not default-allow.
2. **Envelope key.** Set `PROBECTL_ENVELOPE_KEY` to a real 32-byte base64 key
   (KEK) and keep it safe; secrets at rest are sealed with it. probectl encrypts
   the values *it* manages — encrypting the bulk telemetry volumes (Postgres,
   ClickHouse, object store) at rest is the operator's job (dm-crypt/LUKS, ZFS, or
   encrypted cloud volumes).
3. **Disclosure contact.** Set `PROBECTL_SECURITY_CONTACT` so
   `/.well-known/security.txt` advertises your security mailbox (RFC 9116).
4. **Database TLS.** Point `PROBECTL_DATABASE_URL` at a Postgres reachable over
   TLS (`sslmode=require` or stricter) in production.
5. **Audit.** Confirm the audit trail is recording and intact:
   `GET /v1/audit` and `GET /v1/audit/verify` (admin / `audit.read`). The audit
   log is tamper-evident, so `verify` proves the chain hasn't been altered.
