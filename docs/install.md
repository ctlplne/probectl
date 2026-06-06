# Installing probectl

probectl ships **HTTPS-by-default**: every shipped deploy serves the API over TLS
with HSTS and exposes no plaintext listener (CLAUDE.md §7 guardrail 12). This
guide covers the all-in-one Docker Compose deploy and the Kubernetes Helm chart.
For configuration keys, see [`configuration.md`](configuration.md); for
day-2 operation (audit, roles, SSO), see [`admin.md`](admin.md).

## Prerequisites

- A released image (e.g. `ghcr.io/imfeelingtheagi/probectl-control:v0.1.0`) or the
  ability to build one (`make images`).
- Compose path: Docker with Compose v2.
- Helm path: a Kubernetes cluster with an ingress controller (nginx in the
  examples) and a way to provide a TLS certificate (cert-manager or a secret).

## Option A — Docker Compose (all-in-one)

The `probectl.yml` stack runs the control plane behind TLS with a bundled Postgres.
A self-signed certificate is generated on first boot for an immediate start.

```sh
# 1. Configure.
cp deploy/compose/.env.example deploy/compose/.env
# Edit deploy/compose/.env: set PROBECTL_ENVELOPE_KEY (openssl rand -base64 32),
# POSTGRES_PASSWORD, and your TLS hostnames. Auth defaults to "session" (OIDC SSO,
# fail-closed) — set the PROBECTL_OIDC_* values. For a quick NO-AUTH local
# evaluation only, explicitly set PROBECTL_AUTH_MODE=dev (loud startup warning).

# 2. Start.
docker compose -f deploy/compose/probectl.yml up -d

# 3. Grab the generated CA so your client can trust the self-signed cert.
docker compose -f deploy/compose/probectl.yml cp control:/certs/ca.crt ./ca.crt

# 4. Verify — over HTTPS.
curl --cacert ./ca.crt https://localhost:8443/readyz
curl --cacert ./ca.crt https://localhost:8443/.well-known/security.txt
```

There is **no** plaintext port; `http://localhost:8443` will not connect. To use a
real (CA-issued) certificate, place `tls.crt` / `tls.key` in the `certs` volume
(or mount your own) and remove the `certgen` service.

Tear down with `docker compose -f deploy/compose/probectl.yml down` (add `-v` to
drop the database and certs).

## Option B — Kubernetes (Helm)

The chart terminates TLS at the ingress, force-redirects HTTP→HTTPS, and emits
HSTS; the Service is `ClusterIP` (no plaintext exposure). Migrations run as an
init container.

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
or pre-create `probectl-tls`. For the MSP / provider reference sizing, add
`-f deploy/helm/probectl/values-multitenant.yaml`. Verify:

```sh
curl https://probectl.example.com/readyz
```

See [`../deploy/helm/README.md`](../deploy/helm/README.md) for all values.

## First-run checklist

1. **Authentication.** Outside evaluation, run with `authMode=session` and a real
   OIDC IdP. A brand-new SSO user is provisioned with **no roles** — an admin
   must grant access (see [`admin.md`](admin.md)).
2. **Envelope key.** Set `PROBECTL_ENVELOPE_KEY` to a real 32-byte base64 KEK and
   keep it safe; secrets at rest are sealed with it.
3. **Disclosure contact.** Set `PROBECTL_SECURITY_CONTACT` so
   `/.well-known/security.txt` advertises your security mailbox.
4. **Database TLS.** Point `PROBECTL_DATABASE_URL` at a Postgres reachable over TLS
   (`sslmode=require`) in production.
5. **Audit.** Confirm the audit trail is recording and intact:
   `GET /v1/audit` and `GET /v1/audit/verify` (admin / `audit.read`).
