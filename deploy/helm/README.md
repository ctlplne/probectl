# deploy/helm/

Helm chart for deploying probectl on Kubernetes / OpenShift.

The chart lives in [`probectl/`](probectl/). It is **HTTPS-by-default**: the API is
exposed only through a TLS-terminating ingress that emits HSTS and force-redirects
HTTP → HTTPS; the Service is `ClusterIP`, so no plaintext API is reachable from
outside the cluster (CLAUDE.md §7 guardrail 12). The migration runs as an init
container; the pod runs non-root with a read-only root filesystem.

## Install (single-tenant / sovereign)

```sh
helm install probectl deploy/helm/probectl \
  --namespace probectl --create-namespace \
  --set ingress.host=probectl.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set database.url='postgres://probectl:...@db:5432/probectl?sslmode=require' \
  --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set control.authMode=session \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=probectl --set oidc.clientSecret=... \
  --set oidc.redirectUrl=https://probectl.example.com/auth/callback
```

Provide the TLS material via cert-manager (add the issuer annotation in
`ingress.annotations`) or a pre-created secret named by `ingress.tlsSecretName`.

## Install (multi-tenant / provider, MSP)

```sh
helm install probectl deploy/helm/probectl \
  -f deploy/helm/probectl/values-multitenant.yaml \
  --set ingress.host=probectl.msp.example.com \
  --set ingress.tlsSecretName=probectl-msp-tls \
  --set database.url=... --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set oidc.issuer=... --set oidc.clientId=... --set oidc.clientSecret=...
```

Tenant isolation is enforced by the control plane (pooled RLS scoping) regardless
of deployment shape; the multi-tenant values only size the runtime and spread
replicas. Per-tenant white-label and the provider console arrive with the S-T
track.

## Reference values (S35)

Pick a sizing profile and layer your overrides on top:

| Profile | File | Shape |
| ------- | ---- | ----- |
| single-tenant default | [`probectl/values.yaml`](probectl/values.yaml) | 1 replica |
| small | [`probectl/values-small.yaml`](probectl/values-small.yaml) | lab / pilot |
| medium | [`probectl/values-medium.yaml`](probectl/values-medium.yaml) | 3 replicas + PDB + spread |
| large | [`probectl/values-large.yaml`](probectl/values-large.yaml) | HPA 4–12 + PDB + NetworkPolicy |
| provider (MSP) | [`probectl/values-multitenant.yaml`](probectl/values-multitenant.yaml) | 3 replicas + anti-affinity + PDB |

`values.schema.json` types every key (Helm validates it). Security defaults
(non-root pinned uid, read-only root FS, drop-ALL caps, NetworkPolicy/PDB/HPA,
`/readyz` drain probe, HSTS, no default credentials) are enforced by the CI
hardening gate — `make helm-gate` (`helm lint` + `scripts/check_helm_hardening.sh`).
Terraform + GitOps wrap this same chart; see
[`docs/iac-gitops.md`](../../docs/iac-gitops.md). Full guide:
[`docs/install.md`](../../docs/install.md).
