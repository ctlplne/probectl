# deploy/terraform/

Terraform modules for deploying probectl (S35, F29). The core module deploys the
hardened Helm chart plus the sensitive config as a Kubernetes Secret, on **any**
Kubernetes cluster (EKS/GKE/AKS/OpenShift/k3s) — provision the cluster + managed
Postgres with your cloud's own modules and pass the DSN in.

```
deploy/terraform/
├── modules/probectl/         # the reusable module (helm_release + Secret + namespace)
│   ├── versions.tf · variables.tf · main.tf · outputs.tf
└── examples/kubernetes/    # a root you can `terraform apply`
    ├── main.tf · variables.tf · terraform.tfvars.example
```

## Quickstart

```bash
cd deploy/terraform/examples/kubernetes
cp terraform.tfvars.example terraform.tfvars   # fill in (never commit real secrets)
terraform init
terraform apply
```

## Module interface (`modules/probectl`)

### Inputs

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `ingress_host` | string | — (required) | External hostname for the HTTPS ingress |
| `database_url` | string (sensitive) | — (required) | Postgres DSN (`sslmode=require`) |
| `envelope_key` | string (sensitive) | — (required) | base64 32-byte KEK (`openssl rand -base64 32`) |
| `size` | string | `medium` | `small`/`medium`/`large` reference profile (or `""` for chart defaults) |
| `chart` | string | `../../helm/probectl` | chart path (local) or repo/OCI ref |
| `chart_version` | string | `""` | pin a chart version (repo/OCI charts) |
| `release_name` | string | `probectl` | Helm release name |
| `namespace` / `create_namespace` | string / bool | `probectl` / `true` | target namespace |
| `ingress_tls_secret` | string | `probectl-tls` | TLS Secret for the ingress cert |
| `image_repository` / `image_tag` | string | `""` | image overrides |
| `oidc_issuer` / `oidc_client_id` / `oidc_client_secret` / `oidc_redirect_url` | string | `""` | SSO config (secret goes to the Secret, not the ConfigMap) |
| `values_files` | list(string) | `[]` | extra values files applied after the size preset |
| `set_values` | map(string) | `{}` | extra Helm `--set` overrides |
| `atomic` | bool | `true` | roll back automatically on a failed install/upgrade |

### Outputs

`namespace`, `release_name`, `release_status`, `chart_version`, `app_version`,
`secret_name`.

### How secrets are handled

The module writes `PROBECTL_ENVELOPE_KEY` / `PROBECTL_DATABASE_URL` (and the OIDC
client secret) into a Kubernetes `Secret` and sets the chart's
`secrets.existingSecret` to it — so no credential is ever rendered into the
ConfigMap or the Helm release values. Mark `database_url` / `envelope_key` /
`oidc_client_secret` sensitive (they are) and source them from your secret
manager or CI variables; never commit `terraform.tfvars`.

### Security posture

The deployed release is HTTPS-by-default (TLS-terminating ingress + HSTS), runs
as a non-root, read-only-root-FS, all-caps-dropped pod, and (in the `large`
profile / multi-tenant values) ships a PodDisruptionBudget, HPA, and a
default-deny NetworkPolicy. See [`../../docs/iac-gitops.md`](../../docs/iac-gitops.md).
