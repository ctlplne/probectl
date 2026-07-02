# deploy/terraform/

Terraform modules for deploying probectl. **Terraform** is
infrastructure-as-code: you declare the desired end state in `.tf` files and
`terraform apply` makes the live system match it. A **module** is Terraform's
reusable unit — a folder of configuration with typed inputs and outputs,
invoked like a function — and this one is a wall socket: a small, fixed plug
shape on the front (the variables below), the wiring hidden behind the
plate. The core module deploys the hardened
Helm chart plus the sensitive config as a Kubernetes Secret, on **any**
Kubernetes cluster (EKS/GKE/AKS/OpenShift/k3s) — provision the cluster + managed
Postgres with your cloud's own modules and pass the DSN (the database
connection string) in.

```text
deploy/terraform/
├── modules/probectl/                 # Helm release + Secret + namespace
│   └── versions.tf · variables.tf · main.tf · outputs.tf
├── modules/probectl-resources/       # API resources through `probectl api`
│   └── versions.tf · variables.tf · main.tf · outputs.tf · README.md
└── examples/kubernetes/              # a root you can `terraform apply`
    └── main.tf · variables.tf · terraform.tfvars.example
```

The module requires Terraform >= 1.5 with the `hashicorp/helm` (~> 2.12) and
`hashicorp/kubernetes` (~> 2.25) providers (`versions.tf`) — **providers** are
Terraform's drivers, the plugins that each speak one API (here: Helm releases
and the Kubernetes API). It is kept honest in
CI: the `terraform-gate` job runs `make terraform-gate` — `terraform fmt
-recursive -check` plus `terraform validate` of the example root that consumes
the module.

## Quickstart

```bash
cd deploy/terraform/examples/kubernetes
cp terraform.tfvars.example terraform.tfvars   # fill in (never commit real secrets)
terraform init
terraform apply
```

A successful `apply` means the release rolled out — not that probectl is doing
anything useful yet. Data appears once agents are deployed and reporting:
[`docs/getting-started.md`](../../docs/getting-started.md) is the zero →
first-data path, and [`docs/deploying-agents.md`](../../docs/deploying-agents.md)
catalogs which agent produces which data plane.

## Module interface (`modules/probectl`)

### Inputs

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `ingress_host` | string | — (required) | External hostname for the HTTPS ingress |
| `database_url` | string (sensitive) | — (required) | Postgres DSN (`sslmode=require`) |
| `envelope_key` | string (sensitive) | — (required) | base64 32-byte KEK (`openssl rand -base64 32`) |
| `session_hmac_key` | string (sensitive) | — (required) | hex 32-byte session HMAC key (`openssl rand -hex 32`) |
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

The module writes `PROBECTL_ENVELOPE_KEY` / `PROBECTL_SESSION_HMAC_KEY` /
`PROBECTL_DATABASE_URL` (and the OIDC client secret) into a Kubernetes `Secret` and sets the chart's
`secrets.existingSecret` to it — so no credential is ever rendered into the
ConfigMap or the Helm release values. Mark `database_url` / `envelope_key` /
`session_hmac_key` / `oidc_client_secret` sensitive (they are) and source them from your secret
manager or CI variables; never commit `terraform.tfvars` (the file `apply`
reads variable values from).

One Terraform reality to plan around: Terraform records everything it manages
in its **state** (the `terraform.tfstate` file, or a remote state backend).
Marking a variable `sensitive` redacts it from plan/apply *output* — the value
still lands in state. So treat the state backend with the same access control
and encryption as the secrets themselves.

### Security posture

The deployed release inherits the chart's hardening: HTTPS-by-default
(TLS-terminating ingress + HSTS, no plaintext API exposure), a non-root,
read-only-root-FS, all-caps-dropped pod, and a NetworkPolicy that is **on in
every profile** (with two documented holes you tighten per deployment — the
`large` profile ships the filled egress allow-list). `medium` and above add a
PodDisruptionBudget; `large` adds the HPA. See
[`../helm/README.md`](../helm/README.md) and
[`../../docs/iac-gitops.md`](../../docs/iac-gitops.md).

## Native probectl provider

`terraform-provider-probectl` is the native provider binary for managing served
probectl resources after the control plane is reachable. It speaks only to the
operator's self-hosted `api_url`; it does not call a probectl-managed SaaS
endpoint. Remote API URLs must be HTTPS. Plain `http` is accepted only for
loopback development and tests.

Configuration is env-friendly:

```hcl
terraform {
  required_providers {
    probectl = {
      source  = "imfeelingtheagi/probectl"
      version = "~> 0.1"
    }
  }
}

provider "probectl" {
  api_url = "https://probectl.example.com"
  tenant  = var.tenant_id
  token   = var.probectl_token
}
```

`PROBECTL_API_URL`, `PROBECTL_TENANT`, and `PROBECTL_API_TOKEN` are supported
for CI systems. The provider sends `X-Probectl-Tenant` on tenant-scoped `/v1`
resources, uses bearer auth when a token is configured, and keeps all outbound
TLS policy inside `internal/crypto`.

Air-gapped and pre-registry installs use Terraform's normal filesystem mirror or
`dev_overrides` flow: place the signed release binary as
`terraform-provider-probectl_v<version>` under the provider mirror path for
`registry.terraform.io/imfeelingtheagi/probectl/<version>/<os>_<arch>/`, or point
development overrides at a local `bin/` directory.

Resources:

- `probectl_test` -> `/v1/tests`
- `probectl_alert_route` -> `/v1/alerts`
- `probectl_provider_tenant` -> `/provider/v1/tenants`
- `probectl_api_resource` -> advanced arbitrary served API operations, such as
  early SLO or integration endpoints before a typed Terraform resource exists

```hcl
resource "probectl_test" "edge_dns" {
  name             = "edge dns"
  type             = "dns"
  target           = "1.1.1.1"
  interval_seconds = 30
  timeout_seconds  = 3
  enabled          = true
  params = {
    qtype = "A"
  }
}

resource "probectl_alert_route" "loss" {
  name       = "packet loss"
  metric     = "probectl_probe_loss_ratio"
  comparison = "gt"
  threshold  = 0.05
  severity   = "warning"
  channel {
    type = "webhook"
    url  = "https://hooks.internal.example/probectl"
  }
}
```

## API resources module (`modules/probectl-resources`)

`modules/probectl-resources` lets Terraform manage probectl resources after the
control plane is deployed. It uses Terraform's built-in `terraform_data`
resource and the checked-in `probectl api` command, so it adds no Terraform
provider SDK dependency and talks only to the operator's own `api_url`.

Supported typed maps:

- `tests` -> `POST /v1/tests`
- `alert_routes` -> `POST /v1/alerts`
- `slos` -> defaults to `POST /v1/slos` but can override `path`
- `integrations` -> defaults to `POST /v1/alerts/test-channel` but can override
  `method` and `path`
- `provider_tenants` -> `POST /provider/v1/tenants`
- `resources` -> advanced arbitrary API operations

The checked-in module remains useful for bootstrap and no-plugin environments;
the native provider is the first-class managed-resource path when operators want
Terraform state to understand probectl resources directly.
