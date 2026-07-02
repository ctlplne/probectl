# probectl resources Terraform module

This module lets Terraform drive probectl's served API resources through the
`probectl api` command. It is a source-available, self-hosted replacement path
for teams that want reviewed Terraform plans for tests, alert routes, SLO
definitions, integrations, and Provider/MSP tenant bootstrap without installing
the native provider plugin.

It does **not** call a probectl-managed SaaS endpoint. `api_url` must point at
the operator's own control plane. Secrets are passed to the local `probectl`
process as environment variables for the provisioner; as with all Terraform
automation, protect the state backend and CI logs.

## Example

```hcl
module "probectl_resources" {
  source = "../../modules/probectl-resources"

  api_url = "https://probectl.example.com"
  tenant  = var.tenant_id
  token   = var.probectl_token

  tests = {
    edge_dns = {
      name             = "edge dns"
      type             = "dns"
      target           = "1.1.1.1"
      interval_seconds = 30
      timeout_seconds  = 3
      enabled          = true
      params           = { qtype = "A" }
    }
  }

  alert_routes = {
    loss = {
      name       = "packet loss"
      metric     = "probectl_probe_loss_ratio"
      type       = "threshold"
      comparison = "gt"
      threshold  = 0.05
      severity   = "warning"
      enabled    = true
      channels = [{
        type = "webhook"
        url  = "https://hooks.internal.example/probectl"
      }]
    }
  }

  provider_tenants = {
    acme = {
      name = "Acme Networks"
      slug = "acme"
    }
  }

  resources = {
    netbox_smoke = {
      method = "GET"
      path   = "/v1/cmdb/lookup?key=core-sw1.example.com"
    }
  }
}
```

## Native provider

The native `terraform-provider-probectl` binary is also shipped. Use it when you
want Terraform state to track typed probectl resources directly:
`probectl_test`, `probectl_alert_route`, `probectl_provider_tenant`, and
`probectl_api_resource`. This module remains the no-plugin path for bootstrap,
restricted CI runners, and environments that deliberately avoid provider
installation.
