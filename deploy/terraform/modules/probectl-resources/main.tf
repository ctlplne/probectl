locals {
  typed_resources = merge(
    {
      for name, body in var.tests : "test.${name}" => {
        method         = "POST"
        path           = "/v1/tests"
        body           = body
      }
    },
    {
      for name, body in var.alert_routes : "alert.${name}" => {
        method         = "POST"
        path           = "/v1/alerts"
        body           = body
      }
    },
    {
      for name, body in var.slos : "slo.${name}" => {
        method         = "POST"
        path           = try(body.path, "/v1/slos")
        body           = body
      }
    },
    {
      for name, body in var.integrations : "integration.${name}" => {
        method         = try(body.method, "POST")
        path           = try(body.path, "/v1/alerts/test-channel")
        body           = body
      }
    },
    {
      for name, body in var.provider_tenants : "provider_tenant.${name}" => {
        method         = "POST"
        path           = "/provider/v1/tenants"
        body           = body
      }
    }
  )

  resources = merge(local.typed_resources, var.resources)
}

resource "terraform_data" "probectl" {
  for_each = local.resources

  input = {
    method         = upper(each.value.method)
    path           = each.value.path
    body           = try(each.value.body, null)
  }

  triggers_replace = [
    sha256(jsonencode(each.value))
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      set -eu
      if [ "$PROBECTL_BODY" = "null" ]; then
        probectl --url "$PROBECTL_API_URL" --tenant "$PROBECTL_TENANT" --token "$PROBECTL_API_TOKEN" api "$PROBECTL_METHOD" "$PROBECTL_PATH"
      else
        probectl --url "$PROBECTL_API_URL" --tenant "$PROBECTL_TENANT" --token "$PROBECTL_API_TOKEN" api "$PROBECTL_METHOD" "$PROBECTL_PATH" --body "$PROBECTL_BODY"
      fi
    EOT

    environment = {
      PROBECTL_API_URL   = var.api_url
      PROBECTL_API_TOKEN = var.token
      PROBECTL_TENANT    = var.tenant
      PROBECTL_METHOD    = upper(each.value.method)
      PROBECTL_PATH      = each.value.path
      PROBECTL_BODY      = jsonencode(try(each.value.body, null))
    }
  }
}
