locals {
  typed_resources = merge(
    {
      for name, body in var.tests : "test.${name}" => {
        method = "POST"
        path   = "/v1/tests"
        body   = body
      }
    },
    {
      for name, body in var.alert_routes : "alert.${name}" => {
        method = "POST"
        path   = "/v1/alerts"
        body   = body
      }
    },
    {
      for name, body in var.slos : "slo.${name}" => {
        method = "POST"
        path   = try(body.path, "/v1/slos")
        body   = body
      }
    },
    {
      for name, body in var.integrations : "integration.${name}" => {
        method = try(body.method, "POST")
        path   = try(body.path, "/v1/alerts/test-channel")
        body   = body
      }
    },
    {
      for name, body in var.provider_tenants : "provider_tenant.${name}" => {
        method = "POST"
        path   = "/provider/v1/tenants"
        body   = body
      }
    }
  )

  resources = merge(local.typed_resources, var.resources)
}

resource "terraform_data" "probectl" {
  for_each = local.resources

  # RTO-11: non-secret facts the DESTROY provisioner needs are persisted on the
  # resource (a destroy-time provisioner may reference only `self`, never `var`).
  # id_file is a deterministic per-resource path the CREATE provisioner writes
  # the API-returned id into, so destroy can DELETE the exact resource it made.
  input = {
    method  = upper(each.value.method)
    path    = each.value.path
    body    = try(each.value.body, null)
    api_url = var.api_url
    tenant  = var.tenant
    id_file = "${path.module}/.probectl-state/${substr(sha256(each.key), 0, 24)}.id"
  }

  triggers_replace = [
    sha256(jsonencode(each.value))
  ]

  # CREATE/UPDATE: apply the resource, then capture its server id for destroy.
  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      set -eu
      mkdir -p "$(dirname "$PROBECTL_ID_FILE")"
      if [ "$PROBECTL_BODY" = "null" ]; then
        OUT=$(probectl --url "$PROBECTL_API_URL" --tenant "$PROBECTL_TENANT" --token "$PROBECTL_API_TOKEN" api "$PROBECTL_METHOD" "$PROBECTL_PATH")
      else
        OUT=$(probectl --url "$PROBECTL_API_URL" --tenant "$PROBECTL_TENANT" --token "$PROBECTL_API_TOKEN" api "$PROBECTL_METHOD" "$PROBECTL_PATH" --body "$PROBECTL_BODY")
      fi
      printf '%s\n' "$OUT"
      # Record the created resource id (first "id":"..." in the JSON receipt) so
      # `terraform destroy` can DELETE it. Resource types that return no id just
      # leave an empty file and destroy skips them (best-effort cleanup).
      printf '%s' "$OUT" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1 > "$PROBECTL_ID_FILE" || true
    EOT

    environment = {
      PROBECTL_API_URL   = var.api_url
      PROBECTL_API_TOKEN = var.token
      PROBECTL_TENANT    = var.tenant
      PROBECTL_METHOD    = upper(each.value.method)
      PROBECTL_PATH      = each.value.path
      PROBECTL_BODY      = jsonencode(try(each.value.body, null))
      PROBECTL_ID_FILE   = "${path.module}/.probectl-state/${substr(sha256(each.key), 0, 24)}.id"
    }
  }

  # DESTROY: `terraform destroy` previously tore down only Terraform state and
  # left the probectl resource live on the server (RTO-11). Issue the matching
  # DELETE using the id captured at create time. A destroy provisioner may read
  # only `self`, so url/tenant/path/id_file come from self.input; the token is
  # read from the ambient PROBECTL_API_TOKEN env of the `terraform destroy`
  # process (never persisted in state). Fail-open on a missing id (nothing to
  # delete) so a partial apply can still be destroyed.
  provisioner "local-exec" {
    when        = destroy
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      set -eu
      [ -f "$PROBECTL_ID_FILE" ] || exit 0
      ID=$(cat "$PROBECTL_ID_FILE")
      [ -n "$ID" ] || exit 0
      probectl --url "$PROBECTL_API_URL" --tenant "$PROBECTL_TENANT" --token "$PROBECTL_API_TOKEN" api DELETE "$PROBECTL_PATH/$ID"
      rm -f "$PROBECTL_ID_FILE"
    EOT

    environment = {
      PROBECTL_API_URL = self.input.api_url
      PROBECTL_TENANT  = self.input.tenant
      PROBECTL_PATH    = self.input.path
      PROBECTL_ID_FILE = self.input.id_file
    }
  }
}
