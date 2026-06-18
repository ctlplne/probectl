# probectl control-plane module: a Kubernetes Secret for the sensitive config plus a
# Helm release of the hardened chart. The chart references the Secret via
# secrets.existingSecret, so no credential is rendered into the ConfigMap.

locals {
  namespace = var.create_namespace ? kubernetes_namespace.probectl[0].metadata[0].name : var.namespace

  # The size preset's values file (when chart is a local path) + any extra files.
  size_values  = var.size == "" ? [] : [file("${var.chart}/values-${var.size}.yaml")]
  values_files = concat(local.size_values, [for f in var.values_files : file(f)])

  # secrets.existingSecret keys mirror the chart's Secret template.
  secret_data = merge(
    {
      PROBECTL_ENVELOPE_KEY     = var.envelope_key
      PROBECTL_SESSION_HMAC_KEY = var.session_hmac_key
      PROBECTL_DATABASE_URL     = var.database_url
    },
    var.oidc_client_secret == "" ? {} : { PROBECTL_OIDC_CLIENT_SECRET = var.oidc_client_secret },
  )

  # Non-sensitive Helm overrides.
  base_set = merge(
    {
      "ingress.host"           = var.ingress_host
      "ingress.tlsSecretName"  = var.ingress_tls_secret
      "secrets.existingSecret" = kubernetes_secret.probectl.metadata[0].name
    },
    var.image_repository == "" ? {} : { "image.repository" = var.image_repository },
    var.image_tag == "" ? {} : { "image.tag" = var.image_tag },
    var.oidc_issuer == "" ? {} : {
      "oidc.issuer"      = var.oidc_issuer
      "oidc.clientId"    = var.oidc_client_id
      "oidc.redirectUrl" = var.oidc_redirect_url
    },
    var.set_values,
  )
}

resource "kubernetes_namespace" "probectl" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/part-of"    = "probectl"
    }
  }
}

resource "kubernetes_secret" "probectl" {
  metadata {
    name      = "${var.release_name}-secrets"
    namespace = local.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "app.kubernetes.io/part-of"    = "probectl"
    }
  }
  type = "Opaque"
  data = local.secret_data
}

resource "helm_release" "probectl" {
  name      = var.release_name
  namespace = local.namespace
  chart     = var.chart
  version   = var.chart_version == "" ? null : var.chart_version

  values = local.values_files

  dynamic "set" {
    for_each = local.base_set
    content {
      name  = set.key
      value = set.value
    }
  }

  # Wait for the rollout, and roll back on failure (clean GitOps/CI behavior).
  atomic          = var.atomic
  wait            = true
  cleanup_on_fail = true

  depends_on = [kubernetes_secret.probectl]
}
