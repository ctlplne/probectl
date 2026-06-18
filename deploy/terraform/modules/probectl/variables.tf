# Inputs for the probectl module. Sensitive values (database_url, envelope_key,
# session_hmac_key, oidc_client_secret) are written to a Kubernetes Secret the
# chart references via secrets.existingSecret — they never land in the rendered
# ConfigMap.

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "probectl"
}

variable "namespace" {
  description = "Namespace to deploy into."
  type        = string
  default     = "probectl"
}

variable "create_namespace" {
  description = "Create the namespace (false if it already exists / is managed elsewhere)."
  type        = bool
  default     = true
}

variable "chart" {
  description = "Chart reference: a local path (e.g. ../../helm/probectl) or a repo/OCI chart name. Size presets require a local path."
  type        = string
  default     = "../../helm/probectl"
}

variable "chart_version" {
  description = "Chart version to pin (for repo/OCI charts). Empty uses the local/path chart as-is."
  type        = string
  default     = ""
}

variable "size" {
  description = "Reference sizing profile: small | medium | large (uses the chart's values-<size>.yaml). Empty uses chart defaults."
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["", "small", "medium", "large"], var.size)
    error_message = "size must be one of: \"\", small, medium, large."
  }
}

variable "values_files" {
  description = "Additional values files (applied after the size preset)."
  type        = list(string)
  default     = []
}

variable "set_values" {
  description = "Extra Helm --set overrides as a name => value map."
  type        = map(string)
  default     = {}
}

variable "ingress_host" {
  description = "External hostname for the HTTPS-by-default ingress."
  type        = string
}

variable "ingress_tls_secret" {
  description = "Name of the TLS Secret holding the ingress cert for ingress_host."
  type        = string
  default     = "probectl-tls"
}

variable "image_repository" {
  description = "Override the control-plane image repository (empty = chart default)."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Override the control-plane image tag (empty = chart appVersion)."
  type        = string
  default     = ""
}

variable "database_url" {
  description = "Postgres DSN. Use sslmode=require in production."
  type        = string
  sensitive   = true
}

variable "envelope_key" {
  description = "Base64-encoded 32-byte envelope KEK (openssl rand -base64 32)."
  type        = string
  sensitive   = true
}

variable "session_hmac_key" {
  description = "Hex-encoded 32-byte session HMAC key (openssl rand -hex 32)."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9A-Fa-f]{64}$", var.session_hmac_key))
    error_message = "session_hmac_key must be exactly 64 hex characters (openssl rand -hex 32)."
  }
}

variable "oidc_issuer" {
  description = "OIDC issuer URL (empty disables SSO config — only for dev)."
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC client id."
  type        = string
  default     = ""
}

variable "oidc_client_secret" {
  description = "OIDC client secret (written to the Secret, never the ConfigMap)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_redirect_url" {
  description = "OIDC redirect URL."
  type        = string
  default     = ""
}

variable "atomic" {
  description = "Roll back the release automatically if the install/upgrade fails."
  type        = bool
  default     = true
}
