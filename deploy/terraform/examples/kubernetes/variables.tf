variable "kubeconfig" {
  description = "Path to the kubeconfig for the target cluster."
  type        = string
  default     = "~/.kube/config"
}

variable "size" {
  description = "Reference sizing profile: small | medium | large. Defaults to the single-replica 'small' profile so this getting-started example applies against any cluster with no external dependencies. The medium/large profiles run multiple replicas and therefore REQUIRE shared durable backends — a nats/kafka bus, a Prometheus/VictoriaMetrics TSDB and ClickHouse stores (PLAT-02); supply those via set_values/values_files before choosing them, or the chart refuses to render."
  type        = string
  default     = "small"
}

variable "ingress_host" {
  description = "External hostname for the probectl HTTPS ingress."
  type        = string
}

variable "ingress_tls_secret" {
  description = "Name of the TLS Secret holding the ingress cert (e.g. from cert-manager)."
  type        = string
  default     = "probectl-tls"
}

variable "trusted_proxies" {
  description = "CIDRs of the ingress controller (and any L4 LB) whose forwarded client address the per-IP auth throttle may trust (AUTHZ-04). Defaults to the common ingress-nginx pod CIDR; override to match YOUR controller's pod network, or logins may be throttled incorrectly."
  type        = list(string)
  default     = ["10.244.0.0/16"]
}

variable "image_digest" {
  description = "Signed probectl-control release digest: sha256 followed by 64 lowercase hex characters."
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be sha256 followed by exactly 64 lowercase hexadecimal characters."
  }
}

variable "database_url" {
  description = "Postgres DSN (use sslmode=require)."
  type        = string
  sensitive   = true
}

variable "envelope_key" {
  description = "Base64 32-byte envelope KEK: openssl rand -base64 32"
  type        = string
  sensitive   = true
}

variable "session_hmac_key" {
  description = "Hex 32-byte session HMAC key: openssl rand -hex 32"
  type        = string
  sensitive   = true
}
