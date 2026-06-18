variable "kubeconfig" {
  description = "Path to the kubeconfig for the target cluster."
  type        = string
  default     = "~/.kube/config"
}

variable "size" {
  description = "Reference sizing profile: small | medium | large."
  type        = string
  default     = "medium"
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
