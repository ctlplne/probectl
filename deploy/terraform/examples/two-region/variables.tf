variable "region_a" {
  description = "Primary Kubernetes failure domain and its local TLS read replica."
  type = object({
    name                 = string
    kubeconfig           = string
    context              = string
    ingress_host         = string
    tls_secret           = string
    backend_trust_secret = string
    database_read_url    = string
  })
  sensitive = true

  validation {
    condition     = can(regex("[?&]sslmode=(require|verify-ca|verify-full)(&|$)", var.region_a.database_read_url))
    error_message = "region_a.database_read_url must require PostgreSQL TLS."
  }
}

variable "region_b" {
  description = "Standby Kubernetes failure domain and its local TLS read replica."
  type = object({
    name                 = string
    kubeconfig           = string
    context              = string
    ingress_host         = string
    tls_secret           = string
    backend_trust_secret = string
    database_read_url    = string
  })
  sensitive = true

  validation {
    condition     = can(regex("[?&]sslmode=(require|verify-ca|verify-full)(&|$)", var.region_b.database_read_url))
    error_message = "region_b.database_read_url must require PostgreSQL TLS."
  }
}

variable "database_writer_url" {
  description = "TLS DSN for the fenced global PostgreSQL writer endpoint."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("[?&]sslmode=(require|verify-ca|verify-full)(&|$)", var.database_writer_url))
    error_message = "database_writer_url must require PostgreSQL TLS."
  }
}

variable "image_repository" {
  description = "Signed release or approved air-gap mirror repository."
  type        = string
}

variable "image_digest" {
  description = "Immutable signed control-plane image digest."
  type        = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be sha256 followed by 64 lowercase hex characters."
  }
}

variable "envelope_key" {
  description = "Shared base64 32-byte envelope key, supplied by a secret backend."
  type        = string
  sensitive   = true
}

variable "session_hmac_key" {
  description = "Shared 64-hex session HMAC key, supplied by a secret backend."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[0-9A-Fa-f]{64}$", var.session_hmac_key))
    error_message = "session_hmac_key must be exactly 64 hexadecimal characters."
  }
}
