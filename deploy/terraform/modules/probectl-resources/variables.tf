variable "api_url" {
  description = "Self-hosted probectl API base URL."
  type        = string
}

variable "tenant" {
  description = "Tenant header for tenant-scoped /v1 resources."
  type        = string
}

variable "token" {
  description = "Bearer token for the probectl API."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tests" {
  description = "Named synthetic test request bodies posted to /v1/tests."
  type        = map(any)
  default     = {}
}

variable "slos" {
  description = "Named SLO request bodies. Override path/method through resources until /v1/slos writes are enabled."
  type        = map(any)
  default     = {}
}

variable "alert_routes" {
  description = "Named alert route/rule request bodies posted to /v1/alerts."
  type        = map(any)
  default     = {}
}

variable "integrations" {
  description = "Named integration request bodies. Use resources for routes that are not /v1/alerts/test-channel."
  type        = map(any)
  default     = {}
}

variable "provider_tenants" {
  description = "Named Provider/MSP tenant request bodies posted to /provider/v1/tenants."
  type        = map(any)
  default     = {}
}

variable "resources" {
  description = "Advanced resources: arbitrary probectl API operations."
  type = map(object({
    method = string
    path   = string
    body   = optional(any)
  }))
  default = {}
}
