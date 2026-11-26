# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

variable "vantage" {
  description = "Public metadata and TLS trust for one tenant-owned vantage. The join token is read in the VM."
  type = object({
    tenant_id      = string
    name           = string
    site           = string
    region         = string
    enrollment_url = string
    agent_address  = string
    control_ca_pem = string
  })

  validation {
    condition = (
      can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.vantage.tenant_id)) &&
      var.vantage.tenant_id != "00000000-0000-0000-0000-000000000000"
    )
    error_message = "The vantage requires a canonical, nonzero tenant UUID."
  }

  validation {
    condition = alltrue([
      for label in [var.vantage.name, var.vantage.site, var.vantage.region] :
      can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label))
    ])
    error_message = "The vantage name, site, and region must be lowercase DNS labels."
  }

  validation {
    condition = (
      can(regex("^https://([A-Za-z0-9][A-Za-z0-9.-]*|\\[[0-9A-Fa-f:]+\\])(:[1-9][0-9]{0,4})?$", var.vantage.enrollment_url)) &&
      can(regex("^([A-Za-z0-9][A-Za-z0-9.-]*|\\[[0-9A-Fa-f:]+\\]):[1-9][0-9]{0,4}$", var.vantage.agent_address)) &&
      try(tonumber(substr(regex(":[0-9]+$", var.vantage.agent_address), 1, -1)) <= 65535, false) &&
      try(tonumber(substr(regex(":[0-9]+$", var.vantage.enrollment_url), 1, -1)) <= 65535, true)
    )
    error_message = "Supply an HTTPS enrollment origin and a hostname:port for the agent mTLS listener."
  }

  validation {
    condition = (
      length(var.vantage.control_ca_pem) <= 32768 &&
      can(regex("^([[:space:]]*-----BEGIN CERTIFICATE-----[[:space:]]+[A-Za-z0-9+/=[:space:]]+-----END CERTIFICATE-----[[:space:]]*)+$", var.vantage.control_ca_pem))
    )
    error_message = "Supply a PEM bundle containing only public control-plane CA certificates."
  }
}

variable "cloud" {
  description = "The VM's cloud provider."
  type        = string

  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud)
    error_message = "The cloud must be aws, azure, or gcp."
  }
}

variable "secret_reference" {
  description = "An AWS Secrets Manager ARN, Azure Key Vault secret ID, or GCP project:secret reference."
  type        = string
}

variable "azure_client_id" {
  description = "The public client ID of the Azure VM's exact user-assigned identity."
  type        = string
  default     = ""
}
