# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = { source = "hashicorp/azurerm" }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
}

variable "vantages" {
  description = "Tenant-owned deployments keyed by a stable local name. The module validates the two configuration objects."
  type = map(object({
    vantage   = any
    placement = any
    enrollment_secret = object({
      vault_id = string
      name     = string
    })
  }))
}

module "vantages" {
  source   = "../../modules/vantage-azure"
  for_each = var.vantages

  vantage           = each.value.vantage
  placement         = each.value.placement
  enrollment_secret = each.value.enrollment_secret
}

output "instance_ids" {
  description = "Cloud instance identifiers keyed by the configured vantage names."
  value       = { for name, deployed in module.vantages : name => deployed.instance_id }
}
