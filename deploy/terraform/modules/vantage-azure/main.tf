# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "vantage" {
  description = "Tenant identity, labels, and control-plane TLS trust."
  type = object({
    tenant_id      = string
    name           = string
    site           = string
    region         = string
    enrollment_url = string
    agent_address  = string
    control_ca_pem = string
  })
}

variable "placement" {
  description = "Prepared Linux image version, VM size, and existing subnet and network security group."
  type = object({
    resource_group_name  = string
    image_id             = string
    size                 = string
    subnet_id            = string
    security_group_id    = string
    admin_ssh_public_key = string
  })
}

variable "enrollment_secret" {
  description = "Existing RBAC Key Vault resource ID and exact enrollment secret name."
  type = object({
    vault_id = string
    name     = string
  })

  validation {
    condition = (
      can(regex("(?i)^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[a-z0-9-]{3,24}$", var.enrollment_secret.vault_id)) &&
      can(regex("^[a-zA-Z0-9-]{1,127}$", var.enrollment_secret.name))
    )
    error_message = "Supply a Key Vault ARM resource ID and the single secret name."
  }
}

data "azurerm_client_config" "current" {}

locals {
  vault_name = basename(var.enrollment_secret.vault_id)
  admin      = "probectl-admin"
}

resource "azurerm_user_assigned_identity" "vantage" {
  name                = "${var.vantage.name}-probectl"
  resource_group_name = var.placement.resource_group_name
  location            = var.vantage.region
}

resource "azurerm_role_assignment" "enrollment" {
  scope              = "${var.enrollment_secret.vault_id}/secrets/${var.enrollment_secret.name}"
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
  principal_id       = azurerm_user_assigned_identity.vantage.principal_id
  principal_type     = "ServicePrincipal"

  lifecycle {
    precondition {
      condition     = startswith(lower(var.enrollment_secret.vault_id), "/subscriptions/${lower(data.azurerm_client_config.current.subscription_id)}/")
      error_message = "The Key Vault enrollment secret must belong to the deployment subscription."
    }
  }
}

module "bootstrap" {
  source           = "../vantage-bootstrap"
  vantage          = var.vantage
  cloud            = "azure"
  secret_reference = "https://${local.vault_name}.vault.azure.net/secrets/${var.enrollment_secret.name}"
  azure_client_id  = azurerm_user_assigned_identity.vantage.client_id
}

resource "azurerm_network_interface" "vantage" {
  name                = "${var.vantage.name}-probectl"
  resource_group_name = var.placement.resource_group_name
  location            = var.vantage.region

  ip_configuration {
    name                          = "private"
    subnet_id                     = var.placement.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "vantage" {
  network_interface_id      = azurerm_network_interface.vantage.id
  network_security_group_id = var.placement.security_group_id
}

resource "azurerm_linux_virtual_machine" "vantage" {
  name                            = var.vantage.name
  resource_group_name             = var.placement.resource_group_name
  location                        = var.vantage.region
  size                            = var.placement.size
  source_image_id                 = var.placement.image_id
  network_interface_ids           = [azurerm_network_interface.vantage.id]
  custom_data                     = base64encode(module.bootstrap.cloud_config)
  admin_username                  = local.admin
  disable_password_authentication = true

  admin_ssh_key {
    username   = local.admin
    public_key = var.placement.admin_ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vantage.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  depends_on = [azurerm_role_assignment.enrollment, azurerm_network_interface_security_group_association.vantage]
}

output "instance_id" {
  description = "Cloud identifier of the vantage VM."
  value       = azurerm_linux_virtual_machine.vantage.id
}
