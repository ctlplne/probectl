# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = { subscription_id = "00000000-0000-4000-8000-000000000100" }
  }

  mock_resource "azurerm_network_interface" {
    defaults = {
      id = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.Network/networkInterfaces/probe-eu-west"
    }
  }

  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/probe-eu-west"
      client_id    = "00000000-0000-4000-8000-000000000101"
      principal_id = "00000000-0000-4000-8000-000000000102"
    }
  }
}

variables {
  vantage = {
    tenant_id      = "00000000-0000-4000-8000-000000000001"
    name           = "probe-eu-west"
    site           = "owner-cloud"
    region         = "westeurope"
    enrollment_url = "https://control.example:8443"
    agent_address  = "control.example:9443"
    control_ca_pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
  }
  placement = {
    resource_group_name  = "vantage-test"
    image_id             = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.Compute/images/canary"
    size                 = "Standard_B2s"
    subnet_id            = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.Network/virtualNetworks/probes/subnets/private"
    security_group_id    = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.Network/networkSecurityGroups/probes"
    admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f fixture"
  }
  enrollment_secret = {
    vault_id = "/subscriptions/00000000-0000-4000-8000-000000000100/resourceGroups/vantage-test/providers/Microsoft.KeyVault/vaults/probe-vault"
    name     = "owned-join"
  }
}

run "private_vantage_reads_one_secret" {
  command = plan

  assert {
    condition = (
      azurerm_role_assignment.enrollment.scope == "${var.enrollment_secret.vault_id}/secrets/${var.enrollment_secret.name}" &&
      endswith(azurerm_role_assignment.enrollment.role_definition_id, "/4633458b-17de-408a-b874-0445c86b69e6")
    )
    error_message = "The Azure identity must receive Key Vault Secrets User on the exact enrollment secret."
  }

  assert {
    condition     = azurerm_linux_virtual_machine.vantage.disable_password_authentication && azurerm_linux_virtual_machine.vantage.identity[0].type == "UserAssigned"
    error_message = "The Azure VM must use a managed identity and public-key administration."
  }
}

run "reject_other_subscription_secret" {
  command = plan

  variables {
    enrollment_secret = {
      vault_id = "/subscriptions/00000000-0000-4000-8000-000000000200/resourceGroups/vantage-test/providers/Microsoft.KeyVault/vaults/other-vault"
      name     = "other-join"
    }
  }

  expect_failures = [azurerm_role_assignment.enrollment]
}
