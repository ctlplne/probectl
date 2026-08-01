terraform {
  required_version = ">= 1.5"

  required_providers {
    probectl = {
      source  = "ctlplne/probectl"
      version = "~> 0.1"
    }
  }
}

variable "api_url" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "tenant_token" {
  type      = string
  sensitive = true
}

variable "provider_token" {
  type      = string
  sensitive = true
}

variable "test_id" {
  type = string
}

variable "agent_id" {
  type = string
}

provider "probectl" {
  api_url = var.api_url
  tenant  = var.tenant_id
  token   = var.tenant_token
}

# Tenant-scoped by-ID lookups.
data "probectl_test" "selected" {
  test_id = var.test_id
}

data "probectl_agent" "selected" {
  agent_id = var.agent_id
}

# Bounded list pages. Feed next_cursor into after to read the next page.
data "probectl_tests" "first_page" {
  limit = 200
}

data "probectl_agents" "first_page" {
  limit = 200
}

# Provider/MSP inventory is a separate privilege domain and normally uses an
# aliased provider configured with an operator token and no tenant selector.
provider "probectl" {
  alias   = "management"
  api_url = var.api_url
  token   = var.provider_token
}

data "probectl_tenant" "current" {
  provider  = probectl.management
  tenant_id = var.tenant_id
}

data "probectl_tenants" "inventory" {
  provider = probectl.management
}

output "selected_test_name" {
  value = data.probectl_test.selected.name
}

output "selected_agent_status" {
  value = data.probectl_agent.selected.status
}

output "tenant_slug" {
  value = data.probectl_tenant.current.slug
}

output "test_page_next_cursor" {
  value = data.probectl_tests.first_page.next_cursor
}
