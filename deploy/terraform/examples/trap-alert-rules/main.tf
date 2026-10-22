# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# Trap-driven alert rules (D-61): page when a device sends an authenticated
# SNMP linkDown for one uplink, resolve on the matching linkUp or after the
# hold, delivered to the tenant's own signed webhook.

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

variable "webhook_secret" {
  type      = string
  sensitive = true
}

provider "probectl" {
  api_url = var.api_url
  tenant  = var.tenant_id
  token   = var.tenant_token
}

# linkDown on ifIndex 3 of one core switch; linkUp on the same interface clears it.
resource "probectl_alert_route" "core_uplink_down" {
  name     = "core uplink down"
  type     = "trap"
  severity = "critical"

  trap {
    trap_oid       = ".1.3.6.1.6.3.1.1.5.3" # linkDown
    clear_trap_oid = ".1.3.6.1.6.3.1.1.5.4" # linkUp
    device         = "10.0.0.1"
    varbind_oid    = ".1.3.6.1.2.1.2.2.1.1.3" # ifIndex.3
    varbind_value  = "3"
    hold_seconds   = 900
  }

  channel {
    type   = "webhook"
    url    = "https://hooks.internal.example/probectl/traps"
    secret = var.webhook_secret
  }
}

# Any cold start of any device in the tenant; no clear trap, so it resolves
# when an hour passes without another one.
resource "probectl_alert_route" "cold_start" {
  name     = "device cold start"
  type     = "trap"
  severity = "warning"

  trap {
    trap_oid     = ".1.3.6.1.6.3.1.1.5.1" # coldStart
    hold_seconds = 3600
  }

  channel {
    type       = "email"
    recipients = ["noc@example.com"]
  }
}
