# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
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
  description = "Project, exact Linux image, VM shape, zone, and existing private subnetwork."
  type = object({
    project_id   = string
    image        = string
    machine_type = string
    zone         = string
    subnetwork   = string
  })
}

variable "enrollment_secret_name" {
  description = "The existing Secret Manager join secret in this project."
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,255}$", var.enrollment_secret_name))
    error_message = "Supply one Secret Manager secret name in the deployment project."
  }
}

module "bootstrap" {
  source           = "../vantage-bootstrap"
  vantage          = var.vantage
  cloud            = "gcp"
  secret_reference = "${var.placement.project_id}:${var.enrollment_secret_name}"
}

resource "google_service_account" "vantage" {
  project      = var.placement.project_id
  account_id   = "probectl-vantage-${substr(sha256("${var.vantage.tenant_id}/${var.vantage.region}/${var.vantage.name}"), 0, 12)}"
  display_name = "probectl vantage ${var.vantage.name}"
}

resource "google_secret_manager_secret_iam_member" "enrollment" {
  project   = var.placement.project_id
  secret_id = var.enrollment_secret_name
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vantage.email}"
}

# Cloud-init reads this configuration once per VM. Configuration changes need
# a fresh instance and therefore a newly issued one-use enrollment token.
resource "terraform_data" "bootstrap" {
  triggers_replace = sha256(module.bootstrap.cloud_config)
}

resource "google_compute_instance" "vantage" {
  name         = var.vantage.name
  project      = var.placement.project_id
  machine_type = var.placement.machine_type
  zone         = var.placement.zone

  boot_disk {
    initialize_params {
      image = var.placement.image
    }
  }

  network_interface {
    subnetwork = var.placement.subnetwork
  }

  service_account {
    email  = google_service_account.vantage.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    user-data              = module.bootstrap.cloud_config
    block-project-ssh-keys = "TRUE"
  }

  lifecycle {
    replace_triggered_by = [terraform_data.bootstrap]
    precondition {
      condition     = startswith(var.placement.zone, "${var.vantage.region}-")
      error_message = "The VM zone must belong to the vantage region."
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.enrollment]
}

output "instance_id" {
  description = "Cloud identifier of the vantage VM."
  value       = google_compute_instance.vantage.id
}
