# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

mock_provider "google" {}

variables {
  vantage = {
    tenant_id      = "00000000-0000-4000-8000-000000000001"
    name           = "probe-eu-west"
    site           = "owner-cloud"
    region         = "europe-west1"
    enrollment_url = "https://control.example:8443"
    agent_address  = "control.example:9443"
    control_ca_pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
  }
  placement = {
    project_id   = "vantage-project"
    image        = "projects/vantage-project/global/images/canary"
    machine_type = "e2-small"
    zone         = "europe-west1-b"
    subnetwork   = "projects/vantage-project/regions/europe-west1/subnetworks/private"
  }
  enrollment_secret_name = "owned-join"
}

run "private_vantage_reads_one_secret" {
  command = plan

  assert {
    condition = (
      google_secret_manager_secret_iam_member.enrollment.role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.enrollment.project == var.placement.project_id &&
      google_secret_manager_secret_iam_member.enrollment.secret_id == var.enrollment_secret_name
    )
    error_message = "The Compute Engine identity must get access to the exact secret in the deployment project."
  }

  assert {
    condition     = length(google_compute_instance.vantage.network_interface[0].access_config) == 0
    error_message = "The GCP vantage must have no external address configuration."
  }
}

run "reject_other_region_zone" {
  command = plan

  variables {
    placement = {
      project_id   = "vantage-project"
      image        = "projects/vantage-project/global/images/canary"
      machine_type = "e2-small"
      zone         = "us-central1-a"
      subnetwork   = "projects/vantage-project/regions/us-central1/subnetworks/private"
    }
  }

  expect_failures = [google_compute_instance.vantage]
}
