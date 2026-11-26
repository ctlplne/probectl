# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

variables {
  cloud            = "aws"
  secret_reference = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:vantage-red-A1b2C3"
  vantage = {
    tenant_id      = "00000000-0000-4000-8000-000000000001"
    name           = "eu-red"
    site           = "probe-eu"
    region         = "eu-west-1"
    enrollment_url = "https://enroll.example:8443"
    agent_address  = "enroll.example:9443"
    control_ca_pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
  }
}

run "tenant_enrollment_and_trust" {
  command = plan

  assert {
    condition = yamldecode(output.cloud_config).runcmd[0] == [
      "/usr/local/sbin/probectl-vantage-enroll", "aws", var.secret_reference,
      var.vantage.tenant_id, var.vantage.enrollment_url, var.vantage.name, var.vantage.region, "",
    ]
    error_message = "Cloud-init must pass only the secret reference and the intended tenant's enrollment metadata."
  }

  assert {
    condition = yamldecode(one([
      for f in yamldecode(output.cloud_config).write_files : f.content if f.path == "/etc/probectl-vantage/agent.yaml"
    ])).tls.ca_file == "/etc/probectl-vantage/control-ca.pem"
    error_message = "The agent and its first enrollment must share the verified control-plane trust."
  }

  assert {
    condition = yamldecode(one([
      for f in yamldecode(output.cloud_config).write_files : f.content if f.path == "/etc/probectl-vantage/agent.yaml"
      ])).agent.labels == {
      site         = var.vantage.site
      region       = var.vantage.region
      network_role = "cloud"
      provider     = var.cloud
    }
    error_message = "The cloud canary must use the labels the owned-vantage map expects."
  }

  assert {
    condition = strcontains(one([
      for f in yamldecode(output.cloud_config).write_files : f.content
      if f.path == "/etc/systemd/system/probectl-agent.service.d/60-probectl-vantage.conf"
    ]), "Requires=probectl-vantage-metadata.service\nAfter=probectl-vantage-metadata.service")
    error_message = "The canary must start only after the workload identity metadata firewall succeeds."
  }
}

run "azure_read" {
  command = plan

  variables {
    cloud            = "azure"
    secret_reference = "https://test-vantage.vault.azure.net/secrets/enrollment"
    azure_client_id  = "00000000-0000-4000-8000-000000000101"
  }

  assert {
    condition = yamldecode(output.cloud_config).runcmd[0] == [
      "/usr/local/sbin/probectl-vantage-enroll", "azure", var.secret_reference,
      var.vantage.tenant_id, var.vantage.enrollment_url, var.vantage.name, var.vantage.region, var.azure_client_id,
    ]
    error_message = "The Azure bootstrap must carry the exact secret reference and managed identity."
  }
}

run "gcp_read" {
  command = plan

  variables {
    cloud            = "gcp"
    secret_reference = "vantage-project:enrollment"
  }

  assert {
    condition     = yamldecode(output.cloud_config).runcmd[0][1] == "gcp" && yamldecode(output.cloud_config).runcmd[0][2] == var.secret_reference
    error_message = "The GCP bootstrap must carry the exact project and secret."
  }
}

run "refuse_join_token_as_input" {
  command = plan

  variables {
    secret_reference = "pjt_${join("", [for i in range(4) : "0123456789abcdef"])}"
  }

  expect_failures = [output.cloud_config]
}
