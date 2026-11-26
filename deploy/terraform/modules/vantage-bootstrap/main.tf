# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

terraform {
  required_version = ">= 1.5"
}

locals {
  enroll = "/usr/local/sbin/probectl-vantage-enroll"
  config = "/etc/probectl-vantage/agent.yaml"
  ca     = "/etc/probectl-vantage/control-ca.pem"
  files = {
    (local.enroll) = {
      permissions = "0755"
      content     = file("${path.module}/enroll.sh")
    }
    (local.ca) = {
      permissions = "0644"
      content     = var.vantage.control_ca_pem
    }
    "/etc/systemd/system/probectl-vantage-metadata.service" = {
      permissions = "0644"
      content     = <<-UNIT
        [Unit]
        Description=Protect the cloud workload identity from canary probes
        After=nftables.service
        Before=probectl-agent.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=${local.enroll} --isolate-metadata
      UNIT
    }
    "/etc/systemd/system/probectl-agent.service.d/60-probectl-vantage.conf" = {
      permissions = "0644"
      content     = <<-UNIT
        [Unit]
        Requires=probectl-vantage-metadata.service
        After=probectl-vantage-metadata.service

        [Service]
        ExecStart=
        ExecStart=/usr/bin/probectl-agent --config ${local.config}
      UNIT
    }
    (local.config) = {
      permissions = "0644"
      content = yamlencode({
        apiVersion = "probectl.io/agent/v1"
        control_plane = {
          grpc_addr = var.vantage.agent_address
        }
        tls = {
          cert_file = "/var/lib/probectl-agent/identity/cert.pem"
          key_file  = "/var/lib/probectl-agent/identity/key.pem"
          ca_file   = local.ca
        }
        identity = { server = var.vantage.enrollment_url }
        agent = {
          hostname = var.vantage.name
          labels = {
            site         = var.vantage.site
            region       = var.vantage.region
            network_role = "cloud"
            provider     = var.cloud
          }
        }
      })
    }
  }
  references = {
    aws   = "^arn:aws(-[a-z]+)*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$"
    azure = "^https://[A-Za-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+$"
    gcp   = "^[a-z][a-z0-9-]{4,28}[a-z0-9]:[A-Za-z0-9_-]{1,255}$"
  }
}

output "cloud_config" {
  description = "Non-secret cloud-init user data for a prepared probectl canary image."
  value = "#cloud-config\n${yamlencode({
    write_files = [for path, entry in local.files : merge(entry, { path = path, owner = "root:root" })]
    runcmd = [[
      local.enroll, var.cloud, var.secret_reference, var.vantage.tenant_id,
      var.vantage.enrollment_url, var.vantage.name, var.vantage.region, var.azure_client_id,
    ]]
  })}"

  precondition {
    condition     = can(regex(local.references[var.cloud], var.secret_reference))
    error_message = "Supply an exact secret reference for this cloud. The enrollment token itself is never a Terraform input."
  }

  precondition {
    condition     = var.cloud == "azure" ? can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.azure_client_id)) : var.azure_client_id == ""
    error_message = "Azure requires the VM's managed identity client ID. Other clouds use their instance identity."
  }
}
