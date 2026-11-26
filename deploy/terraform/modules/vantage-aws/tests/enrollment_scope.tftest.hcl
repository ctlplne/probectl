# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }

  mock_data "aws_subnet" {
    defaults = { assign_ipv6_address_on_creation = false }
  }
}

variables {
  vantage = {
    tenant_id      = "00000000-0000-4000-8000-000000000001"
    name           = "probe-eu-west"
    site           = "owner-cloud"
    region         = "eu-west-1"
    enrollment_url = "https://control.example:8443"
    agent_address  = "control.example:9443"
    control_ca_pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
  }
  placement = {
    ami_id             = "ami-0123456789abcdef0"
    instance_type      = "t3.small"
    subnet_id          = "subnet-0123456789abcdef0"
    security_group_ids = ["sg-0123456789abcdef0"]
  }
  enrollment_secret_arn = join(":", ["arn", "aws", "secretsmanager", "eu-west-1", "123456789012", "secret", "owned-join-A1b2C3"])
}

run "private_vantage_reads_one_secret" {
  command = plan

  assert {
    condition = jsondecode(aws_iam_role_policy.enrollment.policy).Statement == [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = var.enrollment_secret_arn
    }]
    error_message = "The EC2 role must grant only GetSecretValue on the exact enrollment ARN."
  }

  assert {
    condition     = !aws_instance.vantage.associate_public_ip_address && one(aws_instance.vantage.metadata_options).http_tokens == "required"
    error_message = "The EC2 instance requires private addressing and IMDSv2."
  }
}

run "reject_other_account_secret" {
  command = plan

  variables {
    enrollment_secret_arn = join(":", ["arn", "aws", "secretsmanager", "eu-west-1", "210987654321", "secret", "other-join-A1b2C3"])
  }

  expect_failures = [aws_iam_role_policy.enrollment]
}
