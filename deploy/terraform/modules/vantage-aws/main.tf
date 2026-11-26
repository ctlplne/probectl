# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
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
  description = "Prepared AMI, instance type, and existing subnet and security groups."
  type = object({
    ami_id             = string
    instance_type      = string
    subnet_id          = string
    security_group_ids = set(string)
  })

  validation {
    condition     = length(var.placement.security_group_ids) > 0
    error_message = "Supply the VPC security groups for this vantage."
  }
}

variable "enrollment_secret_arn" {
  description = "Complete ARN of the existing Secrets Manager join secret, using the AWS-managed Secrets Manager key."
  type        = string
}

module "bootstrap" {
  source           = "../vantage-bootstrap"
  vantage          = var.vantage
  cloud            = "aws"
  secret_reference = var.enrollment_secret_arn
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_subnet" "vantage" {
  region = var.vantage.region
  id     = var.placement.subnet_id
}

resource "aws_iam_role" "vantage" {
  name_prefix = "probectl-vantage-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.${data.aws_partition.current.dns_suffix}" }
    }]
  })
}

resource "aws_iam_role_policy" "enrollment" {
  name = "probectl-vantage-enrollment"
  role = aws_iam_role.vantage.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = var.enrollment_secret_arn
    }]
  })

  lifecycle {
    precondition {
      condition = startswith(
        var.enrollment_secret_arn,
        "arn:${data.aws_partition.current.partition}:secretsmanager:${var.vantage.region}:${data.aws_caller_identity.current.account_id}:secret:",
      ) && can(regex("^arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.enrollment_secret_arn))
      error_message = "The exact enrollment secret ARN must belong to this AWS account and vantage region."
    }
  }
}

resource "aws_iam_instance_profile" "vantage" {
  name_prefix = "probectl-vantage-"
  role        = aws_iam_role.vantage.name
}

resource "aws_instance" "vantage" {
  region                      = var.vantage.region
  ami                         = var.placement.ami_id
  instance_type               = var.placement.instance_type
  subnet_id                   = data.aws_subnet.vantage.id
  vpc_security_group_ids      = var.placement.security_group_ids
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.vantage.name
  user_data                   = module.bootstrap.cloud_config
  user_data_replace_on_change = true
  tags                        = { Name = var.vantage.name }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  lifecycle {
    precondition {
      condition     = !data.aws_subnet.vantage.assign_ipv6_address_on_creation
      error_message = "The vantage subnet must not automatically assign public IPv6 addresses."
    }

    precondition {
      condition     = length(module.bootstrap.cloud_config) <= 16384
      error_message = "The canary configuration exceeds EC2's 16 KiB user-data limit."
    }
  }

  depends_on = [aws_iam_role_policy.enrollment]
}

output "instance_id" {
  description = "Cloud identifier of the vantage VM."
  value       = aws_instance.vantage.id
}
