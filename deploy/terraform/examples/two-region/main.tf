# Two-region probectl reference: the same hardened Helm chart is installed in
# two independent Kubernetes API failure domains. Durable metadata has one
# TLS-only global writer endpoint and one local read replica per region.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}

provider "kubernetes" {
  alias          = "region_a"
  config_path    = var.region_a.kubeconfig
  config_context = var.region_a.context
}

provider "helm" {
  alias = "region_a"
  kubernetes {
    config_path    = var.region_a.kubeconfig
    config_context = var.region_a.context
  }
}

provider "kubernetes" {
  alias          = "region_b"
  config_path    = var.region_b.kubeconfig
  config_context = var.region_b.context
}

provider "helm" {
  alias = "region_b"
  kubernetes {
    config_path    = var.region_b.kubeconfig
    config_context = var.region_b.context
  }
}

locals {
  regions_csv = "${var.region_a.name},${var.region_b.name}"
}

module "probectl_region_a" {
  source = "../../modules/probectl"
  providers = {
    helm       = helm.region_a
    kubernetes = kubernetes.region_a
  }

  chart        = "../../../helm/probectl"
  size         = "multiregion"
  release_name = "probectl-${var.region_a.name}"
  namespace    = "probectl"

  ingress_host                     = var.region_a.ingress_host
  ingress_tls_secret               = var.region_a.tls_secret
  ingress_backend_tls_trust_secret = var.region_a.backend_trust_secret
  image_repository                 = var.image_repository
  image_digest                     = var.image_digest

  database_url      = var.database_writer_url
  database_read_url = var.region_a.database_read_url
  envelope_key      = var.envelope_key
  session_hmac_key  = var.session_hmac_key

  set_values = {
    "control.extraEnv.PROBECTL_REGION"           = var.region_a.name
    "control.extraEnv.PROBECTL_REGIONS"          = local.regions_csv
    "control.extraEnv.PROBECTL_REPLICATION_MODE" = "sync"
    "control.extraEnv.PROBECTL_RPO_SECONDS"      = "0"
    "control.extraEnv.PROBECTL_RTO_SECONDS"      = "60"
    "control.extraEnv.PROBECTL_RESIDENCY"        = var.region_a.name
  }
}

module "probectl_region_b" {
  source = "../../modules/probectl"
  providers = {
    helm       = helm.region_b
    kubernetes = kubernetes.region_b
  }

  chart        = "../../../helm/probectl"
  size         = "multiregion"
  release_name = "probectl-${var.region_b.name}"
  namespace    = "probectl"

  ingress_host                     = var.region_b.ingress_host
  ingress_tls_secret               = var.region_b.tls_secret
  ingress_backend_tls_trust_secret = var.region_b.backend_trust_secret
  image_repository                 = var.image_repository
  image_digest                     = var.image_digest

  database_url      = var.database_writer_url
  database_read_url = var.region_b.database_read_url
  envelope_key      = var.envelope_key
  session_hmac_key  = var.session_hmac_key

  set_values = {
    "control.extraEnv.PROBECTL_REGION"           = var.region_b.name
    "control.extraEnv.PROBECTL_REGIONS"          = local.regions_csv
    "control.extraEnv.PROBECTL_REPLICATION_MODE" = "sync"
    "control.extraEnv.PROBECTL_RPO_SECONDS"      = "0"
    "control.extraEnv.PROBECTL_RTO_SECONDS"      = "60"
    "control.extraEnv.PROBECTL_RESIDENCY"        = var.region_b.name
  }
}
