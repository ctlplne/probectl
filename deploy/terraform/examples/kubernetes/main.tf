# Example root: deploy probectl onto any Kubernetes cluster with the probectl module.
# Cloud-agnostic — point the providers at any kubeconfig (EKS/GKE/AKS/OpenShift/
# k3s). Provision the cluster + managed Postgres with your cloud's modules, then
# pass the DSN in via database_url.

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
  config_path = var.kubeconfig
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig
  }
}

module "probectl" {
  source = "../../modules/probectl"

  # Local chart in this repo (so the size presets resolve).
  chart = "../../../helm/probectl"

  namespace          = "probectl"
  size               = var.size
  ingress_host       = var.ingress_host
  ingress_tls_secret = var.ingress_tls_secret

  database_url     = var.database_url
  envelope_key     = var.envelope_key
  session_hmac_key = var.session_hmac_key
}

output "namespace" {
  value = module.probectl.namespace
}

output "release" {
  value = module.probectl.release_name
}

output "app_version" {
  value = module.probectl.app_version
}
