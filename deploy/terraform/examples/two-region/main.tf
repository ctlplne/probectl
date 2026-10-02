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

  # AUTHZ-04: the ingress controller/LB CIDRs the auth throttle trusts.
  # Override to match this region's controller pod network.
  trusted_proxies = ["10.244.0.0/16"]

  set_values = {
    "control.extraEnv.PROBECTL_REGION"           = var.region_a.name
    "control.extraEnv.PROBECTL_REGIONS"          = local.regions_csv
    "control.extraEnv.PROBECTL_REPLICATION_MODE" = "sync"
    "control.extraEnv.PROBECTL_RPO_SECONDS"      = "0"
    "control.extraEnv.PROBECTL_RTO_SECONDS"      = "60"
    "control.extraEnv.PROBECTL_RESIDENCY"        = var.region_a.name
    # PLAT-02: a multi-replica (multiregion) deployment is read-coherent only on
    # SHARED durable backends. These point at the in-cluster services each region
    # runs; override with your real endpoints. The chart refuses to render
    # replicaCount>1 without them.
    "control.extraEnv.PROBECTL_BUS_MODE"           = "kafka"
    "control.extraEnv.PROBECTL_BUS_BROKERS"        = "kafka.probectl.svc:9093"
    "control.extraEnv.PROBECTL_TSDB_MODE"          = "prometheus"
    "control.extraEnv.PROBECTL_TSDB_URL"           = "https://prometheus.probectl.svc:9090"
    "control.extraEnv.PROBECTL_PATHSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_PATHSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_FLOWSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_FLOWSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_OTELSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_OTELSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_EBPFSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_EBPFSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_ENDPOINTSTORE_MODE" = "clickhouse"
    "control.extraEnv.PROBECTL_ENDPOINTSTORE_URL"  = "https://clickhouse.probectl.svc:8443"
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

  # AUTHZ-04: the ingress controller/LB CIDRs the auth throttle trusts.
  # Override to match this region's controller pod network.
  trusted_proxies = ["10.244.0.0/16"]

  set_values = {
    "control.extraEnv.PROBECTL_REGION"           = var.region_b.name
    "control.extraEnv.PROBECTL_REGIONS"          = local.regions_csv
    "control.extraEnv.PROBECTL_REPLICATION_MODE" = "sync"
    "control.extraEnv.PROBECTL_RPO_SECONDS"      = "0"
    "control.extraEnv.PROBECTL_RTO_SECONDS"      = "60"
    "control.extraEnv.PROBECTL_RESIDENCY"        = var.region_b.name
    # PLAT-02: a multi-replica (multiregion) deployment is read-coherent only on
    # SHARED durable backends. These point at the in-cluster services each region
    # runs; override with your real endpoints. The chart refuses to render
    # replicaCount>1 without them.
    "control.extraEnv.PROBECTL_BUS_MODE"           = "kafka"
    "control.extraEnv.PROBECTL_BUS_BROKERS"        = "kafka.probectl.svc:9093"
    "control.extraEnv.PROBECTL_TSDB_MODE"          = "prometheus"
    "control.extraEnv.PROBECTL_TSDB_URL"           = "https://prometheus.probectl.svc:9090"
    "control.extraEnv.PROBECTL_PATHSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_PATHSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_FLOWSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_FLOWSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_OTELSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_OTELSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_EBPFSTORE_MODE"     = "clickhouse"
    "control.extraEnv.PROBECTL_EBPFSTORE_URL"      = "https://clickhouse.probectl.svc:8443"
    "control.extraEnv.PROBECTL_ENDPOINTSTORE_MODE" = "clickhouse"
    "control.extraEnv.PROBECTL_ENDPOINTSTORE_URL"  = "https://clickhouse.probectl.svc:8443"
  }
}
