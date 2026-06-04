output "namespace" {
  description = "Namespace the release is deployed in."
  value       = local.namespace
}

output "release_name" {
  description = "Helm release name."
  value       = helm_release.probectl.name
}

output "release_status" {
  description = "Helm release status."
  value       = helm_release.probectl.status
}

output "chart_version" {
  description = "Resolved chart version."
  value       = helm_release.probectl.metadata[0].version
}

output "app_version" {
  description = "Deployed app (probectl) version."
  value       = helm_release.probectl.metadata[0].app_version
}

output "secret_name" {
  description = "Name of the Kubernetes Secret holding the sensitive config."
  value       = kubernetes_secret.probectl.metadata[0].name
}
