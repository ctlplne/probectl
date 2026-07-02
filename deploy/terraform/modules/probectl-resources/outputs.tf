output "resource_keys" {
  description = "Terraform resource keys applied through probectl api."
  value       = keys(terraform_data.probectl)
}

output "resource_count" {
  description = "Number of probectl API resources managed by this module."
  value       = length(terraform_data.probectl)
}
