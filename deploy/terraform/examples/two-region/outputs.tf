output "regions" {
  description = "Non-secret deployed release identity in each failure domain."
  value = {
    (var.region_a.name) = {
      namespace = module.probectl_region_a.namespace
      release   = module.probectl_region_a.release_name
      version   = module.probectl_region_a.app_version
    }
    (var.region_b.name) = {
      namespace = module.probectl_region_b.namespace
      release   = module.probectl_region_b.release_name
      version   = module.probectl_region_b.app_version
    }
  }
}
