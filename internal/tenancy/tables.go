package tenancy

// Tenant-owned-table vocabulary (S-T2/S-T5): the set of tables that hold
// tenant data is derived LIVE from information_schema (any public table with
// a tenant_id column) MINUS this provider-owned deny list — tables that carry
// tenant_id but belong to the provider plane (billing/branding/break-glass
// records ABOUT tenants). Shared by the silo provisioner (ee) and the core
// tenant-lifecycle engine so the two can never disagree about what counts as
// the tenant\'s data.
var providerOwnedTables = map[string]bool{
	"break_glass_grants": true,
	"usage_records":      true,
	"tenant_quotas":      true,
	"tenant_branding":    true,
	"tenant_keys":        true,
	"tenant_fairness":    true,
}

// ProviderOwnedTable reports whether a tenant_id-bearing table is
// provider-plane data rather than tenant-owned.
func ProviderOwnedTable(name string) bool { return providerOwnedTables[name] }

// FilterTenantOwned drops provider-owned names from a table list.
func FilterTenantOwned(tables []string) []string {
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		if !providerOwnedTables[t] {
			out = append(out, t)
		}
	}
	return out
}
