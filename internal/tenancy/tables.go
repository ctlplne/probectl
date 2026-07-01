// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenancy

import "sort"

type providerOwnedKind uint8

const (
	providerTenantTable providerOwnedKind = iota
	providerGlobalTable
)

// Tenant-owned-table vocabulary (S-T2/S-T5): the set of tables that hold
// tenant data is derived LIVE from information_schema (any public table with
// a tenant_id column) MINUS this provider-owned deny list. Most entries carry
// tenant_id but belong to the provider plane (billing/branding/break-glass/
// lifecycle records ABOUT tenants); global entries are included so callers
// have one vocabulary for tables that must never enter tenant silos. Shared by
// the silo provisioner (ee) and the core
// tenant-lifecycle engine so the two can never disagree about what counts as
// the tenant's data.
var providerOwnedTables = map[string]providerOwnedKind{
	"break_glass_grants": providerTenantTable,
	"usage_records":      providerTenantTable,
	"tenant_quotas":      providerTenantTable,
	"tenant_branding":    providerTenantTable,
	"tenant_retention":   providerTenantTable,
	"tenant_keys":        providerTenantTable,
	"tenant_fairness":    providerTenantTable,
	"tenant_governance":  providerTenantTable,
	"cluster_state":      providerGlobalTable,
}

// ProviderOwnedTable reports whether a tenant_id-bearing table is
// provider-plane data rather than tenant-owned.
func ProviderOwnedTable(name string) bool {
	_, ok := providerOwnedTables[name]
	return ok
}

// ProviderOwnedTenantTables returns provider-plane tables that carry tenant_id.
// These are provider rows ABOUT a tenant, so verifiable erasure deletes them
// via the provider role after tenant-owned data is gone.
func ProviderOwnedTenantTables() []string {
	out := make([]string, 0, len(providerOwnedTables))
	for name, kind := range providerOwnedTables {
		if kind == providerTenantTable {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// FilterTenantOwned drops provider-owned names from a table list.
func FilterTenantOwned(tables []string) []string {
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		if !ProviderOwnedTable(t) {
			out = append(out, t)
		}
	}
	return out
}
