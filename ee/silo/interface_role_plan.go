// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// LIKE copies CHECKs/indexes, not foreign keys. A role configuration copy must
// reference its own context/interface table, including the interface-kind key.
func interfaceRoleStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	q := quoteIdent(schema)
	var plan []string
	for _, key := range []struct{ child, name, columns, parent, parentColumns string }{
		{"interface_role_policies", "fx4_role_policy_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"interface_role_policies", "fx4_role_policy_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id"},
		{"interface_role_overrides", "fx4_role_override_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"interface_role_overrides", "fx4_role_override_interface_fk", "tenant_id,context_id,interface_id,entity_kind", "entities", "tenant_id,context_id,id,kind"},
	} {
		if !owned[key.child] {
			continue
		}
		child, parent := q+"."+quoteIdent(key.child), q+"."+quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = "public.tenants"
		}
		plan = append(plan, fmt.Sprintf(`DO $fx4_role_fk$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
 ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE CASCADE;
END IF;
END $fx4_role_fk$`, quoteLiteral(child), quoteLiteral(key.name), child, quoteIdent(key.name), key.columns, parent, key.parentColumns))
	}
	return plan
}
