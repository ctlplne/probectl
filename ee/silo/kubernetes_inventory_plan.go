// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// LIKE preserves the local indexes and checks. Restore foreign keys with
// both endpoints in the tenant's physical schema, for creation and catch-up.
func kubernetesInventoryStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	const source = "tenant_id,context_id,source_id"
	const generation = source + ",generation_id"
	const window = generation + ",window_index,object_kind"
	const object = window + ",object_uid"
	keys := []struct {
		child, parent, name, columns, parentColumns string
		deferred                                    bool
	}{
		{"kubernetes_inventory_sources", "entity_contexts", "k8s_inventory_source_context_fk", "tenant_id,context_id", "tenant_id,id", false},
		{"kubernetes_inventory_sources", "entity_agent_contexts", "k8s_inventory_source_assignment_fk", "tenant_id,agent_id,context_id", "tenant_id,agent_id,context_id", false},
		{"kubernetes_inventory_staging", "kubernetes_inventory_sources", "k8s_inventory_stage_source_fk", source, "tenant_id,context_id,id", false},
		{"kubernetes_inventory_stage_parts", "kubernetes_inventory_staging", "k8s_inventory_part_stage_fk", generation, generation, false},
		{"kubernetes_inventory_generations", "kubernetes_inventory_sources", "k8s_inventory_generation_source_fk", source, "tenant_id,context_id,id", false},
		{"kubernetes_inventory_windows", "kubernetes_inventory_generations", "k8s_inventory_window_generation_fk", generation, source + ",id", false},
		{"kubernetes_inventory_objects", "kubernetes_inventory_windows", "k8s_inventory_object_window_fk", window, window, false},
		{"kubernetes_inventory_addresses", "kubernetes_inventory_objects", "k8s_inventory_address_object_fk", object, object, true},
		{"kubernetes_inventory_relationships", "kubernetes_inventory_objects", "k8s_inventory_relationship_witness_fk", generation + ",window_index,witness_kind,witness_uid", object, true},
	}
	var plan []string
	for _, key := range keys {
		if !owned[key.child] || !owned[key.parent] {
			continue
		}
		child := quoteIdent(schema) + "." + quoteIdent(key.child)
		parent := quoteIdent(schema) + "." + quoteIdent(key.parent)
		policy := "ON DELETE CASCADE"
		if key.deferred {
			policy += " DEFERRABLE INITIALLY DEFERRED"
		}
		plan = append(plan, fmt.Sprintf(`DO $k8s_silo_fk$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
  ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) %s;
 END IF;
END $k8s_silo_fk$`, quoteLiteral(child), quoteLiteral(key.name), child, quoteIdent(key.name), key.columns, parent, key.parentColumns, policy))
	}
	return plan
}

func kubernetesInventoryRolePlan(quotedTable, table string) []string {
	plan := []string{
		"REVOKE ALL ON " + quotedTable + " FROM probectl_app",
		"REVOKE ALL ON " + quotedTable + " FROM probectl_provider",
		"GRANT SELECT, INSERT, DELETE ON " + quotedTable + " TO probectl_app",
	}
	switch table {
	case "kubernetes_inventory_sources":
		return append(plan, "GRANT UPDATE (closed_at) ON "+quotedTable+" TO probectl_app")
	case "kubernetes_inventory_staging":
		return append(plan, "GRANT UPDATE (next_part, appended_rows, appended_bytes) ON "+quotedTable+" TO probectl_app")
	default:
		return plan
	}
}
