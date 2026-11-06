// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// Restore same-tenant route references after LIKE on provision and catch-up.
func bgpRoutingStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	q := quoteIdent(schema)
	var plan []string
	for _, key := range []struct{ child, name, columns, parent, parentColumns string }{
		{"bgp_routing_views", "fx5_route_view_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_routing_views", "fx5_route_view_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id"},
		{"bgp_routing_views", "fx5_route_view_router_fk", "tenant_id,context_id,router_id,router_kind", "entities", "tenant_id,context_id,id,kind"},
		{"bgp_routing_views", "fx5_route_view_agent_context_fk", "tenant_id,collector_agent_id,context_id", "entity_agent_contexts", "tenant_id,agent_id,context_id"},
		{"bgp_routing_views", "fx5_route_view_source_fk", "tenant_id,collector_agent_id,binding_kind,source_ref", "entity_source_contexts", "tenant_id,agent_id,source_kind,source_ref"},
		{"bgp_routing_entries", "fx5_route_entry_view_fk", "tenant_id,context_id,view_id,generation,afi,safi", "bgp_routing_views", "tenant_id,context_id,id,generation,afi,safi"},
	} {
		if !owned[key.child] {
			continue
		}
		child, parent := q+"."+quoteIdent(key.child), q+"."+quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = "public.tenants"
		}
		plan = append(plan, fmt.Sprintf(`DO $fx5_route_fk$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
 ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE CASCADE;
END IF;
END $fx5_route_fk$`, quoteLiteral(child), quoteLiteral(key.name), child, quoteIdent(key.name), key.columns, parent, key.parentColumns))
	}
	return plan
}
