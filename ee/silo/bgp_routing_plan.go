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
	if owned["entity_source_contexts"] && owned["bgp_public_snapshots"] {
		// A source assignment copied before the tag identity index existed
		// needs its exact key before the new snapshot FK can be installed.
		plan = append(plan, `CREATE UNIQUE INDEX IF NOT EXISTS entity_sources_tenant_context_identity_uidx ON `+q+`."entity_source_contexts" (tenant_id,context_id,agent_id,source_kind,source_ref)`)
	}
	for _, key := range []struct{ child, name, columns, parent, parentColumns string }{
		{"bgp_public_snapshots", "fx5_public_snapshot_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_public_snapshots", "fx5_public_snapshot_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id"},
		{"bgp_public_snapshots", "fx5_public_snapshot_source_fk", "tenant_id,context_id,collector_agent_id,source_kind,source_ref", "entity_source_contexts", "tenant_id,context_id,agent_id,source_kind,source_ref"},
		{"bgp_routing_views", "fx5_public_view_snapshot_fk", "tenant_id,context_id,public_snapshot_id,collector_agent_id,source_ref,sender_serial", "bgp_public_snapshots", "tenant_id,context_id,id,collector_agent_id,source_ref,sender_serial"},
		{"bgp_flow_capture_objects", "fx5_capture_object_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_flow_capture_receipts", "fx5_capture_receipt_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_flow_capture_intents", "fx5_capture_intent_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_flow_capture_intent_payloads", "fx5_capture_intent_payload_intent_fk", "tenant_id,flow_key", "bgp_flow_capture_intents", "tenant_id,flow_key"},
		{"bgp_flow_capture_intent_payloads", "fx5_capture_intent_payload_facts_fk", "tenant_id,facts_digest,facts_kind", "bgp_flow_capture_objects", "tenant_id,digest,kind"},
		{"bgp_flow_capture_intent_payloads", "fx5_capture_intent_payload_clocks_fk", "tenant_id,clocks_digest,clocks_kind", "bgp_flow_capture_objects", "tenant_id,digest,kind"},
		{"bgp_flow_capture_payloads", "fx5_capture_payload_receipt_fk", "tenant_id,flow_key", "bgp_flow_capture_receipts", "tenant_id,flow_key"},
		{"bgp_flow_capture_payloads", "fx5_capture_payload_facts_fk", "tenant_id,facts_digest,facts_kind", "bgp_flow_capture_objects", "tenant_id,digest,kind"},
		{"bgp_flow_capture_payloads", "fx5_capture_payload_clocks_fk", "tenant_id,clocks_digest,clocks_kind", "bgp_flow_capture_objects", "tenant_id,digest,kind"},
		{"bgp_routing_views", "fx5_route_view_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"bgp_routing_views", "fx5_route_view_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id"},
		{"bgp_routing_views", "fx5_route_view_router_fk", "tenant_id,context_id,router_id,router_kind", "entities", "tenant_id,context_id,id,kind"},
		{"bgp_routing_views", "fx5_route_view_collector_context_fk", "tenant_id,collector_agent_id,collector_context_id", "entity_agent_contexts", "tenant_id,agent_id,context_id"},
		{"bgp_routing_views", "fx5_route_view_source_fk", "tenant_id,collector_agent_id,binding_kind,source_ref", "entity_source_contexts", "tenant_id,agent_id,source_kind,source_ref"},
		{"bgp_routing_entries", "fx5_route_entry_view_fk", "tenant_id,context_id,view_id,generation,afi,safi", "bgp_routing_views", "tenant_id,context_id,id,generation,afi,safi"},
	} {
		if !owned[key.child] || (key.parent == "bgp_public_snapshots" && !owned[key.parent]) {
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
	if owned["bgp_routing_views"] {
		plan = append(plan, routingBindingChecksPlan(q+"."+quoteIdent("bgp_routing_views"))...)
		if owned["bgp_public_snapshots"] {
			plan = append(plan, `CREATE UNIQUE INDEX IF NOT EXISTS bgp_routing_views_public_slot_idx ON `+q+`."bgp_routing_views" (tenant_id,context_id,public_snapshot_id,peer_key,afi,safi) WHERE public_snapshot_id IS NOT NULL`)
		}
	}
	if owned["entity_source_contexts"] {
		plan = append(plan, publicSourceChecksPlan(q+"."+quoteIdent("entity_source_contexts")))
	}
	return plan
}

// LIKE copies checks for new silos. Catch-up must also replace the old source
// family check and enforce the public source shape in existing physical silos.
func publicSourceChecksPlan(child string) string {
	return fmt.Sprintf(`DO $fx5_public_source_checks$
DECLARE check_name text; definition text;
BEGIN
 FOREACH check_name IN ARRAY ARRAY['entity_source_contexts_source_kind_check','fx5_public_source_shape'] LOOP
  SELECT pg_get_constraintdef(oid) INTO definition FROM pg_constraint
   WHERE conrelid='public.entity_source_contexts'::regclass AND conname=check_name AND contype='c';
  IF definition IS NULL THEN RAISE EXCEPTION 'public routing source constraint is missing'; END IF;
  EXECUTE 'ALTER TABLE ' || %s || ' DROP CONSTRAINT IF EXISTS ' || quote_ident(check_name);
  EXECUTE 'ALTER TABLE ' || %s || ' ADD CONSTRAINT ' || quote_ident(check_name) || ' ' || definition;
 END LOOP;
END $fx5_public_source_checks$`, quoteLiteral(child), quoteLiteral(child))
}

// Existing silo copies need the expanded checks as well as the new columns.
// Copy only these named CHECKs from the migrated public table, retaining all
// existing state/clock/tenant constraints and restoring schema-local FKs above.
func routingBindingChecksPlan(child string) []string {
	return []string{
		"ALTER TABLE " + child + " DROP CONSTRAINT IF EXISTS fx5_route_view_agent_context_fk",
		"ALTER TABLE " + child + " DROP CONSTRAINT IF EXISTS bgp_routing_views_view_kind_check",
		fmt.Sprintf(`DO $fx5_route_binding_checks$ DECLARE entry record; BEGIN
FOR entry IN SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
 WHERE conrelid='public.bgp_routing_views'::regclass AND contype='c'
 AND conname IN ('fx5_route_view_kind_check','fx5_route_view_routing_selection_check','fx5_public_view_snapshot_shape') LOOP
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=entry.conname) THEN
  EXECUTE 'ALTER TABLE ' || %s || ' ADD CONSTRAINT ' || quote_ident(entry.conname) || ' ' || entry.definition;
 END IF;
END LOOP;
END $fx5_route_binding_checks$`, quoteLiteral(child), quoteLiteral(child)),
	}
}
