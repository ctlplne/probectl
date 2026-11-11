// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// LIKE does not copy FKs or triggers. Repair both for newly provisioned and
// caught-up silos; a counter witness must never refer to another schema's source.
func deviceCounterStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	q := quoteIdent(schema)
	var plan []string
	if owned["entity_source_contexts"] && owned["device_counter_capture_sources"] {
		plan = append(plan, `CREATE UNIQUE INDEX IF NOT EXISTS entity_sources_tenant_context_identity_uidx ON `+q+`."entity_source_contexts" (tenant_id,context_id,agent_id,source_kind,source_ref)`)
	}
	for _, key := range []struct{ child, name, columns, parent, parentColumns string }{
		{"device_counter_captures", "fx6_counter_capture_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"device_counter_capture_sources", "fx6_counter_source_capture_fk", "tenant_id,capture_key", "device_counter_captures", "tenant_id,capture_key"},
		{"device_counter_capture_sources", "fx6_counter_source_device_fk", "tenant_id,context_id,device_id,device_kind", "entities", "tenant_id,context_id,id,kind"},
		{"device_counter_capture_sources", "fx6_counter_source_assignment_fk", "tenant_id,context_id,agent_id,source_kind,source_ref", "entity_source_contexts", "tenant_id,context_id,agent_id,source_kind,source_ref"},
	} {
		if !owned[key.child] {
			continue
		}
		child, parent := q+"."+quoteIdent(key.child), q+"."+quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = "public.tenants"
		}
		plan = append(plan, fmt.Sprintf(`DO $fx6_counter_fk$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
 ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE CASCADE;
END IF;
END $fx6_counter_fk$`, quoteLiteral(child), quoteLiteral(key.name), child, quoteIdent(key.name), key.columns, parent, key.parentColumns))
	}
	if owned["flow_snapshot_epochs"] {
		child := q + `."flow_snapshot_epochs"`
		plan = append(plan,
			"ALTER TABLE "+child+" ADD COLUMN IF NOT EXISTS observation_erasing boolean NOT NULL DEFAULT false",
			fmt.Sprintf(`DO $counter_erasure_shape$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname='counter_observation_erasure_shape') THEN
 ALTER TABLE %s ADD CONSTRAINT counter_observation_erasure_shape CHECK (NOT observation_erasing OR invalidating);
END IF;
END; $counter_erasure_shape$`, quoteLiteral(child), child),
			"DROP TRIGGER IF EXISTS source_observation_fence ON "+child,
			"CREATE TRIGGER source_observation_fence BEFORE INSERT OR UPDATE ON "+child+" FOR EACH ROW EXECUTE FUNCTION public.probectl_source_observation_fence()",
			"ALTER TABLE "+child+" ENABLE ALWAYS TRIGGER source_observation_fence",
		)
	}
	return plan
}
