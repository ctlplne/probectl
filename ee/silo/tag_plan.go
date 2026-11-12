// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"fmt"
	"strings"
)

// tagStoragePlan restores the FKs and statement triggers that CREATE TABLE
// LIKE cannot copy. A new silo adds FK target indexes on its empty tables;
// an old silo builds them concurrently before its catch-up transaction.
func tagStoragePlan(schema string, tables []string, addIndexes bool) []string {
	owned := make(map[string]bool, len(tables))
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	for _, table := range []string{
		"entity_contexts", "entity_path_test_contexts", "entity_test_contexts",
		"entity_agent_contexts", "entity_source_contexts", "entities", "tests",
		"tenant_tag_revisions", "tenant_tag_definitions",
		"tenant_tag_assignments", "tenant_tag_rules",
	} {
		if !owned[table] {
			return nil
		}
	}
	tenantID := schemaTenantID(schema)
	if tenantID == "" {
		return nil
	}
	q := quoteIdent(schema)
	plan := []string{"SELECT set_config('probectl.tenant_id', " + quoteLiteral(tenantID) + ", true)"}
	if addIndexes {
		// New silos copy the current public shape into empty tables. An old
		// silo builds these targets CONCURRENTLY before CatchUpPlan starts.
		plan = append(plan,
			`CREATE UNIQUE INDEX IF NOT EXISTS "entities_tenant_context_id_kind_uidx" ON `+
				q+`."entities" (tenant_id, context_id, id, kind)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS "entity_sources_tenant_context_identity_uidx" ON `+
				q+`."entity_source_contexts" (tenant_id, context_id, agent_id, source_kind, source_ref)`)
		if owned["entity_evidence"] {
			plan = append(plan, `CREATE INDEX IF NOT EXISTS "entity_evidence_tenant_source_latest_idx" ON `+
				q+`."entity_evidence" (tenant_id,context_id,agent_id,source_kind,configured_ref,observed_at DESC,id)`)
		}
	}
	plan = append(plan, `INSERT INTO `+q+`."entity_test_contexts" (tenant_id,test_id,context_id)
SELECT tenant_id,test_id,context_id FROM `+q+`."entity_path_test_contexts"
WHERE tenant_id=`+quoteLiteral(tenantID)+`::uuid
ON CONFLICT (tenant_id,test_id) DO NOTHING`)
	type foreignKey struct {
		child, name, columns, parent, parentColumns, action string
	}
	keys := []foreignKey{
		{"entity_test_contexts", "fx3_test_context_tenant_fk", "tenant_id", "public.tenants", "id", "ON DELETE CASCADE"},
		{"entity_test_contexts", "fx3_test_context_test_fk", "tenant_id,test_id", "tests", "tenant_id,id", "ON DELETE CASCADE"},
		{"entity_test_contexts", "fx3_test_context_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id", "ON DELETE CASCADE"},
		{"entity_path_test_contexts", "fx3_path_general_context_fk", "tenant_id,test_id,context_id", "entity_test_contexts", "tenant_id,test_id,context_id", "ON DELETE CASCADE"},
		{"tenant_tag_revisions", "fx3_tag_revision_tenant_fk", "tenant_id", "public.tenants", "id", "ON DELETE CASCADE"},
		{"tenant_tag_definitions", "fx3_tag_definition_tenant_fk", "tenant_id", "public.tenants", "id", "ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_tag_fk", "tenant_id,tag_id", "tenant_tag_definitions", "tenant_id,id", "ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id", "ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_entity_fk", "tenant_id,context_id,entity_id,entity_kind", "entities", "tenant_id,context_id,id,kind", "ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_agent_fk", "tenant_id,agent_id,context_id", "entity_agent_contexts", "tenant_id,agent_id,context_id", "ON UPDATE RESTRICT ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_test_fk", "tenant_id,test_id,context_id", "entity_test_contexts", "tenant_id,test_id,context_id", "ON DELETE CASCADE"},
		{"tenant_tag_assignments", "fx3_tag_assignment_exporter_fk", "tenant_id,context_id,exporter_agent_id,exporter_source_kind,exporter_source_ref", "entity_source_contexts", "tenant_id,context_id,agent_id,source_kind,source_ref", "ON UPDATE RESTRICT ON DELETE CASCADE"},
		{"tenant_tag_rules", "fx3_tag_rule_tag_fk", "tenant_id,tag_id", "tenant_tag_definitions", "tenant_id,id", "ON DELETE CASCADE"},
		{"tenant_tag_rules", "fx3_tag_rule_context_fk", "tenant_id,context_id", "entity_contexts", "tenant_id,id", "ON DELETE CASCADE"},
	}
	for _, key := range keys {
		child := q + "." + quoteIdent(key.child)
		parent := q + "." + quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = `public.tenants`
		}
		plan = append(plan, fmt.Sprintf(`DO $fx3_silo_fk$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
        ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) %s;
    END IF;
END $fx3_silo_fk$`, quoteLiteral(child), quoteLiteral(key.name), child,
			quoteIdent(key.name), key.columns, parent, key.parentColumns, key.action))
	}
	// LIKE omits triggers. Keep target edits, source ownership changes and tag
	// revisions inside the physical silo; shared functions use TG_TABLE_SCHEMA.
	path := q + `."tests"`
	plan = append(plan,
		"DROP TRIGGER IF EXISTS entity_test_retarget ON "+path,
		"CREATE TRIGGER entity_test_retarget AFTER UPDATE OF target ON "+path+
			" FOR EACH ROW EXECUTE FUNCTION public.entity_clear_test_context_on_retarget()",
		"ALTER TABLE "+path+" ENABLE ALWAYS TRIGGER entity_test_retarget",
	)
	for _, table := range []string{
		"entity_test_contexts", "entity_agent_contexts",
		"entity_source_contexts", "tenant_tag_definitions",
		"tenant_tag_assignments", "tenant_tag_rules",
	} {
		child := q + "." + quoteIdent(table)
		for _, event := range []struct{ name, transition string }{
			{"INSERT", "NEW TABLE AS tag_new_rows"},
			{"UPDATE", "NEW TABLE AS tag_new_rows"},
			{"DELETE", "OLD TABLE AS tag_old_rows"},
		} {
			name := "tenant_tag_revision_" + strings.ToLower(event.name)
			plan = append(plan,
				"DROP TRIGGER IF EXISTS "+quoteIdent(name)+" ON "+child,
				"CREATE TRIGGER "+quoteIdent(name)+" AFTER "+event.name+
					" ON "+child+" REFERENCING "+event.transition+
					" FOR EACH STATEMENT EXECUTE FUNCTION public.tenant_tags_bump_revision()",
				"ALTER TABLE "+child+" ENABLE ALWAYS TRIGGER "+quoteIdent(name))
		}
	}
	plan = append(plan, tagValueConstraintPlan(schema)...)
	return append(plan, tagRuleMatchConstraintPlan(schema)...)
}
