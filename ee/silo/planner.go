// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"github.com/ctlplne/probectl/internal/tenancy"

	"fmt"
	"sort"
	"strings"
)

// The Postgres schema planner: PURE functions from catalog facts to ordered
// DDL, so the provisioning logic is unit-testable without a database and the
// executor stays a dumb loop.
//
// What counts as tenant-owned: every public table with a tenant_id column,
// MINUS the provider-scoped deny list (break_glass_grants carries tenant_id
// but belongs to the provider plane, never inside a tenant's silo). Deriving
// the set from the live catalog makes provisioning drift-proof by
// construction: a new tenant-owned table in a later migration is picked up by
// the next provision/catch-up with no list to forget to update.

// The provider-owned deny list lives in CORE (internal/tenancy) since S-T5,
// shared with the tenant-lifecycle engine so silo provisioning and verifiable
// deletion can never disagree about what counts as tenant data.

// Catalog is the slice of information_schema facts the planner consumes.
type Catalog struct {
	// TenantTables: public tables that carry a tenant_id column.
	TenantTables []string
	// Columns: table -> ordered column declarations ("name type [NOT NULL] [DEFAULT ...]").
	// Used only by the catch-up diff (CREATE uses LIKE INCLUDING ALL).
	Columns map[string][]Column
	// SchemaColumns: the silo schema's current columns per table (catch-up diff).
	SchemaColumns map[string][]Column
	// SchemaTables: tables already present in the silo schema.
	SchemaTables []string
}

// Column is one column's catalog identity.
type Column struct {
	Name     string
	DataType string // information_schema-rendered type, used verbatim in ADD COLUMN
	NotNull  bool
	Default  string // "" = none
}

// TenantOwned filters (via the shared core deny list) and sorts the
// tenant-owned table set.
func TenantOwned(tables []string) []string {
	filtered := tenancy.FilterTenantOwned(tables)
	out := make([]string, 0, len(filtered))
	for _, table := range filtered {
		// IR attribution heads are signed, hash-only provider control state.
		// Ciphertext records are physically siloed; the single public head is
		// tenant-GUC RLS scoped and deliberately not copied into each schema.
		if table != "ir_attribution_heads" {
			out = append(out, table)
		}
	}
	sort.Strings(out)
	return out
}

// quoteIdent renders a safe double-quoted identifier.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func quoteLiteral(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// ProvisionPlan renders the ordered DDL that creates (or completes — every
// statement is idempotent) a tenant's silo schema:
//
//  1. CREATE SCHEMA
//  2. per tenant-owned table: CREATE TABLE (LIKE public.t INCLUDING ALL) —
//     columns, defaults, indexes, constraints; RLS policies do NOT copy, so
//  3. ENABLE+FORCE RLS + recreate both the tenant_isolation policy and a
//     RESTRICTIVE schema-tenant guard. Every row must match the caller GUC AND
//     the immutable tenant UUID encoded by the physical schema; an extra
//     permissive legacy policy therefore cannot OR-open a silo.
//  4. grants for the app role (USAGE on the schema; DML on the tables)
//  5. schema USAGE for the provider plane (for the audit_subject_erasures /
//     ir_attribution_records capabilities it still holds directly). audit_events
//     carries NO direct provider grant (AUD-04): retention/erase run through the
//     public SECURITY DEFINER functions. The app role keeps audit_events
//     append-only (SELECT/INSERT only).
func ProvisionPlan(schema string, tenantTables []string) []string {
	q := quoteIdent(schema)
	plan := []string{
		"CREATE SCHEMA IF NOT EXISTS " + q,
		"GRANT USAGE ON SCHEMA " + q + " TO probectl_app",
		"GRANT USAGE ON SCHEMA " + q + " TO probectl_provider",
	}
	for _, t := range TenantOwned(tenantTables) {
		plan = append(plan, provisionTablePlan(schema, t)...)
	}
	plan = append(plan, entityRegistryForeignKeyPlan(schema, tenantTables)...)
	return plan
}

// CREATE TABLE LIKE INCLUDING ALL copies CHECK/PK/UNIQUE but not foreign keys.
// FX-2's tenant/context composite references must therefore be installed
// after all tenant tables have been copied into a physical silo. This also
// repairs the FX-2b import references. Each statement is idempotent for both
// provision and catch-up.
func entityRegistryForeignKeyPlan(schema string, tables []string) []string {
	owned := make(map[string]bool, len(tables))
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	for _, table := range []string{"entity_contexts", "entity_path_test_contexts", "entity_agent_contexts", "entity_source_contexts", "entities", "entity_evidence", "entity_links", "tests", "incidents", "incident_signals", "incident_correlation_overrides"} {
		if !owned[table] {
			return nil // Registry not yet present in this product version.
		}
	}
	type foreignKey struct {
		table, name, columns, parent, parentColumns string
	}
	keys := []foreignKey{
		{"entity_contexts", "fx2_context_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"entity_path_test_contexts", "fx2_path_test_fk", "tenant_id, test_id", "tests", "tenant_id, id"},
		{"entity_path_test_contexts", "fx2_path_context_fk", "tenant_id, context_id", "entity_contexts", "tenant_id, id"},
		{"entity_agent_contexts", "fx2_agent_context_fk", "tenant_id, context_id", "entity_contexts", "tenant_id, id"},
		{"entity_source_contexts", "fx2_source_context_fk", "tenant_id, context_id", "entity_contexts", "tenant_id, id"},
		{"entity_source_contexts", "fx2_source_agent_context_fk", "tenant_id, agent_id, context_id", "entity_agent_contexts", "tenant_id, agent_id, context_id"},
		{"entity_source_contexts", "fx2_source_anchor_fk", "tenant_id, context_id, anchor_entity_id", "entities", "tenant_id, context_id, id"},
		{"entities", "fx2_entity_context_fk", "tenant_id, context_id", "entity_contexts", "tenant_id, id"},
		{"entities", "fx2_interface_parent_fk", "tenant_id, context_id, parent_entity_id", "entities", "tenant_id, context_id, id"},
		{"entity_evidence", "fx2_evidence_entity_fk", "tenant_id, context_id, entity_id", "entities", "tenant_id, context_id, id"},
		{"entity_evidence", "fx2_evidence_support_fk", "tenant_id, context_id, support_evidence_id", "entity_evidence", "tenant_id, context_id, id"},
		{"entity_links", "fx2_link_from_fk", "tenant_id, context_id, from_entity_id", "entities", "tenant_id, context_id, id"},
		{"entity_links", "fx2_link_to_fk", "tenant_id, context_id, to_entity_id", "entities", "tenant_id, context_id, id"},
		{"entity_links", "fx2_link_evidence_fk", "tenant_id, context_id, evidence_id", "entity_evidence", "tenant_id, context_id, id"},
		{"incidents", "fx2_incident_entity_fk", "tenant_id, entity_context_id, entity_id", "entities", "tenant_id, context_id, id"},
		{"incident_signals", "fx2_signal_entity_fk", "tenant_id, entity_context_id, entity_id", "entities", "tenant_id, context_id, id"},
		{"incident_signals", "fx2_signal_incident_fk", "tenant_id, incident_id", "incidents", "tenant_id, id"},
		{"incident_correlation_overrides", "fx2_override_entity_fk", "tenant_id, entity_context_id, entity_id", "entities", "tenant_id, context_id, id"},
		{"incident_correlation_overrides", "fx2_override_source_fk", "tenant_id, source_incident_id", "incidents", "tenant_id, id"},
		{"incident_correlation_overrides", "fx2_override_detached_fk", "tenant_id, detached_incident_id", "incidents", "tenant_id, id"},
		{"incident_correlation_overrides", "fx2_override_signal_fk", "tenant_id, source_signal_id", "incident_signals", "tenant_id, id"},
	}
	if owned["entity_fault_receipts"] {
		keys = append(keys,
			foreignKey{"entity_fault_receipts", "fx2_fault_receipt_tenant_fk", "tenant_id", "public.tenants", "id"},
			foreignKey{"entity_fault_receipts", "fx2_fault_receipt_incident_fk", "tenant_id, incident_id", "incidents", "tenant_id, id"},
		)
	}
	// CREATE TABLE LIKE omits every import FK. Keep source plans, row targets
	// and provenance inside the same physical tenant and routing context on
	// both first provision and catch-up. Older schemas have no import tables.
	if owned["nms_import_sources"] && owned["nms_import_plans"] &&
		owned["nms_import_pages"] &&
		owned["nms_import_rows"] && owned["nms_import_provenance"] {
		keys = append(keys,
			foreignKey{"nms_import_sources", "fx2b_source_context_fk", "tenant_id, context_id", "entity_contexts", "tenant_id, id"},
			foreignKey{"nms_import_plans", "fx2b_plan_source_fk", "tenant_id, context_id, source_id", "nms_import_sources", "tenant_id, context_id, id"},
			foreignKey{"nms_import_pages", "fx2b_page_plan_fk", "tenant_id, context_id, plan_id", "nms_import_plans", "tenant_id, context_id, id"},
			foreignKey{"nms_import_rows", "fx2b_row_plan_fk", "tenant_id, context_id, plan_id", "nms_import_plans", "tenant_id, context_id, id"},
			foreignKey{"nms_import_rows", "fx2b_row_entity_fk", "tenant_id, context_id, target_entity_id", "entities", "tenant_id, context_id, id"},
			foreignKey{"nms_import_provenance", "fx2b_provenance_source_fk", "tenant_id, context_id, source_id", "nms_import_sources", "tenant_id, context_id, id"},
			foreignKey{"nms_import_provenance", "fx2b_provenance_plan_source_fk", "tenant_id, context_id, plan_id, source_id", "nms_import_plans", "tenant_id, context_id, id, source_id"},
			foreignKey{"nms_import_provenance", "fx2b_provenance_row_fk", "tenant_id, context_id, plan_id, object_kind, external_id", "nms_import_rows", "tenant_id, context_id, plan_id, object_kind, external_id"},
			foreignKey{"nms_import_provenance", "fx2b_provenance_entity_fk", "tenant_id, context_id, entity_id", "entities", "tenant_id, context_id, id"},
		)
		if owned["nms_import_capture_steps"] {
			keys = append(keys, foreignKey{"nms_import_capture_steps", "fx2b_capture_step_plan_fk",
				"tenant_id, context_id, plan_id", "nms_import_plans", "tenant_id, context_id, id"})
		}
		if owned["nms_import_groups"] && owned["nms_import_group_members"] {
			keys = append(keys,
				foreignKey{"nms_import_groups", "fx2b_group_source_fk", "tenant_id, context_id, source_id", "nms_import_sources", "tenant_id, context_id, id"},
				foreignKey{"nms_import_groups", "fx2b_group_plan_fk", "tenant_id, context_id, plan_id, source_id", "nms_import_plans", "tenant_id, context_id, id, source_id"},
				foreignKey{"nms_import_groups", "fx2b_group_revision_plan_fk", "tenant_id, context_id, revision_plan_id, source_id", "nms_import_plans", "tenant_id, context_id, id, source_id"},
				foreignKey{"nms_import_groups", "fx2b_group_row_fk", "tenant_id, context_id, plan_id, object_kind, external_id", "nms_import_rows", "tenant_id, context_id, plan_id, object_kind, external_id"},
				foreignKey{"nms_import_group_members", "fx2b_member_group_fk", "tenant_id, context_id, source_id, group_external_id", "nms_import_groups", "tenant_id, context_id, source_id, external_id"},
				foreignKey{"nms_import_group_members", "fx2b_member_device_fk", "tenant_id, context_id, source_id, member_kind, member_external_id", "nms_import_provenance", "tenant_id, context_id, source_id, object_kind, external_id"},
				foreignKey{"nms_import_group_members", "fx2b_member_plan_fk", "tenant_id, context_id, plan_id, source_id", "nms_import_plans", "tenant_id, context_id, id, source_id"},
				foreignKey{"nms_import_group_members", "fx2b_member_row_fk", "tenant_id, context_id, plan_id, object_kind, row_external_id", "nms_import_rows", "tenant_id, context_id, plan_id, object_kind, external_id"},
			)
		}
		if owned["nms_import_poll_proposals"] {
			keys = append(keys,
				foreignKey{"nms_import_poll_proposals", "fx2b_poll_host_fk", "tenant_id, context_id, source_id, host_kind, host_external_id", "nms_import_provenance", "tenant_id, context_id, source_id, object_kind, external_id"},
				foreignKey{"nms_import_poll_proposals", "fx2b_poll_plan_fk", "tenant_id, context_id, plan_id, source_id", "nms_import_plans", "tenant_id, context_id, id, source_id"},
				foreignKey{"nms_import_poll_proposals", "fx2b_poll_row_fk", "tenant_id, context_id, plan_id, object_kind, item_external_id", "nms_import_rows", "tenant_id, context_id, plan_id, object_kind, external_id"},
			)
		}
	}
	// Existing silos can predate the public (tenant_id,id) index. A global
	// tests.id primary key is insufficient for the composite FK, so install
	// its tenant-aware target before adding the path binding constraint.
	// PostgreSQL places an index in its table's schema. Its CREATE INDEX name
	// must be unqualified even when the table is schema-qualified.
	plan := []string{"CREATE UNIQUE INDEX IF NOT EXISTS " +
		`"fx2_tests_tenant_id_id_uidx" ON ` +
		quoteIdent(schema) + `."tests" (tenant_id, id)`,
		"CREATE UNIQUE INDEX IF NOT EXISTS " +
			`"fx2_incidents_tenant_id_id_uidx" ON ` + quoteIdent(schema) +
			`."incidents" (tenant_id, id)`,
		"CREATE UNIQUE INDEX IF NOT EXISTS " +
			`"fx2_incident_signals_tenant_id_id_uidx" ON ` + quoteIdent(schema) +
			`."incident_signals" (tenant_id, id)`}
	for _, table := range []string{"incidents", "incident_signals", "incident_correlation_overrides"} {
		child := quoteIdent(schema) + "." + quoteIdent(table)
		name := "fx2_" + table + "_entity_pair_ck"
		plan = append(plan, fmt.Sprintf(`DO $fx2_silo_ck$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = %s::regclass AND conname = %s) THEN
        ALTER TABLE %s ADD CONSTRAINT %s CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL);
    END IF;
END $fx2_silo_ck$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name)))
		name = "fx2_" + table + "_identity_lookup_ck"
		plan = append(plan, fmt.Sprintf(`DO $fx2_silo_ck$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = %s::regclass AND conname = %s) THEN
        ALTER TABLE %s ADD CONSTRAINT %s CHECK (entity_context_id IS NULL OR identity_lookup_attempted);
    END IF;
END $fx2_silo_ck$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name)))
	}
	for _, key := range keys {
		child := quoteIdent(schema) + "." + quoteIdent(key.table)
		parent := quoteIdent(schema) + "." + quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = `public.tenants`
		}
		onUpdate := ""
		if key.name == "fx2_source_agent_context_fk" {
			onUpdate = " ON UPDATE CASCADE"
		}
		onDelete := " ON DELETE CASCADE"
		if key.name == "fx2_source_anchor_fk" {
			onDelete = " ON DELETE SET NULL (anchor_entity_id)"
		}
		if key.name == "fx2_incident_entity_fk" || key.name == "fx2_signal_entity_fk" || key.name == "fx2_override_entity_fk" {
			onDelete = " ON DELETE SET NULL (entity_id)"
		}
		if key.name == "fx2b_row_entity_fk" {
			onDelete = " ON DELETE SET NULL (target_entity_id)"
		}
		if key.name == "fx2b_provenance_plan_source_fk" || key.name == "fx2b_provenance_row_fk" ||
			key.name == "fx2b_group_plan_fk" || key.name == "fx2b_group_revision_plan_fk" ||
			key.name == "fx2b_group_row_fk" ||
			key.name == "fx2b_member_plan_fk" || key.name == "fx2b_member_row_fk" ||
			key.name == "fx2b_poll_plan_fk" || key.name == "fx2b_poll_row_fk" {
			// An applied plan remains while provenance cites it. A deferred FK
			// still allows a whole-tenant cascade to remove both records.
			onDelete = " ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED"
		}
		plan = append(plan, fmt.Sprintf(`DO $fx2_silo_fk$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = %s::regclass AND conname = %s) THEN
        ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s)%s%s;
    END IF;
END $fx2_silo_fk$`, quoteLiteral(child), quoteLiteral(key.name), child,
			quoteIdent(key.name), key.columns, parent, key.parentColumns, onUpdate, onDelete))
	}
	plan = append(plan, nmsImportSiloCheckPlan(schema, owned)...)
	// CREATE TABLE LIKE does not copy triggers. Keep the path-target edit
	// invalidation inside the silo schema as well as in public, including on
	// catch-up of a silo that predates FX-2.
	tests := quoteIdent(schema) + `."tests"`
	plan = append(plan,
		"DROP TRIGGER IF EXISTS entity_path_retarget ON "+tests,
		"CREATE TRIGGER entity_path_retarget AFTER UPDATE OF target ON "+tests+
			" FOR EACH ROW EXECUTE FUNCTION public.entity_clear_path_binding_on_retarget()",
		"ALTER TABLE "+tests+" ENABLE ALWAYS TRIGGER entity_path_retarget",
	)
	return plan
}

// nmsImportSiloCheckPlan restores CHECK constraints that CREATE TABLE LIKE
// cannot copy into an older physical silo during schema catch-up.
func nmsImportSiloCheckPlan(schema string, owned map[string]bool) []string {
	var plan []string
	if owned["nms_import_rows"] {
		// Catch-up adds public columns but does not automatically copy later
		// CHECK constraints into an existing silo table. Keep reviewed exact
		// targets fingerprinted in both physical storage layouts.
		rows := quoteIdent(schema) + `."nms_import_rows"`
		plan = append(plan, fmt.Sprintf(`DO $fx2b_target_revision$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid = %s::regclass
                 AND conname='nms_import_rows_target_fingerprint_check'
                 AND position('remove' in pg_get_constraintdef(oid))=0) THEN
        ALTER TABLE %s DROP CONSTRAINT nms_import_rows_target_fingerprint_check;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema=%s AND table_name='nms_import_rows'
                 AND column_name='target_fingerprint')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conrelid = %s::regclass
                         AND conname='nms_import_rows_target_fingerprint_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_rows_target_fingerprint_check
            CHECK (target_fingerprint IS NULL OR
                   (action IN ('update','remove') AND
                    target_fingerprint ~ '^[0-9a-f]{64}$')) NOT VALID;
    END IF;
END $fx2b_target_revision$`, quoteLiteral(rows), rows,
			quoteLiteral(schema), quoteLiteral(rows), rows))
		plan = append(plan, fmt.Sprintf(`DO $fx2b_remove_checks$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid = %s::regclass
                 AND conname='nms_import_rows_action_check'
                 AND position('remove' in pg_get_constraintdef(oid))=0) THEN
        ALTER TABLE %s DROP CONSTRAINT nms_import_rows_action_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = %s::regclass
                     AND conname='nms_import_rows_action_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_rows_action_check
            CHECK (action IN ('captured','create','update','remove',
                             'conflict','skip','unmapped')) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema=%s AND table_name='nms_import_rows'
                 AND column_name='target_group_revision')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conrelid = %s::regclass
                         AND conname='nms_import_rows_target_group_revision_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_rows_target_group_revision_check
            CHECK (target_group_revision IS NULL OR
                   (action='remove' AND target_group_revision>=0)) NOT VALID;
    END IF;
END $fx2b_remove_checks$`, quoteLiteral(rows), rows,
			quoteLiteral(rows), rows, quoteLiteral(schema), quoteLiteral(rows), rows))
		// An older silo copied the original numeric-only parent CHECK. The
		// public expansion allows Zabbix's safe host key for item/trigger
		// lineage, so remove that old CHECK and install its replacement here.
		plan = append(plan, fmt.Sprintf(`DO $fx2b_zabbix_parent$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid = %s::regclass
                 AND conname='nms_import_rows_parent_external_id_check') THEN
        ALTER TABLE %s DROP CONSTRAINT nms_import_rows_parent_external_id_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = %s::regclass
                     AND conname='nms_import_rows_parent_source_key_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_rows_parent_source_key_check
            CHECK (parent_external_id IS NULL OR
                   (octet_length(parent_external_id) BETWEEN 1 AND 256
                    AND parent_external_id !~ '[[:cntrl:]]'
                    AND (parent_external_id ~ '^[0-9a-f]+$' OR
                         object_kind IN ('poll_setting','alert_rule')))) NOT VALID;
    END IF;
END $fx2b_zabbix_parent$`, quoteLiteral(rows), rows, quoteLiteral(rows), rows))
	}
	if owned["nms_import_pages"] {
		pages := quoteIdent(schema) + `."nms_import_pages"`
		plan = append(plan, fmt.Sprintf(`DO $fx2b_removal_pages$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid = %s::regclass
                 AND conname='nms_import_pages_resource_kind_check'
                 AND position('member_removals' in pg_get_constraintdef(oid))=0) THEN
        ALTER TABLE %s DROP CONSTRAINT nms_import_pages_resource_kind_check;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = %s::regclass
                     AND conname='nms_import_pages_resource_kind_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_pages_resource_kind_check
            CHECK (resource_kind IN ('devices','locations','nodes','groups',
                                    'memberships','member_removals','rules',
                                    'hosts','probes')) NOT VALID;
    END IF;
END $fx2b_removal_pages$`, quoteLiteral(pages), pages,
			quoteLiteral(pages), pages))
	}
	if owned["nms_import_groups"] {
		groups := quoteIdent(schema) + `."nms_import_groups"`
		plan = append(plan, fmt.Sprintf(`DO $fx2b_group_revision$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema=%s AND table_name='nms_import_groups'
                 AND column_name='revision')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conrelid = %s::regclass
                         AND conname='nms_import_groups_revision_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_groups_revision_check
            CHECK (revision>=0 AND revision_plan_delta>=0 AND
                   ((revision_plan_id IS NULL)=(revision_plan_delta=0))) NOT VALID;
    END IF;
END $fx2b_group_revision$`, quoteLiteral(schema), quoteLiteral(groups), groups))
	}
	if owned["nms_import_plans"] {
		// A pre-existing physical silo receives the new columns through the
		// generic catch-up plan, but needs the proof-pair CHECK explicitly.
		plans := quoteIdent(schema) + `."nms_import_plans"`
		plan = append(plan, fmt.Sprintf(`DO $fx2b_apply_proof$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema=%s AND table_name='nms_import_plans'
                 AND column_name='apply_verified_review_hash')
       AND NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conrelid = %s::regclass
                         AND conname='nms_import_plans_apply_verified_hash_check') THEN
        ALTER TABLE %s ADD CONSTRAINT nms_import_plans_apply_verified_hash_check
            CHECK ((apply_verified_review_hash IS NULL) = (apply_verified_at IS NULL)
                   AND (apply_verified_review_hash IS NULL OR
                        apply_verified_review_hash ~ '^[0-9a-f]{64}$')) NOT VALID;
    END IF;
END $fx2b_apply_proof$`, quoteLiteral(schema), quoteLiteral(plans), plans))
	}
	return plan
}

func provisionTablePlan(schema, table string) []string {
	qt := quoteIdent(schema) + "." + quoteIdent(table)
	plan := []string{
		"CREATE TABLE IF NOT EXISTS " + qt + " (LIKE public." + quoteIdent(table) + " INCLUDING ALL)",
	}
	return append(plan, repairTenantBoundaryPlan(schema, qt, table)...)
}

func tableRolePlan(quotedTable, table string) []string {
	switch table {
	case "audit_events":
		// AUD-04: the app role stays append-only (SELECT/INSERT). The provider
		// role gets NO direct grant — retention/erase run through the public
		// SECURITY DEFINER functions, which resolve this silo schema and operate
		// on it, so a caller-settable GUC can never drive a direct provider
		// DELETE/SELECT of a tenant audit row.
		return []string{
			"REVOKE ALL ON " + quotedTable + " FROM probectl_app",
			"GRANT SELECT, INSERT ON " + quotedTable + " TO probectl_app",
			"REVOKE ALL ON " + quotedTable + " FROM probectl_provider",
		}
	case "audit_subject_erasures":
		return []string{
			"REVOKE ALL ON " + quotedTable + " FROM probectl_app",
			"GRANT SELECT, INSERT ON " + quotedTable + " TO probectl_app",
			"REVOKE ALL ON " + quotedTable + " FROM probectl_provider",
			"GRANT SELECT, INSERT, DELETE ON " + quotedTable + " TO probectl_provider",
		}
	case "ir_attribution_records":
		return []string{
			"REVOKE ALL ON " + quotedTable + " FROM probectl_app",
			"REVOKE ALL ON " + quotedTable + " FROM probectl_provider",
			"GRANT SELECT, INSERT ON " + quotedTable + " TO probectl_provider",
		}
	}
	return []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE ON " + quotedTable + " TO probectl_app",
	}
}

func providerMaintainedTable(table string) bool {
	return table == "audit_events" ||
		table == "audit_subject_erasures" ||
		table == "ir_attribution_records"
}

func auditWriteFencePlan(quotedTable, table string) []string {
	roles := ""
	switch table {
	case "audit_events":
		roles = "probectl_app"
	case "audit_subject_erasures":
		roles = "probectl_app, probectl_provider"
	default:
		return nil
	}
	return []string{
		"DROP POLICY IF EXISTS tenant_audit_write_eligibility ON " + quotedTable,
		`CREATE POLICY tenant_audit_write_eligibility ON ` + quotedTable + ` AS RESTRICTIVE
  FOR INSERT TO ` + roles + `
  WITH CHECK (public.probectl_tenant_audit_writes_allowed())`,
		"DROP TRIGGER IF EXISTS tenant_audit_write_fence ON " + quotedTable,
		`CREATE TRIGGER tenant_audit_write_fence
  BEFORE INSERT ON ` + quotedTable + `
  FOR EACH ROW
  EXECUTE FUNCTION public.probectl_enforce_tenant_audit_write_fence()`,
		"ALTER TABLE " + quotedTable + " ENABLE ALWAYS TRIGGER tenant_audit_write_fence",
	}
}

func tenantWriteFencePlan(quotedTable, table string) []string {
	switch table {
	case "audit_events", "audit_subject_erasures":
		return nil
	}
	return []string{
		"DROP TRIGGER IF EXISTS tenant_write_fence ON " + quotedTable,
		`CREATE TRIGGER tenant_write_fence
  BEFORE INSERT OR UPDATE ON ` + quotedTable + `
  FOR EACH ROW
  EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()`,
		"ALTER TABLE " + quotedTable + " ENABLE ALWAYS TRIGGER tenant_write_fence",
	}
}

// schemaTenantID decodes the stable t_<UUID-without-dashes> schema name. An
// invalid/non-silo name returns empty so policy generation fails closed.
func schemaTenantID(schema string) string {
	const prefix = "t_"
	schema = strings.ToLower(schema)
	if !strings.HasPrefix(schema, prefix) || len(schema) != len(prefix)+32 {
		return ""
	}
	compact := schema[len(prefix):]
	for _, ch := range compact {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	return compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" +
		compact[16:20] + "-" + compact[20:]
}

func siloTenantPredicate(schema string) string {
	tenantID := schemaTenantID(schema)
	if tenantID == "" {
		return "false"
	}
	return `tenant_id = '` + tenantID + `'::uuid
    AND tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid`
}

// repairTenantBoundaryPlan restores the storage-layer boundary before grants
// are repaired. A restored silo may have RLS disabled, not forced for its
// owner, a GUC-only policy that permits cross-schema writes, or an additional
// permissive policy. The RESTRICTIVE guard remains an AND across every
// permissive policy and binds the row to this physical schema's tenant.
func repairTenantBoundaryPlan(schema, quotedTable, table string) []string {
	predicate := siloTenantPredicate(schema)
	plan := []string{
		"ALTER TABLE " + quotedTable + " ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE " + quotedTable + " FORCE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS tenant_isolation ON " + quotedTable,
		`CREATE POLICY tenant_isolation ON ` + quotedTable + `
  USING (` + predicate + `)
  WITH CHECK (` + predicate + `)`,
		"DROP POLICY IF EXISTS tenant_schema_isolation ON " + quotedTable,
		`CREATE POLICY tenant_schema_isolation ON ` + quotedTable + ` AS RESTRICTIVE
  FOR ALL TO PUBLIC
  USING (` + predicate + `)
  WITH CHECK (` + predicate + `)`,
	}
	plan = append(plan, auditWriteFencePlan(quotedTable, table)...)
	plan = append(plan, tenantWriteFencePlan(quotedTable, table)...)
	return append(plan, tableRolePlan(quotedTable, table)...)
}

// CatchUpPlan renders the DDL that brings an EXISTING silo schema up to the
// current public shape: missing tables are created (the full provision
// recipe), and missing columns on existing tables are added. Because the S34
// migration gate enforces expand/contract (no destructive in-place changes),
// CREATE-missing + ADD-missing-columns covers every migration the gate
// admits; contract phases are operator-run per docs/isolation.md.
func CatchUpPlan(schema string, cat Catalog) []string {
	q := quoteIdent(schema)
	have := map[string]bool{}
	for _, t := range cat.SchemaTables {
		have[t] = true
	}
	var plan []string
	tenantTables := TenantOwned(cat.TenantTables)
	for _, t := range tenantTables {
		if providerMaintainedTable(t) {
			// Provider maintenance tables need schema access whether catch-up
			// creates them or repairs an existing/restored copy.
			plan = append(plan, "GRANT USAGE ON SCHEMA "+q+" TO probectl_provider")
			break
		}
	}
	for _, t := range tenantTables {
		if !have[t] {
			// The same recipe as provisioning, for just this table.
			plan = append(plan, provisionTablePlan(schema, t)...)
			continue
		}
		// Column diff: public minus silo, in public's order.
		siloCols := map[string]bool{}
		for _, c := range cat.SchemaColumns[t] {
			siloCols[c.Name] = true
		}
		for _, c := range cat.Columns[t] {
			if siloCols[c.Name] {
				continue
			}
			stmt := "ALTER TABLE " + q + "." + quoteIdent(t) +
				" ADD COLUMN IF NOT EXISTS " + quoteIdent(c.Name) + " " + c.DataType
			if c.Default != "" {
				stmt += " DEFAULT " + c.Default
			}
			if c.NotNull {
				// Safe only with a default (expand-only migrations carry one);
				// otherwise add nullable and let the operator finish per docs.
				if c.Default != "" {
					stmt += " NOT NULL"
				}
			}
			plan = append(plan, stmt)
		}
		// Repair every existing tenant table, not only provider-maintained
		// tables. This is deliberately emitted even with no structural drift.
		plan = append(
			plan,
			repairTenantBoundaryPlan(schema, q+"."+quoteIdent(t), t)...,
		)
	}
	plan = append(plan, entityRegistryForeignKeyPlan(schema, cat.TenantTables)...)
	return plan
}

// TeardownPlan renders the DDL removing a tenant's silo schema entirely.
func TeardownPlan(schema string) []string {
	return []string{"DROP SCHEMA IF EXISTS " + quoteIdent(schema) + " CASCADE"}
}

// Drift summarizes how far a silo schema lags public (provider-console
// honesty: operators see catch-up debt instead of discovering it in prod).
type Drift struct {
	MissingTables  []string `json:"missing_tables"`
	MissingColumns []string `json:"missing_columns"` // "table.column"
}

// empty reports whether the silo is fully caught up.
func (d Drift) empty() bool { return len(d.MissingTables) == 0 && len(d.MissingColumns) == 0 }

// DiffDrift computes the catch-up debt from catalog facts.
func DiffDrift(cat Catalog) Drift {
	var d Drift
	have := map[string]bool{}
	for _, t := range cat.SchemaTables {
		have[t] = true
	}
	for _, t := range TenantOwned(cat.TenantTables) {
		if !have[t] {
			d.MissingTables = append(d.MissingTables, t)
			continue
		}
		siloCols := map[string]bool{}
		for _, c := range cat.SchemaColumns[t] {
			siloCols[c.Name] = true
		}
		for _, c := range cat.Columns[t] {
			if !siloCols[c.Name] {
				d.MissingColumns = append(d.MissingColumns, fmt.Sprintf("%s.%s", t, c.Name))
			}
		}
	}
	return d
}
