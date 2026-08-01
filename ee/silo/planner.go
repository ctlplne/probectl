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
//  5. an audit-only, tenant-GUC-scoped provider maintenance capability:
//     schema USAGE plus SELECT/DELETE on audit_events. The app role keeps
//     audit_events append-only (SELECT/INSERT only).
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
		return []string{
			"REVOKE ALL ON " + quotedTable + " FROM probectl_app",
			"GRANT SELECT, INSERT ON " + quotedTable + " TO probectl_app",
			"REVOKE ALL ON " + quotedTable + " FROM probectl_provider",
			"GRANT SELECT, DELETE ON " + quotedTable + " TO probectl_provider",
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
