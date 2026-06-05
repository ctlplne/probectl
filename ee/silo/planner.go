// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package silo

import (
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

// providerOwned tables carry tenant_id but are NOT tenant-owned.
var providerOwned = map[string]bool{
	"break_glass_grants": true,
}

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

// TenantOwned filters and sorts the tenant-owned table set.
func TenantOwned(tables []string) []string {
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		if !providerOwned[t] {
			out = append(out, t)
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
//  3. ENABLE+FORCE RLS + recreate the tenant_isolation policy (the silo is
//     schema-isolated AND GUC-scoped: defense-in-depth, not replacement)
//  4. grants for the app role (USAGE on the schema; DML on the tables)
func ProvisionPlan(schema string, tenantTables []string) []string {
	q := quoteIdent(schema)
	plan := []string{
		"CREATE SCHEMA IF NOT EXISTS " + q,
		"GRANT USAGE ON SCHEMA " + q + " TO probectl_app",
	}
	for _, t := range TenantOwned(tenantTables) {
		qt := q + "." + quoteIdent(t)
		plan = append(plan,
			"CREATE TABLE IF NOT EXISTS "+qt+" (LIKE public."+quoteIdent(t)+" INCLUDING ALL)",
			"ALTER TABLE "+qt+" ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE "+qt+" FORCE ROW LEVEL SECURITY",
			"DROP POLICY IF EXISTS tenant_isolation ON "+qt,
			`CREATE POLICY tenant_isolation ON `+qt+`
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)`,
			"GRANT SELECT, INSERT, UPDATE, DELETE ON "+qt+" TO probectl_app",
		)
	}
	return plan
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
	for _, t := range TenantOwned(cat.TenantTables) {
		if !have[t] {
			// The same recipe as provisioning, for just this table.
			plan = append(plan, ProvisionPlan(schema, []string{t})[2:]...)
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

// Empty reports whether the silo is fully caught up.
func (d Drift) Empty() bool { return len(d.MissingTables) == 0 && len(d.MissingColumns) == 0 }

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
