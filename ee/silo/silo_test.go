// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"strings"
	"testing"
)

func TestNaming(t *testing.T) {
	id := "3FA2BC10-1234-5678-9ABC-DEF012345678"
	if s := SchemaName(id); s != "t_3fa2bc10123456789abcdef012345678" {
		t.Fatalf("schema: %s", s)
	}
	if d := CHDatabase(id); d != "probectl_t_3fa2bc10123456789abcdef012345678" {
		t.Fatalf("ch db: %s", d)
	}
	if n := BusNamespace("acme"); n != "t-acme" {
		t.Fatalf("bus ns: %s", n)
	}
	if p := ObjectPrefix(id); p != "silo/3fa2bc10-1234-5678-9abc-def012345678" {
		t.Fatalf("object prefix: %s", p)
	}
}

func TestParseDataPlanes(t *testing.T) {
	planes, err := ParseDataPlanes("eu=https://ch-eu:8123; us = http://ch-us:8123 ")
	if err != nil || len(planes) != 2 || planes["eu"].CHURL != "https://ch-eu:8123" || planes["us"].CHURL != "http://ch-us:8123" {
		t.Fatalf("parse: %+v %v", planes, err)
	}
	if got := PlaneNames(planes); strings.Join(got, ",") != "eu,us" {
		t.Fatalf("names: %v", got)
	}
	if p, err := ParseDataPlanes(""); err != nil || len(p) != 0 {
		t.Fatalf("empty: %v %v", p, err)
	}
	for _, bad := range []string{"justname", "eu=", "=url", "eu=ftp://x", "eu=https://a;eu=https://b"} {
		if _, err := ParseDataPlanes(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// TestProvisionPlan pins the schema-provisioning recipe: schema + grants,
// then per tenant-owned table LIKE-copy + recreated RLS (defense-in-depth on
// top of physical separation) + DML grants — and the provider-owned deny
// list excluded.
func TestProvisionPlan(t *testing.T) {
	plan := ProvisionPlan("t_abc", []string{
		"tests", "agents", "audit_events", "audit_subject_erasures",
		"break_glass_grants", "tenant_retention",
		"credential_locators", "agent_identity_revocations",
	})
	joined := strings.Join(plan, "\n")

	for _, want := range []string{
		`CREATE SCHEMA IF NOT EXISTS "t_abc"`,
		`GRANT USAGE ON SCHEMA "t_abc" TO probectl_app`,
		`GRANT USAGE ON SCHEMA "t_abc" TO probectl_provider`,
		`CREATE TABLE IF NOT EXISTS "t_abc"."agents" (LIKE public."agents" INCLUDING ALL)`,
		`CREATE TABLE IF NOT EXISTS "t_abc"."tests" (LIKE public."tests" INCLUDING ALL)`,
		`ALTER TABLE "t_abc"."tests" ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE "t_abc"."tests" FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON "t_abc"."tests"`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON "t_abc"."tests" TO probectl_app`,
		`REVOKE ALL ON "t_abc"."audit_events" FROM probectl_app`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_events" TO probectl_app`,
		`GRANT SELECT, DELETE ON "t_abc"."audit_events" TO probectl_provider`,
		`REVOKE ALL ON "t_abc"."audit_subject_erasures" FROM probectl_app`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_subject_erasures" TO probectl_app`,
		`GRANT SELECT, INSERT, DELETE ON "t_abc"."audit_subject_erasures" TO probectl_provider`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q", want)
		}
	}
	for _, providerOwned := range []string{
		"break_glass_grants", "tenant_retention",
		"credential_locators", "agent_identity_revocations",
	} {
		if strings.Contains(joined, providerOwned) {
			t.Errorf("provider-owned table %s must never enter a tenant silo", providerOwned)
		}
	}
	// Order: schema first, grants before any table.
	if !strings.HasPrefix(plan[0], "CREATE SCHEMA") {
		t.Error("schema must be created first")
	}
}

// TestCatchUpPlan pins the drift recipe: a missing table gets the full
// per-table provision; a missing column gets an expand-only ADD COLUMN.
func TestCatchUpPlan(t *testing.T) {
	cat := Catalog{
		TenantTables: []string{"tests", "agents", "new_table"},
		SchemaTables: []string{"tests", "agents"},
		Columns: map[string][]Column{
			"tests":  {{Name: "id", DataType: "uuid"}, {Name: "tenant_id", DataType: "uuid"}, {Name: "added_later", DataType: "text", NotNull: true, Default: "''::text"}},
			"agents": {{Name: "id", DataType: "uuid"}},
		},
		SchemaColumns: map[string][]Column{
			"tests":  {{Name: "id", DataType: "uuid"}, {Name: "tenant_id", DataType: "uuid"}},
			"agents": {{Name: "id", DataType: "uuid"}},
		},
	}
	plan := CatchUpPlan("t_abc", cat)
	joined := strings.Join(plan, "\n")
	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS "t_abc"."new_table" (LIKE public."new_table" INCLUDING ALL)`,
		`CREATE POLICY tenant_isolation ON "t_abc"."new_table"`,
		`ALTER TABLE "t_abc"."tests" ADD COLUMN IF NOT EXISTS "added_later" text DEFAULT ''::text NOT NULL`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("catch-up missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, `"t_abc"."agents" ADD COLUMN`) {
		t.Error("an in-sync table must produce no DDL")
	}

	// Drift summary mirrors the same diff.
	d := DiffDrift(cat)
	if d.Empty() || len(d.MissingTables) != 1 || d.MissingTables[0] != "new_table" ||
		len(d.MissingColumns) != 1 || d.MissingColumns[0] != "tests.added_later" {
		t.Fatalf("drift: %+v", d)
	}

	// Fully caught up = only the idempotent audit permission repair + empty
	// structural drift.
	cat.SchemaTables = []string{"tests", "agents", "new_table"}
	cat.SchemaColumns["new_table"] = cat.Columns["new_table"]
	cat.SchemaColumns["tests"] = cat.Columns["tests"]
	if p := CatchUpPlan("t_abc", cat); len(p) != 0 {
		t.Fatalf("caught-up plan without audit_events must be empty: %v", p)
	}
	if !DiffDrift(cat).Empty() {
		t.Fatal("caught-up drift must be empty")
	}

	cat.TenantTables = append(cat.TenantTables, "audit_events")
	cat.SchemaTables = append(cat.SchemaTables, "audit_events")
	cat.Columns["audit_events"] = []Column{{Name: "tenant_id", DataType: "uuid"}}
	cat.SchemaColumns["audit_events"] = cat.Columns["audit_events"]
	repair := strings.Join(CatchUpPlan("t_abc", cat), "\n")
	for _, want := range []string{
		`GRANT USAGE ON SCHEMA "t_abc" TO probectl_provider`,
		`ALTER TABLE "t_abc"."audit_events" ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE "t_abc"."audit_events" FORCE ROW LEVEL SECURITY`,
		`DROP POLICY IF EXISTS tenant_isolation ON "t_abc"."audit_events"`,
		`CREATE POLICY tenant_isolation ON "t_abc"."audit_events"`,
		`REVOKE ALL ON "t_abc"."audit_events" FROM probectl_app`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_events" TO probectl_app`,
		`GRANT SELECT, DELETE ON "t_abc"."audit_events" TO probectl_provider`,
	} {
		if !strings.Contains(repair, want) {
			t.Errorf("caught-up audit permission repair missing %q in:\n%s", want, repair)
		}
	}
	policyAt := strings.Index(repair, `CREATE POLICY tenant_isolation ON "t_abc"."audit_events"`)
	grantAt := strings.Index(repair, `GRANT SELECT, INSERT ON "t_abc"."audit_events" TO probectl_app`)
	if policyAt < 0 || grantAt < 0 || policyAt > grantAt {
		t.Fatalf("audit boundary must be repaired before grants:\n%s", repair)
	}

	cat.TenantTables = append(cat.TenantTables, "audit_subject_erasures")
	cat.SchemaTables = append(cat.SchemaTables, "audit_subject_erasures")
	cat.Columns["audit_subject_erasures"] = []Column{
		{Name: "tenant_id", DataType: "uuid"},
		{Name: "subject_hash", DataType: "text"},
	}
	cat.SchemaColumns["audit_subject_erasures"] = cat.Columns["audit_subject_erasures"]
	markerRepair := strings.Join(CatchUpPlan("t_abc", cat), "\n")
	for _, want := range []string{
		`ALTER TABLE "t_abc"."audit_subject_erasures" ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE "t_abc"."audit_subject_erasures" FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON "t_abc"."audit_subject_erasures"`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_subject_erasures" TO probectl_app`,
		`GRANT SELECT, INSERT, DELETE ON "t_abc"."audit_subject_erasures" TO probectl_provider`,
	} {
		if !strings.Contains(markerRepair, want) {
			t.Errorf("subject-erasure marker repair missing %q in:\n%s", want, markerRepair)
		}
	}
}

func TestTeardownPlan(t *testing.T) {
	plan := TeardownPlan("t_abc")
	if len(plan) != 1 || plan[0] != `DROP SCHEMA IF EXISTS "t_abc" CASCADE` {
		t.Fatalf("teardown: %v", plan)
	}
}
