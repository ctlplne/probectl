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
		"ir_attribution_records", "ir_attribution_heads",
		"ir_key_shred_records", "ir_key_shred_heads",
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
		// AUD-04: the provider gets NO direct grant on audit_events.
		`REVOKE ALL ON "t_abc"."audit_events" FROM probectl_provider`,
		`REVOKE ALL ON "t_abc"."audit_subject_erasures" FROM probectl_app`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_subject_erasures" TO probectl_app`,
		`GRANT SELECT, INSERT, DELETE ON "t_abc"."audit_subject_erasures" TO probectl_provider`,
		`CREATE TABLE IF NOT EXISTS "t_abc"."ir_attribution_records" (LIKE public."ir_attribution_records" INCLUDING ALL)`,
		`REVOKE ALL ON "t_abc"."ir_attribution_records" FROM probectl_app`,
		`REVOKE ALL ON "t_abc"."ir_attribution_records" FROM probectl_provider`,
		`GRANT SELECT, INSERT ON "t_abc"."ir_attribution_records" TO probectl_provider`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q", want)
		}
	}
	for _, providerOwned := range []string{
		"break_glass_grants", "tenant_retention",
		"credential_locators", "agent_identity_revocations",
		"ir_attribution_heads", "ir_key_shred_records", "ir_key_shred_heads",
	} {
		if strings.Contains(joined, providerOwned) {
			t.Errorf("provider-owned table %s must never enter a tenant silo", providerOwned)
		}
	}
	// AUD-04: the provider role must get no direct grant on audit_events.
	if strings.Contains(joined, `ON "t_abc"."audit_events" TO probectl_provider`) {
		t.Errorf("provider must hold no direct grant on silo audit_events:\n%s", joined)
	}
	// Order: schema first, grants before any table.
	if !strings.HasPrefix(plan[0], "CREATE SCHEMA") {
		t.Error("schema must be created first")
	}
	assertAuditWriteFencePlan(t, joined, "audit_events", "probectl_app")
	assertAuditWriteFencePlan(
		t,
		joined,
		"audit_subject_erasures",
		"probectl_app, probectl_provider",
	)
	assertNoAuditWriteFencePlan(t, joined, "tests")
	assertTenantWriteFencePlan(t, joined, "tests")
}

func TestEntityRegistryForeignKeysFollowAllSiloCopies(t *testing.T) {
	tables := []string{"tests", "entity_contexts", "entity_path_test_contexts", "entity_agent_contexts", "entity_source_contexts", "entities", "entity_evidence", "entity_links", "incidents", "incident_signals", "incident_correlation_overrides", "entity_fault_receipts"}
	for name, plan := range map[string][]string{
		"provision": ProvisionPlan("t_abc", tables),
		"catch-up":  CatchUpPlan("t_abc", Catalog{TenantTables: tables}),
	} {
		t.Run(name, func(t *testing.T) {
			joined := strings.Join(plan, "\n")
			lastCopy := -1
			for _, table := range tables {
				copyAt := strings.Index(joined, `CREATE TABLE IF NOT EXISTS "t_abc"."`+table+`"`)
				if copyAt < 0 {
					t.Fatalf("registry silo plan missing %s table", table)
				}
				if copyAt > lastCopy {
					lastCopy = copyAt
				}
			}
			firstFK := strings.Index(joined, `ADD CONSTRAINT "fx2_context_tenant_fk"`)
			if lastCopy < 0 || firstFK < lastCopy {
				t.Fatalf("registry foreign keys precede silo table copies: %s", joined)
			}
			indexAt := strings.Index(joined, `CREATE UNIQUE INDEX IF NOT EXISTS "fx2_tests_tenant_id_id_uidx" ON "t_abc"."tests"`)
			if indexAt < lastCopy || indexAt > firstFK {
				t.Fatalf("path test FK target index must follow silo copies and precede foreign keys")
			}
			incidentIndexAt := strings.Index(joined, `CREATE UNIQUE INDEX IF NOT EXISTS "fx2_incidents_tenant_id_id_uidx" ON "t_abc"."incidents"`)
			if incidentIndexAt < lastCopy || incidentIndexAt > firstFK {
				t.Fatal("signal FK target index must follow silo copies and precede foreign keys")
			}
			signalIndexAt := strings.Index(joined, `CREATE UNIQUE INDEX IF NOT EXISTS "fx2_incident_signals_tenant_id_id_uidx" ON "t_abc"."incident_signals"`)
			if signalIndexAt < lastCopy || signalIndexAt > firstFK {
				t.Fatal("override signal FK target index must follow silo copies and precede foreign keys")
			}
			for _, want := range []string{
				`ADD CONSTRAINT "fx2_context_tenant_fk" FOREIGN KEY (tenant_id) REFERENCES public.tenants (id)`,
				`ADD CONSTRAINT "fx2_path_test_fk" FOREIGN KEY (tenant_id, test_id) REFERENCES "t_abc"."tests" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_path_context_fk" FOREIGN KEY (tenant_id, context_id) REFERENCES "t_abc"."entity_contexts" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_agent_context_fk" FOREIGN KEY (tenant_id, context_id) REFERENCES "t_abc"."entity_contexts" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_source_context_fk" FOREIGN KEY (tenant_id, context_id) REFERENCES "t_abc"."entity_contexts" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_source_agent_context_fk" FOREIGN KEY (tenant_id, agent_id, context_id) REFERENCES "t_abc"."entity_agent_contexts" (tenant_id, agent_id, context_id) ON UPDATE CASCADE`,
				`ADD CONSTRAINT "fx2_source_anchor_fk" FOREIGN KEY (tenant_id, context_id, anchor_entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id) ON DELETE SET NULL (anchor_entity_id)`,
				`ADD CONSTRAINT "fx2_entity_context_fk" FOREIGN KEY (tenant_id, context_id) REFERENCES "t_abc"."entity_contexts" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_interface_parent_fk" FOREIGN KEY (tenant_id, context_id, parent_entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id)`,
				`ADD CONSTRAINT "fx2_evidence_entity_fk" FOREIGN KEY (tenant_id, context_id, entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id)`,
				`ADD CONSTRAINT "fx2_evidence_support_fk" FOREIGN KEY (tenant_id, context_id, support_evidence_id) REFERENCES "t_abc"."entity_evidence" (tenant_id, context_id, id)`,
				`ADD CONSTRAINT "fx2_link_from_fk" FOREIGN KEY (tenant_id, context_id, from_entity_id)`,
				`ADD CONSTRAINT "fx2_link_to_fk" FOREIGN KEY (tenant_id, context_id, to_entity_id)`,
				`ADD CONSTRAINT "fx2_link_evidence_fk" FOREIGN KEY (tenant_id, context_id, evidence_id)`,
				`ADD CONSTRAINT "fx2_incident_entity_fk" FOREIGN KEY (tenant_id, entity_context_id, entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id) ON DELETE SET NULL (entity_id)`,
				`ADD CONSTRAINT "fx2_signal_entity_fk" FOREIGN KEY (tenant_id, entity_context_id, entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id) ON DELETE SET NULL (entity_id)`,
				`ADD CONSTRAINT "fx2_signal_incident_fk" FOREIGN KEY (tenant_id, incident_id) REFERENCES "t_abc"."incidents" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_override_entity_fk" FOREIGN KEY (tenant_id, entity_context_id, entity_id) REFERENCES "t_abc"."entities" (tenant_id, context_id, id) ON DELETE SET NULL (entity_id)`,
				`ADD CONSTRAINT "fx2_override_source_fk" FOREIGN KEY (tenant_id, source_incident_id) REFERENCES "t_abc"."incidents" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_override_detached_fk" FOREIGN KEY (tenant_id, detached_incident_id) REFERENCES "t_abc"."incidents" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_override_signal_fk" FOREIGN KEY (tenant_id, source_signal_id) REFERENCES "t_abc"."incident_signals" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_fault_receipt_tenant_fk" FOREIGN KEY (tenant_id) REFERENCES public.tenants (id)`,
				`ADD CONSTRAINT "fx2_fault_receipt_incident_fk" FOREIGN KEY (tenant_id, incident_id) REFERENCES "t_abc"."incidents" (tenant_id, id)`,
				`ADD CONSTRAINT "fx2_incidents_entity_pair_ck" CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL)`,
				`ADD CONSTRAINT "fx2_incident_signals_entity_pair_ck" CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL)`,
				`ADD CONSTRAINT "fx2_incident_correlation_overrides_entity_pair_ck" CHECK (entity_id IS NULL OR entity_context_id IS NOT NULL)`,
				`ADD CONSTRAINT "fx2_incidents_identity_lookup_ck" CHECK (entity_context_id IS NULL OR identity_lookup_attempted)`,
				`ADD CONSTRAINT "fx2_incident_signals_identity_lookup_ck" CHECK (entity_context_id IS NULL OR identity_lookup_attempted)`,
				`ADD CONSTRAINT "fx2_incident_correlation_overrides_identity_lookup_ck" CHECK (entity_context_id IS NULL OR identity_lookup_attempted)`,
			} {
				if !strings.Contains(joined, want) {
					t.Fatalf("registry silo plan missing %s", want)
				}
			}
			if strings.Count(joined, `conrelid = '"t_abc".`) != 29 {
				t.Fatalf("registry silo plan did not make all twenty-nine foreign keys and checks idempotent")
			}
			if !strings.Contains(joined, `CREATE TRIGGER entity_path_retarget AFTER UPDATE OF target ON "t_abc"."tests"`) ||
				!strings.Contains(joined, `ALTER TABLE "t_abc"."tests" ENABLE ALWAYS TRIGGER entity_path_retarget`) {
				t.Fatal("path retarget invalidation trigger was not installed in the silo")
			}
		})
	}
	if joined := strings.Join(ProvisionPlan("t_abc", []string{"agents", "tests"}), "\n"); strings.Contains(joined, "fx2_") {
		t.Fatal("old product versions cannot plan FX-2 foreign keys")
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
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."new_table" AS RESTRICTIVE`,
		`ALTER TABLE "t_abc"."tests" ADD COLUMN IF NOT EXISTS "added_later" text DEFAULT ''::text NOT NULL`,
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."tests" AS RESTRICTIVE`,
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."agents" AS RESTRICTIVE`,
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
	if d.empty() || len(d.MissingTables) != 1 || d.MissingTables[0] != "new_table" ||
		len(d.MissingColumns) != 1 || d.MissingColumns[0] != "tests.added_later" {
		t.Fatalf("drift: %+v", d)
	}

	// Fully caught up still repairs every table's boundary; structural drift is
	// empty, but policy drift is a startup-critical property rather than a
	// one-time provisioning assumption.
	cat.SchemaTables = []string{"tests", "agents", "new_table"}
	cat.SchemaColumns["new_table"] = cat.Columns["new_table"]
	cat.SchemaColumns["tests"] = cat.Columns["tests"]
	caughtUp := strings.Join(CatchUpPlan("t_abc", cat), "\n")
	for _, table := range []string{"agents", "new_table", "tests"} {
		if !strings.Contains(
			caughtUp,
			`CREATE POLICY tenant_schema_isolation ON "t_abc"."`+table+`" AS RESTRICTIVE`,
		) {
			t.Fatalf("caught-up plan did not repair %s boundary:\n%s", table, caughtUp)
		}
		assertNoAuditWriteFencePlan(t, caughtUp, table)
		assertTenantWriteFencePlan(t, caughtUp, table)
	}
	if strings.Contains(caughtUp, "CREATE TABLE") ||
		strings.Contains(caughtUp, "ADD COLUMN") {
		t.Fatalf("caught-up plan contains structural DDL:\n%s", caughtUp)
	}
	genericGuardAt := strings.Index(
		caughtUp,
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."tests" AS RESTRICTIVE`,
	)
	genericGrantAt := strings.Index(
		caughtUp,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON "t_abc"."tests" TO probectl_app`,
	)
	if genericGuardAt < 0 || genericGrantAt < 0 || genericGuardAt > genericGrantAt {
		t.Fatalf("generic table boundary must be repaired before grants:\n%s", caughtUp)
	}
	if !DiffDrift(cat).empty() {
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
		`DROP POLICY IF EXISTS tenant_schema_isolation ON "t_abc"."audit_events"`,
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."audit_events" AS RESTRICTIVE`,
		`REVOKE ALL ON "t_abc"."audit_events" FROM probectl_app`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_events" TO probectl_app`,
		// AUD-04: the provider gets NO direct grant on audit_events.
		`REVOKE ALL ON "t_abc"."audit_events" FROM probectl_provider`,
	} {
		if !strings.Contains(repair, want) {
			t.Errorf("caught-up audit permission repair missing %q in:\n%s", want, repair)
		}
	}
	if strings.Contains(repair, `ON "t_abc"."audit_events" TO probectl_provider`) {
		t.Errorf("caught-up provider must hold no direct grant on audit_events:\n%s", repair)
	}
	policyAt := strings.Index(repair, `CREATE POLICY tenant_schema_isolation ON "t_abc"."audit_events" AS RESTRICTIVE`)
	grantAt := strings.Index(repair, `GRANT SELECT, INSERT ON "t_abc"."audit_events" TO probectl_app`)
	if policyAt < 0 || grantAt < 0 || policyAt > grantAt {
		t.Fatalf("audit boundary must be repaired before grants:\n%s", repair)
	}
	assertAuditWriteFencePlan(t, repair, "audit_events", "probectl_app")

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
		`CREATE POLICY tenant_schema_isolation ON "t_abc"."audit_subject_erasures" AS RESTRICTIVE`,
		`GRANT SELECT, INSERT ON "t_abc"."audit_subject_erasures" TO probectl_app`,
		`GRANT SELECT, INSERT, DELETE ON "t_abc"."audit_subject_erasures" TO probectl_provider`,
	} {
		if !strings.Contains(markerRepair, want) {
			t.Errorf("subject-erasure marker repair missing %q in:\n%s", want, markerRepair)
		}
	}
	assertAuditWriteFencePlan(t, markerRepair, "audit_events", "probectl_app")
	assertAuditWriteFencePlan(
		t,
		markerRepair,
		"audit_subject_erasures",
		"probectl_app, probectl_provider",
	)
	for _, table := range []string{"agents", "new_table", "tests"} {
		assertNoAuditWriteFencePlan(t, markerRepair, table)
		assertTenantWriteFencePlan(t, markerRepair, table)
	}
}

func assertAuditWriteFencePlan(t *testing.T, plan, table, roles string) {
	t.Helper()
	quotedTable := `"t_abc"."` + table + `"`
	for _, want := range []string{
		`CREATE POLICY tenant_audit_write_eligibility ON ` + quotedTable + ` AS RESTRICTIVE
  FOR INSERT TO ` + roles + `
  WITH CHECK (public.probectl_tenant_audit_writes_allowed())`,
		`CREATE TRIGGER tenant_audit_write_fence
  BEFORE INSERT ON ` + quotedTable + `
  FOR EACH ROW
  EXECUTE FUNCTION public.probectl_enforce_tenant_audit_write_fence()`,
		`ALTER TABLE ` + quotedTable + ` ENABLE ALWAYS TRIGGER tenant_audit_write_fence`,
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("%s audit write-fence plan missing %q in:\n%s", table, want, plan)
		}
	}
}

func assertNoAuditWriteFencePlan(t *testing.T, plan, table string) {
	t.Helper()
	quotedTable := `"t_abc"."` + table + `"`
	for _, forbidden := range []string{
		`tenant_audit_write_eligibility ON ` + quotedTable,
		`tenant_audit_write_fence
  BEFORE INSERT ON ` + quotedTable,
		`ALTER TABLE ` + quotedTable + ` ENABLE ALWAYS TRIGGER tenant_audit_write_fence`,
	} {
		if strings.Contains(plan, forbidden) {
			t.Fatalf("ordinary table %s received audit-only write fence %q", table, forbidden)
		}
	}
}

func assertTenantWriteFencePlan(t *testing.T, plan, table string) {
	t.Helper()
	quotedTable := `"t_abc"."` + table + `"`
	for _, want := range []string{
		`CREATE TRIGGER tenant_write_fence
  BEFORE INSERT OR UPDATE ON ` + quotedTable + `
  FOR EACH ROW
  EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()`,
		`ALTER TABLE ` + quotedTable + ` ENABLE ALWAYS TRIGGER tenant_write_fence`,
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("%s tenant write-fence plan missing %q in:\n%s", table, want, plan)
		}
	}
}

func TestSiloTenantPolicyBindsCallerAndSchemaTenantRestrictively(t *testing.T) {
	const (
		schema   = "t_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
		tenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	)
	plan := strings.Join(
		ProvisionPlan(schema, []string{"tests"}),
		"\n",
	)
	for _, want := range []string{
		`CREATE POLICY tenant_isolation ON "` + schema + `"."tests"`,
		`CREATE POLICY tenant_schema_isolation ON "` + schema + `"."tests" AS RESTRICTIVE`,
		`FOR ALL TO PUBLIC`,
		`tenant_id = '` + tenantID + `'::uuid`,
		`tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid`,
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("schema-bound policy missing %q:\n%s", want, plan)
		}
	}
	if got := strings.Count(plan, `tenant_id = '`+tenantID+`'::uuid`); got != 4 {
		t.Fatalf("schema tenant literal occurrences = %d, want 4:\n%s", got, plan)
	}

	invalid := strings.Join(ProvisionPlan("t_not-a-tenant", []string{"tests"}), "\n")
	if !strings.Contains(
		invalid,
		`CREATE POLICY tenant_schema_isolation ON "t_not-a-tenant"."tests" AS RESTRICTIVE`,
	) || !strings.Contains(invalid, "USING (false)") ||
		!strings.Contains(invalid, "WITH CHECK (false)") {
		t.Fatalf("invalid silo schema must generate a fail-closed guard:\n%s", invalid)
	}
}

func TestTeardownPlan(t *testing.T) {
	plan := TeardownPlan("t_abc")
	if len(plan) != 1 || plan[0] != `DROP SCHEMA IF EXISTS "t_abc" CASCADE` {
		t.Fatalf("teardown: %v", plan)
	}
}
