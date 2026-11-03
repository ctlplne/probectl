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

func TestTagStoragePlanRepairsOldSiloBeforeTypedForeignKeys(t *testing.T) {
	const schema = "t_11111111111141118111111111111111"
	base := []string{"tests", "entity_contexts", "entity_path_test_contexts",
		"entity_agent_contexts", "entity_source_contexts", "entities",
		"entity_evidence", "entity_links", "incidents", "incident_signals",
		"incident_correlation_overrides"}
	tables := append(append([]string{}, base...), "entity_test_contexts",
		"tenant_tag_revisions", "tenant_tag_definitions", "tenant_tag_assignments", "tenant_tag_rules")
	for name, plan := range map[string][]string{
		"provision": ProvisionPlan(schema, tables),
		"old-silo catch-up": CatchUpPlan(schema, Catalog{
			TenantTables: tables, SchemaTables: base,
		}),
	} {
		t.Run(name, func(t *testing.T) {
			joined := strings.Join(plan, "\n")
			mustContain := []string{
				`INSERT INTO "` + schema + `"."entity_test_contexts"`,
				`WHERE tenant_id='11111111-1111-4111-8111-111111111111'::uuid`,
				`ADD CONSTRAINT "fx3_tag_assignment_entity_fk" FOREIGN KEY (tenant_id,context_id,entity_id,entity_kind)`,
				`ADD CONSTRAINT "fx3_tag_assignment_exporter_fk" FOREIGN KEY (tenant_id,context_id,exporter_agent_id,exporter_source_kind,exporter_source_ref)`,
				`ADD CONSTRAINT "fx3_tag_assignment_test_fk" FOREIGN KEY (tenant_id,test_id,context_id)`,
				`CREATE TRIGGER entity_test_retarget`,
				`CREATE TRIGGER "tenant_tag_revision_insert"`,
				`ENABLE ALWAYS TRIGGER "tenant_tag_revision_delete"`,
				`DROP TRIGGER IF EXISTS "tenant_tag_revision_insert" ON "` + schema + `"."entity_source_contexts"`,
				`DROP TRIGGER IF EXISTS "tenant_tag_revision_update" ON "` + schema + `"."entity_agent_contexts"`,
				`ADD CONSTRAINT "tenant_tag_rules_match_v3_check" CHECK`,
				`octet_length(snmp_value) BETWEEN 1 AND 1024`,
				`translate(snmp_value, E'\t\n\r', '') !~ '[[:cntrl:]]'`,
			}
			for _, want := range mustContain {
				if !strings.Contains(joined, want) {
					t.Errorf("missing silo tag guard %q", want)
				}
			}
			indexAt := strings.Index(joined, `CREATE UNIQUE INDEX IF NOT EXISTS "entities_tenant_context_id_kind_uidx"`)
			fkAt := strings.Index(joined, `ADD CONSTRAINT "fx3_tag_assignment_entity_fk"`)
			if name == "provision" {
				if indexAt < 0 || fkAt <= indexAt ||
					!strings.Contains(joined, `"entity_sources_tenant_context_identity_uidx" ON "`+schema+`"."entity_source_contexts"`) {
					t.Fatal("new silo must create empty-table index targets before typed assignment FKs")
				}
			} else if indexAt >= 0 || strings.Contains(joined, `CREATE UNIQUE INDEX IF NOT EXISTS "entity_sources_tenant_context_identity_uidx"`) {
				t.Fatal("old silo catch-up must build existing-table indexes concurrently before its transaction")
			}
		})
	}
	if joined := strings.Join(ProvisionPlan(schema, base), "\n"); strings.Contains(joined, "tenant_tag_rules_match_v3_check") {
		t.Fatal("a pre-tag product version cannot install a CHECK on an absent tag table")
	}
}
