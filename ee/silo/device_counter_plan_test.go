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

func TestDeviceCounterStoragePlanKeepsTenantReferencesAndErasureFence(t *testing.T) {
	const schema = "t_11111111111141118111111111111111"
	tables := []string{"device_counter_captures", "device_counter_capture_sources", "entity_source_contexts", "entities", "flow_snapshot_epochs"}
	for _, statements := range [][]string{ProvisionPlan(schema, tables), CatchUpPlan(schema, Catalog{TenantTables: tables, SchemaTables: tables})} {
		plan := strings.Join(statements, "\n")
		for _, want := range []string{
			`FOREIGN KEY (tenant_id) REFERENCES public.tenants (id)`,
			`REFERENCES "` + schema + `"."device_counter_captures" (tenant_id,capture_key)`,
			`REFERENCES "` + schema + `"."entities" (tenant_id,context_id,id,kind)`,
			`REFERENCES "` + schema + `"."entity_source_contexts" (tenant_id,context_id,agent_id,source_kind,source_ref)`,
			`CREATE TRIGGER source_observation_fence BEFORE INSERT OR UPDATE ON "` + schema + `"."flow_snapshot_epochs"`,
			`ENABLE ALWAYS TRIGGER source_observation_fence`,
			`GRANT SELECT, INSERT, DELETE ON "` + schema + `"."device_counter_capture_sources" TO probectl_app`,
		} {
			if !strings.Contains(plan, want) {
				t.Fatal("counter witness lost its tenant schema, immutable role or erasure fence", want)
			}
		}
		if strings.Contains(plan, "REFERENCES public.entities") || strings.Contains(plan, "REFERENCES public.device_counter_captures") {
			t.Fatal("silo witness references another tenant storage domain")
		}
	}
}
