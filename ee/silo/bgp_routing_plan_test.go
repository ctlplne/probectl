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

func TestBGPRoutingPlanKeepsEveryReferenceInItsTenantSchema(t *testing.T) {
	tables := []string{"entity_contexts", "entities", "entity_agent_contexts", "entity_source_contexts", "bgp_routing_views", "bgp_routing_entries"}
	schema := "t_11111111111141118111111111111111"
	for _, statements := range [][]string{ProvisionPlan(schema, tables), CatchUpPlan(schema, Catalog{TenantTables: tables, SchemaTables: tables})} {
		plan := strings.Join(statements, "\n")
		for _, want := range []string{
			`"fx5_route_view_tenant_fk" FOREIGN KEY (tenant_id) REFERENCES public.tenants (id)`,
			`"fx5_route_view_context_fk" FOREIGN KEY (tenant_id,context_id) REFERENCES "` + schema + `"."entity_contexts" (tenant_id,id)`,
			`"fx5_route_view_router_fk" FOREIGN KEY (tenant_id,context_id,router_id,router_kind) REFERENCES "` + schema + `"."entities" (tenant_id,context_id,id,kind)`,
			`"fx5_route_view_collector_context_fk" FOREIGN KEY (tenant_id,collector_agent_id,collector_context_id) REFERENCES "` + schema + `"."entity_agent_contexts" (tenant_id,agent_id,context_id)`,
			`"fx5_route_view_source_fk" FOREIGN KEY (tenant_id,collector_agent_id,binding_kind,source_ref) REFERENCES "` + schema + `"."entity_source_contexts" (tenant_id,agent_id,source_kind,source_ref)`,
			`"fx5_route_entry_view_fk" FOREIGN KEY (tenant_id,context_id,view_id,generation,afi,safi) REFERENCES "` + schema + `"."bgp_routing_views" (tenant_id,context_id,id,generation,afi,safi)`,
		} {
			if !strings.Contains(plan, want) {
				t.Fatal("routing generation reference escaped its physical tenant schema", want)
			}
		}
	}
	if len(bgpRoutingStoragePlan(schema, []string{"entity_contexts"})) != 0 {
		t.Fatal("routing plan invented absent tenant tables")
	}
}

func TestBGPRoutingBindingPlanPreservesStoredCollectorContextOnCatchUp(t *testing.T) {
	const expression = "COALESCE(((routing_selection ->> 'base_context_id'::text))::uuid, context_id)"
	schema := "t_11111111111141118111111111111111"
	tables := []string{"bgp_routing_views", "entity_agent_contexts"}
	cat := Catalog{TenantTables: tables, SchemaTables: tables,
		Columns: map[string][]Column{"bgp_routing_views": {
			{Name: "routing_selection", DataType: "jsonb"},
			{Name: "collector_context_id", DataType: "uuid", Generated: expression},
		}}}
	plan := strings.Join(CatchUpPlan(schema, cat), "\n")
	want := `ADD COLUMN IF NOT EXISTS "collector_context_id" uuid GENERATED ALWAYS AS (` + expression + `) STORED`
	if !strings.Contains(plan, want) || strings.Contains(plan, `"collector_context_id" uuid DEFAULT`) {
		t.Fatal("silo catch-up lost computed base context storage", plan)
	}
	for _, check := range []string{"fx5_route_view_kind_check", "fx5_route_view_routing_selection_check", "fx5_route_view_collector_context_fk"} {
		if !strings.Contains(plan, check) {
			t.Fatal("silo catch-up omitted routing binding boundary", check)
		}
	}
	newFK := strings.Index(plan, `ADD CONSTRAINT "fx5_route_view_collector_context_fk"`)
	oldFK := strings.Index(plan, `DROP CONSTRAINT IF EXISTS fx5_route_view_agent_context_fk`)
	if newFK < 0 || oldFK <= newFK {
		t.Fatal("silo catch-up retired assignment boundary before its replacement")
	}
}
