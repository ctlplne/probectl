// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSiloPrivateHistoryOwnerBoundarySurvivesProvisionAndCatchup(t *testing.T) {
	const schema = "t_000000000000000000000000000000ab"
	tables := []string{"flow_conversation_messages", "flow_conversation_jobs", "flow_conversation_epochs", "tests"}
	for _, plan := range [][]string{
		ProvisionPlan(schema, tables),
		CatchUpPlan(schema, Catalog{TenantTables: tables, SchemaTables: tables}),
	} {
		text := strings.Join(plan, "\n")
		for _, table := range tables {
			quoted := `"` + schema + `"."` + table + `"`
			if !strings.Contains(text, "CREATE POLICY tenant_schema_isolation ON "+quoted+" AS RESTRICTIVE") {
				t.Fatal("history family lost physical tenant guard")
			}
			present := strings.Contains(text, "CREATE POLICY flow_history_owner ON "+quoted+" AS RESTRICTIVE")
			if present != tenancy.FlowHistoryOwnerTable(table) {
				t.Fatalf("table %s owner guard=%v", table, present)
			}
			if present && !strings.Contains(text, "REVOKE ALL ON "+quoted+" FROM PUBLIC, probectl_provider") {
				t.Fatal("history source/job retained restored public/provider grants")
			}
		}
		if strings.Count(text, "WITH CHECK ("+tenancy.FlowHistoryOwnerPredicate+")") != 2 {
			t.Fatal("history owner WITH CHECK was omitted or narrowed")
		}
	}
}
