// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestFlowServiceColumnsPreserveTenantSQLRollupsAndOriginalDedupIdentity(t *testing.T) {
	row := explorerFixtureRow("red")
	identity := flowRowID(row)
	row.SrcService, row.DstService, row.ServiceEvidence = "source service", "destination service", `{"version":1,"complete":"original"}`
	row.ServiceClassifiedAt = "2026-11-15T10:00:00.123456789Z"
	if flowRowID(row) != identity || ServiceAttributionBytes(row) <= 0 {
		t.Fatal("derived attribution changed original dedup identity or escaped admission")
	}
	for _, prefix := range []string{"", "owned_tenant."} {
		raw, rollup, view := prefix+sharedFlowsTable, prefix+sharedFlowRollupsTable, prefix+sharedFlowRollupsMV
		migration := serviceAttributionMigration(raw, rollup, view)
		joined := strings.Join(migration.Statements, "\n")
		if migration.Version != 10 || !strings.Contains(joined, "CREATE MATERIALIZED VIEW IF NOT EXISTS "+view+"_v10") || !strings.Contains(joined, "DROP TABLE IF EXISTS "+view+"_v7") || strings.Contains(joined, "DROP TABLE IF EXISTS "+raw+"\n") {
			t.Fatal("service upgrade lost existing table or predecessor ordering", joined)
		}
		for _, column := range serviceColumns {
			if !strings.Contains(joined, "ADD COLUMN IF NOT EXISTS "+column.name+" "+column.typ) {
				t.Fatal("upgrade omitted service column", column.name)
			}
		}
		backfill := fullRollupBackfillSQL(raw, rollup)
		if !strings.Contains(backfill, "tenant_id={tenant:String}") || !strings.Contains(backfill, "service_evidence") || !strings.Contains(backfill, "routing_capture_key") {
			t.Fatal("retention replay dropped tenant scope or original metadata", backfill)
		}
	}
	plan := flow.QueryPlan{From: row.TS, To: row.TS.AddDate(0, 0, 1), GroupBy: []string{"src_service", "dst_service_region"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, View: "table", Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_service", Op: flow.QueryEqual, Values: []string{"x' OR tenant_id!='red"}}}}}
	normal, err := flow.NormalizeQueryPlan(plan, row.TS)
	if err != nil {
		t.Fatal(err)
	}
	sql, params, err := planSQL(normal, sharedFlowsTable, nil)
	if err != nil || !strings.Contains(sql, "tenant_id={tenant:String}") || strings.Contains(sql, "x' OR") {
		t.Fatal("service filter escaped bound tenant input", sql, params, err)
	}
}
