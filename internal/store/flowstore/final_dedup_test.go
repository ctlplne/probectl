// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"strings"
	"testing"
	"time"
)

// CORRECT-003: the flow table is a ReplacingMergeTree (dedup keyed on row_id),
// but a SELECT only sees collapsed duplicates if it reads with FINAL (or dedups
// per-key before aggregating). Without FINAL, an at-least-once redelivered
// NetFlow batch — distinct parts not yet merged — is summed twice. The eBPF
// store already reads FINAL; the flow aggregations must match.
//
// This is the always-on query-shape gate (it runs in every CI lane, not only
// when ClickHouse is reachable): it asserts the generated aggregation SQL reads
// the ReplacingMergeTree with FINAL. The live double-count assertion against a
// real ClickHouse is TestFlowFinalDedupRealRoundTrip (build tag `integration`,
// run in the integration job).
func TestAggregationsReadFinal(t *testing.T) {
	const table = sharedFlowsTable

	topQ := TopQuery{TenantID: "t-a", By: BySrc, Window: time.Hour, Now: time.Now()}
	if err := topQ.normalize(); err != nil {
		t.Fatalf("normalize top: %v", err)
	}
	topSQLText, _ := topSQL(topQ, table)
	if !strings.Contains(topSQLText, "FROM "+table+" FINAL") {
		t.Errorf("TopTalkers SQL does not read %s with FINAL — redelivered flows double-count:\n%s", table, topSQLText)
	}

	capQ := CapacityQuery{TenantID: "t-a", Window: time.Hour, Now: time.Now()}
	if err := capQ.normalize(); err != nil {
		t.Fatalf("normalize capacity: %v", err)
	}
	capSQLText, _ := capacitySQL(capQ, table)
	if !strings.Contains(capSQLText, "FROM "+table+" FINAL") {
		t.Errorf("Capacity SQL does not read %s with FINAL — redelivered flows double-count:\n%s", table, capSQLText)
	}
}

func TestFlowDedupDDLUsesReplacingMergeTreeRowID(t *testing.T) {
	ddl := createFlowsDedupDDL(sharedFlowsTable)
	for _, want := range []string{
		"ENGINE = ReplacingMergeTree",
		"row_id String",
		"ORDER BY (tenant_id, ts, exporter, src_addr, dst_addr, src_port, dst_port, protocol, row_id)",
	} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("dedup DDL missing %q:\n%s", want, ddl)
		}
	}
}
