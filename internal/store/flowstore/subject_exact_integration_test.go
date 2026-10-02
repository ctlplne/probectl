// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFlowDeleteSubjectIsExactNotSubstring is the TEN-05 regression against a
// real ClickHouse. The old flowSubjectPredicate used positionCaseInsensitive,
// so DeleteSubject("10.0.0.1") also matched the neighboring addresses
// "10.0.0.10" and "110.0.0.1" and destroyed three subjects' rows for one DSAR
// request. With exact, field-typed equality it must delete EXACTLY the one row
// whose src_addr is "10.0.0.1" and leave the other two tenant rows intact.
//
// Runs in the integration job (PROBECTL_FLOWSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when PROBECTL_TEST_REQUIRE_SERVICES=1
// but CH is unavailable, so it can never pass by silently skipping in CI.
func TestFlowDeleteSubjectIsExactNotSubstring(t *testing.T) {
	url := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — TEN-05 exact-match gate runs in CI")
	}
	c, err := NewClickHouse(url, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("itest-ten05-flow-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Second)
	t.Cleanup(func() { _, _ = c.DeleteTenant(ctx, tenant) })

	row := func(src string) Row {
		return Row{
			TenantID: tenant, AgentID: "a1", Exporter: "e1", Protocol: "netflow",
			TS: now, StartTS: now.Add(-time.Second),
			SrcAddr: src, DstAddr: "203.0.113.9", SrcPort: 40000, DstPort: 443,
			Transport: "tcp", Bytes: 1000, Packets: 10,
		}
	}
	// Three neighboring src_addr values; "10.0.0.1" is a substring of the other
	// two, so the pre-fix predicate matched all three.
	if err := c.Insert(ctx, []Row{row("10.0.0.1"), row("10.0.0.10"), row("110.0.0.1")}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	tenantRows := func() int64 {
		t.Helper()
		rows, err := c.query(ctx, "",
			"SELECT count() AS n FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String}",
			chParams{"tenant": tenant})
		if err != nil {
			t.Fatalf("count tenant rows: %v", err)
		}
		if len(rows) == 0 {
			return 0
		}
		return int64(chToUint64(rows[0]["n"]))
	}
	exactRows := func(addr string) int64 {
		t.Helper()
		rows, err := c.query(ctx, "",
			"SELECT count() AS n FROM "+sharedFlowsTable+" WHERE tenant_id={tenant:String} AND src_addr={a:String}",
			chParams{"tenant": tenant, "a": addr})
		if err != nil {
			t.Fatalf("count src_addr %s: %v", addr, err)
		}
		if len(rows) == 0 {
			return 0
		}
		return int64(chToUint64(rows[0]["n"]))
	}

	if got := tenantRows(); got != 3 {
		t.Fatalf("seed precondition: tenant rows=%d, want 3", got)
	}

	deleted, remaining, err := c.DeleteSubject(ctx, tenant, "10.0.0.1")
	if err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	if deleted != 1 || remaining != 0 {
		t.Fatalf("DeleteSubject(10.0.0.1) = deleted=%d remaining=%d, want 1/0 (substring over-match deletes 3)", deleted, remaining)
	}
	if got := tenantRows(); got != 2 {
		t.Fatalf("tenant rows after subject delete = %d, want 2 survivors (10.0.0.10, 110.0.0.1)", got)
	}
	if got := exactRows("10.0.0.1"); got != 0 {
		t.Fatalf("subject row survived: %d rows with src_addr=10.0.0.1", got)
	}
	if got := exactRows("10.0.0.10"); got != 1 {
		t.Errorf("CROSS-SUBJECT LOSS: neighbor 10.0.0.10 was erased (rows=%d, want 1)", got)
	}
	if got := exactRows("110.0.0.1"); got != 1 {
		t.Errorf("CROSS-SUBJECT LOSS: neighbor 110.0.0.1 was erased (rows=%d, want 1)", got)
	}
}
