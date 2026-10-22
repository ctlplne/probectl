// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package ebpfstore

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// edgeCountVia counts edges on the store's tenant read lane WITHOUT any
// tenant_id predicate beyond extra.
func edgeCountVia(ctx context.Context, t *testing.T, c *ClickHouse, tenant, extra string, params url.Values) int {
	t.Helper()
	lane, err := c.readLane(Target{}, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set(tenantSettingName, tenant)
	rows, err := c.queryOn(ctx, lane.Conn, lane.Key, c.laneBase(lane, ""),
		"SELECT count() AS n FROM "+edgesTable+extra+" FORMAT JSONEachRow", params)
	if err != nil {
		t.Fatalf("lane read: %v", err)
	}
	return int(num(rows[0]["n"]))
}

// DPR-285: on real ClickHouse, a tenant read the store sends WITHOUT any
// tenant_id predicate still returns only the scoped tenant's rows, because it
// runs as the policy-bound reader login (see the pathstore twin). The plant
// half wires the control login in as the "reader": the same read leaks and
// the boot proof refuses it.
func TestEBPFReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_EBPFSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_EBPFSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ta, tb := fmt.Sprintf("ebpflane-a-%d", now.UnixNano()), fmt.Sprintf("ebpflane-b-%d", now.UnixNano())
	t.Cleanup(func() {
		_, _ = c.DeleteTenant(ctx, ta)
		_, _ = c.DeleteTenant(ctx, tb)
	})
	if err := c.Insert(ctx, []Edge{
		{TenantID: ta, AgentID: "n1", WindowStart: now, SrcWorkload: "web", DstWorkload: "db", DstPort: 5432, L7Protocol: "tcp", Bytes: 1000, Packets: 10, Connections: 2},
		{TenantID: tb, AgentID: "n9", WindowStart: now, SrcWorkload: "x", DstWorkload: "y", DstPort: 443, L7Protocol: "tls", Bytes: 9999, Packets: 99, Connections: 9},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "ebpflane_reader")
	scoped, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	scoped.WithTenantScoping(true).WithReader(readerClient)
	if err := scoped.EnsureReaderRowPolicy(ctx, reader); err != nil {
		t.Fatalf("reader policy: %v", err)
	}
	if err := scoped.VerifyReaderIsolation(ctx, reader); err != nil {
		t.Fatalf("a policy-bound least-privilege reader must pass the boot proof: %v", err)
	}
	if n := edgeCountVia(ctx, t, scoped, ta, "", nil); n != 1 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: a predicate-free tenant A read through the reader lane counted %d edges, want only A's 1", n)
	}
	edges, err := scoped.TopEdges(ctx, ta, EdgeQuery{})
	if err != nil || len(edges) != 1 || edges[0].SrcWorkload != "web" {
		t.Fatalf("tenant A edges through the reader lane = %+v err=%v", edges, err)
	}

	planted, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	if n := edgeCountVia(ctx, t, planted, ta, " WHERE tenant_id IN ({a:String}, {b:String})",
		url.Values{"param_a": {ta}, "param_b": {tb}}); n != 2 {
		t.Fatalf("planted control-login reader counted %d edges, want 2 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	if err := planted.VerifyReaderIsolation(ctx, reader); err == nil {
		t.Fatal("the boot proof accepted the control login as the reader")
	}
}
