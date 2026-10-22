// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package flowstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// DPR-285: on real ClickHouse, a tenant read the store sends WITHOUT any
// tenant_id predicate still returns only the scoped tenant's rows, because it
// runs as the policy-bound reader login (see the pathstore twin). The plant
// half wires the control login in as the "reader": the same read leaks and
// the boot proof refuses it.
func TestFlowReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouse(rawURL, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ta, tb := fmt.Sprintf("flowlane-a-%d", now.UnixNano()), fmt.Sprintf("flowlane-b-%d", now.UnixNano())
	t.Cleanup(func() {
		_, _ = c.DeleteTenant(ctx, ta)
		_, _ = c.DeleteTenant(ctx, tb)
	})
	if err := c.Insert(ctx, []Row{
		{TenantID: ta, Exporter: "edge-a", Protocol: "netflow", TS: now, StartTS: now.Add(-time.Second), SrcAddr: "198.51.100.10", DstAddr: "203.0.113.10", Bytes: 100, Packets: 1},
		{TenantID: tb, Exporter: "edge-b", Protocol: "netflow", TS: now, StartTS: now.Add(-time.Second), SrcAddr: "192.0.2.99", DstAddr: "203.0.113.99", Bytes: 900, Packets: 9},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "flowlane_reader")
	scoped, err := NewClickHouse(rawURL, 0)
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
	unfiltered := "SELECT count() AS n FROM " + sharedFlowsTable // no tenant_id predicate
	rows, err := scoped.queryScoped(ctx, Target{}, ta, unfiltered, nil)
	if err != nil {
		t.Fatalf("predicate-free tenant read: %v", err)
	}
	if n := chCount(rows[0]["n"]); n != 1 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: a predicate-free tenant A read through the reader lane counted %d flows, want only A's 1", n)
	}
	top, err := scoped.TopTalkers(ctx, TopQuery{TenantID: ta, By: BySrc, Window: time.Hour, Now: now.Add(time.Minute), Limit: 10})
	if err != nil || len(top) != 1 || top[0].Key != "198.51.100.10" {
		t.Fatalf("tenant A top talkers through the reader lane = %+v err=%v", top, err)
	}

	planted, err := NewClickHouse(rawURL, 0)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	rows, err = planted.queryScoped(ctx, Target{}, ta, unfiltered+" WHERE tenant_id IN ({a:String}, {b:String})", chParams{"a": ta, "b": tb})
	if err != nil {
		t.Fatalf("planted read: %v", err)
	}
	if n := chCount(rows[0]["n"]); n != 2 {
		t.Fatalf("planted control-login reader counted %d flows, want 2 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	if err := planted.VerifyReaderIsolation(ctx, reader); err == nil {
		t.Fatal("the boot proof accepted the control login as the reader")
	}
}
