// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package endpointstore

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

func endpointCountVia(ctx context.Context, t *testing.T, c *ClickHouse, tenant, extra string, params url.Values) int {
	t.Helper()
	lane, err := c.readLane(Target{}, tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set(tenantSetting, tenant)
	rows, err := c.queryOn(ctx, lane.Conn, lane.Key, c.laneBase(lane, ""),
		"SELECT count() AS n FROM "+eventsTable+extra+" FORMAT JSONEachRow", params)
	if err != nil {
		t.Fatalf("lane read: %v", err)
	}
	return chclient.Count(rows)
}

// DPR-285: on real ClickHouse, a tenant read the store sends WITHOUT any
// tenant_id predicate still returns only the scoped tenant's rows, because it
// runs as the policy-bound reader login (see the pathstore twin). The plant
// half wires the control login in as the "reader": the same read leaks and
// the boot proof refuses it.
func TestEndpointReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_ENDPOINTSTORE_URL")
	if rawURL == "" {
		rawURL = os.Getenv("PROBECTL_FLOWSTORE_URL")
	}
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_ENDPOINTSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta, tb := fmt.Sprintf("eplane-a-%d", now.UnixNano()), fmt.Sprintf("eplane-b-%d", now.UnixNano())
	t.Cleanup(func() {
		_, _ = c.DeleteTenant(ctx, ta)
		_, _ = c.DeleteTenant(ctx, tb)
	})
	if err := c.Insert(ctx, []Event{
		{TenantID: ta, AgentID: "a1", Type: "endpoint.session", SignalKey: "k-a", Target: "a.example", ObservedAt: now},
		{TenantID: tb, AgentID: "b1", Type: "endpoint.session", SignalKey: "k-b", Target: "b.example", ObservedAt: now},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "eplane_reader")
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
	if n := endpointCountVia(ctx, t, scoped, ta, "", nil); n != 1 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: a predicate-free tenant A read through the reader lane counted %d events, want only A's 1", n)
	}
	events, err := scoped.Latest(ctx, ta)
	if err != nil || len(events) != 1 || events[0].Target != "a.example" {
		t.Fatalf("tenant A events through the reader lane = %+v err=%v", events, err)
	}

	planted, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	if n := endpointCountVia(ctx, t, planted, ta, " WHERE tenant_id IN ({a:String}, {b:String})",
		url.Values{"param_a": {ta}, "param_b": {tb}}); n != 2 {
		t.Fatalf("planted control-login reader counted %d events, want 2 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	if err := planted.VerifyReaderIsolation(ctx, reader); err == nil {
		t.Fatal("the boot proof accepted the control login as the reader")
	}
}
