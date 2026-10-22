// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package otelstore

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
func TestOtelReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_OTELSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_OTELSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta, tb := fmt.Sprintf("otellane-a-%d", now.UnixNano()), fmt.Sprintf("otellane-b-%d", now.UnixNano())
	t.Cleanup(func() {
		_, _, _ = c.EraseTenant(ctx, ta)
		_, _, _ = c.EraseTenant(ctx, tb)
	})
	if err := c.WriteSpans(ctx, []Span{
		{TenantID: ta, TraceID: "aa", SpanID: "01", Service: "checkout", Start: now},
		{TenantID: tb, TraceID: "bb", SpanID: "02", Service: "checkout", Start: now.Add(time.Millisecond)},
	}); err != nil {
		t.Fatalf("write spans: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "otellane_reader")
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
	unfiltered := "SELECT count() AS n FROM " + spansTable // no tenant_id predicate
	rows, err := scoped.queryScoped(ctx, Target{}, ta, unfiltered, nil)
	if err != nil {
		t.Fatalf("predicate-free tenant read: %v", err)
	}
	if n := countOf(rows[0]["n"]); n != 1 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: a predicate-free tenant A read through the reader lane counted %d spans, want only A's 1", n)
	}
	spans, err := scoped.QuerySpans(ctx, ta, SpanQuery{Service: "checkout"})
	if err != nil || len(spans) != 1 || spans[0].TraceID != "aa" {
		t.Fatalf("tenant A spans through the reader lane = %+v err=%v", spans, err)
	}

	planted, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	rows, err = planted.queryScoped(ctx, Target{}, ta, unfiltered+" WHERE tenant_id IN ({a:String}, {b:String})", chParams{"a": ta, "b": tb})
	if err != nil {
		t.Fatalf("planted read: %v", err)
	}
	if n := countOf(rows[0]["n"]); n != 2 {
		t.Fatalf("planted control-login reader counted %d spans, want 2 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	if err := planted.VerifyReaderIsolation(ctx, reader); err == nil {
		t.Fatal("the boot proof accepted the control login as the reader")
	}
}
