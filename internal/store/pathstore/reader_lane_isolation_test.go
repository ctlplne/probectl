// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package pathstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// DPR-285: on real ClickHouse, a tenant read the store sends WITHOUT any
// tenant_id predicate still returns only the scoped tenant's rows, because it
// runs as the policy-bound reader login. The predicate-free count goes
// through the store's own tenant read path (queryScoped), which is exactly
// where a dropped WHERE would land. The plant half proves the property is the
// DB's: with the control login wired in as the "reader", the same read leaks
// the other tenant's rows and the boot proof refuses to start.
func TestPathReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_PATHSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := newClickHouse(rawURL)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().UnixNano()
	ta, tb := fmt.Sprintf("pathlane-a-%d", now), fmt.Sprintf("pathlane-b-%d", now)
	target := fmt.Sprintf("lane-target-%d.example", now)
	t.Cleanup(func() {
		_, _, _ = c.DeleteTenant(ctx, ta)
		_, _, _ = c.DeleteTenant(ctx, tb)
	})
	mk := func(ip string) *path.Path {
		return &path.Path{Target: target, TargetIP: ip, Mode: "icmp", MaxHops: 8,
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1}}}}}
	}
	if err := c.Save(ctx, ta, mk("198.51.100.10")); err != nil {
		t.Fatalf("save A: %v", err)
	}
	// B saves LAST, so a read that lost its tenant scope picks B's round.
	if err := c.Save(ctx, tb, mk("192.0.2.99")); err != nil {
		t.Fatalf("save B: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "pathlane_reader")
	scoped, err := newClickHouse(rawURL)
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
	unfiltered := "SELECT count() AS n FROM " + hopsTable // no tenant_id predicate
	rows, err := scoped.queryScoped(ctx, Target{}, ta, unfiltered, nil)
	if err != nil {
		t.Fatalf("predicate-free tenant read: %v", err)
	}
	if n := chCount(rows); n != 1 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: a predicate-free tenant A read through the reader lane counted %d hop rows, want only A's 1", n)
	}
	got, ok, err := scoped.Latest(ctx, ta, target)
	if err != nil || !ok || got.TargetIP != "198.51.100.10" {
		t.Fatalf("tenant A latest through the reader lane = %+v ok=%v err=%v", got, ok, err)
	}

	// Plant: the control login wired in as the reader. Nothing at the DB
	// filters it, so the same predicate-free read sees B's rows too — and the
	// boot proof refuses it.
	planted, err := newClickHouse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	rows, err = planted.queryScoped(ctx, Target{}, ta, unfiltered+" WHERE tenant_id IN ({a:String}, {b:String})", chParams{"a": ta, "b": tb})
	if err != nil {
		t.Fatalf("planted read: %v", err)
	}
	if n := chCount(rows); n != 2 {
		t.Fatalf("planted control-login reader counted %d rows, want 2 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	if err := planted.VerifyReaderIsolation(ctx, reader); err == nil {
		t.Fatal("the boot proof accepted the control login as the reader")
	}
}

// DPR-323: a per-tenant (siloed/hybrid) database is read through the same
// reader lane, so a read the router sends to ANOTHER tenant's database, with
// no tenant_id predicate, still finds nothing: ClickHouse admits the reader
// to a per-tenant table only under the row policy chclient.SiloScope
// installs. The plant half proves the property is the DB's: sent as the
// control login, the same misrouted read returns the other tenant's rows.
func TestPathSiloReadOfAnotherTenantsDatabaseFindsNothing(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_PATHSTORE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	ctx := context.Background()
	now := time.Now().UTC().UnixNano()
	ta, tb := fmt.Sprintf("pathsilo-a-%d", now), fmt.Sprintf("pathsilo-b-%d", now)
	dbB := Target{Database: fmt.Sprintf("probectl_t_pathsilo_b_%d", now)}
	writer, err := newClickHouse(rawURL)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	if err := writer.EnsureTenantDatabase(ctx, dbB, 0); err != nil {
		t.Fatalf("silo database: %v", err)
	}
	t.Cleanup(func() { _ = writer.DropTenantDatabase(ctx, dbB) })
	writer.WithRouter(func(context.Context, string) (Target, error) { return dbB, nil })
	if err := writer.Save(ctx, tb, &path.Path{Target: "silo-target.example", TargetIP: "192.0.2.77", Mode: "icmp", MaxHops: 8,
		Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "192.0.2.77", Sent: 1, Received: 1}}}}}); err != nil {
		t.Fatalf("save B into its silo: %v", err)
	}

	reader, readerClient := chtest.ProvisionReader(t, rawURL, "pathsilo_reader")
	scoped, err := newClickHouse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	scoped.WithTenantScoping(true).WithReader(readerClient)
	scope, ok := scoped.SiloReaderScope()
	if !ok {
		t.Fatal("a tenant-scoped store must expose its silo reader scope")
	}
	scope.ReaderUser = reader // bound directly: the pooled policy stays untouched
	if err := scope.Ensure(ctx, "", dbB.Database); err != nil {
		t.Fatalf("silo reader scope: %v", err)
	}
	if err := scope.Verify(ctx, "", dbB.Database); err != nil {
		t.Fatalf("a scoped silo must pass the boot proof: %v", err)
	}
	t.Cleanup(func() { _ = scope.Revoke(ctx, "", dbB.Database) })

	unfiltered := "SELECT count() AS n FROM " + dbB.Database + "." + hopsTable // no tenant_id predicate
	rows, err := scoped.queryScoped(ctx, dbB, ta, unfiltered, nil)
	if err != nil {
		t.Fatalf("misrouted tenant read: %v", err)
	}
	if n := chCount(rows); n != 0 {
		t.Fatalf("CROSS-TENANT LEAK at the DB: tenant A's predicate-free read of tenant B's silo counted %d rows, want 0", n)
	}
	rows, err = scoped.queryScoped(ctx, dbB, tb, unfiltered, nil)
	if err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if n := chCount(rows); n != 1 {
		t.Fatalf("tenant B's own read of its silo counted %d rows, want 1", n)
	}

	planted, err := newClickHouse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	planted.WithTenantScoping(true).WithReader(chtest.URLClient(rawURL))
	rows, err = planted.queryScoped(ctx, dbB, ta, unfiltered, nil)
	if err != nil {
		t.Fatalf("planted read: %v", err)
	}
	if n := chCount(rows); n != 1 {
		t.Fatalf("planted control-login reader counted %d rows of B's silo, want 1 (non-vacuity: without the policy-bound reader the DB does not filter)", n)
	}
	plantedScope, _ := planted.SiloReaderScope()
	plantedScope.ReaderUser = reader
	if err := plantedScope.Verify(ctx, "", dbB.Database); err == nil {
		t.Fatal("the silo boot proof accepted the control login as the reader")
	}
}
