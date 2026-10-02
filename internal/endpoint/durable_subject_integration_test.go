// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package endpoint

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestEndpointSubjectEraseReachesDurableStore is the ING-15 regression against a
// real ClickHouse durable endpoint store. Before the fix Repository.DeleteSubject
// only cleared this replica's bounded cache, so the durable rows survived: the
// subject reappeared on the next Latest/restart and on every other replica while
// the receipt still reported "complete" — a false attestation. The fix erases the
// durable rows too. It also proves TEN-05 exact matching on the endpoint plane:
// erasing "10.0.0.1" must not touch "10.0.0.10" / "110.0.0.1".
//
// This drives the public Repository.DeleteSubject + durable.Latest seam (both
// present before the fix), so it compiles and fails RED on the baseline and
// passes GREEN after the fix.
func TestEndpointSubjectEraseReachesDurableStore(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL not set — ING-15 durable erasure gate runs in CI")
	}
	durable, err := endpointstore.NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("itest-ing15-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Cleanup(func() { _, _ = durable.DeleteTenant(ctx, tenant) })

	if err := durable.Insert(ctx, []endpointstore.Event{
		{TenantID: tenant, AgentID: "agent-x", Type: TypeSession, SignalKey: "10.0.0.1", Target: "10.0.0.1", ObservedAt: now},
		{TenantID: tenant, AgentID: "agent-x", Type: TypeSession, SignalKey: "10.0.0.10", Target: "10.0.0.10", ObservedAt: now},
		{TenantID: tenant, AgentID: "agent-x", Type: TypeSession, SignalKey: "110.0.0.1", Target: "110.0.0.1", ObservedAt: now},
	}); err != nil {
		t.Fatalf("seed durable events: %v", err)
	}

	// A control-plane replica erases the subject through the repository.
	repo := NewRepository(durable, NewSnapshotStore(0))
	deleted, remaining := repo.DeleteSubject(tenant, "10.0.0.1")
	if deleted != 1 || remaining != 0 {
		t.Fatalf("DeleteSubject(10.0.0.1) = deleted=%d remaining=%d, want 1/0 (cache-only delete leaves the durable row, substring over-match deletes 3)", deleted, remaining)
	}

	// ING-15: the durable store — the cross-replica source of truth that a restart
	// rebuilds from — must no longer carry the subject, and the neighbors survive.
	latest, err := durable.Latest(ctx, tenant)
	if err != nil {
		t.Fatalf("durable Latest: %v", err)
	}
	if len(latest) != 2 {
		t.Fatalf("durable rows after erase = %d, want 2 survivors (subject persisted in the durable store)", len(latest))
	}
	for _, ev := range latest {
		if ev.Target == "10.0.0.1" {
			t.Fatalf("ING-15: subject row survived in the durable store and would reappear after restart: %+v", ev)
		}
	}

	// A brand-new repository/cache models a control-plane restart: it rebuilds the
	// snapshot from durable, so the subject must not reappear.
	afterRestart := NewRepository(durable, NewSnapshotStore(0))
	views, err := afterRestart.ListFilteredContext(ctx, tenant, ListFilter{})
	if err != nil {
		t.Fatalf("post-restart list: %v", err)
	}
	for _, v := range views {
		for _, s := range v.Sessions {
			if s.Target == "10.0.0.1" {
				t.Fatalf("ING-15: erased subject reappeared after restart: %+v", s)
			}
		}
	}
}
