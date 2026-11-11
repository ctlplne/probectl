// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCounterHistoryClickHouseRealWholePollsAndReaderLifecycle(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	tenants := []string{uuid.NewString(), uuid.NewString()}
	for _, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		t.Cleanup(func() {
			if _, err := store.DeleteCounterTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		})
		rows := counterHistoryRows(t, tenant)
		var prefix bytes.Buffer
		for _, row := range rows[:2] {
			if err := json.NewEncoder(&prefix).Encode(counterDocument(row)); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.insertCounterBody(ctx, Target{}, sharedCounterHistoryTable, &prefix); err != nil {
			t.Fatal(err)
		}
		if got, err := store.CounterPoints(ctx, counterHistoryQuery(rows)); err != nil || len(got) != 0 {
			t.Fatal("interrupted real multi-block poll exposed a prefix without a commit marker", len(got), err)
		}
		for range 2 {
			if err := store.InsertCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
				t.Fatal(err)
			}
		}
		got, err := store.CounterPoints(ctx, counterHistoryQuery(rows))
		if err != nil || len(got) != len(rows) {
			t.Fatal("real original poll was shortened or retry duplicated it", len(got), err)
		}
		for i := range got {
			if counterDocument(got[i]) != counterDocument(rows[i]) {
				t.Fatal("real storage changed exact values or original provenance", i)
			}
		}
		for table, want := range map[string]int{sharedCounterHistoryTable: 4, sharedCounterPollTable: 1} {
			data, err := store.queryScoped(ctx, Target{}, tenant, "SELECT tenant_id FROM "+table+" FINAL", nil)
			if err != nil || len(data) != want {
				t.Fatal("predicate-free real reader lost storage-layer tenant isolation", table, len(data), err)
			}
			for _, row := range data {
				if row["tenant_id"] != tenant {
					t.Fatal("real reader exposed another tenant", table)
				}
			}
		}
	}
	red := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[0]))
	if deleted, remaining, err := store.DeleteCounterSubject(red, tenants[0], "192.0.2.1"); err != nil || deleted != 4 || remaining != 0 {
		t.Fatal("real erasure failed to verify both points and commit markers", deleted, remaining, err)
	}
	blue := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[1]))
	if n, err := store.ExportCounterTenant(blue, tenants[1], io.Discard); err != nil || n != 4 {
		t.Fatal("real subject erasure changed sibling original evidence", n, err)
	}
	cutoff := counterHistoryRows(t, tenants[1])[0].PollCompletedAt
	if err := store.DeleteCountersBefore(blue, tenants[1], cutoff); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{sharedCounterHistoryTable, sharedCounterPollTable} {
		remaining, err := store.counterCount(blue, Target{}, tenants[1], table, "tenant_id={tenant:String}", chParams{"tenant": tenants[1]})
		if err != nil || remaining != 0 {
			t.Fatal("real retention left a point or poll marker", table, remaining, err)
		}
	}
	t.Log("real-integration: modeled complete original counter polls through actual ClickHouse, exact uint64/nanoseconds, interrupted-prefix invisibility, retries, independent reader row policies and tenant/subject/retention verification; physical sender is separate")
}
