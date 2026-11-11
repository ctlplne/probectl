// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func rekeyCounterHistoryPoll(t *testing.T, rows []CounterRow) {
	t.Helper()
	first := rows[0]
	key, err := entity.CounterCaptureKey(first.TenantID, first.AgentID, first.RawDigest, entity.CounterCaptureInput{
		ConfiguredTarget: first.SourceRef, PollStartedAt: first.PollStartedAt, PollCompletedAt: first.PollCompletedAt, PointCount: uint32(len(rows)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		rows[i].CaptureKey, rows[i].Population = key, uint32(len(rows))
	}
}

func counterHistoryQuery(rows []CounterRow) CounterQuery {
	indexes := make([]uint32, len(rows))
	for i, row := range rows {
		indexes[i] = row.IfIndex
	}
	return CounterQuery{TenantID: rows[0].TenantID, From: rows[0].PollStartedAt.Add(-time.Minute), To: rows[0].PollCompletedAt.Add(time.Minute), Budget: counterHistoryBudget(),
		Sources: []CounterSelector{{CounterSource: rows[0].CounterSource, IfIndexes: indexes}}}
}

func TestCounterHistoryMemoryKeepsExactPollsAndTenantSourceIncarnations(t *testing.T) {
	memory := NewMemoryWithLimit(1) // The unrelated flow FIFO cannot evict counters.
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		rows := counterHistoryRows(t, tenant)
		for range 2 {
			if err := memory.InsertCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
				t.Fatal(err)
			}
		}
		query := counterHistoryQuery(rows)
		got, err := memory.CounterPoints(ctx, query)
		if err != nil || len(got) != len(rows) {
			t.Fatal("redelivery or another tenant changed the complete poll", len(got), err)
		}
		for i := range got {
			if counterDocument(got[i]) != counterDocument(rows[i]) {
				t.Fatal("exact word, original clock or source provenance changed", i)
			}
		}
		query.Sources[0].SourceAssignedAt = query.Sources[0].SourceAssignedAt.Add(time.Nanosecond)
		if got, err := memory.CounterPoints(ctx, query); err != nil || len(got) != 0 {
			t.Fatal("a new source incarnation inherited old counters", len(got), err)
		}
		query = counterHistoryQuery(rows)
		foreign := tenancy.WithTenant(t.Context(), tenancy.ID("77777777-7777-4777-8777-777777777777"))
		if _, err := memory.CounterPoints(foreign, query); err == nil {
			t.Fatal("a different tenant context read the poll")
		}
	}
}

func TestCounterHistoryMemoryRefusesWholePollWithoutEvictingAndCanRaiseBudget(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	rows := counterHistoryRows(t, tenant)
	var charge int64
	for _, row := range rows {
		charge += counterRowCharge(row)
	}
	memory := NewMemory()
	if err := memory.WithCounterMemoryBudget(charge-1, charge*2); err != nil {
		t.Fatal(err)
	}
	if err := memory.InsertCounterPoll(ctx, rows, counterHistoryBudget()); !errors.Is(err, ErrCounterHistoryBudget) {
		t.Fatal("one underfunded final point did not refuse the whole poll", err)
	}
	if got, err := memory.CounterPoints(ctx, counterHistoryQuery(rows)); err != nil || len(got) != 0 {
		t.Fatal("a refused poll left a visible prefix", len(got), err)
	}
	if err := memory.WithCounterMemoryBudget(charge, charge*2); err != nil {
		t.Fatal(err)
	}
	if err := memory.InsertCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
		t.Fatal(err)
	}
	next := append([]CounterRow(nil), rows...)
	for i := range next {
		next[i].RawDigest[1] ^= 0xff
	}
	rekeyCounterHistoryPoll(t, next)
	if err := memory.InsertCounterPoll(ctx, next, counterHistoryBudget()); !errors.Is(err, ErrCounterHistoryBudget) {
		t.Fatal("retained tenant byte admission was ignored", err)
	}
	if got, err := memory.CounterPoints(ctx, counterHistoryQuery(rows)); err != nil || len(got) != len(rows) {
		t.Fatal("new admission evicted original evidence", len(got), err)
	}
	if err := memory.WithCounterMemoryBudget(2*charge, 2*charge); err != nil {
		t.Fatal(err)
	}
	if err := memory.InsertCounterPoll(ctx, next, counterHistoryBudget()); err != nil {
		t.Fatal("the operator could not raise resources for the complete workload", err)
	}
	if got, err := memory.CounterPoints(ctx, counterHistoryQuery(rows)); err != nil || len(got) != 2*len(rows) {
		t.Fatal("increased resources shortened the intended workload", len(got), err)
	}
}

func TestCounterHistoryMemoryPortabilityAndErasureKeepNeighbourAndSibling(t *testing.T) {
	memory := NewMemory()
	tenants := []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"}
	for _, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for _, source := range []string{"192.0.2.1", "192.0.2.10"} {
			rows := counterHistoryRows(t, tenant)
			for i := range rows {
				rows[i].SourceRef = source
			}
			rekeyCounterHistoryPoll(t, rows)
			if err := memory.InsertCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[0]))
	var exported bytes.Buffer
	if n, err := memory.ExportCounterSubject(ctx, tenants[0], "192.0.2.1", &exported); err != nil || n != 4 {
		t.Fatal("subject export lost its exact four points or included the neighbor", n, err)
	}
	decoder := json.NewDecoder(&exported)
	var count int
	for {
		var document map[string]any
		if err := decoder.Decode(&document); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		row, err := counterHistoryRow(document)
		if err != nil || row.TenantID != tenants[0] || row.SourceRef != "192.0.2.1" || (count == 0 && row.Value != ^uint64(0)) {
			t.Fatal("portable output rounded original counters or exposed another source", err)
		}
		count++
	}
	if count != 4 {
		t.Fatal("portable export ended before the complete population", count)
	}
	if n, err := memory.ExportCounterSubjects(ctx, tenants[0], []string{"192.0.2.1", "192.0.2.1"}, io.Discard); err != nil || n != 4 {
		t.Fatal("stable subject aliases duplicated portable points", n, err)
	}
	if deleted, remaining, err := memory.DeleteCounterSubjects(ctx, tenants[0], []string{"192.0.2.1", "192.0.2.1"}); err != nil || deleted != 4 || remaining != 0 {
		t.Fatal("subject erasure did not verify its complete point population", deleted, remaining, err)
	}
	for i, tenant := range tenants {
		own := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		want := int64(8 - 4*(1-i))
		if n, err := memory.ExportCounterTenant(own, tenant, io.Discard); err != nil || n != want {
			t.Fatal("erasure changed a prefix neighbor or a sibling tenant", tenant, n, want, err)
		}
	}
	cutoff := counterHistoryRows(t, tenants[0])[0].PollStartedAt.Add(time.Second)
	if err := memory.DeleteCountersBefore(ctx, tenants[0], cutoff); err != nil {
		t.Fatal(err)
	}
	if n, err := memory.ExportCounterTenant(ctx, tenants[0], io.Discard); err != nil || n != 0 {
		t.Fatal("retention left original counter evidence", n, err)
	}
	if remaining, err := memory.DeleteCounterTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenants[1])), tenants[1]); err != nil || remaining != 0 {
		t.Fatal("tenant erasure was not verified", remaining, err)
	}
}
