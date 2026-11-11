// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func counterHistoryRows(t *testing.T, tenant string) []CounterRow {
	t.Helper()
	at := time.Unix(1794000000, 123456789)
	first := CounterRow{TenantID: tenant, CounterSource: CounterSource{ContextID: "22222222-2222-4222-8222-222222222222", DeviceID: "33333333-3333-4333-8333-333333333333", AgentID: "same-agent", SourceRef: "192.0.2.1", SourceAssignedAt: at.Add(-time.Hour), AgentAssignedAt: at.Add(-time.Hour)},
		SenderSerial: "issued", RawDigest: [32]byte{1, 255}, CapturedAt: at.Add(2 * time.Second), PollStartedAt: at, PollCompletedAt: at.Add(time.Second), Population: 4,
		Name: "probectl.device.if.in.octets", IfIndex: 7, Value: ^uint64(0), Width: 64, UptimeKnown: true, DiscontinuityKnown: true}
	var err error
	first.CaptureKey, err = entity.CounterCaptureKey(tenant, first.AgentID, first.RawDigest, entity.CounterCaptureInput{ConfiguredTarget: first.SourceRef, PollStartedAt: first.PollStartedAt, PollCompletedAt: first.PollCompletedAt, PointCount: first.Population})
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]CounterRow, 4)
	for i := range rows {
		rows[i] = first
		rows[i].IfIndex += uint32(i)
	}
	rows[1].Value = 1<<53 + 1
	rows[2].Value, rows[2].Width = 1<<32-1, 32
	rows[3].Value = 0
	return rows
}

func counterHistoryBudget() CounterBudget {
	return CounterBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20, Timeout: time.Minute}
}

func TestCounterHistoryAdmissionKeepsWholeExactPollAndSeparateTenantIdentity(t *testing.T) {
	var first [2]string
	for lane, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		rows := counterHistoryRows(t, tenant)
		if err := validateCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
			t.Fatal("complete original poll lost exact values, zero clock presence or scope", err)
		}
		first[lane] = counterRowID(rows[0])
		seen := map[string]bool{}
		for _, row := range rows {
			id := counterRowID(row)
			if id == "" || seen[id] || id != counterRowID(row) {
				t.Fatal("original distinct counter points collided or retry identity changed")
			}
			seen[id] = true
		}
		query := CounterQuery{TenantID: tenant, From: rows[0].PollStartedAt.Add(-time.Minute), To: rows[0].PollCompletedAt.Add(time.Minute), Budget: counterHistoryBudget(),
			Sources: []CounterSelector{{CounterSource: rows[0].CounterSource, IfIndexes: []uint32{7, 8, 9, 10}}}}
		if err := validateCounterQuery(ctx, query); err != nil {
			t.Fatal("complete explicit source selection was refused", err)
		}
		// Time zones represent the same authority interval, not a rebind.
		rows[3].SourceAssignedAt = rows[3].SourceAssignedAt.In(time.FixedZone("offset", 3600))
		if err := validateCounterPoll(ctx, rows, counterHistoryBudget()); err != nil {
			t.Fatal("identical source assignment instant was treated as a new incarnation", err)
		}
	}
	if first[0] == first[1] {
		t.Fatal("two tenants reusing all source/interface identities shared a counter row")
	}
}

func TestCounterHistoryAdmissionRejectsForeignLateRowsAndImplicitSourceReads(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	for _, change := range []func(*CounterRow){
		func(r *CounterRow) { r.TenantID = "66666666-6666-4666-8666-666666666666" },
		func(r *CounterRow) { r.DeviceID = "44444444-4444-4444-8444-444444444444" },
		func(r *CounterRow) { r.AgentID = "spoofed" },
		func(r *CounterRow) { r.SourceAssignedAt = r.SourceAssignedAt.Add(time.Nanosecond) },
		func(r *CounterRow) { r.PollStartedAt = r.PollStartedAt.Add(time.Nanosecond) },
		func(r *CounterRow) { r.CaptureKey[0] ^= 255 },
		func(r *CounterRow) { r.RawDigest[0] ^= 255 },
		func(r *CounterRow) { r.Population-- },
		func(r *CounterRow) { r.IfIndex = 0 },
		func(r *CounterRow) { r.Name = "bad\nname" },
		func(r *CounterRow) { r.Width = 32; r.Value = 1 << 32 },
		func(r *CounterRow) { r.UptimeKnown = false; r.UptimeTicks = 1 },
	} {
		rows := counterHistoryRows(t, tenant)
		change(&rows[len(rows)-1])
		if err := validateCounterPoll(ctx, rows, counterHistoryBudget()); err == nil {
			t.Fatal("a foreign or altered late row admitted a prefix of its original poll")
		}
	}
	rows := counterHistoryRows(t, tenant)
	rows[3] = rows[0]
	if err := validateCounterPoll(ctx, rows, counterHistoryBudget()); err == nil {
		t.Fatal("a duplicate original point was admitted twice")
	}
	rows = counterHistoryRows(t, tenant)
	if err := validateCounterPoll(t.Context(), rows, counterHistoryBudget()); err == nil {
		t.Fatal("a counter write without tenant context was admitted")
	}
	query := CounterQuery{TenantID: tenant, From: rows[0].PollStartedAt.Add(-time.Minute), To: rows[0].PollCompletedAt.Add(time.Minute), Budget: counterHistoryBudget()}
	if err := validateCounterQuery(ctx, query); err == nil {
		t.Fatal("empty selectors became an implicit telemetry read")
	}
	query.Sources = []CounterSelector{{CounterSource: rows[0].CounterSource}}
	if err := validateCounterQuery(ctx, query); err == nil {
		t.Fatal("empty interfaces widened source access")
	}
	query.Sources[0].IfIndexes = []uint32{7, 7}
	if err := validateCounterQuery(ctx, query); err == nil {
		t.Fatal("a duplicate interface could be billed twice")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := validateCounterPoll(canceled, rows, counterHistoryBudget()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled source admission succeeded", err)
	}
	budget := counterHistoryBudget()
	budget.MemoryBytes = 1
	if err := validateCounterPoll(ctx, rows, budget); !errors.Is(err, ErrCounterHistoryBudget) {
		t.Fatal("complete source population exceeded allocation admission", err)
	}
}
