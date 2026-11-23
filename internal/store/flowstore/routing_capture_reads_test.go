// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingReferencePopulation(t *testing.T, tenant string, count int) ([]Row, []map[string]any) {
	t.Helper()
	rows := make([]Row, count)
	wire := make([]map[string]any, count)
	for i := range rows {
		row, source := routingCaptureRowForTest(t, tenant, 0)
		row.RawFlowDigest = fmt.Sprintf("%064x", i+1)
		body, err := hex.DecodeString(row.RawFlowDigest)
		if err != nil {
			t.Fatal(err)
		}
		var digest [32]byte
		copy(digest[:], body)
		input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr(row.Exporter), Source: netip.MustParseAddr(row.SrcAddr), Destination: netip.MustParseAddr(row.DstAddr), Protocol: row.Protocol, Domain: row.ObsDomain}
		key, err := entity.FlowCaptureKey(tenant, row.AgentID, digest, input)
		if err != nil {
			t.Fatal(err)
		}
		row.RoutingCaptureKey = hex.EncodeToString(key[:])
		source["raw_flow_digest"], source["routing_capture_key"] = row.RawFlowDigest, row.RoutingCaptureKey
		source["obs_domain"] = strconv.FormatUint(uint64(row.ObsDomain), 10)
		source["routing_captured_unix_nanos"] = strconv.FormatInt(row.RoutingCapturedUnixNanos, 10)
		rows[i], wire[i] = row, source
	}
	return rows, wire
}

func TestRoutingCaptureReferenceReadsKeepCompleteOriginalScopeAndAdmission(t *testing.T) {
	proveRoutingCaptureReferencesShareBatchAdmission(t)
	const count = 1001
	tenants := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	st := NewMemory()
	for _, tenant := range tenants {
		rows, wire := routingReferencePopulation(t, tenant, count)
		if err := st.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		got, err := st.routingCaptureReferences(ctx, tenant, rows[0].TS.Add(-time.Second), rows[0].TS.Add(time.Second), "raw", false)
		if err != nil || len(got) != count {
			t.Fatal("routing reference read truncated the complete original population", len(got), err)
		}
		decoded, err := decodeRoutingReads(ctx, tenant, wire, 16<<20, false)
		if err != nil || len(decoded) != count {
			t.Fatal("routing reference wire lost full original values", len(decoded), err)
		}
		for i, read := range got {
			if read != decoded[i] || read.Ref.CapturedAt.UnixNano() != rows[0].RoutingCapturedUnixNanos || read.Witness.Input.Domain != ^uint32(0) {
				t.Fatal("routing reference read changed order, exact clock or full source domain", i)
			}
		}
		if partial, err := st.routingCaptureReferences(ctx, tenants[1], rows[0].TS.Add(-time.Second), rows[0].TS.Add(time.Second), "raw", false); tenant == tenants[0] && (!errors.Is(err, ErrNoTenant) || partial != nil) {
			t.Fatal("routing reference reader accepted a foreign tenant context", err)
		}
		wire[len(wire)-1]["tenant_id"] = tenants[1]
		if partial, err := decodeRoutingReads(ctx, tenants[0], wire, 16<<20, false); partial != nil || err == nil {
			t.Fatal("foreign late routing reference exposed a partial population")
		}
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows = count - 1
	if err := AttachExplorerBudget(st, budget); err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[0]))
	at := time.Unix(1700000000, 123000000).UTC()
	if partial, err := st.routingCaptureReferences(ctx, tenants[0], at.Add(-time.Second), at.Add(time.Second), "raw", false); !errors.Is(err, ErrExplorerBudget) || partial != nil {
		t.Fatal("routing reference admission returned a truncated prefix", err)
	}
	if _, err := routingReadFromRow(Row{}); err == nil {
		t.Fatal("legacy empty metadata invented an original routing reference")
	}
}

func TestTimedFlowCaptureReadsBoundBothTenantClocksAndRejectFallback(t *testing.T) {
	tenants := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	st := NewMemory()
	for lane, tenant := range tenants {
		rows, wire := routingReferencePopulation(t, tenant, 1)
		row := &rows[0]
		row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
		row.StartTS = row.TS.Add(-time.Duration(lane+1) * time.Second)
		row.TS = row.TS.Add(830 * time.Microsecond)
		wire[0]["clock_basis"] = strconv.FormatInt(int64(row.ClockBasis), 10)
		wire[0]["start_ms"] = strconv.FormatInt(row.StartTS.UnixMilli(), 10)
		wire[0]["end_ms"] = strconv.FormatInt(row.TS.UnixMilli(), 10)
		if err := st.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, until := row.TS.Add(-time.Second), row.TS.Add(time.Second)
		owned, err := ReadTimedFlowCaptureReferences(ctx, st, tenant, from, until, "auto")
		if err != nil || len(owned) != 1 || !owned[0].Timing.Start.Equal(row.StartTS) {
			t.Fatalf("missing original tenant %d clock: %+v %v", lane, owned, err)
		}
		retained, err := decodeRoutingReads(ctx, tenant, wire, 1<<20, true)
		if err != nil || len(retained) != 1 {
			t.Fatal("raw timing wire could not be decoded", err)
		}
		const tolerance = 2 * time.Millisecond
		start, end, ok := owned[0].Timing.ObservationRange(row.Protocol, tolerance)
		dbStart, dbEnd, dbOK := retained[0].Timing.ObservationRange(row.Protocol, tolerance)
		if !ok || !dbOK || !start.Equal(dbStart) || !end.Equal(dbEnd) ||
			!start.Equal(row.StartTS.Truncate(time.Millisecond).Add(-tolerance)) ||
			!end.Equal(row.TS.Truncate(time.Millisecond).Add(3*time.Millisecond)) {
			t.Fatalf("tenant %d timing bounds lost raw precision or tolerance: %v to %v", lane, start, end)
		}
		if _, _, ok := (FlowCaptureTiming{Start: row.StartTS, End: row.TS}).ObservationRange(row.Protocol, tolerance); ok {
			t.Fatal("fallback clock acquired authority")
		}
		if foreign, err := ReadTimedFlowCaptureReferences(ctx, st, tenants[1-lane], from, until, "raw"); foreign != nil || !errors.Is(err, ErrNoTenant) {
			t.Fatal("timed flow reference read crossed the tenant boundary", err)
		}
		if partial, err := ReadTimedFlowCaptureReferences(ctx, st, tenant, from, until, "rollup"); partial != nil || err == nil {
			t.Fatal("rollup acquired original clock authority", err)
		}
	}
}

func proveRoutingCaptureReferencesShareBatchAdmission(t *testing.T) {
	t.Helper()
	const tenant = "11111111-1111-4111-8111-111111111111"
	const count = 501
	rows, _ := routingReferencePopulation(t, tenant, count)
	for i := range rows {
		rows[i].BytesScaled = rows[i].Bytes
	}
	store := NewMemory()
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows = count * 2
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	batch, err := NewPlanBatch(ctx, store, tenant, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batch.Close)
	from, to := rows[0].TS.Add(-time.Second), rows[0].TS.Add(time.Second)
	refs, err := batch.RoutingCaptureReferences(from, to, "raw")
	if err != nil || len(refs) != count {
		t.Fatal("routing reference batch lost the complete admitted population", len(refs), err)
	}
	if partial, err := ReadRoutingCaptureReferences(batch.Context(), store, tenant, from, to, "raw"); !errors.Is(err, ErrExplorerBudget) || partial != nil {
		t.Fatal("routing reference metadata bypassed its batch owner", err)
	}
	plan := flow.QueryPlan{From: from, To: to, GroupBy: []string{"exporter"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	result, err := batch.ExplorePlan(PlanQuery{TenantID: tenant, Plan: plan})
	if err != nil || result.Totals["bytes:total"] != strconv.FormatUint(uint64(count)*rows[0].BytesScaled, 10) {
		t.Fatal("routing metadata consumed a plan slot or changed complete traffic", err)
	}
	if partial, err := batch.RoutingCaptureReferences(from, to, "raw"); !errors.Is(err, ErrExplorerBudget) || partial != nil {
		t.Fatal("routing reference batch reset its cumulative read allowance", err)
	}
	var absent *Memory
	if partial, err := ReadRoutingCaptureReferences(ctx, absent, tenant, from, to, "raw"); !errors.Is(err, ErrExplorerBudget) || partial != nil {
		t.Fatal("routing reference discovery accepted an unwired store", err)
	}
}
