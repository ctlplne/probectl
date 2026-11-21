// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalFlowWindowPlanPreservesWholeTenantHistory(t *testing.T) {
	checkSeasonalFlowWindowPlan(t, NewMemory(), "red", "blue")
}

func TestSeasonalDDoSPreservesPinnedPortFilterUnderGroupBudget(t *testing.T) {
	checkSeasonalDDoSSourcePortProjection(t, NewMemory(), "red", "blue")
}

func checkSeasonalDDoSSourcePortProjection(t *testing.T, store Store, red, blue string) {
	t.Helper()
	const sourcePorts = 2048
	end := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	budget := ExplorerQueryBudget(store)
	budget.IntermediateGroups = 64
	if err := AttachExplorerBudget(store, budget); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range []string{red, blue} {
		amount := [...]uint64{5, 7}[lane]
		row := explorerFixtureRow(tenant)
		row.TS, row.StartTS = end.Add(-time.Second), end.Add(-2*time.Second)
		row.Bytes, row.BytesScaled = amount, amount
		row.Packets, row.PacketsScaled = 2, 2
		rows := make([]Row, 0, sourcePorts+1)
		for port := uint16(20_000); port < 20_000+sourcePorts; port++ {
			row.SrcPort = port
			rows = append(rows, row)
		}
		row.Transport, row.SrcPort = "udp", 53
		row.Bytes, row.BytesScaled = amount*3, amount*3
		rows = append(rows, row)
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: end.Add(-5 * time.Second), To: end, View: "table", DataSeries: "raw", BucketSeconds: 1,
		GroupBy: []string{"dst_addr", "transport", "tcp_flags", "src_port", "sampling"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryNotEqual, Values: []string{"20000"}}}}}
	for lane, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		query := PlanQuery{TenantID: tenant, Plan: plan, DDoSProjection: true}
		result, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0)
		if err != nil || len(result) != 1 || len(result[0].Rows) != 2 {
			t.Fatal("the detector could not read the exact short-window population within the group budget", result, err)
		}
		totals := make(map[string]PlanRow)
		for _, row := range result[0].Rows {
			totals[row.Group["transport"]] = row
		}
		amount := [...]uint64{5, 7}[lane]
		if tcp, udp := totals["tcp"], totals["udp"]; tcp.Group["src_port"] != "0" || udp.Group["src_port"] != "53" ||
			tcp.Metrics["bytes:total"] != strconv.FormatUint(amount*(sourcePorts-1), 10) || tcp.Metrics["packets:total"] != strconv.Itoa(2*(sourcePorts-1)) ||
			tcp.Metrics["flows:total"] != strconv.Itoa(sourcePorts-1) || udp.Metrics["bytes:total"] != strconv.FormatUint(amount*3, 10) ||
			udp.Metrics["packets:total"] != "2" || udp.Metrics["flows:total"] != "1" {
			t.Fatal("projection changed filter membership, scoped totals or the original UDP association", totals)
		}
		query.DDoSProjection = false
		if result, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0); !errors.Is(err, ErrExplorerBudget) || result != nil {
			t.Fatal("the ordinary per-port read should exceed the same group budget", err)
		}
	}
}

func TestSeasonalDDoSSeparatesOriginalCrossingIntervals(t *testing.T) {
	checkSeasonalDDoSClockProjection(t, NewMemory(), "red", "blue")
}

func TestSeasonalDDoSScopesSampledExporterGroups(t *testing.T) {
	checkSeasonalDDoSSampledExporterGroups(t, NewMemory(), "red", "blue")
}

func checkSeasonalDDoSSampledExporterGroups(t *testing.T, store Store, red, blue string) {
	t.Helper()
	const west, east, outside = "203.0.113.15", "203.0.113.16", "203.0.113.17"
	end := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	plan := flow.QueryPlan{From: end.Add(-5 * time.Second), To: end, View: "table", DataSeries: "raw", BucketSeconds: 1,
		GroupBy: []string{"dst_addr", "transport", "tcp_flags", "src_port", "sampling", "exporter"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "exporter", Op: flow.QueryIn, Values: []string{west, east}}}}}
	tenants := []string{red, blue}
	factors := [...]uint64{5, 7}
	for lane, tenant := range tenants {
		var rows []Row
		for _, fixture := range []struct {
			exporter         string
			sampling, amount uint64
			port             uint16
		}{{west, 1, 2, 20000}, {east, 1, 3, 20001}, {west, 8, 4, 20002}, {east, 8, 5, 20003}, {outside, 1, 900, 20004}} {
			row := explorerFixtureRow(tenant)
			row.Exporter, row.Sampling, row.SrcPort = fixture.exporter, fixture.sampling, fixture.port
			row.TS, row.StartTS = end.Add(-time.Second), end.Add(-2*time.Second)
			row.Bytes = fixture.amount * factors[lane]
			row.Packets = 1
			row.BytesScaled, row.PacketsScaled = row.Bytes*row.Sampling, row.Packets*row.Sampling
			rows = append(rows, row)
		}
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 1)
		if err != nil {
			t.Fatal(err)
		}
		query := PlanQuery{TenantID: tenant, Plan: plan, DDoSProjection: true, DDoSVerifySampling: true, DDoSGroupSampledExporters: true}
		out, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0)
		batch.Close()
		if err != nil || len(out) != 1 || len(out[0].Rows) != 3 {
			t.Fatal("the reader did not fold the rate-one group and preserve both sampled exporters", out, err)
		}
		factor := factors[lane]
		want := map[string]struct {
			bytes         uint64
			packets, rows string
		}{"1:": {5 * factor, "2", "2"}, "8:" + west: {32 * factor, "8", "1"}, "8:" + east: {40 * factor, "8", "1"}}
		for _, row := range out[0].Rows {
			key := row.Group["sampling"] + ":" + row.Group["exporter"]
			expected, ok := want[key]
			if !ok || row.Metrics["bytes:total"] != strconv.FormatUint(expected.bytes, 10) ||
				row.Metrics["packets:total"] != expected.packets || row.Metrics["flows:total"] != expected.rows {
				t.Fatalf("exporter grouping changed the authorized scoped observations: %+v", row)
			}
			delete(want, key)
		}
	}
}

func checkSeasonalDDoSClockProjection(t *testing.T, store Store, red, blue string) {
	t.Helper()
	end := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	from := end.Add(-5 * time.Second)
	plan := flow.QueryPlan{From: from, To: end, View: "table", DataSeries: "raw", BucketSeconds: 1,
		GroupBy: []string{"dst_addr", "transport", "tcp_flags", "src_port", "sampling"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryNotEqual, Values: []string{"20003"}}}}}
	for lane, tenant := range []string{red, blue} {
		row := explorerFixtureRow(tenant)
		row.TS = end.Add(-time.Second)
		row.StartTS = from // boundary is inclusive
		row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
		row.SrcPort = 20000
		row.Bytes, row.BytesScaled = 10, 10
		row.Packets, row.PacketsScaled = 1, 1
		contained := row
		row.StartTS = from.Add(-time.Millisecond)
		row.SrcPort = 20001
		row.Bytes, row.BytesScaled = 20, 20
		row.Packets, row.PacketsScaled = 2, 2
		crossing := row
		row.SrcPort = 20002
		row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_UNSPECIFIED
		row.Bytes, row.BytesScaled = 30, 30
		row.Packets, row.PacketsScaled = 3, 3
		legacy := row
		row.SrcPort = 20003
		row.Bytes, row.BytesScaled = 900, 900
		row.Packets, row.PacketsScaled = 90, 90
		if lane == 1 {
			crossing.Bytes, crossing.BytesScaled = 80, 80
			crossing.Packets, crossing.PacketsScaled = 8, 8
		}
		if err := store.Insert(t.Context(), []Row{contained, crossing, legacy, row}); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 1)
		if err != nil {
			t.Fatal(err)
		}
		out, err := batch.ExploreSeasonalWindows(PlanQuery{TenantID: tenant, Plan: plan, DDoSProjection: true}, []time.Time{end}, 0)
		batch.Close()
		if err != nil || len(out) != 1 || len(out[0].Rows) != 2 {
			t.Fatal("the private timing grouping did not retain both original populations", out, err)
		}
		normal, crossing := out[0].Rows[0], out[0].Rows[1]
		wantBytes, wantPackets := [2]string{"20", "80"}[lane], [2]string{"2", "8"}[lane]
		if normal.CrossesWindowStart || !crossing.CrossesWindowStart || normal.Group["src_port"] != "0" || crossing.Group["src_port"] != "0" ||
			normal.Metrics["flows:total"] != "2" || normal.Metrics["bytes:total"] != "40" || normal.Metrics["packets:total"] != "4" ||
			crossing.Metrics["flows:total"] != "1" || crossing.Metrics["bytes:total"] != wantBytes || crossing.Metrics["packets:total"] != wantPackets {
			t.Fatal("timing projection changed the original filter, legacy clocks or scoped exact counts", out[0].Rows)
		}
	}
}

func checkSeasonalFlowWindowPlan(t *testing.T, store Store, red, blue string) (flow.QueryPlan, []time.Time) {
	t.Helper()
	const periods = 42*24 + 1
	last := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Hour)
	ends := make([]time.Time, periods)
	for i := range ends {
		ends[i] = last.Add(-time.Duration(periods-1-i) * time.Hour)
	}
	laneValues := [2]uint64{9007199254740993, 100}
	for i, tenant := range []string{red, blue} {
		rows := make([]Row, 0, periods)
		for period, ending := range ends {
			if period == 1 || period == 2 {
				continue
			}
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = ending.Add(-5*time.Minute), ending.Add(-5*time.Minute-time.Second)
			row.Protocol, row.Bytes, row.BytesScaled = "tcp", laneValues[i], laneValues[i]
			rows = append(rows, row)
		}
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	plan := flow.QueryPlan{From: last.Add(-70 * time.Minute), To: last, View: "table", DataSeries: "raw",
		GroupBy: []string{"protocol"}, BucketSeconds: 300, Metrics: []flow.QueryMetric{
			{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "unique_src", Calculation: "total", Role: "secondary"},
		}}
	for i, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		result, err := batch.ExploreSeasonalWindows(PlanQuery{TenantID: tenant, Plan: plan}, ends, 0)
		if err != nil || len(result) != periods {
			t.Fatalf("read %d of %d whole comparison periods: %v", len(result), periods, err)
		}
		for period, got := range result {
			if !got.Query.To.Equal(ends[period]) || got.Coverage == nil || !got.Coverage.CompleteInputs {
				t.Fatal("flow period lacked its complete input clock", period)
			}
			if period == 2 {
				if len(got.Rows) != 0 || !got.OldestInput.IsZero() {
					t.Fatal("absent flow input was synthesized", period)
				}
				continue
			}
			value := laneValues[i]
			oldest := ends[period].Add(-5 * time.Minute)
			if period != 0 && period != 3 {
				oldest = oldest.Add(-time.Hour)
			}
			if period > 3 {
				value *= 2
			}
			if len(got.Rows) != 1 || got.Rows[0].Group["protocol"] != "tcp" ||
				got.Rows[0].Metrics["bytes:total"] != strconv.FormatUint(value, 10) || got.Rows[0].Metrics["unique_src:total"] != "1" ||
				!got.OldestInput.Equal(oldest) {
				t.Fatalf("period %d lost exact scoped overlap, distinct members or coverage: %+v", period, got.Rows)
			}
		}
		foreign := []string{red, blue}[1-i]
		if rows, err := batch.ExploreSeasonalWindows(PlanQuery{TenantID: foreign, Plan: plan}, ends, 0); !errors.Is(err, ErrNoTenant) || rows != nil {
			t.Fatal("sibling tenant reached the seasonal plan reader", err)
		}
	}
	return plan, ends
}

func TestSeasonalDDoSRetainsScopedInvalidSamplingCounters(t *testing.T) {
	checkSeasonalDDoSInvalidSamplingCounters(t, NewMemory(), "red", "blue")
}

func checkSeasonalDDoSInvalidSamplingCounters(t *testing.T, store Store, red, blue string) {
	t.Helper()
	end := time.Now().UTC().Add(-time.Minute).Truncate(5 * time.Second)
	plan := flow.QueryPlan{From: end.Add(-5 * time.Second), To: end, View: "table", DataSeries: "raw", BucketSeconds: 1,
		GroupBy: []string{"dst_addr", "transport", "tcp_flags", "src_port", "sampling"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"},
			{Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryNotEqual, Values: []string{"20003"}}}}}
	const largestRepresentable = math.MaxUint64 / 2
	for lane, tenant := range []string{red, blue} {
		normal := explorerFixtureRow(tenant)
		normal.TS, normal.StartTS = end.Add(-time.Second), end.Add(-2*time.Second)
		normal.SrcPort, normal.Sampling = 20000, 2
		normal.Bytes, normal.BytesScaled = largestRepresentable, largestRepresentable*2
		normal.Packets, normal.PacketsScaled = 1, 2
		overflow := normal
		overflow.SrcPort = 20001
		overflow.Bytes = largestRepresentable + 1
		overflow.BytesScaled = overflow.Bytes * overflow.Sampling
		mismatch := normal
		mismatch.SrcPort = 20002
		mismatch.BytesScaled--
		if lane == 1 {
			overflow.SrcPort = 20003
			mismatch.SrcPort = 20003
		}
		if err := store.Insert(t.Context(), []Row{normal, overflow, mismatch}); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		batch, err := NewPlanBatch(ctx, store, tenant, 2)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(batch.Close)
		query := PlanQuery{TenantID: tenant, Plan: plan, DDoSProjection: true, DDoSVerifySampling: true}
		out, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0)
		if err != nil || len(out) != 1 || len(out[0].Rows) != 2-lane {
			t.Fatal("sampling validation changed authorized group coverage", lane, out, err)
		}
		normal := out[0].Rows[0]
		if normal.InvalidSamplingCounters || normal.Metrics["bytes:total"] != strconv.FormatUint(largestRepresentable*2, 10) ||
			normal.Metrics["flows:total"] != "1" || normal.Group["sampling"] != "2" {
			t.Fatal("representable corrected counts lost their original evidence", lane, normal)
		}
		if lane == 0 && (!out[0].Rows[1].InvalidSamplingCounters || out[0].Rows[1].Metrics["flows:total"] != "2") {
			t.Fatal("inconsistent counters became ordinary coverage", out[0].Rows)
		}
		query.DDoSVerifySampling = false
		cited, err := batch.ExploreSeasonalWindows(query, []time.Time{end}, 0)
		if err != nil || len(cited) != 1 || len(cited[0].Rows) != 1 || cited[0].Rows[0].InvalidSamplingCounters ||
			cited[0].Rows[0].Metrics["flows:total"] != strconv.Itoa(3-2*lane) {
			t.Fatal("cited scope changed its original input grouping", lane, cited, err)
		}
	}
}

func TestSeasonalInvalidSamplingCountersChecksBothCounters(t *testing.T) {
	limit := uint64(math.MaxUint64 / 2)
	for _, row := range []Row{
		{Sampling: 2, Bytes: limit + 1},
		{Sampling: 2, Packets: limit + 1},
		{Sampling: 2, Bytes: 100, BytesScaled: 199},
		{Sampling: 2, Packets: 100, PacketsScaled: 201},
		{Sampling: 0, Bytes: 1},
		{Sampling: 1, BytesScaled: 1},
	} {
		if !seasonalSamplingCountersInvalid(row) {
			t.Fatal("incorrect corrected counter was accepted")
		}
	}
	if seasonalSamplingCountersInvalid(Row{Sampling: 2, Bytes: limit, BytesScaled: 2 * limit, Packets: limit, PacketsScaled: 2 * limit}) ||
		seasonalSamplingCountersInvalid(Row{Sampling: 1, Bytes: math.MaxUint64, BytesScaled: math.MaxUint64, Packets: math.MaxUint64, PacketsScaled: math.MaxUint64}) {
		t.Fatal("representable boundary values became unusable")
	}
}
