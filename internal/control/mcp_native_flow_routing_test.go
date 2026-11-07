// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestNativeFlowRoutingPathsKeepWholeTypedSegmentsAcrossQueryProjections(t *testing.T) {
	const count = 65_537
	wire, err := json.Marshal([]string{"4111 1111 1111 1111", strings.Repeat("64500 ", count) + "4294967295", "{64500,4294967295} (64501 64502) [64496,64497]"})
	if err != nil {
		t.Fatal(err)
	}
	group := func() []mcp.NativeFlowDimension {
		return []mcp.NativeFlowDimension{{Field: "src_bgp_as_paths", Value: string(wire)}}
	}
	row := func() mcp.NativeFlowRow { return mcp.NativeFlowRow{Group: group()} }
	point := func() mcp.NativeFlowPoint { return mcp.NativeFlowPoint{Group: group()} }
	other, chartOther := row(), row()
	out := mcp.NativeFlowResult{
		Rows:          []mcp.NativeFlowRow{row()},
		ChartRows:     []mcp.NativeFlowRow{row()},
		MatrixRows:    []mcp.NativeFlowRow{row()},
		MatrixColumns: []mcp.NativeFlowRow{row()},
		Other:         &other, ChartOther: &chartOther,
		Series:      []mcp.NativeFlowPoint{point()},
		OtherSeries: []mcp.NativeFlowPoint{point()},
		TotalSeries: []mcp.NativeFlowPoint{point()},
		Matrix:      []mcp.NativeFlowCell{{Row: group(), Column: group()}},
	}
	source := flowstore.PlanResult{
		Query:        flow.QueryPlan{GroupBy: []string{"src_bgp_as_paths"}},
		RoutingProof: &flowstore.RoutingQueryProof{Digest: strings.Repeat("a", 64), InputDigest: strings.Repeat("b", 64)},
	}
	if err := projectNativeFlowRoutingPaths(t.Context(), &out, source, flowstore.DefaultExplorerBudget()); err != nil {
		t.Fatal(err)
	}
	groups := [][]mcp.NativeFlowDimension{out.Rows[0].Group, out.ChartRows[0].Group, out.MatrixRows[0].Group, out.MatrixColumns[0].Group, out.Other.Group, out.ChartOther.Group, out.Series[0].Group, out.OtherSeries[0].Group, out.TotalSeries[0].Group, out.Matrix[0].Row, out.Matrix[0].Column}
	for _, dimensions := range groups {
		value := dimensions[0]
		if value.Value != string(wire) || len(value.RoutingPaths) != 3 || len(value.RoutingPaths[1].Segments) != 1 || len(value.RoutingPaths[1].Segments[0].ASNs) != count+1 || value.RoutingPaths[1].Segments[0].ASNs[count] != ^uint32(0) {
			t.Fatal("native routing projection lost complete typed paths")
		}
		if !reflect.DeepEqual(value.RoutingPaths[0].Segments[0].ASNs, []uint32{4111, 1111, 1111, 1111}) || value.RoutingPaths[0].Segments[0].Kind != uint8(bgp.ASPathSequence) || value.RoutingPaths[2].Segments[0].Kind != uint8(bgp.ASPathSet) || value.RoutingPaths[2].Segments[1].Kind != uint8(bgp.ASPathConfedSequence) || value.RoutingPaths[2].Segments[2].Kind != uint8(bgp.ASPathConfedSet) {
			t.Fatal("native routing projection changed AS segment semantics")
		}
	}
	comparisons := []mcp.NativeFlowComparisonRow{{Group: group()}, {Group: group()}}
	if err := projectNativeComparisonRoutingPaths(comparisons, source.Query, nil); err != nil || !reflect.DeepEqual(comparisons[0].Group[0].RoutingPaths, out.Rows[0].Group[0].RoutingPaths) || !reflect.DeepEqual(comparisons[1].Group[0].RoutingPaths, out.Rows[0].Group[0].RoutingPaths) {
		t.Fatal("native routing comparison discarded complete typed path groups", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := projectNativeFlowRoutingPaths(canceled, &out, source, flowstore.DefaultExplorerBudget()); err == nil {
		t.Fatal("native routing path projection ignored cancellation")
	}
	budget := flowstore.DefaultExplorerBudget()
	budget.MemoryBytes = 4096
	if err := projectNativeFlowRoutingPaths(t.Context(), &out, source, budget); err == nil {
		t.Fatal("native routing paths ignored complete workspace admission")
	}
	source.RoutingProof = nil
	if err := projectNativeFlowRoutingPaths(t.Context(), &out, source, flowstore.DefaultExplorerBudget()); err == nil {
		t.Fatal("native routing paths invented missing server source lineage")
	}
	t.Log("simulation: complete typed native path projections; no current-user/source or transport grant")
}
