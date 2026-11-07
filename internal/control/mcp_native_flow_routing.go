// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Typed protocol values preserve AS paths even when their free-text rendering
// resembles a PII pattern. No text is escaped around or exempted from the
// mandatory MCP redactor; arbitrary labels and evidence remain untrusted text.
func projectNativeFlowRoutingPaths(ctx context.Context, out *mcp.NativeFlowResult, source flowstore.PlanResult, budget flowstore.ExplorerBudget) error {
	if !flowPlanUsesCapturedRouting(source.Query) {
		return nil
	}
	if source.RoutingProof == nil || !canonicalFlowRoutingDigest(source.RoutingProof.Digest) || !canonicalFlowRoutingDigest(source.RoutingProof.InputDigest) {
		return nativeFlowProjectionError()
	}
	remaining := budget.MemoryBytes / 8
	apply := func(dimensions []mcp.NativeFlowDimension) error {
		return projectNativeRoutingDimensions(ctx, dimensions, &remaining)
	}
	for _, rows := range [][]mcp.NativeFlowRow{out.Rows, out.ChartRows, out.MatrixRows, out.MatrixColumns} {
		for i := range rows {
			if err := apply(rows[i].Group); err != nil {
				return err
			}
		}
	}
	for _, row := range []*mcp.NativeFlowRow{out.Other, out.ChartOther} {
		if row != nil {
			if err := apply(row.Group); err != nil {
				return err
			}
		}
	}
	for _, points := range [][]mcp.NativeFlowPoint{out.Series, out.OtherSeries, out.TotalSeries} {
		for i := range points {
			if err := apply(points[i].Group); err != nil {
				return err
			}
		}
	}
	for i := range out.Matrix {
		if err := apply(out.Matrix[i].Row); err != nil {
			return err
		}
		if err := apply(out.Matrix[i].Column); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func projectNativeRoutingDimensions(ctx context.Context, dimensions []mcp.NativeFlowDimension, remaining *int64) error {
	for i := range dimensions {
		if err := ctx.Err(); err != nil {
			return err
		}
		value := &dimensions[i]
		if _, known := flow.RoutingQueryField(value.Field); !known || !strings.HasSuffix(value.Field, "_bgp_as_paths") || value.Value == "" {
			continue
		}
		if *remaining < 512 || int64(len(value.Value)) > (*remaining-512)/32 {
			return nativeFlowProjectionError()
		}
		charge := int64(len(value.Value))*32 + 512
		*remaining -= charge
		var paths []string
		if err := json.Unmarshal([]byte(value.Value), &paths); err != nil || len(paths) == 0 {
			return nativeFlowProjectionError()
		}
		complete := make([]mcp.NativeFlowRoutingPath, 0, len(paths))
		for _, text := range paths {
			segments, err := bgp.ParseRoutingPathText(ctx, text, bgp.ASPathParseBudget{MemoryBytes: charge, WorkUnits: charge})
			if err != nil {
				return nativeFlowProjectionError()
			}
			path := mcp.NativeFlowRoutingPath{Segments: make([]mcp.NativeFlowRoutingSegment, 0, len(segments))}
			for _, segment := range segments {
				path.Segments = append(path.Segments, mcp.NativeFlowRoutingSegment{Kind: uint8(segment.Kind), ASNs: append([]uint32(nil), segment.Values...)})
			}
			complete = append(complete, path)
		}
		value.RoutingPaths = complete
	}
	return nil
}

func projectNativeComparisonRoutingPaths(rows []mcp.NativeFlowComparisonRow, plan flow.QueryPlan, options []nativeFlowProjectionOptions) error {
	if !flowPlanUsesCapturedRouting(plan) {
		return nil
	}
	ctx := context.Background()
	budget := flowstore.DefaultExplorerBudget()
	if len(options) > 0 {
		if options[0].ctx != nil {
			ctx = options[0].ctx
		}
		budget = options[0].budget
	}
	remaining := budget.MemoryBytes / 8
	for i := range rows {
		if err := projectNativeRoutingDimensions(ctx, rows[i].Group, &remaining); err != nil {
			return err
		}
	}
	return ctx.Err()
}
