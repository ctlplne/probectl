// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/bgp"
)

// The route read and complete field projection share finite operation admission.
// Retain every path, aligned with Route.Paths (including its full ADD-PATH ID).
func routingFlowPathFields(ctx context.Context, paths []BGPRoutingChange, budget BGPRoutingBudget) ([]bgp.RoutingPathFields, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(paths)) > budget.MemoryBytes/128 || int64(len(paths)) > budget.WorkUnits {
		return nil, ErrBGPRoutingBudget
	}
	memory := budget.MemoryBytes - int64(len(paths))*128
	work := budget.WorkUnits - int64(len(paths))
	result := make([]bgp.RoutingPathFields, len(paths))
	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if memory < 128 || work < 1 || int64(len(path.Segments)) > (memory-128)/96 || int64(len(path.Segments)) > (work-1)/8 {
			return nil, ErrBGPRoutingBudget
		}
		chargeMemory := 128 + int64(len(path.Segments))*96
		chargeWork := 1 + int64(len(path.Segments))*8
		for _, segment := range path.Segments {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if int64(len(segment.Values)) > (memory-chargeMemory)/64 || int64(len(segment.Values)) > (work-chargeWork)/12 {
				return nil, ErrBGPRoutingBudget
			}
			chargeMemory += int64(len(segment.Values)) * 64
			chargeWork += int64(len(segment.Values)) * 12
		}
		segments := make([]bgp.ASPathSegment, len(path.Segments))
		for j, segment := range path.Segments {
			segments[j] = bgp.ASPathSegment{Kind: bgp.ASPathSegmentKind(segment.Kind), Values: segment.Values}
		}
		var err error
		result[i], err = bgp.ProjectRoutingPathFields(ctx, segments, bgp.ASPathParseBudget{MemoryBytes: chargeMemory, WorkUnits: chargeWork})
		if err != nil {
			return nil, err
		}
		memory -= chargeMemory
		work -= chargeWork
	}
	return result, nil
}
