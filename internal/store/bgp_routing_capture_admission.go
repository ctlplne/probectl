// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// Encoded byte length alone does not bound decoded Go allocations: tiny JSON
// objects can expand into large structs. Admit the complete token shape before
// the typed decoder can allocate any retained paths or provenance collections.
func admitRoutingCaptureJSON(ctx context.Context, object routingCaptureObject, budget *BGPRoutingBudget) error {
	decoder := json.NewDecoder(strings.NewReader(object.payload))
	decoder.UseNumber()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errRoutingCaptureFormat
		}
		memory := int64(64)
		if delimiter, ok := token.(json.Delim); ok && (delimiter == '{' || delimiter == '[') {
			memory = 1024
		}
		if err := routingBatchCharge(budget, memory, 128); err != nil {
			return err
		}
		if value, ok := token.(string); ok {
			if err := routingCaptureStringCharge(ctx, budget, value); err != nil {
				return err
			}
		}
	}
}

// Charge the complete retained shape before JSON allocates its buffers. These
// are conservative representation costs, never route/path/population ceilings.
func admitRoutingCapture(ctx context.Context, lookup BGPRoutingFlowLookup, budget BGPRoutingBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := routingBatchCharge(&budget, 4096, 1024); err != nil {
		return err
	}
	owner := lookup.Owner
	for _, value := range []string{owner.TenantID, owner.ContextID, owner.AgentID, owner.RouterID, owner.SourceID, owner.Protocol} {
		if err := routingCaptureStringCharge(ctx, &budget, value); err != nil {
			return err
		}
	}
	for _, side := range []*BGPRoutingFlowSide{&lookup.Source, &lookup.Destination} {
		if err := ctx.Err(); err != nil {
			return err
		}
		source := side.Route.Source
		for _, value := range []string{side.State, source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial} {
			if err := routingCaptureStringCharge(ctx, &budget, value); err != nil {
				return err
			}
		}
		for _, path := range side.Route.Paths {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := routingCaptureCountCharge(ctx, &budget, len(path.NextHops), 256); err != nil {
				return err
			}
			if err := routingBatchCharge(&budget, 512, 128); err != nil {
				return err
			}
			for _, segment := range path.Segments {
				if err := routingBatchCharge(&budget, 128, 32); err != nil {
					return err
				}
				if err := routingCaptureCountCharge(ctx, &budget, len(segment.Values), 64); err != nil {
					return err
				}
			}
			for _, attribute := range path.Attributes.Wire {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := routingBatchCharge(&budget, 128, 32); err != nil {
					return err
				}
				if err := routingCaptureCountCharge(ctx, &budget, len(attribute.Value), 8); err != nil {
					return err
				}
			}
		}
		for _, field := range side.Fields {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := routingBatchCharge(&budget, 256, 64); err != nil {
				return err
			}
			if err := routingCaptureStringCharge(ctx, &budget, field.ASPathText); err != nil {
				return err
			}
			for _, segment := range field.ASPath {
				if err := routingBatchCharge(&budget, 128, 32); err != nil {
					return err
				}
				if err := routingCaptureCountCharge(ctx, &budget, len(segment.Values), 64); err != nil {
					return err
				}
			}
		}
		for _, field := range side.NextHops {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := routingBatchCharge(&budget, 512, 128); err != nil {
				return err
			}
			if err := routingCaptureStringCharge(ctx, &budget, field.Reason); err != nil {
				return err
			}
			for _, source := range field.Sources {
				if err := routingCaptureStringCharge(ctx, &budget, source); err != nil {
					return err
				}
			}
		}
	}
	return ctx.Err()
}

func routingCaptureCountCharge(ctx context.Context, budget *BGPRoutingBudget, count int, cost int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if count < 0 || cost <= 0 || budget.MemoryBytes < 0 || budget.WorkUnits < 0 || int64(count) > budget.MemoryBytes/cost || int64(count) > budget.WorkUnits/cost {
		return ErrBGPRoutingBudget
	}
	return routingBatchCharge(budget, int64(count)*cost, int64(count)*cost)
}

func routingCaptureStringCharge(ctx context.Context, budget *BGPRoutingBudget, value string) error {
	return routingCaptureCountCharge(ctx, budget, len(value), 64)
}
