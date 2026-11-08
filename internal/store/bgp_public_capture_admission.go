// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import "context"

// Both the full source observations and selected output paths serialize into
// immutable facts. Charge every copy and original binary metadata before JSON
// allocates; no source, peer, path or AS segment may be truncated to fit.
func chargePublicRoutingCapture(ctx context.Context, public *BGPPublicContextLookup, budget *BGPRoutingBudget) error {
	if public == nil {
		return nil
	}
	if err := routingCaptureCountCharge(ctx, budget, len(public.Sources), 4096); err != nil {
		return err
	}
	for _, value := range []string{public.Scope.TenantID, public.Scope.ContextID} {
		if err := routingCaptureStringCharge(ctx, budget, value); err != nil {
			return err
		}
	}
	for _, source := range public.Sources {
		for _, value := range []string{source.Source.TenantID, source.Source.ContextID, source.Source.CollectorAgentID, source.Source.SourceRef, source.Source.SenderSerial, source.SnapshotID} {
			if err := routingCaptureStringCharge(ctx, budget, value); err != nil {
				return err
			}
		}
		for _, path := range source.Paths {
			if err := chargePublicRoutingCapturePath(ctx, path, budget); err != nil {
				return err
			}
		}
	}
	for _, path := range public.Paths {
		if err := chargePublicRoutingCapturePath(ctx, path, budget); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func chargePublicRoutingCapturePath(ctx context.Context, path BGPPublicRoutingPath, budget *BGPRoutingBudget) error {
	if err := routingBatchCharge(budget, 1024, 256); err != nil {
		return err
	}
	for _, value := range []string{path.View.ID, path.View.Generation, path.Peer.Feed, path.Peer.Format, path.Peer.Collector, path.Peer.Cursor} {
		if err := routingCaptureStringCharge(ctx, budget, value); err != nil {
			return err
		}
	}
	if err := routingCaptureCountCharge(ctx, budget, len(path.Peer.ViewName), 64); err != nil {
		return err
	}
	return chargeRoutingCapturePath(ctx, path.Path, budget)
}
