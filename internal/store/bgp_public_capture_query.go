// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func routingCapturePublicQueryFields(ctx context.Context, side BGPRoutingFlowSide, owner InterfaceRoleFlowBinding, prefix string, out *flowstore.RoutingProjection, budget *BGPRoutingBudget) error {
	if side.Public == nil {
		return errRoutingCaptureFormat
	}
	if err := validatePublicRoutingCaptureSide(ctx, owner, &side, time.Unix(0, out.Clock), *budget); err != nil {
		return err
	}
	for _, source := range side.Public.Sources {
		if err := routingBatchCharge(budget, 512, 256); err != nil {
			return err
		}
		out.SourceIDs = append(out.SourceIDs, "public-snapshot/"+source.SnapshotID)
	}
	if side.State == "public_no_prefix" {
		out.Fields[prefix+"bgp_provenance"] = "no_prefix"
		return nil
	}
	provenance := ""
	for _, path := range side.Public.Paths {
		if err := routingBatchCharge(budget, 512, 256); err != nil {
			return err
		}
		out.SourceIDs = append(out.SourceIDs, "public-view/"+path.View.ID+"/"+path.View.Generation)
		current := "public_" + path.Peer.Feed
		if provenance == "" {
			provenance = current
		} else if provenance != current {
			provenance = "public_mixed"
		}
	}
	if provenance == "" {
		return errRoutingCaptureFormat
	}
	out.Fields[prefix+"bgp_provenance"] = provenance
	out.Fields[prefix+"bgp_prefix"] = side.Public.Prefix.String()
	return routingCapturePathQueryFields(ctx, side.Fields, side.NextHops, prefix, out, budget)
}
