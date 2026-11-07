// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Called only after the retained reader has checked the current actor,
// canonical context and every original source in its tenant snapshot. This
// pure conversion grants no access and never queries today's RIB or feeds.
func routingCaptureQueryProjection(ctx context.Context, lookup BGPRoutingFlowLookup, ref BGPRoutingCaptureReference, budget BGPRoutingBudget) (flowstore.RoutingProjection, error) {
	none := flowstore.RoutingProjection{}
	tenant, bound := tenancy.FromContext(ctx)
	scope, err := lookup.Owner.Normalize()
	if !bound || tenant.String() != lookup.Owner.TenantID || err != nil || scope != lookup.Owner.Scope {
		return none, entity.ErrScopeMismatch
	}
	if ref.Key == ([32]byte{}) || ref.CapturedAt.UnixNano() <= 0 || !ref.CapturedAt.Equal(lookup.CapturedAt) || lookup.Owner.SourceID == "" {
		return none, errRoutingCaptureFormat
	}
	if err := routingBatchCharge(&budget, 4096+int64(len(lookup.Owner.SourceID))*12, 256); err != nil {
		return none, err
	}
	projection := flowstore.RoutingProjection{Scope: scope, Key: ref.Key, Clock: ref.CapturedAt.UnixNano(), Fields: make(map[string]string, 14), SourceIDs: []string{lookup.Owner.SourceID}}
	for i, side := range []BGPRoutingFlowSide{lookup.Source, lookup.Destination} {
		prefix := "src_"
		if i == 1 {
			prefix = "dst_"
		}
		if err := routingCaptureSideQueryFields(ctx, side, lookup.Owner, prefix, &projection, &budget); err != nil {
			return none, err
		}
	}
	slices.Sort(projection.SourceIDs)
	projection.SourceIDs = slices.Compact(projection.SourceIDs)
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return projection, nil
}

func routingCaptureSideQueryFields(ctx context.Context, side BGPRoutingFlowSide, owner InterfaceRoleFlowBinding, prefix string, out *flowstore.RoutingProjection, budget *BGPRoutingBudget) error {
	for _, name := range []string{"bgp_prefix", "bgp_as_paths", "bgp_origin_as", "bgp_first_transit_as", "bgp_next_hop_as"} {
		out.Fields[prefix+name] = ""
	}
	// RPKI remains explicitly unknown until independently sourced evidence is
	// attached. Router-selected paths alone establish no validation status.
	out.Fields[prefix+"bgp_rpki"] = "unknown"
	switch side.State {
	case "no_prefix":
		out.Fields[prefix+"bgp_provenance"] = "no_prefix"
		return nil
	case "source_unavailable":
		out.Fields[prefix+"bgp_provenance"] = "unavailable"
		return nil
	case "router_selected":
	default:
		return errRoutingCaptureFormat
	}
	if side.Route.Source.Scope != owner.Scope || side.Route.Source.RouterID != owner.RouterID || !side.Route.Prefix.IsValid() || side.Route.Prefix != side.Route.Prefix.Masked() || len(side.Fields) == 0 || len(side.Fields) != len(side.Route.Paths) || len(side.NextHops) != len(side.Fields) {
		return errRoutingCaptureFormat
	}
	for _, id := range []string{side.Route.View.ID, side.Route.View.Generation} {
		if canonical, err := validRegistryUUID(id); err != nil || canonical != id {
			return errRoutingCaptureFormat
		}
	}
	if err := routingBatchCharge(budget, int64(len(side.Fields))*64+512, int64(len(side.Fields))*64); err != nil {
		return err
	}
	paths := make([]string, 0, len(side.Fields))
	var origin, transit, nextHop *uint32
	originKnown, transitKnown, nextHopKnown := true, true, true
	for i, fields := range side.Fields {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Includes sorting, JSON escaping and complete transient/output copies.
		if err := routingBatchCharge(budget, int64(len(fields.ASPathText))*12, int64(len(fields.ASPathText))*8); err != nil {
			return err
		}
		paths = append(paths, fields.ASPathText)
		origin, originKnown = routingQueryConsensus(origin, originKnown, fields.OriginAS)
		transit, transitKnown = routingQueryConsensus(transit, transitKnown, fields.FirstTransitAS)
		hop := side.NextHops[i]
		nextHop, nextHopKnown = routingQueryConsensus(nextHop, nextHopKnown, hop.ASN)
		for _, source := range hop.Sources {
			if err := routingBatchCharge(budget, 128+int64(len(source))*12, 64); err != nil {
				return err
			}
			out.SourceIDs = append(out.SourceIDs, source)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	encoded, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	out.Fields[prefix+"bgp_provenance"] = "router_selected"
	out.Fields[prefix+"bgp_prefix"] = side.Route.Prefix.String()
	out.Fields[prefix+"bgp_as_paths"] = string(encoded)
	out.Fields[prefix+"bgp_origin_as"] = routingQueryASN(origin, originKnown)
	out.Fields[prefix+"bgp_first_transit_as"] = routingQueryASN(transit, transitKnown)
	out.Fields[prefix+"bgp_next_hop_as"] = routingQueryASN(nextHop, nextHopKnown)
	out.SourceIDs = append(out.SourceIDs, "routing-view/"+side.Route.View.ID+"/"+side.Route.View.Generation)
	return nil
}

func routingQueryConsensus(selected *uint32, known bool, next *uint32) (*uint32, bool) {
	if !known || next == nil || *next == 0 || *next == 23456 || (selected != nil && *selected != *next) {
		return nil, false
	}
	return next, true
}

func routingQueryASN(value *uint32, known bool) string {
	if !known || value == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*value), 10)
}
