// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPublicCaptureQueryProjectionKeepsExactPathsSourceCohortAndExplicitProvenance(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := publicCaptureFixture(t)
	ref := BGPRoutingCaptureReference{Key: [32]byte{31: 1}, CapturedAt: input.CapturedAt}
	got, err := routingCaptureQueryProjection(ctx, input, ref, publicCaptureBudget())
	if err != nil || got.Scope != input.Owner.Scope || got.Fields["src_bgp_provenance"] != "public_ris" || got.Fields["src_bgp_prefix"] != "192.0.2.0/24" || got.Fields["src_bgp_origin_as"] != "" || got.Fields["src_bgp_first_transit_as"] != "" || got.Fields["src_bgp_next_hop_as"] != "4294967295" || got.Fields["src_bgp_rpki"] != "unknown" || got.Fields["dst_bgp_provenance"] != "router_selected" {
		t.Fatal("public native projection changed paths or invented router/RPKI authority", got, err)
	}
	var paths []string
	if err := json.Unmarshal([]byte(got.Fields["src_bgp_as_paths"]), &paths); err != nil || len(paths) != 1 || paths[0] != input.Source.Fields[0].ASPathText {
		t.Fatal("public native projection truncated original AS path", paths, err)
	}
	for _, id := range []string{"public-snapshot/" + input.Source.Public.Sources[0].SnapshotID, "public-view/" + input.Source.Public.Paths[0].View.ID + "/" + input.Source.Public.Paths[0].View.Generation, input.Owner.SourceID} {
		if !slices.Contains(got.SourceIDs, id) {
			t.Fatal("public native projection omitted original source provenance", id, got.SourceIDs)
		}
	}
	other := input.Source.Public.Sources[0]
	other.Source.CollectorAgentID, other.Source.SourceRef = "zz-public-collector", "routeviews/mrt_table_dump_v2/rv2"
	other.SnapshotID = "88888888-8888-4888-8888-888888888888"
	other.Paths = append([]BGPPublicRoutingPath(nil), other.Paths...)
	other.Paths[0].Peer.Feed, other.Paths[0].Peer.Collector, other.Paths[0].Peer.PeerASN = "routeviews", "rv2", 64555
	other.Paths[0].View = BGPRoutingViewRef{ID: "99999999-9999-4999-8999-999999999999", Generation: other.SnapshotID}
	input.Source.Public.Sources = append(input.Source.Public.Sources, other)
	input.Source.Public.Paths = append(input.Source.Public.Paths, other.Paths...)
	input.Source.Fields, input.Source.NextHops, err = publicRoutingFlowFields(ctx, *input.Source.Public, publicCaptureBudget())
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := routingCaptureQueryProjection(ctx, input, ref, publicCaptureBudget())
	if err != nil || mixed.Fields["src_bgp_provenance"] != "public_mixed" || mixed.Fields["src_bgp_next_hop_as"] != "" || !slices.Contains(mixed.SourceIDs, "public-snapshot/"+other.SnapshotID) || !slices.Contains(mixed.SourceIDs, "public-view/"+other.Paths[0].View.ID+"/"+other.SnapshotID) {
		t.Fatal("mixed public observations lost a contributor or invented next-hop consensus", mixed, err)
	}
	input.Source.State = "public_no_prefix"
	input.Source.Public.Prefix, input.Source.Public.Paths = netip.Prefix{}, nil
	for i := range input.Source.Public.Sources {
		input.Source.Public.Sources[i].Prefix, input.Source.Public.Sources[i].Paths = netip.Prefix{}, nil
	}
	input.Source.Fields, input.Source.NextHops = nil, nil
	missing, err := routingCaptureQueryProjection(ctx, input, ref, publicCaptureBudget())
	if err != nil || missing.Fields["src_bgp_provenance"] != "no_prefix" || missing.Fields["src_bgp_prefix"] != "" || missing.Fields["src_bgp_as_paths"] != "" || !slices.Contains(missing.SourceIDs, "public-snapshot/"+other.SnapshotID) {
		t.Fatal("public no-prefix projection lost complete original source evidence", missing, err)
	}
}
