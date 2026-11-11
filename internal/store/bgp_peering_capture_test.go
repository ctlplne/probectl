// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPeeringCaptureMatchKeepsOriginalStructuredPathsAndTenantBeforeAdmission(t *testing.T) {
	const peer = ^uint32(0)
	for _, tenant := range []string{routingCaptureTenant, "99999999-9999-4999-8999-999999999999"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		lookup := routingCaptureFixture(t)
		lookup.Owner.TenantID = tenant
		lookup.Source.Route.Source.Scope = lookup.Owner.Scope
		lookup.Destination.Route.Source.Scope = lookup.Owner.Scope
		path := lookup.Source.Route.Paths[0]
		path.Segments = []BGPRoutingSegment{{Kind: 2, Values: []uint32{64500, peer, peer}}}
		lookup.Source.Route.Paths = []BGPRoutingChange{path}
		// Display text is not the original structured source used for matching.
		lookup.Source.Fields[0].ASPathText = "64500 64501"
		destination := path
		destination.Segments = []BGPRoutingSegment{{Kind: 1, Values: []uint32{peer}}}
		lookup.Destination.Route.Paths = []BGPRoutingChange{destination}
		target := BGPPeeringCaptureTarget{Scope: lookup.Owner.Scope, RouterID: lookup.Owner.RouterID, PeerASN: peer}
		budget := routingViewBudget()
		before := budget.WorkUnits
		match, err := routingCapturePeeringMatch(ctx, lookup, target, &budget)
		if err != nil || match == nil || match.PeerASN != peer || match.RouterID != target.RouterID || match.Source != bgp.PeeringPathEligible || match.Destination != bgp.PeeringPathAmbiguous || budget.WorkUnits >= before {
			t.Fatal("peering capture lost original path semantics, full ASN or shared operation accounting", match, err)
		}
		foreign := target
		foreign.TenantID = "66666666-6666-4666-8666-666666666666"
		tiny := BGPRoutingBudget{}
		if got, err := routingCapturePeeringMatch(ctx, lookup, foreign, &tiny); !errors.Is(err, entity.ErrScopeMismatch) || got != nil {
			t.Fatal("peering capture consulted path availability before tenant scope", err)
		}
		foreign = target
		foreign.RouterID = "88888888-8888-4888-8888-888888888888"
		if got, err := routingCapturePeeringMatch(ctx, lookup, foreign, &tiny); !errors.Is(err, entity.ErrScopeMismatch) || got != nil {
			t.Fatal("peering capture accepted another canonical router", err)
		}
	}
}

func TestPeeringCaptureMatchKeepsPublicProvenanceAndExplicitAbsence(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	lookup := publicCaptureFixture(t)
	const peer = ^uint32(0)
	lookup.Source.Public.Paths[0].Path.Segments = []BGPRoutingSegment{{Kind: 2, Values: []uint32{peer}}}
	target := BGPPeeringCaptureTarget{Scope: lookup.Owner.Scope, RouterID: lookup.Owner.RouterID, PeerASN: peer}
	budget := publicCaptureBudget()
	match, err := routingCapturePeeringMatch(ctx, lookup, target, &budget)
	if err != nil || match.Source != bgp.PeeringPathEligible || lookup.Source.State != "public_fallback" {
		t.Fatal("peering capture replaced original public paths or invented router selection", match, err)
	}
	lookup.Source = BGPRoutingFlowSide{State: "public_no_prefix"}
	lookup.Destination = BGPRoutingFlowSide{State: "source_unavailable"}
	budget = routingViewBudget()
	match, err = routingCapturePeeringMatch(ctx, lookup, target, &budget)
	if err != nil || match.Source != bgp.PeeringPathNotOnPath || match.Destination != bgp.PeeringPathUnavailable {
		t.Fatal("peering capture confused proved absence and unavailable original evidence", match, err)
	}
}
