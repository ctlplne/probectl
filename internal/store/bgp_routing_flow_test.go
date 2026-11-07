// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingFlowCaptureCannotChooseOwnerFromPayloadOrPartialEvidence(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	owner := InterfaceRoleExporterOwner{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, AgentID: "attested", RouterID: "33333333-3333-4333-8333-333333333333", Exporter: netip.MustParseAddr("192.0.2.1")}
	input := BGPRoutingFlowInput{Exporter: owner.Exporter, Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	if got, err := routingFlowOwner(tenant, input.Exporter, []InterfaceRoleExporterOwner{owner}); err != nil || got != owner {
		t.Fatal("unique current configured exporter was not selected", err)
	}
	for _, owners := range [][]InterfaceRoleExporterOwner{nil, {owner, owner}, {{Scope: entity.Scope{TenantID: "foreign"}, Exporter: owner.Exporter}}} {
		if got, err := routingFlowOwner(tenant, input.Exporter, owners); err == nil || got.RouterID != "" {
			t.Fatal("ambiguous or foreign exporter selected canonical routing ownership")
		}
	}
	binding := InterfaceRoleFlowBinding{Scope: owner.Scope, AgentID: owner.AgentID, RouterID: owner.RouterID, SourceID: "evidence/complete", Exporter: owner.Exporter, Protocol: input.Protocol, Domain: input.Domain, InterfaceRoleEvidenceClock: InterfaceRoleEvidenceClock{ObservedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute)}}
	if got, err := routingFlowBinding(owner, input, []InterfaceRoleFlowBinding{binding}); err != nil || got.SourceID != binding.SourceID {
		t.Fatal("complete current flow source was not selected", err)
	}
	for _, change := range []func(*InterfaceRoleFlowBinding){
		func(b *InterfaceRoleFlowBinding) { b.AgentID = "row-claimed" },
		func(b *InterfaceRoleFlowBinding) { b.ContextID = "foreign" },
		func(b *InterfaceRoleFlowBinding) { b.TenantID = "foreign" },
		func(b *InterfaceRoleFlowBinding) { b.RouterID = "foreign" },
		func(b *InterfaceRoleFlowBinding) { b.Exporter = netip.MustParseAddr("192.0.2.2") },
		func(b *InterfaceRoleFlowBinding) { b.Protocol = "sflow5" },
		func(b *InterfaceRoleFlowBinding) { b.Domain = 0 },
		func(b *InterfaceRoleFlowBinding) { b.SourceID = "" },
		func(b *InterfaceRoleFlowBinding) { b.ValidUntil = time.Time{} },
	} {
		changed := binding
		change(&changed)
		if got, err := routingFlowBinding(owner, input, []InterfaceRoleFlowBinding{changed}); err == nil || got.SourceID != "" {
			t.Fatal("partial, foreign or unproven source selected routing evidence")
		}
	}
	if got, err := routingFlowBinding(owner, input, []InterfaceRoleFlowBinding{binding, binding}); err == nil || got.SourceID != "" {
		t.Fatal("competing current source evidence manufactured one routing owner")
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	for _, sc := range []tenancy.Scope{{}, {Tenant: tenancy.ID("foreign")}, {Tenant: tenancy.ID(tenant)}} {
		if got, err := (BGPRouting{}).LookupFlowInScope(ctx, sc, input, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || got.Source.Route.Paths != nil || got.Owner.RouterID != "" {
			t.Fatal("routing capture reached storage without exact outer tenant scope", err)
		}
	}
	if routingFlowSideCurrent(BGPRoutingFlowSide{State: "router_selected", Route: BGPRoutingLookup{ValidUntil: time.Now().Add(-time.Second)}}, time.Now()) {
		t.Fatal("routing capture outlived its current source lease")
	}
}
