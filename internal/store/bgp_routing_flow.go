// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrBGPRoutingFlowSource = errors.New("routing capture requires a unique current attested exporter")

// BGPRoutingFlowInput contains flow dimensions, never canonical ownership or a
// grant. Agent IDs, tenant IDs and claimed VRFs cannot choose a routing context.
type BGPRoutingFlowInput struct {
	Exporter, Source, Destination netip.Addr
	Protocol                      string
	Domain                        uint32
}

// BGPRoutingFlowSide preserves the difference between an owned selected route,
// a complete RIB without a prefix, and unavailable current source evidence.
// Only router_selected has a Route; neither other state invents an empty path.
type BGPRoutingFlowSide struct {
	State    string
	Route    BGPRoutingLookup
	Fields   []bgp.RoutingPathFields // one complete projection per retained path
	NextHops []BGPRoutingNextHopAS
}

// BGPRoutingFlowLookup is capture-time evidence, not a historical forwarding
// claim or permission to read a source later. The ingest adapter must freeze it
// with the flow; readers independently reauthorize its retained provenance.
type BGPRoutingFlowLookup struct {
	Owner               InterfaceRoleFlowBinding
	CapturedAt          time.Time
	Source, Destination BGPRoutingFlowSide
}

// LookupFlowInScope resolves operator-owned exporter identity and current
// attested protocol/domain before either address lookup in the same tenant
// snapshot. This is an ingestion seam; user-facing readers still need current
// actor/context/source authorization. No cross-request authority cache is used.
func (store BGPRouting) LookupFlowInScope(ctx context.Context, sc tenancy.Scope, input BGPRoutingFlowInput, budget BGPRoutingBudget) (BGPRoutingFlowLookup, error) {
	if err := ctx.Err(); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil {
		return BGPRoutingFlowLookup{}, entity.ErrScopeMismatch
	}
	if !input.Exporter.IsValid() || input.Exporter.Zone() != "" || input.Exporter.IsUnspecified() || input.Exporter.IsMulticast() ||
		!input.Source.IsValid() || input.Source.Zone() != "" || !input.Destination.IsValid() || input.Destination.Zone() != "" || !routingFlowProtocol(input.Protocol) {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingFlowSource
	}
	if err := routingBatchCharge(&budget, 4096, 256); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	reader := &InterfaceRoleInputsStore{}
	part := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.WorkUnits / 8}
	owners, err := reader.ExporterOwnersInScope(ctx, sc, part)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	owner, err := routingFlowOwner(tenant.String(), input.Exporter.Unmap(), owners)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	bindings, err := reader.FlowBindingsInScope(ctx, sc, owner.Scope, part)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	binding, err := routingFlowBinding(owner, input, bindings)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	lookupBudget := budget
	lookupBudget.MemoryBytes /= 4
	lookupBudget.WorkUnits /= 4
	result := BGPRoutingFlowLookup{Owner: binding}
	result.Source, err = store.routingFlowSide(ctx, sc, owner, input.Source.Unmap(), lookupBudget)
	if err == nil {
		result.Destination, err = store.routingFlowSide(ctx, sc, owner, input.Destination.Unmap(), lookupBudget)
	}
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if result.Source.State == "router_selected" || result.Destination.State == "router_selected" {
		peers, err := reader.RouterPeersInScope(ctx, sc, owner.Scope, owner.RouterID, part)
		if err != nil {
			return BGPRoutingFlowLookup{}, err
		}
		associationBudget := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 16, WorkUnits: budget.WorkUnits / 16}
		for _, side := range []*BGPRoutingFlowSide{&result.Source, &result.Destination} {
			if side.State != "router_selected" {
				continue
			}
			side.NextHops, err = routingNextHopFields(ctx, side.Route.Paths, peers, associationBudget)
			if err != nil {
				return BGPRoutingFlowLookup{}, err
			}
		}
	}
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&result.CapturedAt); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if !binding.ValidUntil.After(result.CapturedAt) || !routingFlowSideCurrent(&result.Source, result.CapturedAt) || !routingFlowSideCurrent(&result.Destination, result.CapturedAt) {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingFlowSource
	}
	expireRoutingNextHopFields(&result.Source, result.CapturedAt)
	expireRoutingNextHopFields(&result.Destination, result.CapturedAt)
	return result, nil
}

func routingFlowProtocol(protocol string) bool {
	switch protocol {
	case "netflow5", "netflow9", "ipfix", "sflow5":
		return true
	default:
		return false
	}
}

func routingFlowOwner(tenant string, exporter netip.Addr, owners []InterfaceRoleExporterOwner) (InterfaceRoleExporterOwner, error) {
	var selected InterfaceRoleExporterOwner
	matches := 0
	for _, owner := range owners {
		if owner.TenantID != tenant {
			return InterfaceRoleExporterOwner{}, entity.ErrScopeMismatch
		}
		if owner.Exporter == exporter {
			selected = owner
			matches++
		}
	}
	if matches != 1 || selected.RouterID == "" {
		return InterfaceRoleExporterOwner{}, ErrBGPRoutingFlowSource
	}
	return selected, nil
}

func routingFlowBinding(owner InterfaceRoleExporterOwner, input BGPRoutingFlowInput, bindings []InterfaceRoleFlowBinding) (InterfaceRoleFlowBinding, error) {
	var selected InterfaceRoleFlowBinding
	matches := 0
	for _, binding := range bindings {
		if binding.TenantID != owner.TenantID || binding.ContextID != owner.ContextID {
			return InterfaceRoleFlowBinding{}, entity.ErrScopeMismatch
		}
		if binding.RouterID == owner.RouterID && binding.AgentID == owner.AgentID && binding.Exporter == input.Exporter.Unmap() && binding.Protocol == input.Protocol && binding.Domain == input.Domain {
			selected = binding
			matches++
		}
	}
	if matches != 1 || selected.SourceID == "" || selected.ObservedAt.IsZero() || selected.ValidUntil.IsZero() {
		return InterfaceRoleFlowBinding{}, ErrBGPRoutingFlowSource
	}
	return selected, nil
}

func (store BGPRouting) routingFlowSide(ctx context.Context, sc tenancy.Scope, owner InterfaceRoleExporterOwner, address netip.Addr, budget BGPRoutingBudget) (BGPRoutingFlowSide, error) {
	readBudget := budget
	readBudget.MemoryBytes /= 2
	readBudget.WorkUnits /= 2
	route, err := store.LookupRouterInScope(ctx, sc, owner.Scope, owner.RouterID, address, readBudget)
	switch {
	case err == nil:
		fields, err := routingFlowPathFields(ctx, route.Paths, readBudget)
		if err != nil {
			return BGPRoutingFlowSide{}, err
		}
		return BGPRoutingFlowSide{State: "router_selected", Route: route, Fields: fields}, nil
	case errors.Is(err, ErrBGPRoutingRouteMissing):
		return BGPRoutingFlowSide{State: "no_prefix"}, nil
	case errors.Is(err, ErrBGPRoutingSourceUnavailable):
		return BGPRoutingFlowSide{State: "source_unavailable"}, nil
	default:
		return BGPRoutingFlowSide{}, err
	}
}

func routingFlowSideCurrent(side *BGPRoutingFlowSide, at time.Time) bool {
	return side.State != "router_selected" || side.Route.ValidUntil.After(at)
}
