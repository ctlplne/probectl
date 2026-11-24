// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferFlowEvidence struct {
	all          []flowstore.RoutingCaptureRead
	inPrefix     []flowstore.RoutingCaptureRead
	owners       map[[32]byte]store.CapturedFlowOwner
	selected     map[[32]byte]store.BGPRoutingFailureCapture
	destinations map[netip.Addr]netip.Prefix
}

type routingTransferFlowInput struct {
	rows      []flowstore.Row
	originals routingTransferFlowEvidence
}

// A provider need not expose its other end of a link. Exact address/ifIndex
// ownership of the local handoff and the same router's exporter suffice.
func (s *Server) routingTransferExporterSources(ctx context.Context, actor *auth.Principal, scope entity.Scope,
	port store.DeviceCounterInterface, budget flowstore.ExplorerBudget) ([]flowstore.IncidentTrafficSource, error) {
	var out []flowstore.IncidentTrafficSource
	if port.Scope != scope || port.IfIndex == 0 {
		return nil, entity.ErrScopeMismatch
	}
	err := s.withTopologyFailureSnapshot(ctx, actor, scope, budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		for _, id := range []string{port.Source.DeviceID, port.InterfaceID} {
			if err := authorize(ctx, record, id); err != nil {
				return err
			}
		}
		current, err := store.NewDeviceCounterCaptures(s.pool).CurrentInterfaceInScope(ctx, sc, scope, port.InterfaceID)
		if err != nil {
			return err
		}
		if !sameCapacityCounterInterface(port, current) {
			return apierror.Unavailable("handoff ownership changed; retry")
		}
		reader := &store.InterfaceRoleInputsStore{}
		part := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.ReadBytes / 8}
		owners, err := reader.ExporterOwnersInScope(ctx, sc, part)
		if err != nil {
			return err
		}
		byIP := map[netip.Addr][]store.InterfaceRoleExporterOwner{}
		for _, owner := range owners {
			byIP[owner.Exporter] = append(byIP[owner.Exporter], owner)
		}
		bindings, err := reader.FlowBindingsInScope(ctx, sc, scope, part)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			owner := byIP[binding.Exporter]
			if binding.Scope != scope || binding.RouterID != port.Source.DeviceID || len(owner) != 1 ||
				owner[0].Scope != scope || owner[0].RouterID != binding.RouterID || owner[0].AgentID != binding.AgentID {
				continue
			}
			out = append(out, flowstore.IncidentTrafficSource{AgentID: binding.AgentID, Exporter: binding.Exporter, Protocol: binding.Protocol,
				Domain: binding.Domain, InterfaceIndices: []uint32{port.IfIndex}})
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, apierror.Unavailable("the selected handoff has no current original flow exporter")
	}
	return out, ctx.Err()
}

func (s *Server) readRoutingTransferFlows(ctx context.Context, scope entity.Scope, prefix netip.Prefix,
	window flow.CapacityMeasurementWindow, sources []flowstore.IncidentTrafficSource, budget flowstore.ExplorerBudget) (routingTransferFlowInput, error) {
	none := routingTransferFlowInput{}
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, scope.TenantID, 1, 2)
	if err != nil {
		return none, err
	}
	defer batch.Close()
	// The complete egress is needed to distinguish a real zero for this prefix
	// from missing data. The signed counters independently check that total.
	rows, err := batch.IncidentTrafficRows(flowstore.IncidentTrafficQuery{TenantID: scope.TenantID, From: window.From,
		To: window.To, Sources: sources, Series: "raw", FailureSimulation: true})
	if err != nil {
		return none, err
	}
	reads, err := flowstore.IncidentTrafficCaptureReferences(ctx, scope.TenantID, rows, budget.MemoryBytes/8)
	if err != nil {
		return none, err
	}
	out := routingTransferFlowInput{rows: rows, originals: routingTransferFlowEvidence{all: reads}}
	for _, read := range reads {
		if prefix.Contains(read.Witness.Input.Destination.Unmap()) {
			out.originals.inPrefix = append(out.originals.inPrefix, read)
		}
	}
	return out, ctx.Err()
}

func (s *Server) readRoutingTransferOriginals(ctx context.Context, actor *auth.Principal, scope entity.Scope, router string,
	originals routingTransferFlowEvidence, budget flowstore.ExplorerBudget) (routingTransferFlowEvidence, error) {
	out := routingTransferFlowEvidence{all: originals.all, inPrefix: originals.inPrefix,
		owners: map[[32]byte]store.CapturedFlowOwner{}, selected: map[[32]byte]store.BGPRoutingFailureCapture{}, destinations: map[netip.Addr]netip.Prefix{}}
	err := s.withTopologyFailureSnapshot(ctx, actor, scope, budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		if err := authorize(ctx, record, router); err != nil {
			return err
		}
		bgpBudget := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.ReadBytes / 8, StateBytes: budget.MemoryBytes}
		owners, err := (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, originals.all, bgpBudget,
			func(ctx context.Context, current entity.ContextRecord, binding store.InterfaceRoleFlowBinding) error {
				if binding.Scope != scope || binding.RouterID != router {
					return entity.ErrScopeMismatch
				}
				return authorize(ctx, current, router)
			})
		if err != nil {
			return err
		}
		for _, owner := range owners {
			if owner.Available {
				out.owners[owner.Reference.Key] = owner
			}
		}
		routing := store.BGPRouting{}
		captures, err := routing.FailureCapturesInScope(ctx, sc, scope, originals.inPrefix, bgpBudget, func(ctx context.Context, current entity.ContextRecord) error {
			return authorize(ctx, current, router)
		})
		if err != nil {
			return err
		}
		for _, capture := range captures {
			if capture.Owner.Scope != scope || capture.Owner.RouterID != router {
				return entity.ErrScopeMismatch
			}
			out.selected[capture.Reference.Key] = capture
		}
		return readRoutingTransferCurrentPrefixes(ctx, sc, scope, router, &out, bgpBudget)
	})
	if err != nil {
		return routingTransferFlowEvidence{}, err
	}
	return out, ctx.Err()
}

func readRoutingTransferCurrentPrefixes(ctx context.Context, sc tenancy.Scope, scope entity.Scope, router string,
	out *routingTransferFlowEvidence, budget store.BGPRoutingBudget) error {
	unique := map[netip.Addr]bool{}
	for _, read := range out.inPrefix {
		unique[read.Witness.Input.Destination.Unmap()] = true
	}
	if len(unique) == 0 {
		return ctx.Err()
	}
	budget.MemoryBytes /= int64(len(unique))
	budget.WorkUnits /= int64(len(unique))
	for address := range unique {
		result, err := (store.BGPRouting{}).LookupRouterInScope(ctx, sc, scope, router, address, budget)
		if err != nil {
			return err
		}
		out.destinations[address] = result.Prefix
	}
	return ctx.Err()
}
