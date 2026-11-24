// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type topologyFailureFlows struct {
	rows      []flowstore.Row
	originals []flowstore.RoutingCaptureRead
	ports     map[topologyFailureInterfaceKey]string
	complete  bool
}

type topologyFailureExporterKey struct {
	agent, exporter, protocol string
	domain                    uint32
}

// readTopologyFailureFlows selects measured traffic by the original
// authenticated exporter tuple and its router's failed interface indices.
// Tenant, routing context and interface identity come from retained evidence.
func (s *Server) readTopologyFailureFlows(ctx context.Context, scope entity.Scope, sources topologyFailureSourcePlan,
	target topologyFailureTarget, from, to time.Time, budget flowstore.ExplorerBudget) (topologyFailureFlows, error) {
	none := topologyFailureFlows{}
	if tenant, bound := tenancy.FromContext(ctx); !bound || tenant.String() != scope.TenantID {
		return none, tenancy.ErrNoTenant
	}
	failed := map[flow.FailurePort]bool{}
	for _, port := range target.ports {
		failed[port] = true
	}
	indices := map[string][]uint32{}
	out := topologyFailureFlows{complete: target.complete, ports: map[topologyFailureInterfaceKey]string{}}
	for _, link := range sources.links {
		p := link.port
		if p.InterfaceID == "" || !failed[flow.FailurePort{InterfaceID: p.InterfaceID, Direction: "out"}] {
			continue
		}
		if p.Scope != scope {
			return none, entity.ErrScopeMismatch
		}
		key := topologyFailureInterfaceKey{p.Source.DeviceID, p.IfIndex}
		if prior, found := out.ports[key]; found && prior != p.InterfaceID {
			return none, entity.ErrConflictingEvidence
		}
		out.ports[key] = p.InterfaceID
		indices[key.device] = append(indices[key.device], key.index)
	}
	for router, values := range indices {
		slices.Sort(values)
		indices[router] = slices.Compact(values)
	}
	covered := map[string]bool{}
	routers := map[topologyFailureExporterKey]string{}
	query := flowstore.IncidentTrafficQuery{TenantID: scope.TenantID, From: from, To: to, Series: "raw", FailureSimulation: true}
	for _, binding := range sources.bindings {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		ports := indices[binding.RouterID]
		if len(ports) == 0 {
			continue
		}
		if binding.Scope != scope {
			return none, entity.ErrScopeMismatch
		}
		covered[binding.RouterID] = true
		key := topologyFailureExporterKey{binding.AgentID, binding.Exporter.String(), binding.Protocol, binding.Domain}
		if router, exists := routers[key]; exists {
			if router != binding.RouterID {
				return none, entity.ErrConflictingEvidence
			}
			continue
		}
		routers[key] = binding.RouterID
		query.Sources = append(query.Sources, flowstore.IncidentTrafficSource{
			AgentID: binding.AgentID, Exporter: binding.Exporter, Protocol: binding.Protocol, Domain: binding.Domain,
			InterfaceIndices: ports,
		})
	}
	out.complete = out.complete && len(covered) == len(indices) && len(query.Sources) > 0
	if len(query.Sources) == 0 {
		return out, nil
	}
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, scope.TenantID, 1, 2)
	if err != nil {
		return none, err
	}
	defer batch.Close()
	out.rows, err = batch.IncidentTrafficRows(query)
	if err != nil {
		return none, err
	}
	kept := out.rows[:0]
	for _, row := range out.rows {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		router := routers[topologyFailureExporterKey{row.AgentID, row.Exporter, row.Protocol, row.ObsDomain}]
		if row.TenantID != scope.TenantID || router == "" {
			return none, entity.ErrScopeMismatch
		}
		if out.ports[topologyFailureInterfaceKey{router, row.OutIf}] != "" {
			kept = append(kept, row)
		}
	}
	out.rows = kept
	out.originals, err = flowstore.IncidentTrafficCaptureReferences(ctx, scope.TenantID, out.rows, budget.MemoryBytes/8)
	if err != nil {
		return none, err
	}
	return out, ctx.Err()
}
