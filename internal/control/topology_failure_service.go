// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"reflect"
	"time"

	guuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/topology"
)

type topologyFailureWindow struct {
	scope           entity.Scope
	from, to, until time.Time
	pollGap         time.Duration
}

type topologyFailureTraffic struct {
	ContextID        string                     `json:"context_id"`
	From             time.Time                  `json:"from"`
	To               time.Time                  `json:"to"`
	Model            string                     `json:"model"`
	Status           string                     `json:"status"`
	Reason           string                     `json:"reason,omitempty"`
	FailedPorts      []flow.FailurePort         `json:"failed_ports"`
	FlowRecords      int                        `json:"flow_records"`
	UnattributedRows int                        `json:"unattributed_rows"`
	Projection       *flow.FailureTrafficSeries `json:"projection,omitempty"`
	checkPublication func() error
}

func (s *Server) measureTopologyWhatIf(op capacityForecastOperation, req whatIfRequest) (whatIfResponse, error) {
	window, err := topologyFailureScope(req, op.actor.TenantID, time.Now().UTC())
	if err != nil {
		return whatIfResponse{}, err
	}
	graph, err := s.simulateWhatIf(op.request, req)
	if err != nil {
		return whatIfResponse{}, err
	}
	traffic, err := s.simulateTopologyFailureTraffic(op.request.Context(), op.actor, graph, req, window, op.budget)
	if err != nil {
		return whatIfResponse{}, topologyFailureError(err)
	}
	return whatIfResponse{Impact: graph, Traffic: &traffic}, nil
}

func topologyFailureScope(req whatIfRequest, tenant string, now time.Time) (topologyFailureWindow, error) {
	none := topologyFailureWindow{}
	scope := entity.Scope{TenantID: tenant, ContextID: req.ContextID}
	normalized, err := scope.Normalize()
	if err != nil || normalized != scope {
		return none, apierror.Validation("traffic simulation requires a canonical routing context")
	}
	if req.FailureInterfaceID != "" {
		id, err := guuid.Parse(req.FailureInterfaceID)
		if err != nil || id == guuid.Nil || id.String() != req.FailureInterfaceID {
			return none, apierror.Validation("failed interface requires a canonical interface identity")
		}
	}
	from, err := topologyFailureClock(req.TrafficFrom)
	if err != nil {
		return none, err
	}
	to, err := topologyFailureClock(req.TrafficTo)
	if err != nil {
		return none, err
	}
	if !to.After(from) || !from.Add(to.Sub(from)).Equal(to) || to.After(now) {
		return none, apierror.Validation("traffic simulation requires a closed original observation window")
	}
	var until time.Time
	if req.RunoutUntil != "" {
		until, err = topologyFailureClock(req.RunoutUntil)
		if err != nil {
			return none, err
		}
		if !until.After(to) || !from.Add(until.Sub(from)).Equal(until) {
			return none, apierror.Validation("runout horizon must follow the observation window")
		}
	}
	gap, err := time.ParseDuration(req.MaximumPollGap)
	if err != nil || gap <= 0 {
		return none, apierror.Validation("traffic simulation requires a positive maximum counter poll gap")
	}
	return topologyFailureWindow{scope: scope, from: from, to: to, until: until, pollGap: gap}, nil
}

func topologyFailureClock(text string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
		return time.Time{}, apierror.Validation("traffic clocks require exact supported RFC3339 instants")
	}
	return at.UTC(), nil
}

// simulateTopologyFailureTraffic requires the caller's bounded query slot and
// records the source authority to be revalidated after encoding.
func (s *Server) simulateTopologyFailureTraffic(ctx context.Context, actor *auth.Principal, graph topology.Impact, req whatIfRequest,
	window topologyFailureWindow, budget flowstore.ExplorerBudget) (_ topologyFailureTraffic, err error) {
	none := topologyFailureTraffic{}
	finish := s.beginFlowOperation(ctx, "topology_failure")
	defer func() { finish(err) }()
	ctx, err = bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	sources, err := s.readTopologyFailureSources(ctx, actor, window.scope, budget)
	if err != nil {
		return none, err
	}
	result := topologyFailureTraffic{ContextID: window.scope.ContextID, From: window.from, To: window.to,
		Model: "original_flow_mean_overlap_and_directional_counter_load", Status: "unavailable", FailedPorts: []flow.FailurePort{},
		checkPublication: ctx.Err}
	if req.At != "" {
		result.Reason = "historical_route_eligibility_unavailable"
		return result, nil
	}
	if graph.Partial {
		result.Reason = "topology_traversal_incomplete"
		return result, nil
	}
	target, err := s.topologyFailurePorts(ctx, window.scope, sources, graph.Target, graph.TargetKind, req.FailureInterfaceID, budget.MemoryBytes/16)
	if err != nil {
		return none, err
	}
	if len(target.ports) == 0 {
		result.Reason = target.reason
		return result, nil
	}
	result.FailedPorts = target.ports
	counterWindow := flow.CapacityMeasurementWindow{From: window.from, To: window.to, MaximumPollGap: window.pollGap,
		MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.ReadBytes / 2}
	counterBudget := flowstore.CounterBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.ReadBytes / 2, Timeout: budget.ExecutionLimit}
	counters, err := s.readTopologyFailureCounters(ctx, actor.TenantID, sources, counterWindow, counterBudget)
	if err != nil {
		return none, err
	}
	flows, err := s.readTopologyFailureFlows(ctx, window.scope, sources, target, window.from, window.to, budget)
	if err != nil {
		return none, err
	}
	routes, err := s.readTopologyFailureRouting(ctx, actor, window.scope, sources, flows.originals, budget)
	if err != nil {
		return none, err
	}
	out, err := projectTopologyFailure(ctx, window.scope, target, flows, routes, counters, window.from, window.to, window.until, budget)
	if err != nil {
		return none, err
	}
	result.checkPublication = func() error {
		return s.recheckTopologyFailureSources(ctx, actor, graph, req, window, budget, sources, target, counters, flows, routes)
	}
	result.FlowRecords, result.UnattributedRows, result.Projection = len(flows.rows), out.unattributed, &out.series
	result.Status = "projected"
	if !out.series.Complete {
		result.Status = "partial"
		result.Reason = target.reason
		if result.Reason == "" {
			result.Reason = "traffic_or_capacity_coverage_incomplete"
		}
	}
	return result, ctx.Err()
}

func (s *Server) recheckTopologyFailureSources(ctx context.Context, actor *auth.Principal, graph topology.Impact, req whatIfRequest,
	window topologyFailureWindow, budget flowstore.ExplorerBudget, before topologyFailureSourcePlan, target topologyFailureTarget,
	counters topologyFailureCounters, flows topologyFailureFlows, routes topologyFailureRouting) error {
	after, err := s.readTopologyFailureSources(ctx, actor, window.scope, budget)
	if err != nil {
		return err
	}
	if !sameTopologyFailureSources(before, after) {
		return apierror.Unavailable("traffic simulation source authority changed; retry")
	}
	currentTarget, err := s.topologyFailurePorts(ctx, window.scope, after, graph.Target, graph.TargetKind, req.FailureInterfaceID, budget.MemoryBytes/16)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(target, currentTarget) {
		return apierror.Unavailable("failed link mapping changed; retry")
	}
	currentRoutes, err := s.readTopologyFailureRouting(ctx, actor, window.scope, after, flows.originals, budget)
	if err != nil {
		return err
	}
	if !sameTopologyFailureRouting(routes, currentRoutes) {
		return apierror.Unavailable("traffic simulation routing authority changed; retry")
	}
	return s.recheckTopologyFailureCounters(ctx, counters, budget.MemoryBytes/2)
}

func sameTopologyFailureSources(a, b topologyFailureSourcePlan) bool {
	if len(a.links) != len(b.links) || !reflect.DeepEqual(a.bindings, b.bindings) {
		return false
	}
	for i, old := range a.links {
		current := b.links[i]
		old.original.CapturedAt, current.original.CapturedAt = time.Time{}, time.Time{}
		if old.original != current.original || old.fromDevice != current.fromDevice || !sameCapacityCounterInterface(old.port, current.port) {
			return false
		}
	}
	return true
}

func sameTopologyFailureRouting(a, b topologyFailureRouting) bool {
	if len(a.routes) != len(b.routes) || !reflect.DeepEqual(a.captures, b.captures) {
		return false
	}
	for key, old := range a.routes {
		current, found := b.routes[key]
		if !found || !reflect.DeepEqual(old.evidence, current.evidence) || !reflect.DeepEqual(old.exits, current.exits) ||
			!sameFailureRouteLookup(old.original.Selected, current.original.Selected) ||
			len(old.original.Neighbors) != len(current.original.Neighbors) {
			return false
		}
		for i, neighbor := range old.original.Neighbors {
			got := current.original.Neighbors[i]
			if neighbor.Peer != got.Peer || neighbor.Local != got.Local || neighbor.ASN != got.ASN || !sameFailureRouteLookup(neighbor.Route, got.Route) {
				return false
			}
		}
	}
	return true
}

func sameFailureRouteLookup(a, b store.BGPRoutingLookup) bool {
	return a.View == b.View && a.Prefix == b.Prefix && reflect.DeepEqual(a.Source, b.Source) && reflect.DeepEqual(a.Paths, b.Paths)
}

func topologyFailureError(err error) error {
	var apiErr *apierror.Error
	switch {
	case errors.As(err, &apiErr):
		return err
	case errors.Is(err, flow.ErrFailureTrafficInput):
		return apierror.Unavailable("complete original traffic observations are unavailable")
	case errors.Is(err, flow.ErrFailureTrafficBudget):
		return apierror.TooLarge("complete traffic simulation exceeds resource admission")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return apierror.Unavailable("traffic simulation deadline elapsed")
	default:
		return capacityBillAPIError(flowRoutingQueryError(err))
	}
}
