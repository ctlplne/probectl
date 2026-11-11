// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type peeringEstimateRequest struct {
	Target        peeringTarget
	Direction     string
	From, To      time.Time
	BucketSeconds int
	DataSeries    string
}

// estimatePeeringTraffic is the shared service entry point. No transport may
// accept private projection/digest/completeness values as source authority.
func (s *Server) estimatePeeringTraffic(ctx context.Context, actor *auth.Principal, request peeringEstimateRequest) (peeringEstimateResult, error) {
	none := peeringEstimateResult{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if request.Target.Scope.TenantID != actor.TenantID {
		return none, apierror.Forbidden("peering estimate requires its credential's tenant")
	}
	if request.Direction != "inbound" && request.Direction != "outbound" {
		return none, apierror.Validation("peering direction must be inbound or outbound")
	}
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: request.From, To: request.To, BucketSeconds: request.BucketSeconds, DataSeries: request.DataSeries}, time.Now().UTC())
	if err != nil {
		return none, apierror.Validation(err.Error())
	}
	request.From, request.To, request.BucketSeconds, request.DataSeries = plan.From, plan.To, plan.BucketSeconds, plan.DataSeries
	if err := s.authorizeNativeFlow(ctx, actor); err != nil {
		return none, err
	}
	if s.fairnessGate == nil {
		return none, apierror.Unavailable("peering query admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	defer release()
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, actor.TenantID, 1, 1)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	defer batch.Close()
	ctx = batch.Context()
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	roleBudget := interfaceRoleBudget{MemoryBytes: budget.MemoryBytes, WorkUnits: budget.MemoryBytes}
	target, err := s.loadPeeringTarget(ctx, actor, request.Target, roleBudget)
	if err != nil {
		return none, err
	}
	if !target.Eligible {
		return peeringEstimateResult{Target: target, Direction: request.Direction, Reason: target.Reason, From: request.From, To: request.To, BucketSeconds: request.BucketSeconds}, nil
	}
	fullRoles, err := s.loadFlowRoleSnapshot(ctx, actor, budget)
	if err != nil {
		return none, err
	}
	roles, err := fullRoles.data.ForRouter(ctx, request.Target.Scope, target.RouterID, time.Now().UTC(), budget.MemoryBytes/4)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	selection := flowstore.PeeringQueryTarget{Scope: request.Target.Scope, RouterID: target.RouterID, PeerASN: request.Target.PeerASN, Direction: request.Direction}
	before, err := s.loadPeeringRoutingSnapshot(ctx, actor, selection, budget, func(context.Context) ([]flowstore.RoutingCaptureRead, error) {
		return batch.RoutingCaptureReferences(request.From, request.To, request.DataSeries)
	})
	if err != nil {
		return none, err
	}
	query := flowstore.PeeringTrafficQuery{Data: before.data, Roles: roles, From: request.From, To: request.To, BucketSeconds: request.BucketSeconds, DataSeries: request.DataSeries}
	traffic, err := batch.PeeringTraffic(query)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	result, err := summarizePeeringTraffic(ctx, request, target, traffic, budget)
	if err != nil {
		return none, err
	}
	// Re-read only the original selectors; a newer RIB cannot refill an old
	// capture. Refresh all actor/source grants and the complete ownership catalog.
	after, err := s.loadPeeringRoutingSnapshot(ctx, actor, selection, budget, func(context.Context) ([]flowstore.RoutingCaptureRead, error) { return before.reads, nil })
	if err != nil {
		return none, err
	}
	currentRoles, err := s.loadFlowRoleSnapshot(ctx, actor, budget)
	if err != nil {
		return none, err
	}
	current, err := currentRoles.data.ForRouter(ctx, request.Target.Scope, target.RouterID, time.Now().UTC(), budget.MemoryBytes/4)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	roleDigest, err := current.Digest(ctx, actor.TenantID, time.Now().UTC())
	if err != nil || before.digest != after.digest || before.inputDigest != after.inputDigest || traffic.InputDigest != before.digest || traffic.RoleDigest != roleDigest || fullRoles.inputDigest != currentRoles.inputDigest {
		return none, apierror.Unavailable("current peering routing or role authority changed; run a fresh estimate")
	}
	currentTarget, err := s.recheckPeeringTarget(ctx, actor, target, roleBudget)
	if err != nil {
		return none, err
	}
	result.Target = currentTarget
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return result, nil
}
