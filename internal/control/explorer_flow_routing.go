// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowRoutingSnapshot struct {
	data        *flowstore.RoutingQueryData
	reads       []flowstore.RoutingCaptureRead
	inputDigest string
	digest      string
}

func flowPlanUsesCapturedRouting(plan flow.QueryPlan) bool {
	for _, names := range [][]string{plan.GroupBy, plan.MatrixWith, flow.QueryFilterFields(plan.Filter)} {
		for _, name := range names {
			if _, found := flow.RoutingQueryField(name); found {
				return true
			}
		}
	}
	return false
}

func (s *Server) loadFlowRoutingSnapshot(ctx context.Context, actor *auth.Principal, plan flow.QueryPlan, budget flowstore.ExplorerBudget) (flowRoutingSnapshot, error) {
	return s.loadFlowRoutingSnapshotFrom(ctx, actor, budget, func(ctx context.Context) ([]flowstore.RoutingCaptureRead, error) {
		if batch, present := ctx.Value(reportFlowBatchKey{}).(*flowstore.PlanBatch); present {
			if batch == nil {
				return nil, flowstore.ErrExplorerBudget
			}
			return batch.RoutingCaptureReferences(plan.From, plan.To, plan.DataSeries)
		}
		return flowstore.ReadRoutingCaptureReferences(ctx, s.flowStore, actor.TenantID, plan.From, plan.To, plan.DataSeries)
	})
}

// Frozen readers use their original server-retained selectors, rather than
// enumerating a window again as new traffic arrives. Retained selectors still
// grant no source access: this executes every current-user/source check anew.
func (s *Server) recheckFlowRoutingSnapshot(ctx context.Context, actor *auth.Principal, reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) (flowRoutingSnapshot, error) {
	return s.loadFlowRoutingSnapshotFrom(ctx, actor, budget, func(context.Context) ([]flowstore.RoutingCaptureRead, error) { return reads, nil })
}

func (s *Server) loadFlowRoutingSnapshotFrom(ctx context.Context, actor *auth.Principal, budget flowstore.ExplorerBudget, selectReferences func(context.Context) ([]flowstore.RoutingCaptureRead, error)) (flowRoutingSnapshot, error) {
	none := flowRoutingSnapshot{}
	tenant, bound := tenancy.FromContext(ctx)
	if actor == nil || actor.TenantID == "" || actor.UserID == "" || !bound || tenant.String() != actor.TenantID {
		return none, apierror.Forbidden("current tenant user is required for routing metadata")
	}
	if actual := auth.PrincipalFrom(ctx); actual != nil && (actual.TenantID != actor.TenantID || actual.UserID != actor.UserID) {
		return none, apierror.Forbidden("routing user scope does not match its credential")
	}
	if s.pool == nil || budget.Validate() != nil || selectReferences == nil {
		return none, apierror.Unavailable("current routing storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, flowRoutingQueryError(err)
	}
	if status != "active" {
		return none, apierror.Forbidden("current routing tenant is inactive")
	}
	var reads []flowstore.RoutingCaptureRead
	var projections []flowstore.RoutingProjection
	var digest []byte
	var at time.Time
	limit := budget.MemoryBytes / 4
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeNativeFlow(ctx, principal); err != nil {
			return err
		}
		if err := s.authorize(ctx, principal, ai.PermEntitiesRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
			return err
		}
		reads, err = selectReferences(ctx)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, nil, reads, limit)
		if err != nil {
			return err
		}
		records := map[string]entity.ContextRecord{}
		authorize := func(ctx context.Context, record entity.ContextRecord) error {
			if record.TenantID != actor.TenantID {
				return entity.ErrScopeMismatch
			}
			for _, permission := range []string{permAIQuery, permFlowRead, ai.PermEntitiesRead} {
				if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
					return err
				}
			}
			records[record.ContextID] = record
			return nil
		}
		profile := store.BGPRoutingBudget{MemoryBytes: limit, WorkUnits: limit, StateBytes: limit}
		projections, err = (store.BGPRouting{}).FlowCaptureQueryProjectionsInScope(ctx, sc, reads, profile, authorize)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(records))
		for id := range records {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			digest, err = hashFlowRoleInputs(ctx, digest, records[id], limit)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return none, flowRoutingQueryError(err)
	}
	data, err := flowstore.NewRoutingQueryData(ctx, actor.TenantID, at, projections, limit)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	valueDigest, err := data.Digest(ctx, actor.TenantID)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	return flowRoutingSnapshot{data: data, reads: reads, inputDigest: hex.EncodeToString(digest), digest: valueDigest}, nil
}

func flowRoutingQueryError(err error) error {
	var public *apierror.Error
	if errors.As(err, &public) {
		return public
	}
	if errors.Is(err, store.ErrBGPRoutingBudget) || errors.Is(err, entity.ErrInterfaceRoleBudget) {
		return flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	return flowExplorerStoreError(err)
}
