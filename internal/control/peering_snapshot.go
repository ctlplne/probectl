// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type peeringRoutingSnapshot struct {
	data        *flowstore.PeeringQueryData
	reads       []flowstore.RoutingCaptureRead
	inputDigest string
	digest      string
}

// Retained selectors are always re-read through current user, credential,
// context and original source authority in the application's tenant snapshot.
func (s *Server) loadPeeringRoutingSnapshot(ctx context.Context, actor *auth.Principal, target flowstore.PeeringQueryTarget, budget flowstore.ExplorerBudget, selectReads func(context.Context) ([]flowstore.RoutingCaptureRead, error)) (peeringRoutingSnapshot, error) {
	none := peeringRoutingSnapshot{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if actor.TenantID != target.TenantID {
		return none, apierror.Forbidden("peering capture tenant scope does not match its credential")
	}
	if s.pool == nil || budget.Validate() != nil || selectReads == nil {
		return none, apierror.Unavailable("current peering routing storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current peering tenant is inactive")
	}
	var result peeringRoutingSnapshot
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
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, target.ContextID)
		if err != nil {
			return err
		}
		if err := s.authorizeFlowRoutingContext(ctx, principal, record); err != nil {
			return err
		}
		// Context authorization deliberately precedes enumeration, including an
		// empty flow selection or an eventual admission refusal.
		reads, err := selectReads(ctx)
		if err != nil {
			return err
		}
		limit := budget.MemoryBytes / 4
		inputDigest, err := hashFlowRoleInputs(ctx, nil, reads, limit)
		if err != nil {
			return err
		}
		inputDigest, err = hashFlowRoleInputs(ctx, inputDigest, record, limit)
		if err != nil {
			return err
		}
		authorize := func(ctx context.Context, selected entity.ContextRecord) error {
			if selected.TenantID != target.TenantID || selected.ContextID != target.ContextID {
				return entity.ErrScopeMismatch
			}
			return s.authorizeFlowRoutingContext(ctx, principal, selected)
		}
		projections, err := (store.BGPRouting{}).FlowPeeringCaptureProjectionsInScope(ctx, sc, reads,
			store.BGPPeeringCaptureTarget{Scope: target.Scope, RouterID: target.RouterID, PeerASN: target.PeerASN},
			store.BGPRoutingBudget{MemoryBytes: limit, WorkUnits: limit, StateBytes: limit}, authorize)
		if err != nil {
			return err
		}
		var at time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
			return err
		}
		data, err := flowstore.NewPeeringQueryData(ctx, target, at, projections, limit)
		if err != nil {
			return err
		}
		digest, err := data.Digest(ctx, principal.TenantID)
		if err != nil {
			return err
		}
		result = peeringRoutingSnapshot{data: data, reads: reads, inputDigest: hex.EncodeToString(inputDigest), digest: digest}
		return nil
	})
	if err != nil {
		return none, flowRoutingQueryError(err)
	}
	return result, nil
}
