// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferWithdrawalInput struct {
	Fingerprint string `json:"review_fingerprint"`
}

func (s *Server) handleGetRoutingTransferRollback(w http.ResponseWriter, r *http.Request) error {
	svc, actor, err := s.routingTransferRollbackActor(r)
	if err != nil {
		return err
	}
	if !reportRequirementUUID(r.PathValue("id")) {
		return apierror.Validation("select an approved routing transfer")
	}
	current := s.pathAlertRequestCredential(r, actor)
	if err := current(r.Context()); err != nil {
		return err
	}
	ctx, flush := scopedABACDenial(r.Context())
	defer flush(s)
	result, err := svc.GetRoutingTransferRollback(ctx, actor.TenantID, r.PathValue("id"),
		s.routingTransferRollbackAuthority(actor, permRemediationPropose))
	if err != nil {
		return mapRemediationErr(err)
	}
	if err := current(r.Context()); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) handleRequestRoutingTransferWithdrawal(w http.ResponseWriter, r *http.Request) error {
	svc, actor, err := s.routingTransferRollbackActor(r)
	if err != nil {
		return err
	}
	if !reportRequirementUUID(r.PathValue("id")) {
		return apierror.Validation("select an approved routing transfer")
	}
	ctx, err := s.routingReviewApprovalContext(r)
	if err != nil {
		return err
	}
	var input routingTransferWithdrawalInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	result, err := svc.RequestRoutingTransferWithdrawal(ctx, actor.TenantID, "user:"+actor.Email, r.PathValue("id"),
		input.Fingerprint, s.routingTransferRollbackAuthority(actor, permRemediationApprove))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) routingTransferRollbackActor(r *http.Request) (remediation.RoutingTransferRollbackService, *auth.Principal, error) {
	svc, err := s.remediationSvc()
	if err != nil {
		return nil, nil, err
	}
	available, ok := svc.(remediation.RoutingTransferRollbackService)
	if !ok {
		return nil, nil, apierror.NotFound("routing transfer rollback is unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, nil, apierror.Unauthorized("a current tenant account is required")
	}
	return available, actor, nil
}

func (s *Server) routingTransferRollbackAuthority(actor *auth.Principal, permission string) remediation.RoutingTransferRollbackAuthorizer {
	return func(ctx context.Context, sc tenancy.Scope, contextID, routerID string, source entity.SourceKey) error {
		if actor == nil || sc.Tenant.String() != actor.TenantID || sc.Q == nil ||
			source.Kind != entity.DeviceTarget || source.AgentID == "" || source.SourceRef == "" ||
			(permission != permRemediationPropose && permission != permRemediationApprove) {
			return entity.ErrScopeMismatch
		}
		if s.requireMFA && !actor.MFASatisfied {
			return apierror.Forbidden("current multi-factor authentication required")
		}
		if permission == permRemediationApprove {
			if err := s.lockRoutingReviewApprovalSession(ctx, sc, actor); err != nil {
				return err
			}
		}
		authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, current, err := authority.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		registry := store.NewEntityRegistry(s.pool)
		scope := entity.Scope{TenantID: actor.TenantID, ContextID: contextID}
		record, err := registry.GetEntityContextInScope(ctx, sc, scope.ContextID)
		if errors.Is(err, pgx.ErrNoRows) {
			return apierror.NotFound("the owned rollback router is unavailable")
		}
		if err != nil {
			return err
		}
		resource := entityContextResource(record)
		resource["entity_id"] = routerID
		for _, wanted := range []string{permission, ai.PermEntitiesRead} {
			if err := s.authorize(ctx, current, wanted, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		resource["agent_id"], resource["source_kind"], resource["source_ref"] = source.AgentID, string(source.Kind), source.SourceRef
		if err := s.authorize(ctx, current, "metrics.read", auth.RBACGlobal, resource); err != nil {
			return err
		}
		router, err := registry.GetEntityInScope(ctx, sc, scope, routerID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && router.Kind != entity.Device {
			return apierror.NotFound("the owned rollback router is unavailable")
		}
		return err
	}
}
