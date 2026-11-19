// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingReviewApprovalKey struct{}
type routingReviewSessionCheck func(context.Context, tenancy.Scope, *auth.Principal) (bool, error)

func (s *Server) routingReviewApprovalContext(r *http.Request) (context.Context, error) {
	token := auth.TokenFromRequest(r)
	if token == "" || s.sessions == nil {
		return nil, apierror.Forbidden("routing review approval requires a current interactive session")
	}
	check := routingReviewSessionCheck(func(ctx context.Context, sc tenancy.Scope, actor *auth.Principal) (bool, error) {
		return s.sessions.VerifyCurrentToken(token, func(hash []byte, idle time.Duration) (bool, error) {
			return (store.Sessions{}).LockCurrentSessionInScope(ctx, sc, hash, actor.UserID, actor.MFASatisfied, idle)
		})
	})
	return context.WithValue(r.Context(), routingReviewApprovalKey{}, check), nil
}

func (s *Server) lockRoutingReviewApprovalSession(ctx context.Context, sc tenancy.Scope, actor *auth.Principal) error {
	check, _ := ctx.Value(routingReviewApprovalKey{}).(routingReviewSessionCheck)
	if check == nil || actor.ViaBearerToken {
		return apierror.Forbidden("routing review approval requires a current interactive session")
	}
	active, err := check(ctx, sc, actor)
	if err != nil {
		return err
	}
	if !active {
		return apierror.Forbidden("routing review approval requires a current interactive session")
	}
	return nil
}

func (s *Server) handleProposeRTBHReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.routingReviewActor(r)
	if err != nil {
		return err
	}
	var in remediation.RTBHProposalInput
	if err := decodeJSONLimit(r, 4096, &in); err != nil {
		return err
	}
	result, err := service.ProposeRTBH(r.Context(), actor.TenantID, "user:"+actor.Email, in, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusCreated, result)
	return nil
}

func (s *Server) handleGetRTBHReview(w http.ResponseWriter, r *http.Request) error {
	service, actor, err := s.routingReviewActor(r)
	if err != nil {
		return err
	}
	result, err := service.GetRTBHReview(r.Context(), actor.TenantID, r.PathValue("id"), s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) routingReviewActor(r *http.Request) (remediation.RTBHReviews, *auth.Principal, error) {
	service, err := s.remediationSvc()
	if err != nil {
		return nil, nil, err
	}
	reviews, ok := service.(remediation.RTBHReviews)
	if !ok {
		return nil, nil, apierror.NotFound("traffic review is unavailable")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, nil, apierror.Unauthorized("a current tenant account is required")
	}
	return reviews, actor, nil
}
