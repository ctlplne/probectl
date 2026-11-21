// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bgpRPKIPostureQuery struct {
	Monitor     string
	Context     string
	Prefix      string
	IntendedASN uint32
}

func (s *Server) handleBGPRPKIPosture(w http.ResponseWriter, r *http.Request) error {
	params := r.URL.Query()
	query := bgpRPKIPostureQuery{Monitor: r.PathValue("id"), Context: params.Get("context_id"), Prefix: params.Get("prefix_id")}
	if text := params.Get("intended_asn"); text != "" {
		value, err := strconv.ParseUint(text, 10, 32)
		if err != nil || value == 0 || value == 23456 {
			return apierror.Validation("intended_asn must identify an explicit nonzero origin")
		}
		query.IntendedASN = uint32(value)
	}
	out, err := s.readBGPRPKIPosture(r.Context(), auth.PrincipalFrom(r.Context()), query, time.Now().UTC(), false)
	if err != nil {
		return bgpASPathHistoryError(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) readBGPRPKIPosture(ctx context.Context, actor *auth.Principal, query bgpRPKIPostureQuery, at time.Time, native bool) (bgpRPKICurrentPosture, error) {
	var empty bgpRPKICurrentPosture
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	if s.pool == nil {
		return empty, apierror.Unavailable("RPKI posture storage is unavailable")
	}
	if !reportRequirementUUID(query.Monitor) || !reportRequirementUUID(query.Context) || !reportRequirementUUID(query.Prefix) {
		return empty, apierror.Validation("RPKI posture requires a current monitored and inventoried prefix")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return empty, err
	}
	if s.requireMFA && !actor.MFASatisfied {
		return empty, apierror.Forbidden("multi-factor authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return empty, apierror.Unavailable("RPKI posture admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return empty, err
		}
		defer release()
	}
	profile := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.MemoryBytes / 2, StateBytes: budget.MemoryBytes}
	result := empty
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		checked, principal, err := s.currentRoutingAuthority(ctx, sc, actor, ai.PermEventsRead)
		if err != nil {
			return err
		}
		target, err := s.readBGPRPKIPostureTarget(checked, sc, principal, query.Context, query.Prefix, query.Monitor)
		if err != nil {
			return err
		}
		if native {
			resource := entityContextResource(target.Context)
			resource["entity_id"], resource["prefix"], resource["monitor_id"] = target.Prefix.ID, target.Monitor.Prefix.String(), target.Monitor.ID
			if err := s.authorize(checked, principal, permAIQuery, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		result, err = s.readBGPRPKICurrentInScope(checked, sc, principal, target, query.IntendedASN, at.AddDate(0, 0, -30), at, 128, profile)
		return err
	})
	if err != nil {
		return empty, err
	}
	return result, ctx.Err()
}
