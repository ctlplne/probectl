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
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type alertEvaluationRetention = alert.EvaluationRetention
type alertEvaluationsResponse = alert.EvaluationsResult

// handleListAlertEvaluations serves the bounded transition ledger for one
// alert rule. The caller's tenant is resolved before the rule lookup, and the
// store repeats tenant_id in every query under forced RLS.
func (s *Server) handleListAlertEvaluations(w http.ResponseWriter, r *http.Request) error {
	ruleID := strings.TrimSpace(r.PathValue("id"))
	if ruleID == "" {
		return apierror.Validation("alert rule id is required")
	}
	fingerprint := strings.TrimSpace(r.URL.Query().Get("fingerprint"))
	if len(fingerprint) > 2048 {
		return apierror.Validation("fingerprint must be at most 2048 characters")
	}
	limit := store.MaxAlertEvaluationReceiptsPerSeries
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > store.MaxAlertEvaluationReceiptRead {
			return apierror.Validation("limit must be an integer between 1 and 100")
		}
		limit = parsed
	}
	resp, err := s.readAlertEvaluations(r, ruleID, fingerprint, limit)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// Shared bounded domain read for the API and the named native tool. Existing
// alert.read grants still expose ordinary receipts; only the new source clock
// requires the current user's live credential AND freshly loaded source role.
func (s *Server) readAlertEvaluations(r *http.Request, ruleID, fingerprint string, limit int) (alert.EvaluationsResult, error) {
	if strings.TrimSpace(ruleID) == "" || len(fingerprint) > 2048 || limit < 1 || limit > store.MaxAlertEvaluationReceiptRead {
		return alert.EvaluationsResult{}, apierror.Validation("valid rule, fingerprint and receipt limit are required")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	src, tenantID, err := s.alertStateFor(r)
	if err != nil {
		return alert.EvaluationsResult{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	r = r.WithContext(ctx)
	resp := alertEvaluationsResponse{
		ContractVersion:    "probectl.alert-evaluations/v1",
		TagSelectionAccess: "withheld",
		Items:              []alert.EvaluationReceipt{},
		Limit:              limit,
		Freshness:          "unavailable",
		EvaluatorRunning:   src != nil,
		PersistenceRunning: s.pool != nil,
		Retention: alertEvaluationRetention{
			MaxPerSeries: store.MaxAlertEvaluationReceiptsPerSeries,
			MaxPerRule:   store.MaxAlertEvaluationReceiptsPerRule,
			ExpiresDays:  int(store.AlertEvaluationReceiptRetention / (24 * time.Hour)),
		},
	}
	if s.pool == nil {
		return resp, nil
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.AlertRules{}).Get(ctx, sc, ruleID); err != nil {
			return err
		}
		items, truncated, err := (store.AlertEvaluations{}).List(ctx, sc, ruleID, fingerprint, limit)
		if err != nil {
			return err
		}
		resp.Items, resp.Truncated = items, truncated
		return nil
	}); err != nil {
		return alert.EvaluationsResult{}, err
	}
	if len(resp.Items) > 0 {
		latest := resp.Items[len(resp.Items)-1].ObservedAt
		resp.LatestAt = &latest
		interval := 30 * time.Second
		if s.cfg != nil && s.cfg.AlertEvalInterval > 0 {
			interval = s.cfg.AlertEvalInterval
		}
		resp.Freshness = "current"
		if time.Since(latest) > 2*interval {
			resp.Freshness = "stale"
		}
	}
	if s.alertSelectionReceiptAllowed(ctx, auth.PrincipalFrom(ctx)) {
		resp.TagSelectionAccess = "available"
	} else {
		for i := range resp.Items {
			resp.Items[i].TagSelection = nil
		}
	}
	return resp, nil
}

func (s *Server) alertSelectionReceiptAllowed(ctx context.Context, actor *auth.Principal) bool {
	if actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return false
	}
	// Missing credential scope can only withhold. It never gets widened by the
	// source owner's stored role or the freshly loaded current user below.
	for _, permission := range alertTagPermissions() {
		if !actor.Has(permission) {
			return false
		}
	}
	authority, err := loadAlertTagAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return false
	}
	for _, permission := range alertTagPermissions() {
		if !authority.permitsRequest(ctx, actor, permission) {
			return false
		}
	}
	return ctx.Err() == nil
}
