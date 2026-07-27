// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type alertEvaluationRetention struct {
	MaxPerSeries int `json:"max_per_series"`
	MaxPerRule   int `json:"max_per_rule"`
	ExpiresDays  int `json:"expires_days"`
}

type alertEvaluationsResponse struct {
	ContractVersion    string                    `json:"contract_version"`
	Items              []alert.EvaluationReceipt `json:"items"`
	Truncated          bool                      `json:"truncated"`
	Limit              int                       `json:"limit"`
	Freshness          string                    `json:"freshness"`
	LatestAt           *time.Time                `json:"latest_at,omitempty"`
	EvaluatorRunning   bool                      `json:"evaluator_running"`
	PersistenceRunning bool                      `json:"persistence_running"`
	Retention          alertEvaluationRetention  `json:"retention"`
}

// handleListAlertEvaluations serves the bounded transition ledger for one
// alert rule. The caller's tenant is resolved before the rule lookup, and the
// store repeats tenant_id in every query under forced RLS.
func (s *Server) handleListAlertEvaluations(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertStateFor(r)
	if err != nil {
		return err
	}
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
	resp := alertEvaluationsResponse{
		ContractVersion:    "probectl.alert-evaluations/v1",
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
		writeJSON(w, http.StatusOK, resp)
		return nil
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
		return err
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
	writeJSON(w, http.StatusOK, resp)
	return nil
}
