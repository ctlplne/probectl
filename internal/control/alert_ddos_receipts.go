// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleGetAlertDDoSReceipt(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	result, err := s.readAlertDDoSReceipt(r.Context(), actor, r.PathValue("id"), r.URL.Query().Get("fingerprint"), s.pathAlertRequestCredential(r, actor), nil)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) readAlertDDoSReceipt(ctx context.Context, actor *auth.Principal, ruleID, fingerprint string, credential func(context.Context) error, retain pathHealthPublication) (alert.DDoSEvaluationEvidence, error) {
	return readAlertFlowReceipt(ctx, s, actor, ruleID, fingerprint, "traffic assessment", credential, retain,
		func(ctx context.Context) (alert.DDoSEvaluationEvidence, []byte, error) {
			return s.loadAlertDDoSReceipt(ctx, actor, ruleID, fingerprint)
		})
}

func (s *Server) loadAlertDDoSReceipt(ctx context.Context, actor *auth.Principal, ruleID, fingerprint string) (alert.DDoSEvaluationEvidence, []byte, error) {
	var evidence alert.DDoSEvaluationEvidence
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return evidence, nil, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return evidence, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var raw []byte
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return s.loadAlertDDoSReceiptInScope(ctx, sc, actor, ruleID, fingerprint, budget.MemoryBytes/8,
			func(_ context.Context, _ tenancy.Scope, proof alert.DDoSEvaluationEvidence, body []byte) error {
				evidence, raw = proof, body
				return nil
			})
	})
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrAlertQueryChanged) {
		return alert.DDoSEvaluationEvidence{}, nil, apierror.NotFound("traffic assessment receipt not found")
	}
	if err != nil {
		return alert.DDoSEvaluationEvidence{}, nil, err
	}
	return evidence, raw, ctx.Err()
}

// loadAlertDDoSReceiptInScope keeps the same rule and audit locks around a
// caller's final publication. The caller supplies current authorization.
func (s *Server) loadAlertDDoSReceiptInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, ruleID, fingerprint string,
	memory int64, publish func(context.Context, tenancy.Scope, alert.DDoSEvaluationEvidence, []byte) error) error {
	rules := store.AlertRules{}
	rule, err := rules.Get(ctx, sc, ruleID)
	if err != nil {
		return err
	}
	return rules.WithQueryPublication(ctx, sc, ruleID, rule.UpdatedAt, memory,
		func(ctx context.Context, sc tenancy.Scope, source alert.QuerySource) error {
			if source.Condition.Mode != alert.DDoSCondition || source.Condition.DDoS == nil {
				return apierror.NotFound("traffic assessment receipt not found")
			}
			record, err := (store.AlertEvaluations{}).GetFlowReceipt(ctx, sc, store.AlertDDoSReceipt, ruleID, fingerprint, rule.UpdatedAt, memory)
			if err != nil {
				return err
			}
			parsed, capture, err := decodeDDoSReceipt(ctx, record, source.Binding(sc.Tenant.String(), ruleID), rule.UpdatedAt, fingerprint, memory)
			if err != nil {
				return err
			}
			if err := s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture); err != nil {
				return err
			}
			return publish(store.WithReportSourceAuditLock(ctx, sc), sc, parsed.Evidence, record.Body)
		})
}

func decodeDDoSReceipt(ctx context.Context, record store.AlertFlowReceipt, binding alert.QueryGroupBinding, revision time.Time, fingerprint string, memory int64) (storedDDoSReceipt, *reportFlowCapture, error) {
	var proof, empty storedDDoSReceipt
	input := binding.Condition.DDoS
	if input == nil || record.ObservedAt.IsZero() || int64(len(record.Body)) > memory {
		return empty, nil, alert.ErrQueryGroups
	}
	decoder := json.NewDecoder(bytes.NewReader(record.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil || decoder.Decode(new(any)) != io.EOF || proof.Version != 1 ||
		!reportRequirementUUID(proof.Evidence.IncidentID) || !alert.ValidFieldDigest(proof.Evidence.EpisodeID) || !proof.Evidence.Current.After.To.Equal(record.ObservedAt) {
		return empty, nil, alert.ErrQueryGroups
	}
	want, err := flowEpisodeReceiptFingerprint(binding.TenantID, binding.RuleID, revision, record.ObservedAt)
	if err != nil || want != fingerprint {
		return empty, nil, alert.ErrQueryGroups
	}
	clocks, err := ddosClocks(record.ObservedAt, input.PeriodSeconds)
	if err != nil || !clocks.Current.After.End.Equal(record.ObservedAt) {
		return empty, nil, alert.ErrQueryGroups
	}
	settings, err := normalizeDDoSAssessment(binding.ViewID, *input)
	if err != nil {
		return empty, nil, err
	}
	started, _, err := alert.EvaluateDDoSEpisode(ctx, binding, alert.QueryGroupState{}, proof.Evidence.Previous, proof.Evidence.Current,
		alert.QueryGroupBudget{MemoryBytes: memory / 4, WorkUnits: memory / 4})
	if err != nil || started == nil || started.SignalID != proof.Evidence.EpisodeID {
		return empty, nil, alert.ErrQueryGroups
	}
	capture, err := decodeStoredFlowScope(ctx, proof.Scope, memory/2)
	if err != nil {
		return empty, nil, err
	}
	if !matchDDoSEvidenceClocks(capture.Inputs, settings, clocks.ends()) {
		return empty, nil, alert.ErrQueryGroups
	}
	if err := checkStoredFlowReceiptInputs(ctx, capture, memory/2); err != nil {
		return empty, nil, err
	}
	return proof, capture, ctx.Err()
}
