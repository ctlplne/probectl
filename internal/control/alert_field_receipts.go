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
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) handleGetAlertFieldReceipt(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	result, err := s.readAlertFieldReceipt(r.Context(), actor, r.PathValue("id"), r.URL.Query().Get("fingerprint"), s.pathAlertRequestCredential(r, actor), nil)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func (s *Server) readAlertFieldReceipt(ctx context.Context, actor *auth.Principal, ruleID, fingerprint string, credential func(context.Context) error, retain pathHealthPublication) (alert.FieldEvaluationEvidence, error) {
	var out alert.FieldEvaluationEvidence
	if !reportRequirementUUID(ruleID) || !alert.ValidFieldDigest(fingerprint) {
		return out, apierror.Validation("a rule ID and exact field receipt fingerprint are required")
	}
	if credential == nil || actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return out, apierror.Forbidden("current field receipt credential is unavailable")
	}
	if s.fairnessGate == nil {
		return out, apierror.Unavailable("field receipt admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return out, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	load := func(ctx context.Context) (storedFieldReceipt, []byte, error) {
		if err := credential(ctx); err != nil {
			return storedFieldReceipt{}, nil, err
		}
		proof, raw, err := s.loadAlertFieldReceipt(ctx, actor, ruleID, fingerprint)
		if err != nil {
			return storedFieldReceipt{}, nil, err
		}
		return proof, raw, credential(ctx)
	}
	proof, original, err := load(ctx)
	if err != nil {
		return out, err
	}
	if retain != nil {
		check := func(ctx context.Context) error {
			_, current, err := load(ctx)
			if err != nil {
				return err
			}
			if !bytes.Equal(original, current) {
				return apierror.Conflict("field receipt changed during publication")
			}
			return nil
		}
		if err := retain(ctx, check, release); err != nil {
			return out, err
		}
		retained = true
	}
	return proof.Evidence, ctx.Err()
}

func (s *Server) loadAlertFieldReceipt(ctx context.Context, actor *auth.Principal, ruleID, fingerprint string) (storedFieldReceipt, []byte, error) {
	var proof storedFieldReceipt
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return proof, nil, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return proof, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var raw []byte
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rules := store.AlertRules{}
		rule, err := rules.Get(ctx, sc, ruleID)
		if err != nil {
			return err
		}
		return rules.WithQueryPublication(ctx, sc, ruleID, rule.UpdatedAt, budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope, source alert.QuerySource) error {
				if source.Condition.Mode != alert.FieldChangeCondition || source.Condition.Field == nil {
					return apierror.NotFound("field receipt not found")
				}
				record, err := (store.AlertEvaluations{}).GetFieldReceipt(ctx, sc, ruleID, fingerprint, rule.UpdatedAt, budget.MemoryBytes/8)
				if err != nil {
					return err
				}
				parsed, capture, err := decodeFieldReceipt(ctx, record, source, budget.MemoryBytes/8)
				if err != nil {
					return err
				}
				if err := s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture); err != nil {
					return err
				}
				proof, raw = parsed, record.Body
				return nil
			})
	})
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrAlertQueryChanged) {
		return storedFieldReceipt{}, nil, apierror.NotFound("field receipt not found")
	}
	if err != nil {
		return storedFieldReceipt{}, nil, err
	}
	return proof, raw, ctx.Err()
}

func decodeFieldReceipt(ctx context.Context, record store.AlertFieldReceipt, source alert.QuerySource, memory int64) (storedFieldReceipt, *reportFlowCapture, error) {
	var proof, empty storedFieldReceipt
	field := source.Condition.Field
	if field == nil || record.ObservedAt.IsZero() || int64(len(record.Body)) > memory {
		return empty, nil, alert.ErrQueryGroups
	}
	decoder := json.NewDecoder(bytes.NewReader(record.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil || decoder.Decode(new(any)) != io.EOF || proof.Version != 1 {
		return empty, nil, alert.ErrQueryGroups
	}
	comparison := proof.Evidence.Comparison
	windows, err := anomaly.FlowFieldCompletedWindows(record.ObservedAt, anomaly.FlowFieldComparisonCadence(field.Cadence), field.PeriodSeconds)
	if err != nil || !windows.After.End.Equal(record.ObservedAt) || comparison.ViewID != source.ViewID || comparison.Version != source.ViewVersion ||
		comparison.Mode != field.Mode || comparison.Measure != field.Measure || comparison.Cadence != field.Cadence || comparison.TopKeys != field.TopKeys ||
		!comparison.Before.From.Equal(windows.Before.Start) || !comparison.Before.To.Equal(windows.Before.End) ||
		!comparison.After.From.Equal(windows.After.Start) || !comparison.After.To.Equal(windows.After.End) ||
		len(comparison.Changes) == 0 || len(comparison.Changes) > 2*field.TopKeys || len(comparison.Changes) != len(proof.Evidence.Signals) {
		return empty, nil, alert.ErrQueryGroups
	}
	for i, signal := range proof.Evidence.Signals {
		if signal.ChangeKey != comparison.Changes[i].Key || !alert.ValidFieldDigest(signal.ChangeKey) ||
			!alert.ValidFieldDigest(signal.EpisodeID) || !reportRequirementUUID(signal.IncidentID) {
			return empty, nil, alert.ErrQueryGroups
		}
	}
	capture, err := decodeStoredFlowScope(ctx, proof.Scope, memory/2)
	if err != nil {
		return empty, nil, err
	}
	if len(capture.Inputs) != 2 || capture.Inputs[0].TagRevision != capture.Inputs[1].TagRevision ||
		!capture.Inputs[0].TagAsOf.Equal(capture.Inputs[1].TagAsOf) {
		return empty, nil, alert.ErrQueryGroups
	}
	for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		input := capture.Inputs[i]
		if input.ID != source.ViewID || input.Version != source.ViewVersion || input.Period != "current" ||
			!input.From.Equal(window.Start) || !input.To.Equal(window.End) {
			return empty, nil, alert.ErrQueryGroups
		}
		if err := validateReportSourceInputs(ctx, []reportFlowInput{input}, slices.Contains(capture.Permissions, permTagsRead), memory/2); err != nil {
			return empty, nil, err
		}
	}
	return proof, capture, ctx.Err()
}
