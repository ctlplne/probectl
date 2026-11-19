// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type storedFieldReceipt struct {
	Version  int                           `json:"version"`
	Scope    json.RawMessage               `json:"scope"`
	Evidence alert.FieldEvaluationEvidence `json:"evidence"`
}

func (s *Server) readAlertFieldRule(ctx context.Context, rule alert.Rule, source store.AlertQuerySource, actor *auth.Principal, budget flowstore.ExplorerBudget, deps AlertTagDependencies) (alert.RuleMetricRead, error) {
	var empty alert.RuleMetricRead
	if source.Source.Condition.Mode != alert.FieldChangeCondition || source.Source.Condition.Field == nil || actor == nil || actor.TenantID != rule.TenantID {
		return empty, alert.ErrQueryGroups
	}
	settings := fieldComparisonSettings(source.Source.ViewID, *source.Source.Condition.Field)
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	comparison, capture, err := s.captureFlowFieldComparison(ctx, actor, settings, time.Now(), budget)
	if err != nil {
		return empty, err
	}
	defer capture.Close()
	started, next, err := alert.EvaluateFieldEpisodes(ctx, source.Source.Binding(rule.TenantID, rule.ID), source.State, comparison,
		alert.QueryGroupBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.MemoryBytes / 8})
	if err != nil {
		return empty, err
	}
	var rawScope []byte
	if len(started) > 0 {
		rawScope, err = encodeSeasonalFlowScope(ctx, capture, budget.MemoryBytes/8)
		if err != nil {
			return empty, err
		}
	}
	var committed []seasonalIncidentPublication
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertRules{}).CommitQueryState(ctx, sc, rule.ID, rule.UpdatedAt, source, next, budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope) error {
				if err := s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture); err != nil {
					return err
				}
				if len(started) > 0 {
					committed, err = s.publishAlertFieldEpisodes(ctx, sc, actor.UserID, rule, comparison, started, rawScope, deps.IncidentWindow, budget.MemoryBytes/8)
				}
				return err
			})
	})
	if err != nil {
		return empty, err
	}
	if deps.IncidentObserver != nil {
		for _, current := range committed {
			deps.IncidentObserver(ctx, current.incident, current.opened)
		}
	}
	samples := make([]alert.Sample, 0, len(next.Keys))
	for _, key := range next.Keys {
		samples = append(samples, alert.Sample{Labels: map[string]string{"query_view_id": comparison.ViewID, "query_group": key}, Value: 1, Reason: "saved flow field comparison met"})
	}
	return alert.RuleMetricRead{Samples: samples, FieldIncidents: true,
		QuerySelection: &alert.QuerySelection{TenantID: rule.TenantID, RuleID: rule.ID, Binding: next.Binding, At: next.At, Complete: true}}, nil
}

func (s *Server) publishAlertFieldEpisodes(ctx context.Context, sc tenancy.Scope, owner string, rule alert.Rule, comparison flow.FieldComparison, started []alert.FieldEpisode, scope []byte, window time.Duration, memory int64) ([]seasonalIncidentPublication, error) {
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return nil, err
	}
	identity, err := json.Marshal([4]string{sc.Tenant.String(), rule.ID, rule.UpdatedAt.UTC().Format(time.RFC3339Nano), comparison.After.To.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	digest := crypto.Hash(identity)
	if len(digest) != 32 {
		return nil, alert.ErrQueryGroups
	}
	fingerprint := hex.EncodeToString(digest)
	proof := storedFieldReceipt{Version: 1, Scope: scope, Evidence: alert.FieldEvaluationEvidence{Comparison: comparison}}
	proof.Evidence.Comparison.Changes = make([]flow.FieldChange, 0, len(started))
	proof.Evidence.Signals = make([]alert.FieldSignalLink, 0, len(started))
	committed := make([]seasonalIncidentPublication, 0, len(started))
	var opened bool
	correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, window, s.log,
		incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
	for _, episode := range started {
		opened = false
		result, err := correlator.Ingest(ctx, fieldIncidentSignal(rule, comparison, episode, fingerprint))
		if err != nil {
			return nil, err
		}
		if result == nil || result.ID == "" || result.TenantID != sc.Tenant.String() {
			return nil, alert.ErrQueryGroups
		}
		proof.Evidence.Comparison.Changes = append(proof.Evidence.Comparison.Changes, episode.Change)
		proof.Evidence.Signals = append(proof.Evidence.Signals, alert.FieldSignalLink{ChangeKey: episode.Change.Key, EpisodeID: episode.SignalID, IncidentID: result.ID})
		committed = append(committed, seasonalIncidentPublication{id: result.ID, incident: result, opened: opened})
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	receipt := alert.EvaluationReceipt{ContractVersion: alert.EvaluationReceiptVersion, Fingerprint: fingerprint, RuleID: rule.ID,
		RuleRevision: rule.UpdatedAt.UTC().Format(time.RFC3339Nano), State: alert.EvaluationFiring, ObservedAt: comparison.After.To,
		Expectation: alert.EvaluationExpectation{Kind: rule.Type}, BreachCount: 1, RequiredBreaches: 1, Reason: "Saved flow field changes"}
	if err := (store.AlertEvaluations{}).AppendFieldReceipt(ctx, sc, rule.UpdatedAt, receipt, body, memory); err != nil {
		return nil, err
	}
	return committed, audit.TenantRecord(ctx, sc, owner, "alert.field.published", fingerprint, map[string]any{"rule_id": rule.ID, "signals": len(started)})
}

func fieldIncidentSignal(rule alert.Rule, comparison flow.FieldComparison, episode alert.FieldEpisode, receipt string) incident.Signal {
	return incident.Signal{TenantID: rule.TenantID, Plane: "flow", Kind: "alert.field_change", Severity: incident.Severity(rule.Severity),
		Title: rule.Name, Summary: "Saved flow field comparison met", Target: "query:" + rule.ID + ":" + episode.GroupKey, OccurredAt: comparison.After.To,
		Attributes: map[string]string{"rule_id": rule.ID, "query_view_id": comparison.ViewID, "query_group": episode.GroupKey,
			"probectl.alert.field.episode_id": episode.SignalID, "probectl.alert.field.receipt_fingerprint": receipt}}
}
