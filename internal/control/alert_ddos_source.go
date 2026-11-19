// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ddosEpisodeClocks struct {
	Previous, Current anomaly.FlowFieldComparisonClocks
}

func ddosClocks(at time.Time, seconds int) (ddosEpisodeClocks, error) {
	current, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldPreviousWeek, seconds)
	if err != nil {
		return ddosEpisodeClocks{}, err
	}
	previous, err := anomaly.FlowFieldCompletedWindows(current.After.Start, anomaly.FlowFieldPreviousWeek, seconds)
	return ddosEpisodeClocks{Previous: previous, Current: current}, err
}

func (clocks ddosEpisodeClocks) ends() []time.Time {
	return []time.Time{clocks.Previous.Before.End, clocks.Current.Before.End, clocks.Previous.After.End, clocks.Current.After.End}
}

type storedDDoSReceipt struct {
	Version  int                          `json:"version"`
	Scope    json.RawMessage              `json:"scope"`
	Evidence alert.DDoSEvaluationEvidence `json:"evidence"`
}

func (s *Server) readAlertDDoSRule(ctx context.Context, rule alert.Rule, source store.AlertQuerySource, actor *auth.Principal,
	budget flowstore.ExplorerBudget, deps AlertTagDependencies) (alert.RuleMetricRead, error) {
	var empty alert.RuleMetricRead
	input := source.Source.Condition.DDoS
	if source.Source.Condition.Mode != alert.DDoSCondition || input == nil || actor == nil || actor.TenantID != rule.TenantID {
		return empty, alert.ErrQueryGroups
	}
	settings, err := normalizeDDoSAssessment(source.Source.ViewID, *input)
	if err != nil {
		return empty, err
	}
	clocks, err := ddosClocks(time.Now(), input.PeriodSeconds)
	if err != nil {
		return empty, err
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	capture, err := s.captureDDoSWindows(ctx, actor, settings, clocks.ends(), budget.MemoryBytes/4)
	if err != nil {
		return empty, err
	}
	defer capture.Close()
	previous, err := assessCapturedDDoS(ctx, capture, settings, clocks.Previous, 0, 2, budget.MemoryBytes/8)
	if err != nil {
		return empty, mapDDoSCoverage(err)
	}
	current, err := assessCapturedDDoS(ctx, capture, settings, clocks.Current, 1, 3, budget.MemoryBytes/8)
	if err != nil {
		return empty, mapDDoSCoverage(err)
	}
	started, next, err := alert.EvaluateDDoSEpisode(ctx, source.Source.Binding(rule.TenantID, rule.ID), source.State, previous, current,
		alert.QueryGroupBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.MemoryBytes / 8})
	if err != nil {
		return empty, err
	}
	proof := storedDDoSReceipt{Version: 1, Evidence: alert.DDoSEvaluationEvidence{Previous: previous, Current: current}}
	if started != nil {
		proof.Evidence.EpisodeID = started.SignalID
		proof.Scope, err = encodeSeasonalFlowScope(ctx, capture, budget.MemoryBytes/8)
		if err != nil {
			return empty, err
		}
	}
	committed, err := s.commitAlertDDoSRead(ctx, rule, source, actor, capture, next, proof, started, deps.IncidentWindow, budget.MemoryBytes/8)
	if err != nil {
		return empty, err
	}
	if committed.incident != nil && deps.IncidentObserver != nil {
		deps.IncidentObserver(ctx, committed.incident, committed.opened)
	}
	samples := make([]alert.Sample, 0, len(next.Keys))
	for _, key := range next.Keys {
		samples = append(samples, alert.Sample{Labels: map[string]string{"query_view_id": current.ViewID, "query_group": key}, Value: 1,
			Reason: "sustained flow traffic pressure"})
	}
	return alert.RuleMetricRead{Samples: samples, SourceIncidents: true,
		QuerySelection: &alert.QuerySelection{TenantID: rule.TenantID, RuleID: rule.ID, Binding: next.Binding, At: next.At, Complete: true}}, nil
}

func (s *Server) commitAlertDDoSRead(ctx context.Context, rule alert.Rule, source store.AlertQuerySource, actor *auth.Principal, capture *reportFlowCapture,
	next alert.QueryGroupState, proof storedDDoSReceipt, started *alert.DDoSEpisode, window time.Duration, memory int64) (seasonalIncidentPublication, error) {
	var published seasonalIncidentPublication
	err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertRules{}).CommitQueryState(ctx, sc, rule.ID, rule.UpdatedAt, source, next, memory,
			func(ctx context.Context, sc tenancy.Scope) error {
				if err := s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, actor, capture); err != nil {
					return err
				}
				if started == nil {
					return nil
				}
				var err error
				published, err = s.publishAlertDDoSEpisode(ctx, sc, actor.UserID, rule, *started, proof, window, memory)
				return err
			})
	})
	return published, err
}

func (s *Server) publishAlertDDoSEpisode(ctx context.Context, sc tenancy.Scope, owner string, rule alert.Rule, started alert.DDoSEpisode,
	proof storedDDoSReceipt, window time.Duration, memory int64) (seasonalIncidentPublication, error) {
	var published seasonalIncidentPublication
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return published, err
	}
	current := proof.Evidence.Current
	receipt, err := flowEpisodeReceiptFingerprint(sc.Tenant.String(), rule.ID, rule.UpdatedAt, current.After.To)
	if err != nil {
		return seasonalIncidentPublication{}, err
	}
	signal := incident.Signal{TenantID: rule.TenantID, Plane: "flow", Kind: "alert.ddos_assessment", Severity: incident.Severity(rule.Severity),
		Title: rule.Name, Summary: "Sustained flow traffic pressure", Target: "query:" + rule.ID + ":" + started.GroupKey, OccurredAt: current.After.To,
		Attributes: map[string]string{"rule_id": rule.ID, "query_view_id": current.ViewID, "query_group": started.GroupKey,
			"probectl.alert.ddos.episode_id": started.SignalID, "probectl.alert.ddos.receipt_fingerprint": receipt}}
	correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, window, s.log,
		incident.WithObserver(func(_ context.Context, _ *incident.Incident, opened bool) { published.opened = opened }))
	item, err := correlator.Ingest(ctx, signal)
	if err != nil {
		return seasonalIncidentPublication{}, err
	}
	if item == nil || item.ID == "" || item.TenantID != sc.Tenant.String() {
		return seasonalIncidentPublication{}, alert.ErrQueryGroups
	}
	proof.Evidence.IncidentID = item.ID
	body, err := json.Marshal(proof)
	if err != nil {
		return seasonalIncidentPublication{}, err
	}
	evaluation := alert.EvaluationReceipt{ContractVersion: alert.EvaluationReceiptVersion, Fingerprint: receipt, RuleID: rule.ID,
		RuleRevision: rule.UpdatedAt.UTC().Format(time.RFC3339Nano), State: alert.EvaluationFiring, ObservedAt: current.After.To,
		Expectation: alert.EvaluationExpectation{Kind: rule.Type}, BreachCount: 2, RequiredBreaches: 2, Reason: "Sustained flow traffic pressure"}
	if err := (store.AlertEvaluations{}).AppendFlowReceipt(ctx, sc, store.AlertDDoSReceipt, rule.UpdatedAt, evaluation, body, memory); err != nil {
		return seasonalIncidentPublication{}, err
	}
	if err := audit.TenantRecord(ctx, sc, owner, "alert.ddos.published", receipt, map[string]any{"rule_id": rule.ID}); err != nil {
		return seasonalIncidentPublication{}, err
	}
	published.id, published.incident = item.ID, item
	return published, nil
}
