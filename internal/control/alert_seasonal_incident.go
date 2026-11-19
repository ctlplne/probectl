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
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type seasonalIncidentPublication struct {
	id       string
	incident *incident.Incident
	opened   bool
}

func (s *Server) publishSeasonalAlert(tenant tenancy.ID, window time.Duration, observer incident.Observer) alert.SeasonalPublisher {
	return func(ctx context.Context, rule alert.Rule, firing alert.Alert, evidence alert.SeasonalEvaluationEvidence, flowPublication *alert.SeasonalReadPublication, receipt *alert.EvaluationReceipt) (string, error) {
		if s.pool == nil || !rule.HasSeasonalSource || !rule.Enabled || tenant.String() == "" || rule.TenantID != tenant.String() ||
			firing.TenantID != tenant.String() || firing.RuleID != rule.ID || firing.Metric != rule.Metric {
			return "", alert.ErrSeasonalSource
		}
		if bound, ok := tenancy.FromContext(ctx); ok && bound != tenant {
			return "", tenancy.ErrNoTenant
		}
		budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
		if err := budget.Validate(); err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenant), budget.ExecutionLimit)
		defer cancel()
		ctx, flush := scopedABACDenial(ctx)
		defer flush(s)
		var publication seasonalIncidentPublication
		err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertRules{}).WithSeasonalPublication(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/8,
				func(ctx context.Context, sc tenancy.Scope, source *alert.SeasonalSource) error {
					if err := s.authorizeSeasonalPublication(ctx, sc, source); err != nil {
						return err
					}
					if err := authorizeSeasonalCitedCapture(ctx, sc, source, flowPublication, evidence); err != nil {
						return err
					}
					var err error
					publication, err = s.storeSeasonalIncident(ctx, sc, source, rule, firing, evidence, window, receipt)
					return err
				})
		})
		if err != nil {
			return "", err
		}
		if publication.incident != nil && observer != nil {
			observer(ctx, publication.incident, publication.opened)
		}
		return publication.id, nil
	}
}

func (s *Server) authorizeSeasonalPublication(ctx context.Context, sc tenancy.Scope, source *alert.SeasonalSource) error {
	ceiling, err := source.CredentialCeiling(sc.Tenant.String())
	if err != nil {
		return err
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, ceiling.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, ceiling)
	if err != nil {
		return err
	}
	if source.Config.Flow != nil {
		return s.authorizeSeasonalFlowRevisionInScope(ctx, sc, principal, *source.Config.Flow)
	}
	if err := s.authorize(ctx, principal, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
		return err
	}
	if source.Config.TestID != "" {
		_, err = s.seasonalTestInScope(ctx, sc, principal, source.Config.TestID, source.TestRevision)
	}
	return err
}

func (s *Server) storeSeasonalIncident(ctx context.Context, sc tenancy.Scope, source *alert.SeasonalSource, rule alert.Rule, firing alert.Alert, evidence alert.SeasonalEvaluationEvidence, window time.Duration, receipt *alert.EvaluationReceipt) (seasonalIncidentPublication, error) {
	var none seasonalIncidentPublication
	if source.TestRevision != nil && (firing.Labels["test_id"] != source.Config.TestID || !evidence.ObservedAt.After(*source.TestRevision)) {
		return none, alert.ErrSeasonalSource
	}
	if source.Config.Flow != nil && !seasonalFlowReceiptMatches(rule, evidence, receipt) {
		return none, alert.ErrSeasonalSource
	}
	if source.Config.Cadence != evidence.Calendar.Cadence || source.Config.Direction != evidence.Direction {
		return none, alert.ErrSeasonalSource
	}
	signal, key, err := seasonalIncidentSignal(rule, firing, evidence, source.Config.Timezone)
	if err != nil {
		return none, err
	}
	if source.Config.Flow != nil {
		signal.Attributes["probectl.alert.seasonal.receipt_fingerprint"] = receipt.Fingerprint
	}
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return none, err
	}
	var previousID *string
	err = sc.Q.QueryRow(ctx, `SELECT i.id::text FROM audit_events AS a
 LEFT JOIN incidents AS i ON i.tenant_id=a.tenant_id AND i.id=(a.data->>'incident_id')::uuid
 WHERE a.tenant_id=$1 AND a.action='alert.seasonal.published' AND a.target=$2 LIMIT 1`, sc.Tenant.String(), key).Scan(&previousID)
	if !errors.Is(err, pgx.ErrNoRows) {
		if err != nil {
			return none, err
		}
		if previousID == nil || *previousID == "" {
			return none, alert.ErrSeasonalSource
		}
		return seasonalIncidentPublication{id: *previousID}, nil
	}
	var opened bool
	correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, window, s.log,
		incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
	result, err := correlator.Ingest(ctx, signal)
	if err != nil {
		return none, err
	}
	if result == nil || result.ID == "" || result.TenantID != sc.Tenant.String() {
		return none, alert.ErrSeasonalSource
	}
	if source.Config.Flow != nil {
		if err := appendSeasonalFlowIncidentReceipt(ctx, sc, *receipt, result.ID); err != nil {
			return none, err
		}
	}
	err = audit.TenantRecord(ctx, sc, source.OwnerUserID, "alert.seasonal.published", key, map[string]any{"incident_id": result.ID, "rule_id": rule.ID})
	return seasonalIncidentPublication{id: result.ID, incident: result, opened: opened}, err
}

func seasonalFlowReceiptMatches(rule alert.Rule, evidence alert.SeasonalEvaluationEvidence, receipt *alert.EvaluationReceipt) bool {
	if receipt == nil || receipt.RuleID != rule.ID || receipt.Fingerprint == "" ||
		receipt.RuleRevision != rule.UpdatedAt.UTC().Format(time.RFC3339Nano) || receipt.ObservedValue != nil {
		return false
	}
	current := receipt.Expectation.Seasonal
	return current != nil && current.Exact != nil && evidence.Exact != nil && *current.Exact == *evidence.Exact &&
		len(current.FlowScope) > 0 && current.Subject == evidence.Subject &&
		current.ObservedAt.Equal(evidence.ObservedAt)
}

func appendSeasonalFlowIncidentReceipt(ctx context.Context, sc tenancy.Scope, receipt alert.EvaluationReceipt, incidentID string) error {
	evidence := *receipt.Expectation.Seasonal
	evidence.IncidentID = incidentID
	receipt.Expectation.Seasonal = &evidence
	return (store.AlertEvaluations{}).Append(ctx, sc, receipt)
}

func seasonalIncidentSignal(rule alert.Rule, firing alert.Alert, evidence alert.SeasonalEvaluationEvidence, timezone string) (incident.Signal, string, error) {
	if (firing.State != alert.StateFiring && firing.State != alert.StateResolved) || evidence.ObservedAt.IsZero() || evidence.IncidentID != "" ||
		evidence.Calendar.Timezone != timezone || evidence.Subject == "" || len(evidence.Citations) < 2 {
		return incident.Signal{}, "", alert.ErrSeasonalSource
	}
	body, err := seasonalIncidentEvidenceBody(rule, evidence)
	if err != nil || len(body) > alert.SeasonalEvidenceBytes {
		return incident.Signal{}, "", alert.ErrSeasonalSource
	}
	identity, err := json.Marshal([6]string{rule.TenantID, rule.ID, rule.UpdatedAt.UTC().Format(time.RFC3339Nano), evidence.Subject, evidence.ObservedAt.UTC().Format(time.RFC3339Nano), string(firing.State)})
	if err != nil {
		return incident.Signal{}, "", err
	}
	digest := crypto.Hash(identity)
	if len(digest) != 32 {
		return incident.Signal{}, "", alert.ErrSeasonalSource
	}
	key := hex.EncodeToString(digest)
	signal := signalFromAlert(firing)
	if rule.Metric == alert.SeasonalFlowMetric {
		signal.Plane = "flow"
		delete(signal.Attributes, "value")
	}

	if signal.Target == "" {
		signal.Target = "seasonal:" + rule.ID + ":" + evidence.Subject
	}
	signal.OccurredAt = evidence.ObservedAt
	signal.Attributes["probectl.alert.seasonal.evidence"] = string(body)
	signal.Attributes["probectl.alert.seasonal.observation_id"] = key
	return signal, key, nil
}

func authorizeSeasonalCitedCapture(ctx context.Context, sc tenancy.Scope, source *alert.SeasonalSource, proof *alert.SeasonalReadPublication, evidence alert.SeasonalEvaluationEvidence) error {
	if source.Config.Flow == nil {
		if proof != nil || evidence.Exact != nil {
			return alert.ErrSeasonalSource
		}
		return nil
	}
	if proof == nil || proof.Revalidate == nil || evidence.Exact == nil {
		return alert.ErrSeasonalSource
	}
	return proof.Revalidate(ctx, sc)
}

func seasonalIncidentEvidenceBody(rule alert.Rule, evidence alert.SeasonalEvaluationEvidence) ([]byte, error) {
	if rule.Metric != alert.SeasonalFlowMetric {
		return json.Marshal(evidence)
	}
	// Use an evidentiary citation on the incident itself. Exact flow quantities
	// stay in the authorized evaluation receipt, whose reader checks this view.
	return json.Marshal(struct {
		Subject         string                  `json:"subject"`
		ObservedAt      time.Time               `json:"observed_at"`
		Timezone        string                  `json:"timezone"`
		Hour            int                     `json:"hour"`
		Weekday         time.Weekday            `json:"weekday"`
		TrainingDates   []string                `json:"training_days"`
		ReceiptRuleID   string                  `json:"receipt_rule_id"`
		Cadence         anomaly.SeasonalCadence `json:"cadence,omitempty"`
		Minute          *int                    `json:"minute,omitempty"`
		TrainingPeriods int                     `json:"training_periods,omitempty"`
		Provisional     bool                    `json:"provisional,omitempty"`
	}{evidence.Subject, evidence.ObservedAt, evidence.Calendar.Timezone, evidence.Calendar.Hour, evidence.Calendar.Weekday,
		evidence.Calendar.TrainingDays, rule.ID, evidence.Calendar.Cadence, evidence.Calendar.Minute, evidence.Calendar.TrainingPeriods, evidence.Calendar.Provisional})
}
