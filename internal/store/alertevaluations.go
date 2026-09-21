// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	MaxAlertEvaluationReceiptsPerSeries = 64
	MaxAlertEvaluationReceiptsPerRule   = 256
	MaxAlertEvaluationReceiptRead       = 100
	AlertEvaluationReceiptRetention     = 7 * 24 * time.Hour
)

// AlertEvaluations persists a deliberately bounded alert-transition ledger.
// Forced RLS is the outer boundary, every statement also binds tenant_id, and
// Append enforces both age and row-count retention before it returns.
type AlertEvaluations struct{}

func (AlertEvaluations) Append(ctx context.Context, s tenancy.Scope, receipt alert.EvaluationReceipt) error {
	labels := receipt.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	encodedLabels, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	expiresAt := receipt.ObservedAt.Add(AlertEvaluationReceiptRetention)
	_, err = s.Q.Exec(ctx, `
		INSERT INTO alert_evaluation_receipts
		       (tenant_id, rule_id, fingerprint, contract_version, rule_revision,
		        evaluation_state, observed_at, observed_value, expectation_kind,
		        comparison, threshold, expected_mean, expected_stddev,
		        expected_lower, expected_upper, breach_count, required_breaches,
		        warmup_samples, warmup_required, reason, labels, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		        $14, $15, $16, $17, $18, $19, $20, $21::jsonb, $22)
		ON CONFLICT (tenant_id, rule_id, fingerprint, observed_at, evaluation_state)
		DO UPDATE SET
		  observed_value = EXCLUDED.observed_value,
		  expectation_kind = EXCLUDED.expectation_kind,
		  comparison = EXCLUDED.comparison,
		  threshold = EXCLUDED.threshold,
		  expected_mean = EXCLUDED.expected_mean,
		  expected_stddev = EXCLUDED.expected_stddev,
		  expected_lower = EXCLUDED.expected_lower,
		  expected_upper = EXCLUDED.expected_upper,
		  breach_count = EXCLUDED.breach_count,
		  required_breaches = EXCLUDED.required_breaches,
		  warmup_samples = EXCLUDED.warmup_samples,
		  warmup_required = EXCLUDED.warmup_required,
		  reason = EXCLUDED.reason,
		  labels = EXCLUDED.labels,
		  expires_at = EXCLUDED.expires_at`,
		s.Tenant.String(), receipt.RuleID, receipt.Fingerprint, receipt.ContractVersion,
		receipt.RuleRevision, string(receipt.State), receipt.ObservedAt, receipt.ObservedValue,
		string(receipt.Expectation.Kind), string(receipt.Expectation.Comparison),
		receipt.Expectation.Threshold, receipt.Expectation.Mean, receipt.Expectation.StdDev,
		receipt.Expectation.Lower, receipt.Expectation.Upper, receipt.BreachCount,
		receipt.RequiredBreaches, receipt.WarmupSamples, receipt.WarmupRequired,
		receipt.Reason, encodedLabels, expiresAt)
	if err != nil {
		return mapWriteErr("alert evaluation receipt", err)
	}
	if _, err = s.Q.Exec(ctx, `
		DELETE FROM alert_evaluation_receipts
		 WHERE tenant_id = $1 AND rule_id = $2
		   AND expires_at <= clock_timestamp()`,
		s.Tenant.String(), receipt.RuleID); err != nil {
		return err
	}
	if _, err = s.Q.Exec(ctx, `
		DELETE FROM alert_evaluation_receipts
		 WHERE tenant_id = $1 AND rule_id = $2 AND fingerprint = $3
		   AND (observed_at, evaluation_state) IN (
		     SELECT observed_at, evaluation_state
		       FROM alert_evaluation_receipts
		      WHERE tenant_id = $1 AND rule_id = $2 AND fingerprint = $3
		      ORDER BY observed_at DESC, evaluation_state DESC
		      OFFSET $4
		   )`,
		s.Tenant.String(), receipt.RuleID, receipt.Fingerprint,
		MaxAlertEvaluationReceiptsPerSeries); err != nil {
		return err
	}
	_, err = s.Q.Exec(ctx, `
		DELETE FROM alert_evaluation_receipts
		 WHERE tenant_id = $1 AND rule_id = $2
		   AND (fingerprint, observed_at, evaluation_state) IN (
		     SELECT fingerprint, observed_at, evaluation_state
		       FROM alert_evaluation_receipts
		      WHERE tenant_id = $1 AND rule_id = $2
		      ORDER BY observed_at DESC, fingerprint, evaluation_state DESC
		      OFFSET $3
		   )`,
		s.Tenant.String(), receipt.RuleID, MaxAlertEvaluationReceiptsPerRule)
	return err
}

// List returns the newest bounded receipt window in chronological order. A
// requested series also receives rule-level no-data transitions, so a missing
// source is visible from an active alert's details.
func (AlertEvaluations) List(ctx context.Context, s tenancy.Scope, ruleID, fingerprint string, limit int) ([]alert.EvaluationReceipt, bool, error) {
	if limit < 1 {
		limit = MaxAlertEvaluationReceiptsPerSeries
	}
	if limit > MaxAlertEvaluationReceiptRead {
		limit = MaxAlertEvaluationReceiptRead
	}
	rows, err := s.Q.Query(ctx, `
		SELECT contract_version, fingerprint, rule_id::text, rule_revision,
		       evaluation_state, observed_at, observed_value, expectation_kind,
		       comparison, threshold, expected_mean, expected_stddev,
		       expected_lower, expected_upper, breach_count, required_breaches,
		       warmup_samples, warmup_required, reason, labels
		  FROM (
		    SELECT contract_version, fingerprint, rule_id, rule_revision,
		           evaluation_state, observed_at, observed_value, expectation_kind,
		           comparison, threshold, expected_mean, expected_stddev,
		           expected_lower, expected_upper, breach_count, required_breaches,
		           warmup_samples, warmup_required, reason, labels
		      FROM alert_evaluation_receipts
		     WHERE tenant_id = $1 AND rule_id = $2
		       AND expires_at > clock_timestamp()
		       AND ($3 = '' OR fingerprint = $3 OR evaluation_state = 'no_data')
		     ORDER BY observed_at DESC, fingerprint, evaluation_state DESC
		     LIMIT $4
		  ) AS recent
		 ORDER BY observed_at, fingerprint, evaluation_state`,
		s.Tenant.String(), ruleID, fingerprint, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]alert.EvaluationReceipt, 0, limit)
	truncated := false
	for rows.Next() {
		if len(out) == limit {
			truncated = true
			break
		}
		var (
			receipt                     alert.EvaluationReceipt
			state, expectation, compare string
			labels                      []byte
		)
		if err := rows.Scan(
			&receipt.ContractVersion, &receipt.Fingerprint, &receipt.RuleID,
			&receipt.RuleRevision, &state, &receipt.ObservedAt,
			&receipt.ObservedValue, &expectation, &compare,
			&receipt.Expectation.Threshold, &receipt.Expectation.Mean,
			&receipt.Expectation.StdDev, &receipt.Expectation.Lower,
			&receipt.Expectation.Upper, &receipt.BreachCount,
			&receipt.RequiredBreaches, &receipt.WarmupSamples,
			&receipt.WarmupRequired, &receipt.Reason, &labels,
		); err != nil {
			return nil, false, err
		}
		receipt.State = alert.EvaluationState(state)
		receipt.Expectation.Kind = alert.RuleType(expectation)
		receipt.Expectation.Comparison = alert.Comparison(compare)
		if len(labels) > 0 {
			if err := json.Unmarshal(labels, &receipt.Labels); err != nil {
				return nil, false, err
			}
		}
		out = append(out, receipt)
	}
	return out, truncated, rows.Err()
}

func (AlertEvaluations) DeleteRule(ctx context.Context, s tenancy.Scope, ruleID string) error {
	_, err := s.Q.Exec(ctx, `
		DELETE FROM alert_evaluation_receipts
		 WHERE tenant_id = $1 AND rule_id = $2`,
		s.Tenant.String(), ruleID)
	return err
}
