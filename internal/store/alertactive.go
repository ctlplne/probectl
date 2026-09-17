// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AlertActiveState is the tenant's published active-alert set plus the
// evaluator heartbeat (DPR-067). The evaluator leader replaces it after every
// pass; every control replica serves it. Operator state (silence/ack) is not
// stored here — alert_ops stays the single source of truth for it.
type AlertActiveState struct{}

// Replace atomically swaps the tenant's active set for items and records the
// evaluator heartbeat. Call it inside InTenant (one transaction).
func (AlertActiveState) Replace(ctx context.Context, s tenancy.Scope, items []alert.ActiveAlert, evaluatedAt time.Time, interval time.Duration) error {
	if _, err := s.Q.Exec(ctx, `DELETE FROM alert_active_state`); err != nil {
		return fmt.Errorf("alert active state: clear: %w", err)
	}
	for _, a := range items {
		labels, err := json.Marshal(a.Labels)
		if err != nil {
			return fmt.Errorf("alert active state: labels: %w", err)
		}
		if _, err := s.Q.Exec(ctx, `
			INSERT INTO alert_active_state
			  (tenant_id, fingerprint, evaluation_fingerprint, rule_id, rule_name, severity, metric,
			   labels, value, reason, since, last_seen_at, updated_at)
			VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())`,
			a.Fingerprint, a.EvaluationFingerprint, a.RuleID, a.RuleName, string(a.Severity), a.Metric,
			labels, a.Value, a.Reason, a.Since, a.LastSeenAt); err != nil {
			return fmt.Errorf("alert active state: insert: %w", err)
		}
	}
	seconds := int(interval / time.Second)
	if seconds <= 0 {
		seconds = 30
	}
	if _, err := s.Q.Exec(ctx, `
		INSERT INTO alert_evaluator_status (tenant_id, evaluated_at, interval_seconds, updated_at)
		VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, now())
		ON CONFLICT (tenant_id) DO UPDATE SET
		  evaluated_at = EXCLUDED.evaluated_at, interval_seconds = EXCLUDED.interval_seconds, updated_at = now()`,
		evaluatedAt, seconds); err != nil {
		return fmt.Errorf("alert active state: heartbeat: %w", err)
	}
	return nil
}

// List returns the tenant's published active set (no operator overlay).
func (AlertActiveState) List(ctx context.Context, s tenancy.Scope) ([]alert.ActiveAlert, error) {
	rows, err := s.Q.Query(ctx, `
		SELECT fingerprint, evaluation_fingerprint, rule_id, rule_name, severity, metric,
		       labels, value, reason, since, last_seen_at
		  FROM alert_active_state
		 ORDER BY since DESC, fingerprint`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alert.ActiveAlert
	for rows.Next() {
		var (
			a        alert.ActiveAlert
			severity string
			labels   []byte
		)
		if err := rows.Scan(&a.Fingerprint, &a.EvaluationFingerprint, &a.RuleID, &a.RuleName, &severity, &a.Metric,
			&labels, &a.Value, &a.Reason, &a.Since, &a.LastSeenAt); err != nil {
			return nil, err
		}
		a.Severity = alert.Severity(severity)
		if len(labels) > 0 {
			_ = json.Unmarshal(labels, &a.Labels)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Status returns the evaluator heartbeat for the tenant; ok=false when the
// evaluator never published for it.
func (AlertActiveState) Status(ctx context.Context, s tenancy.Scope) (evaluatedAt time.Time, interval time.Duration, ok bool, err error) {
	var seconds int
	err = s.Q.QueryRow(ctx, `SELECT evaluated_at, interval_seconds FROM alert_evaluator_status`).Scan(&evaluatedAt, &seconds)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, 0, false, nil
		}
		return time.Time{}, 0, false, err
	}
	return evaluatedAt, time.Duration(seconds) * time.Second, true, nil
}
