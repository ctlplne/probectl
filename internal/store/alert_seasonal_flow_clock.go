// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SeasonalFlowWindowDue is a bounded metadata read before expensive Explorer
// admission. It supplies neither source read authority nor a publication grant.
func (AlertRules) SeasonalFlowWindowDue(ctx context.Context, sc tenancy.Scope, ruleID string, revision, end time.Time) (bool, error) {
	if err := alertQueryScope(ctx, sc, revision, 1<<20); err != nil || end.IsZero() || ruleID == "" {
		return false, alert.ErrSeasonalSource
	}
	var due bool
	err := sc.Q.QueryRow(ctx, `SELECT (seasonal_last_window_at IS NULL OR seasonal_last_window_at<$4)
 FROM alert_rules WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND enabled AND type='baseline'
 AND seasonal_source->'config'->'flow' IS NOT NULL`, sc.Tenant.String(), ruleID, revision, end).Scan(&due)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAlertSeasonalChanged
	}
	return due, err
}

// FinishSeasonalFlowWindow runs only after a whole admitted source evaluation,
// under its exact tenant/rule/lifecycle/audit publication transaction.
func (AlertRules) FinishSeasonalFlowWindow(ctx context.Context, sc tenancy.Scope, ruleID string, revision, end time.Time) error {
	if err := alertQueryScope(ctx, sc, revision, 1<<20); err != nil || end.IsZero() || ruleID == "" {
		return alert.ErrSeasonalSource
	}
	result, err := sc.Q.Exec(ctx, `UPDATE alert_rules SET seasonal_last_window_at=$4
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND enabled AND type='baseline'
 AND seasonal_source->'config'->'flow' IS NOT NULL AND
 (seasonal_last_window_at IS NULL OR seasonal_last_window_at<$4)`, sc.Tenant.String(), ruleID, revision, end)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrAlertSeasonalChanged
	}
	return nil
}
