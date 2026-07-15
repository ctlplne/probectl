// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"encoding/json"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// AlertMaintenance is the restart-safe repository for operator-created alert
// maintenance windows. Every statement runs through a tenant Scope and the
// table also enforces RLS, so an id from another tenant behaves as absent.
type AlertMaintenance struct{}

// Upsert records a validated window. TenantID is always derived from Scope.
func (AlertMaintenance) Upsert(ctx context.Context, s tenancy.Scope, w alert.MaintenanceWindow) error {
	matchValues := w.Match
	if matchValues == nil {
		matchValues = map[string]string{}
	}
	ruleIDs := w.RuleIDs
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	match, err := json.Marshal(matchValues)
	if err != nil {
		return err
	}
	_, err = s.Q.Exec(ctx,
		`INSERT INTO alert_maintenance_windows
		   (tenant_id, id, name, reason, starts_at, ends_at, recurrence, match,
		    rule_ids, created_by, audit_ref, created_at, updated_at)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3, $4, $5,
		         $6, $7::jsonb, $8, $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO UPDATE SET
		   name = EXCLUDED.name,
		   reason = EXCLUDED.reason,
		   starts_at = EXCLUDED.starts_at,
		   ends_at = EXCLUDED.ends_at,
		   recurrence = EXCLUDED.recurrence,
		   match = EXCLUDED.match,
		   rule_ids = EXCLUDED.rule_ids,
		   audit_ref = EXCLUDED.audit_ref,
		   updated_at = EXCLUDED.updated_at`,
		w.ID, w.Name, w.Reason, w.StartsAt, w.EndsAt, string(w.Recurrence), string(match),
		ruleIDs, w.CreatedBy, w.AuditRef, w.CreatedAt, w.UpdatedAt)
	return mapWriteErr("alert maintenance window", err)
}

// Delete removes one window in the caller's tenant.
func (AlertMaintenance) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM alert_maintenance_windows WHERE id = $1`, id)
	return err
}

// List returns this tenant's durable schedule in evaluator order.
func (AlertMaintenance) List(ctx context.Context, s tenancy.Scope) ([]alert.MaintenanceWindow, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT id, tenant_id::text, name, reason, starts_at, ends_at, recurrence,
		        match, rule_ids, created_by, audit_ref, created_at, updated_at
		   FROM alert_maintenance_windows
		  ORDER BY starts_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []alert.MaintenanceWindow{}
	for rows.Next() {
		var (
			w          alert.MaintenanceWindow
			recurrence string
			match      []byte
		)
		if err := rows.Scan(&w.ID, &w.TenantID, &w.Name, &w.Reason, &w.StartsAt, &w.EndsAt,
			&recurrence, &match, &w.RuleIDs, &w.CreatedBy, &w.AuditRef, &w.CreatedAt,
			&w.UpdatedAt); err != nil {
			return nil, err
		}
		w.Recurrence = alert.MaintenanceRecurrence(recurrence)
		if len(match) > 0 {
			if err := json.Unmarshal(match, &w.Match); err != nil {
				return nil, err
			}
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
