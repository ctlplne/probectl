// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/device"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// DeviceCollectionOutcomes is the forced-RLS Postgres implementation of the
// current per-configured-target readiness receipt store.
type DeviceCollectionOutcomes struct {
	pool *pgxpool.Pool
}

func NewDeviceCollectionOutcomes(pool *pgxpool.Pool) *DeviceCollectionOutcomes {
	if pool == nil {
		return nil
	}
	return &DeviceCollectionOutcomes{pool: pool}
}

func (s *DeviceCollectionOutcomes) UpsertCollectionOutcome(ctx context.Context, tenant string, outcome device.CollectionOutcome) error {
	if s == nil || s.pool == nil {
		return errors.New("device collection outcomes: persistence is not wired")
	}
	if tenant == "" || outcome.TenantID != tenant {
		return errors.New("device collection outcomes: tenant scope mismatch")
	}
	valid, err := device.ValidateCollectionOutcome(outcome)
	if err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `
			INSERT INTO device_collection_outcomes
			       (tenant_id, agent_id, configured_target, protocol,
			        last_attempt_at, last_success_at, state, reason, row_count,
			        next_action, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, clock_timestamp())
			ON CONFLICT (tenant_id, agent_id, configured_target, protocol) DO UPDATE SET
			  last_attempt_at = EXCLUDED.last_attempt_at,
			  last_success_at = CASE
			    WHEN device_collection_outcomes.last_success_at IS NULL THEN EXCLUDED.last_success_at
			    WHEN EXCLUDED.last_success_at IS NULL THEN device_collection_outcomes.last_success_at
			    ELSE greatest(device_collection_outcomes.last_success_at, EXCLUDED.last_success_at)
			  END,
			  state = EXCLUDED.state,
			  reason = EXCLUDED.reason,
			  row_count = EXCLUDED.row_count,
			  next_action = EXCLUDED.next_action,
			  updated_at = clock_timestamp()
			WHERE device_collection_outcomes.last_attempt_at IS NULL
			   OR (EXCLUDED.last_attempt_at IS NOT NULL
			       AND EXCLUDED.last_attempt_at >= device_collection_outcomes.last_attempt_at)`,
			sc.Tenant.String(), valid.AgentID, valid.ConfiguredTarget, valid.Protocol,
			valid.LastAttemptAt, valid.LastSuccessAt, valid.State, valid.Reason,
			valid.RowCount, valid.NextAction); err != nil {
			return mapWriteErr("device collection outcome", err)
		}
		if _, err := sc.Q.Exec(ctx, `
			DELETE FROM device_collection_outcomes
			 WHERE tenant_id = $1
			   AND coalesce(last_attempt_at, updated_at)
			       < clock_timestamp() - ($2 * interval '1 second')`,
			sc.Tenant.String(), int64(device.CollectionOutcomeRetention/time.Second)); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `
			DELETE FROM device_collection_outcomes
			 WHERE tenant_id = $1
			   AND (agent_id, configured_target, protocol) IN (
			     SELECT agent_id, configured_target, protocol
			       FROM device_collection_outcomes
			      WHERE tenant_id = $1
			      ORDER BY coalesce(last_attempt_at, updated_at) DESC,
			               agent_id, configured_target, protocol
			      OFFSET $2
			   )`,
			sc.Tenant.String(), device.MaxCollectionOutcomesPerTenant)
		return err
	})
}

func (s *DeviceCollectionOutcomes) ListCollectionOutcomes(ctx context.Context, tenant string, filter device.CollectionOutcomeFilter) ([]device.CollectionOutcome, bool, error) {
	if s == nil || s.pool == nil {
		return nil, false, errors.New("device collection outcomes: persistence is not wired")
	}
	if tenant == "" {
		return nil, false, errors.New("device collection outcomes: tenant_id is required")
	}
	filter.AgentID = strings.TrimSpace(filter.AgentID)
	filter.Target = strings.TrimSpace(filter.Target)
	filter.State = strings.ToLower(strings.TrimSpace(filter.State))
	if filter.State != "" && !device.ValidCollectionState(filter.State) {
		return nil, false, errors.New("device collection outcomes: invalid state")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > device.MaxCollectionOutcomeRead {
		limit = device.MaxCollectionOutcomeRead
	}
	var out []device.CollectionOutcome
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT agent_id, configured_target, protocol, last_attempt_at,
			       last_success_at, state, reason, row_count, next_action
			  FROM device_collection_outcomes
			 WHERE tenant_id = $1
			   AND coalesce(last_attempt_at, updated_at)
			       >= clock_timestamp() - ($2 * interval '1 second')
			   AND ($3 = '' OR agent_id = $3)
			   AND ($4 = '' OR configured_target = $4)
			   AND ($5 = '' OR state = $5)
			 ORDER BY last_attempt_at DESC NULLS LAST,
			          agent_id, configured_target, protocol
			 LIMIT $6`,
			sc.Tenant.String(), int64(device.CollectionOutcomeRetention/time.Second),
			filter.AgentID, filter.Target, filter.State, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row device.CollectionOutcome
			row.TenantID = tenant
			if err := rows.Scan(
				&row.AgentID, &row.ConfiguredTarget, &row.Protocol,
				&row.LastAttemptAt, &row.LastSuccessAt, &row.State, &row.Reason,
				&row.RowCount, &row.NextAction,
			); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, nil
}

var _ device.CollectionOutcomeStore = (*DeviceCollectionOutcomes)(nil)
