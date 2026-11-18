// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// LookupWitnessesInScope checks a complete original-receipt set in the caller's
// current RLS snapshot. The keys must already be derived from the selected
// source's original sender/digest/poll facts. This returns provenance, never
// actor authority. Missing, erased, rebound, revoked or foreign keys refuse the
// whole set; no successful prefix or shortened billing population is returned.
func (s *DeviceCounterCaptures) LookupWitnessesInScope(ctx context.Context, sc tenancy.Scope, keys [][32]byte, memoryBytes int64) (witnesses map[[32]byte]DeviceCounterCapture, lookupErr error) {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if s == nil || s.pool == nil {
		return nil, ErrCounterCaptureUnavailable
	}
	if memoryBytes < 4096 || int64(len(keys)) > (memoryBytes-4096)/4096 {
		return nil, ErrCounterCaptureBudget
	}
	selected := make(map[[32]byte]bool, len(keys))
	parameters := make([][]byte, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if key == ([32]byte{}) {
			return nil, ErrCounterCaptureUnavailable
		}
		if !selected[key] {
			selected[key] = true
			parameters = append(parameters, append([]byte(nil), key[:]...))
		}
	}
	result := make(map[[32]byte]DeviceCounterCapture, len(parameters))
	if len(parameters) == 0 {
		return result, ctx.Err()
	}
	args := []any{tenant.String(), parameters}
	if len(parameters) >= 1024 {
		restore, err := preferCounterWitnessSetJoin(ctx, sc.Q)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := restore(); err != nil && lookupErr == nil {
				witnesses, lookupErr = nil, err
			}
		}()
		args = []any{pgx.QueryExecModeDescribeExec, tenant.String(), parameters}
	}
	rows, err := sc.Q.Query(ctx, `SELECT c.capture_key,c.captured_at,p.context_id::text,p.device_id::text,p.sender_serial,p.source_assigned_at,p.agent_assigned_at `+
		deviceCounterWitnessScopeSQL+` AND c.capture_key=ANY($2::bytea[])`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var key []byte
		witness := DeviceCounterCapture{Scope: entity.Scope{TenantID: tenant.String()}}
		if err := rows.Scan(&key, &witness.CapturedAt, &witness.Scope.ContextID, &witness.DeviceID, &witness.SenderSerial, &witness.SourceAssignedAt, &witness.AgentAssignedAt); err != nil {
			return nil, err
		}
		if len(key) != len(witness.Key) {
			return nil, ErrCounterCaptureUnavailable
		}
		copy(witness.Key[:], key)
		if !selected[witness.Key] {
			return nil, ErrCounterCaptureUnavailable
		}
		if _, duplicate := result[witness.Key]; duplicate {
			return nil, ErrCounterCaptureUnavailable
		}
		result[witness.Key] = witness
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) != len(parameters) {
		return nil, ErrCounterCaptureUnavailable
	}
	return result, nil
}

// Large fresh batches can have low row estimates even when both receipt tables
// contain thousands of selected rows. Prefer set joins so PostgreSQL does not
// rescan the capture set for every source record. The preference ends when the
// result closes, inside the caller's tenant transaction.
func preferCounterWitnessSetJoin(ctx context.Context, q tenancy.Querier) (func() error, error) {
	var previous string
	if err := q.QueryRow(ctx, `SELECT current_setting('enable_nestloop')`).Scan(&previous); err != nil {
		return nil, err
	}
	const configure = `SELECT set_config('enable_nestloop',$1,true)`
	if _, err := q.Exec(ctx, configure, "off"); err != nil {
		return nil, err
	}
	return func() error {
		_, err := q.Exec(ctx, configure, previous)
		return err
	}, nil
}
