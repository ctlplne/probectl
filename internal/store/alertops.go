// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// AlertOps persists operator silences/acks (Sprint 16, ARCH-005 — the
// volatile-stores ADR's documented exception). Rows are tenant-confined by
// RLS; the engine re-applies them when the series fires after a restart and
// the API layer deletes them when the episode resolves.
type AlertOps struct{}

// AlertOp is one persisted operator action.
type AlertOp struct {
	Fingerprint   string
	RuleID        string
	SilencedUntil *time.Time
	AckedBy       string
	AckedAt       *time.Time
}

// Upsert records/updates the op for a fingerprint.
func (AlertOps) Upsert(ctx context.Context, s tenancy.Scope, op AlertOp) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO alert_ops (tenant_id, fingerprint, rule_id, silenced_until, acked_by, acked_at, updated_at)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3, $4, $5, now())
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
		   rule_id = EXCLUDED.rule_id,
		   silenced_until = EXCLUDED.silenced_until,
		   acked_by = EXCLUDED.acked_by,
		   acked_at = EXCLUDED.acked_at,
		   updated_at = now()`,
		op.Fingerprint, op.RuleID, op.SilencedUntil, op.AckedBy, op.AckedAt)
	return err
}

// Delete removes the op (episode resolved, or silence cleared with no ack).
func (AlertOps) Delete(ctx context.Context, s tenancy.Scope, fingerprint string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM alert_ops WHERE fingerprint = $1`, fingerprint)
	return err
}

// List returns the tenant's persisted ops (boot reload).
func (AlertOps) List(ctx context.Context, s tenancy.Scope) ([]AlertOp, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT fingerprint, rule_id, silenced_until, acked_by, acked_at FROM alert_ops`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertOp
	for rows.Next() {
		var op AlertOp
		if err := rows.Scan(&op.Fingerprint, &op.RuleID, &op.SilencedUntil, &op.AckedBy, &op.AckedAt); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}
