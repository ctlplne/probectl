// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// SIEMDelivery is the per-tenant SIEM export cursor (S32, F26): the highest audit
// `seq` already forwarded to the operator's SIEM. The audit poller reads it on
// start and advances it only past delivered events, so a restart resumes without
// dropping (delivery is idempotent on the SIEM side regardless). RLS confines
// every row to the caller's tenant (F50).
type SIEMDelivery struct{}

// Cursor returns the tenant's last-forwarded audit seq (0 when none recorded).
func (SIEMDelivery) Cursor(ctx context.Context, s tenancy.Scope) (int64, error) {
	var seq int64
	err := s.Q.QueryRow(ctx,
		`SELECT last_seq FROM siem_delivery WHERE tenant_id = $1`, s.Tenant.String()).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// CursorForUpdate returns the tenant cursor while holding its row lock until
// the caller's tenant transaction commits or rolls back. The insert is required:
// SELECT FOR UPDATE cannot lock a row that does not exist, so two first-time
// pollers could otherwise both read zero and forward the same page.
//
// Call this only inside the delivery transaction that also calls Advance.
func (SIEMDelivery) CursorForUpdate(ctx context.Context, s tenancy.Scope) (int64, error) {
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO siem_delivery (tenant_id, last_seq, updated_at)
		 VALUES ($1, 0, now())
		 ON CONFLICT (tenant_id) DO NOTHING`, s.Tenant.String()); err != nil {
		return 0, err
	}
	var seq int64
	if err := s.Q.QueryRow(ctx,
		`SELECT last_seq FROM siem_delivery WHERE tenant_id = $1 FOR UPDATE`,
		s.Tenant.String()).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// Advance records seq as forwarded. It is monotonic (GREATEST), so a concurrent
// or out-of-order call never rewinds the cursor.
func (SIEMDelivery) Advance(ctx context.Context, s tenancy.Scope, seq int64) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO siem_delivery (tenant_id, last_seq, updated_at)
		   VALUES ($1, $2, now())
		 ON CONFLICT (tenant_id)
		   DO UPDATE SET last_seq = GREATEST(siem_delivery.last_seq, EXCLUDED.last_seq),
		                 updated_at = now()`,
		s.Tenant.String(), seq)
	return err
}
