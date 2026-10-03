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

// AlertNotifications persists per-series notification bookkeeping (RTO-20): the
// firing-since and last-notified the alert engine dedupes/renotifies against.
// Rows are tenant-confined by forced RLS; a newly-elected singleton leader
// rehydrates them so a continuously-firing alert is not re-notified across
// failover, and the engine's resolve hook deletes them when the episode ends.
// Like AlertOps, this is the volatile-stores ADR's documented exception.
type AlertNotifications struct{}

// AlertNotification is one series' persisted notification state. Fingerprint is
// the engine state key (rule + series), the same handle alert_ops uses.
type AlertNotification struct {
	Fingerprint  string
	FiringSince  time.Time
	LastNotified time.Time
}

// Upsert records/updates the notification state for a fingerprint (on notify).
func (AlertNotifications) Upsert(ctx context.Context, s tenancy.Scope, n AlertNotification) error {
	var firingSince *time.Time
	if !n.FiringSince.IsZero() {
		firingSince = &n.FiringSince
	}
	_, err := s.Q.Exec(ctx,
		`INSERT INTO alert_notifications (tenant_id, fingerprint, firing_since, last_notified, updated_at)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3, now())
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
		   firing_since = EXCLUDED.firing_since,
		   last_notified = EXCLUDED.last_notified,
		   updated_at = now()`,
		n.Fingerprint, firingSince, n.LastNotified)
	return err
}

// Delete removes the notification state (episode resolved).
func (AlertNotifications) Delete(ctx context.Context, s tenancy.Scope, fingerprint string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM alert_notifications WHERE fingerprint = $1`, fingerprint)
	return err
}

// List returns the tenant's persisted notification state (leadership reload).
func (AlertNotifications) List(ctx context.Context, s tenancy.Scope) ([]AlertNotification, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT fingerprint, firing_since, last_notified FROM alert_notifications`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertNotification
	for rows.Next() {
		var (
			n           AlertNotification
			firingSince *time.Time
		)
		if err := rows.Scan(&n.Fingerprint, &firingSince, &n.LastNotified); err != nil {
			return nil, err
		}
		if firingSince != nil {
			n.FiringSince = *firingSince
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
