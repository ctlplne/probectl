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
	Dependency   *alert.DependencyNotificationState
}

// Upsert records/updates the notification state for a fingerprint (on notify).
func (AlertNotifications) Upsert(ctx context.Context, s tenancy.Scope, n AlertNotification) error {
	var transition any
	held := false
	if n.Dependency != nil {
		if err := n.Dependency.Validate(); err != nil {
			return err
		}
		if n.Dependency.Held && n.FiringSince.IsZero() {
			return alert.ErrDependencyEvidence
		}
		held = n.Dependency.Held
		if n.Dependency.TransitionID != "" {
			transition = n.Dependency.TransitionID
		}
	}
	var firingSince *time.Time
	if !n.FiringSince.IsZero() {
		firingSince = &n.FiringSince
	}
	_, err := s.Q.Exec(ctx,
		`INSERT INTO alert_notifications (tenant_id, fingerprint, firing_since, last_notified, updated_at, dependency_held, dependency_transition)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3, now(), $5::boolean, $6::uuid)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
		   dependency_held = CASE WHEN $4::boolean THEN EXCLUDED.dependency_held
		     WHEN alert_notifications.firing_since IS NOT DISTINCT FROM EXCLUDED.firing_since THEN alert_notifications.dependency_held ELSE false END,
		   dependency_transition = CASE WHEN $4::boolean AND EXCLUDED.dependency_transition IS NOT NULL THEN EXCLUDED.dependency_transition
		     WHEN $4::boolean AND NOT EXCLUDED.dependency_held AND alert_notifications.firing_since IS NOT DISTINCT FROM EXCLUDED.firing_since THEN alert_notifications.dependency_transition
		     WHEN $4::boolean THEN NULL
		     WHEN alert_notifications.firing_since IS NOT DISTINCT FROM EXCLUDED.firing_since THEN alert_notifications.dependency_transition ELSE NULL END,
		   firing_since = EXCLUDED.firing_since,
		   last_notified = EXCLUDED.last_notified,
		   updated_at = now()`,
		n.Fingerprint, firingSince, n.LastNotified, n.Dependency != nil, held, transition)
	return err
}

// Get reads only the tenant's exact episode, locking it through publication.
// The marker is bookkeeping; it is never current source or parent authority.
func (AlertNotifications) Get(ctx context.Context, s tenancy.Scope, fingerprint string) (*AlertNotification, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != s.Tenant || s.Q == nil {
		return nil, alert.ErrDependencyEvidence
	}
	var out AlertNotification
	err := scanAlertNotification(s.Q.QueryRow(ctx, `SELECT fingerprint,firing_since,last_notified,dependency_held,dependency_transition::text
 FROM alert_notifications WHERE tenant_id=$1 AND fingerprint=$2 FOR UPDATE`, s.Tenant.String(), fingerprint), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &out, err
}

// GetPopulation locks complete requested episode bookkeeping in one tenant
// transaction. Missing keys stay absent; no marker grants source authority.
func (AlertNotifications) GetPopulation(ctx context.Context, s tenancy.Scope, fingerprints []string, maxBytes int64) (map[string]*AlertNotification, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != s.Tenant || s.Q == nil {
		return nil, alert.ErrDependencyEvidence
	}
	if maxBytes < 4096 || int64(len(fingerprints)) > maxBytes/1024 {
		return nil, ErrAlertDependencyBudget
	}
	remaining := maxBytes
	wanted := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		cost := int64(len(fingerprint))
		if remaining < 1024 || cost > remaining-1024 {
			return nil, ErrAlertDependencyBudget
		}
		remaining -= 1024 + cost
		if fingerprint == "" || wanted[fingerprint] {
			return nil, alert.ErrDependencyEvidence
		}
		wanted[fingerprint] = true
	}
	out := make(map[string]*AlertNotification, len(fingerprints))
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := s.Q.Query(ctx, `SELECT fingerprint,firing_since,last_notified,dependency_held,dependency_transition::text
 FROM alert_notifications WHERE tenant_id=$1 AND fingerprint=ANY($2::text[])
 ORDER BY fingerprint FOR UPDATE`, s.Tenant.String(), fingerprints)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var value AlertNotification
		if err := scanAlertNotification(rows, &value); err != nil {
			return nil, err
		}
		if !wanted[value.Fingerprint] || out[value.Fingerprint] != nil {
			return nil, alert.ErrDependencyEvidence
		}
		out[value.Fingerprint] = &value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

// Delete removes the notification state (episode resolved).
func (AlertNotifications) Delete(ctx context.Context, s tenancy.Scope, fingerprint string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM alert_notifications WHERE fingerprint = $1`, fingerprint)
	return err
}

// List returns the tenant's persisted notification state (leadership reload).
func (AlertNotifications) List(ctx context.Context, s tenancy.Scope) ([]AlertNotification, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT fingerprint, firing_since, last_notified, dependency_held, dependency_transition::text FROM alert_notifications`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertNotification
	for rows.Next() {
		var n AlertNotification
		if err := scanAlertNotification(rows, &n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func scanAlertNotification(row interface{ Scan(...any) error }, out *AlertNotification) error {
	var since *time.Time
	var transition *string
	var held bool
	if err := row.Scan(&out.Fingerprint, &since, &out.LastNotified, &held, &transition); err != nil {
		return err
	}
	if since != nil {
		out.FiringSince = *since
	}
	if transition != nil {
		out.Dependency = &alert.DependencyNotificationState{Held: held, TransitionID: *transition}
		if err := out.Dependency.Validate(); err != nil {
			return err
		}
	} else if held {
		return alert.ErrDependencyEvidence
	}
	return nil
}
