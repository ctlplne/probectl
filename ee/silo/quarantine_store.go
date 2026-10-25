// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// pgQuarantineStore is tenant_quarantine (migration 0130) plus the provider
// stream. Each operation is one provider transaction that takes a per-tenant
// advisory lock first, so the "first live holder" / "last live holder"
// decision and its audit event are atomic across replicas (DPR-381).
type pgQuarantineStore struct{ pool *pgxpool.Pool }

const quarantineLockKey = "probectl:silo-quarantine:"

func lockQuarantineTenant(ctx context.Context, q tenancy.Querier, tenantID string) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, quarantineLockKey+tenantID)
	return err
}

func liveHolders(ctx context.Context, q tenancy.Querier, tenantID string, live time.Duration) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM tenant_quarantine
		 WHERE tenant = $1::uuid AND checked_at >= now() - make_interval(secs => $2)`, tenantID, live.Seconds()).Scan(&n)
	return n, err
}

func providerData(replica string, e tenancy.QuarantineEntry, extra map[string]any) map[string]any {
	data := map[string]any{
		"reason": string(e.Reason), "plane": e.Plane, "detail": e.Detail, "remedy": e.Remedy,
		"replica": replica, "since": e.Since.UTC().Format(time.RFC3339), "decision": "D-62",
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func (p pgQuarantineStore) hold(ctx context.Context, replica string, e tenancy.QuarantineEntry, live time.Duration) (bool, error) {
	entered := false
	err := tenancy.InProvider(ctx, p.pool, func(ctx context.Context, q tenancy.Querier) error {
		if err := lockQuarantineTenant(ctx, q, e.TenantID); err != nil {
			return err
		}
		before, err := liveHolders(ctx, q, e.TenantID, live)
		if err != nil {
			return err
		}
		var prevReason string
		var mineLive bool
		if err := q.QueryRow(ctx, `SELECT reason, checked_at >= now() - make_interval(secs => $3) FROM tenant_quarantine
			 WHERE tenant = $1::uuid AND replica = $2`, e.TenantID, replica, live.Seconds()).Scan(&prevReason, &mineLive); err != nil && !isNoRows(err) {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO tenant_quarantine (tenant, replica, reason, plane, detail, remedy, since, checked_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (tenant, replica) DO UPDATE
			   SET reason = EXCLUDED.reason, plane = EXCLUDED.plane, detail = EXCLUDED.detail,
			       remedy = EXCLUDED.remedy, checked_at = now()`,
			e.TenantID, replica, string(e.Reason), e.Plane, e.Detail, e.Remedy, e.Since); err != nil {
			return err
		}
		switch {
		case before == 0:
			entered = true
			_, err = audit.ProviderAppendTx(ctx, q, QuarantineActor, AuditTenantQuarantined, e.TenantID, providerData(replica, e, map[string]any{"holders": 1}))
		case mineLive && prevReason != string(e.Reason):
			_, err = audit.ProviderAppendTx(ctx, q, QuarantineActor, AuditQuarantineCauseChanged, e.TenantID,
				providerData(replica, e, map[string]any{"previous_reason": prevReason}))
		}
		return err
	})
	return entered, err
}

func (p pgQuarantineStore) drop(ctx context.Context, replica string, e tenancy.QuarantineEntry, live time.Duration, why string) (bool, error) {
	released := false
	err := tenancy.InProvider(ctx, p.pool, func(ctx context.Context, q tenancy.Querier) error {
		if err := lockQuarantineTenant(ctx, q, e.TenantID); err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `DELETE FROM tenant_quarantine WHERE tenant = $1::uuid AND replica = $2`, e.TenantID, replica)
		if err != nil {
			return err
		}
		after, err := liveHolders(ctx, q, e.TenantID, live)
		if err != nil {
			return err
		}
		// The row existed (its entered was recorded, and a row is released
		// exactly once: by this drop or by prune, both under the lock) and no
		// live holder remains.
		if tag.RowsAffected() == 0 || after > 0 {
			return nil
		}
		released = true
		_, err = audit.ProviderAppendTx(ctx, q, QuarantineActor, AuditTenantReleased, e.TenantID,
			providerData(replica, e, map[string]any{"released_because": why}))
		return err
	})
	return released, err
}

func (p pgQuarantineStore) predecessors(ctx context.Context, host, me string, idle time.Duration) ([]heldRow, error) {
	var out []heldRow
	err := tenancy.InProvider(ctx, p.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT tenant::text, reason, plane, detail, remedy, since, replica FROM tenant_quarantine
			 WHERE left(replica, length($1) + 1) = $1 || '/' AND replica <> $2
			   AND checked_at < now() - make_interval(secs => $3)`, host, me, idle.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r heldRow
			var reason string
			if err := rows.Scan(&r.entry.TenantID, &reason, &r.entry.Plane, &r.entry.Detail, &r.entry.Remedy, &r.entry.Since, &r.replica); err != nil {
				return err
			}
			r.entry.Reason = tenancy.QuarantineReason(reason)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (p pgQuarantineStore) prune(ctx context.Context, live time.Duration) ([]tenancy.QuarantineEntry, error) {
	var stale []tenancy.QuarantineEntry
	if err := tenancy.InProvider(ctx, p.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT DISTINCT ON (tenant) tenant::text, reason, plane, detail, remedy, since FROM tenant_quarantine
			 WHERE checked_at < now() - make_interval(secs => $1) ORDER BY tenant, checked_at DESC`, live.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		stale, err = scanQuarantineEntries(rows)
		return err
	}); err != nil {
		return nil, err
	}
	var released []tenancy.QuarantineEntry
	for _, e := range stale {
		gone := false
		if err := tenancy.InProvider(ctx, p.pool, func(ctx context.Context, q tenancy.Querier) error {
			if err := lockQuarantineTenant(ctx, q, e.TenantID); err != nil {
				return err
			}
			tag, err := q.Exec(ctx, `DELETE FROM tenant_quarantine WHERE tenant = $1::uuid AND checked_at < now() - make_interval(secs => $2)`,
				e.TenantID, live.Seconds())
			if err != nil || tag.RowsAffected() == 0 {
				return err // another replica pruned it first
			}
			after, err := liveHolders(ctx, q, e.TenantID, live)
			if err != nil || after > 0 {
				return err
			}
			gone = true
			_, err = audit.ProviderAppendTx(ctx, q, QuarantineActor, AuditTenantReleased, e.TenantID,
				providerData("", e, map[string]any{"released_because": "every replica that held it stopped re-checking it (gone)"}))
			return err
		}); err != nil {
			return released, err
		}
		if gone {
			released = append(released, e)
		}
	}
	return released, nil
}

func (p pgQuarantineStore) record(ctx context.Context, action, tenantID string, data map[string]any) error {
	_, err := audit.ProviderAppend(ctx, p.pool, QuarantineActor, action, tenantID, data)
	return err
}

type entryRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanQuarantineEntries(rows entryRows) ([]tenancy.QuarantineEntry, error) {
	var out []tenancy.QuarantineEntry
	for rows.Next() {
		var e tenancy.QuarantineEntry
		var reason string
		if err := rows.Scan(&e.TenantID, &reason, &e.Plane, &e.Detail, &e.Remedy, &e.Since); err != nil {
			return nil, fmt.Errorf("scan tenant_quarantine: %w", err)
		}
		e.Reason = tenancy.QuarantineReason(reason)
		out = append(out, e)
	}
	return out, rows.Err()
}

// LoadReplicaQuarantine (D-62) copies into q every quarantine a live serving
// replica holds — rows of tenant_quarantine refreshed within freshWithin — so
// a one-shot command (mcp-stdio, mcp-token, bootstrap-admin, …) refuses a
// tenant the serving replicas have quarantined instead of serving it from a
// process that never ran the startup checks. A database that predates
// migration 0130 can hold no quarantine and loads nothing.
func LoadReplicaQuarantine(ctx context.Context, pool *pgxpool.Pool, q *tenancy.Quarantine, freshWithin time.Duration) (int, error) {
	var entries []tenancy.QuarantineEntry
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, tx tenancy.Querier) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('public.tenant_quarantine') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (tenant) tenant::text, reason, plane, detail, remedy, since
			   FROM tenant_quarantine
			  WHERE checked_at >= now() - make_interval(secs => $1)
			  ORDER BY tenant, since`, freshWithin.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e tenancy.QuarantineEntry
			var reason string
			if err := rows.Scan(&e.TenantID, &reason, &e.Plane, &e.Detail, &e.Remedy, &e.Since); err != nil {
				return err
			}
			e.Reason = tenancy.QuarantineReason(reason)
			entries = append(entries, e)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, fmt.Errorf("silo quarantine: read the replicas' quarantine view: %w", err)
	}
	for _, e := range entries {
		q.Enter(e)
	}
	return len(entries), nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
