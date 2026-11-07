// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type postgres struct {
	pool        *pgxpool.Pool
	headerBytes int64
}

func (p *postgres) scoped(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	if !canonicalID(tenant) {
		return tenancy.ErrNoTenant
	}
	if p == nil || p.pool == nil {
		return errors.New("flow snapshot metadata unavailable")
	}
	return tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), p.pool, fn)
}

// The lease transaction is separate from the short state transactions below.
// Invalidation's committed marker survives a process crash/lease rollback.
// A shared lease spans SOURCE READ through publication, not only the final put.
func (p *postgres) lease(ctx context.Context, tenant string, exclusive bool, fn func(context.Context) error) error {
	return p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		query := `SELECT pg_advisory_xact_lock_shared(hashtextextended('probectl.flow_snapshots.lease:' || $1::text,0))`
		if exclusive {
			query = `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_snapshots.lease:' || $1::text,0))`
		}
		if _, err := sc.Q.Exec(ctx, query, tenant); err != nil {
			return err
		}
		return fn(ctx)
	})
}

func ensureEpoch(ctx context.Context, sc tenancy.Scope) error {
	return sourceepoch.PrepareInScope(ctx, sc)
}

func (p *postgres) state(ctx context.Context, tenant string) (epoch, error) {
	var result epoch
	err := p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := ensureEpoch(ctx, sc); err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx, `SELECT generation,invalidating FROM flow_snapshot_epochs WHERE tenant_id=$1::uuid`, tenant).Scan(&result.Generation, &result.Invalidating)
	})
	return result, err
}

func snapshotMutationLock(ctx context.Context, sc tenancy.Scope) error {
	_, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_snapshots.quota:' || $1::text,0))`, sc.Tenant.String())
	return err
}

func (p *postgres) reserve(ctx context.Context, m manifest, budget int64) error {
	return p.scoped(ctx, m.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := snapshotMutationLock(ctx, sc); err != nil {
			return err
		}
		var used int64
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(sum(charged_bytes),0)::bigint FROM flow_snapshots WHERE tenant_id=$1::uuid`, m.TenantID).Scan(&used); err != nil {
			return err
		}
		if m.ChargedBytes <= 0 || m.ChargedBytes > budget || used > budget-m.ChargedBytes {
			return ErrBudget
		}
		command, err := sc.Q.Exec(ctx, `INSERT INTO flow_snapshots(tenant_id,id,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,private_header,charged_bytes,state)
		SELECT $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending'
		FROM flow_snapshot_epochs WHERE tenant_id=$1::uuid AND generation=$4 AND NOT invalidating`, m.TenantID, m.ID, m.Owner, m.Generation, m.QueryHash, m.Lane, m.CreatedAt, m.ExpiresAt, m.Rows, m.PageSize, m.Permissions, m.Private, m.ChargedBytes)
		if err == nil && command.RowsAffected() != 1 {
			return ErrInvalidating
		}
		if err != nil {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, m.Owner, "flow.snapshot.create_intent", m.ID, map[string]any{"query_hash": m.QueryHash, "selected_rows": m.Rows, "expires_at": m.ExpiresAt, "charged_bytes": m.ChargedBytes})
		return err
	})
}

func (p *postgres) publish(ctx context.Context, m manifest) error {
	return p.scoped(ctx, m.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		command, err := sc.Q.Exec(ctx, `UPDATE flow_snapshots s SET state='ready' FROM flow_snapshot_epochs e
		WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND s.owner_id=$3 AND s.state='pending'
		AND e.tenant_id=s.tenant_id AND e.generation=s.generation AND e.generation=$4 AND NOT e.invalidating`, m.TenantID, m.ID, m.Owner, m.Generation)
		if err == nil && command.RowsAffected() != 1 {
			return ErrInvalidating
		}
		if err != nil {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, m.Owner, "flow.snapshot.create", m.ID, map[string]any{"query_hash": m.QueryHash, "selected_rows": m.Rows, "expires_at": m.ExpiresAt})
		return err
	})
}

const manifestColumns = `tenant_id::text,id::text,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,CASE WHEN octet_length(private_header)<=$4::bigint THEN private_header ELSE '' END,charged_bytes,(state='ready'),(octet_length(private_header)>$4::bigint)`

type scanner interface{ Scan(...any) error }

func scanManifest(row scanner) (manifest, error) {
	var m manifest
	var oversized bool
	err := row.Scan(&m.TenantID, &m.ID, &m.Owner, &m.Generation, &m.QueryHash, &m.Lane, &m.CreatedAt, &m.ExpiresAt, &m.Rows, &m.PageSize, &m.Permissions, &m.Private, &m.ChargedBytes, &m.Ready, &oversized)
	if err == nil && oversized {
		return m, ErrBudget
	}
	return m, err
}

func (p *postgres) get(ctx context.Context, scope Scope, id string) (manifest, error) {
	if !canonicalID(id) {
		return manifest{}, ErrNotFound
	}
	var m manifest
	err := p.scoped(ctx, scope.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		m, err = scanManifest(sc.Q.QueryRow(ctx, `SELECT `+manifestColumns+` FROM flow_snapshots WHERE tenant_id=$1::uuid AND id=$2::uuid AND owner_id=$3 AND state='ready'`, scope.TenantID, id, scope.Owner, p.headerBytes))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return manifest{}, ErrNotFound
	}
	return m, err
}

func (p *postgres) remove(ctx context.Context, tenant, id string) error {
	return p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		command, err := sc.Q.Exec(ctx, `DELETE FROM flow_snapshots WHERE tenant_id=$1::uuid AND id=$2::uuid`, tenant, id)
		if err != nil || command.RowsAffected() == 0 {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, "system", "flow.snapshot.reclaim", id, map[string]any{"objects_verified_absent": true})
		return err
	})
}

func (p *postgres) expired(ctx context.Context, tenant string, now time.Time, limit int) ([]manifest, error) {
	var result []manifest
	err := p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT `+manifestColumns+` FROM flow_snapshots WHERE tenant_id=$1::uuid AND (state='pending' OR expires_at<=$2) ORDER BY created_at,id LIMIT $3`, tenant, now, limit, p.headerBytes)
		if err != nil {
			return err
		}
		defer rows.Close()
		var retainedBytes int64
		for rows.Next() {
			m, err := scanManifest(rows)
			if err != nil {
				return err
			}
			// Refuse the whole maintenance batch before retaining another
			// header beyond its shared allowance; no object has been deleted.
			bytes := int64(len(m.Private))
			if bytes > p.headerBytes || retainedBytes > p.headerBytes-bytes {
				return ErrBudget
			}
			retainedBytes += bytes
			result = append(result, m)
		}
		return rows.Err()
	})
	return result, err
}

func (p *postgres) beginInvalidation(ctx context.Context, tenant, token string, prepare Preparation) (bool, error) {
	var audited bool
	err := p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		if err := ensureEpoch(ctx, sc); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=true,transition_token=$2::uuid WHERE tenant_id=$1::uuid`, tenant, token)
		if err != nil {
			return err
		}
		if prepare != nil {
			if err := prepare(ctx, sc); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_snapshots WHERE tenant_id=$1::uuid)`, tenant).Scan(&audited); err != nil {
				return err
			}
		} else {
			audited = true
		}
		// An empty cache has no data mutation to audit separately. The policy
		// preparation already appends its own atomic audit; keep its exact
		// existing row/head contract rather than adding unrelated empty events.
		if !audited {
			return nil
		}
		_, err = audit.TenantAppend(ctx, sc, "system", "flow.snapshot.invalidate_intent", "flow-snapshot-cache", map[string]any{"cause": "tenant_lifecycle"})
		return err
	})
	return audited, err
}

func (p *postgres) endInvalidation(ctx context.Context, tenant, token string, audited bool) error {
	return p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		command, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL WHERE tenant_id=$1::uuid AND invalidating AND transition_token=$2::uuid`, tenant, token)
		if err == nil && command.RowsAffected() != 1 {
			return ErrInvalidating
		}
		if err != nil {
			return err
		}
		if !audited {
			return nil
		}
		_, err = audit.TenantAppend(ctx, sc, "system", "flow.snapshot.invalidate_complete", "flow-snapshot-cache", map[string]any{"objects_verified_absent": true})
		return err
	})
}

func (p *postgres) clear(ctx context.Context, tenant string) error {
	return p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM flow_snapshots WHERE tenant_id=$1::uuid`, tenant)
		return err
	})
}

func (p *postgres) any(ctx context.Context, tenant string) (bool, error) {
	var exists bool
	err := p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_snapshots WHERE tenant_id=$1::uuid)`, tenant).Scan(&exists)
	})
	return exists, err
}

func (p *postgres) reclaimable(ctx context.Context, tenant string, now time.Time) (bool, error) {
	var exists bool
	err := p.scoped(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_snapshots WHERE tenant_id=$1::uuid AND (state='pending' OR expires_at<=$2))`, tenant, now).Scan(&exists)
	})
	return exists, err
}
