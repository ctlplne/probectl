// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DeviceTraps is the forced-RLS Postgres trap read model (D-60, migration
// 0126). Every read and write runs in a tenant-scoped transaction, so row
// security — not the handler or the consumer — is the tenant boundary.
type DeviceTraps struct {
	pool *pgxpool.Pool
}

// NewDeviceTraps binds the store to the writer pool (nil pool → nil store).
func NewDeviceTraps(pool *pgxpool.Pool) *DeviceTraps {
	if pool == nil {
		return nil
	}
	return &DeviceTraps{pool: pool}
}

const deviceTrapCols = `id::text, agent_id, fingerprint, device_address, source_address,
	auth_principal, version, kind, severity, trap_oid, request_id, uptime_ticks,
	if_index, varbinds, varbinds_truncated, observed_at, received_at`

// RecordTrapEvent stores one validated trap for tenant. A record whose
// (agent, fingerprint) is already stored — a bus redelivery — inserts nothing
// and reports inserted=false. Each insert prunes the tenant's rows past the
// retention age and count bounds in the same transaction.
func (s *DeviceTraps) RecordTrapEvent(ctx context.Context, tenant string, rec device.TrapRecord) (bool, error) {
	if s == nil || s.pool == nil {
		return false, apierror.Unavailable("device traps are not available in this deployment")
	}
	if tenant == "" || rec.TenantID != tenant {
		return false, apierror.Forbidden("device trap tenant scope mismatch")
	}
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	valid, err := device.ValidateTrapRecord(rec)
	if err != nil {
		return false, apierror.Validation(err.Error())
	}
	binds, err := json.Marshal(valid.VarBinds)
	if err != nil {
		return false, err
	}
	inserted := false
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var id string
		err := sc.Q.QueryRow(ctx, `
			INSERT INTO device_traps
			       (tenant_id, agent_id, fingerprint, device_address, source_address,
			        auth_principal, version, kind, severity, trap_oid, request_id,
			        uptime_ticks, if_index, varbinds, varbinds_truncated,
			        observed_at, received_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			        $14::jsonb, $15, $16, $17)
			ON CONFLICT (tenant_id, agent_id, fingerprint) DO NOTHING
			RETURNING id::text`,
			sc.Tenant.String(), valid.AgentID, valid.Fingerprint, valid.DeviceAddress,
			valid.SourceAddress, valid.AuthPrincipal, valid.Version, valid.Kind,
			valid.Severity, valid.TrapOID, valid.RequestID, int64(valid.UptimeTicks),
			int64(valid.IfIndex), string(binds), valid.VarBindsTruncated,
			valid.ObservedAt, valid.ReceivedAt).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // already stored: idempotent redelivery
		}
		if err != nil {
			return mapWriteErr("device trap", err)
		}
		inserted = true
		return pruneDeviceTraps(ctx, sc)
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// pruneDeviceTraps enforces the trap retention age and per-tenant count cap.
func pruneDeviceTraps(ctx context.Context, sc tenancy.Scope) error {
	if _, err := sc.Q.Exec(ctx, `
		DELETE FROM device_traps
		 WHERE tenant_id = $1
		   AND received_at < clock_timestamp() - ($2 * interval '1 second')`,
		sc.Tenant.String(), int64(device.TrapRetention/time.Second)); err != nil {
		return err
	}
	_, err := sc.Q.Exec(ctx, `
		DELETE FROM device_traps
		 WHERE tenant_id = $1 AND id IN (
		   SELECT id FROM device_traps
		    WHERE tenant_id = $1
		    ORDER BY received_at DESC, id DESC
		    OFFSET $2
		 )`,
		sc.Tenant.String(), device.MaxTrapsPerTenant)
	return err
}

// ListTrapEvents returns tenant's newest traps (received_at DESC), optionally
// for one device and a received-at window, capped at device.MaxTrapRead. The
// second result reports that more rows matched than were returned.
func (s *DeviceTraps) ListTrapEvents(ctx context.Context, tenant string, filter device.TrapFilter) ([]device.TrapRecord, bool, error) {
	if s == nil || s.pool == nil {
		return nil, false, apierror.Unavailable("device traps are not available in this deployment")
	}
	if tenant == "" {
		return nil, false, apierror.Validation("tenant_id is required")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = device.DefaultTrapRead
	}
	limit = min(limit, device.MaxTrapRead)
	var since, until *time.Time
	if !filter.Since.IsZero() {
		v := filter.Since.UTC()
		since = &v
	}
	if !filter.Until.IsZero() {
		v := filter.Until.UTC()
		until = &v
	}
	var out []device.TrapRecord
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT `+deviceTrapCols+`
			  FROM device_traps
			 WHERE tenant_id = $1
			   AND ($2 = '' OR device_address = $2)
			   AND ($3::timestamptz IS NULL OR received_at >= $3)
			   AND ($4::timestamptz IS NULL OR received_at < $4)
			 ORDER BY received_at DESC, id DESC
			 LIMIT $5`,
			sc.Tenant.String(), strings.TrimSpace(filter.Device), since, until, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rec, err := scanDeviceTrap(rows, tenant)
			if err != nil {
				return err
			}
			out = append(out, rec)
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

func scanDeviceTrap(row pgx.Row, tenant string) (device.TrapRecord, error) {
	rec := device.TrapRecord{TenantID: tenant}
	var binds []byte
	var uptime, ifIndex int64
	if err := row.Scan(&rec.ID, &rec.AgentID, &rec.Fingerprint, &rec.DeviceAddress,
		&rec.SourceAddress, &rec.AuthPrincipal, &rec.Version, &rec.Kind, &rec.Severity,
		&rec.TrapOID, &rec.RequestID, &uptime, &ifIndex, &binds, &rec.VarBindsTruncated,
		&rec.ObservedAt, &rec.ReceivedAt); err != nil {
		return device.TrapRecord{}, err
	}
	rec.UptimeTicks, rec.IfIndex = uint32(uptime), uint32(ifIndex) //nolint:gosec // CHECK-bounded to uint32 by migration 0126
	rec.VarBinds = []device.TrapVarBind{}
	if len(binds) > 0 {
		if err := json.Unmarshal(binds, &rec.VarBinds); err != nil {
			return device.TrapRecord{}, err
		}
	}
	rec.TrapName = device.TrapName(rec.TrapOID)
	rec.ObservedAt, rec.ReceivedAt = rec.ObservedAt.UTC(), rec.ReceivedAt.UTC()
	return rec, nil
}

// LatestTrapMatches returns, per device, tenant's newest stored trap whose OID
// is q.TrapOID or q.ClearTrapOID (and, when set, from q.Device and carrying the
// varbind q.VarBindOID = q.VarBindValue), received at or after q.Since — the
// read a trap alert rule evaluates (D-61). Bounded to
// device.MaxTrapMatchDevices devices; scoped by the tenant transaction.
func (s *DeviceTraps) LatestTrapMatches(ctx context.Context, tenant string, q device.TrapMatchQuery) ([]device.TrapMatch, error) {
	if s == nil || s.pool == nil {
		return nil, apierror.Unavailable("device traps are not available in this deployment")
	}
	if tenant == "" || q.TrapOID == "" || q.Since.IsZero() {
		return nil, apierror.Validation("tenant_id, trap_oid and since are required")
	}
	limit := q.Limit
	if limit < 1 || limit > device.MaxTrapMatchDevices {
		limit = device.MaxTrapMatchDevices
	}
	var out []device.TrapMatch
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT DISTINCT ON (device_address) device_address, trap_oid, received_at
			  FROM device_traps
			 WHERE tenant_id = $1
			   AND (trap_oid = $2 OR ($3 <> '' AND trap_oid = $3))
			   AND ($4 = '' OR device_address = $4)
			   AND ($5 = '' OR varbinds @> jsonb_build_array(jsonb_build_object('oid', $5::text, 'value', $6::text)))
			   AND received_at >= $7
			 ORDER BY device_address, received_at DESC, id DESC
			 LIMIT $8`,
			sc.Tenant.String(), q.TrapOID, q.ClearTrapOID, q.Device, q.VarBindOID, q.VarBindValue,
			q.Since.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m device.TrapMatch
			if err := rows.Scan(&m.DeviceAddress, &m.TrapOID, &m.ReceivedAt); err != nil {
				return err
			}
			m.ReceivedAt = m.ReceivedAt.UTC()
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var (
	_ device.TrapEventStore  = (*DeviceTraps)(nil)
	_ device.TrapMatchReader = (*DeviceTraps)(nil)
)
