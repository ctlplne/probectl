// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DeviceNeighbors is the forced-RLS Postgres implementation of the device
// neighbor current-evidence store.
type DeviceNeighbors struct {
	pool *pgxpool.Pool
}

func NewDeviceNeighbors(pool *pgxpool.Pool) *DeviceNeighbors {
	if pool == nil {
		return nil
	}
	return &DeviceNeighbors{pool: pool}
}

func (s *DeviceNeighbors) ReplaceSnapshot(ctx context.Context, tenant string, snapshot device.NeighborSnapshot) error {
	if s == nil || s.pool == nil {
		return apierror.Unavailable("device neighbors are not available in this deployment")
	}
	if tenant == "" || snapshot.TenantID != tenant {
		return apierror.Forbidden("device neighbor tenant scope mismatch")
	}
	valid, err := device.ValidateNeighborSnapshot(snapshot)
	if err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `
			DELETE FROM device_neighbor_evidence
			 WHERE tenant_id = $1 AND agent_id = $2 AND local_device_address = $3`,
			sc.Tenant.String(), valid.AgentID, valid.DeviceAddress); err != nil {
			return err
		}
		for _, n := range valid.Neighbors {
			if _, err := sc.Q.Exec(ctx, `
				INSERT INTO device_neighbor_evidence
				       (tenant_id, evidence_id, agent_id, local_device_address,
				        local_device_name, local_if_index, local_port_id,
				        remote_chassis_id, remote_device_name, remote_port_id,
				        remote_management_address, remote_platform, capabilities,
				        protocol, confidence, observed_at, fresh_until)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
				        $13, $14, $15, $16, $17)
				ON CONFLICT (tenant_id, evidence_id) DO UPDATE SET
				  agent_id = EXCLUDED.agent_id,
				  local_device_address = EXCLUDED.local_device_address,
				  local_device_name = EXCLUDED.local_device_name,
				  local_if_index = EXCLUDED.local_if_index,
				  local_port_id = EXCLUDED.local_port_id,
				  remote_chassis_id = EXCLUDED.remote_chassis_id,
				  remote_device_name = EXCLUDED.remote_device_name,
				  remote_port_id = EXCLUDED.remote_port_id,
				  remote_management_address = EXCLUDED.remote_management_address,
				  remote_platform = EXCLUDED.remote_platform,
				  capabilities = EXCLUDED.capabilities,
				  protocol = EXCLUDED.protocol,
				  confidence = EXCLUDED.confidence,
				  observed_at = EXCLUDED.observed_at,
				  fresh_until = EXCLUDED.fresh_until`,
				sc.Tenant.String(), n.EvidenceID(), n.AgentID, n.LocalDeviceAddress,
				n.LocalDeviceName, n.LocalIfIndex, n.LocalPortID, n.RemoteChassisID,
				n.RemoteDeviceName, n.RemotePortID, n.RemoteManagementAddress,
				n.RemotePlatform, n.Capabilities, n.Protocol, n.Confidence,
				n.ObservedAt, n.FreshUntil); err != nil {
				return mapWriteErr("device neighbor evidence", err)
			}
		}
		if _, err := sc.Q.Exec(ctx, `
			DELETE FROM device_neighbor_evidence
			 WHERE tenant_id = $1
			   AND observed_at < clock_timestamp() - ($2 * interval '1 second')`,
			sc.Tenant.String(), int64(device.NeighborStaleRetention/time.Second)); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `
			DELETE FROM device_neighbor_evidence
			 WHERE tenant_id = $1 AND evidence_id IN (
			   SELECT evidence_id FROM device_neighbor_evidence
			    WHERE tenant_id = $1
			    ORDER BY observed_at DESC, evidence_id
			    OFFSET $2
			 )`,
			sc.Tenant.String(), device.MaxNeighborsPerTenant)
		return err
	})
}

func (s *DeviceNeighbors) ListNeighbors(ctx context.Context, tenant string, filter device.NeighborFilter) ([]device.NeighborEvidence, bool, error) {
	if s == nil || s.pool == nil {
		return nil, false, apierror.Unavailable("device neighbors are not available in this deployment")
	}
	if tenant == "" {
		return nil, false, apierror.Validation("tenant_id is required")
	}
	filter.Device = strings.TrimSpace(filter.Device)
	filter.Protocol = strings.ToLower(strings.TrimSpace(filter.Protocol))
	if filter.Protocol != "" && filter.Protocol != device.NeighborProtocolLLDP &&
		filter.Protocol != device.NeighborProtocolCDP {
		return nil, false, apierror.Validation("protocol must be lldp or cdp")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > device.MaxNeighborRead {
		limit = device.MaxNeighborRead
	}
	var out []device.NeighborEvidence
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
			SELECT evidence_id, agent_id, local_device_address, local_device_name,
			       local_if_index, local_port_id, remote_chassis_id,
			       remote_device_name, remote_port_id, remote_management_address,
			       remote_platform, capabilities, protocol, confidence,
			       observed_at, fresh_until
			  FROM device_neighbor_evidence
			 WHERE tenant_id = $1
			   AND observed_at >= clock_timestamp() - ($2 * interval '1 second')
			   AND ($3 = '' OR local_device_address = $3)
			   AND ($4 = '' OR protocol = $4)
			 ORDER BY observed_at DESC, evidence_id
			 LIMIT $5`,
			sc.Tenant.String(), int64(device.NeighborStaleRetention/time.Second),
			filter.Device, filter.Protocol, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n device.NeighborEvidence
			n.TenantID = tenant
			if err := rows.Scan(
				&n.ID, &n.AgentID, &n.LocalDeviceAddress, &n.LocalDeviceName,
				&n.LocalIfIndex, &n.LocalPortID, &n.RemoteChassisID,
				&n.RemoteDeviceName, &n.RemotePortID, &n.RemoteManagementAddress,
				&n.RemotePlatform, &n.Capabilities, &n.Protocol, &n.Confidence,
				&n.ObservedAt, &n.FreshUntil,
			); err != nil {
				return err
			}
			out = append(out, n)
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

var _ device.NeighborStore = (*DeviceNeighbors)(nil)
