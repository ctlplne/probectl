// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type DevicePhysicalInventoryEvidence struct {
	EvidenceID string
	ObservedAt time.Time
	Snapshot   entity.SNMPPhysicalInventory
}

// CurrentDevicePhysicalInventoryInScope reads one exact authorized evidence
// source. The latest epoch fences older values, including when its evidence
// credential has expired or the newest poll explicitly reports unavailable.
func (r *EntityRegistry) CurrentDevicePhysicalInventoryInScope(ctx context.Context, sc tenancy.Scope,
	selected entity.Scope, deviceID string, source entity.SourceKey) (DevicePhysicalInventoryEvidence, error) {
	var evidence DevicePhysicalInventoryEvidence
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || selected.TenantID != tenant.String() {
		return evidence, entity.ErrScopeMismatch
	}
	if sc.Q == nil {
		return evidence, ErrEntityRegistryUnavailable
	}
	selected, err := selected.Normalize()
	if err != nil {
		return evidence, err
	}
	source, err = source.Normalize()
	if err != nil || source.Kind != entity.DeviceTarget {
		return evidence, entity.ErrInvalidSource
	}
	if id, err := uuid.Parse(deviceID); err != nil || id == uuid.Nil || id.String() != deviceID {
		return evidence, entity.ErrInvalidClaim
	}
	var document []byte
	err = sc.Q.QueryRow(ctx, `
WITH newest AS (
	SELECT max(f.observed_at) AS at FROM entity_evidence f
	WHERE f.tenant_id=$1 AND f.context_id=$2 AND f.entity_id=$3
	AND f.agent_id=$4 AND f.source_kind='device_target' AND f.configured_ref=$5
	AND f.source_ref=$6 AND f.alias_kind='address' AND f.observed_at<=transaction_timestamp()
), candidates AS MATERIALIZED (
	SELECT e.id,e.observation_id,e.observed_at,e.snmp_physical_inventory AS snapshot
	FROM entity_evidence e JOIN newest ON newest.at=e.observed_at
	JOIN entities device ON (device.tenant_id,device.context_id,device.id)=(e.tenant_id,e.context_id,e.entity_id) AND device.kind='device'
	JOIN entity_source_contexts source ON
	 (source.tenant_id,source.context_id,source.agent_id,source.source_kind,source.source_ref,source.anchor_entity_id)=
	 (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref,e.entity_id)
	WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.entity_id=$3
	AND e.agent_id=$4 AND e.source_kind='device_target' AND e.configured_ref=$5
	AND e.source_ref=$6 AND e.alias_kind='address' AND e.support_evidence_id IS NULL
	AND `+currentEntityEvidenceSnapshotSQL(false)+` ORDER BY e.observation_id LIMIT 9
)
SELECT c.id::text,c.observed_at,c.snapshot FROM candidates c
WHERE (SELECT count(*) FROM candidates) <= 8
AND NOT EXISTS (SELECT 1 FROM candidates other WHERE other.snapshot IS DISTINCT FROM c.snapshot)
ORDER BY c.observation_id LIMIT 1`,
		selected.TenantID, selected.ContextID, deviceID, source.AgentID, source.SourceRef, entity.SNMPPhysicalInventorySource).
		Scan(&evidence.EvidenceID, &evidence.ObservedAt, &document)
	if err != nil {
		return DevicePhysicalInventoryEvidence{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence.Snapshot); err != nil {
		return DevicePhysicalInventoryEvidence{}, entity.ErrInvalidClaim
	}
	valid, err := entity.NormalizeSNMPPhysicalInventory(&evidence.Snapshot)
	if err != nil {
		return DevicePhysicalInventoryEvidence{}, err
	}
	evidence.Snapshot = *valid
	return evidence, ctx.Err()
}
