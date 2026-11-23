// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

func (r *Runtime) emitSNMPPhysicalInventory(ctx context.Context, conn snmpConn, dev Target, peer netip.Addr) {
	if !dev.PhysicalInventory || r.evidence == nil || ctx.Err() != nil {
		return
	}
	at := time.Now().UTC()
	r.evidenceMu.Lock()
	due, epoch := r.physicalInventoryNext[dev.Address], r.evidenceEpoch
	r.evidenceMu.Unlock()
	if at.Before(due) {
		return
	}
	address, err := netip.ParseAddr(dev.Address)
	if err != nil {
		address = peer
	}
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		r.stats.EvidenceErrors.Add(1)
		return
	}
	pollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	rows, pollErr := pollSNMPPhysicalInventory(pollCtx, conn)
	cancel()
	if ctx.Err() != nil {
		return
	}
	snapshot := &entity.SNMPPhysicalInventory{Version: 1}
	delay := entityEvidenceUnresolvedRetry
	if pollErr == nil && len(rows) != 0 {
		snapshot.Available, snapshot.Components = true, rows
		delay = entityEvidenceRefresh
		r.stats.PhysicalInventorySnapshots.Add(1)
	} else {
		r.stats.PhysicalInventoryUnavailable.Add(1)
	}
	claim := entity.Observation{ID: id, ObservedAt: at, SourceRef: entity.SNMPPhysicalInventorySource,
		Source:                entity.SourceKey{AgentID: r.cfg.AgentID, Kind: entity.DeviceTarget, SourceRef: dev.Address},
		Alias:                 entity.AliasKey{Kind: entity.AddressAlias, Value: address.Unmap().String()},
		SNMPPhysicalInventory: snapshot}
	accepted, unresolved, err := r.evidence.Submit(ctx, []entity.Observation{claim})
	if err != nil {
		r.stats.EvidenceErrors.Add(1)
		r.log.Warn("physical inventory evidence unavailable",
			"tenant_id", r.cfg.TenantID, "agent_id", r.cfg.AgentID)
		return
	}
	switch {
	case accepted == 1 && unresolved == 0:
		r.stats.EvidenceAccepted.Add(1)
	case accepted == 0 && unresolved == 1:
		r.stats.EvidenceUnresolved.Add(1)
		delay = entityEvidenceUnresolvedRetry
	default:
		r.stats.EvidenceErrors.Add(1)
		return
	}
	r.evidenceMu.Lock()
	defer r.evidenceMu.Unlock()
	if epoch != r.evidenceEpoch {
		return
	}
	if r.physicalInventoryNext == nil {
		r.physicalInventoryNext = make(map[string]time.Time)
	}
	r.physicalInventoryNext[dev.Address] = at.Add(delay)
}
