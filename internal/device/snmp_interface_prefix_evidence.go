// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

// Collect on the same authenticated/configured SNMP connection as the base
// inventory. Extra read-only requests are made only with an evidence channel.
// The finite input budgets derive from the existing whole-message admission:
// every encoded row needs at least eight bytes, and a supported OID needs at
// most256 text bytes. No complete in-wire workload is excluded by a row quota.
func (r *Runtime) collectSNMPPrefixEvidence(ctx context.Context, conn snmpConn, inv *Inventory) {
	inv.prefixAttempted, inv.interfacePrefixes = true, nil
	if inv.addressesUnavailable {
		r.stats.InterfacePrefixUnavailable.Add(1)
		return
	}
	walker, ok := conn.(snmpInterfacePrefixWalker)
	if !ok {
		r.stats.InterfacePrefixUnavailable.Add(1)
		return
	}
	rows, err := collectSNMPInterfacePrefixes(ctx, walker, snmpInterfacePrefixLimits{
		Rows: entity.MaxSNMPInterfacePrefixWireBytes / 8, IndexBytes: entity.MaxSNMPInterfacePrefixWireBytes * 32,
	})
	if err != nil {
		r.stats.InterfacePrefixUnavailable.Add(1)
		r.log.Debug("device interface prefix snapshot unavailable; raw metrics retained",
			"tenant_id", r.cfg.TenantID, "agent_id", r.cfg.AgentID)
		return
	}
	inv.interfacePrefixes = rows
	r.stats.InterfacePrefixSnapshots.Add(1)
}

// Only the configured-target observation may carry the complete prefix set.
// Unavailable/over-budget input publishes nil, never a previous/partial table.
// Its changed fingerprint sends a new collection epoch that fences old data.
func (r *Runtime) withSNMPPrefixMetadata(claim entity.Observation, inv Inventory, at time.Time) entity.Observation {
	if !inv.prefixAttempted || inv.interfacePrefixes == nil {
		return claim
	}
	withPrefixes := claim
	withPrefixes.SNMPInterfacePrefixes = make([]entity.SNMPInterfacePrefix, 0, len(inv.interfacePrefixes))
	for _, row := range inv.interfacePrefixes {
		withPrefixes.SNMPInterfacePrefixes = append(withPrefixes.SNMPInterfacePrefixes,
			entity.SNMPInterfacePrefix{IfIndex: row.IfIndex, Prefix: row.Prefix, OnLink: row.OnLink})
	}
	if normalized, err := withPrefixes.Normalize(at); err == nil {
		return normalized
	}
	r.stats.InterfacePrefixUnavailable.Add(1)
	r.stats.EvidenceErrors.Add(1)
	return claim
}
