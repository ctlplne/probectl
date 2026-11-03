// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"slices"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func loadCurrentTagAgentAddresses(ctx context.Context, sc tenancy.Scope, subject *tags.Subject, maxBytes int64, charge func(...string) error) error {
	// The latest historical site epoch is a negative fence even if its sender
	// or authority has expired. Only currently authorized rows in that epoch
	// can supply facts; older snapshots never revive after a clear/failure.
	rows, err := sc.Q.Query(ctx, `SELECT e.agent_addresses FROM entity_evidence e
	 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.agent_id=$3
	 AND e.source_kind='agent_site' AND e.configured_ref=$3
	 AND e.alias_kind='agent_site_id' AND e.source_ref='agent:label:site'
	 AND e.observed_at=(SELECT max(f.observed_at) FROM entity_evidence f
	  WHERE f.tenant_id=$1 AND f.context_id=$2 AND f.agent_id=$3
	   AND f.source_kind='agent_site' AND f.configured_ref=$3
	   AND f.alias_kind='agent_site_id' AND f.source_ref='agent:label:site'
	   AND f.observed_at<=transaction_timestamp())
	 AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.id LIMIT $4`, subject.TenantID, subject.ContextID, subject.ID, maxBytes/2048+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	var chosen []netip.Addr
	seen := int64(0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		seen++
		if seen >= maxBytes/2048+1 {
			return ErrTagSnapshotBudget
		}
		var addresses []netip.Addr
		if err := rows.Scan(&addresses); err != nil {
			return err
		}
		if err := charge("agent-address-snapshot"); err != nil {
			return err
		}
		for _, address := range addresses {
			if err := charge(address.String()); err != nil {
				return err
			}
		}
		addresses, err = entity.NormalizeAgentAddresses(addresses)
		if err != nil {
			return err
		}
		if seen == 1 {
			chosen = addresses
			continue
		}
		if (chosen == nil) != (addresses == nil) || !slices.Equal(chosen, addresses) {
			return ErrTagSubjectFactsAmbiguous
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	subject.Addresses = chosen
	return ctx.Err()
}
