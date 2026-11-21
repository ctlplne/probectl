// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPRPKIHijack struct {
	IncidentID string    `json:"incident_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// BGPRPKIHijacksInScope lists bounded same-prefix and same-origin incident
// candidates in the owned context. The caller authorizes every incident.
func BGPRPKIHijacksInScope(ctx context.Context, sc tenancy.Scope, contextID string, prefix netip.Prefix, origin uint32,
	from, until time.Time) ([]BGPRPKIHijack, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return nil, err
	}
	if !bgpVisibilityID(contextID) || !prefix.IsValid() || prefix != prefix.Masked() || origin == 0 ||
		from.IsZero() || !from.Before(until) {
		return nil, ErrBGPVisibilityInput
	}
	rows, err := sc.Q.Query(ctx, `SELECT event.id::text,max(signal.occurred_at)
 FROM incidents event JOIN incident_signals signal ON signal.tenant_id=event.tenant_id AND signal.incident_id=event.id
 WHERE event.tenant_id=$1 AND event.entity_context_id=$2 AND signal.prefix=$3
   AND signal.plane='bgp' AND signal.kind='bgp.possible_hijack' AND signal.attributes->>'new_origin_asn'=$4
   AND signal.occurred_at>=$5 AND signal.occurred_at<=$6
 GROUP BY event.id ORDER BY max(signal.occurred_at) DESC,event.id LIMIT 16`,
		sc.Tenant.String(), contextID, prefix.String(), strconv.FormatUint(uint64(origin), 10), from, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []BGPRPKIHijack
	for rows.Next() {
		var item BGPRPKIHijack
		if err := rows.Scan(&item.IncidentID, &item.ObservedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
