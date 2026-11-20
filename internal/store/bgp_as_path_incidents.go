// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPASPathIncident struct {
	ID       string `json:"id"`
	Relation string `json:"relation"`
}

// BGPASPathIncidentsInScope returns links a caller can present after checking
// incident.read. Public links share the exact approved archive and monitor.
// Owned links share current routing identity, prefix and an explicit window.
func BGPASPathIncidentsInScope(ctx context.Context, sc tenancy.Scope, monitor BGPVisibilityMonitor, row BGPASPathHistoryRecord,
	public *BGPASPathPublicSource, window time.Duration, limit int) ([]BGPASPathIncident, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return nil, err
	}
	if limit < 1 || !bgpVisibilityID(monitor.ID) || !monitor.Prefix.IsValid() {
		return nil, ErrBGPVisibilityInput
	}
	relation := "same_public_archive"
	var rows pgx.Rows
	var err error
	switch {
	case public != nil && public.Coverage == "":
		if err := validateBGPASPathPublicSource(*public); err != nil {
			return nil, err
		}
		rows, err = sc.Q.Query(ctx, `SELECT event.id::text
 FROM incidents event JOIN incident_signals signal ON signal.tenant_id=event.tenant_id AND signal.incident_id=event.id
 WHERE event.tenant_id=$1 AND signal.prefix=$2 AND signal.plane='bgp'
 AND signal.kind IN ('bgp.visibility_partial','bgp.visibility_lost')
 AND signal.attributes->>'probectl.bgp.visibility.monitor_id'=$3
 AND signal.attributes->>'probectl.bgp.visibility.source'=$4
 AND signal.attributes->>'probectl.bgp.visibility.collector'=$5
 AND signal.attributes->>'probectl.bgp.visibility.baseline_sha256'=$6
 AND signal.attributes->>'probectl.bgp.visibility.archive_sha256'=$7
 GROUP BY event.id ORDER BY max(signal.occurred_at) DESC,event.id LIMIT $8`,
			sc.Tenant.String(), monitor.Prefix.String(), monitor.ID, public.Source, public.Collector, public.BaselineSHA256, public.ArchiveSHA256, limit)
	case row.SourceKind == "router_bmp" && row.Kind != "baseline" && window > 0:
		relation = "nearby_owned_change"
		if !bgpVisibilityID(row.ContextID) || !bgpVisibilityID(row.RouterID) {
			return nil, ErrBGPVisibilityInput
		}
		rows, err = sc.Q.Query(ctx, `SELECT id::text FROM incidents
 WHERE tenant_id=$1 AND entity_context_id=$2 AND entity_id=$3 AND prefix=$4
 AND started_at>=$5 AND started_at<=$6 ORDER BY started_at DESC,id LIMIT $7`,
			sc.Tenant.String(), row.ContextID, row.RouterID, monitor.Prefix.String(), row.ObservedAt.Add(-window), row.ObservedAt.Add(window), limit)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var links []BGPASPathIncident
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		links = append(links, BGPASPathIncident{ID: id, Relation: relation})
	}
	return links, rows.Err()
}
