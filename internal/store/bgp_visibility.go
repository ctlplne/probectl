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
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const MaxBGPVisibilityMonitors = 128

var (
	ErrBGPVisibilityInput    = errors.New("bgp visibility: invalid monitor or observation")
	ErrBGPVisibilityMissing  = errors.New("bgp visibility: monitor missing")
	ErrBGPVisibilityConflict = errors.New("bgp visibility: conflicting observation at an accepted source clock")
)

type BGPVisibility struct{}

type BGPVisibilityMonitor struct {
	ID                        string       `json:"id"`
	Prefix                    netip.Prefix `json:"prefix"`
	MinimumVisibleBasisPoints int          `json:"minimum_visible_basis_points"`
	AlertOnPartial            bool         `json:"alert_on_partial"`
	AlertOnLoss               bool         `json:"alert_on_loss"`
	CreatedAt                 time.Time    `json:"created_at"`
}

type BGPVisibilityCounts struct {
	EligiblePeers        int                          `json:"eligible_peers"`
	VisiblePeers         int                          `json:"visible_peers"`
	AmbiguousOriginPeers int                          `json:"ambiguous_origin_peers"`
	Origins              []bgp.PublicVisibilityOrigin `json:"origins"`
}

type BGPVisibilityObservation struct {
	Source            string               `json:"source"`
	Collector         string               `json:"collector"`
	ObservedAt        time.Time            `json:"observed_at"`
	BaselineClock     time.Time            `json:"baseline_clock"`
	ArchiveClock      time.Time            `json:"archive_clock"`
	BaselineSHA256    string               `json:"baseline_sha256"`
	ArchiveSHA256     string               `json:"archive_sha256"`
	PolicyVersion     string               `json:"policy_version"`
	MinimumPeerRoutes int                  `json:"minimum_peer_routes"`
	Availability      string               `json:"availability"`
	Counts            *BGPVisibilityCounts `json:"counts,omitempty"`
}

const bgpVisibilityMonitorColumns = `id::text,prefix::text,minimum_visible_basis_points,alert_on_partial,alert_on_loss,created_at`

func (BGPVisibility) ListMonitors(ctx context.Context, sc tenancy.Scope) ([]BGPVisibilityMonitor, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT `+bgpVisibilityMonitorColumns+`
 FROM bgp_visibility_monitors WHERE tenant_id=$1 ORDER BY prefix LIMIT $2`, sc.Tenant.String(), MaxBGPVisibilityMonitors+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	monitors := []BGPVisibilityMonitor{}
	for rows.Next() {
		monitor, err := scanBGPVisibilityMonitor(rows)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, monitor)
	}
	if len(monitors) > MaxBGPVisibilityMonitors {
		return nil, ErrBGPVisibilityInput
	}
	return monitors, rows.Err()
}

func (BGPVisibility) SaveMonitor(ctx context.Context, sc tenancy.Scope, monitor BGPVisibilityMonitor) (BGPVisibilityMonitor, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return BGPVisibilityMonitor{}, err
	}
	if !monitor.Prefix.IsValid() || monitor.Prefix != monitor.Prefix.Masked() || monitor.Prefix.Addr().Is4In6() ||
		monitor.MinimumVisibleBasisPoints < 1 || monitor.MinimumVisibleBasisPoints > 10000 {
		return BGPVisibilityMonitor{}, ErrBGPVisibilityInput
	}
	if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
		return BGPVisibilityMonitor{}, err
	}
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('bgp-visibility:'||$1::text,0))`, sc.Tenant.String()); err != nil {
		return BGPVisibilityMonitor{}, err
	}
	var count int
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_visibility_monitors WHERE tenant_id=$1 AND prefix<>$2`,
		sc.Tenant.String(), monitor.Prefix).Scan(&count); err != nil {
		return BGPVisibilityMonitor{}, err
	}
	if count >= MaxBGPVisibilityMonitors {
		return BGPVisibilityMonitor{}, ErrBGPVisibilityInput
	}
	return scanBGPVisibilityMonitor(sc.Q.QueryRow(ctx, `INSERT INTO bgp_visibility_monitors
 (tenant_id,prefix,minimum_visible_basis_points,alert_on_partial,alert_on_loss) VALUES ($1,$2,$3,$4,$5)
 ON CONFLICT (tenant_id,prefix) DO UPDATE SET minimum_visible_basis_points=EXCLUDED.minimum_visible_basis_points,
 alert_on_partial=EXCLUDED.alert_on_partial,alert_on_loss=EXCLUDED.alert_on_loss RETURNING `+bgpVisibilityMonitorColumns,
		sc.Tenant.String(), monitor.Prefix, monitor.MinimumVisibleBasisPoints, monitor.AlertOnPartial, monitor.AlertOnLoss))
}

func (BGPVisibility) DeleteMonitor(ctx context.Context, sc tenancy.Scope, id string) error {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return err
	}
	if !bgpVisibilityID(id) {
		return ErrBGPVisibilityInput
	}
	if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
		return err
	}
	tag, err := sc.Q.Exec(ctx, `DELETE FROM bgp_visibility_monitors WHERE tenant_id=$1 AND id=$2`, sc.Tenant.String(), id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrBGPVisibilityMissing
	}
	return err
}

func BGPVisibilityMonitorInScope(ctx context.Context, sc tenancy.Scope, id string) (BGPVisibilityMonitor, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return BGPVisibilityMonitor{}, err
	}
	if !bgpVisibilityID(id) {
		return BGPVisibilityMonitor{}, ErrBGPVisibilityInput
	}
	return scanBGPVisibilityMonitor(sc.Q.QueryRow(ctx, `SELECT `+bgpVisibilityMonitorColumns+`
 FROM bgp_visibility_monitors WHERE tenant_id=$1 AND id=$2`, sc.Tenant.String(), id))
}

func scanBGPVisibilityMonitor(row pgx.Row) (BGPVisibilityMonitor, error) {
	var out BGPVisibilityMonitor
	var prefix string
	err := row.Scan(&out.ID, &prefix, &out.MinimumVisibleBasisPoints, &out.AlertOnPartial, &out.AlertOnLoss, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BGPVisibilityMonitor{}, ErrBGPVisibilityMissing
	}
	if err != nil {
		return BGPVisibilityMonitor{}, err
	}
	out.Prefix, err = netip.ParsePrefix(prefix)
	return out, err
}

func verifyBGPVisibilityScope(ctx context.Context, sc tenancy.Scope) error {
	id, ok := tenancy.FromContext(ctx)
	if !ok || id != sc.Tenant || sc.Q == nil {
		return tenancy.ErrNoTenant
	}
	return nil
}

func bgpVisibilityID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func appendBGPVisibilityCounts(observation BGPVisibilityObservation) (eligible, visible, ambiguous *int, origins []byte, err error) {
	counts := observation.Counts
	if observation.Availability != "available" {
		if counts != nil {
			err = ErrBGPVisibilityInput
		}
		return
	}
	if counts == nil || counts.EligiblePeers < 1 || counts.EligiblePeers > 65535 || counts.VisiblePeers < 0 ||
		counts.VisiblePeers > counts.EligiblePeers || counts.AmbiguousOriginPeers < 0 || counts.AmbiguousOriginPeers > counts.VisiblePeers ||
		len(counts.Origins) > 4096 {
		return nil, nil, nil, nil, ErrBGPVisibilityInput
	}
	last := uint32(0)
	for _, origin := range counts.Origins {
		if origin.ASN <= last || origin.Peers < 1 || origin.Peers > counts.VisiblePeers {
			return nil, nil, nil, nil, ErrBGPVisibilityInput
		}
		last = origin.ASN
	}
	originCounts := counts.Origins
	if originCounts == nil {
		originCounts = []bgp.PublicVisibilityOrigin{}
	}
	origins, err = json.Marshal(originCounts)
	return &counts.EligiblePeers, &counts.VisiblePeers, &counts.AmbiguousOriginPeers, origins, err
}
