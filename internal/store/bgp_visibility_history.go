// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const BGPVisibilityHistoryMax = 200

type BGPVisibilityPosition struct {
	ObservedAt time.Time `json:"at"`
	Source     string    `json:"source"`
	Collector  string    `json:"collector"`
}

const bgpVisibilityPointColumns = `source,collector,observed_at,baseline_clock,archive_clock,
 encode(baseline_sha256,'hex'),encode(archive_sha256,'hex'),policy_version,minimum_peer_routes,
 availability,eligible_peers,visible_peers,ambiguous_origin_peers,origins`

const bgpVisibilityHistorySQL = `SELECT ` + bgpVisibilityPointColumns + ` FROM bgp_visibility_points
 WHERE tenant_id=$1 AND monitor_id=$2`

var (
	bgpVisibilitySourceLabel    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	bgpVisibilityCollectorLabel = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	bgpVisibilityPolicyLabel    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
)

// Record assigns a locally generated observation to an existing tenant
// monitor. The replay check and optional incident publication use the same
// tenant transaction, so a retry cannot replace an already accepted point.
func (BGPVisibility) Record(ctx context.Context, sc tenancy.Scope, id string, observation BGPVisibilityObservation) (bool, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return false, err
	}
	if !bgpVisibilityID(id) || !bgpVisibilityObservationValid(observation) {
		return false, ErrBGPVisibilityInput
	}
	baseline, err := bgpVisibilityDigest(observation.BaselineSHA256)
	if err != nil {
		return false, err
	}
	archive, err := bgpVisibilityDigest(observation.ArchiveSHA256)
	if err != nil {
		return false, err
	}
	eligible, visible, ambiguous, origins, err := appendBGPVisibilityCounts(observation)
	if err != nil {
		return false, err
	}
	tag, err := sc.Q.Exec(ctx, `INSERT INTO bgp_visibility_points (tenant_id,monitor_id,source,collector,
 observed_at,baseline_clock,archive_clock,baseline_sha256,archive_sha256,policy_version,minimum_peer_routes,
 availability,eligible_peers,visible_peers,ambiguous_origin_peers,origins)
 SELECT monitor.tenant_id,monitor.id,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb
 FROM bgp_visibility_monitors monitor WHERE monitor.tenant_id=$1 AND monitor.id=$2
 ON CONFLICT (tenant_id,monitor_id,source,collector,observed_at) DO NOTHING`, sc.Tenant.String(), id,
		observation.Source, observation.Collector, observation.ObservedAt, observation.BaselineClock,
		observation.ArchiveClock, baseline, archive, observation.PolicyVersion, observation.MinimumPeerRoutes,
		observation.Availability, eligible, visible, ambiguous, origins)
	if err != nil || tag.RowsAffected() == 1 {
		return err == nil, err
	}
	var same bool
	err = sc.Q.QueryRow(ctx, `SELECT (baseline_clock,archive_clock,baseline_sha256,archive_sha256,policy_version,
 minimum_peer_routes,availability,eligible_peers,visible_peers,ambiguous_origin_peers,origins)
 IS NOT DISTINCT FROM ($6::timestamptz,$7::timestamptz,$8::bytea,$9::bytea,$10::text,
 $11::integer,$12::text,$13::integer,$14::integer,$15::integer,$16::jsonb)
 FROM bgp_visibility_points WHERE tenant_id=$1 AND monitor_id=$2 AND source=$3 AND collector=$4 AND observed_at=$5`,
		sc.Tenant.String(), id, observation.Source, observation.Collector, observation.ObservedAt, observation.BaselineClock,
		observation.ArchiveClock, baseline, archive, observation.PolicyVersion, observation.MinimumPeerRoutes,
		observation.Availability, eligible, visible, ambiguous, origins).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrBGPVisibilityMissing
	}
	if err == nil && !same {
		return false, ErrBGPVisibilityConflict
	}
	return false, err
}

func (BGPVisibility) History(ctx context.Context, sc tenancy.Scope, id string, before time.Time, after *BGPVisibilityPosition, limit int) ([]BGPVisibilityObservation, bool, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return nil, false, err
	}
	if !bgpVisibilityID(id) || before.IsZero() || limit < 1 || limit > BGPVisibilityHistoryMax {
		return nil, false, ErrBGPVisibilityInput
	}
	if _, err := BGPVisibilityMonitorInScope(ctx, sc, id); err != nil {
		return nil, false, err
	}
	var at *time.Time
	var source, collector string
	if after != nil {
		if after.ObservedAt.IsZero() || !after.ObservedAt.Before(before) || !bgpVisibilitySourceLabel.MatchString(after.Source) ||
			!bgpVisibilityCollectorLabel.MatchString(after.Collector) {
			return nil, false, ErrBGPVisibilityInput
		}
		at, source, collector = &after.ObservedAt, after.Source, after.Collector
	}
	rows, err := sc.Q.Query(ctx, bgpVisibilityHistorySQL+`
 AND observed_at<$3 AND observed_at<=COALESCE($4::timestamptz,$3::timestamptz)
 AND ($4::timestamptz IS NULL OR observed_at<$4
 OR (observed_at=$4 AND (source,collector)>($5::text,$6::text)))
 ORDER BY observed_at DESC,source,collector LIMIT $7`, sc.Tenant.String(), id, before, at, source, collector, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	points := []BGPVisibilityObservation{}
	for rows.Next() {
		observation, err := scanBGPVisibilityObservation(rows)
		if err != nil {
			return nil, false, err
		}
		points = append(points, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(points) > limit {
		return points[:limit], true, nil
	}
	return points, false, nil
}

func (BGPVisibility) Previous(ctx context.Context, sc tenancy.Scope, id string, point BGPVisibilityObservation) (BGPVisibilityObservation, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return BGPVisibilityObservation{}, err
	}
	if !bgpVisibilityID(id) || !bgpVisibilityObservationValid(point) {
		return BGPVisibilityObservation{}, ErrBGPVisibilityInput
	}
	return scanBGPVisibilityObservation(sc.Q.QueryRow(ctx, bgpVisibilityHistorySQL+`
 AND source=$3 AND collector=$4 AND observed_at<$5 ORDER BY observed_at DESC LIMIT 1`,
		sc.Tenant.String(), id, point.Source, point.Collector, point.ObservedAt))
}

func scanBGPVisibilityObservation(row pgx.Row) (BGPVisibilityObservation, error) {
	var out BGPVisibilityObservation
	var eligible, visible, ambiguous *int
	var origins []byte
	err := row.Scan(&out.Source, &out.Collector, &out.ObservedAt, &out.BaselineClock, &out.ArchiveClock,
		&out.BaselineSHA256, &out.ArchiveSHA256, &out.PolicyVersion, &out.MinimumPeerRoutes,
		&out.Availability, &eligible, &visible, &ambiguous, &origins)
	if err != nil {
		return BGPVisibilityObservation{}, err
	}
	if out.Availability == "available" {
		if eligible == nil || visible == nil || ambiguous == nil || len(origins) == 0 {
			return BGPVisibilityObservation{}, ErrBGPVisibilityInput
		}
		out.Counts = &BGPVisibilityCounts{EligiblePeers: *eligible, VisiblePeers: *visible, AmbiguousOriginPeers: *ambiguous}
		if err := json.Unmarshal(origins, &out.Counts.Origins); err != nil {
			return BGPVisibilityObservation{}, err
		}
	}
	return out, nil
}

func bgpVisibilityObservationValid(point BGPVisibilityObservation) bool {
	if !bgpVisibilitySourceLabel.MatchString(point.Source) || !bgpVisibilityCollectorLabel.MatchString(point.Collector) ||
		!bgpVisibilityPolicyLabel.MatchString(point.PolicyVersion) || point.MinimumPeerRoutes < 1 ||
		point.ObservedAt.IsZero() || point.BaselineClock.IsZero() || point.BaselineClock.After(point.ArchiveClock) ||
		point.ArchiveClock.After(point.ObservedAt) || !point.ObservedAt.Equal(point.ObservedAt.Truncate(time.Microsecond)) {
		return false
	}
	switch point.Availability {
	case "available", "empty_cohort", "archive_gap", "session_change":
		return true
	default:
		return false
	}
}

func bgpVisibilityDigest(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrBGPVisibilityInput
	}
	digest, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(digest) != value {
		return nil, ErrBGPVisibilityInput
	}
	return digest, nil
}
