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
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRPKIHistoryObservation carries the validator and origin when an owned
// original was committed. The retained source still authorizes every read.
type BGPRPKIHistoryObservation struct {
	Origin  *uint32              `json:"origin_asn,omitempty"`
	Posture opendata.RPKIPosture `json:"posture"`
}

type bgpRPKIRetainedObservation struct {
	BGPRPKIHistoryObservation
	ValidatorValidUntil time.Time `json:"validator_valid_until"`
}

const maxRPKIHistoryPaths = 128

// WithRPKIHistory retains original validation for watched owned routes using
// the deployment's already configured validator. It leaves route digests and
// source authentication independent of the validator generation.
func (routing BGPRouting) WithRPKIHistory(source *opendata.Enricher) BGPRouting {
	routing.rpkiHistory = source
	return routing
}

func captureBGPChangeRPKI(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, snapshot opendata.RPKISnapshot,
	changes []routingPreparedChange, budget BGPRoutingBudget) ([]byte, error) {
	if !snapshot.UsableAt(source.ObservedAt) || len(changes) == 0 || len(changes) > 8192 {
		return nil, ctx.Err()
	}
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, len(changes))
	for _, change := range changes {
		if !change.Withdraw {
			prefixes = append(prefixes, change.Prefix.String())
		}
	}
	if len(prefixes) == 0 {
		return nil, ctx.Err()
	}
	rows, err := sc.Q.Query(ctx, `SELECT DISTINCT prefix::text FROM bgp_visibility_monitors
 WHERE tenant_id=$1 AND prefix IN (SELECT candidate::cidr FROM unnest($2::text[]) AS candidate) AND created_at<=$3 LIMIT $4`,
		source.TenantID, prefixes, source.ObservedAt, maxRPKIHistoryPaths+1)
	if err != nil {
		return nil, err
	}
	watched := make(map[string]bool)
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err != nil {
			rows.Close()
			return nil, err
		}
		watched[prefix] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(watched) > maxRPKIHistoryPaths {
		return nil, ctx.Err()
	}
	paths := make(map[string]BGPRoutingChange)
	for i, change := range changes {
		if !change.Withdraw && watched[change.Prefix.String()] {
			if len(paths) == maxRPKIHistoryPaths {
				return nil, ctx.Err()
			}
			paths[strconv.Itoa(i)] = change.BGPRoutingChange
		}
	}
	return captureBGPRPKIHistory(ctx, snapshot, source.ObservedAt, paths, budget)
}

func captureBGPBaselineRPKI(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, family int,
	snapshot opendata.RPKISnapshot, budget BGPRoutingBudget) ([]byte, error) {
	if !snapshot.UsableAt(source.ObservedAt) {
		return nil, ctx.Err()
	}
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT entry.prefix::text,entry.has_path_id,entry.path_id,
 CASE WHEN octet_length(entry.segments::text)<=$8 THEN entry.segments::text END
 FROM bgp_routing_entries entry WHERE entry.tenant_id=$1 AND entry.context_id=$2 AND entry.view_id=$3 AND entry.generation=$4
 AND family(entry.prefix)=$5 AND EXISTS (SELECT 1 FROM bgp_visibility_monitors m
 WHERE m.tenant_id=$1 AND m.prefix=entry.prefix AND m.created_at<=$6) LIMIT $7`,
		source.TenantID, source.ContextID, ref.ID, ref.Generation, family, source.ObservedAt, maxRPKIHistoryPaths+1, budget.MemoryBytes/maxRPKIHistoryPaths/8)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := make(map[string]BGPRoutingChange)
	for rows.Next() {
		if len(paths) == maxRPKIHistoryPaths {
			return nil, ctx.Err()
		}
		var prefix string
		var hasPathID bool
		var pathID int64
		var segments []byte
		if err := rows.Scan(&prefix, &hasPathID, &pathID, &segments); err != nil {
			return nil, err
		}
		if len(segments) == 0 {
			continue
		}
		network, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, err
		}
		var path []BGPRoutingSegment
		if err := json.Unmarshal(segments, &path); err != nil {
			return nil, err
		}
		key := prefix + "/" + strconv.FormatBool(hasPathID) + "/" + strconv.FormatInt(pathID, 10)
		paths[key] = BGPRoutingChange{Prefix: network, Segments: path}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return captureBGPRPKIHistory(ctx, snapshot, source.ObservedAt, paths, budget)
}

func captureBGPRPKIHistory(ctx context.Context, snapshot opendata.RPKISnapshot, observedAt time.Time,
	paths map[string]BGPRoutingChange, budget BGPRoutingBudget) ([]byte, error) {
	if len(paths) == 0 {
		return nil, ctx.Err()
	}
	population := int64(len(paths))
	perPath := BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / population / 8,
		WorkUnits: budget.WorkUnits / population / 8, StateBytes: budget.StateBytes}
	metadata := make(map[string]json.RawMessage, len(paths))
	remaining := budget.MemoryBytes / 8
	for key, path := range paths {
		fields, err := routingFlowPathFields(ctx, []BGPRoutingChange{path}, perPath)
		if errors.Is(err, ErrBGPRoutingBudget) {
			continue
		}
		if err != nil {
			return nil, err
		}
		origin := fields[0].OriginAS
		verdict, err := opendata.AssessRPKIPosture(ctx, snapshot, observedAt, path.Prefix, origin, false, perPath.MemoryBytes, perPath.WorkUnits)
		if errors.Is(err, opendata.ErrRPKIVRPBudget) {
			continue
		}
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(bgpRPKIRetainedObservation{
			BGPRPKIHistoryObservation: BGPRPKIHistoryObservation{Origin: origin, Posture: verdict}, ValidatorValidUntil: snapshot.ValidUntil,
		})
		if err != nil {
			return nil, err
		}
		if len(body) > 256<<10 {
			continue
		}
		charge := int64(len(body) + len(key) + 64)
		if charge > remaining {
			return nil, ctx.Err()
		}
		remaining -= charge
		metadata[key] = body
	}
	return json.Marshal(metadata)
}

// ReadBGPRPKIHistoryInScope checks current source access and compares retained
// validation with the exact original route. Missing historical evidence is
// unknown. Today's validator never fills a past observation.
func ReadBGPRPKIHistoryInScope(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix, row BGPASPathHistoryRecord,
	budget BGPRoutingBudget, authorize RoutingChangeAuthorizer) (BGPRPKIHistoryObservation, error) {
	unknown := BGPRPKIHistoryObservation{Posture: opendata.RPKIPosture{Status: "unknown", Reason: "historical_validator_unavailable", Covering: []opendata.RPKIVRP{}}}
	if _, err := VerifyBGPASPathHistorySourceInScope(ctx, sc, prefix, row, budget, authorize); err != nil {
		return unknown, err
	}
	if len(row.Current) == 0 {
		return unknown, ErrBGPRoutingRouteMissing
	}
	if int64(len(row.Current)+len(row.RPKI)) > budget.MemoryBytes/8 {
		return unknown, ErrBGPRoutingBudget
	}
	var original struct {
		Segments []BGPRoutingSegment `json:"segments"`
	}
	if err := json.Unmarshal(row.Current, &original); err != nil {
		return unknown, err
	}
	fields, err := routingFlowPathFields(ctx, []BGPRoutingChange{{Prefix: prefix, Segments: original.Segments}}, budget)
	if err != nil {
		return unknown, err
	}
	unknown.Origin = fields[0].OriginAS
	if len(row.RPKI) == 0 {
		return unknown, ctx.Err()
	}
	var retained bgpRPKIRetainedObservation
	if err := json.Unmarshal(row.RPKI, &retained); err != nil {
		return unknown, err
	}
	posture := &retained.Posture
	retainedOrigin, exactOrigin := retained.Origin, unknown.Origin
	if (retainedOrigin == nil) != (exactOrigin == nil) ||
		retainedOrigin != nil && *retainedOrigin != *exactOrigin || posture.Suggestion != nil ||
		posture.ValidatorObservedAt == nil || posture.ValidatorObservedAt.Truncate(time.Microsecond).After(row.ObservedAt) ||
		!retained.ValidatorValidUntil.After(row.ObservedAt) {
		return unknown, errRoutingCaptureFormat
	}
	if _, err := bgpVisibilityDigest(posture.ValidatorVersion); err != nil {
		return unknown, err
	}
	status, err := opendata.RPKICoveringVerdict(ctx, prefix, exactOrigin, posture.Covering, budget.MemoryBytes, budget.WorkUnits)
	if err != nil {
		return unknown, err
	}
	if status != posture.Status {
		return unknown, errRoutingCaptureFormat
	}
	return retained.BGPRPKIHistoryObservation, ctx.Err()
}
