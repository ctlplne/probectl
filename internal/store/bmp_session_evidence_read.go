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
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BMPSessionSource selects one assigned collector and its router within the
// current tenant. The handler authorizes the canonical registry resources.
type BMPSessionSource struct {
	ContextID        string `json:"context_id"`
	RouterID         string `json:"router_id"`
	CollectorAgentID string `json:"collector_agent_id"`
	SourceRef        string `json:"source_ref"`
}

type BMPSessionHistorySelection struct {
	Source BMPSessionSource           `json:"source"`
	From   time.Time                  `json:"from"`
	To     time.Time                  `json:"to"`
	Limit  int                        `json:"-"`
	Peer   string                     `json:"peer,omitempty"`
	After  *BMPSessionHistoryPosition `json:"after,omitempty"`
}

type BMPSessionHistoryPosition struct {
	Nanos      int64  `json:"observed_unix_nanos,string"`
	Connection string `json:"connection_id"`
	Sequence   int64  `json:"sequence,string"`
}

type BMPSessionHistoryPoint struct {
	BMPSessionHistoryPosition
	ObservedAt     time.Time                  `json:"observed_at"`
	Kind           string                     `json:"kind"`
	EvidenceDigest string                     `json:"evidence_digest"`
	CoverageGap    bool                       `json:"coverage_gap"`
	Statistics     *bgp.BMPStatisticsReport   `json:"statistics,omitempty"`
	Lifecycle      *bgp.BMPConnectionEvent    `json:"lifecycle,omitempty"`
	Neighbor       *bgp.BMPNeighborTransition `json:"neighbor,omitempty"`
	UpdateChurn    *bgp.BMPUpdateChurn        `json:"update_churn,omitempty"`
}

// VerifyBMPSessionSourceInScope resolves the operator's source selector
// against the current tenant registry before any history is read.
func VerifyBMPSessionSourceInScope(ctx context.Context, sc tenancy.Scope, source BMPSessionSource) error {
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return err
	}
	for _, value := range []string{source.ContextID, source.RouterID} {
		canonical, err := validRegistryUUID(value)
		if err != nil || value != canonical {
			return ErrBMPSessionEvidenceInput
		}
	}
	for _, value := range []string{source.CollectorAgentID, source.SourceRef} {
		if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value {
			return ErrBMPSessionEvidenceInput
		}
	}
	var present bool
	err := sc.Q.QueryRow(ctx, `SELECT true FROM entity_source_contexts source
 JOIN entities router ON (router.tenant_id,router.context_id,router.id)=
 (source.tenant_id,source.context_id,source.anchor_entity_id) AND router.kind='device'
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.anchor_entity_id=$3
 AND source.agent_id=$4 AND source.source_kind='bmp_peer' AND source.source_ref=$5
 AND (source.expires_at IS NULL OR source.expires_at>transaction_timestamp())`, sc.Tenant.String(),
		source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef).Scan(&present)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBGPRoutingSourceUnavailable
	}
	return err
}

// BMPSessionHistoryInScope requires a repeatable tenant snapshot. Every
// returned observation is rechecked against its original authority and the
// currently active assignment. No grant in the page cursor is trusted.
func BMPSessionHistoryInScope(ctx context.Context, sc tenancy.Scope, selection BMPSessionHistorySelection,
	profile BGPRoutingBudget) ([]BMPSessionHistoryPoint, bool, error) {
	if err := VerifyBMPSessionSourceInScope(ctx, sc, selection.Source); err != nil {
		return nil, false, err
	}
	if !validBMPSessionClock(selection.From) || !validBMPSessionClock(selection.To) || !selection.To.After(selection.From) || selection.Limit < 1 || selection.Limit >= 1<<31 {
		return nil, false, ErrBMPSessionEvidenceInput
	}
	if int64(selection.Limit)+1 > profile.WorkUnits || int64(selection.Limit)+1 > profile.MemoryBytes/512 {
		return nil, false, ErrBGPRoutingBudget
	}
	var afterNanos, afterSequence int64
	var afterConnection string
	if after := selection.After; after != nil {
		connection, err := validRegistryUUID(after.Connection)
		if err != nil || connection != after.Connection || after.Sequence <= 0 ||
			after.Nanos < selection.From.UnixNano() || after.Nanos >= selection.To.UnixNano() {
			return nil, false, ErrBMPSessionEvidenceInput
		}
		afterNanos, afterConnection, afterSequence = after.Nanos, after.Connection, after.Sequence
	}
	var peer netip.Addr
	if selection.Peer != "" {
		var err error
		peer, err = netip.ParseAddr(selection.Peer)
		if err != nil || peer.Zone() != "" || peer.Unmap().String() != selection.Peer || peer.IsMulticast() || peer.IsUnspecified() {
			return nil, false, ErrBMPSessionEvidenceInput
		}
	}
	source := selection.Source
	rows, err := sc.Q.Query(ctx, `SELECT observed_unix_nanos,point.connection_id::text,source_sequence,
 evidence_kind,evidence_digest,coverage_gap,
 CASE WHEN octet_length(evidence::text)<=$13 THEN evidence END,
 sender_serial,origin_serial,COALESCE(point.source_epoch::text,'')
 FROM bmp_session_evidence point JOIN entity_source_contexts current
 ON current.tenant_id=point.tenant_id AND current.context_id=point.context_id AND current.anchor_entity_id=point.router_id
 AND current.agent_id=point.collector_agent_id AND current.source_kind='bmp_peer' AND current.source_ref=point.source_ref
 AND current.routing_epoch IS NOT DISTINCT FROM point.source_epoch
 AND current.assigned_at<=point.observed_at
 AND (current.routing_assigned_at IS NULL OR current.routing_assigned_at<=point.observed_at)
 WHERE point.tenant_id=$1 AND point.context_id=$2 AND point.router_id=$3 AND point.collector_agent_id=$4 AND point.source_ref=$5
 AND point.observed_unix_nanos>=$6 AND point.observed_unix_nanos<$7
 AND ($8::bigint=0 OR (point.observed_unix_nanos,point.connection_id,point.source_sequence)<($8,NULLIF($9::text,'')::uuid,$10))
 AND ($11::inet IS NULL OR point.peer_addr IS NULL OR point.peer_addr=$11)
 ORDER BY point.observed_unix_nanos DESC,point.connection_id DESC,point.source_sequence DESC LIMIT $12`,
		sc.Tenant.String(), source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef,
		selection.From.UnixNano(), selection.To.UnixNano(), afterNanos, afterConnection, afterSequence, peer, selection.Limit+1, profile.MemoryBytes/8)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	points := []BMPSessionHistoryPoint{}
	type originalAuthority struct {
		sender, origin, epoch string
		at                    time.Time
	}
	originals := []originalAuthority{}
	used := int64(0)
	for rows.Next() {
		var point BMPSessionHistoryPoint
		var digest, encoded []byte
		var authority originalAuthority
		if err := rows.Scan(&point.Nanos, &point.Connection, &point.Sequence, &point.Kind, &digest, &point.CoverageGap,
			&encoded, &authority.sender, &authority.origin, &authority.epoch); err != nil {
			return nil, false, err
		}
		used += 512 + int64(len(encoded))*4
		if encoded == nil || used > profile.MemoryBytes {
			return nil, false, ErrBGPRoutingBudget
		}
		var body bmpSessionEvidenceBody
		if err := json.Unmarshal(encoded, &body); err != nil || len(digest) != 32 {
			return nil, false, ErrBMPSessionEvidenceInput
		}
		point.ObservedAt = time.Unix(0, point.Nanos).UTC()
		point.EvidenceDigest = hex.EncodeToString(digest)
		point.Statistics, point.Lifecycle, point.Neighbor = body.Statistics, body.Lifecycle, body.Neighbor
		point.UpdateChurn = body.UpdateChurn
		authority.at = point.ObservedAt
		points, originals = append(points, point), append(originals, authority)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(points) > selection.Limit
	if more {
		points, originals = points[:selection.Limit], originals[:selection.Limit]
	}
	for _, original := range originals {
		bound := BGPRoutingSource{Scope: entity.Scope{TenantID: sc.Tenant.String(), ContextID: source.ContextID},
			RouterID: source.RouterID, CollectorAgentID: source.CollectorAgentID, SourceRef: source.SourceRef,
			SenderSerial: original.sender, OriginSerial: original.origin, ObservedAt: original.at}
		if _, err := routingCredentialAuthorityAt(ctx, sc, bound, false, original.epoch, true); err != nil {
			return nil, false, err
		}
	}
	return points, more, ctx.Err()
}

// The signed nanosecond column must represent the same original instant.
func validBMPSessionClock(value time.Time) bool {
	nanos := value.UnixNano()
	return nanos > 0 && time.Unix(0, nanos).Equal(value)
}
