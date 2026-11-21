// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type BMPSessionSignalPolicy struct {
	LossEnabled   bool
	FlapThreshold int
	FlapWindow    time.Duration
}

type bmpSessionLossEvidence struct {
	confirmed bool
	flapping  bool
}

func verifyBMPSessionLoss(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, input BMPSessionEvidenceInput,
	neighbor *bgp.BMPNeighborTransition, gap bool, policy BMPSessionSignalPolicy) (bmpSessionLossEvidence, error) {
	none := bmpSessionLossEvidence{}
	if gap || neighbor == nil || neighbor.State != "down" {
		return none, nil
	}
	var gapSequence int64
	// Limit continuity to the closest previously recorded gap on this exact
	// authenticated connection. Silence or a closed transport proves no loss.
	err := sc.Q.QueryRow(ctx, `SELECT COALESCE((
 SELECT source_sequence FROM bmp_session_evidence
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND connection_id=$4
 AND coverage_gap AND source_sequence<$5 ORDER BY source_sequence DESC LIMIT 1),0)`,
		source.TenantID, source.CollectorAgentID, source.SourceRef, input.ConnectionID, input.Sequence).Scan(&gapSequence)
	if err != nil {
		return none, err
	}
	peer := neighbor.Peer
	var previousState string
	err = sc.Q.QueryRow(ctx, `SELECT evidence#>>'{neighbor,state}' FROM bmp_session_evidence
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND connection_id=$4
 AND evidence_kind='neighbor' AND peer_addr=$5 AND peer_asn=$6 AND peer_bgp_id=$7
 AND source_sequence>$8 AND source_sequence<$9 ORDER BY source_sequence DESC LIMIT 1`, source.TenantID,
		source.CollectorAgentID, source.SourceRef, input.ConnectionID, peer.PeerAddress, int64(peer.PeerASN),
		peer.BGPIdentifier, gapSequence, input.Sequence).Scan(&previousState)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, nil
	}
	if err != nil || previousState != "up" {
		return none, err
	}
	out := bmpSessionLossEvidence{confirmed: true}
	if policy.FlapThreshold < 2 || policy.FlapThreshold > 100 || policy.FlapWindow <= 0 || policy.FlapWindow > 24*time.Hour {
		return out, nil
	}
	var preceding int
	err = sc.Q.QueryRow(ctx, `SELECT count(*) FROM (
 SELECT 1 FROM bmp_session_evidence
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND connection_id=$4
 AND peer_addr=$5 AND peer_asn=$6 AND peer_bgp_id=$7 AND loss_confirmed
 AND source_sequence>$8 AND source_sequence<$9 AND observed_unix_nanos>=$10
 LIMIT $11) matching_down`, source.TenantID, source.CollectorAgentID, source.SourceRef, input.ConnectionID,
		peer.PeerAddress, int64(peer.PeerASN), peer.BGPIdentifier, gapSequence, input.Sequence,
		input.ObservedAt.Add(-policy.FlapWindow).UnixNano(), policy.FlapThreshold).Scan(&preceding)
	out.flapping = err == nil && preceding == policy.FlapThreshold-1
	return out, err
}

func bmpSessionSignals(source BGPRoutingSource, input BMPSessionEvidenceInput, neighbor *bgp.BMPNeighborTransition,
	loss bmpSessionLossEvidence, policy BMPSessionSignalPolicy) []incident.Signal {
	if !loss.confirmed {
		return nil
	}
	peer := neighbor.Peer
	peerASN := strconv.FormatUint(uint64(peer.PeerASN), 10)
	attributes := map[string]string{
		"network.peer.address":                peer.PeerAddress.String(),
		"probectl.bgp.peer.asn":               peerASN,
		"probectl.bgp.bmp.connection_id":      input.ConnectionID,
		"probectl.bgp.bmp.sequence":           strconv.FormatInt(input.Sequence, 10),
		"probectl.bgp.bmp.observation_digest": hex.EncodeToString(input.Digest[:]),
		"probectl.bgp.bmp.raw_frame_sha256":   neighbor.FrameDigest,
		"probectl.bgp.bmp.peer_down_reason":   strconv.FormatUint(uint64(*neighbor.DownReason), 10),
		"probectl.entity.context_id":          source.ContextID,
		"probectl.entity.id":                  source.RouterID,
		"detector.confidence":                 "90",
	}
	signal := incident.Signal{TenantID: source.TenantID, Plane: "bgp", Severity: incident.SeverityWarning,
		Target: "bmp:" + source.RouterID + ":" + peer.PeerAddress.String() + "/as" + peerASN, OccurredAt: input.ObservedAt, Attributes: attributes}
	out := []incident.Signal{}
	if policy.LossEnabled {
		down := signal
		down.Kind, down.Title, down.Summary = "bgp.session_loss", "BGP peer session lost", "An original BMP Peer Down followed Peer Up within the same continuous router connection."
		out = append(out, down)
	}
	if loss.flapping {
		flap := signal
		flap.Kind, flap.Title, flap.Summary = "bgp.session_flap", "BGP peer session flapping", "Repeated observed Peer Up and Peer Down transitions crossed the configured flap threshold."
		out = append(out, flap)
	}
	return out
}
