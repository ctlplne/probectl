// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrBMPSessionEvidenceInput    = errors.New("store: invalid BMP session evidence")
	ErrBMPSessionEvidenceConflict = errors.New("store: conflicting or closed BMP session evidence sequence")
)

// BMPSessionEvidenceInput carries the transport-verified collector identity
// and the router authenticated by that collector. The store resolves the
// canonical context and device through the current assignment.
type BMPSessionEvidenceInput struct {
	CollectorAgentID, SenderSerial, SourceRef, OriginSerial string
	ConnectionID                                            string
	Sequence                                                int64
	ObservedAt                                              time.Time
	Frame                                                   []byte
	TransportClosed                                         bool
	UpdateWindow                                            *agentv1.BmpSessionUpdateWindow
	Digest                                                  [32]byte
}

const (
	bmpSessionStatistics = "statistics"
	bmpSessionNeighbor   = "neighbor"
	bmpSessionChurn      = "update_churn"
	bmpSessionInitiation = "initiation"
	bmpSessionTerminated = "termination"
	bmpSessionClosed     = "transport_closed"
)

type bmpSessionEvidenceBody struct {
	Statistics  *bgp.BMPStatisticsReport   `json:"statistics,omitempty"`
	Lifecycle   *bgp.BMPConnectionEvent    `json:"lifecycle,omitempty"`
	Neighbor    *bgp.BMPNeighborTransition `json:"neighbor,omitempty"`
	UpdateChurn *bgp.BMPUpdateChurn        `json:"update_churn,omitempty"`
}

type BMPSessionWriteResult struct {
	CoverageGap bool
	Signals     []incident.Signal
}

// RecordBMPSessionEvidenceInScope durably records one original, ordered
// observation. Exact retries return the original coverage result.
func RecordBMPSessionEvidenceInScope(ctx context.Context, sc tenancy.Scope, input BMPSessionEvidenceInput, budget bgp.PeerMessageBudget, policy BMPSessionSignalPolicy) (BMPSessionWriteResult, error) {
	connection, err := validRegistryUUID(input.ConnectionID)
	if err != nil || connection != input.ConnectionID || input.Sequence <= 0 || input.Sequence == math.MaxInt64 ||
		!validBMPSessionClock(input.ObservedAt) || input.Digest == ([32]byte{}) {
		return BMPSessionWriteResult{}, ErrBMPSessionEvidenceInput
	}
	source := BGPRoutingSource{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial,
		SourceRef: input.SourceRef, OriginSerial: input.OriginSerial, ObservedAt: input.ObservedAt}
	source.TenantID = sc.Tenant.String()
	source, err = resolveOwnedRouterEvidenceSource(ctx, sc, source)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
		return BMPSessionWriteResult{}, err
	}
	// A Peer Down can emit an audited incident. Lock incident correlation,
	// then audit, before taking credential or assignment row locks. Entity
	// evidence writers already hold the audit lock while locking those rows.
	if len(input.Frame) >= 6 && input.Frame[5] == 2 && (policy.LossEnabled || policy.flapEnabled()) {
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
			return BMPSessionWriteResult{}, err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return BMPSessionWriteResult{}, err
		}
	}
	authority, err := routingBaseAuthority(ctx, sc, source)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	kind, data, err := decodeBMPSessionEvidence(ctx, input, budget)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	return writeBMPSessionEvidence(ctx, sc, source, authority.Epoch, input, kind, data, policy)
}

func decodeBMPSessionEvidence(ctx context.Context, input BMPSessionEvidenceInput, budget bgp.PeerMessageBudget) (string, bmpSessionEvidenceBody, error) {
	data := bmpSessionEvidenceBody{}
	if input.UpdateWindow != nil {
		if input.TransportClosed || len(input.Frame) != 0 {
			return "", data, ErrBMPSessionEvidenceInput
		}
		window, err := bgp.ParseBMPUpdateWindow(input.UpdateWindow, input.ObservedAt)
		if err != nil {
			return "", data, err
		}
		data.UpdateChurn = &window
		return bmpSessionChurn, data, nil
	}
	if input.TransportClosed {
		if len(input.Frame) != 0 {
			return "", data, ErrBMPSessionEvidenceInput
		}
		return bmpSessionClosed, data, nil
	}
	if len(input.Frame) < 6 {
		return "", data, ErrBMPSessionEvidenceInput
	}
	var kind string
	switch input.Frame[5] {
	case 1:
		stats, err := bgp.ParseBMPStatisticsReport(ctx, input.Frame, budget)
		if err != nil {
			return "", data, err
		}
		if stats.Peer.PeerType != 0 {
			return "", data, ErrBGPRoutingSourceUnavailable
		}
		kind, data.Statistics = bmpSessionStatistics, &stats
	case 2, 3:
		neighbor, err := bgp.DecodeBMPNeighborTransition(ctx, input.Frame, budget)
		if err != nil {
			return "", data, err
		}
		kind, data.Neighbor = bmpSessionNeighbor, &neighbor
	case 4, 5:
		lifecycle, err := bgp.ParseBMPConnectionEvent(ctx, input.Frame, budget)
		if err != nil {
			return "", data, err
		}
		kind, data.Lifecycle = bmpSessionInitiation, &lifecycle
		if lifecycle.Terminated {
			kind = bmpSessionTerminated
		}
	default:
		return "", data, ErrBMPSessionEvidenceInput
	}
	return kind, data, nil
}

func writeBMPSessionEvidence(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, epoch string,
	input BMPSessionEvidenceInput, kind string, data bmpSessionEvidenceBody, policy BMPSessionSignalPolicy) (BMPSessionWriteResult, error) {
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"bmp-session/"+source.TenantID+"/"+source.CollectorAgentID+"/"+source.SourceRef+"/"+input.ConnectionID); err != nil {
		return BMPSessionWriteResult{}, err
	}
	var digest []byte
	var gap, sameScope bool
	err := sc.Q.QueryRow(ctx, `SELECT evidence_digest,coverage_gap,
 context_id=$6 AND router_id=$7 AND source_epoch IS NOT DISTINCT FROM NULLIF($8::text,'')::uuid
 FROM bmp_session_evidence WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3
 AND connection_id=$4 AND source_sequence=$5`, source.TenantID, source.CollectorAgentID, source.SourceRef,
		input.ConnectionID, input.Sequence, source.ContextID, source.RouterID, epoch).Scan(&digest, &gap, &sameScope)
	if err == nil {
		if !sameScope || !bytes.Equal(digest, input.Digest[:]) {
			return BMPSessionWriteResult{}, ErrBMPSessionEvidenceConflict
		}
		return BMPSessionWriteResult{CoverageGap: gap}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return BMPSessionWriteResult{}, err
	}
	gap, err = bmpSessionEvidenceGap(ctx, sc, source, epoch, input)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	loss, err := verifyBMPSessionLoss(ctx, sc, source, input, data.Neighbor, gap, policy)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	var asn *int64
	var peer, bgpID netip.Addr
	switch {
	case data.Statistics != nil:
		peer = data.Statistics.Peer.PeerAddress.Unmap()
	case data.Neighbor != nil:
		peer = data.Neighbor.Peer.PeerAddress.Unmap()
		bgpID = data.Neighbor.Peer.BGPIdentifier
		value := int64(data.Neighbor.Peer.PeerASN)
		asn = &value
	case data.UpdateChurn != nil:
		peer = data.UpdateChurn.Peer.PeerAddress.Unmap()
	}
	body, err := json.Marshal(data)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO bmp_session_evidence
 (tenant_id,context_id,router_id,collector_agent_id,source_ref,sender_serial,origin_serial,source_epoch,
 connection_id,source_sequence,observed_at,observed_unix_nanos,evidence_digest,evidence_kind,coverage_gap,evidence,peer_addr,peer_asn,peer_bgp_id,loss_confirmed)
 VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8::text,'')::uuid,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18,$19,$20)`,
		source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial,
		epoch, input.ConnectionID, input.Sequence, input.ObservedAt, input.ObservedAt.UnixNano(), input.Digest[:], kind, gap, body, peer, asn, bgpID, loss.confirmed)
	if err != nil {
		return BMPSessionWriteResult{}, err
	}
	return BMPSessionWriteResult{CoverageGap: gap, Signals: bmpSessionSignals(source, input, data.Neighbor, loss, policy)}, nil
}

func bmpSessionEvidenceGap(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, epoch string, input BMPSessionEvidenceInput) (bool, error) {
	var lastSeq, lastNanos int64
	var lastKind string
	var sameScope, sameSender bool
	err := sc.Q.QueryRow(ctx, `SELECT source_sequence,observed_unix_nanos,evidence_kind,
 context_id=$5 AND router_id=$6 AND source_epoch IS NOT DISTINCT FROM NULLIF($7::text,'')::uuid,
 sender_serial=$8 AND origin_serial=$9
 FROM bmp_session_evidence WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND connection_id=$4
 ORDER BY source_sequence DESC LIMIT 1`, source.TenantID, source.CollectorAgentID, source.SourceRef,
		input.ConnectionID, source.ContextID, source.RouterID, epoch, source.SenderSerial, source.OriginSerial).Scan(&lastSeq, &lastNanos, &lastKind, &sameScope, &sameSender)
	if errors.Is(err, pgx.ErrNoRows) {
		return input.Sequence != 1 || input.TransportClosed, nil
	}
	if err != nil {
		return false, err
	}
	if !sameScope || lastSeq >= input.Sequence || lastNanos > input.ObservedAt.UnixNano() || lastKind == bmpSessionClosed ||
		lastKind == bmpSessionTerminated && !input.TransportClosed {
		return false, ErrBMPSessionEvidenceConflict
	}
	return input.Sequence != lastSeq+1 || !sameSender || input.TransportClosed && lastKind != bmpSessionTerminated, nil
}
