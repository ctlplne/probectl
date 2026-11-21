// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/store"
)

type mcpBMPSessionHistoryBackend struct{ server *Server }

func bmpSessionHistoryToolOption(server *Server) (mcp.Option, error) {
	schema, err := bgpHistoryToolSchema("/v1/bgp/sessions/{router_id}", 14, "router_id", "context_id", "collector_agent_id", "source_ref")
	if err != nil {
		return nil, err
	}
	return mcp.WithBMPSessionHistoryBackend(mcpBMPSessionHistoryBackend{server}, schema), nil
}

// The native cursor carries only server-generated clock and position
// metadata. It never embeds a router reference or a private address.
type nativeBMPHistoryCursor struct {
	From  time.Time                       `json:"from"`
	To    time.Time                       `json:"to"`
	After store.BMPSessionHistoryPosition `json:"after"`
}

func parseNativeBMPHistory(command mcp.BMPSessionHistoryCommand) (bmpSessionHistoryCursor, error) {
	limit := 100
	if command.Limit != nil {
		limit = *command.Limit
	}
	cursor, err := parseBMPSessionHistoryArgs(bmpSessionHistoryArgs{Source: store.BMPSessionSource{
		RouterID: command.RouterID, ContextID: command.ContextID, CollectorAgentID: command.Collector, SourceRef: command.Source},
		From: command.From, To: command.To, Peer: command.Peer, Limit: limit, Statistic: command.Statistic,
		AFI: command.AFI, SAFI: command.SAFI, Minimum: command.Minimum, Maximum: command.Maximum})
	if err != nil || command.Cursor == "" {
		return cursor, err
	}
	if len(command.Cursor) > 1024 || command.From != "" || command.To != "" {
		return cursor, apierror.Validation("continue using the cursor's original time window")
	}
	raw, err := base64.RawURLEncoding.DecodeString(command.Cursor)
	position := nativeBMPHistoryCursor{}
	if err != nil || json.Unmarshal(raw, &position) != nil || position.From.IsZero() || !position.To.After(position.From) || position.After.Nanos <= 0 {
		return cursor, apierror.Validation("invalid BMP native cursor")
	}
	cursor.Query.From, cursor.Query.To, cursor.Query.After = position.From, position.To, &position.After
	return cursor, nil
}

func (b mcpBMPSessionHistoryBackend) BMPSessionHistory(ctx context.Context, actor *auth.Principal, command mcp.BMPSessionHistoryCommand) (json.RawMessage, error) {
	if b.server == nil || b.server.pool == nil || actor == nil || actor.UserID == "" {
		return nil, apierror.Forbidden("a current authorized tenant user is required")
	}
	cursor, err := parseNativeBMPHistory(command)
	if err != nil {
		return nil, err
	}
	read := func(ctx context.Context) (json.RawMessage, error) {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return nil, err
		}
		status, err := NewTenantStatusCache(b.server.pool, 0).TenantStatus(ctx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		if status != "active" {
			return nil, apierror.Forbidden("BMP session history tenant is inactive")
		}
		page, err := b.server.readBMPSessionHistory(ctx, actor, cursor, true)
		if err != nil {
			return nil, bmpSessionHistoryError(err)
		}
		return marshalNativeBMPHistory(page, cursor.Query)
	}
	raw, err := read(ctx)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		latest, err := read(active)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, latest) {
			return apierror.Conflict("BMP session history changed before publication")
		}
		return active.Err()
	}, func() {}); err != nil {
		return nil, err
	}
	return raw, nil
}

type nativeBMPPeer struct {
	ASN           uint32           `json:"peer_asn"`
	Type          uint8            `json:"peer_type"`
	Flags         uint8            `json:"flags"`
	View          bgp.BMPRouteView `json:"view"`
	OriginalClock *time.Time       `json:"original_clock,omitempty"`
}

func redactNativeBMPPeer(peer bgp.BMPObservationPeer) nativeBMPPeer {
	return nativeBMPPeer{peer.PeerASN, peer.PeerType, peer.Flags, peer.View, peer.OriginalClock}
}

func bmpExactCounter(value uint64) mcp.NativePeeringCounter {
	return mcp.NativePeeringCounter(strconv.FormatUint(value, 10))
}

func marshalNativeBMPHistory(page bmpSessionHistoryPage, query store.BMPSessionHistorySelection) (json.RawMessage, error) {
	type nativeSample struct {
		bgp.BMPStatistic
		Value mcp.NativePeeringCounter `json:"value"`
	}
	type nativeReport struct {
		Peer    nativeBMPPeer  `json:"peer"`
		Samples []nativeSample `json:"samples"`
	}
	type nativeNeighbor struct {
		bgp.BMPNeighborTransition
		Peer        nativeBMPPeer        `json:"peer"`
		FrameDigest mcp.NativeRoleDigest `json:"frame_digest"`
	}
	type nativeChurn struct {
		bgp.BMPUpdateChurn
		Peer    nativeBMPPeer            `json:"peer"`
		Updates mcp.NativePeeringCounter `json:"updates"`
	}
	type nativePoint struct {
		bmpSessionHistoryPoint
		Connection  mcp.NativeRoleUUID     `json:"connection_id"`
		Nanos       mcp.NativeRoleRevision `json:"observed_unix_nanos"`
		Sequence    mcp.NativeRoleRevision `json:"sequence"`
		Digest      mcp.NativeRoleDigest   `json:"evidence_digest"`
		Statistics  *nativeReport          `json:"statistics,omitempty"`
		Neighbor    *nativeNeighbor        `json:"neighbor,omitempty"`
		UpdateChurn *nativeChurn           `json:"update_churn,omitempty"`
	}
	type expectedRange struct {
		bgp.BMPStatisticRange
		Minimum mcp.NativePeeringCounter `json:"minimum"`
		Maximum mcp.NativePeeringCounter `json:"maximum"`
	}
	out := struct {
		Router   mcp.NativeRoleUUID `json:"router_id"`
		Context  mcp.NativeRoleUUID `json:"context_id"`
		Coverage string             `json:"coverage"`
		Limit    int                `json:"effective_limit"`
		Items    []nativePoint      `json:"items"`
		Range    *expectedRange     `json:"expected_range,omitempty"`
		Cursor   json.RawMessage    `json:"next_cursor,omitempty"`
	}{
		Router: mcp.NativeRoleUUID(page.Source.RouterID), Context: mcp.NativeRoleUUID(page.Source.ContextID),
		Coverage: page.Coverage, Limit: page.EffectiveLimit, Items: make([]nativePoint, 0, len(page.Items)),
	}
	if page.Range != nil {
		out.Range = &expectedRange{*page.Range, bmpExactCounter(page.Range.Minimum), bmpExactCounter(page.Range.Maximum)}
	}
	for _, original := range page.Items {
		value := nativePoint{bmpSessionHistoryPoint: original, Connection: mcp.NativeRoleUUID(original.Connection),
			Nanos: mcp.NativeRoleRevision(strconv.FormatInt(original.Nanos, 10)), Sequence: mcp.NativeRoleRevision(strconv.FormatInt(original.Sequence, 10)),
			Digest: mcp.NativeRoleDigest(original.EvidenceDigest)}
		if report := original.Statistics; report != nil {
			value.Statistics = &nativeReport{Peer: redactNativeBMPPeer(report.Peer), Samples: make([]nativeSample, 0, len(report.Samples))}
			for _, sample := range report.Samples {
				value.Statistics.Samples = append(value.Statistics.Samples, nativeSample{sample, bmpExactCounter(sample.Value)})
			}
		}
		if neighbor := original.Neighbor; neighbor != nil {
			value.Neighbor = &nativeNeighbor{*neighbor, redactNativeBMPPeer(neighbor.Peer), mcp.NativeRoleDigest(neighbor.FrameDigest)}
		}
		if churn := original.UpdateChurn; churn != nil {
			value.UpdateChurn = &nativeChurn{*churn, redactNativeBMPPeer(churn.Peer), bmpExactCounter(churn.Updates)}
		}
		out.Items = append(out.Items, value)
	}
	if page.NextCursor != "" && len(page.Items) != 0 {
		last := page.Items[len(page.Items)-1].BMPSessionHistoryPosition
		cursor, err := json.Marshal(nativeBMPHistoryCursor{query.From, query.To, last})
		if err != nil {
			return nil, err
		}
		out.Cursor, err = nativeValidatedCursorJSON(base64.RawURLEncoding.EncodeToString(cursor))
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}
